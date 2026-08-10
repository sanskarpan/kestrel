// crates/kestreld/src/api/attach.rs
//
//! `WS /containers/:id/attach` + `POST /containers/:id/resize` (Task 12,
//! design doc §5): where `kestrel-shim`'s `attach.sock` design (Task 2)
//! pays off. `kestreld` is just a CLIENT of that already-fully-specified
//! wire protocol (`kestrel_shim::framing`) — this module bridges it to a
//! WebSocket, it doesn't invent any new protocol of its own.
//!
//! ## Attach: a direct bridge, not much new logic
//!
//! On WS upgrade, `kestreld` connects to `<run_dir>/<id>/attach.sock` as
//! an ordinary client of `kestrel-shim`'s own `daemon::accept_loop`/
//! `handle_attach_conn` (Task 2, `crates/kestrel-shim/src/daemon.rs`):
//! every `Frame::Data` the shim broadcasts (container output) is forwarded
//! as a WS Binary message; every WS Binary message FROM the client is
//! wrapped as a `Frame::Data` and written back to the socket (container
//! input, tty only — see below). `POST /resize` is a second, independent,
//! short-lived connection to the same socket that just sends one
//! `Frame::Resize` and disconnects — `handle_attach_conn` already handles
//! any number of concurrent connections per container, so this needs no
//! coordination with the attach WS connection at all.
//!
//! ## Why one `tokio::select!` loop, not two spawned tasks, for the WS side
//!
//! The plan text allows either. Two independently-spawned tasks (one per
//! direction) was the first design tried here, but it runs into a real
//! problem: reacting to a non-tty container's client sending input (see
//! below) needs to send a WS Close frame back to the SAME client — which
//! means the "read WS, write attach.sock" direction needs access to the
//! WS sink, not just the WS stream. Splitting `WebSocket` into
//! `SplitSink`/`SplitStream` and handing the sink to a different task than
//! the one deciding when to close would need a second synchronization
//! mechanism just to arbitrate access to one sink. Keeping the whole
//! `WebSocket` unsplit, in one task, driven by `tokio::select!`, avoids
//! that entirely: only one task ever touches `socket`, so there is nothing
//! to arbitrate.
//!
//! **Cancellation safety**, the classic footgun with `tokio::select!`:
//! `kestrel_shim::framing::read_frame` is NOT cancellation-safe (it awaits
//! across several sequential reads — tag byte, length, payload — with no
//! internal state that survives being dropped mid-await), so it must NEVER
//! appear as a `select!` branch directly (a lost race would silently
//! desync the frame boundary for the rest of the connection). It instead
//! runs in its own dedicated, never-selected-against task (`reader_task`
//! below), forwarding complete frames over an `mpsc` channel — and
//! `mpsc::Receiver::recv` IS cancellation-safe (a lost race just leaves
//! the value in the channel for the next call). The other `select!` branch,
//! `WebSocket::recv`, is safe for the same reason `axum`'s own examples
//! rely on it inside `select!`: it's driven by `&mut self` across calls, so
//! a lost race leaves any partially-buffered frame state inside `socket`
//! itself, not dropped.
//!
//! ## Non-tty containers (Step 3; design doc §5's carve-out)
//!
//! A non-tty container's entrypoint stdin is `/dev/null` (§2 step 1) — the
//! shim has no PTY master to write into, and `handle_attach_conn` already
//! silently drops `Frame::Data`/`Frame::Resize` it receives for one. But a
//! non-tty attach connection is still useful as a live-tail-equivalent
//! (design doc's own words): read-direction (container output -> WS
//! client) is left fully working regardless of `tty`. Only the
//! write-direction is restricted, and this module picks the more honest of
//! the plan's two allowed options: the first WS Binary message a client
//! sends to a non-tty attach gets an explicit WS Close (code 1008, "policy
//! violation") with a reason explaining why, ending the whole session —
//! not a silent drop that would leave the client wondering why its
//! keystrokes never had any effect. `POST /resize` against a non-tty
//! container is rejected even more explicitly, with a `409` before ever
//! touching `attach.sock` (`resize_container` below), checked purely via
//! the registry's `ContainerHandle.meta.tty` — never by asking the shim.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as PathParam, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use futures_util::SinkExt as _;
use kestrel_shim::framing::{self, Frame};
use serde::Deserialize;
use tokio::net::UnixStream;

use crate::api::containers::get_registered;
use crate::api::AppError;
use crate::events::{self, EventBus};
use crate::AppState;

/// Sent back to the client (as a WS Close reason) the moment a non-tty
/// attach connection receives ANY Binary message from it — see this
/// module's own doc comment for why this, rather than a silent drop, was
/// chosen.
const NON_TTY_WRITE_REJECTED_REASON: &str =
    "non-tty container: attach only supports the read (output) direction here; see POST .../resize's 409 for the same restriction";

/// Forwarded to the WS client as a Text message (never Binary — Binary is
/// reserved for real container output, see this module's own doc comment)
/// the moment `kestrel_shim::framing::Frame::Ready` arrives from the shim
/// (Task 16 adversarial-review round 2 fix). A client that waits for this
/// exact message before triggering whatever it wants observed over this
/// same attach session (a seccomp-notify violation, in the one real
/// consumer today — `kestreld`'s own capstone test,
/// `test_seccomp_notify_violation_reaches_event_bus_with_correct_syscall`)
/// gets a genuine, deterministic guarantee that this session is already a
/// live subscriber on the shim side, instead of guessing at a sleep
/// duration long enough to (probably) outlast an unbounded scheduling
/// delay. Using the WS message TYPE (Text vs Binary) as the discriminator,
/// rather than inventing a second, incompatible payload shape inside
/// Binary messages, keeps this additive: any consumer that only cares
/// about container output can keep ignoring non-Binary messages exactly as
/// `Some(Ok(_)) => {}` below already does for Ping/Pong/Text.
pub(crate) const ATTACH_READY_TEXT: &str = "kestrel.attach.ready";

/// `WS /containers/:id/attach`. Existence is checked BEFORE the upgrade so
/// an unknown id gets a real HTTP `404`, not a WS connection that
/// immediately errors out — matching `exec_container`'s (Task 10) own
/// convention (`crates/kestreld/src/api/containers.rs`).
pub async fn attach_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let handle = get_registered(&state, &id).await?;
    let attach_sock_path = attach_sock_path(&state.run_dir, &id);
    let tty = handle.meta.tty;
    let event_bus = state.event_bus.clone();
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = run_attach_session(socket, &attach_sock_path, tty, &id, &event_bus).await {
            tracing::warn!(id, error = %e, "attach session ended with an error");
        }
    }))
}

fn attach_sock_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join(id).join("attach.sock")
}

/// Pulls just the `syscall` field out of a `Frame::SeccompEvent` payload
/// (Phase 9 Task 16): `serde_json`-encoded bytes of
/// `kestrel_security::notify::NotifyEvent` (`kestrel-shim`'s
/// `handle_seccomp_conn`). Parsed as a generic `serde_json::Value` rather
/// than deserialized into a full `NotifyEvent` type — `kestreld`
/// deliberately has no dependency on `kestrel-security` (it never links
/// `kestrel-runtime` or its security pipeline, see `lib.rs`'s own doc
/// comment on Rule #2), and `syscall` is the only field
/// `Event::SeccompViolation` needs.
fn parse_seccomp_syscall(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value.get("syscall")?.as_str().map(str::to_string)
}

/// Connects to `attach_sock_path`, retrying briefly on `NotFound`/
/// `ConnectionRefused` — both transient, expected states while
/// `kestrel-shim`'s own `daemon::run` is still working through
/// daemonizing and binding `attach.sock`, not a real failure. A genuine,
/// reproduced race (found via this project's own root-gated capstone
/// test failing intermittently once its unrelated 1-second settle-wait
/// sleep — previously masking it purely by accident — was removed): `POST
/// /containers` returning `201` only proves `kestrel-shim` wrote its
/// status-handshake line, which happens BEFORE `main.rs` even calls
/// `daemon::run` (see that crate's own module doc comment) — binding
/// `attach.sock` is several steps further into `daemon::run` (daemonizing,
/// redirecting stdio, creating the log dir, opening `output.jsonl`, THEN
/// creating `<run_dir>/<id>` and binding). A client — any client, not just
/// a test — that calls `WS /containers/:id/attach` immediately after a
/// `201` can race this and lose, especially under load. Retried on a
/// short, fixed interval up to a generous overall bound: there's nothing
/// productive to wait on beyond that — a shim that hasn't managed to bind
/// its own socket after 2 real seconds has a different, actual problem
/// this loop should not paper over, so anything else (including
/// `NotFound`/`ConnectionRefused` past the deadline) is returned as a real
/// error, exactly as an unretried `connect` would have.
async fn connect_attach_sock_with_retry(attach_sock_path: &Path) -> std::io::Result<UnixStream> {
    const RETRY_INTERVAL: Duration = Duration::from_millis(10);
    const RETRY_BUDGET: Duration = Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + RETRY_BUDGET;
    loop {
        match UnixStream::connect(attach_sock_path).await {
            Ok(stream) => return Ok(stream),
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Drives one attach WS session end to end: connects to `attach.sock`,
/// bridges it to `socket` until either side closes, then tears both down.
/// See this module's own doc comment for the cancellation-safety reasoning
/// behind this exact shape.
///
/// `id`/`event_bus` (Phase 9 Task 16): while this session is open, any
/// `Frame::SeccompEvent` the shim forwards over this SAME `attach.sock`
/// connection (`kestrel_shim::daemon::handle_attach_conn`'s own
/// `SeccompHub`-backed broadcast, design doc §7) is decoded just far enough
/// to pull out the `syscall` name and published onto the daemon's event bus as
/// `Event::SeccompViolation`. Like `logs -f`/live-tail, this only happens
/// while a client is actually attached — no separate, always-on internal
/// subscriber exists (see this module's own doc comment on why attach.sock
/// connections are on-demand, not persistent).
async fn run_attach_session(
    mut socket: WebSocket,
    attach_sock_path: &Path,
    tty: bool,
    id: &str,
    event_bus: &EventBus,
) -> anyhow::Result<()> {
    let stream = match connect_attach_sock_with_retry(attach_sock_path).await {
        Ok(s) => s,
        Err(e) => {
            // Best-effort: tell the already-upgraded client WHY, rather
            // than just silently dropping the connection.
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 1011, // "internal error"
                    reason: format!("connecting to attach.sock failed: {e}").into(),
                })))
                .await;
            return Err(e).with_context(|| format!("connecting to {}", attach_sock_path.display()));
        }
    };
    let (mut sock_read, mut sock_write) = stream.into_split();

    // What the select! loop below forwards to the WS client: either a real
    // `Frame::Data` payload (container output, as a WS Binary message), or
    // `kestrel_shim::framing::Frame::Ready`'s arrival (forwarded as a WS
    // Text message — see `ATTACH_READY_TEXT` below). Bundled into one
    // channel item type rather than two channels so `rx.recv()` stays a
    // single `select!` branch.
    enum Relayed {
        Data(Vec<u8>),
        Ready,
    }

    // Bounded channel: complete frames read from `attach.sock`, handed off
    // to the select! loop below for forwarding onto the WS. See this
    // module's doc comment for why `read_frame` itself must stay confined
    // to this dedicated task rather than ever appearing directly in a
    // `select!` branch.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Relayed>(64);
    let reader_id = id.to_string();
    let reader_event_bus = event_bus.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            match framing::read_frame(&mut sock_read).await {
                Ok(Frame::Data(bytes)) => {
                    if tx.send(Relayed::Data(bytes)).await.is_err() {
                        break; // the select! loop below already gave up
                    }
                }
                Ok(Frame::Ready) => {
                    if tx.send(Relayed::Ready).await.is_err() {
                        break; // the select! loop below already gave up
                    }
                }
                Ok(Frame::SeccompEvent(bytes)) => {
                    match parse_seccomp_syscall(&bytes) {
                        Some(syscall) => {
                            events::publish(
                                &reader_event_bus,
                                events::Event::SeccompViolation { id: reader_id.clone(), syscall },
                            );
                        }
                        None => {
                            tracing::warn!(
                                id = %reader_id,
                                "received a malformed SeccompEvent frame over attach.sock (no `syscall` field)"
                            );
                        }
                    }
                }
                Ok(Frame::Close) | Err(_) => break, // shim closed, or a read error (EOF included)
                Ok(_) => {} // Resize is never sent inbound by the shim; ignore defensively
            }
        }
    });

    loop {
        tokio::select! {
            chunk = rx.recv() => {
                match chunk {
                    Some(Relayed::Data(bytes)) => {
                        if socket.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(Relayed::Ready) => {
                        if socket.send(Message::Text(ATTACH_READY_TEXT.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break, // attach.sock reader ended (EOF/Close/error) — nothing more to relay
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        if !tty {
                            // Explicit close-with-reason, not a silent
                            // drop — see this module's doc comment.
                            let _ = socket
                                .send(Message::Close(Some(CloseFrame {
                                    code: 1008, // "policy violation"
                                    reason: NON_TTY_WRITE_REJECTED_REASON.into(),
                                })))
                                .await;
                            break;
                        }
                        if framing::write_frame(&mut sock_write, &Frame::Data(bytes.to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // Text/Ping/Pong: no meaning here, and axum already auto-handles Ping/Pong
                    Some(Err(_)) => break,
                }
            }
        }
    }

    reader_task.abort();
    let _ = framing::write_frame(&mut sock_write, &Frame::Close).await;
    let _ = socket.close().await;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ResizeRequest {
    pub rows: u16,
    pub cols: u16,
}

/// `POST /containers/:id/resize` — a fresh, short-lived connection to
/// `attach.sock` per request (the shim's `accept_loop`, Task 2, already
/// supports any number of concurrent connections per container, so this
/// needs no coordination with a possibly-already-open attach WS
/// connection for the same id).
pub async fn resize_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    Json(req): Json<ResizeRequest>,
) -> Result<StatusCode, AppError> {
    let handle = get_registered(&state, &id).await?;
    if !handle.meta.tty {
        return Err(AppError::conflict(format!(
            "container {id} is not a tty container; there is no PTY to resize"
        )));
    }

    let attach_sock_path = attach_sock_path(&state.run_dir, &id);
    let mut stream = UnixStream::connect(&attach_sock_path)
        .await
        .with_context(|| format!("connecting to {}", attach_sock_path.display()))?;
    framing::write_frame(&mut stream, &Frame::Resize { rows: req.rows, cols: req.cols })
        .await
        .context("sending RESIZE frame to attach.sock")?;

    Ok(StatusCode::OK)
}
