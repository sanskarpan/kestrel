// crates/kestrel-shim/src/daemon.rs
//
//! Design doc §2 steps 5-7: once `kestrel-runtime create` has succeeded and
//! the status handshake line has been written to the shim's own stdout,
//! `main.rs` hands off here to daemonize (`setsid()`, ignore `SIGHUP`) and
//! run the durable event loop — tailing the PTY/pipe `io` into
//! `<data_dir>/containers/<id>/output.jsonl` while serving
//! `<run_dir>/<id>/attach.sock` per the design doc §5 framing protocol.
//!
//! ## Real fd→async wiring
//!
//! The fds this module reads/writes (`io::allocate` already set them
//! non-blocking) are wrapped in `tokio::io::unix::AsyncFd`, following the
//! exact pattern documented on `AsyncFd` itself: `guard.try_io(|inner|
//! nix::unistd::read/write(...))` inside a `loop { fd.readable()/writable()
//! .await?; ... }`, retrying on the `WouldBlock`-shaped `TryIoError`.
//!
//! A PTY master read after every slave has closed classically returns
//! `EIO`, not `Ok(0)` the way a pipe does at EOF — both `read_stream_loop`
//! treats identically as "the container is gone, stop reading."
//!
//! ## Ownership shape
//!
//! `ContainerIo::into_daemon_io` (see `io.rs`) is called as literally the
//! first thing in `run()`, closing the shim's own copy of the slave/write
//! ends before anything else happens — see that method's doc comment for
//! why. For the PTY case, the surviving master fd is wrapped once in
//! `Arc<AsyncFd<OwnedFd>>` and shared between the read loop and every
//! `accept_loop` connection task that needs to write into it (attach's
//! write-direction, `TIOCSWINSZ`) — `AsyncFd::readable()`/`writable()` are
//! both `&self` methods and tokio explicitly supports separate readers and
//! writers driving the same `AsyncFd` concurrently, so no duplication is
//! needed.

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};

use crate::framing::{self, Frame};
use crate::io::{ContainerIo, DaemonIo};

/// Read buffer size for each stdio stream. Generous enough that ordinary
/// line-buffered CLI output rarely spans multiple reads, but line-splitting
/// below handles the case where it does regardless.
const READ_BUF_SIZE: usize = 8192;

/// Broadcast channel capacity (in in-flight byte chunks) fanned out to
/// every currently-connected `attach.sock` client. A slow/stalled attach
/// client falls behind and sees `RecvError::Lagged` rather than back-
/// pressuring the container's own stdio — see `handle_attach_conn`.
const BROADCAST_CAPACITY: usize = 256;

pub async fn run(id: String, run_dir: PathBuf, data_dir: PathBuf, io: ContainerIo) -> Result<()> {
    // MUST be first: close the shim's own copy of the slave (tty) /
    // write-ends (pipes) before anything else, including setsid(). See
    // `ContainerIo::into_daemon_io`'s doc comment — without this, the
    // shim's own lingering copy would keep the pipe/PTY "open" forever
    // from the kernel's point of view, masking the real EOF/EIO condition
    // this whole daemon depends on to know the container is gone.
    let daemon_io = io.into_daemon_io();

    // Daemonize: detach from whatever controlling terminal/session
    // kestreld's own fork gave us, so a SIGHUP to kestreld's process group
    // doesn't propagate here. setsid() requires we are NOT already a
    // process group leader — true here since kestreld just fork+exec'd us
    // directly (not via a shell), so this process's pid is fresh.
    nix::unistd::setsid().context("setsid")?;

    // Ignore SIGHUP for the same reason — belt-and-suspenders in case
    // something in our ancestry (or a future ctty edge case) still manages
    // to deliver one after setsid().
    // SAFETY: installing a plain SIG_IGN handler via sigaction is always
    // safe; no signal-handler-reentrancy concerns since SIG_IGN has no
    // user-defined handler body to run.
    unsafe {
        nix::sys::signal::signal(nix::sys::signal::Signal::SIGHUP, nix::sys::signal::SigHandler::SigIgn)
    }
    .context("ignoring SIGHUP")?;

    // Redirect this process's own stdin/stdout/stderr to `/dev/null`, now
    // that the status handshake has been sent (design doc §2 step 5,
    // literally: "redirect its own stdin/stdout/stderr to /dev/null now
    // that the status line has been sent"). Real gap found and fixed
    // during Phase 9 Task 16: without this, the shim keeps holding open
    // whatever stdin/stdout/stderr fds it inherited from `kestreld`'s own
    // spawn (`Stdio::piped()`/`Stdio::inherit()`,
    // `api::containers::spawn_shim_and_create`) for as long as the shim
    // itself runs — which, by this whole architecture's OWN design (§2:
    // "own one container's stdio for its entire lifetime, independent of
    // kestreld"), can be indefinitely. A daemonized shim silently holding
    // one of those fds open has a real, observable consequence: anything
    // downstream that was piping `kestreld`'s (or, in a test, the test
    // harness's own process's) stderr — a shell pipeline, `journald`,
    // etc. — never sees EOF on that pipe for as long as ANY still-running
    // container's shim is alive, even long after `kestreld`/the test
    // process itself has exited. Caught via a real reproduction (a
    // root-gated capstone test whose container legitimately stays running
    // for tens of seconds while WS-attached — the first test in this
    // phase long-lived enough for the gap to matter): a `cargo test ... |
    // tail` pipeline hung indefinitely past the test's own `timeout`-
    // enforced deadline, because the orphaned, reparented-to-PID-1 shim
    // was still holding the pipe's write end open.
    redirect_stdio_to_devnull().context("redirecting stdin/stdout/stderr to /dev/null")?;

    let log_dir = data_dir.join("containers").join(&id);
    tokio::fs::create_dir_all(&log_dir)
        .await
        .context("creating container log dir")?;
    let log_path = log_dir.join("output.jsonl");
    let log_file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
        .context("opening output.jsonl")?;
    let log = Arc::new(Mutex::new(log_file));

    let sock_dir = run_dir.join(&id);
    tokio::fs::create_dir_all(&sock_dir)
        .await
        .context("creating run_dir/<id>")?;
    let attach_sock_path = sock_dir.join("attach.sock");
    let _ = tokio::fs::remove_file(&attach_sock_path).await; // stale socket from a crashed prior shim
    let attach_listener = UnixListener::bind(&attach_sock_path).context("binding attach.sock")?;

    // Phase 9 Task 16 (design doc §7): always bound, regardless of whether
    // this container's seccomp profile actually uses `SCMP_ACT_NOTIFY` —
    // cheap, and simpler than kestreld having to know in advance whether to
    // expect a connection here. A container with no notify rule never gets
    // a `Bootstrap.seccomp_notify_sink`, so `kestrel-init`'s `exec_into`
    // never even attempts to connect — this listener just never accepts
    // anything for such a container.
    let seccomp_sock_path = sock_dir.join("seccomp.sock");
    let _ = tokio::fs::remove_file(&seccomp_sock_path).await;
    let seccomp_listener = UnixListener::bind(&seccomp_sock_path).context("binding seccomp.sock")?;

    // Broadcasts every raw byte chunk read from the container's stdio to
    // every currently-connected attach.sock client (design doc §5's DATA
    // frame: "raw bytes, forwarded verbatim"). Log-line tagging/JSON
    // encoding happens separately in `read_stream_loop`, not over this
    // channel.
    let (tx, _rx) = broadcast::channel::<Vec<u8>>(BROADCAST_CAPACITY);

    // Phase 9 Task 16 (adversarial-review round 2 fix): fans out each
    // `serde_json`-encoded `kestrel_security::notify::NotifyEvent`
    // (received off the real notify fd by `handle_seccomp_conn`'s
    // `run_notify_loop`) to every currently-connected attach.sock client,
    // as a `Frame::SeccompEvent` — same fan-out SHAPE as `tx` above (a
    // seccomp violation is not container stdio and must never be
    // interleaved into `output.jsonl`/the DATA stream), but wrapped in
    // `SeccompHub` rather than a bare `broadcast::Sender`: see that type's
    // own doc comment for why a bare broadcast channel here is a genuine,
    // reproduced race (not just theoretical) and how the small replay
    // buffer closes it unconditionally.
    let seccomp_hub = SeccompHub::new();

    let result = match daemon_io {
        DaemonIo::Pty(master) => {
            let master = Arc::new(AsyncFd::new(master).context("registering pty master with reactor")?);
            tokio::select! {
                r = read_stream_loop(master.clone(), StreamTag::Stdout, log.clone(), tx.clone()) => r,
                _ = accept_loop(attach_listener, tx.clone(), seccomp_hub.clone(), Some(master.clone())) => Ok(()),
                _ = seccomp_accept_loop(seccomp_listener, seccomp_hub.clone()) => Ok(()),
            }
        }
        DaemonIo::Pipes { stdout_read, stderr_read } => {
            let stdout_fd = Arc::new(AsyncFd::new(stdout_read).context("registering stdout pipe with reactor")?);
            let stderr_fd = Arc::new(AsyncFd::new(stderr_read).context("registering stderr pipe with reactor")?);
            let read_both = async {
                tokio::try_join!(
                    read_stream_loop(stdout_fd, StreamTag::Stdout, log.clone(), tx.clone()),
                    read_stream_loop(stderr_fd, StreamTag::Stderr, log.clone(), tx.clone()),
                )?;
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! {
                r = read_both => r,
                // Pipes case: no PTY master to write into, so no
                // write-direction / TIOCSWINSZ is possible over this
                // attach connection — see design doc §5's non-tty carve
                // out. `handle_attach_conn` drops/ignores Data and Resize
                // frames when `pty_master` is `None`.
                _ = accept_loop(attach_listener, tx.clone(), seccomp_hub.clone(), None) => Ok(()),
                _ = seccomp_accept_loop(seccomp_listener, seccomp_hub.clone()) => Ok(()),
            }
        }
    };

    // Final flush before exit, per design doc §2 step 7.
    {
        let mut f = log.lock().await;
        let _ = f.flush().await;
    }
    let _ = tokio::fs::remove_file(&attach_sock_path).await;
    let _ = tokio::fs::remove_file(&seccomp_sock_path).await;

    result
}

/// Redirects fd 0/1/2 (stdin/stdout/stderr) to `/dev/null`, read-write.
/// Opens `/dev/null` once and `dup2`s it onto all three targets (rather
/// than opening it three times) — standard daemonization idiom. The
/// original `/dev/null` fd is closed afterward if it landed above fd 2
/// (i.e. wasn't itself one of the three targets, which can't actually
/// happen here since all of 0/1/2 are already open inherited fds at this
/// point, but the check costs nothing and avoids ever leaking it).
fn redirect_stdio_to_devnull() -> Result<()> {
    use std::os::fd::AsRawFd;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("opening /dev/null")?;
    let devnull_fd = devnull.as_raw_fd();
    for target in [0, 1, 2] {
        nix::unistd::dup2(devnull_fd, target)
            .with_context(|| format!("dup2 /dev/null onto fd {target}"))?;
    }
    if devnull_fd > 2 {
        drop(devnull);
    } else {
        std::mem::forget(devnull); // IS one of 0/1/2 — dropping would close a fd we just dup2'd into
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StreamTag {
    Stdout,
    Stderr,
}

impl StreamTag {
    fn as_str(self) -> &'static str {
        match self {
            StreamTag::Stdout => "stdout",
            StreamTag::Stderr => "stderr",
        }
    }
}

#[derive(serde::Serialize)]
struct LogLine<'a> {
    ts: String,
    stream: &'a str,
    msg: String,
}

/// Reads one stdio stream (the PTY master, or one pipe read end) to
/// completion, line-buffering raw chunks into clean `output.jsonl` lines
/// and broadcasting each raw chunk verbatim to `tx` for attach clients.
/// Returns once EOF (pipes: `Ok(0)`) or EIO (PTY: last slave closed) is
/// observed — that's the normal, expected way this function ends, not an
/// error.
async fn read_stream_loop(
    fd: Arc<AsyncFd<OwnedFd>>,
    tag: StreamTag,
    log: Arc<Mutex<tokio::fs::File>>,
    tx: broadcast::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = [0u8; READ_BUF_SIZE];
    let mut line_buf: Vec<u8> = Vec::new();

    loop {
        match read_from_fd(&fd, &mut buf).await {
            Ok(0) => break,                                          // pipes: clean EOF
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,  // PTY: last slave closed
            Err(e) => return Err(e).context("reading container stdio"),
            Ok(n) => {
                let chunk = &buf[..n];
                // Broadcast errors (no receivers currently subscribed) are
                // expected and harmless — nobody attached right now.
                let _ = tx.send(chunk.to_vec());

                line_buf.extend_from_slice(chunk);
                while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = line_buf.drain(..=pos).collect();
                    write_log_line(&log, tag, &line[..line.len() - 1]).await?;
                }
            }
        }
    }

    // Flush any partial trailing line that never got a terminating '\n'
    // (e.g. the container's last write before exiting had no newline).
    if !line_buf.is_empty() {
        write_log_line(&log, tag, &line_buf).await?;
    }

    Ok(())
}

async fn write_log_line(log: &Mutex<tokio::fs::File>, tag: StreamTag, line: &[u8]) -> Result<()> {
    let entry = LogLine {
        ts: rfc3339_now(),
        stream: tag.as_str(),
        msg: String::from_utf8_lossy(line).into_owned(),
    };
    let mut json = serde_json::to_vec(&entry).context("serializing log line")?;
    json.push(b'\n');

    let mut f = log.lock().await;
    f.write_all(&json).await.context("writing output.jsonl")?;
    Ok(())
}

/// Current UTC time as an RFC3339 string with microsecond precision.
/// Hand-rolled via `libc::clock_gettime`/`gmtime_r` rather than pulling in
/// `chrono`/`time` — this workspace has no existing RFC3339 dependency
/// (confirmed: no crate in the lockfile provides it), and this project's
/// established convention (design doc §12) is to add new dependencies only
/// when genuinely needed; `libc` is already a dependency here.
fn rfc3339_now() -> String {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a valid, appropriately-sized out-param; CLOCK_REALTIME
    // is always available.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `ts.tv_sec` and `tm` are valid in/out params for gmtime_r.
    unsafe {
        libc::gmtime_r(&ts.tv_sec, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        ts.tv_nsec / 1_000,
    )
}

/// Reads into `buf` from `fd`, following the exact pattern documented on
/// `tokio::io::unix::AsyncFd`: loop on `readable()` + `try_io`, retrying
/// when the closure reports `WouldBlock` (which clears the readiness flag).
async fn read_from_fd(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| nix::unistd::read(inner.get_ref().as_raw_fd(), buf).map_err(std::io::Error::from)) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Writes the whole of `buf` to `fd`, handling partial writes and
/// `WouldBlock` the same way `read_from_fd` handles readability.
async fn write_to_fd(fd: &AsyncFd<OwnedFd>, buf: &[u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| nix::unistd::write(inner.get_ref(), &buf[offset..]).map_err(std::io::Error::from)) {
            Ok(Ok(n)) => offset += n,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// Issues `TIOCSWINSZ` on the PTY master fd. No `nix` helper exists for
/// this (confirmed: `nix::pty` only exposes `Winsize` as a `libc::winsize`
/// alias, no ioctl wrapper) — direct `libc::ioctl`, matching this crate's
/// existing comfort with raw libc syscalls where `nix` doesn't cover
/// something.
fn set_winsize(fd: &AsyncFd<OwnedFd>, rows: u16, cols: u16) -> std::io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` is a valid, open PTY master fd for the lifetime of this
    // call (borrowed, not consumed); `ws` is a valid, fully-initialized
    // `libc::winsize` the kernel only reads from.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws as *const libc::winsize) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Accepts `attach.sock` connections forever, spawning a task per
/// connection. Only returns (well: never does, under normal operation) if
/// `listener.accept()` fails in a way that isn't worth retrying — in
/// practice this future is always the LOSING side of the `tokio::select!`
/// in `run()`, cancelled once `read_stream_loop`/`read_both` observes
/// EOF/EIO and the container is confirmed gone.
async fn accept_loop(
    listener: UnixListener,
    tx: broadcast::Sender<Vec<u8>>,
    seccomp_hub: Arc<SeccompHub>,
    pty_master: Option<Arc<AsyncFd<OwnedFd>>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let tx = tx.clone();
                let seccomp_hub = seccomp_hub.clone();
                let master = pty_master.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_attach_conn(stream, tx, seccomp_hub, master).await {
                        tracing::warn!(error = %e, "attach connection ended with an error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "attach.sock accept failed");
                // A persistently-failing accept() (e.g. fd exhaustion)
                // would otherwise busy-loop; this is short-lived and cheap
                // enough not to warrant anything fancier for this daemon's
                // scope.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// Accepts connections on `seccomp.sock` (Phase 9 Task 16, design doc §7)
/// forever. In practice at most ONE real connection ever arrives per
/// container — `kestrel-init`'s `exec::send_fd_to_socket` makes a single,
/// one-shot connect immediately before `execve`, only when this
/// container's `Bootstrap.seccomp_notify_sink` is `Some` (i.e. its profile
/// genuinely uses `SCMP_ACT_NOTIFY`) — but a loop (rather than a single
/// `accept()`) tolerates the ordinary "never" case (most containers) with
/// no extra bookkeeping, and mirrors `accept_loop`'s own shape/error
/// handling above.
async fn seccomp_accept_loop(listener: UnixListener, seccomp_hub: Arc<SeccompHub>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let seccomp_hub = seccomp_hub.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_seccomp_conn(stream, seccomp_hub).await {
                        tracing::warn!(error = %e, "seccomp-notify connection ended with an error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "seccomp.sock accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// Fan-out + short replay buffer for seccomp-notify violation events
/// (Phase 9 Task 16, adversarial-review round 2 fix). A bare
/// `broadcast::Sender` alone silently drops an event fired before any
/// `attach.sock` client's `handle_attach_conn` has actually reached
/// `subscribe()` — exactly the shape of a REAL, reproduced race: the
/// capstone end-to-end test (`kestreld::main::
/// test_seccomp_notify_violation_reaches_event_bus_with_correct_syscall`)
/// failed ~50% of the time under a loaded full-suite run, because a fixed
/// client-side settle-wait sleep cannot bound how long it takes the SHIM's
/// OWN `accept_loop` to accept kestreld's `attach.sock` connection and its
/// spawned `handle_attach_conn` task to actually run `subscribe()` — a
/// second hop of tokio scheduling with no upper bound under load. No sleep,
/// however large, can close that deterministically; `SeccompHub` does, by
/// making "did I already miss it" structurally impossible rather than just
/// rare: every send is captured into a small ring buffer, and every new
/// subscriber replays that buffer's current contents before observing
/// anything live — see `send`/`subscribe` for the exact ordering argument.
///
/// This also happens to genuinely help a case an ack-only fix would not:
/// `kestreld` restarting (or simply reconnecting) and re-attaching well
/// after a violation fired still sees it, up to `SECCOMP_REPLAY_CAPACITY`
/// events back.
struct SeccompHub {
    tx: broadcast::Sender<Vec<u8>>,
    recent: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
}

/// How many of the most recent seccomp-notify events a late subscriber can
/// still see via replay. Small and cheap — genuine seccomp violations are
/// rare relative to ordinary container stdio (this is not the firehose
/// `BROADCAST_CAPACITY` above sizes for) — this only needs to bridge a
/// real accept-to-subscribe scheduling gap (observed up to hundreds of
/// milliseconds under a loaded test run), not model any adversarial
/// workload.
const SECCOMP_REPLAY_CAPACITY: usize = 16;

impl SeccompHub {
    fn new() -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Arc::new(Self {
            tx,
            recent: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(SECCOMP_REPLAY_CAPACITY)),
        })
    }

    /// Records `bytes` into the replay buffer and broadcasts it live, as
    /// ONE atomic operation under `recent`'s lock — this pairing with
    /// `subscribe`'s own lock acquisition is what makes the race genuinely
    /// closed rather than just narrowed: racing this against a concurrent
    /// `subscribe()` always resolves exactly one of two ways, never both,
    /// never neither. If `subscribe()` wins the lock first, its
    /// `tx.subscribe()` call (which only ever observes messages sent AFTER
    /// it runs) necessarily happens-before this `send`'s `tx.send()` —
    /// `send` cannot acquire the lock until `subscribe` releases it — so
    /// the new receiver genuinely observes this event live. If `send` wins
    /// the lock first, the event is already sitting in `recent` by the time
    /// `subscribe` takes the lock, so its replay snapshot includes it (and
    /// its own, later `tx.subscribe()` correctly does NOT see it a second
    /// time live, since `tx.send()` already completed before that
    /// subscribe call could even start).
    fn send(&self, bytes: Vec<u8>) {
        let mut recent = self.recent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        recent.push_back(bytes.clone());
        while recent.len() > SECCOMP_REPLAY_CAPACITY {
            recent.pop_front();
        }
        let _ = self.tx.send(bytes);
    }

    /// Subscribes and returns the replay buffer's current snapshot
    /// alongside the new receiver, both computed under the SAME lock
    /// acquisition as the `tx.subscribe()` call — see `send`'s doc comment
    /// for why that pairing is what makes the ordering race-free.
    fn subscribe(&self) -> (broadcast::Receiver<Vec<u8>>, Vec<Vec<u8>>) {
        let recent = self.recent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let rx = self.tx.subscribe();
        (rx, recent.iter().cloned().collect())
    }
}

/// Receives exactly one fd via `SCM_RIGHTS` off `stream` (the seccomp-
/// notify fd `kestrel-init`'s `exec::send_fd_to_socket` sent), then runs
/// `kestrel_security::notify::run_notify_loop` — a blocking read loop, not
/// async, per that function's own doc comment — on a `spawn_blocking`
/// task for as long as the fd stays alive (i.e. for the container's whole
/// remaining lifetime), forwarding each decoded `NotifyEvent` as
/// `serde_json`-encoded bytes onto `seccomp_hub` for every currently (or
/// later — see `SeccompHub`'s own doc comment on its replay buffer)
/// connected `attach.sock` client to receive as a `Frame::SeccompEvent`.
async fn handle_seccomp_conn(stream: UnixStream, seccomp_hub: Arc<SeccompHub>) -> Result<()> {
    // `recvmsg`'s real `nix` 0.29 API (verified against the vendored
    // source's own `test_scm_rights`, see `recv_fd_via_scm_rights`'s doc
    // comment) is a plain blocking syscall wrapper with no tokio/AsyncFd
    // integration of its own — converting to a std, blocking `UnixStream`
    // and doing the whole receive-then-supervise sequence inside ONE
    // `spawn_blocking` task is simpler than trying to straddle async/
    // blocking for just the first read of an otherwise-fully-blocking
    // fd's lifetime.
    let std_stream = stream
        .into_std()
        .context("converting seccomp.sock connection to a std (blocking) socket")?;
    std_stream
        .set_nonblocking(false)
        .context("setting seccomp.sock connection back to blocking mode")?;

    tokio::task::spawn_blocking(move || {
        let notify_fd = match recv_fd_via_scm_rights(std_stream) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::warn!(error = %e, "failed to receive seccomp-notify fd via SCM_RIGHTS");
                return;
            }
        };
        let result = kestrel_security::notify::run_notify_loop(notify_fd.as_fd(), |event| {
            match serde_json::to_vec(&event) {
                Ok(bytes) => {
                    // No currently-connected attach.sock client is an
                    // entirely ordinary state (same "expected and
                    // harmless" posture `read_stream_loop`'s own stdio
                    // broadcast already documents) — `SeccompHub::send`
                    // still captures it into the replay buffer so a client
                    // that subscribes shortly afterward doesn't miss it.
                    seccomp_hub.send(bytes);
                }
                Err(e) => tracing::warn!(error = %e, "failed to serialize seccomp-notify NotifyEvent"),
            }
        });
        if let Err(e) = result {
            tracing::warn!(error = %e, "seccomp-notify supervisor loop ended with an error");
        }
    })
    .await
    .context("seccomp-notify supervisor task panicked")?;

    Ok(())
}

/// Real `nix` 0.29 `SCM_RIGHTS` receive shape, verified against the
/// vendored source inside the Lima VM (`nix-0.29.0/test/sys/
/// test_socket.rs::test_scm_rights`) rather than assumed:
/// `recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())`,
/// `cmsg_buffer` sized via `nix::cmsg_space!([RawFd; 1])`, the fd itself
/// read back out via `msg.cmsgs()?` yielding `ControlMessageOwned::
/// ScmRights(Vec<RawFd>)`. Symmetric with `kestrel-init`'s
/// `exec::send_fd_to_socket` (Phase 9 Task 16), which sends a single real
/// marker byte alongside the `ScmRights` control message — this reads
/// (and discards) that same byte via the 1-byte `iov` buffer below.
fn recv_fd_via_scm_rights(stream: std::os::unix::net::UnixStream) -> Result<OwnedFd> {
    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::IoSliceMut;

    let raw_fd = stream.as_raw_fd();
    let mut cmsg_buffer = cmsg_space!([RawFd; 1]);
    let mut iov_buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut iov_buf)];
    let msg = recvmsg::<()>(raw_fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())
        .context("recvmsg for seccomp-notify fd")?;

    for cmsg in msg.cmsgs().context("iterating control messages")? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                // SAFETY: `fd` is a valid, freshly-received fd from a
                // successful `SCM_RIGHTS` control message on THIS process's
                // own socket — this is the sole owner-transfer point for it.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    anyhow::bail!("no fd received in SCM_RIGHTS control message on seccomp.sock")
}

/// Handles one `attach.sock` connection: relays every broadcast byte chunk
/// to the client as `Frame::Data` (read-direction), and every broadcast
/// seccomp-notify event as `Frame::SeccompEvent` (Phase 9 Task 16), while
/// concurrently reading frames from the client for the write-direction
/// (`Data` -> PTY master, tty only), `Resize` (`TIOCSWINSZ`, tty only), and
/// `Close` (ends the connection). Multiple simultaneous connections are
/// expected and supported — `tx.subscribe()`/`seccomp_hub.subscribe()` each
/// give this connection its own independent broadcast receiver (the latter
/// also replaying any events `SeccompHub` already had buffered — see its
/// own doc comment).
async fn handle_attach_conn(
    stream: UnixStream,
    tx: broadcast::Sender<Vec<u8>>,
    seccomp_hub: Arc<SeccompHub>,
    pty_master: Option<Arc<AsyncFd<OwnedFd>>>,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut rx = tx.subscribe();
    let (mut seccomp_rx, seccomp_replay) = seccomp_hub.subscribe();

    let writer_task = tokio::spawn(async move {
        // Sent FIRST, before anything else on this connection: a real,
        // observable proof — not a guess — that `rx`/`seccomp_rx` above
        // have ALREADY been subscribed (they were, synchronously, a few
        // lines up, before this task was even spawned). `kestreld`'s
        // `api::attach::run_attach_session` is the one real consumer:
        // waiting for this frame (there, forwarded on to its own WS
        // client) before ever calling `start` is what lets a caller know,
        // with certainty, that subscribing has already happened — see
        // `Frame::Ready`'s own doc comment for why a bare "we opened the
        // WS" or "we connected the socket" signal is NOT equivalent to
        // this (both of those can complete before this task, spawned by
        // `accept_loop`, has even been scheduled).
        if framing::write_frame(&mut write_half, &Frame::Ready).await.is_err() {
            return;
        }
        // Replay whatever `SeccompHub` already had buffered BEFORE this
        // connection subscribed, in original order, before ever entering
        // the live `select!` loop below — see `SeccompHub::send`'s doc
        // comment for why this is what makes a late-subscribing client
        // (accept-to-subscribe scheduling delay, not just this specific
        // client's own connect latency) genuinely unable to miss an event,
        // rather than merely less likely to. Belt-and-suspenders alongside
        // `Frame::Ready` above: a consumer that (unlike `kestreld`) doesn't
        // wait for `Ready` before triggering the thing it's watching for
        // still can't lose an event to this specific race.
        for bytes in seccomp_replay {
            if framing::write_frame(&mut write_half, &Frame::SeccompEvent(bytes)).await.is_err() {
                return;
            }
        }
        loop {
            tokio::select! {
                data = rx.recv() => {
                    match data {
                        Ok(chunk) => {
                            if framing::write_frame(&mut write_half, &Frame::Data(chunk)).await.is_err() {
                                break;
                            }
                        }
                        // Fell behind the broadcast channel's buffer — skip
                        // ahead rather than stalling the container's own
                        // stdio; the client just misses some already-old
                        // output.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                event = seccomp_rx.recv() => {
                    match event {
                        Ok(bytes) => {
                            if framing::write_frame(&mut write_half, &Frame::SeccompEvent(bytes)).await.is_err() {
                                break;
                            }
                        }
                        // Same lagging-tolerance posture as the stdio
                        // branch above — a missed seccomp event is a real
                        // loss but must never stall the connection.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    });

    loop {
        let frame = match framing::read_frame(&mut read_half).await {
            Ok(f) => f,
            Err(_) => break, // client disconnected or sent garbage
        };
        match frame {
            Frame::Data(bytes) => {
                if let Some(master) = &pty_master {
                    if let Err(e) = write_to_fd(master, &bytes).await {
                        tracing::warn!(error = %e, "writing attach data to pty master failed");
                        break;
                    }
                }
                // Non-tty: no meaningful "write into the container's
                // stdin" path (design doc §5) — silently dropped.
            }
            Frame::Resize { rows, cols } => {
                if let Some(master) = &pty_master {
                    if let Err(e) = set_winsize(master, rows, cols) {
                        tracing::warn!(error = %e, "TIOCSWINSZ failed");
                    }
                }
                // Non-tty: ignored, matching Data's handling above.
            }
            Frame::Close => break,
            Frame::SeccompEvent(_) | Frame::Ready => {
                // Both outbound (shim -> kestreld) only — not meaningful
                // received FROM a client on an inbound attach connection.
                // Ignored.
            }
        }
    }

    writer_task.abort();
    Ok(())
}

#[cfg(test)]
mod seccomp_scm_rights_tests {
    use super::*;
    use std::io::IoSlice;

    /// Proves `recv_fd_via_scm_rights` — the exact function `handle_seccomp_
    /// conn` calls on a real `seccomp.sock` connection — correctly receives
    /// a real, working fd sent the same way `kestrel-init`'s
    /// `exec::send_fd_to_socket` sends it: a `SOCK_STREAM` connect, one real
    /// marker byte, and a `ControlMessage::ScmRights` alongside it. No root
    /// required — plain fd-passing needs no privilege, unlike the real
    /// seccomp-notify fd this mechanism is built to carry in production
    /// (that full path is covered by `kestreld`'s own root-gated end-to-end
    /// test, Phase 9 Task 16 Step 5).
    #[test]
    fn test_recv_fd_via_scm_rights_receives_a_genuinely_working_fd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("seccomp.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind");

        let payload_path = dir.path().join("payload");
        std::fs::write(&payload_path, b"kestrel-seccomp-notify-fd").expect("write payload file");
        let file = std::fs::File::open(&payload_path).expect("open payload file");
        let send_fd = file.as_raw_fd();

        let sender = std::thread::spawn(move || {
            let stream = std::os::unix::net::UnixStream::connect(&sock_path).expect("connect");
            let marker = [0u8];
            let iov = [IoSlice::new(&marker)];
            let fds = [send_fd];
            let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
            nix::sys::socket::sendmsg::<()>(
                stream.as_raw_fd(),
                &iov,
                &cmsg,
                nix::sys::socket::MsgFlags::empty(),
                None,
            )
            .expect("sendmsg(SCM_RIGHTS)");
            // Keep `file`/`stream` alive until the send has definitely
            // completed on this thread.
            drop(file);
        });

        let (conn, _addr) = listener.accept().expect("accept");
        let received_fd = recv_fd_via_scm_rights(conn).expect("recv_fd_via_scm_rights");
        sender.join().expect("sender thread panicked");

        // `OwnedFd` -> `File` needs no `unsafe`: `std::fs::File` has a safe
        // `From<OwnedFd>` conversion that takes ownership directly.
        let mut received_file: std::fs::File = received_fd.into();
        use std::io::Read;
        let mut buf = Vec::new();
        received_file.read_to_end(&mut buf).expect("read via received fd");
        assert_eq!(
            buf, b"kestrel-seccomp-notify-fd",
            "the received fd must be a genuinely working duplicate of the original, not just a valid-looking fd number"
        );
    }
}
