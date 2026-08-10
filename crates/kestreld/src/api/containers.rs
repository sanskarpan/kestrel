// crates/kestreld/src/api/containers.rs
//
//! `POST /containers` (Task 8, design doc §4's first row): the first real
//! end-to-end path in this daemon — HTTP request -> bundle materialization
//! (`bundle.rs`) -> `kestrel-shim` spawn -> `kestrel-runtime create`
//! subprocess -> registry entry.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as PathParam, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use futures_util::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

use crate::api::AppError;
use crate::bundle;
use crate::events::{self, Event};
use crate::registry::{self, ContainerHandle, ContainerMeta};
use crate::runtime_cli;
use crate::{network, AppState};

#[derive(Debug, Deserialize)]
pub struct CreateContainerRequest {
    /// e.g. "docker.io/library/alpine:latest" — pulled if not already
    /// present. Exactly one of `image`/`bundle_rootfs` must be given.
    pub image: Option<String>,
    /// Alternative to `image`: a plain, already-extracted rootfs
    /// directory (Task 3's fallback path).
    pub bundle_rootfs: Option<PathBuf>,
    /// Accepted but not yet wired to anything — a later task's
    /// name-registry/lookup support is the real consumer. Kept on the
    /// request shape now so clients don't need a breaking API change
    /// later.
    #[allow(dead_code)]
    pub name: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub tty: bool,
    #[serde(default)]
    pub memory_bytes: Option<i64>,
    #[serde(default)]
    pub pids_limit: Option<i64>,
    /// "bridge" | "host" | "none" | "container:<id>" — absent defaults to
    /// "none" (see `bundle::NetworkMode`'s own doc comment for why).
    pub network_mode: Option<String>,
    /// Phase 9 Task 16: syscall names to install `SCMP_ACT_NOTIFY` for
    /// (default action `SCMP_ACT_ALLOW` for everything else) — a minimal,
    /// deliberately narrow knob (not a full custom-profile API, which is
    /// out of this task's scope) that exists so a client can genuinely
    /// exercise the seccomp-notify fd-hand-back + supervisor chain
    /// end to end through the real HTTP API, matching Phase 5's own
    /// `personality`-syscall test-profile pattern
    /// (`kestrel-security/tests/notify.rs::notify_personality_profile`).
    /// Absent or empty: no seccomp profile is set on the container at all
    /// (unchanged, pre-Task-16 behavior).
    #[serde(default)]
    pub seccomp_notify_syscalls: Option<Vec<String>>,
    /// Phase 9 Task 17: `(host_port, container_port)` TCP pairs to DNAT
    /// for a `network_mode: "bridge"` container — ignored for every other
    /// mode. Absent/empty: no published ports (the container is still
    /// reachable container<->container and container->host/internet via
    /// the bridge + MASQUERADE, just not FROM the host on a fixed port).
    #[serde(default)]
    pub published_ports: Vec<(u16, u16)>,
}

#[derive(Debug, Serialize)]
pub struct CreateContainerResponse {
    pub id: String,
}

/// The one-line JSON status handshake `kestrel-shim` writes to its own
/// stdout after `kestrel-runtime create` exits (Task 1's real contract,
/// `kestrel-shim/src/main.rs`): `{"ok":true}` or
/// `{"ok":false,"error":"..."}`.
#[derive(Debug, Deserialize)]
struct ShimStatus {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

pub async fn create_container(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateContainerRequest>,
) -> Result<(StatusCode, Json<CreateContainerResponse>), AppError> {
    // Plain v4 UUID — no existing id-generation precedent elsewhere in
    // this workspace (`kestrel-runtime`'s own CLI/tests always take an id
    // as an explicit argument), so this is a fresh, reasonable choice
    // rather than a continuation of an established scheme.
    let id = uuid::Uuid::new_v4().to_string();

    let materialized = bundle::materialize_bundle(&id, &req, &state.run_dir, &state.data_dir).await?;

    match spawn_shim_and_create(&state, &id, &req, &materialized.bundle_dir).await {
        Ok(()) => {
            // Task 17: the POST-create half of bridge-mode network
            // attachment — `bundle.rs` (Task 8) already created + pinned
            // the netns and (via Task 4's real join mechanism) the
            // container's pid 1 is already inside it by the time
            // `create()` above returned successfully; this is the
            // veth/bridge/NAT half that can only happen now that a real
            // pid/netns exists to attach to.
            let network_info = if req.network_mode.as_deref() == Some("bridge") {
                let netns_pin = materialized.netns_pin_to_cleanup_on_failure.clone().expect(
                    "bundle::materialize_bundle always returns Some(pin) for network_mode \
                     \"bridge\" — see MaterializedBundle::netns_pin_to_cleanup_on_failure's own doc comment",
                );
                match network::attach(&id, &netns_pin, &state.data_dir, &state.network, &req.published_ports).await {
                    Ok(info) => Some(info),
                    Err(e) => {
                        // The container itself was already created
                        // successfully (real pid, real state.json) but its
                        // networking never finished attaching — treat the
                        // whole POST as failed rather than register a
                        // container with broken/absent networking.
                        // Best-effort force-delete + netns-pin teardown,
                        // matching the same "a failed create must never
                        // leak state" posture the `Err(e)` arm below
                        // already established for the pre-create() half of
                        // this sequence.
                        if let Err(delete_err) = runtime_cli::run_kestrel_runtime(
                            &state.run_dir,
                            &state.data_dir,
                            &["delete", &id, "--force"],
                        )
                        .await
                        {
                            tracing::warn!(
                                id,
                                error = %delete_err,
                                "failed to force-delete container after a failed network attach"
                            );
                        }
                        if let Err(unpin_err) = kestrel_net::netns::teardown_netns(&state.run_dir, &id) {
                            tracing::warn!(
                                id,
                                error = %unpin_err,
                                "failed to tear down bridge-mode netns after a failed network attach"
                            );
                        }
                        return Err(AppError::from(e.context("attaching bridge-mode networking")));
                    }
                }
            } else {
                None
            };

            let meta = ContainerMeta {
                tty: req.tty,
                network_mode: req.network_mode.clone(),
                network: network_info,
            };
            // Re-write meta.json with the real NetworkInfo now that
            // attachment (if any) has genuinely completed — `bundle.rs`
            // already wrote an initial `meta.json` (network: None) before
            // `create()` ever ran; this second write is what makes Task
            // 17's persistence survive a `kestreld` restart (Step 2's own
            // requirement). Best-effort: a failure here doesn't fail the
            // whole create (the in-memory registry entry below is still
            // correct for this process's own lifetime), but IS logged
            // loudly since it silently weakens the restart-durability
            // guarantee.
            if let Err(e) = registry::write_meta(&state.data_dir, &id, &meta).await {
                tracing::warn!(id, error = %e, "failed to persist meta.json with real network info");
            }

            let handle = ContainerHandle {
                id: id.clone(),
                bundle_path: materialized.bundle_dir.clone(),
                meta,
            };
            state.registry.write().await.insert(id.clone(), handle);
            // Task 14: `container.create` — published directly here, the
            // moment creation genuinely succeeds, rather than derived from
            // Task 13's status-transition sampler: `Creating`->`Created`
            // isn't one of SPEC.md §13's event types at all (see
            // `events.rs`'s own doc comment).
            events::publish(&state.event_bus, Event::ContainerCreate { id: id.clone() });
            if req.network_mode.as_deref() == Some("bridge") {
                events::publish(&state.event_bus, Event::NetAttach { id: id.clone() });
            }
            Ok((StatusCode::CREATED, Json(CreateContainerResponse { id })))
        }
        Err(e) => {
            // Tear down any netns THIS create() attempt allocated — a
            // failed `POST /containers` must never leak a pinned
            // namespace (design doc §4a / plan Task 8 Step 3).
            if materialized.netns_pin_to_cleanup_on_failure.is_some() {
                if let Err(unpin_err) = kestrel_net::netns::teardown_netns(&state.run_dir, &id) {
                    tracing::warn!(
                        id,
                        error = %unpin_err,
                        "failed to tear down bridge-mode netns after a failed create"
                    );
                }
            }
            Err(AppError::from(e))
        }
    }
}

/// Spawns `kestrel-shim --id <id> --run-dir <run_dir> --data-dir
/// <data_dir> --tty <bool> -- kestrel-runtime --run-dir <run_dir>
/// --data-dir <data_dir> create <id> --bundle <bundle_dir>` (Task 1's
/// exact invocation contract — note the global `--run-dir`/`--data-dir`
/// flags precede the `create` subcommand token, per `kestrel-runtime`'s
/// real `Cli` struct, `crates/kestrel-runtime/src/cli.rs`), reads exactly
/// one status-handshake line from the shim's stdout, and confirms the
/// container genuinely reached `Created`.
async fn spawn_shim_and_create(
    state: &AppState,
    id: &str,
    req: &CreateContainerRequest,
    bundle_dir: &Path,
) -> anyhow::Result<()> {
    let tty_arg = if req.tty { "true" } else { "false" };

    let mut cmd = tokio::process::Command::new(&state.shim_path);
    cmd.arg("--id")
        .arg(id)
        .arg("--run-dir")
        .arg(&state.run_dir)
        .arg("--data-dir")
        .arg(&state.data_dir)
        .arg("--tty")
        .arg(tty_arg)
        .arg("--")
        .arg(&state.runtime_path)
        .arg("--run-dir")
        .arg(&state.run_dir)
        .arg("--data-dir")
        .arg(&state.data_dir)
        .arg("create")
        .arg(id)
        .arg("--bundle")
        .arg(bundle_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", state.shim_path.display()))?;
    let stdout = child.stdout.take().context("kestrel-shim's stdout was not piped")?;
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .context("reading kestrel-shim status handshake")?;
    anyhow::ensure!(
        n > 0,
        "kestrel-shim closed stdout without writing a status handshake line \
         (crashed before kestrel-runtime create finished?)"
    );

    let status: ShimStatus = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing kestrel-shim status handshake line: {line:?}"))?;

    // Deliberately NOT `child.wait()`ed: after this handshake line, the
    // shim daemonizes (`setsid`) and outlives this call by design (design
    // doc §2) — tokio's own orphan-process reaper handles eventually
    // reaping it without kestreld blocking here or leaking a zombie.
    drop(child);

    anyhow::ensure!(
        status.ok,
        "kestrel-runtime create failed: {}",
        status.error.unwrap_or_default()
    );

    // Real Task 7 `read_state` caller: confirm the container genuinely
    // reached `Created` (not just that the shim reported success) before
    // telling the client 201.
    let state_json = registry::read_state(&state.run_dir, id)
        .await
        .context("reading state.json after create")?;
    anyhow::ensure!(
        state_json.status == kestrel_oci::state::Status::Created,
        "kestrel-runtime create reported success but state.json shows {:?}, not Created",
        state_json.status
    );

    Ok(())
}

// ===========================================================================
// Task 9: lifecycle endpoints (start/stop/kill/pause/unpause/delete) +
// list/inspect
// ===========================================================================
//
// Every lifecycle endpoint below is a thin wrapper around
// `runtime_cli::run_kestrel_runtime` (Task 9's one shared subprocess-
// invocation helper) EXCEPT `stop`, which is deliberately NOT a direct
// passthrough — see `stop_container`'s own doc comment for the real
// SIGTERM -> grace-period-poll -> SIGKILL sequencing design doc §4's table
// calls for.

/// Looks up `id` in the registry, mapping "not present" to a real `404`
/// rather than letting an unknown id fall through to `kestrel-runtime`'s
/// own (much less specific) failure, which `AppError::from(anyhow::Error)`
/// would otherwise turn into a generic `500`.
///
/// `pub(crate)` (Task 12): `api::attach`'s WS/resize handlers need the
/// exact same "unknown id -> 404, not a generic 500" lookup this module
/// already established — reusing it rather than re-deriving a second copy
/// of the same 15 lines.
pub(crate) async fn get_registered(state: &AppState, id: &str) -> Result<ContainerHandle, AppError> {
    state
        .registry
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or_else(|| AppError::not_found(format!("container {id} not found")))
}

/// Polls `state.json` (via `registry::read_state`, matching every other
/// read-path's own "state.json is the source of truth, never trust a
/// cached copy" convention) every 200ms until `status == want` or
/// `timeout` elapses. `true` once observed, `false` on timeout. A
/// container whose `state.json` transiently fails to read (e.g. raced a
/// concurrent delete) is treated as "not yet at `want`", not a hard
/// error — a polling loop's whole point is to tolerate exactly this kind
/// of transient absence.
async fn poll_for_status(
    run_dir: &Path,
    id: &str,
    want: kestrel_oci::state::Status,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(state) = registry::read_state(run_dir, id).await {
            if state.status == want {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub async fn start_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<StatusCode, AppError> {
    get_registered(&state, &id).await?;
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["start", &id]).await?;
    // Task 14: `container.start` — published directly here (Step 3), NOT
    // derived from Task 13's `Created`->`Running` status-transition signal
    // (`events.rs`'s own doc comment explains why deriving it there too
    // would double-publish this same occurrence).
    events::publish(&state.event_bus, Event::ContainerStart { id: id.clone() });
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct KillQuery {
    pub signal: Option<String>,
}

pub async fn kill_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    Query(query): Query<KillQuery>,
) -> Result<StatusCode, AppError> {
    get_registered(&state, &id).await?;
    let signal = query.signal.ok_or_else(|| {
        AppError::bad_request("missing required ?signal=<name-or-number> query parameter, e.g. ?signal=SIGTERM")
    })?;
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["kill", &id, &signal]).await?;
    Ok(StatusCode::OK)
}

pub async fn pause_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<StatusCode, AppError> {
    get_registered(&state, &id).await?;
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["pause", &id]).await?;
    // Task 14: `container.pause` — published directly here, same
    // no-double-publish reasoning as `start_container` above.
    events::publish(&state.event_bus, Event::ContainerPause { id: id.clone() });
    Ok(StatusCode::OK)
}

pub async fn unpause_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<StatusCode, AppError> {
    get_registered(&state, &id).await?;
    // The CLI subcommand is `resume` (`kestrel-runtime`'s real `Cli`,
    // `crates/kestrel-runtime/src/cli.rs`'s `Command::Resume`) — the HTTP
    // verb is `unpause` (matching the design doc §4 table's own naming and
    // the more familiar Docker-style REST vocabulary), so this is the one
    // lifecycle endpoint whose HTTP path segment and CLI subcommand name
    // genuinely differ; that's intentional, not a typo.
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["resume", &id]).await?;
    // Task 14: `container.unpause` — published directly here, same
    // no-double-publish reasoning as `start_container` above.
    events::publish(&state.event_bus, Event::ContainerUnpause { id: id.clone() });
    Ok(StatusCode::OK)
}

/// `POST /containers/:id/stop` — NOT a direct passthrough to a single
/// `kestrel-runtime` subcommand (design doc §4's `stop` row): send
/// SIGTERM, poll `state.json` every 200ms for up to
/// `config.daemon.stop_grace_period_s` seconds for `Stopped`, and only if
/// the container is STILL not `Stopped` once that grace period elapses,
/// escalate to SIGKILL and poll a second, fixed bounded window
/// (`SIGKILL_FOLLOWUP_TIMEOUT`) for the same. A container already
/// `Stopped` by the time this is called is treated as an idempotent
/// success (no signal sent at all) rather than an error — `kestrel-
/// runtime kill` on an already-dead pid would fail loudly for no useful
/// reason.
const SIGKILL_FOLLOWUP_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn stop_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<StatusCode, AppError> {
    get_registered(&state, &id).await?;

    let current = registry::read_state(&state.run_dir, &id)
        .await
        .with_context(|| format!("reading state.json for {id} before stop"))?;
    if current.status == kestrel_oci::state::Status::Stopped {
        return Ok(StatusCode::OK);
    }

    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["kill", &id, "SIGTERM"]).await?;

    let grace = Duration::from_secs(state.stop_grace_period_s);
    if poll_for_status(&state.run_dir, &id, kestrel_oci::state::Status::Stopped, grace).await {
        return Ok(StatusCode::OK);
    }

    tracing::warn!(
        id,
        grace_period_s = state.stop_grace_period_s,
        "container did not stop within the grace period after SIGTERM — escalating to SIGKILL"
    );
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &["kill", &id, "SIGKILL"]).await?;

    let killed = poll_for_status(
        &state.run_dir,
        &id,
        kestrel_oci::state::Status::Stopped,
        SIGKILL_FOLLOWUP_TIMEOUT,
    )
    .await;
    if !killed {
        return Err(AppError::internal(format!(
            "container {id} did not reach Stopped status even {SIGKILL_FOLLOWUP_TIMEOUT:?} after SIGKILL"
        )));
    }
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    pub force: bool,
}

/// `DELETE /containers/:id?force=true` — `kestrel-runtime delete <id>
/// [--force]`, then (only on success) remove the registry entry and
/// `<data_dir>/containers/<id>/`, plus (design doc §4's `DELETE` row,
/// Task 9's own network-teardown note) a bridge-mode network teardown call
/// — the real implementation as of Task 17, see `network::teardown`'s own
/// doc comment.
pub async fn delete_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, AppError> {
    let handle = get_registered(&state, &id).await?;

    // Real cross-task race fix (found by Phase 9 Task 22's capstone suite,
    // `crates/kestreld/tests/capstone.rs::test_events_and_metrics_flow_end_
    // to_end`): `kestrel-runtime delete` (below) removes `<run_dir>/<id>/`
    // ENTIRELY, `state.json` included — and once this function goes on to
    // remove the registry entry too, the metrics sampler's next tick will
    // never even see this id again (`metrics::sample_tick` only diffs ids
    // currently in the registry). A client that calls `stop` then
    // immediately `delete`s — an entirely ordinary sequence — can beat the
    // sampler's own periodic tick to this window, silently losing
    // `container.die` forever. Closed by synchronously performing the
    // SAME status-transition check the sampler's tick loop does, against
    // the SAME shared `LastStatusMap`, HERE, while `state.json` is still
    // readable — deterministic, no dependency on tick timing. Sharing the
    // map with the sampler (rather than each maintaining an independent
    // copy) is what guarantees this can never DOUBLE-publish
    // `container.die` for a transition the sampler's own tick already
    // caught first: whichever of the two runs first wins the diff, the
    // other sees "no change" and stays silent. Best-effort: a read/lock
    // failure here must not block the delete itself (`state.json` may
    // simply not exist for a `Created`-but-never-`state.json`-written edge
    // case — nothing to observe in that case anyway).
    if let Ok(Some((_from, to))) =
        crate::metrics::check_terminal_transition(&state.last_status_map, &state.run_dir, &id).await
    {
        if to == kestrel_oci::state::Status::Stopped {
            let exit_code = registry::read_state(&state.run_dir, &id).await.ok().and_then(|s| s.exit_code);
            events::publish(&state.event_bus, Event::ContainerDie { id: id.clone(), exit_code });
        }
    }

    let mut args: Vec<&str> = vec!["delete", id.as_str()];
    if query.force {
        args.push("--force");
    }
    runtime_cli::run_kestrel_runtime(&state.run_dir, &state.data_dir, &args).await?;

    if handle.meta.network_mode.as_deref() == Some("bridge") {
        match network::teardown(&state.run_dir, &state.data_dir, &id, &state.network, &handle.meta).await {
            Ok(()) => {
                events::publish(&state.event_bus, Event::NetDetach { id: id.clone() });
            }
            Err(e) => {
                tracing::warn!(id, error = %e, "bridge-mode network teardown failed during delete");
            }
        }
    }

    state.registry.write().await.remove(&id);
    // Task 19 Part B leak fix: prune this container's entry out of the
    // daemon-side seccomp violation ring buffer too, right alongside the
    // registry entry it's removed with above — without this, `SeccompLog`'s
    // outer `HashMap` (see that type's own doc comment) keeps one key per
    // container that ever triggered a violation for the rest of this
    // daemon's process lifetime, growing without bound as container ids
    // churn across create/delete cycles.
    state.seccomp_log.remove(&id).await;
    // Task 14: `container.destroy` — published directly here, the moment
    // deletion genuinely succeeds.
    events::publish(&state.event_bus, Event::ContainerDestroy { id: id.clone() });

    let container_data_dir = state.data_dir.join("containers").join(&id);
    if let Err(e) = tokio::fs::remove_dir_all(&container_data_dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                id,
                error = %e,
                "failed to remove {} after a successful delete",
                container_data_dir.display()
            );
        }
    }

    Ok(StatusCode::OK)
}

/// `GET /containers` and `GET /containers/:id`'s shared response shape:
/// `State` (design doc's real source of truth) merged with the registry's
/// own `ContainerHandle`/`ContainerMeta` fields. `namespaces`/`cgroup` are
/// LATER tasks' job (Task 18) — always `null` here, kept on the shape now
/// so that task only needs to start actually populating them, not change
/// the response's field names. `network` is Task 17's own job (this
/// task): the real, persisted `NetworkInfo`, `null` for every non-bridge
/// mode — the same data `GET /containers/:id/network` (`api::network`)
/// returns as its own dedicated endpoint, just also inlined here for
/// convenience.
#[derive(Debug, Serialize)]
pub struct ContainerView {
    pub id: String,
    pub status: kestrel_oci::state::Status,
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    pub exit_code: Option<i32>,
    pub tty: bool,
    pub network_mode: Option<String>,
    pub namespaces: Option<serde_json::Value>,
    pub cgroup: Option<serde_json::Value>,
    pub network: Option<crate::network::NetworkInfo>,
}

impl ContainerView {
    fn new(id: String, state: kestrel_oci::state::State, meta: ContainerMeta) -> Self {
        ContainerView {
            id,
            status: state.status,
            pid: state.pid,
            bundle: state.bundle,
            exit_code: state.exit_code,
            tty: meta.tty,
            network_mode: meta.network_mode,
            namespaces: None,
            cgroup: None,
            network: meta.network,
        }
    }
}

/// `GET /containers` — iterates the registry, re-reads `state.json` for
/// each entry (never trusts a cached copy, matching every other read path
/// in this crate). A registry entry whose `state.json` has since vanished
/// (e.g. raced a concurrent `delete`) is silently skipped rather than
/// failing the whole listing — the same "tolerate transient absence"
/// posture `poll_for_status` above documents.
pub async fn list_containers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ContainerView>>, AppError> {
    let handles: Vec<ContainerHandle> = state.registry.read().await.values().cloned().collect();
    let mut views = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(s) = registry::read_state(&state.run_dir, &handle.id).await {
            views.push(ContainerView::new(handle.id.clone(), s, handle.meta.clone()));
        }
    }
    Ok(Json(views))
}

/// `GET /containers/:id` — single-container inspect, same shape as one
/// element of `list_containers`'s array.
pub async fn inspect_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<ContainerView>, AppError> {
    let handle = get_registered(&state, &id).await?;
    let s = registry::read_state(&state.run_dir, &id)
        .await
        .with_context(|| format!("reading state.json for {id}"))?;
    Ok(Json(ContainerView::new(id, s, handle.meta)))
}

// ===========================================================================
// Task 10: exec (WS bridge) + top
// ===========================================================================
//
// `POST /containers/:id/exec` in the plan's own words is spawned directly —
// NOT via `kestrel-shim` — because a one-off exec session has no durability
// requirement (no "reconnect after kestreld restart" story the way the
// entrypoint's `attach.sock` needs). But an exec session's whole point is
// interactive/streamed I/O with a real exit-code report at the end, which a
// plain request/response HTTP call can't carry — so THIS implementation
// exposes it as `WS /containers/:id/exec` (a GET request that upgrades to a
// websocket) rather than a literal `POST` that returns immediately. The
// plan's own Task 10 Step 1 text says to bridge this "over the SAME
// WS-attach mechanism as the entrypoint" — i.e. Task 12's attach.sock
// bridge — but Task 12 doesn't exist yet at this point in the task
// sequence (Task 10 only depends on Task 9), so that literal instruction
// isn't satisfiable as written. A WS handshake is inherently an HTTP GET
// per RFC 6455 regardless, so `GET /containers/:id/exec` upgrading to a
// websocket is the closest honest reading: this is its own small,
// self-contained bridge, deliberately NOT coupled to the not-yet-built
// `attach` mechanism, reusing none of that later task's (not yet
// existing) code.
//
// **Protocol** (documented here since there's no separate spec doc section
// for it yet): the client connects to `GET /containers/:id/exec` with the
// `Upgrade: websocket` header. Immediately after the upgrade, the client
// MUST send exactly one WS Text message shaped `{"cmd":["echo","hi"],
// "tty":false}` (`tty` optional, defaults to `false`) — chosen over a query
// param because a command is a list of arbitrary strings (spaces, leading
// hyphens, ...) that would need ad hoc encoding in a query string, whereas a
// JSON array is the natural, unambiguous shape and WS already gives us a
// message channel for free. The server then spawns `kestrel-runtime
// --run-dir <run_dir> --data-dir <data_dir> exec <id> -- <cmd...>` (same
// corrected global-flags-before-subcommand order as every other lifecycle
// invocation in this crate), relays every byte of the exec'd process's
// combined stdout+stderr back as WS Binary messages as it's produced, and
// (tty sessions only — see design doc §5's identical non-tty carve-out for
// `attach`) relays WS Binary messages FROM the client into the process's
// stdin. Once the process exits, the server sends one final WS Text control
// message `{"type":"exit","exit_code":<N or null>}` and closes the socket.
// A malformed/missing init message gets a `{"type":"error","message":"..."}`
// control message instead, then the socket closes.

#[derive(Debug, Deserialize)]
struct ExecInit {
    cmd: Vec<String>,
    #[serde(default)]
    tty: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExecControlMessage {
    Exit { exit_code: Option<i32> },
    Error { message: String },
}

async fn send_exec_control<S>(sink: &mut S, msg: &ExecControlMessage)
where
    S: Sink<Message> + Unpin,
{
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = sink.send(Message::Text(json.into())).await;
    }
}

/// `GET /containers/:id/exec` (WS upgrade). Existence is checked BEFORE the
/// upgrade so an unknown id gets a real HTTP `404` (via `AppError`), not a
/// WS connection that immediately errors out — matching every other
/// endpoint's `get_registered` convention.
pub async fn exec_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    get_registered(&state, &id).await?;
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = run_exec_session(socket, &state, &id).await {
            tracing::warn!(id, error = %e, "exec session ended with an error");
        }
    }))
}

/// Small, deliberately-scoped duplicate of `kestrel_shim::io::allocate`'s
/// PTY branch (see that function's own doc comment in
/// `crates/kestrel-shim/src/io.rs`) — pulling in a cross-crate dependency on
/// `kestrel-shim` for ~15 lines wasn't judged worth it (plan Task 10's own
/// note). `kestreld` only ever needs the PTY case duplicated here: exec's
/// non-tty case uses `tokio::process::Command`'s own `Stdio::piped()`
/// directly (see `spawn_exec_child` below), which is already async-native
/// and doesn't need this crate to hand-roll raw-fd plumbing the way the
/// shim's long-lived, multi-attach-client broadcast design requires.
///
/// Mirrors `io::allocate`'s Task 2 fix: the returned master fd is already
/// set `O_NONBLOCK` here (required before wrapping it in
/// `tokio::io::unix::AsyncFd`, which does not set this itself) — a
/// duplicated copy of this function that forgot that step would silently
/// break the read loop below.
fn allocate_pty() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let result = nix::pty::openpty(None, None).context("openpty")?;
    set_pty_master_nonblocking(&result.master).context("set PTY master non-blocking")?;
    Ok((result.master, result.slave))
}

fn set_pty_master_nonblocking(fd: &OwnedFd) -> anyhow::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let raw = fd.as_raw_fd();
    let current = fcntl(raw, FcntlArg::F_GETFL).context("fcntl F_GETFL")?;
    let current = OFlag::from_bits_truncate(current);
    fcntl(raw, FcntlArg::F_SETFL(current | OFlag::O_NONBLOCK)).context("fcntl F_SETFL O_NONBLOCK")?;
    Ok(())
}

/// Reads into `buf` from `fd`, following the same `AsyncFd` pattern
/// `kestrel-shim/src/daemon.rs::read_from_fd` documents and uses for its own
/// PTY master read loop (loop on `readable()` + `try_io`, retrying on
/// `WouldBlock`) — duplicated here for the same small-and-self-contained
/// reason `allocate_pty` above is.
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
/// `WouldBlock` the same way `read_from_fd` handles readability — same
/// duplication rationale.
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

/// Builds the `kestrel-runtime --run-dir <run_dir> --data-dir <data_dir>
/// exec <id> -- <cmd...>` command — same corrected global-flags-before-
/// subcommand order as `runtime_cli::run_kestrel_runtime` and
/// `spawn_shim_and_create`. The `--` separator matches the plan's literal
/// invocation text; empirically confirmed (during this task's own
/// implementation, via a throwaway `clap` parse probe against the real
/// `Cli`/`Command::Exec` struct) that clap strips a bare `--` token from a
/// `trailing_var_arg` positional rather than treating it as part of the
/// command — `exec <id> -- echo hi` and `exec <id> echo hi` parse
/// identically to `command = ["echo", "hi"]`, so including it here is safe,
/// not just cosmetic.
fn build_exec_command(state: &AppState, id: &str, argv: &[String]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&state.runtime_path);
    cmd.arg("--run-dir")
        .arg(&state.run_dir)
        .arg("--data-dir")
        .arg(&state.data_dir)
        .arg("exec")
        .arg(id)
        .arg("--")
        .args(argv)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    cmd
}

/// Reads the client's required first WS message: a Text frame shaped
/// `{"cmd":[...],"tty":bool}`. Bounded by a timeout so a client that upgrades
/// and then never sends anything can't hold an exec session (and its
/// subprocess-to-be) open forever.
async fn read_exec_init(socket: &mut WebSocket) -> anyhow::Result<ExecInit> {
    let msg = tokio::time::timeout(Duration::from_secs(10), socket.recv())
        .await
        .context("timed out waiting for the exec init message")?
        .context("client closed the connection before sending an exec init message")?
        .context("reading exec init websocket message")?;
    match msg {
        Message::Text(text) => {
            let init: ExecInit =
                serde_json::from_str(&text).with_context(|| format!("parsing exec init message: {text:?}"))?;
            anyhow::ensure!(!init.cmd.is_empty(), "exec init message's \"cmd\" must not be empty");
            Ok(init)
        }
        other => anyhow::bail!(
            "expected a Text init message shaped {{\"cmd\":[...],\"tty\":bool}}, got {other:?}"
        ),
    }
}

/// Duplicates `fd` (`nix::unistd::dup`) into a `std::process::Stdio` the
/// spawned child can own independently of `kestreld`'s own copy — same
/// technique `kestrel-shim/src/main.rs`'s own `dup` closure uses to wire a
/// PTY slave into all three of a child's stdio fds.
///
/// SAFETY: `raw` is a valid, open fd this function just obtained from a
/// successful `dup(2)` call and immediately, exclusively hands off to
/// `Stdio::from_raw_fd` — nothing else observes or closes `raw` in between,
/// so `Stdio` becomes its sole owner with no aliasing or double-close risk.
fn dup_as_stdio(fd: &OwnedFd) -> anyhow::Result<Stdio> {
    let raw = nix::unistd::dup(fd.as_raw_fd()).context("dup pty slave")?;
    Ok(unsafe { Stdio::from_raw_fd(raw) })
}

/// Runs one full exec session end to end: reads the init message, spawns
/// `kestrel-runtime exec`, bridges its I/O over `socket` until the process
/// exits, reports the exit code, and closes the socket.
///
/// **Why the output drain is never raced against `child.wait()`:** this
/// deliberately does NOT `tokio::select!` the output-forwarding loop against
/// `child.wait()` — doing so could report an exit before the last chunk of
/// output written right before the process died has actually been read and
/// forwarded (a real, easy-to-get-wrong race). Instead, an internal
/// `mpsc` channel's producer side is held by every output-reading task
/// (PTY master read loop, or the two piped-stdout/stderr read loops); once
/// EVERY producer has hit EOF/EIO and dropped its sender, the channel itself
/// closes, and only THEN does the single consumer loop below finish
/// draining and move on to `child.wait()` — which is guaranteed to resolve
/// essentially immediately at that point, since EOF/EIO on the process's own
/// stdio already means every copy of those fds (including the process's
/// own) is closed, which only happens once the process has itself exited.
async fn run_exec_session(mut socket: WebSocket, state: &AppState, id: &str) -> anyhow::Result<()> {
    let init = match read_exec_init(&mut socket).await {
        Ok(init) => init,
        Err(e) => {
            send_exec_control(&mut socket, &ExecControlMessage::Error { message: e.to_string() }).await;
            let _ = socket.close().await;
            return Err(e);
        }
    };

    let mut cmd = build_exec_command(state, id, &init.cmd);

    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let mut pty_master: Option<Arc<AsyncFd<OwnedFd>>> = None;
    let mut child;

    if init.tty {
        let (master, slave) = allocate_pty()?;
        cmd.stdin(dup_as_stdio(&slave)?)
            .stdout(dup_as_stdio(&slave)?)
            .stderr(dup_as_stdio(&slave)?);
        child = cmd.spawn().context("spawning kestrel-runtime exec (tty)")?;
        // Close kestreld's own original slave copy now that the child has
        // its own independently dup'd copies — see `io.rs::into_daemon_io`'s
        // doc comment (same reasoning applies verbatim here): an unclosed
        // original would keep the PTY "open" from the kernel's point of
        // view forever, masking the EOF/EIO this whole bridge depends on.
        drop(slave);

        let master = Arc::new(AsyncFd::new(master).context("registering pty master with reactor")?);
        pty_master = Some(master.clone());

        let tx = output_tx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match read_from_fd(&master, &mut buf).await {
                    Ok(0) => break,                                         // defensive; PTYs signal via EIO, not 0
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // last slave closed
                    Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    } else {
        child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning kestrel-runtime exec")?;
        let stdout = child.stdout.take().context("kestrel-runtime exec's stdout was not piped")?;
        let stderr = child.stderr.take().context("kestrel-runtime exec's stderr was not piped")?;

        let tx_out = output_tx.clone();
        tokio::spawn(read_pipe_to_channel(stdout, tx_out));
        let tx_err = output_tx.clone();
        tokio::spawn(read_pipe_to_channel(stderr, tx_err));
    }
    // Drop this function's own original sender — the channel only closes
    // once every clone held by the spawned reader task(s) above ALSO drops,
    // which happens exactly when those tasks see EOF/EIO and return.
    drop(output_tx);

    let (mut ws_sink, mut ws_stream) = socket.split();

    // Write-direction (client -> process stdin): tty only, per design doc
    // §5's identical non-tty carve-out for `attach` — a non-tty exec's
    // stdin is `/dev/null` (see `build_exec_command`), so there is no
    // meaningful path for client-sent bytes to go; they're read and
    // dropped so the socket stays responsive to a client `Close` regardless.
    let input_master = pty_master.clone();
    let input_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            match msg {
                Message::Binary(bytes) => {
                    if let Some(master) = &input_master {
                        if write_to_fd(master, &bytes).await.is_err() {
                            break;
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Read-direction: drain every output chunk to the client, in order,
    // until every producer above has finished (see this function's own doc
    // comment for why this is never raced against `child.wait()`).
    while let Some(chunk) = output_rx.recv().await {
        if ws_sink.send(Message::Binary(chunk.into())).await.is_err() {
            break;
        }
    }

    input_task.abort();

    let status = child.wait().await.context("waiting on kestrel-runtime exec")?;
    let exit_code = status.code();

    send_exec_control(&mut ws_sink, &ExecControlMessage::Exit { exit_code }).await;
    let _ = ws_sink.close().await;

    Ok(())
}

/// Reads one piped child stdio stream (stdout or stderr) to completion,
/// forwarding each chunk read into `tx` — mirrors `kestrel-shim/src/
/// daemon.rs::read_stream_loop`'s "read until EOF" shape, but simpler:
/// `tokio::process::Child{Stdout,Stderr}` are already `AsyncRead` directly
/// (tokio wires their non-blocking-ness itself), so no manual `AsyncFd`
/// plumbing is needed here the way the PTY branch above requires.
async fn read_pipe_to_channel(mut reader: impl tokio::io::AsyncRead + Unpin, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------
// Task 10 Step 2: GET /containers/:id/top
// ---------------------------------------------------------------------
//
// Genuinely NEW recursive `/proc` tree-walking code — NOT a reuse of
// `kestrel_runtime::start::resolve_entrypoint_host_pid`, which is a private,
// single-target, single-level lookup (first child of ONE specific pid, with
// its own retry/zombie-detection logic tuned for "has kestrel-init forked
// its entrypoint yet") unsuitable for (and not exposed for) enumerating an
// entire process tree. This walks `/proc/<pid>/task/*/children` — note the
// glob over EVERY thread id under `task/`, not just the main thread, since
// a multi-threaded process's children can be reparented across any of its
// threads — recursively from the entrypoint's host pid down.

#[derive(Debug, Serialize)]
pub struct TopEntry {
    /// The process's real pid as seen from the host's (kestreld's own) pid
    /// namespace — what a host-side `kill`/`/proc/<pid>` would use.
    pub host_pid: i32,
    /// The SAME process's pid as seen from inside the container's own
    /// (innermost) pid namespace — what a command running INSIDE the
    /// container would see as its own pid.
    pub container_pid: i32,
    /// Best-effort `/proc/<pid>/comm` (process/command name) — empty string
    /// if unreadable (e.g. the process exited between being discovered by
    /// the tree walk and this read; see `read_nspid_and_comm`'s doc comment).
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct TopResponse {
    pub processes: Vec<TopEntry>,
}

/// `GET /containers/:id/top`.
pub async fn top_container(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<TopResponse>, AppError> {
    get_registered(&state, &id).await?;
    let s = registry::read_state(&state.run_dir, &id)
        .await
        .with_context(|| format!("reading state.json for {id}"))?;
    let entrypoint_host_pid = s.pid.ok_or_else(|| {
        AppError::bad_request(format!(
            "container {id} has no recorded pid yet (not started?) — nothing to walk"
        ))
    })?;

    // `/proc` reads below are ordinary blocking syscalls (`std::fs`, not
    // `tokio::fs`) — genuinely fast per-call, but a real container can have
    // many processes, and this is still blocking I/O; run it on a blocking
    // thread rather than the async reactor thread, matching this crate's
    // other `spawn_blocking`-wrapped filesystem-walk convention
    // (`registry::read_state`).
    let processes = tokio::task::spawn_blocking(move || collect_top_entries(entrypoint_host_pid))
        .await
        .map_err(|e| AppError::internal(format!("top: process-tree walk task panicked: {e}")))?;

    Ok(Json(TopResponse { processes }))
}

fn collect_top_entries(entrypoint_host_pid: i32) -> Vec<TopEntry> {
    let mut host_pids = Vec::new();
    let mut seen = HashSet::new();
    collect_host_pids_recursive(entrypoint_host_pid, &mut host_pids, &mut seen);

    host_pids
        .into_iter()
        .filter_map(|host_pid| {
            // A process discovered by the walk below can legitimately have
            // exited (and been reaped) by the time we get here — the
            // container's process tree is live and changing throughout this
            // whole function. Skip it rather than erroring the whole
            // response over one racy process.
            let (container_pid, command) = read_nspid_and_comm(host_pid)?;
            Some(TopEntry { host_pid, container_pid, command })
        })
        .collect()
}

/// Recursively walks `/proc/<pid>/task/*/children`, appending every host pid
/// discovered (including `pid` itself) to `out`. `seen` guards against a
/// pid being visited twice (e.g. a pid getting reused mid-walk on a very
/// busy system — defensive, not expected in practice) rather than looping
/// forever or double-reporting it.
fn collect_host_pids_recursive(pid: i32, out: &mut Vec<i32>, seen: &mut HashSet<i32>) {
    if !seen.insert(pid) {
        return;
    }
    out.push(pid);

    let Ok(task_entries) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return; // process gone (or never had a /proc entry) by the time we got here
    };
    for task_entry in task_entries.flatten() {
        let tid = task_entry.file_name();
        let children_path = format!("/proc/{pid}/task/{}/children", tid.to_string_lossy());
        let Ok(content) = std::fs::read_to_string(&children_path) else {
            continue; // this thread/task gone; other threads' children lists still checked
        };
        for child_str in content.split_whitespace() {
            if let Ok(child_pid) = child_str.parse::<i32>() {
                collect_host_pids_recursive(child_pid, out, seen);
            }
        }
    }
}

/// Reads `/proc/<host_pid>/status`'s `NSpid` line and `/proc/<host_pid>/
/// comm`. Real, confirmed `proc(5)` semantics (verified empirically during
/// this task's implementation, not just assumed from the doc text): when
/// read by a process in an ANCESTOR pid namespace (kestreld, running in the
/// host/root namespace, reading about a process nested inside a container's
/// pid namespace), `NSpid` lists that process's pid as seen from EVERY pid
/// namespace between the reader's own and the process's own, starting with
/// the reader-visible (host) pid and ending with the pid as seen in the
/// process's own (innermost/deepest) namespace — confirmed live via `sudo
/// unshare --pid --fork --mount-proc sleep 5` plus reading `/proc/<host
/// -pid>/status` from the host shell: `NSpid: <host-pid> 1` (the `sleep`
/// process really was pid 1 inside its own fresh pid namespace). A process
/// NOT in any nested pid namespace at all reports a single value (confirmed
/// the same way, without `unshare`: plain `NSpid: <pid>`) — handled below by
/// simply taking the LAST whitespace-separated value, which is correct
/// (equal to the host pid) whether there are 1 or many values, rather than
/// indexing `[1]` and risking an out-of-bounds panic on the single-value
/// case.
fn read_nspid_and_comm(host_pid: i32) -> Option<(i32, String)> {
    let status = std::fs::read_to_string(format!("/proc/{host_pid}/status")).ok()?;
    let nspid_line = status.lines().find(|l| l.starts_with("NSpid:"))?;
    let container_pid = nspid_line
        .split_whitespace()
        .skip(1) // "NSpid:" label itself
        .filter_map(|tok| tok.parse::<i32>().ok())
        .last()?;

    let comm = std::fs::read_to_string(format!("/proc/{host_pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    Some((container_pid, comm))
}
