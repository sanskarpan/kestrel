mod api;
mod bundle;
mod copyup_scanner;
mod events;
mod leak_sweep;
mod metrics;
mod network;
mod registry;
mod runtime_cli;

use std::collections::HashMap;
use std::future::IntoFuture;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::{mpsc, RwLock};

use kestreld::Config;
use registry::{read_meta, ContainerHandle, Registry};

const DEFAULT_CONFIG_PATH: &str = "/etc/kestrel/config.toml";

/// Shared state every HTTP handler in `api::*` reads through axum's
/// `State` extractor: the two real, durable filesystem roots
/// (`kestrel-runtime`'s own `run_dir`/`data_dir` convention), the in-
/// memory container registry (design doc §3), and the resolved,
/// absolute paths of the two sibling binaries `POST /containers` (Task 8)
/// spawns — resolved once at startup (`resolve_sibling_binary`) rather
/// than re-resolved per request.
pub struct AppState {
    pub run_dir: PathBuf,
    pub data_dir: PathBuf,
    pub registry: Registry,
    pub shim_path: PathBuf,
    pub runtime_path: PathBuf,
    /// `config.daemon.stop_grace_period_s` (Task 6), read by `POST
    /// /containers/:id/stop` (Task 9): how long to wait after SIGTERM
    /// before escalating to SIGKILL.
    pub stop_grace_period_s: u64,
    /// The receiving half of the metrics sampler's `MetricsSignal`
    /// channel (`metrics::spawn`, Task 13) — wrapped in a `tokio::sync::
    /// Mutex` since `mpsc::Receiver` isn't `Clone` and only ever needs
    /// ONE consumer draining it: `events::spawn_consumer` (Task 14),
    /// spawned once at startup right after this `AppState` is built,
    /// locks this and `.recv()`s from it for the daemon's entire
    /// lifetime — see that function's own doc comment.
    pub metrics_rx: tokio::sync::Mutex<mpsc::Receiver<metrics::MetricsSignal>>,
    /// The real event bus (Task 14, SPEC.md §13's `### Events` section):
    /// every lifecycle handler in `api::containers` publishes directly
    /// onto this, and `events::spawn_consumer`'s background task
    /// publishes onto it too, translating Task 13's `MetricsSignal`s.
    /// `GET /events` (`events::get_events`) subscribes a fresh receiver
    /// from this same sender to serve one SSE stream per connected
    /// client.
    pub event_bus: events::EventBus,
    /// Shared with the metrics sampler's own background task
    /// (`metrics::spawn`) — see `metrics::LastStatusMap`'s own doc
    /// comment for the real, reproduced stop-then-delete race this
    /// sharing exists to close. `api::containers::delete_container` is
    /// this field's one real consumer outside `metrics.rs` itself.
    pub last_status_map: metrics::LastStatusMap,
    /// `config.network` (Task 6's `NetworkConfig`), read by `network.rs`
    /// (Task 17) for the bridge name / subnet / gateway / iptables-enabled
    /// knobs the post-create veth/bridge/NAT attachment sequence and
    /// delete-time teardown both need. Stored as the whole struct (rather
    /// than exploded into individual `AppState` fields) since it's always
    /// consumed together and already has a real `Default` impl, keeping
    /// every test call site's own addition to a single line.
    pub network: kestreld::config::NetworkConfig,
    /// Task 19: the per-container seccomp-violation ring buffer `GET
    /// /containers/:id/seccomp` reads from — fed by `spawn_seccomp_log_
    /// consumer` (`api::introspect`), the one real, always-on subscriber
    /// to `Event::SeccompViolation` off `event_bus` above, spawned once at
    /// startup right after this `AppState` is built (same "subscribe
    /// before anything can publish" ordering `events::spawn_consumer`
    /// already requires). See `api::introspect::SeccompLog`'s own doc
    /// comment for the full shape, including a real, documented
    /// limitation in what it can observe.
    pub seccomp_log: api::introspect::SeccompLog,
}

/// Builds the real `axum::Router` this daemon serves — factored out of
/// `main()` so this crate's own root-gated tests can drive the exact same
/// router (via `tower::ServiceExt::oneshot`) instead of only calling a
/// handler function directly, genuinely proving the route is reachable
/// the way a real client would reach it. `pub(crate)` (rather than
/// private to this file) since Task 11's own `api::logs` tests need it
/// too, for the same "genuinely reachable via HTTP, not just a direct
/// handler call" reason — every other module's tests so far happened to
/// live in this file, this is just the first one that doesn't.
pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/containers",
            post(api::containers::create_container).get(api::containers::list_containers),
        )
        .route(
            "/containers/{id}",
            get(api::containers::inspect_container).delete(api::containers::delete_container),
        )
        .route("/containers/{id}/start", post(api::containers::start_container))
        .route("/containers/{id}/stop", post(api::containers::stop_container))
        .route("/containers/{id}/kill", post(api::containers::kill_container))
        .route("/containers/{id}/pause", post(api::containers::pause_container))
        .route("/containers/{id}/unpause", post(api::containers::unpause_container))
        // Task 10: exec is a WS upgrade (GET, not POST — see
        // `api::containers::exec_container`'s own doc comment for why); top
        // is a plain GET.
        .route("/containers/{id}/exec", get(api::containers::exec_container))
        .route("/containers/{id}/top", get(api::containers::top_container))
        // Task 11: tail (+ optional `?since=`/`?tail=`) or, with
        // `?follow=true`, an SSE live stream of `output.jsonl`.
        .route("/containers/{id}/logs", get(api::logs::get_logs))
        // Task 12: attach is a WS upgrade (GET), same "WS handshake is
        // inherently an HTTP GET" reasoning as Task 10's exec endpoint;
        // resize is a plain POST that sends one RESIZE frame and
        // disconnects (`api::attach`'s own doc comment).
        .route("/containers/{id}/attach", get(api::attach::attach_container))
        .route("/containers/{id}/resize", post(api::attach::resize_container))
        // Task 14: the real event bus's SSE endpoint.
        .route("/events", get(events::get_events))
        // Task 17: the persisted bridge-mode `NetworkInfo` for one
        // container, and the daemon-wide bridge/subnet/container-IP
        // aggregation across all of them.
        .route("/containers/{id}/network", get(api::network::get_container_network))
        .route("/system/topology", get(api::network::get_topology))
        // Task 18: introspection endpoints, part A (namespaces, cgroup,
        // pressure, mounts, capabilities).
        .route("/containers/{id}/namespaces", get(api::introspect::get_namespaces))
        .route("/containers/{id}/cgroup", get(api::introspect::get_cgroup))
        .route("/containers/{id}/pressure", get(api::introspect::get_pressure))
        .route("/containers/{id}/mounts", get(api::introspect::get_mounts))
        .route("/containers/{id}/caps", get(api::introspect::get_caps))
        // Task 19: introspection endpoints, part B (layers, copyups,
        // seccomp, system-wide namespace graph).
        .route("/containers/{id}/layers", get(api::introspect::get_layers))
        .route("/containers/{id}/copyups", get(api::introspect::get_copyups))
        .route("/containers/{id}/seccomp", get(api::introspect::get_seccomp))
        .route("/system/namespaces", get(api::introspect::get_system_namespaces))
        // Task 20: image endpoints. `/images/dedup` is registered as its
        // own literal route alongside the dynamic `/images/{reference}`
        // one — axum/matchit's documented static-over-dynamic routing
        // priority (proven directly by `api::images`'s own
        // `test_dedup_route_is_not_shadowed_by_the_dynamic_reference_route`)
        // is what keeps `GET /images/dedup` from ever being mis-routed to
        // `get_image` with `reference == "dedup"`.
        .route("/images/pull", post(api::images::pull_image_endpoint))
        .route("/images", get(api::images::list_images))
        .route("/images/dedup", get(api::images::get_dedup))
        .route(
            "/images/{reference}",
            get(api::images::get_image).delete(api::images::delete_image),
        )
        .route("/images/{reference}/layers", get(api::images::get_image_layers))
        .with_state(state)
}

/// Resolves a workspace sibling binary (`kestrel-shim`, `kestrel-runtime`)
/// by name. Mirrors `kestrel_net::netns::resolve_helper_path`'s and
/// `kestrel-runtime`'s own `create.rs::resolve_kestrel_init_path`'s
/// established convention: binaries built by this workspace's `cargo
/// build` end up next to each other (`target/<profile>/`, or — under
/// `cargo test`, whose own binary lives in `target/<profile>/deps/` — that
/// directory's parent), so the well-known layout is checked directly
/// rather than requiring an explicit `--bin-dir` config flag.
///
/// `CARGO_BIN_EXE_<name>` is checked first purely for parity with that
/// same convention, though it is NOT expected to ever actually be set for
/// these two specific binaries: Cargo only populates it for `[[bin]]`
/// targets of the SAME package as the test/bench binary being run, and
/// `kestrel-shim`/`kestrel-runtime` are separate workspace crates from
/// `kestreld`.
pub(crate) fn resolve_sibling_binary(name: &str) -> Result<PathBuf> {
    let env_var = format!("CARGO_BIN_EXE_{name}");
    if let Ok(p) = std::env::var(&env_var) {
        return Ok(PathBuf::from(p));
    }

    let current_exe = std::env::current_exe().context("resolving current_exe")?;
    let exe_dir = current_exe.parent().context("current_exe has no parent dir")?;

    let sibling = exe_dir.join(name);
    if sibling.is_file() {
        return Ok(sibling);
    }

    if let Some(grandparent) = exe_dir.parent() {
        let candidate = grandparent.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "could not locate {name} binary near {} (checked {} and its parent dir) — \
         build the workspace first (e.g. `cargo build --workspace`)",
        current_exe.display(),
        exe_dir.display()
    );
}

/// Matches `kestrel-runtime`'s own `tracing_subscriber::fmt()` init
/// convention (see `crates/kestrel-runtime/src/main.rs`), so logs from both
/// binaries are shaped the same way and both honor `RUST_LOG`.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

/// Minimal `--config <path>` parsing. No other flags exist yet, and this
/// crate deliberately doesn't take on a CLI-parsing dependency (`clap`) for
/// a single optional flag — later tasks can promote this if the surface
/// grows.
fn parse_config_path(args: impl Iterator<Item = String>) -> Result<PathBuf> {
    let mut args = args.skip(1); // skip argv[0]
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .context("--config requires a path argument")?;
                config_path = PathBuf::from(value);
            }
            other if other.starts_with("--config=") => {
                config_path = PathBuf::from(&other["--config=".len()..]);
            }
            other => {
                anyhow::bail!("unrecognized argument: {other}");
            }
        }
    }
    Ok(config_path)
}

/// Remove a stale Unix socket file left behind by a previous, uncleanly
/// terminated run so `UnixListener::bind` doesn't fail with "address in
/// use" on restart. Only removes an actual socket file, never a directory
/// or a regular file, so a misconfigured `socket` path fails loudly instead
/// of silently deleting user data.
///
/// Critically, the mere presence of a socket file does not mean it is
/// stale: a socket file also exists for a live, healthy listener. Before
/// unlinking, this probes the path with a real `connect(2)` (via
/// `UnixStream::connect`) to tell the two cases apart:
///   - connect succeeds => a process is actively listening; this is NOT
///     stale, and removing it would silently steal the socket out from
///     under a running `kestreld` instance. Refuse to start instead.
///   - connect fails with `ConnectionRefused` => the socket file is a
///     leftover from a crashed/killed process with nothing listening
///     behind it anymore; safe to remove.
fn remove_stale_socket(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    anyhow::bail!(
                        "socket at {} is already in use by a running kestreld instance \
                         — refusing to start",
                        path.display()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)
                        .with_context(|| format!("removing stale socket {}", path.display()))?;
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("probing socket {}", path.display()));
                }
            }
        }
        Ok(_) => {
            anyhow::bail!(
                "refusing to bind: {} exists and is not a socket",
                path.display()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("stat-ing {}", path.display()));
        }
    }
    Ok(())
}

/// State recovery (design doc §3, plan Task 7 Step 2): scans
/// `<run_dir>/*/state.json`. For each real container directory (one that
/// actually has a `state.json` — `run_dir` also holds non-container
/// entries like `netns/`, which `leak_sweep` handles separately) whose
/// status is not `Stopped` (a stopped container has no live shim to
/// reconnect to, and nothing to recover), rebuilds a `ContainerHandle`
/// from the real, persisted `state.json` and `meta.json` — never a
/// placeholder.
async fn recover_registry(run_dir: &Path, data_dir: &Path) -> Result<Registry> {
    let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
    let mut entries = tokio::fs::read_dir(run_dir)
        .await
        .with_context(|| format!("reading run_dir {}", run_dir.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let id = entry.file_name().to_string_lossy().into_owned();
        let state_path = entry.path().join("state.json");
        if !state_path.exists() {
            continue; // not a container dir (e.g. `netns/`) — leak_sweep handles genuine orphans
        }
        let Ok(state) = kestrel_oci::state::State::read(&state_path) else {
            continue;
        };
        if state.status == kestrel_oci::state::Status::Stopped {
            continue; // no live shim to reconnect to, nothing to recover
        }
        let attach_sock = run_dir.join(&id).join("attach.sock");
        let shim_alive = tokio::net::UnixStream::connect(&attach_sock).await.is_ok();
        let meta = read_meta(data_dir, &id).await; // real tty/network metadata, not a placeholder
        tracing::info!(
            id,
            shim_alive,
            status = ?state.status,
            tty = meta.tty,
            "recovered container from state.json"
        );
        registry.write().await.insert(
            id.clone(),
            ContainerHandle {
                id,
                bundle_path: state.bundle,
                meta,
            },
        );
    }
    Ok(registry)
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config_path = parse_config_path(std::env::args())?;
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    tracing::info!(
        socket = %config.daemon.socket,
        http_addr = %config.daemon.http_addr,
        "starting kestreld"
    );

    // State recovery + leak sweep (CHECKLIST's two 🔴 daemon items), run
    // before ever binding a listener: a client connecting the instant
    // kestreld starts serving must see an already-consistent registry, not
    // one racing recovery/cleanup in the background.
    let run_dir = PathBuf::from(&config.daemon.state_dir);
    let data_dir = PathBuf::from(&config.daemon.data_dir);
    tokio::fs::create_dir_all(&run_dir)
        .await
        .with_context(|| format!("creating run_dir {}", run_dir.display()))?;
    tokio::fs::create_dir_all(&data_dir)
        .await
        .with_context(|| format!("creating data_dir {}", data_dir.display()))?;

    let registry = recover_registry(&run_dir, &data_dir)
        .await
        .with_context(|| format!("recovering container registry from {}", run_dir.display()))?;
    let recovered_count = registry.read().await.len();

    let leaked_cleaned = leak_sweep::run(&run_dir, &data_dir, &registry).await;

    tracing::info!(
        recovered = recovered_count,
        leaked_cleaned,
        "{recovered_count} containers recovered, {leaked_cleaned} leaked resources cleaned"
    );

    // Resolved once here (Task 8), not per-request — `POST /containers`
    // spawns these two as real subprocesses (`api::containers::
    // create_container`).
    let shim_path = resolve_sibling_binary("kestrel-shim").context("locating kestrel-shim binary")?;
    let runtime_path =
        resolve_sibling_binary("kestrel-runtime").context("locating kestrel-runtime binary")?;

    // Task 13: the ONE metrics/status-transition/OOM/PSI/throttle poller
    // the whole daemon uses — see `metrics.rs`'s own module doc comment.
    // `cgroups_root` mirrors the SAME `<data_dir>/cgroups` convention
    // every other cgroup-touching path in this codebase already uses
    // (`kestrel-runtime`'s own create/kill/pause/resume/delete, this
    // crate's own `leak_sweep`) — not `config.cgroup.root`.
    // Shared with `api::containers::delete_container` (via `AppState`
    // below) — see `metrics::LastStatusMap`'s own doc comment for why a
    // fast stop-then-delete sequence needs this to be the SAME map the
    // sampler's own tick loop uses, not two independent copies.
    let last_status_map = metrics::new_last_status_map();
    let metrics_rx = metrics::spawn(
        registry.clone(),
        run_dir.clone(),
        data_dir.join("cgroups"),
        std::time::Duration::from_millis(config.daemon.metrics_interval_ms),
        config.cgroup.psi_trigger_stall_us,
        config.cgroup.psi_trigger_window_us,
        last_status_map.clone(),
    );

    let app_state = Arc::new(AppState {
        run_dir: run_dir.clone(),
        data_dir: data_dir.clone(),
        registry: registry.clone(),
        shim_path,
        runtime_path,
        stop_grace_period_s: config.daemon.stop_grace_period_s,
        metrics_rx: tokio::sync::Mutex::new(metrics_rx),
        event_bus: events::new_bus(),
        last_status_map,
        network: config.network.clone(),
        seccomp_log: api::introspect::SeccompLog::new(),
    });
    // Task 14: the one real consumer of `metrics_rx` for the daemon's
    // entire lifetime — see `events::spawn_consumer`'s own doc comment.
    events::spawn_consumer(app_state.clone());

    // Task 19: the one real, always-on consumer of `Event::
    // SeccompViolation` for the daemon's entire lifetime, feeding
    // `AppState.seccomp_log` — spawned here, immediately after the event
    // bus it subscribes to is built, so no real violation published later
    // can ever be missed (a `broadcast` channel only delivers to
    // receivers that already existed at publish time).
    api::introspect::spawn_seccomp_log_consumer(app_state.event_bus.clone(), app_state.seccomp_log.clone());

    // Task 15: the copy-up scanner — its own, separate, slower-cadence
    // background poller (`config.storage.copyup_scan_interval_s`,
    // default 5s), genuinely independent of Task 13's 1Hz metrics
    // sampler tick above. See `copyup_scanner.rs`'s own module doc
    // comment for how it resolves each running container's upperdir/
    // lower chain-ids without needing Task 19's future `layers.json`.
    copyup_scanner::spawn(
        registry.clone(),
        run_dir.clone(),
        data_dir.clone(),
        std::time::Duration::from_secs(config.storage.copyup_scan_interval_s),
        app_state.event_bus.clone(),
    );

    let router = build_router(app_state);

    let socket_path = Path::new(&config.daemon.socket);
    remove_stale_socket(socket_path)?;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {}", parent.display()))?;
    }
    let unix_listener = tokio::net::UnixListener::bind(socket_path)
        .with_context(|| format!("binding unix socket {}", socket_path.display()))?;
    let tcp_listener = tokio::net::TcpListener::bind(&config.daemon.http_addr)
        .await
        .with_context(|| format!("binding tcp listener {}", config.daemon.http_addr))?;

    tracing::info!("kestreld listening (unix + tcp)");

    // Task 21 (design doc §10): graceful shutdown on SIGTERM. Both
    // listeners get their own `.with_graceful_shutdown(shutdown_signal())`
    // — axum's own mechanism to stop ACCEPTING new connections the moment
    // the given future resolves, while letting whatever requests are
    // already in flight finish naturally, then return. There is
    // DELIBERATELY no explicit container-teardown step anywhere in this
    // shutdown path: per design doc §10, a container's process tree is
    // never a child of `kestreld` (that indirection, via the daemonized
    // `kestrel-shim`, is the entire point of the shim architecture — see
    // design doc §2) — nothing about a running container depends on this
    // process staying alive, so "graceful shutdown" here genuinely means
    // only "stop serving HTTP cleanly", never "stop containers". Once both
    // `axum::serve` futures return (both have drained their in-flight
    // requests), `try_join!` resolves and `main()` returns, exiting the
    // process — containers, and their owning `kestrel-shim`s, keep running
    // completely undisturbed.
    tokio::try_join!(
        axum::serve(unix_listener, router.clone().into_make_service())
            .with_graceful_shutdown(shutdown_signal())
            .into_future(),
        axum::serve(tcp_listener, router.into_make_service())
            .with_graceful_shutdown(shutdown_signal())
            .into_future(),
    )?;

    tracing::info!("kestreld shut down gracefully");

    Ok(())
}

/// Resolves the moment `kestreld` itself receives a real `SIGTERM` —
/// awaited independently by BOTH `axum::serve(...).with_graceful_shutdown`
/// calls above, one per listener (Task 21, design doc §10).
///
/// Calling `tokio::signal::unix::signal` more than once for the SAME
/// `SignalKind` is safe and correct, not a race for exclusive ownership of
/// the signal: each call registers its own independent listener against
/// tokio's single, shared, per-process signal driver, and EVERY registered
/// listener is notified when the signal actually arrives (this is a
/// broadcast, not a single-consumer channel) — so one real `SIGTERM`
/// delivered to this process correctly resolves BOTH listeners' shutdown
/// futures, not just whichever one happened to register first.
async fn shutdown_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            sigterm.recv().await;
            tracing::info!("received SIGTERM, starting graceful shutdown");
        }
        Err(e) => {
            // Not expected in practice, but must not silently resolve
            // immediately (which would make every request racy against an
            // instant "shutdown") if it somehow does happen — pending
            // forever here just means graceful shutdown never triggers,
            // matching pre-Task-21 behavior (the process only stops via an
            // ungraceful signal like SIGKILL), which is a safe fallback.
            tracing::error!(error = %e, "failed to install SIGTERM handler; graceful shutdown disabled");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[test]
    fn default_config_path_when_no_args() {
        let args = vec!["kestreld".to_string()];
        let path = parse_config_path(args.into_iter()).unwrap();
        assert_eq!(path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn explicit_config_flag_with_space() {
        let args = vec![
            "kestreld".to_string(),
            "--config".to_string(),
            "/tmp/foo.toml".to_string(),
        ];
        let path = parse_config_path(args.into_iter()).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/foo.toml"));
    }

    #[test]
    fn explicit_config_flag_with_equals() {
        let args = vec!["kestreld".to_string(), "--config=/tmp/bar.toml".to_string()];
        let path = parse_config_path(args.into_iter()).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/bar.toml"));
    }

    #[test]
    fn unrecognized_argument_errors() {
        let args = vec!["kestreld".to_string(), "--bogus".to_string()];
        assert!(parse_config_path(args.into_iter()).is_err());
    }

    /// Reproduces exactly what a crashed/killed process leaves behind: a
    /// socket file on disk with nothing listening on it anymore (the
    /// `UnixListener`'s fd is closed via `drop`, but — matching real OS
    /// behavior — the socket's dirent is never auto-unlinked). This is the
    /// genuinely-stale case, and `remove_stale_socket` must clear it so a
    /// fresh bind at the same path succeeds.
    #[test]
    fn test_remove_stale_socket_removes_genuinely_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kestreld.sock");

        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener); // simulate a crashed process: fd closed, file left behind

        assert!(path.exists(), "socket file should still be on disk after drop");

        remove_stale_socket(&path).expect("genuinely stale socket should be removed cleanly");

        // A fresh bind at the same path must now succeed.
        let fresh = std::os::unix::net::UnixListener::bind(&path);
        assert!(
            fresh.is_ok(),
            "rebinding after removing a genuinely stale socket should succeed: {fresh:?}"
        );
    }

    /// Reproduces the original bug: a second instance pointed at the same
    /// socket path while a first instance is alive and actively listening.
    /// `remove_stale_socket` must detect the live listener via a connect
    /// probe, refuse to unlink, and return an error — leaving the original
    /// listener completely untouched and still functional.
    #[test]
    fn test_refuses_to_steal_live_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kestreld.sock");

        // "Instance A": a real, live listener that stays alive for the
        // whole test.
        let live_listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        // "Instance B" attempting to start against the same path.
        let result = remove_stale_socket(&path);
        assert!(
            result.is_err(),
            "remove_stale_socket must refuse to touch a live listener's socket"
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("already in use"),
            "error message should clearly explain the collision, got: {message}"
        );

        // The socket file must not have been removed.
        assert!(
            path.exists(),
            "live socket file must still exist after the refused removal attempt"
        );

        // And instance A's listener must still be genuinely functional:
        // a client can connect and instance A can accept the connection.
        let client = std::os::unix::net::UnixStream::connect(&path)
            .expect("original live listener should still accept new connections");
        let accepted = live_listener.accept();
        assert!(
            accepted.is_ok(),
            "original listener should still be able to accept: {accepted:?}"
        );
        drop(client);
    }

    /// Task 13 added a required `metrics_rx` field to `AppState`. Every
    /// test in this module below constructs an `AppState` for something
    /// entirely unrelated to the metrics sampler, so they just need SOME
    /// valid receiver to satisfy the type — an idle channel with no
    /// sender-side task ever spawned against it is exactly that: cheap,
    /// and (per `metrics.rs`'s own `publish` doc comment) an
    /// undrained/senderless channel is an explicitly supported,
    /// non-error state, not a footgun these tests need to worry about.
    fn idle_metrics_rx() -> tokio::sync::Mutex<mpsc::Receiver<metrics::MetricsSignal>> {
        tokio::sync::Mutex::new(mpsc::channel(1).1)
    }

    /// Task 14 added a required `event_bus` field to `AppState`. Every
    /// test in this module below that doesn't care about `GET /events`
    /// just needs a real, valid sender to satisfy the type — same
    /// "cheap, no receiver required" reasoning `idle_metrics_rx` above
    /// already documents for its own field.
    fn idle_event_bus() -> events::EventBus {
        events::new_bus()
    }

    // -------------------------------------------------------------------
    // Task 7: recover_registry / leak_sweep::run — root-gated
    // -------------------------------------------------------------------
    //
    // These reuse `kestrel-runtime`'s own established root-gated
    // test-fixture pattern (`crates/kestrel-runtime/tests/
    // create_pins_namespaces.rs`): a stub `kestrel-init` (this crate's
    // own `[[bin]] kestreld-fixture-stub-init`, installed as a sibling
    // `kestrel-init` of the test binary) that blocks forever once
    // `kestrel_runtime::create::create` execs into it, giving a real,
    // on-disk `state.json` (status `Created`, a real pid) without needing
    // the full, statically-linked real `kestrel-init`.

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }

    struct CgroupGuard(kestrel_cgroup::manager::CgroupManager);
    impl Drop for CgroupGuard {
        fn drop(&mut self) {
            let _ = self.0.destroy();
        }
    }

    /// Kills (SIGKILL) and reaps the stub container process on drop —
    /// it blocks forever, so a panic in any assertion must not leak it.
    struct ProcessGuard(nix::unistd::Pid);
    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.0, None);
        }
    }

    /// Kills (SIGKILL) any `kestrel-shim` process for this container's
    /// `id` on drop — `ProcessGuard` above only knows about a container's
    /// own entrypoint (`init_pid`); it has no idea a SEPARATE, daemonized
    /// `kestrel-shim` process exists alongside it, spawned by
    /// `api::containers::spawn_shim_and_create` and deliberately never
    /// `wait()`ed (see that function's own doc comment — the shim
    /// `setsid()`s and outlives the call by design). A panic/failed
    /// assertion between that spawn and this test's own end-of-test
    /// cleanup previously leaked exactly this: a real, root-owned,
    /// reparented-to-PID-1 shim still holding a live kernel seccomp-notify
    /// fd open forever — reproduced and root-caused via direct `/proc/
    /// <pid>/fd` inspection of a live orphan during this task's own
    /// adversarial review. The shim's own pid is never captured by
    /// `spawn_shim_and_create` (`child` is dropped, unwaited, right after
    /// the status handshake), so matching by container id in its argv
    /// (`kestrel-shim --id <id> ...`) — the same technique this test used
    /// for its own manual end-of-test cleanup before this guard existed —
    /// is the only way to find and kill it after the fact. Best-effort,
    /// idempotent, safe to race against an already-exited shim (matches
    /// `MountGuard`/`ProcessGuard`'s own posture).
    struct ShimGuard(String);
    impl Drop for ShimGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("pkill")
                .args(["-9", "-f", &format!("kestrel-shim --id {} ", self.0)])
                .status();
        }
    }

    /// Best-effort cleanup, on drop, of everything about a real
    /// container's on-disk footprint that a killed shim/entrypoint doesn't
    /// itself remove: the namespace pins under `<run_dir>/<id>/ns/*`
    /// (`unpin_default_namespaces`) and the data-dir artifacts under
    /// `<data_dir>/{bundles,snapshots,containers}/<id>` plus the layer
    /// store's own `bundle-<id>` scratch layer
    /// (`cleanup_real_container_artifacts`). Exists so a panicking
    /// assertion mid-test doesn't leak these the way it previously could —
    /// a successful, explicit `delete()` (or this test's own explicit
    /// end-of-test cleanup) already does the same work itself, so this
    /// guard running afterward too is a harmless no-op, matching
    /// `MountGuard`/`ProcessGuard`'s own "cheap, idempotent, best-effort"
    /// convention.
    struct ContainerArtifactsGuard {
        run_dir: PathBuf,
        id: String,
    }
    impl Drop for ContainerArtifactsGuard {
        fn drop(&mut self) {
            unpin_default_namespaces(&self.run_dir, &self.id);
            cleanup_real_container_artifacts(&self.id);
        }
    }

    /// Installs this crate's own `kestreld-fixture-stub-init` `[[bin]]` as
    /// a sibling of THIS test binary, named literally `kestrel-init` —
    /// matching `kestrel-runtime`'s `create.rs::resolve_kestrel_init_path`
    /// sibling-binary convention. Same copy-to-tmp-then-rename
    /// race-safety technique as `create_pins_namespaces.rs`'s own
    /// `install_stub_kestrel_init`.
    /// Locates the `kestreld-fixture-stub-init` `[[bin]]` artifact this
    /// crate's own `Cargo.toml` builds.
    ///
    /// `CARGO_BIN_EXE_<name>` (checked first) is confirmed EMPIRICALLY
    /// (Task 7) to NOT be set — at compile time via `env!()`, nor even as
    /// a runtime `std::env::var` — for a package's own `#[cfg(test)]`
    /// unit tests embedded in `src/main.rs`/`src/lib.rs`; Cargo only
    /// populates it for genuine integration-test/bench binaries under
    /// `tests/`/`benches/`. (`kestrel-net`'s `netns.rs::CARGO_BIN_ENV_VAR`
    /// doc comment describes the same variable working for ITS tests —
    /// but every one of those call sites is itself an integration test
    /// under `tests/netns.rs`, not a `src/`-embedded unit test like this
    /// one, so that precedent does not actually cover this case.) Falls
    /// back to the deterministic build location instead: this unit test
    /// binary's own `current_exe()` resolves to
    /// `target/debug/deps/kestreld-<hash>`, whose grandparent
    /// (`target/debug/`, NOT the immediate `deps/` parent) is exactly
    /// where a plain `[[bin]]` target artifact like this fixture lands —
    /// same resolution shape as `kestrel_net::netns::resolve_helper_path`'s
    /// own documented fallback tier.
    fn resolve_stub_init_fixture_path() -> PathBuf {
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_kestreld-fixture-stub-init") {
            return PathBuf::from(p);
        }
        let current_exe = std::env::current_exe().expect("current_exe");
        let deps_dir = current_exe
            .parent()
            .expect("current_exe has a parent dir (deps/)");
        let target_debug_dir = deps_dir
            .parent()
            .expect("deps/ dir has a parent dir (target/debug/)");
        let candidate = target_debug_dir.join("kestreld-fixture-stub-init");
        assert!(
            candidate.is_file(),
            "kestreld-fixture-stub-init fixture binary not found at {} — run `cargo build -p \
             kestreld --bin kestreld-fixture-stub-init` (or a full `cargo test -p kestreld`) first",
            candidate.display()
        );
        candidate
    }

    fn install_stub_kestrel_init() -> PathBuf {
        let stub = resolve_stub_init_fixture_path();
        let current_exe = std::env::current_exe().expect("current_exe");
        let sibling_dir = current_exe
            .parent()
            .expect("current_exe has a parent directory")
            .to_path_buf();
        let target = sibling_dir.join("kestrel-init");
        let tmp = sibling_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
        std::fs::copy(&stub, &tmp).expect("copy kestreld-fixture-stub-init to tmp");
        std::fs::rename(&tmp, &target).expect("rename tmp into place as sibling kestrel-init");
        target
    }

    /// A minimal-but-real bundle: `default_namespaces()` minus `Mount`
    /// (this Lima VM cannot bind-mount mount namespaces at all — see
    /// `create_pins_namespaces.rs`'s own module doc comment for the full
    /// story) plus `User`, and a trivial identity uid/gid map so
    /// `create()`'s createRuntime hook step (none configured here)
    /// trivially succeeds and the go-ahead to exec the stub is always
    /// sent.
    fn bundle_with_namespaces(bundle_dir: &Path) -> kestrel_runtime::bundle::Bundle {
        std::fs::create_dir_all(bundle_dir.join("rootfs")).expect("mkdir rootfs");

        let mut namespaces = kestrel_oci::default_spec::default_namespaces();
        namespaces.retain(|ns| ns.typ() != kestrel_oci::runtime::LinuxNamespaceType::Mount);
        namespaces.push(
            kestrel_oci::runtime::LinuxNamespaceBuilder::default()
                .typ(kestrel_oci::runtime::LinuxNamespaceType::User)
                .build()
                .expect("build user namespace"),
        );

        let mut spec = kestrel_oci::default_spec::default_spec();
        let uid_mapping = kestrel_oci::runtime::LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(nix::unistd::getuid().as_raw())
            .size(1u32)
            .build()
            .expect("build uid mapping");
        let gid_mapping = kestrel_oci::runtime::LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(nix::unistd::getgid().as_raw())
            .size(1u32)
            .build()
            .expect("build gid mapping");
        let linux = kestrel_oci::runtime::LinuxBuilder::default()
            .namespaces(namespaces)
            .uid_mappings(vec![uid_mapping])
            .gid_mappings(vec![gid_mapping])
            .build()
            .expect("build linux section");
        spec.set_linux(Some(linux));

        kestrel_runtime::bundle::Bundle {
            path: bundle_dir.to_path_buf(),
            spec: kestrel_oci::raw::RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        }
    }

    /// Mounts a real cgroup2 view at `data_dir/cgroups` (same technique
    /// `kestrel-runtime`'s own root-gated tests use) and returns a fresh
    /// `run_dir` tempdir alongside it.
    fn setup_dirs(id: &str, data_dir: &Path) -> (tempfile::TempDir, MountGuard, CgroupGuard) {
        let cgroups_mount = data_dir.join("cgroups");
        std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
        let mount_status = std::process::Command::new("mount")
            .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
            .status()
            .expect("spawning mount(8)");
        assert!(
            mount_status.success(),
            "mounting a second cgroup2 view at {} failed — this test must run as root",
            cgroups_mount.display()
        );
        let mount_guard = MountGuard(cgroups_mount.clone());

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let cgroup_guard = CgroupGuard(
            kestrel_cgroup::manager::CgroupManager::new(cgroups_mount, id).expect("valid cgroup id"),
        );

        (run_dir, mount_guard, cgroup_guard)
    }

    /// Proves the recovery gap the daemon design doc closes: a container
    /// created by a "previous kestreld" that then crashed (never cleaned
    /// up) must be found by `recover_registry`, with `meta.tty` read back
    /// from a REAL `meta.json` — not defaulted to `false`.
    #[test]
    #[ignore = "requires root"]
    fn test_recover_registry_finds_crashed_container_with_real_meta() {
        kestrel_ns::test_util::run_isolated(|| {
            install_stub_kestrel_init();

            let id = format!("kestreld-recover-{}", nix::unistd::getpid().as_raw());
            let data_dir = tempfile::tempdir().expect("data_dir tempdir");
            let (run_dir, _mount_guard, cgroup_guard) = setup_dirs(&id, data_dir.path());

            let bundle_dir = tempfile::tempdir().expect("bundle_dir tempdir");
            let bundle = bundle_with_namespaces(bundle_dir.path());

            // ---- simulate a "previous kestreld" that created a container
            // and then crashed: create() succeeds, nothing cleans it up ----
            let create_result =
                kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
            assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

            let state_path = run_dir.path().join(&id).join("state.json");
            let state = kestrel_oci::state::State::read(&state_path).expect("read state.json");
            assert_eq!(state.status, kestrel_oci::state::Status::Created);
            let init_pid =
                nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
            let process_guard = ProcessGuard(init_pid);

            // Real meta.json, written directly by this test (Task 8 is the
            // one that writes it in production) — the exact shape
            // `ContainerMeta` serializes to.
            let meta_path = registry::meta_path(data_dir.path(), &id);
            std::fs::create_dir_all(meta_path.parent().unwrap()).expect("mkdir meta parent");
            std::fs::write(
                &meta_path,
                serde_json::to_vec(&registry::ContainerMeta {
                    tty: true,
                    ..Default::default()
                })
                .expect("serialize meta"),
            )
            .expect("write meta.json");

            let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
            let (recovered, reread_state) = rt.block_on(async {
                let registry = recover_registry(run_dir.path(), data_dir.path())
                    .await
                    .expect("recover_registry");
                let map = registry.read().await;
                let handle = map.get(&id).cloned();
                let reread = registry::read_state(run_dir.path(), &id)
                    .await
                    .expect("read_state");
                (handle, reread)
            });

            let handle = recovered.expect("crashed container should be recovered");
            assert_eq!(handle.id, id);
            assert_eq!(handle.bundle_path, bundle.path);
            assert!(
                handle.meta.tty,
                "meta.tty should round-trip as true from the real meta.json, not default to false"
            );
            assert_eq!(reread_state.status, kestrel_oci::state::Status::Created);

            // ---- cleanup: kill the stub init (it blocks forever), unpin
            // every namespace `create()` bind-mounted under
            // `run_dir/<id>/ns/*`, then tear down the cgroup/tempdir
            // guards — same order and technique as
            // `create_pins_namespaces.rs`'s own cleanup (lines ~330-339 in
            // that file). Without this, the pins stay busy and
            // `TempDir::drop`'s internal `remove_dir_all` silently fails,
            // leaking both the nsfs bind mounts and the tempdir itself.
            drop(process_guard);
            let ns_dir = run_dir.path().join(&id).join("ns");
            let ns_types = [
                kestrel_ns::types::NsType::Pid,
                kestrel_ns::types::NsType::Net,
                kestrel_ns::types::NsType::Ipc,
                kestrel_ns::types::NsType::Uts,
                kestrel_ns::types::NsType::Cgroup,
                kestrel_ns::types::NsType::User,
            ];
            for ns in ns_types {
                let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
            }
            drop(cgroup_guard);
        });
    }

    /// Leaves an orphaned cgroup dir behind (no matching registry entry,
    /// no `state.json` anywhere for it) and proves `leak_sweep::run`
    /// finds and destroys it.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_leak_sweep_destroys_orphaned_cgroup() {
        let id = format!("kestreld-leak-{}", std::process::id());
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");

        let cgroups_mount = data_dir.path().join("cgroups");
        std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
        let mount_status = std::process::Command::new("mount")
            .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
            .status()
            .expect("spawning mount(8)");
        assert!(
            mount_status.success(),
            "mounting a second cgroup2 view at {} failed — this test must run as root",
            cgroups_mount.display()
        );
        let _mount_guard = MountGuard(cgroups_mount.clone());

        let cgroup = kestrel_cgroup::manager::CgroupManager::new(cgroups_mount, &id)
            .expect("valid cgroup id");
        cgroup.create().expect("create orphaned cgroup");
        assert!(cgroup.path.exists(), "orphaned cgroup dir should exist before the sweep");

        // Empty registry — nothing claims this cgroup, so it's a genuine
        // orphan.
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));

        let cleaned = leak_sweep::run(run_dir.path(), data_dir.path(), &registry).await;
        assert!(cleaned >= 1, "expected at least the orphaned cgroup to be cleaned, got {cleaned}");
        assert!(
            !cgroup.path.exists(),
            "orphaned cgroup dir should have been destroyed by leak_sweep::run"
        );
    }

    // -------------------------------------------------------------------
    // Task 8: POST /containers — real end-to-end kestreld -> kestrel-shim
    // -> kestrel-runtime create — root-gated
    // -------------------------------------------------------------------
    //
    // Unlike every test above, these spawn REAL, separate subprocesses
    // (`kestrel-shim`, itself exec-ing `kestrel-runtime`) via
    // `resolve_sibling_binary` rather than calling `kestrel_runtime::
    // create::create` in-process — so, unlike Task 7's own tests, no
    // `kestrel_ns::test_util::run_isolated` fork-isolation is needed here:
    // THIS process never itself calls `unshare()`, only the subprocess
    // does, in its own single process. A plain `#[tokio::test]` is enough.
    //
    // Prerequisites (build once before running):
    // ```text
    // cargo build -p kestrel-shim -p kestrel-runtime -p kestrel-init -p kestrel-net --bins
    // ```
    // (or a full `cargo build --workspace`) — these tests locate the real
    // `kestrel-shim`/`kestrel-runtime`/`netns-helper` binaries at
    // `target/debug/` via the exact same `resolve_sibling_binary`
    // production code path `main()` itself uses at startup.

    /// The real `kestrel-runtime` binary (spawned by `kestrel-shim`)
    /// resolves `kestrel-init` as a sibling of ITS OWN `current_exe()` —
    /// i.e. `target/debug/kestrel-init`, NOT a sibling of THIS test
    /// binary (that's Task 7's `install_stub_kestrel_init`, for the
    /// different in-process-`create()`-call case). Nothing else in this
    /// workspace's test suite resolves `kestrel-init` from this exact
    /// directory — `create_from_layers.rs`/`lifecycle.rs` use the
    /// explicit `--target aarch64-unknown-linux-gnu` static-build
    /// directory instead — so overwriting it here for test purposes
    /// cannot regress any other test.
    fn target_debug_dir() -> PathBuf {
        let current_exe = std::env::current_exe().expect("current_exe");
        current_exe
            .parent()
            .expect("current_exe has a parent dir (deps/)")
            .parent()
            .expect("deps/ dir has a parent dir (target/debug/)")
            .to_path_buf()
    }

    fn install_stub_kestrel_init_at_target_debug() {
        let stub = resolve_stub_init_fixture_path();
        let target_debug_dir = target_debug_dir();
        let target = target_debug_dir.join("kestrel-init");
        let tmp = target_debug_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
        std::fs::copy(&stub, &tmp).expect("copy kestreld-fixture-stub-init to tmp");
        std::fs::rename(&tmp, &target).expect("rename tmp into place as target/debug/kestrel-init");
    }

    fn resolve_test_binary(name: &str) -> PathBuf {
        resolve_sibling_binary(name).unwrap_or_else(|e| {
            panic!(
                "{e}\nRun `cargo build -p kestrel-shim -p kestrel-runtime -p kestrel-init \
                 -p kestrel-net --bins` (or `cargo build --workspace`) first."
            )
        })
    }

    async fn poll_until<T, F: FnMut() -> Option<T>>(timeout: std::time::Duration, mut probe: F) -> Option<T> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(v) = probe() {
                return Some(v);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Mounts a real cgroup2 view under `data_dir/cgroups` — same
    /// technique as `setup_dirs` above, duplicated because that helper
    /// also constructs an id-keyed `CgroupManager` this flow doesn't need
    /// (the real `kestrel-runtime` subprocess builds its own).
    fn mount_cgroups(data_dir: &Path) -> MountGuard {
        let cgroups_mount = data_dir.join("cgroups");
        std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
        let mount_status = std::process::Command::new("mount")
            .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
            .status()
            .expect("spawning mount(8)");
        assert!(
            mount_status.success(),
            "mounting a second cgroup2 view at {} failed — this test must run as root",
            cgroups_mount.display()
        );
        MountGuard(cgroups_mount)
    }

    /// Real proof of Task 8 Step 4's first scenario: `POST /containers`
    /// with a plain `bundle_rootfs` (no image pull involved) succeeds
    /// end to end through the real router, `kestrel-shim`, and
    /// `kestrel-runtime create` — `201` + a real id, `state.json` shows
    /// `Created`, `attach.sock` is connectable (the shim is genuinely
    /// alive), and `meta.json` carries the real `tty` value.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_post_containers_with_bundle_rootfs_creates_container_end_to_end() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task8").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": true,
        });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = tower::ServiceExt::oneshot(app, request)
            .await
            .expect("router oneshot");
        let status = response.status();
        let response_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            status,
            axum::http::StatusCode::CREATED,
            "unexpected response: {}",
            String::from_utf8_lossy(&response_bytes)
        );

        let parsed: serde_json::Value = serde_json::from_slice(&response_bytes).expect("parse response JSON");
        let id = parsed["id"].as_str().expect("response has a real id").to_string();
        assert!(!id.is_empty());

        // ---- state.json shows Created ----
        let state_path = run_dir.path().join(&id).join("state.json");
        let state = kestrel_oci::state::State::read(&state_path).expect("read state.json");
        assert_eq!(state.status, kestrel_oci::state::Status::Created);
        let init_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        let process_guard = ProcessGuard(init_pid);

        // ---- attach.sock is connectable (shim genuinely alive) ----
        // The shim daemonizes AFTER writing its status-handshake line
        // (which already happened, synchronously, before `create_container`
        // returned 201 above) — a small poll absorbs the tiny remaining
        // race between that handshake and `daemon::run`'s own
        // `UnixListener::bind` a few lines later.
        let attach_sock = run_dir.path().join(&id).join("attach.sock");
        let connected = poll_until(std::time::Duration::from_secs(10), || {
            std::os::unix::net::UnixStream::connect(&attach_sock).ok()
        })
        .await;
        assert!(
            connected.is_some(),
            "attach.sock at {} never became connectable — shim not alive?",
            attach_sock.display()
        );

        // ---- meta.json carries the real tty value ----
        let meta = registry::read_meta(data_dir.path(), &id).await;
        assert!(meta.tty, "meta.json's tty should be true, matching the request");

        // ---- registry updated ----
        assert!(registry.read().await.contains_key(&id), "registry should contain the new container");

        // ---- cleanup: kill the stub init, unpin every namespace
        // create() pinned under run_dir/<id>/ns/* (default mode: Pid,
        // Net, Ipc, Uts, Cgroup all genuinely created+pinned; Mount is
        // tolerated-EINVAL on this VM and was never actually pinned, but
        // unpinning a never-pinned path is a harmless no-op here) —
        // without this, `TempDir::drop`'s `remove_dir_all` would silently
        // fail against a still-busy nsfs bind mount. ----
        drop(process_guard);
        let ns_dir = run_dir.path().join(&id).join("ns");
        for ns in [
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Net,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ] {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }
    }

    /// Real proof of Task 8 Step 4's second scenario: `POST /containers`
    /// with `network_mode: "bridge"` genuinely creates a NEW network
    /// namespace (`kestrel_net::netns::create_netns`) and joins the
    /// container to it via Task 4's real `NamespacePlan.join` mechanism —
    /// the first real, full-HTTP-path proof that gap-fill actually works,
    /// not just in `kestrel-ns`'s own isolated `join_by_path.rs` tests.
    ///
    /// multi_thread (Task 17 update): `POST /containers` in bridge mode
    /// now ALSO runs Task 17's real post-create veth/bridge attachment
    /// (`network::attach`), which calls `kestrel_net::veth::attach_veth`'s
    /// `tokio::task::block_in_place` — same "needs a multi-threaded
    /// runtime" requirement as Task 17's own
    /// `test_bridge_network_containers_reach_each_other_and_survive_restart`,
    /// now applying here too since this test exercises the same
    /// `network_mode: "bridge"` HTTP path.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires root"]
    async fn test_post_containers_with_bridge_network_mode_joins_new_netns() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        // `create_netns` (kestrel-net) needs its own sibling `netns-helper`
        // binary, resolved via the identical sibling-of-current_exe/
        // grandparent convention as `resolve_sibling_binary` here — built
        // by the same `cargo build --workspace` prerequisite.
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task8-bridge").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "network_mode": "bridge",
        });
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = tower::ServiceExt::oneshot(app, request)
            .await
            .expect("router oneshot");
        let status = response.status();
        let response_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            status,
            axum::http::StatusCode::CREATED,
            "unexpected response: {}",
            String::from_utf8_lossy(&response_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&response_bytes).expect("parse response JSON");
        let id = parsed["id"].as_str().expect("response has a real id").to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let state = kestrel_oci::state::State::read(&state_path).expect("read state.json");
        assert_eq!(state.status, kestrel_oci::state::Status::Created);
        let init_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        let process_guard = ProcessGuard(init_pid);

        // ---- THE assertion this test exists for: the container's net
        // namespace genuinely differs from the host's, AND matches the
        // pin `create_netns` created — proving Task 4's join-by-path
        // mechanism actually ran through the full HTTP path, not just in
        // isolation (kestrel-ns's own join_by_path.rs). ----
        fn ns_inode(path: &Path) -> u64 {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path)
                .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
                .ino()
        }
        let host_net_inode = ns_inode(Path::new("/proc/self/ns/net"));
        let container_net_ns_path = format!("/proc/{}/ns/net", init_pid.as_raw());
        let container_net_inode = ns_inode(Path::new(&container_net_ns_path));
        let pinned_net_inode = ns_inode(&run_dir.path().join("netns").join(&id));

        assert_ne!(
            container_net_inode, host_net_inode,
            "container's network namespace must NOT be the host's own — a silently-dropped \
             join (the pre-Task-4 bug) would produce exactly this"
        );
        assert_eq!(
            container_net_inode, pinned_net_inode,
            "container's network namespace must match the pin create_netns created and \
             config.json referenced, proving the join actually reached it"
        );

        // ---- cleanup ----
        drop(process_guard);
        let ns_dir = run_dir.path().join(&id).join("ns");
        // Net is deliberately excluded here: in bridge mode it was
        // JOINED (`plan.join`), not created (`plan.create`), so
        // `pin_namespaces` never pins a second copy under `ns_dir` for
        // it — the only netns pin that exists is `run_dir/netns/<id>`,
        // torn down separately below.
        for ns in [
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ] {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }
        let _ = kestrel_net::netns::teardown_netns(run_dir.path(), &id);

        // Task 17 update: this request now ALSO runs the real post-create
        // veth/bridge/NAT attachment sequence (`network::attach`) against
        // the DEFAULT `NetworkConfig` (`AppState::network`'s own default
        // in this test, since it isn't overridden) — i.e. a REAL
        // `kestrel0` bridge, a real host-side veth, and (default
        // `iptables: true`) real `KESTREL-*` iptables chains/rules and
        // `net.ipv4.ip_forward`/`route_localnet` sysctls, none of which
        // existed before Task 17 landed. Clean all of it up so this test
        // doesn't leave global, VM-wide network state behind for a LATER
        // test run to trip over — the same host-side-veth/bridge/NAT
        // teardown Task 17's own test performs for its own,
        // test-specific bridge name.
        let (connection, handle, _) = rtnetlink::new_connection().expect("rtnetlink connection");
        tokio::spawn(connection);
        let (host_if, _) = kestrel_net_veth_names_for_test(&id);
        if let Ok(Some(idx)) = kestrel_net::bridge::find_link_index(&handle, &host_if).await {
            let _ = handle.link().del(idx).execute().await;
        }
        let _ = kestrel_net::bridge::delete_bridge(&handle, "kestrel0").await;
        let _ = kestrel_net::nat::teardown_all("kestrel0");
    }

    // -----------------------------------------------------------------
    // Task 17: network attachment (bridge mode) + /containers/:id/network
    // + /system/topology — root-gated
    // -----------------------------------------------------------------
    //
    // Real end-to-end proof: TWO bridge-mode containers created via the
    // real HTTP API (exercising Task 8's `create_netns`-at-create-time
    // step, Task 4's join mechanism, and THIS task's post-create
    // veth/bridge/NAT attachment together for the first time), confirmed
    // to reach each other directly over the bridge — same ping/TCP-based
    // proof technique `kestrel-net`'s own
    // `tests/lifecycle.rs::test_inter_container` uses: a dedicated OS
    // thread `nsenter`s into each container's REAL, `kestreld`-managed
    // netns pin (`<run_dir>/netns/<id>`, the exact path `network::attach`
    // itself used) and proves direct L2 reachability, so this is
    // confirming the attachment sequence produced a netns that is
    // genuinely connected, not just that the HTTP calls returned `201`.
    // `/containers/:id/network` reports the correct IPs; `/system/
    // topology` lists both under the same bridge; deleting one releases
    // its IPAM allocation for real (proven by re-allocating and observing
    // the exact same address come back — the only way to check this
    // without reaching into `Ipam`'s private fields); a simulated
    // `kestreld` restart (a fresh `recover_registry` against the same
    // `run_dir`/`data_dir`, matching what a real restart does) still
    // reports the surviving container's `NetworkInfo` correctly, proving
    // the `meta.json`-persistence half of this task's restart-durability
    // contribution.

    fn t17_network_config(bridge: &str) -> kestreld::config::NetworkConfig {
        kestreld::config::NetworkConfig {
            bridge: bridge.to_string(),
            subnet: "172.70.0.0/24".to_string(),
            gateway: "172.70.0.1".to_string(),
            mtu: 1500,
            // No NAT/masquerade/forwarding needed to prove same-bridge
            // container<->container reachability (pure L2 switching,
            // same scope `kestrel-net`'s own `test_inter_container`
            // proves) — left off so this test doesn't also mutate global
            // sysctl/iptables state it doesn't need for its own
            // assertions.
            iptables: false,
            rootless_backend: "pasta".to_string(),
        }
    }

    const T17_PING: &[u8; 4] = b"PING";
    const T17_PONG: &[u8; 4] = b"PONG";

    fn t17_accept_with_timeout(
        listener: &std::net::TcpListener,
        timeout: Duration,
    ) -> anyhow::Result<(std::net::TcpStream, std::net::SocketAddr)> {
        listener.set_nonblocking(true)?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    stream.set_nonblocking(false)?;
                    return Ok((stream, peer));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    anyhow::ensure!(std::time::Instant::now() < deadline, "timed out waiting for a connection");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Same technique as `kestrel-net/tests/lifecycle.rs::
    /// spawn_ping_pong_listener`: a plain OS thread (not a tokio task —
    /// `nsenter` only needs "runs on one dedicated OS thread for its
    /// duration", which a raw thread satisfies for free) `nsenter`s into
    /// `pin`, binds a TCP listener at `bind_addr`, signals readiness,
    /// accepts one connection, expects `PING`, replies `PONG`, and
    /// returns the observed peer address.
    fn t17_spawn_listener(
        pin: PathBuf,
        bind_addr: std::net::SocketAddr,
        ready_tx: std::sync::mpsc::Sender<()>,
    ) -> std::thread::JoinHandle<anyhow::Result<std::net::SocketAddr>> {
        std::thread::spawn(move || {
            kestrel_net::netns::nsenter(&pin, move || {
                let listener = std::net::TcpListener::bind(bind_addr)
                    .with_context(|| format!("binding {bind_addr}"))?;
                let _ = ready_tx.send(());
                let (mut stream, peer) = t17_accept_with_timeout(&listener, Duration::from_secs(10))?;
                let mut buf = [0u8; 4];
                std::io::Read::read_exact(&mut stream, &mut buf).context("reading PING")?;
                anyhow::ensure!(&buf == T17_PING, "expected PING, got {buf:?}");
                std::io::Write::write_all(&mut stream, T17_PONG).context("writing PONG")?;
                Ok(peer)
            })
        })
    }

    fn t17_connect_and_ping(target: std::net::SocketAddr) -> anyhow::Result<()> {
        let mut stream = std::net::TcpStream::connect(target).with_context(|| format!("connecting to {target}"))?;
        std::io::Write::write_all(&mut stream, T17_PING).context("writing PING")?;
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut stream, &mut buf).context("reading PONG")?;
        anyhow::ensure!(&buf == T17_PONG, "expected PONG, got {buf:?}");
        Ok(())
    }

    // multi_thread: `network::attach`'s call into `kestrel_net::veth::
    // attach_veth` uses `tokio::task::block_in_place` (required by
    // `nsenter`'s own "one dedicated OS thread" contract, `netns.rs`'s own
    // doc comment) — that call panics outright on the default
    // current-thread test runtime ("can call blocking only when running
    // on the multi-threaded runtime"), so this test needs the same
    // `flavor = "multi_thread"` every one of `kestrel-net`'s own
    // `tests/lifecycle.rs` scenarios already uses for the identical reason.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires root"]
    async fn test_bridge_network_containers_reach_each_other_and_survive_restart() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task17").expect("write marker");

        let network_cfg = t17_network_config("kbr-t17net");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path: shim_path.clone(),
            runtime_path: runtime_path.clone(),
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: network_cfg.clone(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state.clone());

        // ---- create two bridge-mode containers ----
        async fn create_one(app: Router, rootfs: &Path) -> String {
            let body = serde_json::json!({
                "bundle_rootfs": rootfs,
                "tty": false,
                "network_mode": "bridge",
            });
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/containers")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let response = tower::ServiceExt::oneshot(app, request).await.expect("router oneshot");
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("reading body");
            assert_eq!(
                status,
                axum::http::StatusCode::CREATED,
                "create failed: {}",
                String::from_utf8_lossy(&bytes)
            );
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("parse response JSON");
            parsed["id"].as_str().expect("response has a real id").to_string()
        }
        let id_a = create_one(app.clone(), rootfs_dir.path()).await;
        let id_b = create_one(app.clone(), rootfs_dir.path()).await;
        assert_ne!(id_a, id_b);

        fn pid_of(run_dir: &Path, id: &str) -> nix::unistd::Pid {
            let state_path = run_dir.join(id).join("state.json");
            let state = kestrel_oci::state::State::read(&state_path).expect("read state.json");
            assert_eq!(state.status, kestrel_oci::state::Status::Created);
            nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"))
        }
        let guard_a = ProcessGuard(pid_of(run_dir.path(), &id_a));
        let guard_b = ProcessGuard(pid_of(run_dir.path(), &id_b));
        // `ProcessGuard` only knows about each container's own entrypoint
        // (`init_pid`) — it has no idea a SEPARATE, daemonized
        // `kestrel-shim` process exists alongside it (spawned by
        // `spawn_shim_and_create`, deliberately never `wait()`ed). Without
        // this, a panic between here and this test's own end-of-test
        // cleanup would leak a real, root-owned, reparented-to-PID-1 shim
        // — see `ShimGuard`'s own doc comment (Task 7's tests, above) for
        // the full story; reused verbatim here for the same reason.
        let shim_guard_a = ShimGuard(id_a.clone());
        let shim_guard_b = ShimGuard(id_b.clone());

        // ---- GET /containers/:id/network reports the real, correct IPs ----
        async fn get_network(app: Router, id: &str) -> serde_json::Value {
            let request = axum::http::Request::builder()
                .method("GET")
                .uri(format!("/containers/{id}/network"))
                .body(axum::body::Body::empty())
                .unwrap();
            let response = tower::ServiceExt::oneshot(app, request).await.expect("router oneshot");
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("reading body");
            serde_json::from_slice(&bytes).expect("parse response JSON")
        }
        let network_a = get_network(app.clone(), &id_a).await;
        let network_b = get_network(app.clone(), &id_b).await;
        for network in [&network_a, &network_b] {
            assert_eq!(network["mode"], "bridge");
            assert_eq!(network["bridge_name"], "kbr-t17net");
            assert_eq!(network["gateway"], "172.70.0.1");
            assert!(network["ip"].as_str().is_some(), "network info must carry a real ip: {network:?}");
        }
        let ip_a: std::net::Ipv4Addr = network_a["ip"].as_str().unwrap().parse().expect("valid ipv4");
        let ip_b: std::net::Ipv4Addr = network_b["ip"].as_str().unwrap().parse().expect("valid ipv4");
        assert_ne!(ip_a, ip_b, "the two containers must get distinct IPs");

        // ---- GET /system/topology lists both under the same bridge ----
        let topology_request = axum::http::Request::builder()
            .method("GET")
            .uri("/system/topology")
            .body(axum::body::Body::empty())
            .unwrap();
        let topology_response = tower::ServiceExt::oneshot(app.clone(), topology_request)
            .await
            .expect("router oneshot");
        assert_eq!(topology_response.status(), axum::http::StatusCode::OK);
        let topology_bytes = axum::body::to_bytes(topology_response.into_body(), usize::MAX)
            .await
            .expect("reading body");
        let topology: serde_json::Value = serde_json::from_slice(&topology_bytes).expect("parse topology JSON");
        let bridges = topology["bridges"].as_array().expect("bridges array");
        let bridge_entry = bridges
            .iter()
            .find(|b| b["name"] == "kbr-t17net")
            .unwrap_or_else(|| panic!("expected a \"kbr-t17net\" bridge entry in topology, got {topology:?}"));
        let containers = bridge_entry["containers"].as_array().expect("containers array");
        for (id, ip) in [(&id_a, ip_a), (&id_b, ip_b)] {
            assert!(
                containers
                    .iter()
                    .any(|c| c["id"] == id.as_str() && c["ip"] == ip.to_string()),
                "expected container {id} (ip {ip}) in topology's bridge entry, got {containers:?}"
            );
        }

        // ---- the two containers can genuinely reach each other directly
        // over the bridge (pure L2 switching — no NAT anywhere in this
        // scenario, matching kestrel-net's own test_inter_container) ----
        let listen_addr = std::net::SocketAddr::new(ip_b.into(), 9300);
        let pin_b = run_dir.path().join("netns").join(&id_b);
        let pin_a = run_dir.path().join("netns").join(&id_a);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = t17_spawn_listener(pin_b.clone(), listen_addr, ready_tx);
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("listener in container B must become ready");
        let pin_a_for_client = pin_a.clone();
        tokio::task::spawn_blocking(move || {
            kestrel_net::netns::nsenter(&pin_a_for_client, move || t17_connect_and_ping(listen_addr))
        })
        .await
        .expect("client task panicked")
        .expect("container A must be able to connect directly to container B's bridge-assigned IP");
        let observed_peer = server
            .join()
            .expect("server thread panicked")
            .expect("server-side exchange must succeed");
        assert_eq!(
            observed_peer.ip(),
            std::net::IpAddr::V4(ip_a),
            "container B must observe container A's real bridge-assigned IP, unmodified by any NAT"
        );

        // ---- delete container B; confirm its NetworkInfo AND its IPAM
        // allocation are both released ----
        let delete_request = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/containers/{id_b}?force=true"))
            .body(axum::body::Body::empty())
            .unwrap();
        let delete_response = tower::ServiceExt::oneshot(app.clone(), delete_request)
            .await
            .expect("router oneshot");
        assert_eq!(delete_response.status(), axum::http::StatusCode::OK);
        drop(guard_b); // the real delete() already killed it; this is now a harmless no-op
        drop(shim_guard_b); // ditto — delete()'s teardown already ended B's shim

        let not_found_request = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/containers/{id_b}/network"))
            .body(axum::body::Body::empty())
            .unwrap();
        let not_found_response = tower::ServiceExt::oneshot(app.clone(), not_found_request)
            .await
            .expect("router oneshot");
        assert_eq!(
            not_found_response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "container B should be gone from the registry after delete"
        );

        {
            let subnet: ipnetwork::Ipv4Network = "172.70.0.0/24".parse().unwrap();
            let gateway: std::net::Ipv4Addr = "172.70.0.1".parse().unwrap();
            let mut ipam = kestrel_net::ipam::Ipam::load(
                subnet,
                gateway,
                network::ipam_state_path(data_dir.path()),
            )
            .expect("load real IPAM state");
            let reallocated = ipam.allocate("t17-release-probe").expect("allocate after release");
            assert_eq!(
                reallocated, ip_b,
                "container B's IP must have been genuinely released by delete — the next \
                 allocation (lowest-numbered free address) should be the exact same address, \
                 not some other still-free one"
            );
            ipam.release(reallocated).expect("release probe allocation");
        }

        // ---- simulate a kestreld restart: a fresh recover_registry
        // against the SAME run_dir/data_dir, then confirm the SURVIVING
        // container's /network still reports correctly — the real proof
        // that Task 17's persisted meta.json (not just the in-memory
        // registry) is what makes this durable across a restart. ----
        let recovered_registry = recover_registry(run_dir.path(), data_dir.path())
            .await
            .expect("recover_registry after simulated restart");
        assert!(
            recovered_registry.read().await.contains_key(&id_a),
            "surviving container A must be recovered after a simulated restart"
        );
        let app_state_2 = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: recovered_registry,
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: network_cfg,
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app_2 = build_router(app_state_2);
        let network_a_after_restart = get_network(app_2, &id_a).await;
        assert_eq!(
            network_a_after_restart, network_a,
            "container A's /network response must be byte-for-byte identical after a \
             simulated kestreld restart — proving meta.json persistence, not just an \
             in-memory registry entry, is what carries this across"
        );

        // ---- cleanup ----
        drop(guard_a);
        drop(shim_guard_a);
        let ns_dir = run_dir.path().join(&id_a);
        // Net is deliberately excluded: in bridge mode it was JOINED
        // (`plan.join`), not created (`plan.create`) — see the Task 8
        // bridge-mode test's own cleanup comment for the full reasoning.
        for ns in [
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ] {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join("ns").join(ns.proc_name()));
        }
        let _ = kestrel_net::netns::teardown_netns(run_dir.path(), &id_a);

        let (connection, handle, _) = rtnetlink::new_connection().expect("rtnetlink connection");
        tokio::spawn(connection);
        let (host_if_a, _) = kestrel_net_veth_names_for_test(&id_a);
        if let Ok(Some(idx)) = kestrel_net::bridge::find_link_index(&handle, &host_if_a).await {
            let _ = handle.link().del(idx).execute().await;
        }
        let _ = kestrel_net::bridge::delete_bridge(&handle, "kbr-t17net").await;
    }

    /// `kestrel_net::veth::veth_names` is `pub(crate)` to that crate, not
    /// exposed to callers outside it — this reproduces its exact naming
    /// formula (`"veth" + id[..min(8, id.len())]`, see that function's own
    /// doc comment) purely for this test's own end-of-test host-side veth
    /// cleanup, which has no other way to learn the interface name it
    /// needs to delete.
    fn kestrel_net_veth_names_for_test(id: &str) -> (String, String) {
        let host_if = format!("veth{}", &id[..id.len().min(8)]);
        let peer_if = format!("{host_if}p");
        (host_if, peer_if)
    }

    // -----------------------------------------------------------------
    // Task 9: lifecycle endpoints (start/stop/kill/pause/unpause/delete)
    // + list/inspect — root-gated
    // -----------------------------------------------------------------
    //
    // Unlike Task 8's own `POST /containers`-only tests, `start`/`stop`
    // need a container that ACTUALLY RUNS an entrypoint — `kestrel-init`
    // only forks the entrypoint after `kestrel-runtime start` unblocks the
    // exec FIFO, and Task 8's stub `kestrel-init` (which just blocks
    // forever, never reading the FIFO at all) cannot exercise that. These
    // tests therefore install the REAL, statically-linked `kestrel-init`
    // (`make build-kestrel-init-static`) plus the REAL, statically-linked
    // `lifecycle_fixture` (`make build-lifecycle-fixture-static`,
    // `crates/kestrel-runtime/tests/fixtures/lifecycle_fixture.rs` — this
    // Task adds a new `ignore-sigterm <secs>` mode to that SHARED fixture
    // for the grace-period test below), following the exact same
    // real-artifact precedent `crates/kestrel-runtime/tests/lifecycle.rs`
    // already established for `kestrel-runtime`'s own capstone.
    //
    // Prerequisites (build once before running):
    // ```text
    // make build-kestrel-init-static build-lifecycle-fixture-static
    // cargo build -p kestrel-shim -p kestrel-runtime --bins
    // ```
    //
    // **Why `data_dir` is the REAL `/var/lib/kestrel`, not a tempdir**:
    // same reason `kestrel-runtime/tests/lifecycle.rs`'s own module doc
    // comment gives — the REAL `kestrel-init` hardcodes its own
    // `data_dir` as the literal `/var/lib/kestrel` (see that file's
    // `main.rs`), so the HOST-side `data_dir` these tests pass to
    // `kestrel-runtime create` (via `AppState::data_dir`, which
    // `bundle.rs`/`spawn_shim_and_create` and every lifecycle endpoint all
    // read from) must match byte-for-byte or the container-side rootfs
    // staging looks in the wrong place and finds nothing. `run_dir`
    // remains a plain tempdir, same as that file — nothing in
    // `kestrel-init` hardcodes it.

    /// See this section's own doc comment for why this is NOT a tempdir.
    fn real_data_dir() -> PathBuf {
        PathBuf::from("/var/lib/kestrel")
    }

    /// Installs the REAL, statically-linked `kestrel-init` as
    /// `target/debug/kestrel-init` — the sibling location
    /// `kestrel_runtime::create::resolve_kestrel_init_path` resolves
    /// relative to the SEPARATELY-SPAWNED `kestrel-runtime` subprocess's
    /// own `current_exe()` (`target/debug/kestrel-runtime`, per
    /// `resolve_sibling_binary`'s convention), NOT relative to this test
    /// binary itself. Same shared-location reasoning as
    /// `install_stub_kestrel_init_at_target_debug` above, just installing
    /// the real artifact instead of the stub. Overwrites whatever was
    /// there before (stub or real) — safe because every test in this
    /// module (re)installs what it needs immediately before running, and
    /// `cargo test` runs each test *binary* to completion before starting
    /// the next one, so there is no cross-binary race on this shared path.
    fn install_real_kestrel_init_at_target_debug() {
        let real = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/kestrel-init");
        assert!(
            real.exists(),
            "real statically-linked kestrel-init not found at {} — run `make \
             build-kestrel-init-static` first.",
            real.display()
        );
        let file_output = std::process::Command::new("file")
            .arg(&real)
            .output()
            .unwrap_or_else(|e| panic!("run `file {}`: {e}", real.display()));
        let file_stdout = String::from_utf8_lossy(&file_output.stdout);
        assert!(
            file_output.status.success() && !file_stdout.contains("dynamically linked"),
            "kestrel-init at {} does not look statically linked (`file` reported: {:?}). \
             Rebuild it with `make build-kestrel-init-static`.",
            real.display(),
            file_stdout.trim()
        );

        let target_debug_dir = target_debug_dir();
        let target = target_debug_dir.join("kestrel-init");
        let tmp = target_debug_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
        std::fs::copy(&real, &tmp).expect("copy real kestrel-init to tmp");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::rename(&tmp, &target).expect("rename tmp into place as target/debug/kestrel-init");
    }

    /// Path to the statically-linked `lifecycle_fixture` artifact
    /// (`make build-lifecycle-fixture-static`) — same
    /// `CARGO_MANIFEST_DIR`-relative resolution
    /// `kestrel-runtime/tests/common/mod.rs::static_fixture_path` uses;
    /// `kestreld`'s own `CARGO_MANIFEST_DIR` (`crates/kestreld`) resolves
    /// to the same workspace-root `target/` via the same `../../target`
    /// relative path, since both crates sit one level under `crates/`.
    fn static_lifecycle_fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture")
    }

    /// Builds a minimal synthetic rootfs DIRECTORY at `dest` containing the
    /// real, statically-linked `lifecycle_fixture` binary at `<dest>/fixture`
    /// (mode 0o755) — this crate's own copy of
    /// `kestrel-runtime/tests/common/mod.rs::build_synthetic_rootfs`,
    /// duplicated (not imported) because that module is test-only source
    /// private to the `kestrel-runtime` crate's own integration tests, not
    /// reachable from another crate's tests even via a dev-dependency.
    fn build_lifecycle_synthetic_rootfs(dest: &Path) {
        std::fs::create_dir_all(dest).expect("mkdir synthetic rootfs dir");
        let fixture_path = static_lifecycle_fixture_path();
        assert!(
            fixture_path.exists(),
            "static lifecycle_fixture artifact not found at {} — run `make \
             build-lifecycle-fixture-static` first.",
            fixture_path.display()
        );
        let file_output = std::process::Command::new("file")
            .arg(&fixture_path)
            .output()
            .unwrap_or_else(|e| panic!("run `file {}`: {e}", fixture_path.display()));
        let file_stdout = String::from_utf8_lossy(&file_output.stdout);
        assert!(
            file_output.status.success() && !file_stdout.contains("dynamically linked"),
            "lifecycle_fixture artifact at {} does not look statically linked (`file` reported: \
             {:?}). Rebuild it with `make build-lifecycle-fixture-static`.",
            fixture_path.display(),
            file_stdout.trim()
        );
        std::fs::copy(&fixture_path, dest.join("fixture")).unwrap_or_else(|e| {
            panic!("copy {} to {}: {e}", fixture_path.display(), dest.join("fixture").display())
        });
        std::fs::set_permissions(dest.join("fixture"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod fixture binary");
    }

    /// Removes everything a successful real (non-stub) `create()` call
    /// against `real_data_dir()` leaves behind for `id`, beyond what
    /// `DELETE /containers/:id` itself already removes
    /// (`<data_dir>/containers/<id>/`): the synthetic bundle-rootfs layer
    /// `bundle.rs`'s `bundle_rootfs` fallback path caused `kestrel-
    /// runtime`'s own annotation-less fast-path-fallback to copy into
    /// `<data_dir>/layers/bundle-<id>/`, the bundle scratch dir under
    /// `<data_dir>/bundles/<id>/`, and the overlay snapshot scratch dir
    /// under `<data_dir>/snapshots/<id>/` (normally removed by `delete()`
    /// itself, but best-effort-removed again here in case delete didn't
    /// run, e.g. an assertion failure before reaching that step). Mirrors
    /// `kestrel-runtime/tests/lifecycle.rs::cleanup_synthetic_layer`'s own
    /// precedent, extended to also cover the two `kestreld`-specific
    /// directories.
    fn cleanup_real_container_artifacts(id: &str) {
        let data_dir = real_data_dir();
        let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir.clone());
        let _ = std::fs::remove_dir_all(layer_store.layer_dir(&format!("bundle-{id}")));
        let _ = std::fs::remove_dir_all(data_dir.join("bundles").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("snapshots").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("containers").join(id));
    }

    /// Best-effort unpin of every namespace `create()`'s default (no
    /// bridge networking) namespace set pins under `<run_dir>/<id>/ns/*` —
    /// same list/technique as `test_post_containers_with_bundle_rootfs_
    /// creates_container_end_to_end`'s own cleanup, factored out since
    /// three Task 9 tests below all need it. A successful `delete()` call
    /// already does this itself (its own step 4); calling it again here is
    /// a harmless no-op in that case, and the necessary cleanup path when
    /// a test's own `delete()` call is skipped or fails before reaching
    /// that step.
    fn unpin_default_namespaces(run_dir: &Path, id: &str) {
        let ns_dir = run_dir.join(id).join("ns");
        for ns in [
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Net,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ] {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }
    }

    /// Builds an HTTP request with no body against `app` (the real router)
    /// and returns its status code plus body bytes — small shared
    /// boilerplate every test below repeats several times (start/stop/
    /// delete calls all look identical modulo method+uri).
    async fn call_router(
        app: Router,
        method: &str,
        uri: String,
    ) -> (axum::http::StatusCode, Vec<u8>) {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tower::ServiceExt::oneshot(app, request).await.expect("router oneshot");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        (status, body.to_vec())
    }

    /// Real proof of Task 9's happy path: create -> start -> poll for
    /// `Running` -> stop -> poll for `Stopped` with a real, SIGTERM-death
    /// `exit_code` -> delete, all through the real HTTP router, with a
    /// REAL container process actually running and dying.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_lifecycle_start_then_stop_end_to_end() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        // ---- create ----
        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "sleep", "30"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        assert_eq!(created.status, kestrel_oci::state::Status::Created);
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // ---- start ----
        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );

        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // `start()` writes `Running` BEFORE its own best-effort resolution
        // of the entrypoint's real host pid finishes (`start.rs`'s own doc
        // comment — deliberately, so a fast-exiting container's Stopped
        // transition never races a slow pid-resolution write) — so
        // `state.json`'s `pid` field can still be `kestrel-init`'s own for
        // a short window even after this handler observes `Running`.
        // `kill.rs`'s (non-`--all`) `kill` signals whatever pid is
        // CURRENTLY recorded — signaling `kestrel-init` itself (acting as
        // its own container's PID 1) would hit the kernel's PID-1-ignores-
        // unhandled-SIGTERM rule and never actually reach `/fixture`,
        // which would incorrectly turn this into a false grace-period
        // escalation. Same fix `kestrel-runtime/tests/lifecycle.rs`'s own
        // `test_signal_exit_code` applies: poll for the recorded pid to
        // actually change away from `kestrel-init`'s own before signaling.
        let real_entrypoint_pid = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.pid != created.pid)
        })
        .await;
        assert!(
            real_entrypoint_pid.is_some(),
            "state.json's pid was never updated from kestrel-init's own pid ({:?}) to the \
             entrypoint's real pid",
            created.pid
        );

        // ---- stop (happy path: entrypoint has no SIGTERM handler, so the
        // default disposition — terminate — kicks in well within the
        // grace period; this must NOT need to escalate to SIGKILL) ----
        let (stop_status, stop_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        assert_eq!(
            stop_status,
            axum::http::StatusCode::OK,
            "stop failed: {}",
            String::from_utf8_lossy(&stop_body)
        );

        let stopped = kestrel_oci::state::State::read(&state_path)
            .expect("read state.json after stop returned 200");
        assert_eq!(stopped.status, kestrel_oci::state::Status::Stopped);
        assert_eq!(
            stopped.exit_code,
            Some(143),
            "expected exit_code 143 (128 + SIGTERM) from a plain signal death, got {stopped:?}"
        );

        // ---- delete (already Stopped, no --force needed) ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        assert!(
            !registry.read().await.contains_key(&id),
            "registry entry should be removed after a successful delete"
        );
        assert!(
            !data_dir.join("containers").join(&id).exists(),
            "container data dir should be removed after a successful delete"
        );

        // ---- cleanup ----
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    /// Real proof of the "force-kill-a-Created-container" path (design
    /// doc's `DELETE` row, Phase 8's `delete()` step 1): a container that
    /// was created but never started still has a live process
    /// (`kestrel-init`, blocked on the exec FIFO) — `DELETE` without
    /// `?force=true` must fail (leaving the registry entry intact), and
    /// `DELETE ?force=true` must succeed, proving that path genuinely
    /// propagates through `kestreld`'s own endpoint, not just through
    /// `kestrel-runtime delete` directly (already proven in Phase 8's own
    /// suite). Uses the STUB `kestrel-init` (Task 7/8's own fixture) —
    /// this test only cares about "is there a live process to force-kill",
    /// not about running a real entrypoint, so the stub (blocks forever,
    /// cheap, no real pivot_root) is the right tool, matching Task 8's own
    /// `POST /containers`-only tests.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_delete_without_starting_requires_force_then_succeeds() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task9-delete").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        assert_eq!(create_response.status(), axum::http::StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        assert_eq!(created.status, kestrel_oci::state::Status::Created);
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // ---- DELETE without ?force=true must fail: kestrel-init (the
        // stub) is still genuinely alive, blocked forever. ----
        let (no_force_status, _) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}")).await;
        assert_eq!(
            no_force_status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "delete without --force should fail while the container's process is still alive"
        );
        assert!(
            registry.read().await.contains_key(&id),
            "registry entry must remain after a failed (non-forced) delete"
        );

        // ---- DELETE ?force=true must succeed, force-killing the stub. ----
        let (force_status, force_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            force_status,
            axum::http::StatusCode::OK,
            "force delete failed: {}",
            String::from_utf8_lossy(&force_body)
        );
        assert!(
            !registry.read().await.contains_key(&id),
            "registry entry should be removed after a successful force delete"
        );
        assert!(
            !data_dir.path().join("containers").join(&id).exists(),
            "container data dir should be removed after a successful force delete"
        );

        // ---- cleanup: delete() itself already force-killed + unpinned
        // everything on success; this is a best-effort safety net only. ----
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
    }

    /// The grace-period test this task exists to prove: a container whose
    /// entrypoint genuinely IGNORES SIGTERM (`/fixture ignore-sigterm 60`,
    /// this task's new `lifecycle_fixture` mode) must NOT be considered
    /// stopped by `POST /containers/:id/stop` until AFTER the configured
    /// grace period elapses and a follow-up SIGKILL actually lands —
    /// proven two ways: (1) `stop`'s own HTTP call takes at least
    /// `stop_grace_period_s` wall-clock seconds to return (it cannot have
    /// given up early), and (2) the final `exit_code` is 137 (128 +
    /// SIGKILL), not 143 (128 + SIGTERM) — SIGTERM alone never killed this
    /// process; only the escalation did.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_stop_escalates_to_sigkill_after_grace_period_when_sigterm_ignored() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        // Short but clearly-distinguishable-from-zero grace period: long
        // enough that "stop returned instantly" and "stop actually waited
        // out the grace period" are unambiguous, short enough that the
        // test doesn't need the real ~10s production default.
        const GRACE_PERIOD_S: u64 = 3;

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: GRACE_PERIOD_S,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "ignore-sigterm", "60"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // Wait for the recorded pid to become the FIXTURE's own (not
        // kestrel-init's) — see the happy-path test's own comment on why:
        // this test's whole point is proving the FIXTURE ignores SIGTERM,
        // not merely that kestrel-init (PID 1 of its own namespace, which
        // the kernel makes immune to an unhandled SIGTERM regardless of
        // this fixture's own `ignore-sigterm` mode) does.
        let real_entrypoint_pid = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.pid != created.pid)
        })
        .await;
        assert!(
            real_entrypoint_pid.is_some(),
            "state.json's pid was never updated from kestrel-init's own pid ({:?}) to the \
             entrypoint's real pid",
            created.pid
        );

        // ---- stop: measure wall-clock time to prove the grace period was
        // genuinely honored, not skipped. ----
        let started_at = std::time::Instant::now();
        let (stop_status, stop_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        let elapsed = started_at.elapsed();

        assert_eq!(
            stop_status,
            axum::http::StatusCode::OK,
            "stop failed: {}",
            String::from_utf8_lossy(&stop_body)
        );
        assert!(
            elapsed >= Duration::from_secs(GRACE_PERIOD_S),
            "stop returned after only {elapsed:?}, before the {GRACE_PERIOD_S}s grace period \
             could have elapsed — did it actually wait for SIGTERM before escalating?"
        );
        assert!(
            elapsed < Duration::from_secs(GRACE_PERIOD_S) + Duration::from_secs(15),
            "stop took implausibly long ({elapsed:?}) to return after escalating to SIGKILL"
        );

        let stopped = kestrel_oci::state::State::read(&state_path)
            .expect("read state.json after stop returned 200");
        assert_eq!(stopped.status, kestrel_oci::state::Status::Stopped);
        assert_eq!(
            stopped.exit_code,
            Some(137),
            "expected exit_code 137 (128 + SIGKILL) — SIGTERM alone was ignored by the fixture, \
             so only the grace-period escalation to SIGKILL could have produced this, got {stopped:?}"
        );

        // ---- delete + cleanup ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );

        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    // -----------------------------------------------------------------
    // Task 10: exec (WS bridge) + top — root-gated
    // -----------------------------------------------------------------
    //
    // exec's tests reuse Task 8/9's STUB `kestrel-init` (blocks forever,
    // never calls `pivot_root`) rather than the real one: since the stub
    // never pivots the container's mount namespace away from the host's
    // own root filesystem, a plain host-visible path like `/bin/echo`
    // stays reachable and exec'able from INSIDE the container's joined
    // namespaces — exactly the same precedent `kestrel-runtime/tests/
    // exec_cmd.rs` already established with its own host-path
    // `fixture-exec-probe` binary (see that file's own module doc comment
    // for the full explanation). This means these tests don't need the
    // real, statically-linked `kestrel-init`/`lifecycle_fixture` artifacts
    // `make build-*-static` produces at all — a real container process
    // tree to exec INTO is all that's required, and the stub (cheap, no
    // pivot_root) already provides that.
    //
    // `top`'s test is different: it needs a REAL running entrypoint
    // (`lifecycle_fixture spawn-abandon N`) actually forking children, so
    // it uses the real `kestrel-init`/`lifecycle_fixture` artifacts, same
    // as every other "container must actually run" test in this file.

    use std::collections::HashSet;

    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    /// Binds a real, ephemeral-port `TcpListener` and serves `app` on it in
    /// a background task — needed because `tower::ServiceExt::oneshot`
    /// (every other test in this file) has no real hyper connection for a
    /// genuine WS upgrade to happen over. The returned `JoinHandle` should
    /// be `.abort()`ed once the test is done with it.
    async fn spawn_test_server(app: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral TCP port for WS test server");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (addr, handle)
    }

    /// Drives one full `WS /containers/:id/exec` session: connects, sends
    /// the `{"cmd":[...],"tty":false}` init message, collects every Binary
    /// chunk into `output`, and returns the `exit_code` reported by the
    /// final `{"type":"exit",...}` control message.
    async fn run_exec_over_ws(addr: std::net::SocketAddr, id: &str, cmd: &[&str]) -> (Vec<u8>, Option<i32>) {
        let url = format!("ws://{addr}/containers/{id}/exec");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect to exec WS endpoint");

        let init = serde_json::json!({ "cmd": cmd, "tty": false });
        ws.send(WsMessage::Text(init.to_string().into()))
            .await
            .expect("send exec init message");

        let mut output = Vec::new();
        let mut exit_code = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let next = tokio::time::timeout(remaining, ws.next())
                .await
                .expect("exec WS session did not finish within the test's time budget");
            match next {
                Some(Ok(WsMessage::Binary(bytes))) => output.extend_from_slice(&bytes),
                Some(Ok(WsMessage::Text(text))) => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&text).expect("exec control message is valid JSON");
                    if parsed["type"] == "exit" {
                        exit_code = parsed["exit_code"].as_i64().map(|n| n as i32);
                        break;
                    }
                }
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("exec WS session errored: {e}"),
            }
        }
        (output, exit_code)
    }

    /// Real proof of Task 10 Step 3's first scenario: `exec`ing `/bin/echo
    /// hi` against a running (stub) container's WS bridge round-trips the
    /// real output and reports a real, successful exit code.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_exec_echo_round_trips_over_ws_with_zero_exit_code() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task10-exec").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        assert_eq!(create_response.status(), axum::http::StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (addr, server_handle) = spawn_test_server(app).await;
        let (output, exit_code) = run_exec_over_ws(addr, &id, &["/bin/echo", "hi"]).await;

        assert_eq!(
            String::from_utf8_lossy(&output).trim(),
            "hi",
            "exec'd /bin/echo hi's output did not round-trip over the WS bridge, got: {:?}",
            String::from_utf8_lossy(&output)
        );
        assert_eq!(exit_code, Some(0), "expected a clean 0 exit code from /bin/echo");

        server_handle.abort();
        drop(process_guard);
        unpin_default_namespaces(run_dir.path(), &id);
    }

    /// Real proof of Task 10 Step 3's second scenario: a nonzero exec exit
    /// code is genuinely reported back over the WS bridge's final control
    /// message, not silently swallowed or always reported as 0/success.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_exec_nonzero_exit_code_is_reported() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task10-exec-nonzero").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        assert_eq!(create_response.status(), axum::http::StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (addr, server_handle) = spawn_test_server(app).await;
        let (_output, exit_code) = run_exec_over_ws(addr, &id, &["/bin/sh", "-c", "exit 7"]).await;

        assert_eq!(exit_code, Some(7), "expected the real nonzero exit code (7) to be reported");

        server_handle.abort();
        drop(process_guard);
        unpin_default_namespaces(run_dir.path(), &id);
    }

    /// Real proof of Task 10 Step 3's third scenario: `top` against a
    /// container running `lifecycle_fixture spawn-abandon N` lists multiple
    /// processes (the fixture itself plus its spawned-then-abandoned
    /// children, which sit as zombies parented to the fixture — still
    /// genuinely enumerable via `/proc` — for the ~2s window before the
    /// fixture itself exits) with plausible (positive) host/container pid
    /// pairs.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_top_lists_multiple_processes_with_plausible_pids() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "spawn-abandon", "5", "/spawn-count"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // Same "wait for the real entrypoint's pid, not kestrel-init's own"
        // reasoning as every other real-container test in this file.
        let real_entrypoint_pid = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.pid != created.pid)
        })
        .await;
        assert!(
            real_entrypoint_pid.is_some(),
            "state.json's pid was never updated from kestrel-init's own pid ({:?}) to the \
             entrypoint's real pid",
            created.pid
        );

        // ---- top, called only once the fixture has PROVABLY finished
        // forking its children — not merely once state.json's pid has
        // updated. Those two events are NOT the same instant: state.json's
        // pid updates the moment kestrel-init forks the entrypoint, which
        // can race ahead of the freshly-exec'd fixture binary actually
        // reaching its own spawn-abandon loop (page faults for the new
        // image, scheduler latency under load), especially inside a full
        // `make test-root` run sharing the VM with many other back-to-back
        // root-gated tests. Confirmed as a REAL, reproducible-under-load
        // race (not a hypothetical): a bare `state.json pid changed` ->
        // immediate `top` call intermittently found only the entrypoint
        // itself with zero children, under exactly this contention.  Fixed
        // the same way `kestrel-runtime/tests/lifecycle.rs`'s own
        // `test_zombie_reaping` already synchronizes this: pass the fixture
        // a count-file path and wait for it to appear (written right after
        // the fork loop, well before the 2s post-spawn sleep) before
        // proceeding — a real, provable signal instead of a proxy one. ----
        let count_host_path = data_dir.join("snapshots").join(&id).join("upper").join("spawn-count");
        let achieved = poll_until(Duration::from_secs(10), || {
            std::fs::read_to_string(&count_host_path)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
        })
        .await;
        assert!(
            achieved.is_some(),
            "spawn-abandon count file never appeared/parsed at {}",
            count_host_path.display()
        );
        assert!(
            achieved.unwrap() > 0,
            "fixture achieved 0 forked children — nothing for top to find beyond the entrypoint itself"
        );

        let (top_status, top_body) = call_router(app.clone(), "GET", format!("/containers/{id}/top")).await;
        assert_eq!(
            top_status,
            axum::http::StatusCode::OK,
            "top failed: {}",
            String::from_utf8_lossy(&top_body)
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&top_body).expect("parse top response JSON");
        let processes = parsed["processes"].as_array().expect("processes is an array");
        assert!(
            processes.len() >= 2,
            "expected the fixture entrypoint plus at least one spawned-then-abandoned child, got: {processes:?}"
        );
        for p in processes {
            let host_pid = p["host_pid"].as_i64().expect("host_pid is present");
            let container_pid = p["container_pid"].as_i64().expect("container_pid is present");
            assert!(host_pid > 0, "implausible host_pid in {p:?}");
            assert!(container_pid > 0, "implausible container_pid in {p:?}");
        }
        let host_pids: HashSet<i64> = processes.iter().map(|p| p["host_pid"].as_i64().unwrap()).collect();
        assert!(
            host_pids.contains(&(real_entrypoint_pid.unwrap().pid.unwrap() as i64)),
            "top's process list should include the entrypoint itself, got: {processes:?}"
        );

        // ---- cleanup ----
        let (stop_status, _) = call_router(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        assert_eq!(stop_status, axum::http::StatusCode::OK);
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );

        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    // -----------------------------------------------------------------
    // Task 12: attach WS + resize — root-gated
    // -----------------------------------------------------------------
    //
    // The tty attach test needs a REAL running entrypoint (same
    // "container must actually run" precedent
    // `test_top_lists_multiple_processes_with_plausible_pids` established
    // above), running `lifecycle_fixture echo-stdin` — Task 12's own new
    // argv mode (see that fixture's own doc comment, `crates/kestrel-
    // runtime/tests/fixtures/lifecycle_fixture.rs`, for why raw mode is
    // required for a byte-exact round trip). The non-tty resize-409 test
    // does NOT need a live entrypoint at all: `resize_container` returns
    // before ever touching `attach.sock` for a non-tty container, so the
    // cheap Task 8-style stub `kestrel-init`/`Created`-is-enough pattern
    // suffices there.

    /// Drives one attach WS session: connects, sends `payload` as a single
    /// Binary message, then collects Binary messages until at least
    /// `payload.len()` bytes have been received (or the time budget below
    /// elapses) — real, on-the-wire proof that bytes sent over `WS
    /// /containers/:id/attach` reached the container's stdin and came back
    /// out its stdout, through the shim's real `attach.sock` framing, not
    /// just that the endpoint returned some response.
    async fn attach_send_and_collect_echo(addr: std::net::SocketAddr, id: &str, payload: &[u8]) -> Vec<u8> {
        let url = format!("ws://{addr}/containers/{id}/attach");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect to attach WS endpoint");

        ws.send(WsMessage::Binary(payload.to_vec().into()))
            .await
            .expect("send attach input");

        let mut collected = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while collected.len() < payload.len() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                remaining > Duration::ZERO,
                "timed out waiting for attach echo; collected so far: {collected:?}"
            );
            let next = tokio::time::timeout(remaining, ws.next())
                .await
                .expect("attach WS session did not finish within the test's time budget");
            match next {
                Some(Ok(WsMessage::Binary(bytes))) => collected.extend_from_slice(&bytes),
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("attach WS session errored: {e}"),
            }
        }
        collected
    }

    /// Real proof of Task 12 Step 1 + Step 2's happy path: a tty container
    /// running `lifecycle_fixture echo-stdin` round-trips real bytes sent
    /// over `WS /containers/:id/attach` through the shim's real
    /// `attach.sock` framing and back out again, and `POST .../resize`
    /// against the SAME (tty) container succeeds without error.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_attach_ws_echoes_tty_container_stdin_and_resize_succeeds() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": true,
            "cmd": ["/fixture", "echo-stdin"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");
        // Same "wait for the real entrypoint's pid, not kestrel-init's
        // own" reasoning as the Task 10 `top` test above — makes sure
        // `/fixture echo-stdin` has actually been forked (and put its
        // stdin into raw mode) before this test starts writing to it.
        let real_entrypoint = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.pid != created.pid)
        })
        .await;
        assert!(
            real_entrypoint.is_some(),
            "state.json's pid was never updated from kestrel-init's own pid ({:?}) to the \
             entrypoint's real pid",
            created.pid
        );

        let (addr, server_handle) = spawn_test_server(app.clone()).await;

        let payload = b"hello attach, this is a real round trip\x00\x01\xff";
        let echoed = attach_send_and_collect_echo(addr, &id, payload).await;
        assert_eq!(
            echoed, payload,
            "attach WS did not echo back the exact bytes sent — got {echoed:?}"
        );

        // ---- Step 2: POST /resize against the SAME tty container succeeds ----
        let resize_request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/containers/{id}/resize"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&serde_json::json!({ "rows": 40, "cols": 120 })).unwrap(),
            ))
            .unwrap();
        let resize_response = tower::ServiceExt::oneshot(app.clone(), resize_request)
            .await
            .expect("router oneshot");
        let resize_status = resize_response.status();
        let resize_body = axum::body::to_bytes(resize_response.into_body(), usize::MAX)
            .await
            .expect("reading resize response body");
        assert_eq!(
            resize_status,
            axum::http::StatusCode::OK,
            "resize failed: {}",
            String::from_utf8_lossy(&resize_body)
        );

        // ---- cleanup ----
        server_handle.abort();
        let (stop_status, _) = call_router(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        assert_eq!(stop_status, axum::http::StatusCode::OK);
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );

        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    /// Real proof of Task 12 Step 3: `POST /containers/:id/resize` against
    /// a non-tty container is rejected with a real `409`, decided purely
    /// via the registry's `ContainerHandle.meta.tty` — `resize_container`
    /// never even attempts to connect to `attach.sock` in this case, so
    /// (matching Task 8's own cheap "stub kestrel-init, `Created` is
    /// enough" precedent) no running entrypoint is needed to prove this.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_resize_returns_409_for_non_tty_container() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task12-resize-409").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        assert_eq!(create_response.status(), axum::http::StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        let id = serde_json::from_slice::<serde_json::Value>(&create_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created =
            kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let resize_request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/containers/{id}/resize"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&serde_json::json!({ "rows": 24, "cols": 80 })).unwrap(),
            ))
            .unwrap();
        let resize_response = tower::ServiceExt::oneshot(app.clone(), resize_request)
            .await
            .expect("router oneshot");
        assert_eq!(
            resize_response.status(),
            axum::http::StatusCode::CONFLICT,
            "resize against a non-tty container should 409"
        );

        // ---- cleanup ----
        drop(process_guard);
        unpin_default_namespaces(run_dir.path(), &id);
    }

    // -----------------------------------------------------------------
    // Task 16: seccomp-notify fd hand-back + supervisor — root-gated,
    // real end to end
    // -----------------------------------------------------------------
    //
    // The single strongest available proof of this task's whole mechanism:
    // a real container, created through the real HTTP API with a real
    // `SCMP_ACT_NOTIFY` seccomp profile (`seccomp_notify_syscalls`, this
    // task's own minimal API addition, `api::containers::
    // CreateContainerRequest`), whose real entrypoint
    // (`lifecycle_fixture trigger-personality`, this task's own new fixture
    // mode) makes the notified syscall for real, whose real seccomp-notify
    // fd genuinely crosses the fork+exec boundary via `SCM_RIGHTS`
    // (`kestrel-init`'s `exec::send_fd_to_socket` -> `kestrel-shim`'s
    // `daemon::handle_seccomp_conn`), whose real
    // `kestrel_security::notify::run_notify_loop` genuinely decodes it and
    // responds, forwarded over a real `attach.sock` connection as a real
    // `Frame::SeccompEvent`, translated by the real attach-WS bridge
    // (`api::attach::run_attach_session`) into a real `Event::
    // SeccompViolation` on the real event bus, observed by a real `GET
    // /events` SSE subscriber. Every link in design doc §7's chain is
    // exercised for real — nothing here is mocked or short-circuited.
    //
    // Prerequisites (build once before running):
    // ```text
    // make build-kestrel-init-static build-lifecycle-fixture-static
    // cargo build -p kestrel-shim -p kestrel-runtime --bins
    // ```

    /// Reads SSE `data: <json>` frames from `body` until one with
    /// `"type":"seccomp.violation"` and a matching `"id"` arrives (or
    /// `timeout` elapses). Same framing assumptions as `events.rs`'s own
    /// `collect_matching_events` (axum's `Event::data()` emits one `data:
    /// <json>\n\n` block per event) — duplicated rather than imported,
    /// matching this crate's established "test infra lives in each test
    /// module that needs it" precedent.
    async fn collect_seccomp_violation_event(
        body: &mut axum::body::Body,
        container_id: &str,
        timeout: Duration,
    ) -> serde_json::Value {
        use http_body_util::BodyExt;
        let mut acc = String::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                remaining > Duration::ZERO,
                "timed out waiting for a seccomp.violation event for {container_id}; accumulated so far: {acc:?}"
            );
            let frame = tokio::time::timeout(remaining, body.frame())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for next SSE frame; accumulated so far: {acc:?}"))
                .expect("SSE body stream ended unexpectedly")
                .expect("reading SSE frame");
            if let Some(data) = frame.data_ref() {
                acc.push_str(&String::from_utf8_lossy(data));
            }
            while let Some(idx) = acc.find("\n\n") {
                let chunk: String = acc.drain(..idx + 2).collect();
                for line in chunk.lines() {
                    let Some(json_str) = line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) else {
                        continue; // keep-alive/comment lines, blank lines, etc.
                    };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str.trim()) else {
                        continue;
                    };
                    if v["type"] == "seccomp.violation" && v.get("id").and_then(|x| x.as_str()) == Some(container_id)
                    {
                        return v;
                    }
                }
            }
        }
    }

    /// Real proof of Task 16's whole mechanism. See this section's own
    /// module-level doc comment for the full chain being exercised.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_seccomp_notify_violation_reaches_event_bus_with_correct_syscall() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let event_bus = events::new_bus();
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus,
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        // ---- subscribe to /events BEFORE triggering anything, so the
        // event this test asserts on can't be raced/missed (same ordering
        // precedent `events.rs`'s own capstone test establishes). ----
        let events_request = axum::http::Request::builder()
            .method("GET")
            .uri("/events")
            .body(axum::body::Body::empty())
            .unwrap();
        let events_response = tower::ServiceExt::oneshot(app.clone(), events_request)
            .await
            .expect("GET /events oneshot");
        assert_eq!(events_response.status(), axum::http::StatusCode::OK);
        let mut events_body = events_response.into_body();

        // ---- create: a real SCMP_ACT_NOTIFY profile on `personality`,
        // an entrypoint that actually calls it. ----
        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "trigger-personality"],
            "seccomp_notify_syscalls": ["personality"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_resp_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // Defense-in-depth (adversarial-review round 2 fix): declared
        // right after `id`/`run_dir` are known, covering everything from
        // here through the real assertion below — the highest-risk span
        // in this test, per its own history. Reverse-declaration-order
        // drop (Rust's normal scope-end behavior, same convention this
        // file's other tests already rely on for `process_guard`/
        // `_mount_guard` pairs) means, if a panic short-circuits the
        // explicit cleanup at the bottom: `process_guard` (kill the
        // entrypoint) drops first, then `shim_guard` (kill the shim
        // process — see that type's own doc comment for the real, root-
        // caused orphan this specifically closes), then
        // `artifacts_guard` (unpin namespaces, remove data-dir artifacts),
        // then finally this test's own `_mount_guard` (declared earlier,
        // near the top) unmounts the cgroup2 view.
        let shim_guard = ShimGuard(id.clone());
        let artifacts_guard = ContainerArtifactsGuard { run_dir: run_dir.path().to_path_buf(), id: id.clone() };

        // ---- open (and keep alive) an attach WS session BEFORE start —
        // still worth doing early even though it's no longer strictly
        // load-bearing for correctness (see below): `kestreld`'s attach-WS
        // bridge (`api::attach::run_attach_session`) is what bridges
        // `Frame::SeccompEvent` frames into `Event::SeccompViolation` in
        // the first place (see that module's own doc comment on why this
        // is on-demand, not an always-on internal subscriber), so a client
        // has to attach at SOME point during this test for the assertion
        // below to have anything to observe. Attaching BEFORE `start`
        // (attach.sock is already live the moment `create` succeeds —
        // independent of `start`, per design doc §5) is simply the
        // earliest, most natural point to do so. A background task just
        // drains whatever the shim forwards over the WS (the container's
        // own — empty — stdout), keeping the session's read direction from
        // ever blocking. ----
        let (addr, server_handle) = spawn_test_server(app.clone()).await;
        let ws_url = format!("ws://{addr}/containers/{id}/attach");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(ws_url)
            .await
            .expect("connect to attach WS endpoint");

        // Real, deterministic synchronization — NOT a sleep — closing what
        // was previously a genuine, reproduced race (this exact test
        // failing ~50% of the time in a full, loaded suite run, even
        // behind a 1-second fixed "settle wait" sleep here). The client-
        // side WS handshake completing (`connect_async` returning above)
        // does NOT guarantee axum's server-side `on_upgrade` callback
        // (`api::attach::run_attach_session`) has even reached
        // `UnixStream::connect(attach_sock_path)` yet, let alone that the
        // SHIM's OWN `accept_loop`/`handle_attach_conn` has reached
        // `subscribe()` — two more hops of independently-scheduled tokio
        // tasks whose combined delay under load has no fixed upper bound.
        // No finite sleep can out-wait an unbounded scheduling delay (a
        // bigger constant only narrows the window, as this test's own
        // history already proved once). Fixed for real with an actual
        // acknowledgment instead of a guess: `kestrel-shim`'s
        // `daemon::handle_attach_conn` sends `kestrel_shim::framing::
        // Frame::Ready` as the very first frame on this connection, but
        // ONLY once it has genuinely finished subscribing to the shim's
        // seccomp-notify broadcast — `kestreld`'s own `api::attach::
        // run_attach_session` forwards that arrival on to THIS WS client
        // as a one-time `ATTACH_READY_TEXT` Text message (see that
        // constant's own doc comment). Blocking here for that exact
        // message before ever calling `start` below means: by construction,
        // `handle_attach_conn` has already subscribed by the time this test
        // proceeds — the entrypoint hasn't even been told to run yet. No
        // guesswork, no fixed budget to size, and no residual window left
        // to reproduce under load.
        let ready_msg = tokio::time::timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut ws))
            .await
            .expect("timed out waiting for the attach session's Ready acknowledgment")
            .expect("attach WS stream ended before sending Ready")
            .expect("reading the attach WS Ready message");
        assert_eq!(
            ready_msg,
            tokio_tungstenite::tungstenite::Message::Text(api::attach::ATTACH_READY_TEXT.into()),
            "expected the attach session's first WS message to be the Ready acknowledgment, got: {ready_msg:?}"
        );

        // Belt-and-suspenders alongside the deterministic wait above (not a
        // substitute for it): `kestrel-shim`'s `daemon::SeccompHub` (see
        // its own doc comment) ALSO captures every seccomp-notify event
        // into a small replay buffer before broadcasting it live, so even
        // a consumer that (unlike this test, now) doesn't wait for `Ready`
        // still can't lose an event to this specific race — genuinely
        // useful beyond this one test, e.g. a real `kestreld` restarting
        // and reattaching well after a violation already fired.
        let drain_task = tokio::spawn(async move {
            while let Some(msg) = futures_util::StreamExt::next(&mut ws).await {
                if msg.is_err() {
                    break;
                }
            }
        });

        // ---- start ----
        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // ---- the real assertion: a seccomp.violation event for THIS
        // container, with the right syscall name, genuinely arrives on
        // kestreld's event bus. `/fixture trigger-personality` calls
        // personality() unconditionally right after start — no extra
        // trigger step needed from this test. ----
        let violation =
            collect_seccomp_violation_event(&mut events_body, &id, Duration::from_secs(20)).await;
        assert_eq!(
            violation["syscall"], "personality",
            "expected the seccomp.violation event to report the real syscall name, got: {violation:?}"
        );

        // ---- cleanup ----
        let (stop_status, stop_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/stop")).await;
        assert_eq!(
            stop_status,
            axum::http::StatusCode::OK,
            "stop failed: {}",
            String::from_utf8_lossy(&stop_body)
        );
        drain_task.abort();
        server_handle.abort();
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);

        // A REAL gap found during this task's own testing, root-caused via
        // direct `/proc/<pid>/fd`/`/proc/<pid>/task` inspection of a live
        // orphan: this test's own attach WS client disconnecting (via
        // `drain_task.abort()`/`server_handle.abort()` above) does NOT
        // reliably make `kestrel-shim`'s own per-connection
        // `handle_attach_conn` task (spawned via a bare, detached
        // `tokio::spawn` inside `accept_loop`, per design — see
        // `kestrel-shim/src/daemon.rs`) notice the disconnect and end
        // promptly — that task is independent of `run()`'s own top-level
        // `tokio::select!` (which itself DOES correctly resolve once the
        // container's stdio pipes hit EOF, confirmed directly: a live
        // orphan's `/proc/<pid>/fd` showed the container's own stdio pipe
        // fds already closed, notify fd still open, yet the process itself
        // never exited) — dropping `Runtime` on `main()`'s return blocks
        // waiting for EVERY outstanding spawned task, including that one,
        // so the whole process lingers as long as that one connection
        // handler keeps waiting on a peer that already vanished. This is a
        // real, pre-existing `kestrel-shim`/Task 2 robustness gap (attach
        // connections have no idle/liveness timeout), not something Task
        // 16 introduces or is positioned to fix — worked around explicitly
        // here on the happy path (`drop(shim_guard)`, same targeted
        // `SIGKILL`-by-id this test used inline before `ShimGuard` existed)
        // and, on any OTHER exit path (a panicking assertion above), by
        // `shim_guard`'s own `Drop` impl running automatically at scope
        // end — not chased further given the actual seccomp-notify
        // mechanism this task exists to prove is already fully verified
        // above.
        drop(shim_guard);
        drop(artifacts_guard);
    }

    // -----------------------------------------------------------------
    // Task 18: introspection endpoints, part A (namespaces, cgroup,
    // pressure, mounts, caps) — root-gated
    // -----------------------------------------------------------------
    //
    // `namespaces`/`mounts`/`caps` only need a real, live container process
    // (namespace pinning and `config.json` are both already real by the
    // time `create()` returns — Running status is not required), so these
    // three reuse the cheap STUB `kestrel-init` harness Task 7/8 already
    // established (`install_stub_kestrel_init_at_target_debug`). `cgroup`/
    // `pressure` genuinely need real, moving resource usage, so those two
    // share `t18_spawn_alloc_hold_container` below, which reuses the REAL,
    // statically-linked `kestrel-init` + `lifecycle_fixture`'s own
    // `alloc-hold <mib>` behavior (Task 13's own precedent for proving a
    // cgroup number moves under genuine load).

    /// Real proof of Step 1: for a single, freshly-created container, every
    /// namespace type this dev VM successfully pins reports an inode that
    /// is byte-for-byte consistent with `/proc/<pid>/ns/<type>` (read
    /// independently of the endpoint, directly off `/proc`) — not a
    /// fabricated or stale value — `"mnt"` is correctly ABSENT (this dev
    /// Lima VM's own documented, independently re-verified `EINVAL`-on-
    /// Mount-namespace-bind-mount limitation — see `create.rs::
    /// pin_namespaces`'s doc comment), and `shared_with` is correctly empty
    /// for every entry (there is no other registered container to share
    /// with in this test).
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_namespaces_endpoint_reports_real_inodes_consistent_with_proc() {
        use std::os::unix::fs::MetadataExt;

        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task18-namespaces").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body_bytes)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body_bytes).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // ---- the real assertion ----
        let (status, resp_body) = call_router(app.clone(), "GET", format!("/containers/{id}/namespaces")).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "namespaces endpoint failed: {}",
            String::from_utf8_lossy(&resp_body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&resp_body).expect("parse namespaces JSON");
        let namespaces = parsed["namespaces"].as_array().expect("namespaces array");

        assert!(
            namespaces.len() >= 5,
            "expected at least 5 pinned namespace types (uts/ipc/pid/net/cgroup) for a default \
             bundle, got: {parsed}"
        );

        let types: Vec<&str> = namespaces.iter().map(|n| n["ns_type"].as_str().unwrap()).collect();
        assert!(
            !types.contains(&"mnt"),
            "this dev VM is documented (create.rs::pin_namespaces) to always fail pinning the \
             Mount namespace via bind-mount (EINVAL) — 'mnt' must be ABSENT from the response \
             here, not silently included with a bogus value: {parsed}"
        );

        for entry in namespaces {
            let ns_type = entry["ns_type"].as_str().unwrap();
            let reported_inode = entry["inode"].as_u64().unwrap();
            let proc_path = format!("/proc/{}/ns/{ns_type}", init_pid.as_raw());
            let real_inode = std::fs::metadata(&proc_path)
                .unwrap_or_else(|e| panic!("stat {proc_path}: {e}"))
                .ino();
            assert_eq!(
                reported_inode, real_inode,
                "reported inode for ns_type {ns_type:?} must match /proc/{}/ns/{ns_type}'s real \
                 inode, got response {parsed}",
                init_pid.as_raw()
            );
            assert!(
                entry["shared_with"].as_array().unwrap().is_empty(),
                "a single, freshly-created container with no other registered containers must \
                 share no namespace with anyone: {entry}"
            );
        }

        // ---- cleanup: `DELETE ?force=true` reaps the real cgroup
        // `create()` made (this project's cgroup2 hierarchy is a single
        // global tree, not isolated per test — leaving it behind would
        // leak into this shared VM), then the same best-effort namespace-
        // pin/data-dir cleanup every other test in this module already
        // does, in case delete() itself didn't reach that step. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        let _ = std::fs::remove_dir_all(data_dir.path().join("containers").join(&id));
    }

    /// Real proof of Step 4. This dev VM's Mount-namespace pin is
    /// documented (`create.rs::pin_namespaces`'s own doc comment) to always
    /// fail with `EINVAL` — independently re-confirmed for this task via a
    /// direct `mount --bind /proc/self/ns/mnt <target>` probe, which
    /// returns exactly that error on this VM right now. This test branches
    /// on the pin's real, observed existence rather than hardcoding either
    /// outcome: if a future/different environment DOES succeed at pinning
    /// Mount, this test asserts the full happy path (real parsed
    /// `mountinfo` rows, a `/` entry, valid propagation values); on this
    /// VM, it asserts the endpoint fails with a real, specific error that
    /// names the missing pin — never a silent/fabricated `200`, and never
    /// an opaque, contextless `500`.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_mounts_endpoint_parses_real_mountinfo_or_reports_the_known_pin_limitation() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task18-mounts").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body_bytes)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body_bytes).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let mnt_pin = run_dir.path().join(&id).join("ns").join("mnt");
        let (status, resp_body) = call_router(app.clone(), "GET", format!("/containers/{id}/mounts")).await;

        if mnt_pin.exists() {
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "mounts endpoint failed even though the mnt pin exists at {}: {}",
                mnt_pin.display(),
                String::from_utf8_lossy(&resp_body)
            );
            let parsed: serde_json::Value = serde_json::from_slice(&resp_body).expect("parse mounts JSON");
            let mounts = parsed["mounts"].as_array().expect("mounts array");
            assert!(!mounts.is_empty(), "a real container's mountinfo must never be empty: {parsed}");
            assert!(
                mounts.iter().any(|m| m["mount_point"] == "/"),
                "expected a root '/' mount entry in a real container's mountinfo: {parsed}"
            );
            for m in mounts {
                let propagation = m["propagation"].as_str().unwrap();
                assert!(
                    propagation == "private"
                        || propagation == "unbindable"
                        || propagation.contains("shared:")
                        || propagation.contains("master:"),
                    "unexpected propagation value {propagation:?} in entry {m}"
                );
            }
        } else {
            assert_eq!(
                status,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "unexpected status when the mnt pin is genuinely absent (verified via {} not \
                 existing): {}",
                mnt_pin.display(),
                String::from_utf8_lossy(&resp_body)
            );
            let parsed: serde_json::Value = serde_json::from_slice(&resp_body).expect("parse error JSON");
            let message = parsed["error"].as_str().unwrap_or_default();
            assert!(
                message.contains("pinned mount namespace"),
                "expected the error to explain the missing mount-namespace pin, got: {message:?}"
            );
        }

        // ---- cleanup: see test_namespaces_endpoint_...'s own cleanup
        // comment for why DELETE runs here too. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        let _ = std::fs::remove_dir_all(data_dir.path().join("containers").join(&id));
    }

    /// Real proof of Step 5: the endpoint's response matches BOTH the
    /// real, deterministic default capability set (`oci_spec::runtime::
    /// Process::default()`'s `LinuxCapabilities::default()` — `bundle.rs`
    /// never overrides `capabilities`, so every set is exactly
    /// `{CAP_AUDIT_WRITE, CAP_KILL, CAP_NET_BIND_SERVICE}`) AND the real,
    /// independently-read bytes of the container's own on-disk
    /// `config.json` — not just an internally-consistent-with-itself
    /// fabrication.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_caps_endpoint_reports_real_default_capability_set_from_config_json() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        std::fs::write(rootfs_dir.path().join("marker"), b"hello-task18-caps").expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body_bytes)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body_bytes).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (status, resp_body) = call_router(app.clone(), "GET", format!("/containers/{id}/caps")).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "caps endpoint failed: {}",
            String::from_utf8_lossy(&resp_body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&resp_body).expect("parse caps JSON");
        let expected = serde_json::json!(["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"]);
        for field in ["bounding", "effective", "inheritable", "permitted", "ambient"] {
            assert_eq!(parsed[field], expected, "unexpected {field} set: {parsed}");
        }

        // Cross-check against the real, independently-read bytes of the
        // container's own on-disk config.json — not just trusting the
        // endpoint's own internal serialization round trip.
        let config_path = data_dir.path().join("bundles").join(&id).join("config.json");
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read real config.json"))
                .expect("parse real config.json");
        let mut on_disk_bounding: Vec<String> = raw["process"]["capabilities"]["bounding"]
            .as_array()
            .expect("config.json has process.capabilities.bounding")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        on_disk_bounding.sort();
        assert_eq!(
            on_disk_bounding,
            vec!["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
            "the endpoint's response must match the real on-disk config.json"
        );

        // ---- cleanup: see test_namespaces_endpoint_...'s own cleanup
        // comment for why DELETE runs here too. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        let _ = std::fs::remove_dir_all(data_dir.path().join("containers").join(&id));
    }

    /// Shared setup for the `cgroup`/`pressure` tests below: a REAL,
    /// running container (statically-linked `kestrel-init` +
    /// `lifecycle_fixture`, matching Task 13's own precedent for proving a
    /// cgroup number moves under genuine load) running `/fixture alloc-hold
    /// <mib>` under a `memory_bytes` limit comfortably above `<mib>` MiB —
    /// enough headroom that it is never OOM-killed, while still applying a
    /// real, distinct-from-default configured limit for `cgroup`'s own
    /// `memory_max` assertion.
    async fn t18_spawn_alloc_hold_container(
        mib: usize,
        memory_bytes: i64,
    ) -> (
        Router,
        String,
        tempfile::TempDir,
        MountGuard,
        ProcessGuard,
        ShimGuard,
        ContainerArtifactsGuard,
        PathBuf,
        nix::unistd::Pid,
    ) {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "alloc-hold", mib.to_string()],
            "memory_bytes": memory_bytes,
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body_bytes)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body_bytes).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);
        let shim_guard = ShimGuard(id.clone());
        let artifacts_guard = ContainerArtifactsGuard { run_dir: run_dir.path().to_path_buf(), id: id.clone() };

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );

        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        (app, id, run_dir, mount_guard, process_guard, shim_guard, artifacts_guard, state_path, init_pid)
    }

    /// Real proof of Step 2: `memory_current` genuinely rises under
    /// `alloc-hold`'s real, incremental, non-zero-byte memory allocation
    /// (Task 13's own established technique for proving this isn't a
    /// `calloc`-fast-pathed no-op), `memory_max` reports the real
    /// CONFIGURED limit this test itself set (not a default), and
    /// `pids_current`/`cpu_stat.usage_usec` both report genuinely non-zero,
    /// plausible values for a real running process.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_cgroup_endpoint_reports_memory_current_rising_under_real_load() {
        let memory_limit: i64 = 200 * 1024 * 1024; // 200 MiB — comfortably above the 20 MiB this test allocates.
        let (app, id, _run_dir, _mount_guard, process_guard, shim_guard, artifacts_guard, _state_path, init_pid) =
            t18_spawn_alloc_hold_container(20, memory_limit).await;

        let (status0, body0) = call_router(app.clone(), "GET", format!("/containers/{id}/cgroup")).await;
        assert_eq!(
            status0,
            axum::http::StatusCode::OK,
            "cgroup endpoint failed: {}",
            String::from_utf8_lossy(&body0)
        );
        let baseline: serde_json::Value = serde_json::from_slice(&body0).expect("parse cgroup JSON");
        let baseline_memory = baseline["memory_current"].as_u64().expect("memory_current is a number");

        // Poll (rather than one fixed sleep) until memory_current has
        // genuinely risen by a real, substantial margin — alloc-hold's own
        // 8ms-per-MiB pacing (`lifecycle_fixture.rs`'s own doc comment)
        // means 20 MiB takes at least ~160ms of real wall-clock time to
        // accumulate, plus real allocator/page-fault overhead.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let latest: serde_json::Value = loop {
            let (status, body) = call_router(app.clone(), "GET", format!("/containers/{id}/cgroup")).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse cgroup JSON");
            let current = parsed["memory_current"].as_u64().expect("memory_current is a number");
            if current >= baseline_memory + 5 * 1024 * 1024 || std::time::Instant::now() >= deadline {
                break parsed;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let final_memory = latest["memory_current"].as_u64().expect("memory_current is a number");
        assert!(
            final_memory >= baseline_memory + 5 * 1024 * 1024,
            "memory_current must rise by at least 5 MiB under alloc-hold's real load: \
             baseline={baseline_memory}, final={final_memory}, latest response={latest}"
        );

        assert_eq!(
            latest["memory_max"].as_str().unwrap(),
            memory_limit.to_string(),
            "memory_max must report the real CONFIGURED limit this test set, got: {latest}"
        );
        assert!(
            latest["pids_current"].as_u64().unwrap() >= 1,
            "pids_current must report at least the fixture's own real process: {latest}"
        );
        assert!(
            latest["cpu_stat"]["usage_usec"].as_u64().unwrap() > 0,
            "cpu_stat.usage_usec must be genuinely non-zero after real allocator/page-fault work: \
             {latest}"
        );
        assert!(latest["io_stat"].is_array(), "io_stat must be an array: {latest}");

        // ---- cleanup: alloc-hold sleeps ~300s after finishing its
        // allocation, so `DELETE ?force=true` (not a graceful stop) is
        // what actually reaps it — real proof this test's own real cgroup
        // (created under the real, shared /sys/fs/cgroup/kestrel/<id>
        // hierarchy `mount_cgroups` exposes, per that helper's own doc
        // comment) doesn't leak into this shared VM beyond this test's own
        // run, matching `test_lifecycle_start_then_stop_end_to_end`'s own
        // "always delete before finishing" precedent. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        drop(shim_guard);
        drop(artifacts_guard);
    }

    /// Real proof of Step 3: a direct passthrough of `CgroupManager::
    /// pressure` for all three resources against a real running container.
    /// PSI's `total_us` fields are kernel-side CUMULATIVE counters (never
    /// decrease) — asserted for real across two time-separated reads taken
    /// while the container is under `alloc-hold`'s real memory-allocation
    /// load, alongside the documented `[0, 100]` bound on every `avgN`
    /// field — genuinely tied to this specific endpoint's real output, not
    /// a placeholder "200 OK" check.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_pressure_endpoint_reports_valid_and_monotonic_psi_values() {
        let memory_limit: i64 = 60 * 1024 * 1024; // tighter than the cgroup test's own limit — real
                                                    // memory pressure/reclaim is more likely to show up
                                                    // the closer the configured limit sits to the
                                                    // working set alloc-hold actually builds.
        let (app, id, _run_dir, _mount_guard, process_guard, shim_guard, artifacts_guard, _state_path, init_pid) =
            t18_spawn_alloc_hold_container(40, memory_limit).await;

        fn assert_valid_psi(psi: &serde_json::Value, label: &str) {
            for line_key in ["some", "full"] {
                let Some(line) = psi.get(line_key).filter(|v| !v.is_null()) else { continue };
                for avg_key in ["avg10", "avg60", "avg300"] {
                    let avg = line[avg_key].as_f64().unwrap_or_else(|| panic!("{label}.{line_key}.{avg_key} must be a number: {psi}"));
                    assert!(
                        (0.0..=100.0).contains(&avg),
                        "{label}.{line_key}.{avg_key} must be within PSI's documented [0, 100] \
                         bound, got {avg} in {psi}"
                    );
                }
                assert!(line["total_us"].as_u64().is_some(), "{label}.{line_key}.total_us must be a number: {psi}");
            }
        }

        let (status1, body1) = call_router(app.clone(), "GET", format!("/containers/{id}/pressure")).await;
        assert_eq!(
            status1,
            axum::http::StatusCode::OK,
            "pressure endpoint failed: {}",
            String::from_utf8_lossy(&body1)
        );
        let first: serde_json::Value = serde_json::from_slice(&body1).expect("parse pressure JSON");
        for resource in ["cpu", "memory", "io"] {
            assert_valid_psi(&first[resource], resource);
        }

        // Give alloc-hold real time to keep running (and potentially keep
        // accumulating stall time) between the two reads.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (status2, body2) = call_router(app.clone(), "GET", format!("/containers/{id}/pressure")).await;
        assert_eq!(status2, axum::http::StatusCode::OK);
        let second: serde_json::Value = serde_json::from_slice(&body2).expect("parse pressure JSON");
        for resource in ["cpu", "memory", "io"] {
            assert_valid_psi(&second[resource], resource);
            let before = first[resource]["some"]["total_us"].as_u64().unwrap();
            let after = second[resource]["some"]["total_us"].as_u64().unwrap();
            assert!(
                after >= before,
                "{resource}.some.total_us is a cumulative kernel counter and must never decrease \
                 across two reads of the same live cgroup: before={before}, after={after}"
            );
        }

        // ---- cleanup: `DELETE ?force=true` (not a graceful stop —
        // alloc-hold sleeps ~300s after finishing its allocation) reaps the
        // process and destroys this test's own real cgroup, matching
        // `test_lifecycle_start_then_stop_end_to_end`'s own precedent. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        drop(shim_guard);
        drop(artifacts_guard);
    }

    // -----------------------------------------------------------------
    // Task 19: introspection endpoints, part B (layers, copyups,
    // seccomp, system namespaces) — root-gated
    // -----------------------------------------------------------------

    /// Real proof of Step 1: `layers.json` (written by `bundle.rs`, this
    /// same task's own gap-fill to Task 8 — see `registry::LayersMeta`'s
    /// own doc comment) round-trips through `GET /containers/:id/layers`
    /// with the real, single synthetic `bundle-<id>` chain-id a
    /// `bundle_rootfs`-sourced container gets (`kestrel-runtime
    /// create.rs`'s own `stage_bundle_rootfs_as_synthetic_layer`
    /// fallback), a real `origin` path that matches `LayerStore::diff_dir`
    /// byte-for-byte, and a real `size_bytes` that matches the exact,
    /// INDEPENDENTLY-known byte length of the one file this test's own
    /// synthetic rootfs contains — computed here from the literal byte
    /// string this test itself wrote, not by re-running the same
    /// directory-walk code the endpoint under test uses (which would only
    /// prove the walk is self-consistent, not that it reports the truth).
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_layers_endpoint_reports_real_chain_id_origin_and_size() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_stub_kestrel_init_at_target_debug();

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let _mount_guard = mount_cgroups(data_dir.path());

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        const MARKER_CONTENT: &[u8] = b"hello-task19-layers-real-content";
        std::fs::write(rootfs_dir.path().join("marker"), MARKER_CONTENT).expect("write marker");

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let body = serde_json::json!({ "bundle_rootfs": rootfs_dir.path(), "tty": false });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_body_bytes = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_body_bytes)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_body_bytes).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        // ---- the real assertion ----
        let (status, resp_body) = call_router(app.clone(), "GET", format!("/containers/{id}/layers")).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "layers endpoint failed: {}",
            String::from_utf8_lossy(&resp_body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&resp_body).expect("parse layers JSON");
        let layers = parsed["layers"].as_array().expect("layers array");
        assert_eq!(
            layers.len(),
            1,
            "a plain bundle_rootfs container gets exactly one synthetic layer, got: {parsed}"
        );

        let expected_chain_id = format!("bundle-{id}");
        assert_eq!(layers[0]["chain_id"], expected_chain_id);

        let expected_diff_dir =
            kestrel_rootfs::snapshot::LayerStore::new(data_dir.path().to_path_buf()).diff_dir(&expected_chain_id);
        assert_eq!(layers[0]["origin"], expected_diff_dir.display().to_string());

        // Independently verify the marker file genuinely landed at that
        // real path with the real content, then assert the endpoint's
        // reported size matches its real, independently-known length.
        let real_marker = std::fs::read(expected_diff_dir.join("marker")).expect("read real marker in diff dir");
        assert_eq!(real_marker, MARKER_CONTENT);
        assert_eq!(layers[0]["size_bytes"].as_u64().unwrap(), MARKER_CONTENT.len() as u64);

        // ---- cleanup ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        let _ = std::fs::remove_dir_all(data_dir.path().join("containers").join(&id));
    }

    /// Same real, statically-linked `lifecycle_fixture` rootfs as
    /// `build_lifecycle_synthetic_rootfs`, plus a pre-existing
    /// `/app.conf` file — `kestrel-runtime create.rs`'s
    /// `stage_bundle_rootfs_as_synthetic_layer` copies this whole
    /// directory into the synthetic layer's diff dir (the container's
    /// LOWER layer), so `app.conf` genuinely exists below the overlay
    /// before the container ever runs, and the entrypoint's own write to
    /// `/app.conf` triggers a REAL overlayfs copy-up — same fixture setup
    /// `copyup_scanner.rs`'s own Task 15 test already established,
    /// duplicated here (not imported — that module's test infra is
    /// private to it) per this crate's own "test infra lives in each test
    /// module that needs it" precedent (see `collect_seccomp_violation_
    /// event`'s own doc comment for the same convention stated
    /// explicitly).
    fn build_copyup_synthetic_rootfs_for_task19(dest: &Path) {
        build_lifecycle_synthetic_rootfs(dest);
        std::fs::write(dest.join("app.conf"), b"lower-layer-original-app-conf-content")
            .expect("write lower-layer app.conf");
    }

    /// Real proof of Step 2: the exact same `kestrel_rootfs::copyup::
    /// scan_copy_ups` call Task 15's background scanner (`copyup_
    /// scanner.rs`) already uses, run here ON DEMAND — Task 15's own
    /// scanner never even runs in this test. A real container entrypoint
    /// (the real, statically-linked `lifecycle_fixture`'s own
    /// `copyup-write` mode) writes to a path that already exists in its
    /// synthetic lower layer, triggering a genuine overlayfs copy-up;
    /// `GET /containers/:id/copyups` reports it with the real upperdir
    /// file size, the real originating chain-id, and `kind: "Data"` —
    /// values this test verifies against the fixture's own known,
    /// hardcoded first-write byte string, not against the endpoint's own
    /// internal computation.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_copyups_endpoint_reports_real_full_current_set() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_copyup_synthetic_rootfs_for_task19(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        // A generous delay before the fixture's own SECOND write —
        // irrelevant to this endpoint's correctness either way (it always
        // reports the FULL current set fresh, with no dedup to break),
        // but keeps the window this test polls within comfortably before
        // the second write could land and change `size_bytes` out from
        // under a slow CI run.
        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "copyup-write", "/app.conf", "60000"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_resp_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // ---- poll the on-demand endpoint itself until the real
        // overlayfs copy-up genuinely lands (no scanner/event-bus
        // involved at all here — this endpoint re-scans fresh every
        // call). ----
        const FIRST_WRITE_CONTENT: &[u8] = b"first-write-triggers-copy-up";
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let parsed = loop {
            let (status, body) = call_router(app.clone(), "GET", format!("/containers/{id}/copyups")).await;
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "copyups endpoint failed: {}",
                String::from_utf8_lossy(&body)
            );
            let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse copyups JSON");
            let arr = parsed["copy_ups"].as_array().expect("copy_ups array");
            if arr.iter().any(|e| e["path"] == "app.conf") {
                break parsed;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for a real copy-up to appear: last response {parsed}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let entry = parsed["copy_ups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "app.conf")
            .expect("app.conf entry");
        assert_eq!(
            entry["size_bytes"].as_u64().unwrap(),
            FIRST_WRITE_CONTENT.len() as u64,
            "size_bytes should be the real upperdir file size after the fixture's first write: {entry}"
        );
        assert_eq!(entry["from_layer"], format!("bundle-{id}"));
        assert_eq!(entry["kind"], "Data");

        // ---- cleanup: `DELETE ?force=true` (not a graceful stop — the
        // fixture is still sleeping out its 60s delay) reaps the real
        // process AND destroys this test's own real cgroup
        // (`kestrel-runtime delete.rs`'s own force-kill + `CgroupManager::
        // destroy` steps) — `copyup_scanner.rs`'s own Task 15 test skips
        // this (it never calls `DELETE` at all), which leaks exactly this
        // container's cgroup; this test does not repeat that gap. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }

    /// Real proof of Step 3: the active profile reported by `GET
    /// /containers/:id/seccomp` matches the real `SCMP_ACT_NOTIFY`
    /// profile this test's own `POST /containers` call configured
    /// (`seccomp_notify_syscalls`, Task 16's own API knob) byte-for-byte —
    /// read straight back out of the real `config.json` `bundle.rs`
    /// wrote, not fabricated — and starts with an empty violation log.
    /// Once the SAME real end-to-end seccomp-notify chain Task 16's own
    /// capstone test exercises (`personality()` -> kernel suspend ->
    /// `kestrel-shim`'s notify supervisor -> `Frame::SeccompEvent` over
    /// `attach.sock` -> `Event::SeccompViolation` on the event bus)
    /// produces a real violation, this daemon's OWN always-on
    /// `SeccompLog` consumer (`spawn_seccomp_log_consumer`, spawned here
    /// exactly as `main()` spawns it in production) picks it up
    /// independently of this test's own `/events` SSE subscriber, and the
    /// endpoint's violation log genuinely reflects it.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_seccomp_endpoint_reports_real_profile_and_real_violation_log() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let event_bus = events::new_bus();
        let seccomp_log = api::introspect::SeccompLog::new();
        // Spawned here, exactly as `main()` spawns it in production —
        // BEFORE any request that could publish a real violation.
        api::introspect::spawn_seccomp_log_consumer(event_bus.clone(), seccomp_log.clone());
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus,
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log,
        });
        let app = build_router(app_state);

        // ---- subscribe to /events BEFORE triggering anything ----
        let events_request = axum::http::Request::builder()
            .method("GET")
            .uri("/events")
            .body(axum::body::Body::empty())
            .unwrap();
        let events_response = tower::ServiceExt::oneshot(app.clone(), events_request)
            .await
            .expect("GET /events oneshot");
        assert_eq!(events_response.status(), axum::http::StatusCode::OK);
        let mut events_body = events_response.into_body();

        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "trigger-personality"],
            "seccomp_notify_syscalls": ["personality"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_resp_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);
        let shim_guard = ShimGuard(id.clone());
        let artifacts_guard = ContainerArtifactsGuard { run_dir: run_dir.path().to_path_buf(), id: id.clone() };

        // ---- first assertion: the real profile, read back before the
        // container has even started, with an empty violation log. ----
        let (profile_status, profile_body) =
            call_router(app.clone(), "GET", format!("/containers/{id}/seccomp")).await;
        assert_eq!(
            profile_status,
            axum::http::StatusCode::OK,
            "seccomp endpoint failed: {}",
            String::from_utf8_lossy(&profile_body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&profile_body).expect("parse seccomp JSON");
        let profile = &parsed["profile"];
        assert!(!profile.is_null(), "a seccomp_notify_syscalls container must report a real profile, got: {parsed}");
        assert_eq!(profile["default_action"], "SCMP_ACT_ALLOW");
        let architectures: Vec<&str> =
            profile["architectures"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(architectures.contains(&"SCMP_ARCH_X86_64"), "expected SCMP_ARCH_X86_64 in {architectures:?}");
        assert!(architectures.contains(&"SCMP_ARCH_AARCH64"), "expected SCMP_ARCH_AARCH64 in {architectures:?}");
        let syscalls = profile["syscalls"].as_array().unwrap();
        assert_eq!(syscalls.len(), 1, "expected exactly one syscall rule, got: {parsed}");
        assert_eq!(syscalls[0]["names"], serde_json::json!(["personality"]));
        assert_eq!(syscalls[0]["action"], "SCMP_ACT_NOTIFY");
        assert_eq!(
            parsed["violations"].as_array().unwrap().len(),
            0,
            "no violation has happened yet: {parsed}"
        );

        // ---- attach + wait for the Ready acknowledgment, same
        // deterministic-synchronization technique as Task 16's own
        // capstone test (see that test's own doc comment for the full
        // reasoning) ----
        let (addr, server_handle) = spawn_test_server(app.clone()).await;
        let ws_url = format!("ws://{addr}/containers/{id}/attach");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(ws_url)
            .await
            .expect("connect to attach WS endpoint");
        let ready_msg = tokio::time::timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut ws))
            .await
            .expect("timed out waiting for the attach session's Ready acknowledgment")
            .expect("attach WS stream ended before sending Ready")
            .expect("reading the attach WS Ready message");
        assert_eq!(
            ready_msg,
            tokio_tungstenite::tungstenite::Message::Text(api::attach::ATTACH_READY_TEXT.into()),
            "expected the attach session's first WS message to be the Ready acknowledgment, got: {ready_msg:?}"
        );
        let drain_task = tokio::spawn(async move {
            while let Some(msg) = futures_util::StreamExt::next(&mut ws).await {
                if msg.is_err() {
                    break;
                }
            }
        });

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // ---- confirm the real violation reached the event bus, via this
        // test's own /events subscriber (same helper Task 16's own
        // capstone test uses) ----
        let violation = collect_seccomp_violation_event(&mut events_body, &id, Duration::from_secs(20)).await;
        assert_eq!(violation["syscall"], "personality");

        // ---- the real assertion for THIS task: the SAME real violation
        // is independently observed by this daemon's own always-on
        // SeccompLog consumer (a separate subscriber to the same event
        // bus) and genuinely surfaced by GET /containers/:id/seccomp —
        // polled for a bounded window since the two subscribers process
        // independently, with no ordering guarantee between them. ----
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let seccomp_parsed = loop {
            let (status, body) = call_router(app.clone(), "GET", format!("/containers/{id}/seccomp")).await;
            assert_eq!(status, axum::http::StatusCode::OK);
            let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse seccomp JSON");
            if parsed["violations"].as_array().unwrap().iter().any(|v| v == "personality") {
                break parsed;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the violation log to reflect the real violation: {parsed}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(seccomp_parsed["violations"], serde_json::json!(["personality"]));

        // ---- cleanup: `DELETE ?force=true`, not just `stop` — force-
        // delete also destroys this test's own real cgroup
        // (`kestrel-runtime delete.rs`'s own `CgroupManager::destroy`
        // step), which a plain `stop` alone never does. Task 16's own
        // capstone test (which this test's setup otherwise mirrors) only
        // calls `stop`, which leaks exactly this container's cgroup; this
        // test does not repeat that gap. ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        drain_task.abort();
        server_handle.abort();
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        drop(shim_guard);
        drop(artifacts_guard);
    }

    /// Adversarial-review fix (Task 19 Part B): `SeccompLog`'s outer
    /// `HashMap` used to keep a container's key forever once a real
    /// violation had populated it — `delete_container` removed the
    /// registry entry but never touched `AppState.seccomp_log`, a slow
    /// leak as container ids churn over a long-running daemon's
    /// lifetime. This is the same real end-to-end seccomp-notify chain
    /// `test_seccomp_endpoint_reports_real_profile_and_real_violation_log`
    /// uses to put a genuine entry in the log (not a synthetic one
    /// inserted straight into the map), followed by a real `DELETE
    /// ?force=true`, then a direct, test-only check
    /// (`SeccompLog::contains_key`) that the outer map's key for this
    /// container id is gone afterward — `snapshot`/`GET .../seccomp`
    /// alone can't distinguish "key removed" from "key present but
    /// empty", so this reaches into `AppState.seccomp_log` directly, the
    /// same way `test_system_namespaces_endpoint_reports_real_proc_wide_scan`
    /// below constructs `AppState` directly in this same test module.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_delete_container_prunes_its_seccomp_log_entry() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let event_bus = events::new_bus();
        let seccomp_log = api::introspect::SeccompLog::new();
        // Spawned here, exactly as `main()` spawns it in production —
        // BEFORE any request that could publish a real violation.
        api::introspect::spawn_seccomp_log_consumer(event_bus.clone(), seccomp_log.clone());
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus,
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: seccomp_log.clone(),
        });
        let app = build_router(app_state);

        // ---- subscribe to /events BEFORE triggering anything ----
        let events_request = axum::http::Request::builder()
            .method("GET")
            .uri("/events")
            .body(axum::body::Body::empty())
            .unwrap();
        let events_response = tower::ServiceExt::oneshot(app.clone(), events_request)
            .await
            .expect("GET /events oneshot");
        assert_eq!(events_response.status(), axum::http::StatusCode::OK);
        let mut events_body = events_response.into_body();

        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "trigger-personality"],
            "seccomp_notify_syscalls": ["personality"],
        });
        let create_request = axum::http::Request::builder()
            .method("POST")
            .uri("/containers")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&create_body).unwrap()))
            .unwrap();
        let create_response = tower::ServiceExt::oneshot(app.clone(), create_request)
            .await
            .expect("router oneshot");
        let create_status = create_response.status();
        let create_resp_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .expect("reading response body");
        assert_eq!(
            create_status,
            axum::http::StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp_body)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp_body).unwrap()["id"]
            .as_str()
            .expect("response has a real id")
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);
        let shim_guard = ShimGuard(id.clone());
        let artifacts_guard = ContainerArtifactsGuard { run_dir: run_dir.path().to_path_buf(), id: id.clone() };

        // Before the container has ever run, this id genuinely has no key
        // in the log yet.
        assert!(
            !seccomp_log.contains_key(&id).await,
            "a freshly created container must not already have a seccomp log entry"
        );

        // ---- attach + wait for the Ready acknowledgment, same
        // deterministic-synchronization technique as Task 16's own
        // capstone test ----
        let (addr, server_handle) = spawn_test_server(app.clone()).await;
        let ws_url = format!("ws://{addr}/containers/{id}/attach");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(ws_url)
            .await
            .expect("connect to attach WS endpoint");
        let ready_msg = tokio::time::timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut ws))
            .await
            .expect("timed out waiting for the attach session's Ready acknowledgment")
            .expect("attach WS stream ended before sending Ready")
            .expect("reading the attach WS Ready message");
        assert_eq!(
            ready_msg,
            tokio_tungstenite::tungstenite::Message::Text(api::attach::ATTACH_READY_TEXT.into()),
            "expected the attach session's first WS message to be the Ready acknowledgment, got: {ready_msg:?}"
        );
        let drain_task = tokio::spawn(async move {
            while let Some(msg) = futures_util::StreamExt::next(&mut ws).await {
                if msg.is_err() {
                    break;
                }
            }
        });

        let (start_status, start_body) =
            call_router(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(
            start_status,
            axum::http::StatusCode::OK,
            "start failed: {}",
            String::from_utf8_lossy(&start_body)
        );
        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // ---- confirm the real violation reached the event bus ----
        let violation = collect_seccomp_violation_event(&mut events_body, &id, Duration::from_secs(20)).await;
        assert_eq!(violation["syscall"], "personality");

        // ---- confirm this daemon's own SeccompLog genuinely has a live
        // entry for this container id BEFORE delete — the real precondition
        // for this test to prove anything about pruning ----
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if seccomp_log.contains_key(&id).await {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for SeccompLog to genuinely record the real violation for {id}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // ---- the real assertion for this fix: `DELETE ?force=true` must
        // prune the outer map's key for this id, not just the registry
        // entry ----
        let (delete_status, delete_body) =
            call_router(app.clone(), "DELETE", format!("/containers/{id}?force=true")).await;
        assert_eq!(
            delete_status,
            axum::http::StatusCode::OK,
            "force-delete failed: {}",
            String::from_utf8_lossy(&delete_body)
        );
        assert!(
            !seccomp_log.contains_key(&id).await,
            "delete_container must prune this container's entry out of SeccompLog's outer map, \
             not just the registry"
        );

        drain_task.abort();
        server_handle.abort();
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        drop(shim_guard);
        drop(artifacts_guard);
    }

    /// Real proof of Step 4: a genuine host-wide `/proc/*/ns/*` scan —
    /// this TEST PROCESS'S OWN real pid appears in the response (proving
    /// the scan is genuinely walking `/proc`, not returning a fixed or
    /// fabricated set), with a `pid`-namespace inode that matches
    /// `/proc/self/ns/pid`'s real inode — read independently, directly
    /// off `/proc`, not through the endpoint under test.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_system_namespaces_endpoint_reports_real_proc_wide_scan() {
        use std::os::unix::fs::MetadataExt;

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        // Never spawned/exec'd by this test (no container is created), so
        // these don't need to resolve to real binaries.
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.path().to_path_buf(),
            registry,
            shim_path: PathBuf::from("unused-in-this-test"),
            runtime_path: PathBuf::from("unused-in-this-test"),
            stop_grace_period_s: 10,
            metrics_rx: idle_metrics_rx(),
            event_bus: idle_event_bus(),
            last_status_map: metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state);

        let (status, body) = call_router(app.clone(), "GET", "/system/namespaces".to_string()).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "system namespaces endpoint failed: {}",
            String::from_utf8_lossy(&body)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse system namespaces JSON");
        let processes = parsed["processes"].as_object().expect("processes object");

        let own_pid = std::process::id();
        let own_entry = processes.get(&own_pid.to_string()).unwrap_or_else(|| {
            panic!(
                "this test's own real pid {own_pid} must be present in a genuine /proc-wide scan, \
                 got {} entries",
                processes.len()
            )
        });

        let real_pid_ns_inode = std::fs::metadata("/proc/self/ns/pid").expect("stat /proc/self/ns/pid").ino();
        let reported = own_entry.get("pid").and_then(|v| v.as_u64()).expect("own entry has a pid namespace inode");
        assert_eq!(
            reported, real_pid_ns_inode,
            "reported pid-namespace inode for this test's own real pid must match /proc/self/ns/pid's \
             real inode"
        );
    }

    // -------------------------------------------------------------------
    // Task 21: graceful shutdown — root-gated, spawns a REAL, separate
    // `kestreld` OS subprocess (not `build_router`'s in-process `oneshot`
    // every other test in this file uses) so a genuine `SIGTERM` can be
    // delivered to kestreld's own real pid, and the container it created
    // can be checked for survival entirely independently of it. Reuses
    // this file's own established real-container conventions
    // (`install_real_kestrel_init_at_target_debug`, `real_data_dir`,
    // `build_lifecycle_synthetic_rootfs`, `mount_cgroups`,
    // `unpin_default_namespaces`, `cleanup_real_container_artifacts` — all
    // defined above, first introduced around `test_lifecycle_start_then_
    // stop_end_to_end`) rather than re-inventing a parallel set.
    // -------------------------------------------------------------------

    /// Binds an ephemeral TCP port, reads back which real port the kernel
    /// assigned, then drops the listener — the standard "find a free port"
    /// idiom. A real (if narrow) TOCTOU race exists between the drop here
    /// and this test's own later bind of the same port for the real
    /// `kestreld` subprocess, but `SO_REUSEADDR` plus this test never
    /// running concurrently with itself (root-gated, single-threaded by
    /// convention across this whole file's own test suite) makes it a
    /// non-issue in practice — the same tradeoff every other "find a free
    /// port" helper in the ecosystem makes.
    fn find_free_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local_addr").port()
    }

    /// Writes a real, minimal `kestreld` config file — just enough of
    /// `[daemon]` (every other section legitimately falls back to its own
    /// documented default via `Config`'s `#[serde(default)]` fields,
    /// exactly as `config.rs`'s own `partial_config_falls_back_to_defaults`
    /// test already proves) to point a real spawned `kestreld` subprocess
    /// at this test's own tempdir `run_dir`/`data_dir`, a tempdir-local
    /// unix socket, and a real, free TCP port.
    fn write_daemon_config(config_path: &Path, socket_path: &Path, http_addr: &str, run_dir: &Path, data_dir: &Path) {
        let toml = format!(
            "[daemon]\n\
             socket = {socket_path:?}\n\
             http_addr = {http_addr:?}\n\
             state_dir = {run_dir_str:?}\n\
             data_dir = {data_dir_str:?}\n\
             metrics_interval_ms = 1000\n\
             stop_grace_period_s = 5\n",
            socket_path = socket_path.display().to_string(),
            http_addr = http_addr,
            run_dir_str = run_dir.display().to_string(),
            data_dir_str = data_dir.display().to_string(),
        );
        std::fs::write(config_path, toml).expect("write daemon config.toml");
    }

    /// Spawns a real `kestreld` subprocess against `config_path`, with its
    /// own stdout/stderr redirected to real files under `log_dir` (never
    /// read by this test directly — just there so a failure's root cause is
    /// inspectable after the fact, and so an unbounded pipe buffer can never
    /// stall the child if this test doesn't drain it). Returns the child
    /// handle and its real OS pid.
    fn spawn_real_kestreld(kestreld_bin: &Path, config_path: &Path, log_dir: &Path, log_tag: &str) -> (tokio::process::Child, i32) {
        let stdout_log = std::fs::File::create(log_dir.join(format!("{log_tag}.stdout.log")))
            .expect("create kestreld stdout log");
        let stderr_log = std::fs::File::create(log_dir.join(format!("{log_tag}.stderr.log")))
            .expect("create kestreld stderr log");
        let child = tokio::process::Command::new(kestreld_bin)
            .arg("--config")
            .arg(config_path)
            .stdout(std::process::Stdio::from(stdout_log))
            .stderr(std::process::Stdio::from(stderr_log))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn real kestreld subprocess ({}): {e}", kestreld_bin.display()));
        let pid = child.id().expect("just-spawned kestreld child has a real pid") as i32;
        (child, pid)
    }

    /// Best-effort, idempotent, belt-and-suspenders cleanup for THIS test's
    /// own real container — matching this file's own established
    /// `ProcessGuard`/`ShimGuard`/`ContainerArtifactsGuard` posture, just
    /// combined into one guard since this test's whole point is that the
    /// container survives past its owning daemon, so ordinary "ask the
    /// daemon to clean up" cleanup can't assume any particular daemon is
    /// still alive by the time this runs. Re-reads `state.json` directly
    /// off disk (never through a daemon) to find whatever pid is CURRENTLY
    /// recorded and SIGKILLs it, best-effort pkills the daemonized shim by
    /// container id, unpins every namespace `create()` pinned, and removes
    /// the data-dir artifacts a successful `delete()` would otherwise
    /// already have removed. Running this after this test's own deliberate,
    /// successful stop+delete is a harmless no-op — same "safe to race
    /// against already-cleaned-up state" contract every other guard in this
    /// file documents.
    struct RealContainerGuard {
        run_dir: PathBuf,
        id: String,
    }
    impl Drop for RealContainerGuard {
        fn drop(&mut self) {
            let state_path = self.run_dir.join(&self.id).join("state.json");
            if let Ok(state) = kestrel_oci::state::State::read(&state_path) {
                if let Some(pid) = state.pid {
                    let _ =
                        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
                }
            }
            let _ = std::process::Command::new("pkill")
                .args(["-9", "-f", &format!("kestrel-shim --id {} ", self.id)])
                .status();
            unpin_default_namespaces(&self.run_dir, &self.id);
            cleanup_real_container_artifacts(&self.id);
        }
    }

    /// The real proof this whole task exists for (design doc §10, plan's
    /// own Task 21 Step 2): create + start a REAL container (genuine
    /// `pivot_root`, genuine exec'd long-running entrypoint, genuine
    /// `Created` -> `Running` transition) through a REAL, separately
    /// spawned `kestreld` OS process, send that process a REAL `SIGTERM`,
    /// confirm it exits promptly — and confirm the container's real
    /// entrypoint process is STILL ALIVE afterward, checked directly via
    /// `kill(pid, 0)` against the pid `kestrel_runtime::start` itself
    /// resolved and recorded in `state.json`, read straight off disk —
    /// never by asking the now-dead daemon (which no longer exists to
    /// ask). This is the single most important property the whole
    /// `kestrel-shim` architecture (Task 1/2) exists to guarantee.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires root"]
    async fn test_sigterm_to_kestreld_exits_promptly_and_container_survives() {
        install_real_kestrel_init_at_target_debug();
        let kestreld_bin = target_debug_dir().join("kestreld");
        assert!(
            kestreld_bin.is_file(),
            "kestreld binary not found at {} — run `cargo build -p kestreld` (or `cargo test -p \
             kestreld`, which builds it too) first",
            kestreld_bin.display()
        );

        // `real_data_dir()` (`/var/lib/kestrel`), NOT a tempdir — same
        // reason every other real-`kestrel-init` test in this file uses it
        // (see that fn's own doc comment): the real, statically-linked
        // `kestrel-init` hardcodes its own `data_dir` as that literal path,
        // so the daemon subprocess this test spawns must be configured with
        // the exact same `data_dir` for its host-side layer staging to land
        // where the real `kestrel-init` will actually look for it.
        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_lifecycle_synthetic_rootfs(rootfs_dir.path());

        // A scratch dir for this test's own config files/subprocess logs —
        // deliberately separate from `data_dir` (the real, shared
        // `/var/lib/kestrel`) so nothing this test writes for its own
        // bookkeeping ever gets mistaken for a real container artifact.
        let scratch_dir = tempfile::tempdir().expect("scratch tempdir for config/logs");

        let socket_path = run_dir.path().join("kestreld.sock");
        let port = find_free_tcp_port();
        let http_addr = format!("127.0.0.1:{port}");
        let config_path = scratch_dir.path().join("config.toml");
        write_daemon_config(&config_path, &socket_path, &http_addr, run_dir.path(), &data_dir);

        let (mut daemon, daemon_pid) =
            spawn_real_kestreld(&kestreld_bin, &config_path, scratch_dir.path(), "kestreld");

        let socket_ready = poll_until(Duration::from_secs(20), || {
            std::os::unix::net::UnixStream::connect(&socket_path).ok()
        })
        .await;
        assert!(
            socket_ready.is_some(),
            "kestreld's unix socket at {} never became connectable — see {}",
            socket_path.display(),
            scratch_dir.path().join("kestreld.stderr.log").display()
        );

        // ---- create + start a REAL container over the real HTTP API ----
        let client = reqwest::Client::new();
        let base = format!("http://{http_addr}");

        let create_resp = client
            .post(format!("{base}/containers"))
            .json(&serde_json::json!({
                "bundle_rootfs": rootfs_dir.path(),
                "cmd": ["/fixture", "sleep", "300"],
                "tty": false,
            }))
            .send()
            .await
            .expect("POST /containers");
        assert_eq!(
            create_resp.status(),
            reqwest::StatusCode::CREATED,
            "unexpected create response: {}",
            create_resp.text().await.unwrap_or_default()
        );
        let created: serde_json::Value = create_resp.json().await.expect("parse create response JSON");
        let id = created["id"].as_str().expect("response has a real id").to_string();
        assert!(!id.is_empty());
        let guard = RealContainerGuard {
            run_dir: run_dir.path().to_path_buf(),
            id: id.clone(),
        };

        let state_path = run_dir.path().join(&id).join("state.json");
        let created_state = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        assert_eq!(created_state.status, kestrel_oci::state::Status::Created);
        let created_pid = created_state.pid;

        let start_resp = client
            .post(format!("{base}/containers/{id}/start"))
            .send()
            .await
            .expect("POST start");
        assert_eq!(
            start_resp.status(),
            reqwest::StatusCode::OK,
            "unexpected start response: {}",
            start_resp.text().await.unwrap_or_default()
        );

        // ---- poll `state.json` directly off disk (same technique as
        // `test_lifecycle_start_then_stop_end_to_end` above) until genuinely
        // `Running` with a pid that has changed away from kestrel-init's own
        // (`start.rs`'s own doc comment: `Running` is written BEFORE the
        // best-effort entrypoint-pid resolution finishes, so a pid read too
        // early can still be kestrel-init's own, not the real entrypoint) ----
        let resolved = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running && s.pid != created_pid)
        })
        .await
        .unwrap_or_else(|| panic!("container {id} never reached Running with a resolved entrypoint pid"));
        let entrypoint_pid = resolved.pid.expect("a Running state always carries a pid");

        let cmdline_before = std::fs::read_to_string(format!("/proc/{entrypoint_pid}/cmdline")).unwrap_or_default();
        assert!(
            cmdline_before.contains("fixture"),
            "resolved pid {entrypoint_pid} does not look like the real /fixture entrypoint \
             (cmdline: {cmdline_before:?})"
        );

        // ---- the real test: SIGTERM to kestreld's OWN pid, bounded wait
        // for its own exit ----
        let shutdown_start = std::time::Instant::now();
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(daemon_pid), nix::sys::signal::Signal::SIGTERM)
            .expect("send SIGTERM to the real kestreld process");

        let wait_result = tokio::time::timeout(Duration::from_secs(10), daemon.wait()).await;
        let elapsed = shutdown_start.elapsed();
        let status = match wait_result {
            Ok(inner) => inner.expect("waiting on kestreld child"),
            Err(_) => panic!(
                "kestreld (pid {daemon_pid}) did not exit within 10s of receiving SIGTERM \
                 (elapsed {elapsed:?}) — graceful shutdown not wired up, or hung"
            ),
        };
        assert!(
            status.success(),
            "kestreld should exit cleanly (status 0) on a graceful SIGTERM shutdown, got {status:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "kestreld took {elapsed:?} to exit after SIGTERM with no in-flight requests — not prompt"
        );
        tracing::info!(?elapsed, "kestreld exited after SIGTERM");

        // ---- THE assertion this whole task exists for: the container's
        // real entrypoint process is STILL RUNNING, checked directly via a
        // real `kill(pid, 0)` liveness probe against the real pid — never
        // by asking the now-dead daemon (design doc §10: containers are not
        // children of kestreld, so there is nothing left to ask it) ----
        let still_alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(entrypoint_pid), None).is_ok();
        assert!(
            still_alive,
            "container entrypoint (pid {entrypoint_pid}) should still be alive after kestreld's own \
             SIGTERM-triggered exit, but it is not — this is exactly the property the kestrel-shim \
             architecture (design doc §2/§10) exists to guarantee"
        );
        let cmdline_after = std::fs::read_to_string(format!("/proc/{entrypoint_pid}/cmdline")).unwrap_or_default();
        assert!(
            cmdline_after.contains("fixture"),
            "pid {entrypoint_pid} exists after kestreld's death but no longer looks like the real \
             entrypoint (possible pid reuse); cmdline: {cmdline_after:?}"
        );

        // ---- cleanup: this test's own responsibility (the container has
        // no live owner anymore) — spin up a SECOND, fresh kestreld pointed
        // at the same run_dir/data_dir, which recovers it (Task 7) exactly
        // as a real operator restarting kestreld would, then tear it down
        // through the real stop+delete HTTP path (Task 9) ----
        let port2 = find_free_tcp_port();
        let http_addr2 = format!("127.0.0.1:{port2}");
        let socket_path2 = run_dir.path().join("kestreld2.sock");
        let config_path2 = scratch_dir.path().join("config2.toml");
        write_daemon_config(&config_path2, &socket_path2, &http_addr2, run_dir.path(), &data_dir);

        let (mut daemon2, daemon2_pid) =
            spawn_real_kestreld(&kestreld_bin, &config_path2, scratch_dir.path(), "kestreld2");

        let socket2_ready = poll_until(Duration::from_secs(20), || {
            std::os::unix::net::UnixStream::connect(&socket_path2).ok()
        })
        .await;
        assert!(
            socket2_ready.is_some(),
            "cleanup kestreld's unix socket never became connectable — see {}",
            scratch_dir.path().join("kestreld2.stderr.log").display()
        );
        let base2 = format!("http://{http_addr2}");

        // Bonus real-property check (not just blind cleanup): the fresh
        // instance's own startup recovery must actually find this container
        // before this test tears it down.
        let inspect_resp = client
            .get(format!("{base2}/containers/{id}"))
            .send()
            .await
            .expect("GET inspect on recovery daemon");
        assert_eq!(
            inspect_resp.status(),
            reqwest::StatusCode::OK,
            "the fresh kestreld instance did not recover the still-running container across restart"
        );

        let stop_resp = client
            .post(format!("{base2}/containers/{id}/stop"))
            .send()
            .await
            .expect("POST stop via recovery daemon");
        assert!(
            stop_resp.status().is_success(),
            "stop via recovery daemon failed: {} {}",
            stop_resp.status(),
            stop_resp.text().await.unwrap_or_default()
        );

        let delete_resp = client
            .delete(format!("{base2}/containers/{id}"))
            .send()
            .await
            .expect("DELETE via recovery daemon");
        assert!(
            delete_resp.status().is_success(),
            "delete via recovery daemon failed: {} {}",
            delete_resp.status(),
            delete_resp.text().await.unwrap_or_default()
        );

        // Shut the cleanup daemon down too, best-effort — not the subject
        // of this test, just good hygiene so it doesn't linger.
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(daemon2_pid), nix::sys::signal::Signal::SIGTERM);
        let _ = tokio::time::timeout(Duration::from_secs(10), daemon2.wait()).await;

        // Final liveness check: the real entrypoint must be gone now that
        // it has gone through a real stop+delete.
        let gone = nix::sys::signal::kill(nix::unistd::Pid::from_raw(entrypoint_pid), None).is_err();
        assert!(
            gone,
            "container entrypoint (pid {entrypoint_pid}) should be gone after a real stop+delete via \
             the recovery daemon"
        );

        // `RealContainerGuard::drop` runs now — a harmless no-op given the
        // successful stop+delete above (including its own belt-and-
        // suspenders shim pkill), and the real safety net if any assertion
        // earlier in this test had panicked instead.
        drop(guard);
    }
}
