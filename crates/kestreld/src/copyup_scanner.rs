// crates/kestreld/src/copyup_scanner.rs
//
//! Phase 9 Task 15: the copy-up scanner — a separate, slower-cadence
//! background poller (its own `config.storage.copyup_scan_interval_s`
//! interval, default 5s — genuinely separate from Task 13's 1Hz metrics
//! sampler, not folded into it) that periodically re-scans every
//! `Running` container's overlay upperdir for copy-ups
//! (`kestrel_rootfs::copyup::scan_copy_ups`, real, from Phase 4) and
//! publishes `Event::CopyUp` (Task 14's real event bus) for genuinely
//! new ones only.
//!
//! ## Resolving `upper_dir`/`lowers` for a running container
//!
//! There is no `layers.json` yet (that's Task 19's job) — the exact
//! information this scanner needs already exists, real and durable,
//! today:
//!   - `upper_dir` is always `<data_dir>/snapshots/<id>/upper`
//!     (`kestrel_rootfs::snapshot::Snapshotter::prepare_snapshot`'s own,
//!     already-real path convention — `kestrel-init`'s `mounts::
//!     stage_rootfs`, Task 5, calls this same function with this same
//!     `container_id` for every container, image-pulled or plain bundle,
//!     so this convention is already load-bearing production behavior,
//!     not something this task invents).
//!   - the lower chain-ids are read straight back off the container's
//!     own `<data_dir>/bundles/<id>/config.json`: an image-pulled
//!     container carries them verbatim in the `kestrel.lowerChainIds`
//!     annotation `kestreld::bundle::materialize_bundle_inner` already
//!     writes; a plain `bundle_rootfs` container has no such annotation,
//!     and `kestrel-runtime create.rs`'s own
//!     `stage_bundle_rootfs_as_synthetic_layer` falls back to a single
//!     deterministic synthetic chain-id, `bundle-<id>` — this module
//!     mirrors that exact fallback (duplicated as a literal, not
//!     imported, since `kestreld` never links `kestrel-runtime` as a
//!     library — see `lib.rs`'s own doc comment; this string,
//!     `LOWER_CHAIN_IDS_ANNOTATION`, and the `bundle-<id>` format are the
//!     real, load-bearing contract already shared verbatim between
//!     `kestreld::bundle` and `kestrel-runtime create.rs`, and this is a
//!     third copy of the same contract, not a new one).
//!   - each chain-id's `diff_dir` is `kestrel_rootfs::snapshot::
//!     LayerStore::new(data_dir).diff_dir(chain_id)` — the exact same
//!     content-addressed layer root every other layer-touching path in
//!     this workspace already reads.
//!
//! Everything here is read fresh off disk every tick — nothing is cached
//! beyond the per-container `HashSet<PathBuf>` of previously-seen
//! copy-up paths this scanner owns for de-duplication (matching
//! `metrics.rs`'s own "nothing durable, a restart just starts over"
//! posture — a missed/re-observed copy-up across a `kestreld` restart is
//! an accepted gap, not a correctness bug).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::state::Status;
use kestrel_rootfs::copyup::{scan_copy_ups, CopyUpEvent, LowerLayer};
use kestrel_rootfs::snapshot::LayerStore;

use crate::events::{self, Event, EventBus};
use crate::registry::{self, Registry};

/// Duplicated, byte-for-byte, from `kestreld::bundle`'s (Task 8) and
/// `kestrel-runtime create.rs`'s (Task 3) own private copies of this same
/// constant — see this module's own top-level doc comment for why a
/// third copy here, rather than an import, is correct: `kestreld` never
/// links `kestrel-runtime` as a library.
const LOWER_CHAIN_IDS_ANNOTATION: &str = "kestrel.lowerChainIds";

/// Spawns the scanner as a detached background task, on its OWN interval
/// — genuinely separate from Task 13's 1Hz metrics sampler (this task's
/// own plan wording), not a second consumer of that tick. Runs forever,
/// same "no cancellation mechanism yet" posture as `metrics::spawn`/
/// `events::spawn_consumer` (a later graceful-shutdown task, Phase 9
/// Task 21, is the natural place to add one for all three).
pub fn spawn(registry: Registry, run_dir: PathBuf, data_dir: PathBuf, interval: Duration, event_bus: EventBus) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Same reasoning as `metrics::spawn`'s own ticker: a slow tick
        // (e.g. many containers, or a slow disk) should never pile up a
        // burst of catch-up ticks against itself.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seen: HashMap<String, HashSet<PathBuf>> = HashMap::new();
        loop {
            ticker.tick().await;
            scan_tick(&registry, &run_dir, &data_dir, &event_bus, &mut seen).await;
        }
    });
}

/// One full tick: for every container currently `Running`, re-scans its
/// upperdir for copy-ups and publishes `Event::CopyUp` for any path not
/// already in that container's own `seen` set.
async fn scan_tick(
    registry: &Registry,
    run_dir: &Path,
    data_dir: &Path,
    event_bus: &EventBus,
    seen: &mut HashMap<String, HashSet<PathBuf>>,
) {
    let ids: Vec<String> = registry.read().await.keys().cloned().collect();
    // Prune bookkeeping for containers no longer in the registry —
    // otherwise this map grows unboundedly over a long-running daemon's
    // lifetime as containers churn (same concern `metrics.rs`'s own
    // `sample_tick` already documents for its own per-container maps).
    seen.retain(|id, _| ids.iter().any(|i| i == id));

    for id in &ids {
        let status = match registry::read_state(run_dir, id).await {
            Ok(s) => s.status,
            // Registry said this id exists, but state.json is currently
            // unreadable (e.g. a delete() raced this exact tick) — skip
            // this container for this tick only, matching metrics.rs's
            // own sample_tick.
            Err(_) => continue,
        };
        if status != Status::Running {
            continue;
        }

        let copy_ups = match scan_container(data_dir, id).await {
            Ok(v) => v,
            Err(e) => {
                // Best-effort: a container whose upperdir/config.json
                // isn't (yet, or anymore) in the expected shape just
                // means nothing to report this tick, not a fatal error
                // for the whole scanner.
                tracing::debug!(id, error = %e, "copyup scanner: scan failed for this tick");
                continue;
            }
        };

        let seen_paths = seen.entry(id.clone()).or_default();
        for cu in copy_ups {
            // `HashSet::insert` returns `true` only the first time a
            // given path is added — the exact dedup-against-previously-
            // seen check this task exists to implement.
            if seen_paths.insert(cu.path.clone()) {
                events::publish(
                    event_bus,
                    Event::CopyUp {
                        id: id.clone(),
                        path: cu.path.display().to_string(),
                        size_bytes: cu.size_bytes,
                    },
                );
            }
        }
    }
}

/// Runs the real, synchronous `scan_copy_ups` (and the `config.json` read
/// it needs first) on the blocking-task pool — same "wrap the blocking
/// fs call" convention `registry::read_state`/`metrics.rs`'s own cgroup
/// reads already establish for this crate's async code.
async fn scan_container(data_dir: &Path, id: &str) -> Result<Vec<CopyUpEvent>> {
    let data_dir = data_dir.to_path_buf();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || scan_container_blocking(&data_dir, &id))
        .await
        .context("copyup scan blocking task panicked")?
}

fn scan_container_blocking(data_dir: &Path, id: &str) -> Result<Vec<CopyUpEvent>> {
    let lower_chain_ids = resolve_lower_chain_ids(data_dir, id)?;
    let layer_store = LayerStore::new(data_dir.to_path_buf());
    let diff_dirs: Vec<PathBuf> = lower_chain_ids.iter().map(|c| layer_store.diff_dir(c)).collect();
    let lowers: Vec<LowerLayer> = lower_chain_ids
        .iter()
        .zip(diff_dirs.iter())
        .map(|(chain_id, diff_dir)| LowerLayer { chain_id: chain_id.as_str(), diff_dir: diff_dir.as_path() })
        .collect();

    let upper_dir = data_dir.join("snapshots").join(id).join("upper");
    scan_copy_ups(&upper_dir, &lowers)
}

/// See this module's own top-level doc comment for the full reasoning —
/// mirrors `kestrel-runtime create.rs`'s own
/// `stage_bundle_rootfs_as_synthetic_layer` fallback exactly.
fn resolve_lower_chain_ids(data_dir: &Path, id: &str) -> Result<Vec<String>> {
    let config_path = data_dir.join("bundles").join(id).join("config.json");
    let bytes =
        std::fs::read(&config_path).with_context(|| format!("reading {}", config_path.display()))?;
    let raw: RawSpec =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", config_path.display()))?;
    if let Some(annotations) = raw.spec.annotations() {
        if let Some(csv) = annotations.get(LOWER_CHAIN_IDS_ANNOTATION) {
            if !csv.trim().is_empty() {
                return Ok(csv.split(',').map(str::to_string).collect());
            }
        }
    }
    Ok(vec![format!("bundle-{id}")])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use crate::registry::Registry;
    use crate::{build_router, events, resolve_sibling_binary, AppState};

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }

    /// Kills (SIGKILL) and reaps a container's real `kestrel-init` pid on
    /// drop — a panic in any assertion must not leak the process.
    struct ProcessGuard(nix::unistd::Pid);
    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.0, None);
        }
    }

    /// Same reasoning as `metrics.rs`'s/`events.rs`'s own `real_data_dir`:
    /// the REAL `kestrel-init` hardcodes `/var/lib/kestrel` as its own
    /// `data_dir`, so the host-side `data_dir` these tests pass to
    /// `kestrel-runtime create` must match byte-for-byte.
    fn real_data_dir() -> PathBuf {
        PathBuf::from("/var/lib/kestrel")
    }

    fn target_debug_dir() -> PathBuf {
        let current_exe = std::env::current_exe().expect("current_exe");
        current_exe
            .parent()
            .expect("current_exe has a parent dir (deps/)")
            .parent()
            .expect("deps/ dir has a parent dir (target/debug/)")
            .to_path_buf()
    }

    fn resolve_test_binary(name: &str) -> PathBuf {
        resolve_sibling_binary(name).unwrap_or_else(|e| {
            panic!(
                "{e}\nRun `cargo build -p kestrel-shim -p kestrel-runtime -p kestrel-init \
                 -p kestrel-net --bins` (or `cargo build --workspace`) first."
            )
        })
    }

    fn install_real_kestrel_init_at_target_debug() {
        let real = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/kestrel-init");
        assert!(
            real.exists(),
            "real statically-linked kestrel-init not found at {} — run `make \
             build-kestrel-init-static` first.",
            real.display()
        );
        let target_debug_dir = target_debug_dir();
        let target = target_debug_dir.join("kestrel-init");
        let tmp = target_debug_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
        std::fs::copy(&real, &tmp).expect("copy real kestrel-init to tmp");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::rename(&tmp, &target).expect("rename tmp into place as target/debug/kestrel-init");
    }

    fn static_lifecycle_fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture")
    }

    /// Real rootfs for this task's own scenario: the real, statically
    /// linked `lifecycle_fixture` binary at `/fixture`, PLUS a
    /// pre-existing `/app.conf` file. `kestrel-runtime create.rs`'s
    /// `stage_bundle_rootfs_as_synthetic_layer` copies this entire
    /// directory into the synthetic layer's diff dir (the container's
    /// LOWER layer) — so `app.conf` genuinely exists below the overlay
    /// before the container ever runs, and the entrypoint's own write to
    /// `/app.conf` triggers a REAL overlayfs copy-up, not a simulated
    /// one.
    fn build_copyup_synthetic_rootfs(dest: &Path) {
        std::fs::create_dir_all(dest).expect("mkdir synthetic rootfs dir");
        let fixture_path = static_lifecycle_fixture_path();
        assert!(
            fixture_path.exists(),
            "static lifecycle_fixture artifact not found at {} — run `make \
             build-lifecycle-fixture-static` first.",
            fixture_path.display()
        );
        std::fs::copy(&fixture_path, dest.join("fixture")).unwrap_or_else(|e| {
            panic!("copy {} to {}: {e}", fixture_path.display(), dest.join("fixture").display())
        });
        std::fs::set_permissions(dest.join("fixture"), std::fs::Permissions::from_mode(0o755))
            .expect("chmod fixture binary");
        std::fs::write(dest.join("app.conf"), b"lower-layer-original-app-conf-content")
            .expect("write lower-layer app.conf");
    }

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

    async fn poll_until<T, F: FnMut() -> Option<T>>(timeout: Duration, mut probe: F) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(v) = probe() {
                return Some(v);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

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

    fn cleanup_real_container_artifacts(id: &str) {
        let data_dir = real_data_dir();
        let layer_store = LayerStore::new(data_dir.clone());
        let _ = std::fs::remove_dir_all(layer_store.layer_dir(&format!("bundle-{id}")));
        let _ = std::fs::remove_dir_all(data_dir.join("bundles").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("snapshots").join(id));
        let _ = std::fs::remove_dir_all(data_dir.join("containers").join(id));
    }

    async fn call_router_json(
        app: axum::Router,
        method: &str,
        uri: String,
        body: serde_json::Value,
    ) -> (StatusCode, Vec<u8>) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect body");
        (status, bytes.to_vec())
    }

    async fn call_router_empty(app: axum::Router, method: &str, uri: String) -> (StatusCode, Vec<u8>) {
        let request = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect body");
        (status, bytes.to_vec())
    }

    /// Real, end-to-end proof of this whole task: a container whose
    /// entrypoint writes to a file that already exists in its (synthetic
    /// bundle-rootfs) lower layer triggers a genuine overlayfs copy-up;
    /// the scanner detects it on its own, independent interval and
    /// publishes exactly one `Event::CopyUp` for that path, with the
    /// real byte count of what was actually written. A SECOND write to
    /// the SAME path — the fixture's own `copyup-write` mode does this
    /// itself, after a delay — must NOT re-fire: the dedup-against-
    /// previously-seen check this task exists to implement.
    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_copyup_scanner_fires_once_and_dedupes_second_write_to_same_path() {
        let shim_path = resolve_test_binary("kestrel-shim");
        let runtime_path = resolve_test_binary("kestrel-runtime");
        install_real_kestrel_init_at_target_debug();

        let data_dir = real_data_dir();
        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let _mount_guard = mount_cgroups(&data_dir);

        let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
        build_copyup_synthetic_rootfs(rootfs_dir.path());

        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let app_state = Arc::new(AppState {
            run_dir: run_dir.path().to_path_buf(),
            data_dir: data_dir.clone(),
            registry: registry.clone(),
            shim_path,
            runtime_path,
            stop_grace_period_s: 10,
            metrics_rx: tokio::sync::Mutex::new(tokio::sync::mpsc::channel(1).1),
            event_bus: events::new_bus(),
            last_status_map: crate::metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: crate::api::introspect::SeccompLog::new(),
        });
        let app = build_router(app_state.clone());

        // Subscribe BEFORE the container exists, so the very first
        // CopyUp event for this (not-yet-created) container is genuinely
        // captured, not raced.
        let mut sub = app_state.event_bus.subscribe();

        // This scanner's own, separate, fast interval — proving its
        // cadence is genuinely independent of Task 13's 1Hz metrics
        // sampler, which isn't even spawned in this test at all.
        spawn(
            registry.clone(),
            run_dir.path().to_path_buf(),
            data_dir.clone(),
            Duration::from_millis(100),
            app_state.event_bus.clone(),
        );

        // ---- create + start: entrypoint writes /app.conf (a real
        // copy-up — it already exists in the synthetic lower layer),
        // waits 1s, then writes the same path again. ----
        let create_body = serde_json::json!({
            "bundle_rootfs": rootfs_dir.path(),
            "tty": false,
            "cmd": ["/fixture", "copyup-write", "/app.conf", "1000"],
        });
        let (create_status, create_resp) =
            call_router_json(app.clone(), "POST", "/containers".to_string(), create_body).await;
        assert_eq!(
            create_status,
            StatusCode::CREATED,
            "create failed: {}",
            String::from_utf8_lossy(&create_resp)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&create_resp).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        let state_path = run_dir.path().join(&id).join("state.json");
        let created = kestrel_oci::state::State::read(&state_path).expect("read state.json after create");
        let init_pid = nix::unistd::Pid::from_raw(created.pid.expect("pid recorded after create"));
        let process_guard = ProcessGuard(init_pid);

        let (start_status, start_resp) =
            call_router_empty(app.clone(), "POST", format!("/containers/{id}/start")).await;
        assert_eq!(start_status, StatusCode::OK, "start failed: {}", String::from_utf8_lossy(&start_resp));

        let running = poll_until(Duration::from_secs(10), || {
            kestrel_oci::state::State::read(&state_path)
                .ok()
                .filter(|s| s.status == kestrel_oci::state::Status::Running)
        })
        .await;
        assert!(running.is_some(), "container never reached Running after start");

        // ---- the first assertion: exactly one CopyUp event for
        // app.conf, with the real size of the FIRST write. ----
        let (first_path, first_size) = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match sub.recv().await.expect("event_bus recv") {
                    events::Event::CopyUp { id: eid, path, size_bytes } if eid == id => {
                        return (path, size_bytes);
                    }
                    _ => continue, // a different, concurrently-run test's own container
                }
            }
        })
        .await
        .expect("no CopyUp event for app.conf arrived within 10s");

        assert_eq!(first_path, "app.conf");
        assert_eq!(
            first_size,
            "first-write-triggers-copy-up".len() as u64,
            "size_bytes should reflect the real bytes written by the entrypoint's first write"
        );

        // ---- the dedup proof: the entrypoint's own second write to the
        // SAME path (already scheduled ~1s after container start) must
        // NOT produce a second CopyUp event across several more scanner
        // ticks. ----
        let second_event = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                match sub.recv().await.expect("event_bus recv") {
                    events::Event::CopyUp { id: eid, path, .. } if eid == id && path == "app.conf" => return,
                    _ => continue,
                }
            }
        })
        .await;
        assert!(
            second_event.is_err(),
            "a second CopyUp event fired for the same already-seen path — dedup is broken"
        );

        // ---- cleanup ----
        drop(process_guard);
        let _ = nix::sys::wait::waitpid(init_pid, None);
        unpin_default_namespaces(run_dir.path(), &id);
        cleanup_real_container_artifacts(&id);
    }
}
