// crates/kestreld/tests/capstone.rs
//
//! Phase 9 Task 22: the capstone integration suite for the whole daemon
//! phase — same role Phase 8's `crates/kestrel-runtime/tests/lifecycle.rs`
//! played for that phase's own capstone. Every one of Tasks 1-21 has its
//! own, narrowly-scoped tests already; this file's whole job is to prove
//! they compose correctly end to end, through the real HTTP API, against a
//! real, separately-spawned `kestreld` OS process — never by calling into
//! `kestrel_runtime`/`kestrel_shim` directly, and never by driving
//! `main.rs`'s own in-process `axum::Router` via `tower::ServiceExt::
//! oneshot` (unlike most of that file's own tests): `kestreld`'s `lib.rs`
//! only exports `config` (confirmed by reading it) — `AppState`/
//! `build_router` are private to the `kestreld` BINARY target, unreachable
//! from a `tests/` integration binary like this one. So every test below
//! follows Task 21's own `test_sigterm_to_kestreld_exits_promptly_and_
//! container_survives` precedent: build the real `kestreld` binary,
//! `spawn_real_kestreld` it, and talk to it purely over real HTTP/WS
//! (`reqwest` + `tokio-tungstenite`), exactly as any real client would.
//!
//! Prerequisites (build once before running):
//! ```text
//! make build-kestrel-init-static build-lifecycle-fixture-static
//! cargo build --workspace
//! ```
//!
//! Run with (root required — real namespaces/cgroups/mounts):
//! ```text
//! sudo -E cargo test -p kestreld --test capstone -- --ignored --test-threads=1
//! ```
//!
//! **Why `data_dir` is the REAL `/var/lib/kestrel`, not a tempdir**: same
//! reason every real-`kestrel-init` root-gated test elsewhere in this
//! workspace gives (`crates/kestreld/src/main.rs`'s own `real_data_dir`,
//! `crates/kestrel-runtime/tests/lifecycle.rs`'s module doc comment) — the
//! real, statically-linked `kestrel-init` hardcodes its own `data_dir` as
//! that literal path, so every `kestreld` instance spawned below that
//! creates a REAL (non-stub) container must be configured with the exact
//! same `data_dir` or the container-side rootfs staging looks in the wrong
//! place and finds nothing.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as WsMessage;

// ===========================================================================
// Binary / fixture resolution — same conventions as
// `crates/kestreld/src/main.rs`'s own root-gated test module, duplicated
// (not imported: that module is private to the `kestreld` binary target,
// unreachable from here).
// ===========================================================================

/// This test BINARY's own `target/debug/` — `current_exe()` for a `tests/`
/// integration binary resolves to `target/debug/deps/capstone-<hash>`, so
/// the grandparent (not the immediate `deps/` parent) is where a plain
/// `[[bin]]` artifact like `kestreld` itself lands.
fn target_debug_dir() -> PathBuf {
    let current_exe = std::env::current_exe().expect("current_exe");
    current_exe
        .parent()
        .expect("current_exe has a parent dir (deps/)")
        .parent()
        .expect("deps/ dir has a parent dir (target/debug/)")
        .to_path_buf()
}

/// Installs the REAL, statically-linked `kestrel-init` as
/// `target/debug/kestrel-init` — the sibling location
/// `kestrel_runtime::create::resolve_kestrel_init_path` resolves relative
/// to the SEPARATELY-SPAWNED `kestrel-runtime` subprocess `kestreld` itself
/// execs (`target/debug/kestrel-runtime`), not relative to this test
/// binary. Every capstone test needs a REAL (non-stub) entrypoint — unlike
/// several of `main.rs`'s own Task 7/8-only tests, there is no stub-init
/// path here: every scenario below genuinely runs an entrypoint to
/// completion or holds it running across real operations.
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

/// Builds a minimal synthetic rootfs DIRECTORY at `dest` containing the
/// real, statically-linked `lifecycle_fixture` binary at `<dest>/fixture`
/// — this crate's own copy of `kestrel-runtime/tests/common/mod.rs::
/// build_synthetic_rootfs` / `main.rs`'s own `build_lifecycle_synthetic_
/// rootfs`, duplicated for the same "not reachable from here" reason.
fn build_lifecycle_synthetic_rootfs(dest: &Path) {
    std::fs::create_dir_all(dest).expect("mkdir synthetic rootfs dir");
    let fixture_path = static_lifecycle_fixture_path();
    assert!(
        fixture_path.exists(),
        "static lifecycle_fixture artifact not found at {} — run `make \
         build-lifecycle-fixture-static` first.",
        fixture_path.display()
    );
    std::fs::copy(&fixture_path, dest.join("fixture"))
        .unwrap_or_else(|e| panic!("copy {} to {}: {e}", fixture_path.display(), dest.join("fixture").display()));
    std::fs::set_permissions(dest.join("fixture"), std::fs::Permissions::from_mode(0o755))
        .expect("chmod fixture binary");
}

/// See this file's own top-level doc comment for why this is NOT a
/// tempdir.
fn real_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/kestrel")
}

// ===========================================================================
// cgroup2 mount + real kestreld subprocess plumbing
// ===========================================================================

struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.0).status();
    }
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

fn find_free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Writes a real `kestreld` config file. `extra_toml` is appended verbatim
/// (e.g. a `[network]` section for Step 5's non-default bridge/subnet) —
/// every other section legitimately falls back to its own documented
/// default (`config.rs`'s `#[serde(default)]` fields).
fn write_daemon_config(
    config_path: &Path,
    socket_path: &Path,
    http_addr: &str,
    run_dir: &Path,
    data_dir: &Path,
    extra_toml: &str,
) {
    let mut toml = format!(
        "[daemon]\n\
         socket = {socket_path:?}\n\
         http_addr = {http_addr:?}\n\
         state_dir = {run_dir_str:?}\n\
         data_dir = {data_dir_str:?}\n\
         metrics_interval_ms = 250\n\
         stop_grace_period_s = 5\n",
        socket_path = socket_path.display().to_string(),
        http_addr = http_addr,
        run_dir_str = run_dir.display().to_string(),
        data_dir_str = data_dir.display().to_string(),
    );
    toml.push_str(extra_toml);
    std::fs::write(config_path, toml).expect("write daemon config.toml");
}

/// Spawns a real `kestreld` subprocess, its own stdout/stderr redirected to
/// real files under `log_dir` — never read directly, just there so a
/// failure's root cause is inspectable after the fact.
fn spawn_real_kestreld(kestreld_bin: &Path, config_path: &Path, log_dir: &Path, log_tag: &str) -> (tokio::process::Child, i32) {
    let stdout_log =
        std::fs::File::create(log_dir.join(format!("{log_tag}.stdout.log"))).expect("create kestreld stdout log");
    let stderr_log =
        std::fs::File::create(log_dir.join(format!("{log_tag}.stderr.log"))).expect("create kestreld stderr log");
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

async fn wait_socket_ready(socket_path: &Path) {
    let ready = poll_until(Duration::from_secs(20), || std::os::unix::net::UnixStream::connect(socket_path).ok()).await;
    assert!(ready.is_some(), "kestreld's unix socket at {} never became connectable", socket_path.display());
}

fn kestreld_bin() -> PathBuf {
    let bin = target_debug_dir().join("kestreld");
    assert!(
        bin.is_file(),
        "kestreld binary not found at {} — run `cargo build -p kestreld` (or `cargo build --workspace`) first",
        bin.display()
    );
    bin
}

async fn shutdown_kestreld(mut child: tokio::process::Child, pid: i32) {
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGTERM);
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
}

/// Best-effort SIGKILL-on-drop safety net for a spawned `kestreld`
/// subprocess. `tokio::process::Child::drop` does NOT kill its child on
/// drop (this is `std::process::Child`'s own well-documented behavior,
/// which `tokio::process::Child` inherits) — without this guard, a
/// panicking assertion anywhere between `spawn_real_kestreld` and this
/// test's own explicit `shutdown_kestreld` call would leak a real,
/// listening `kestreld` daemon for the rest of the VM's uptime (reproduced
/// and confirmed directly while developing this suite: an earlier
/// iteration's assertion failures left multiple orphaned `kestreld`
/// processes behind). Safe/idempotent to signal an already-gracefully-
/// exited pid (a plain `ESRCH`, silently discarded) — this guard runs
/// AFTER any successful, explicit `shutdown_kestreld` call too, as a
/// harmless no-op, matching every other guard in this file's "cheap,
/// best-effort, safe to race against already-clean state" posture.
struct KestreldGuard(i32);
impl Drop for KestreldGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.0), nix::sys::signal::Signal::SIGKILL);
    }
}

// ===========================================================================
// Container cleanup — best-effort, idempotent, safe to race against an
// already-successful stop+delete (matches `main.rs`'s own `RealContainerGuard`
// posture).
// ===========================================================================

struct ContainerCleanup {
    run_dir: PathBuf,
    id: String,
    bridge_mode: bool,
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let state_path = self.run_dir.join(&self.id).join("state.json");
        if let Ok(state) = kestrel_oci::state::State::read(&state_path) {
            if let Some(pid) = state.pid {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
        }
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-f", &format!("kestrel-shim --id {} ", self.id)])
            .status();

        let ns_dir = self.run_dir.join(&self.id).join("ns");
        let mut ns_types = vec![
            kestrel_ns::types::NsType::Pid,
            kestrel_ns::types::NsType::Ipc,
            kestrel_ns::types::NsType::Uts,
            kestrel_ns::types::NsType::Cgroup,
            kestrel_ns::types::NsType::Mount,
        ];
        if !self.bridge_mode {
            // Bridge mode JOINS an externally-created netns (Task 4's
            // mechanism) rather than creating+pinning a fresh one under
            // `ns/net` — see `main.rs`'s own bridge-mode tests for the
            // identical reasoning.
            ns_types.push(kestrel_ns::types::NsType::Net);
        }
        for ns in ns_types {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }
        if self.bridge_mode {
            let _ = kestrel_net::netns::teardown_netns(&self.run_dir, &self.id);
        }

        let data_dir = real_data_dir();
        let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir.clone());
        let _ = std::fs::remove_dir_all(layer_store.layer_dir(&format!("bundle-{}", self.id)));
        let _ = std::fs::remove_dir_all(data_dir.join("bundles").join(&self.id));
        let _ = std::fs::remove_dir_all(data_dir.join("snapshots").join(&self.id));
        let _ = std::fs::remove_dir_all(data_dir.join("containers").join(&self.id));
    }
}

// ===========================================================================
// HTTP/WS helpers
// ===========================================================================

async fn poll_container_status(client: &reqwest::Client, base: &str, id: &str, want: &str, timeout: Duration) -> Value {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(resp) = client.get(format!("{base}/containers/{id}")).send().await {
            if resp.status() == reqwest::StatusCode::OK {
                if let Ok(body) = resp.json::<Value>().await {
                    if body["status"] == want {
                        return body;
                    }
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "container {id} never reached HTTP-reported status {want:?} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reads `data: <json>\n\n`-framed SSE chunks off `resp` until a predicate
/// returns `Some`, or `timeout` elapses. Shared by the pull-progress
/// consumer (Step 4) and the event-bus consumer (Step 3).
async fn collect_sse_until<T>(
    mut resp: reqwest::Response,
    timeout: Duration,
    mut on_event: impl FnMut(Value) -> Option<T>,
) -> T {
    let mut acc = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for the expected SSE event");
        let chunk = tokio::time::timeout(remaining, resp.chunk())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for next SSE chunk"))
            .expect("reading SSE chunk");
        let Some(bytes) = chunk else {
            panic!("SSE stream ended before the expected event arrived");
        };
        acc.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(idx) = acc.find("\n\n") {
            let piece: String = acc.drain(..idx + 2).collect();
            for line in piece.lines() {
                let Some(json_str) = line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) else {
                    continue;
                };
                let Ok(v) = serde_json::from_str::<Value>(json_str.trim()) else { continue };
                if let Some(result) = on_event(v) {
                    return result;
                }
            }
        }
    }
}

/// A long-lived SSE subscriber (`GET /events`): drains chunks into a
/// shared, growing `Vec<Value>` on a background task for the rest of the
/// test's duration.
struct EventCollector {
    events: Arc<tokio::sync::Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

async fn subscribe_events(client: &reqwest::Client, base: &str) -> EventCollector {
    let mut resp = client.get(format!("{base}/events")).send().await.expect("GET /events");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "GET /events must succeed");
    let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let events2 = events.clone();
    let task = tokio::spawn(async move {
        let mut acc = String::new();
        while let Ok(Some(bytes)) = resp.chunk().await {
            acc.push_str(&String::from_utf8_lossy(&bytes));
            while let Some(idx) = acc.find("\n\n") {
                let piece: String = acc.drain(..idx + 2).collect();
                for line in piece.lines() {
                    let Some(json_str) = line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) else {
                        continue;
                    };
                    if let Ok(v) = serde_json::from_str::<Value>(json_str.trim()) {
                        events2.lock().await.push(v);
                    }
                }
            }
        }
    });
    EventCollector { events, task }
}

impl Drop for EventCollector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Sends `payload` over `WS /containers/:id/attach`, collects Binary
/// echoes until at least `payload.len()` bytes have come back (or timeout).
async fn attach_round_trip(addr: &str, id: &str, payload: &[u8]) -> Vec<u8> {
    let url = format!("ws://{addr}/containers/{id}/attach");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.expect("connect attach WS endpoint");
    ws.send(WsMessage::Binary(payload.to_vec().into())).await.expect("send attach payload");

    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while collected.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for attach echo; collected so far: {collected:?}");
        match tokio::time::timeout(remaining, ws.next()).await.expect("attach WS session did not finish in time") {
            Some(Ok(WsMessage::Binary(bytes))) => collected.extend_from_slice(&bytes),
            Some(Ok(WsMessage::Close(_))) | None => break,
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("attach WS session errored: {e}"),
        }
    }
    let _ = ws.close(None).await;
    collected
}

/// Drives one `WS /containers/:id/exec` session to completion: connects,
/// sends the `{"cmd":[...],"tty":false}` init message, collects Binary
/// output, and returns it plus the reported exit code.
async fn exec_over_ws(addr: &str, id: &str, cmd: &[&str]) -> (Vec<u8>, Option<i32>) {
    let url = format!("ws://{addr}/containers/{id}/exec");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.expect("connect exec WS endpoint");
    let init = json!({ "cmd": cmd, "tty": false });
    ws.send(WsMessage::Text(init.to_string().into())).await.expect("send exec init message");

    let mut output = Vec::new();
    let mut exit_code = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, ws.next()).await.expect("exec WS session did not finish in time") {
            Some(Ok(WsMessage::Binary(bytes))) => output.extend_from_slice(&bytes),
            Some(Ok(WsMessage::Text(text))) => {
                let parsed: Value = serde_json::from_str(&text).expect("exec control message is valid JSON");
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

// ===========================================================================
// Step 1: test_full_lifecycle_via_http
// ===========================================================================
//
// create -> start -> poll running -> logs show expected output -> exec a
// command -> stop -> delete, entirely through the real HTTP API.

#[tokio::test]
#[ignore = "requires root"]
async fn test_full_lifecycle_via_http() {
    install_real_kestrel_init_at_target_debug();
    let kestreld_bin = kestreld_bin();

    let data_dir = real_data_dir();
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _mount_guard = mount_cgroups(&data_dir);

    let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
    build_lifecycle_synthetic_rootfs(rootfs_dir.path());

    let scratch_dir = tempfile::tempdir().expect("scratch tempdir");
    let socket_path = run_dir.path().join("kestreld.sock");
    let port = find_free_tcp_port();
    let http_addr = format!("127.0.0.1:{port}");
    let config_path = scratch_dir.path().join("config.toml");
    write_daemon_config(&config_path, &socket_path, &http_addr, run_dir.path(), &data_dir, "");

    let (daemon, daemon_pid) = spawn_real_kestreld(&kestreld_bin, &config_path, scratch_dir.path(), "kestreld");
    let _kestreld_guard = KestreldGuard(daemon_pid);
    wait_socket_ready(&socket_path).await;

    let client = reqwest::Client::new();
    let base = format!("http://{http_addr}");

    // ---- create: a real, tty container (echo-stdin) — kept alive by its
    // own blocking stdin read until this test explicitly stops it ----
    let create_resp = client
        .post(format!("{base}/containers"))
        .json(&json!({
            "bundle_rootfs": rootfs_dir.path(),
            "cmd": ["/fixture", "echo-stdin"],
            "tty": true,
        }))
        .send()
        .await
        .expect("POST /containers");
    assert_eq!(
        create_resp.status(),
        reqwest::StatusCode::CREATED,
        "create failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let created: Value = create_resp.json().await.expect("parse create response JSON");
    let id = created["id"].as_str().expect("response has a real id").to_string();
    assert!(!id.is_empty());
    let _cleanup = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id.clone(), bridge_mode: false };

    // ---- start ----
    let start_resp = client.post(format!("{base}/containers/{id}/start")).send().await.expect("POST start");
    assert_eq!(start_resp.status(), reqwest::StatusCode::OK, "start failed: {}", start_resp.text().await.unwrap_or_default());

    // ---- poll running, purely via the real HTTP API ----
    poll_container_status(&client, &base, &id, "running", Duration::from_secs(10)).await;

    // ---- logs show expected output: round-trip real bytes through the
    // real attach WS -> shim -> PTY -> echo-stdin -> shim's output.jsonl ----
    let addr_str = http_addr.clone();
    let payload = b"capstone-full-lifecycle\n";
    let echoed = attach_round_trip(&addr_str, &id, payload).await;
    assert_eq!(echoed, payload, "attach WS did not echo back the exact bytes sent");

    let logs_resp = client.get(format!("{base}/containers/{id}/logs")).send().await.expect("GET logs");
    assert_eq!(logs_resp.status(), reqwest::StatusCode::OK);
    let logs_body = logs_resp.text().await.expect("logs body text");
    assert!(
        logs_body.contains("capstone-full-lifecycle"),
        "expected the echoed line in output.jsonl, got: {logs_body}"
    );

    // ---- exec a command, over the real WS exec bridge. `kestrel-runtime
    // exec` joins every namespace pin that genuinely EXISTS for this
    // container (`exec_cmd.rs`'s own doc comment) — but `NsType::Mount`
    // pinning is a documented, pre-existing Lima VM limitation
    // (`kestrel-runtime/tests/create_pins_namespaces.rs`'s own module doc
    // comment: this VM cannot bind-mount mount namespaces at all, so
    // `create()` never pins one), so an exec'd process in THIS environment
    // genuinely runs in the HOST's own mount namespace, not the
    // container's pivoted rootfs — exactly why Task 10's own exec tests
    // (`main.rs`) exec `/bin/echo`, a HOST path, rather than `/fixture`
    // (container-rootfs-only). Same precedent followed here. ----
    let (exec_output, exit_code) = exec_over_ws(&addr_str, &id, &["/bin/sh", "-c", "exit 5"]).await;
    assert!(exec_output.is_empty(), "unexpected exec output: {exec_output:?}");
    assert_eq!(exit_code, Some(5), "exec should report the real exit code of /bin/sh -c 'exit 5'");

    // ---- stop ----
    let stop_resp = client.post(format!("{base}/containers/{id}/stop")).send().await.expect("POST stop");
    assert!(stop_resp.status().is_success(), "stop failed: {} {}", stop_resp.status(), stop_resp.text().await.unwrap_or_default());
    let stopped = poll_container_status(&client, &base, &id, "stopped", Duration::from_secs(10)).await;
    assert_eq!(stopped["exit_code"], json!(143), "expected a plain SIGTERM death (exit_code 143), got {stopped}");

    // ---- delete ----
    let delete_resp = client.delete(format!("{base}/containers/{id}")).send().await.expect("DELETE");
    assert!(delete_resp.status().is_success(), "delete failed: {} {}", delete_resp.status(), delete_resp.text().await.unwrap_or_default());

    let not_found = client.get(format!("{base}/containers/{id}")).send().await.expect("GET after delete");
    assert_eq!(not_found.status(), reqwest::StatusCode::NOT_FOUND, "container should be gone after delete");

    shutdown_kestreld(daemon, daemon_pid).await;
}

// ===========================================================================
// Step 2: test_daemon_restart_preserves_running_container_and_live_attach
// ===========================================================================

#[tokio::test]
#[ignore = "requires root"]
async fn test_daemon_restart_preserves_running_container_and_live_attach() {
    install_real_kestrel_init_at_target_debug();
    let kestreld_bin = kestreld_bin();

    let data_dir = real_data_dir();
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _mount_guard = mount_cgroups(&data_dir);

    let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
    build_lifecycle_synthetic_rootfs(rootfs_dir.path());

    let scratch_dir = tempfile::tempdir().expect("scratch tempdir");
    let socket_path1 = run_dir.path().join("kestreld1.sock");
    let port1 = find_free_tcp_port();
    let http_addr1 = format!("127.0.0.1:{port1}");
    let config_path1 = scratch_dir.path().join("config1.toml");
    write_daemon_config(&config_path1, &socket_path1, &http_addr1, run_dir.path(), &data_dir, "");

    let (daemon1, daemon1_pid) = spawn_real_kestreld(&kestreld_bin, &config_path1, scratch_dir.path(), "kestreld1");
    let _kestreld_guard1 = KestreldGuard(daemon1_pid);
    wait_socket_ready(&socket_path1).await;

    let client = reqwest::Client::new();
    let base1 = format!("http://{http_addr1}");

    // ---- create + start a real tty container over kestreld #1 ----
    let create_resp = client
        .post(format!("{base1}/containers"))
        .json(&json!({
            "bundle_rootfs": rootfs_dir.path(),
            "cmd": ["/fixture", "echo-stdin"],
            "tty": true,
        }))
        .send()
        .await
        .expect("POST /containers");
    assert_eq!(create_resp.status(), reqwest::StatusCode::CREATED, "create failed: {}", create_resp.text().await.unwrap_or_default());
    let created: Value = create_resp.json().await.expect("parse create response JSON");
    let id = created["id"].as_str().expect("response has a real id").to_string();
    let _cleanup = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id.clone(), bridge_mode: false };

    let start_resp = client.post(format!("{base1}/containers/{id}/start")).send().await.expect("POST start");
    assert_eq!(start_resp.status(), reqwest::StatusCode::OK);
    poll_container_status(&client, &base1, &id, "running", Duration::from_secs(10)).await;

    // ---- (b) live attach through kestreld #1, BEFORE the restart ----
    let before_payload = b"before-restart\n";
    let echoed_before = attach_round_trip(&http_addr1, &id, before_payload).await;
    assert_eq!(echoed_before, before_payload, "pre-restart attach echo mismatch");

    // ---- kill kestreld #1's OWN process — never the container ----
    let state_path = run_dir.path().join(&id).join("state.json");
    let state_before_kill = kestrel_oci::state::State::read(&state_path).expect("read state.json before killing kestreld #1");
    let entrypoint_pid = state_before_kill.pid.expect("Running state carries a pid");

    let mut daemon1 = daemon1;
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(daemon1_pid), nix::sys::signal::Signal::SIGTERM);
    let wait_result = tokio::time::timeout(Duration::from_secs(10), daemon1.wait()).await;
    assert!(wait_result.is_ok(), "kestreld #1 did not exit within 10s of SIGTERM");

    // The container's real entrypoint must still be alive — nothing about
    // it is a child of kestreld (design doc §10/§2).
    let still_alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(entrypoint_pid), None).is_ok();
    assert!(still_alive, "container entrypoint (pid {entrypoint_pid}) should survive kestreld #1's death");

    // ---- spin up kestreld #2, pointed at the SAME run_dir/data_dir ----
    let socket_path2 = run_dir.path().join("kestreld2.sock");
    let port2 = find_free_tcp_port();
    let http_addr2 = format!("127.0.0.1:{port2}");
    let config_path2 = scratch_dir.path().join("config2.toml");
    write_daemon_config(&config_path2, &socket_path2, &http_addr2, run_dir.path(), &data_dir, "");
    let (daemon2, daemon2_pid) = spawn_real_kestreld(&kestreld_bin, &config_path2, scratch_dir.path(), "kestreld2");
    let _kestreld_guard2 = KestreldGuard(daemon2_pid);
    wait_socket_ready(&socket_path2).await;
    let base2 = format!("http://{http_addr2}");

    // ---- (a) GET /containers/:id shows it still running, via the fresh
    // daemon's own startup recovery ----
    let recovered = poll_container_status(&client, &base2, &id, "running", Duration::from_secs(10)).await;
    assert_eq!(recovered["id"], id);

    // ---- (b) WS attach to it still works — bytes round-trip through the
    // SURVIVING shim, now bridged by kestreld #2. This exercises the
    // meta.json-based tty recovery: attach_container reads `handle.meta.tty`
    // straight from `recover_registry`'s real meta.json read, not a
    // default — a regression there would either 404/refuse the upgrade or
    // silently treat this as a non-tty (write-rejected) session instead of
    // genuinely echoing these bytes back. ----
    let after_payload = b"after-restart\n";
    let echoed_after = attach_round_trip(&http_addr2, &id, after_payload).await;
    assert_eq!(echoed_after, after_payload, "post-restart attach echo mismatch through the surviving shim");

    // ---- (c) logs show continuous output spanning the restart, no gap ----
    let logs_resp = client.get(format!("{base2}/containers/{id}/logs")).send().await.expect("GET logs via kestreld #2");
    assert_eq!(logs_resp.status(), reqwest::StatusCode::OK);
    let logs_body = logs_resp.text().await.expect("logs body text");
    let before_idx = logs_body.find("before-restart").unwrap_or_else(|| panic!("missing pre-restart log line in: {logs_body}"));
    let after_idx = logs_body.find("after-restart").unwrap_or_else(|| panic!("missing post-restart log line in: {logs_body}"));
    assert!(
        before_idx < after_idx,
        "expected before-restart to precede after-restart in the continuous log stream, got: {logs_body}"
    );

    // ---- cleanup, via kestreld #2 ----
    let stop_resp = client.post(format!("{base2}/containers/{id}/stop")).send().await.expect("POST stop via kestreld #2");
    assert!(stop_resp.status().is_success(), "stop via recovery daemon failed: {}", stop_resp.status());
    let delete_resp = client.delete(format!("{base2}/containers/{id}")).send().await.expect("DELETE via kestreld #2");
    assert!(delete_resp.status().is_success(), "delete via recovery daemon failed: {}", delete_resp.status());

    let gone = nix::sys::signal::kill(nix::unistd::Pid::from_raw(entrypoint_pid), None).is_err();
    assert!(gone, "container entrypoint should be gone after a real stop+delete via the recovery daemon");

    shutdown_kestreld(daemon2, daemon2_pid).await;
}

// ===========================================================================
// Step 3: test_events_and_metrics_flow_end_to_end
// ===========================================================================

#[tokio::test]
#[ignore = "requires root"]
async fn test_events_and_metrics_flow_end_to_end() {
    install_real_kestrel_init_at_target_debug();
    let kestreld_bin = kestreld_bin();

    let data_dir = real_data_dir();
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _mount_guard = mount_cgroups(&data_dir);

    let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
    build_lifecycle_synthetic_rootfs(rootfs_dir.path());

    let scratch_dir = tempfile::tempdir().expect("scratch tempdir");
    let socket_path = run_dir.path().join("kestreld.sock");
    let port = find_free_tcp_port();
    let http_addr = format!("127.0.0.1:{port}");
    let config_path = scratch_dir.path().join("config.toml");
    write_daemon_config(&config_path, &socket_path, &http_addr, run_dir.path(), &data_dir, "");

    let (daemon, daemon_pid) = spawn_real_kestreld(&kestreld_bin, &config_path, scratch_dir.path(), "kestreld");
    let _kestreld_guard = KestreldGuard(daemon_pid);
    wait_socket_ready(&socket_path).await;

    let client = reqwest::Client::new();
    let base = format!("http://{http_addr}");

    // Subscribe BEFORE creating the container — a `broadcast` channel only
    // delivers to receivers that already exist at publish time.
    let collector = subscribe_events(&client, &base).await;
    // Give the SSE background task a moment to actually be pumping —
    // best-effort, not load-bearing: even if `container.create` races this
    // and is momentarily missed by a slow subscribe, later events would
    // still land and the sequence assertion below would legitimately fail,
    // which is exactly the right outcome for either cause.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let create_resp = client
        .post(format!("{base}/containers"))
        .json(&json!({
            "bundle_rootfs": rootfs_dir.path(),
            "cmd": ["/fixture", "sleep", "8"],
            "tty": false,
        }))
        .send()
        .await
        .expect("POST /containers");
    assert_eq!(create_resp.status(), reqwest::StatusCode::CREATED);
    let created: Value = create_resp.json().await.expect("parse create response JSON");
    let id = created["id"].as_str().expect("response has a real id").to_string();
    let _cleanup = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id.clone(), bridge_mode: false };

    let start_resp = client.post(format!("{base}/containers/{id}/start")).send().await.expect("POST start");
    assert_eq!(start_resp.status(), reqwest::StatusCode::OK);
    poll_container_status(&client, &base, &id, "running", Duration::from_secs(10)).await;

    // ---- /pressure returns real, structurally valid PSI numbers while
    // genuinely Running ----
    let pressure_resp = client.get(format!("{base}/containers/{id}/pressure")).send().await.expect("GET pressure");
    assert_eq!(pressure_resp.status(), reqwest::StatusCode::OK, "pressure endpoint must succeed for a Running container");
    let pressure: Value = pressure_resp.json().await.expect("parse pressure JSON");
    for resource in ["cpu", "memory", "io"] {
        let avg10 = pressure[resource]["some"]["avg10"]
            .as_f64()
            .unwrap_or_else(|| panic!("{resource}.some.avg10 missing/non-numeric in {pressure}"));
        assert!((0.0..=100.0).contains(&avg10), "{resource}.some.avg10 out of a plausible PSI range: {avg10}");
        assert!(
            pressure[resource]["some"]["total_us"].is_u64(),
            "{resource}.some.total_us must be a real integer counter in {pressure}"
        );
    }

    // ---- stop -> die (via the metrics sampler) -> delete -> destroy ----
    let stop_resp = client.post(format!("{base}/containers/{id}/stop")).send().await.expect("POST stop");
    assert!(stop_resp.status().is_success());
    poll_container_status(&client, &base, &id, "stopped", Duration::from_secs(10)).await;

    let delete_resp = client.delete(format!("{base}/containers/{id}")).send().await.expect("DELETE");
    assert!(delete_resp.status().is_success());

    // ---- assert the full expected sequence, with NO duplicates
    // (Task 13/14's fix: ContainerDie must come ONLY from the sampler's
    // StatusTransition->Stopped translation, never double-published by
    // `stop`'s own handler too) ----
    let this_container_events = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let filtered: Vec<Value> = {
                let events = collector.events.lock().await;
                events.iter().filter(|e| e["id"] == id).cloned().collect()
            };
            if filtered.iter().any(|e| e["type"] == "container.destroy") {
                break filtered;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "container.destroy never observed on the event bus for {id}; seen so far: {filtered:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    let types: Vec<&str> = this_container_events.iter().map(|e| e["type"].as_str().unwrap_or("<non-string>")).collect();
    assert_eq!(
        types,
        vec!["container.create", "container.start", "container.die", "container.destroy"],
        "unexpected/duplicated event sequence for {id}: {types:?} (full events: {this_container_events:?})"
    );
    let die_event = this_container_events.iter().find(|e| e["type"] == "container.die").unwrap();
    assert_eq!(die_event["exit_code"], json!(143), "expected the real SIGTERM exit_code on container.die: {die_event}");

    drop(collector);
    shutdown_kestreld(daemon, daemon_pid).await;
}

// ===========================================================================
// Step 4: test_image_pull_and_container_from_image (network-gated)
// ===========================================================================

#[tokio::test]
#[ignore = "requires root and real network access to Docker Hub — set KESTREL_TEST_NETWORK=1 to run"]
async fn test_image_pull_and_container_from_image() {
    if std::env::var_os("KESTREL_TEST_NETWORK").is_none() {
        eprintln!(
            "skipping test_image_pull_and_container_from_image: set KESTREL_TEST_NETWORK=1 to \
             actually run it (this test makes real HTTPS calls to Docker Hub)"
        );
        return;
    }

    install_real_kestrel_init_at_target_debug();
    let kestreld_bin = kestreld_bin();

    let data_dir = real_data_dir();
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _mount_guard = mount_cgroups(&data_dir);

    let scratch_dir = tempfile::tempdir().expect("scratch tempdir");
    let socket_path = run_dir.path().join("kestreld.sock");
    let port = find_free_tcp_port();
    let http_addr = format!("127.0.0.1:{port}");
    let config_path = scratch_dir.path().join("config.toml");
    write_daemon_config(&config_path, &socket_path, &http_addr, run_dir.path(), &data_dir, "");

    let (daemon, daemon_pid) = spawn_real_kestreld(&kestreld_bin, &config_path, scratch_dir.path(), "kestreld");
    let _kestreld_guard = KestreldGuard(daemon_pid);
    wait_socket_ready(&socket_path).await;

    let client = reqwest::Client::new();
    let base = format!("http://{http_addr}");

    // ---- real pull ----
    let pull_resp = client
        .post(format!("{base}/images/pull"))
        .json(&json!({ "reference": "alpine:latest" }))
        .send()
        .await
        .expect("POST /images/pull");
    assert_eq!(pull_resp.status(), reqwest::StatusCode::OK, "POST /images/pull must return 200 (an SSE stream)");

    let pull_chain_ids = collect_sse_until(pull_resp, Duration::from_secs(180), |v| {
        if v["type"] == "Complete" {
            Some(v["chain_ids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect::<Vec<_>>())
        } else if v["type"] == "Error" {
            panic!("pull failed: {v}");
        } else {
            None
        }
    })
    .await;
    assert!(!pull_chain_ids.is_empty(), "pull must produce at least one real chain-id");

    // ---- create a container FROM that pulled image — exercising Task 3's
    // annotation fast path for real, end to end (kestreld writes
    // kestrel.lowerChainIds into config.json; kestrel-runtime's create.rs
    // reads it and mounts those exact chain-ids directly, no rootfs copy) ----
    let create_resp = client
        .post(format!("{base}/containers"))
        .json(&json!({
            "image": "alpine:latest",
            "cmd": ["/bin/echo", "hello-from-alpine-capstone"],
            "tty": false,
        }))
        .send()
        .await
        .expect("POST /containers with image");
    assert_eq!(create_resp.status(), reqwest::StatusCode::CREATED, "create-from-image failed: {}", create_resp.text().await.unwrap_or_default());
    let created: Value = create_resp.json().await.expect("parse create response JSON");
    let id = created["id"].as_str().expect("response has a real id").to_string();
    let _cleanup = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id.clone(), bridge_mode: false };

    let start_resp = client.post(format!("{base}/containers/{id}/start")).send().await.expect("POST start");
    assert_eq!(start_resp.status(), reqwest::StatusCode::OK, "start failed: {}", start_resp.text().await.unwrap_or_default());

    // ---- confirm it runs correctly: real exit_code 0, real stdout ----
    let stopped = poll_container_status(&client, &base, &id, "stopped", Duration::from_secs(15)).await;
    assert_eq!(stopped["exit_code"], json!(0), "expected /bin/echo to exit 0: {stopped}");

    let logs_resp = client.get(format!("{base}/containers/{id}/logs")).send().await.expect("GET logs");
    assert_eq!(logs_resp.status(), reqwest::StatusCode::OK);
    let logs_body = logs_resp.text().await.expect("logs body text");
    assert!(logs_body.contains("hello-from-alpine-capstone"), "expected real alpine /bin/echo output in logs, got: {logs_body}");

    // ---- confirm /containers/:id/layers reports the real chain-ids used ----
    let layers_resp = client.get(format!("{base}/containers/{id}/layers")).send().await.expect("GET layers");
    assert_eq!(layers_resp.status(), reqwest::StatusCode::OK);
    let layers: Value = layers_resp.json().await.expect("parse layers JSON");
    let reported_chain_ids: Vec<String> = layers["layers"]
        .as_array()
        .expect("layers array")
        .iter()
        .map(|l| l["chain_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        reported_chain_ids, pull_chain_ids,
        "the container's real, persisted layers.json chain-ids must match exactly what the pull \
         produced — proving the annotation fast path used the already-pulled layers directly, not \
         a fresh synthetic copy"
    );
    for layer in layers["layers"].as_array().unwrap() {
        assert!(
            layer["size_bytes"].as_u64().unwrap_or(0) > 0,
            "expected a real, non-zero extracted layer size for {layer}"
        );
    }

    let delete_resp = client.delete(format!("{base}/containers/{id}")).send().await.expect("DELETE");
    assert!(delete_resp.status().is_success());

    // Hygiene: release the pulled image too.
    let _ = client.delete(format!("{base}/images/alpine:latest")).send().await;

    shutdown_kestreld(daemon, daemon_pid).await;
}

// ===========================================================================
// Step 5: test_bridge_network_container_to_container
// ===========================================================================

const T5_PING: &[u8; 4] = b"PING";
const T5_PONG: &[u8; 4] = b"PONG";

fn t5_accept_with_timeout(listener: &std::net::TcpListener, timeout: Duration) -> anyhow::Result<(std::net::TcpStream, std::net::SocketAddr)> {
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

/// A plain OS thread `nsenter`s into `pin`, binds a TCP listener, signals
/// readiness, accepts one connection, expects `PING`, replies `PONG` —
/// same technique as `kestrel-net/tests/lifecycle.rs::
/// spawn_ping_pong_listener` and `main.rs`'s own Task 17 test.
fn t5_spawn_listener(
    pin: PathBuf,
    bind_addr: std::net::SocketAddr,
    ready_tx: std::sync::mpsc::Sender<()>,
) -> std::thread::JoinHandle<anyhow::Result<std::net::SocketAddr>> {
    std::thread::spawn(move || {
        kestrel_net::netns::nsenter(&pin, move || {
            let listener = std::net::TcpListener::bind(bind_addr)?;
            let _ = ready_tx.send(());
            let (mut stream, peer) = t5_accept_with_timeout(&listener, Duration::from_secs(10))?;
            let mut buf = [0u8; 4];
            std::io::Read::read_exact(&mut stream, &mut buf)?;
            anyhow::ensure!(&buf == T5_PING, "expected PING, got {buf:?}");
            std::io::Write::write_all(&mut stream, T5_PONG)?;
            Ok(peer)
        })
    })
}

fn t5_connect_and_ping(target: std::net::SocketAddr) -> anyhow::Result<()> {
    let mut stream = std::net::TcpStream::connect(target)?;
    std::io::Write::write_all(&mut stream, T5_PING)?;
    let mut buf = [0u8; 4];
    std::io::Read::read_exact(&mut stream, &mut buf)?;
    anyhow::ensure!(&buf == T5_PONG, "expected PONG, got {buf:?}");
    Ok(())
}

/// `veth::veth_names` is `pub(crate)` to `kestrel-net`, not reachable from
/// here — reproduces its exact naming formula purely for this test's own
/// end-of-test host-side veth cleanup, same as `main.rs`'s own copy.
fn veth_names_for_test(id: &str) -> String {
    format!("veth{}", &id[..id.len().min(8)])
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_bridge_network_container_to_container() {
    install_real_kestrel_init_at_target_debug();
    let kestreld_bin = kestreld_bin();

    let data_dir = real_data_dir();
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _mount_guard = mount_cgroups(&data_dir);

    let rootfs_dir = tempfile::tempdir().expect("rootfs tempdir");
    build_lifecycle_synthetic_rootfs(rootfs_dir.path());

    let scratch_dir = tempfile::tempdir().expect("scratch tempdir");
    let socket_path = run_dir.path().join("kestreld.sock");
    let port = find_free_tcp_port();
    let http_addr = format!("127.0.0.1:{port}");
    let config_path = scratch_dir.path().join("config.toml");
    // Own, dedicated bridge/subnet (not the default `kestrel0`) and
    // `iptables = false` — matches Task 17's own test config: pure L2
    // switching is enough to prove real connectivity without also
    // mutating global iptables/sysctl state this test would then have to
    // fully undo.
    let network_toml = "\n[network]\n\
                         bridge = \"kbr-capstone\"\n\
                         subnet = \"172.72.0.0/24\"\n\
                         gateway = \"172.72.0.1\"\n\
                         mtu = 1500\n\
                         iptables = false\n\
                         rootless_backend = \"pasta\"\n";
    write_daemon_config(&config_path, &socket_path, &http_addr, run_dir.path(), &data_dir, network_toml);

    let (daemon, daemon_pid) = spawn_real_kestreld(&kestreld_bin, &config_path, scratch_dir.path(), "kestreld");
    let _kestreld_guard = KestreldGuard(daemon_pid);
    wait_socket_ready(&socket_path).await;

    let client = reqwest::Client::new();
    let base = format!("http://{http_addr}");

    async fn create_bridge_container(client: &reqwest::Client, base: &str, rootfs: &Path) -> String {
        let resp = client
            .post(format!("{base}/containers"))
            .json(&json!({
                "bundle_rootfs": rootfs,
                "cmd": ["/fixture", "sleep", "30"],
                "tty": false,
                "network_mode": "bridge",
            }))
            .send()
            .await
            .expect("POST /containers (bridge)");
        assert_eq!(resp.status(), reqwest::StatusCode::CREATED, "bridge-mode create failed: {}", resp.text().await.unwrap_or_default());
        let created: Value = resp.json().await.expect("parse create response JSON");
        created["id"].as_str().expect("response has a real id").to_string()
    }

    let id_a = create_bridge_container(&client, &base, rootfs_dir.path()).await;
    let id_b = create_bridge_container(&client, &base, rootfs_dir.path()).await;
    assert_ne!(id_a, id_b);
    let _cleanup_a = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id_a.clone(), bridge_mode: true };
    let _cleanup_b = ContainerCleanup { run_dir: run_dir.path().to_path_buf(), id: id_b.clone(), bridge_mode: true };

    for id in [&id_a, &id_b] {
        let resp = client.post(format!("{base}/containers/{id}/start")).send().await.expect("POST start");
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "start failed for {id}: {}", resp.text().await.unwrap_or_default());
    }
    for id in [&id_a, &id_b] {
        poll_container_status(&client, &base, id, "running", Duration::from_secs(10)).await;
    }

    // ---- GET /containers/:id/network reports real, distinct IPs ----
    async fn get_network(client: &reqwest::Client, base: &str, id: &str) -> Value {
        let resp = client.get(format!("{base}/containers/{id}/network")).send().await.expect("GET network");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        resp.json().await.expect("parse network JSON")
    }
    let network_a = get_network(&client, &base, &id_a).await;
    let network_b = get_network(&client, &base, &id_b).await;
    for network in [&network_a, &network_b] {
        assert_eq!(network["mode"], "bridge");
        assert_eq!(network["bridge_name"], "kbr-capstone");
    }
    let ip_a: std::net::Ipv4Addr = network_a["ip"].as_str().expect("container A has a real ip").parse().expect("valid ipv4");
    let ip_b: std::net::Ipv4Addr = network_b["ip"].as_str().expect("container B has a real ip").parse().expect("valid ipv4");
    assert_ne!(ip_a, ip_b, "the two containers must get distinct IPs");

    // ---- GET /system/topology lists both under the same bridge ----
    let topology_resp = client.get(format!("{base}/system/topology")).send().await.expect("GET topology");
    assert_eq!(topology_resp.status(), reqwest::StatusCode::OK);
    let topology: Value = topology_resp.json().await.expect("parse topology JSON");
    let bridge_entry = topology["bridges"]
        .as_array()
        .expect("bridges array")
        .iter()
        .find(|b| b["name"] == "kbr-capstone")
        .unwrap_or_else(|| panic!("expected a kbr-capstone bridge entry in topology, got {topology}"));
    let containers = bridge_entry["containers"].as_array().expect("containers array");
    for (id, ip) in [(&id_a, ip_a), (&id_b, ip_b)] {
        assert!(
            containers.iter().any(|c| c["id"] == id.as_str() && c["ip"] == ip.to_string()),
            "expected container {id} (ip {ip}) in topology's bridge entry, got {containers:?}"
        );
    }

    // ---- real connectivity: container A reaches container B directly
    // over the bridge (exercises Task 4's namespace-join gap-fill + Task
    // 17's veth/bridge attachment sequence together, end to end) ----
    let pin_a = run_dir.path().join("netns").join(&id_a);
    let pin_b = run_dir.path().join("netns").join(&id_b);
    let listen_addr = std::net::SocketAddr::new(ip_b.into(), 9400);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let server = t5_spawn_listener(pin_b.clone(), listen_addr, ready_tx);
    ready_rx.recv_timeout(Duration::from_secs(5)).expect("listener in container B must become ready");
    let pin_a_for_client = pin_a.clone();
    tokio::task::spawn_blocking(move || kestrel_net::netns::nsenter(&pin_a_for_client, move || t5_connect_and_ping(listen_addr)))
        .await
        .expect("client task panicked")
        .expect("container A must be able to connect directly to container B's bridge-assigned IP");
    let observed_peer = server.join().expect("server thread panicked").expect("server-side exchange must succeed");
    assert_eq!(
        observed_peer.ip(),
        std::net::IpAddr::V4(ip_a),
        "container B must observe container A's real bridge-assigned IP"
    );

    // ---- cleanup: delete both containers (still genuinely running their
    // `sleep 30` entrypoint — `?force=true`, matching Task 17's own test's
    // identical need, since a plain DELETE requires an already-Stopped
    // container), then the bridge/veth state ----
    for id in [&id_a, &id_b] {
        let resp = client.delete(format!("{base}/containers/{id}?force=true")).send().await.expect("DELETE");
        assert!(resp.status().is_success(), "delete failed for {id}: {}", resp.status());
    }

    let (connection, handle, _) = rtnetlink::new_connection().expect("rtnetlink connection");
    tokio::spawn(connection);
    for id in [&id_a, &id_b] {
        let host_if = veth_names_for_test(id);
        if let Ok(Some(idx)) = kestrel_net::bridge::find_link_index(&handle, &host_if).await {
            let _ = handle.link().del(idx).execute().await;
        }
    }
    let _ = kestrel_net::bridge::delete_bridge(&handle, "kbr-capstone").await;

    shutdown_kestreld(daemon, daemon_pid).await;
}
