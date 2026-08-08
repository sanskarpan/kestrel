// crates/kestrel-runtime/tests/lifecycle.rs
//
//! Task 16's capstone: the 5 required end-to-end integration tests that
//! exercise the REAL `kestrel-init` (not a stub) across the full
//! `create()` → `start()` → `kill()`/natural-exit → `delete()` lifecycle,
//! including a genuine `pivot_root`, real OCI hooks, the FIFO-blocked
//! exec handshake, and `kestrel-init`'s own SIGCHLD reaper.
//!
//! ## Prerequisites — READ BEFORE RUNNING
//!
//! This file needs TWO statically-linked artifacts to already be built,
//! neither of which `cargo test` builds for you:
//!
//! 1. `make build-kestrel-init-static` — produces the real
//!    `target/aarch64-unknown-linux-gnu/debug/kestrel-init`. This test
//!    file installs that exact binary as a sibling of the test binary
//!    (see `install_real_kestrel_init` below), matching `create.rs`'s
//!    `resolve_kestrel_init_path` sibling-binary convention. A missing or
//!    dynamically-linked binary at that path fails loudly with an
//!    actionable panic message rather than silently falling back to
//!    anything else.
//! 2. `make build-lifecycle-fixture-static` — produces the real
//!    `target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture`, needed
//!    by `tests/common/mod.rs::build_synthetic_rootfs` (see that module's
//!    own doc comment for why the plain `cargo test`-built dynamic
//!    default cannot serve as this rootfs's entrypoint).
//!
//! Run as root inside the Lima VM:
//! ```text
//! sudo -E $(which cargo) test -p kestrel-runtime --test lifecycle -- --ignored --nocapture --test-threads=1
//! ```
//!
//! ## Why `data_dir` is the REAL `/var/lib/kestrel`, not a tempdir
//!
//! Every other root-gated test file in this crate (`delete_teardown.rs`,
//! `create_pins_namespaces.rs`, `create_hook_failure_no_hang.rs`) passes
//! a fresh `tempfile::tempdir()` as `data_dir` to `create()`. That works
//! for them ONLY because they install a STUB `kestrel-init`
//! (`fixture-stub-init`) that never actually calls
//! `kestrel_init::mounts::stage_rootfs` at all — so it never notices (or
//! cares) what `data_dir` the host-side `create()` call used.
//!
//! This file uses the REAL `kestrel-init`, whose `main.rs` hardcodes its
//! own `data_dir` as the literal `/var/lib/kestrel` (see that file's
//! `stage_rootfs(Path::new("/var/lib/kestrel"), ...)` call — `Bootstrap`
//! carries no `data_dir` field at all, by design, matching the CLI's own
//! `--data-dir` default in `cli.rs`). If this test passed a tempdir as
//! `data_dir` to `create()`, the host side would stage the bundle's
//! synthetic rootfs layer under `<tempdir>/layers/bundle-<id>/diff`, but
//! the real `kestrel-init` would go looking for that exact layer under
//! `/var/lib/kestrel/layers/bundle-<id>/diff` — finding nothing, and
//! mounting an empty (or nonexistent) lower layer. This is exactly the
//! kind of mismatch a real, running `kestrel-init` — as opposed to a
//! stub — surfaces: `data_dir` must be `/var/lib/kestrel` here, matching
//! the CLI's own real default, for the two sides of the `create()`/
//! `kestrel-init` split to agree on where the layer store lives.
//!
//! `run_dir` and each test's `bundle_dir` remain plain tempdirs — nothing
//! in `kestrel-init` hardcodes those; only the layer-store `data_dir` is
//! special.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use kestrel_oci::default_spec::default_namespaces;
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    HookBuilder, HooksBuilder, LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace,
    LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder, RootBuilder, SpecBuilder,
};
use kestrel_oci::state::{State, Status};
use kestrel_runtime::bundle::Bundle;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

/// The one, real `data_dir` this whole file uses — see this file's own
/// doc comment ("Why `data_dir` is the REAL `/var/lib/kestrel`").
fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/kestrel")
}

// ---------------------------------------------------------------------
// Guards — every test below must leave zero residue (no stray
// kestrel-init/fixture process, no leftover cgroup2 mount, no leftover
// namespace pins) even if an assertion panics partway through.
// ---------------------------------------------------------------------

/// Best-effort `umount` on drop — the secondary cgroup2 view this file
/// mounts at `data_dir()/cgroups`, same technique every other root-gated
/// test file in this crate already uses.
struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// Kills (SIGKILL) and reaps the container's `kestrel-init` process on
/// drop, best-effort. Unlike `delete_teardown.rs`'s/`create_pins_namespaces.rs`'s
/// own `ProcessGuard` (guarding a STUB init that blocks forever), the
/// REAL `kestrel-init` here is expected to exit on its own once the
/// entrypoint dies and gets reaped — but `kestrel_ns::test_util::run_isolated`
/// makes THIS test process a `PR_SET_CHILD_SUBREAPER` (see
/// `create_hook_failure_no_hang.rs`'s own doc comment for the mechanism),
/// so nothing else in this process tree reaps it automatically. Every
/// test explicitly `waitpid`s the real exit path before this guard's
/// `Drop` runs; this is purely the safety net for a panic that happens
/// before that explicit reap.
struct ProcessGuard(Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

// ---------------------------------------------------------------------
// Shared setup helpers
// ---------------------------------------------------------------------

/// Installs the REAL, statically-linked `kestrel-init` (built via `make
/// build-kestrel-init-static`) as a sibling of THIS test binary, named
/// literally `kestrel-init` — matching `create.rs`'s
/// `resolve_kestrel_init_path`'s sibling-binary convention
/// (`current_exe().parent().join("kestrel-init")`). Unlike
/// `create_pins_namespaces.rs`'s/`delete_teardown.rs`'s own
/// `install_stub_kestrel_init`, this does NOT use `env!("CARGO_BIN_EXE_...")`
/// — `kestrel-init` is a separate crate, built via a distinct
/// `--target aarch64-unknown-linux-gnu` invocation (the Makefile's
/// `build-kestrel-init-static` target), not a `[[bin]]` of THIS crate, so
/// no `CARGO_BIN_EXE_kestrel-init` env var exists for it. Same
/// copy-to-tmp-then-rename race-safety technique as the stub-installers.
///
/// Panics loudly (not a silent fallback) if the artifact is missing or
/// doesn't look statically linked — same defensive posture as
/// `tests/common/mod.rs::build_synthetic_rootfs`.
fn install_real_kestrel_init() -> PathBuf {
    let real = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/aarch64-unknown-linux-gnu/debug/kestrel-init");
    if !real.exists() {
        panic!(
            "real statically-linked kestrel-init not found at {}\n\
             Run `make build-kestrel-init-static` first.",
            real.display()
        );
    }
    let file_output = Command::new("file")
        .arg(&real)
        .output()
        .unwrap_or_else(|e| panic!("run `file {}`: {e}", real.display()));
    let file_stdout = String::from_utf8_lossy(&file_output.stdout);
    if !file_output.status.success() || file_stdout.contains("dynamically linked") {
        panic!(
            "kestrel-init at {} does not look statically linked (`file` reported: {:?}).\n\
             Rebuild it with `make build-kestrel-init-static`.",
            real.display(),
            file_stdout.trim()
        );
    }

    let current_exe = std::env::current_exe().expect("current_exe");
    let sibling_dir = current_exe
        .parent()
        .expect("current_exe has a parent directory")
        .to_path_buf();
    let target = sibling_dir.join("kestrel-init");
    let tmp = sibling_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
    std::fs::copy(&real, &tmp).expect("copy real kestrel-init to tmp");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::rename(&tmp, &target).expect("rename tmp into place as sibling kestrel-init");
    target
}

/// `default_namespaces()` (Pid, Network, Ipc, Uts, Mount, Cgroup) plus a
/// User namespace — `create_pins_namespaces.rs`'s own precedent
/// (`default_namespaces_plus_user`) for routing around the
/// `stage0_inner`/`plan.has_user_ns()` mismatch documented in
/// `create_hook_failure_no_hang.rs`. UNLIKE every prior test file in this
/// crate, `NsType::Mount` is deliberately KEPT here (not filtered out):
/// this file's whole point is exercising a genuine `pivot_root`, which
/// requires a real Mount namespace. `create.rs`'s `pin_namespaces` now
/// tolerates the Mount-pin EINVAL failure this Lima VM has (see that
/// function's own doc comment and `create_pins_namespaces.rs`'s
/// `test_create_tolerates_unpinnable_mount_namespace_and_pins_the_rest`)
/// — namespace CREATION (this list) is unaffected by that; only the
/// later, separate pinning step is.
fn namespaces_for_lifecycle() -> Vec<LinuxNamespace> {
    let mut namespaces = default_namespaces();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()
            .expect("build user namespace"),
    );
    namespaces
}

/// Builds a real `Spec` with `process.args` set to `args`, the standard
/// lifecycle namespace set (including Mount/User), an identity uid/gid
/// map (container uid/gid 0 -> this process's real host uid/gid — root,
/// since every test here is root-gated), and `hooks` if provided.
fn build_spec(args: Vec<String>, hooks: Option<kestrel_oci::runtime::Hooks>) -> kestrel_oci::runtime::Spec {
    let uid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0u32)
        .host_id(nix::unistd::getuid().as_raw())
        .size(1u32)
        .build()
        .expect("build uid mapping");
    let gid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0u32)
        .host_id(nix::unistd::getgid().as_raw())
        .size(1u32)
        .build()
        .expect("build gid mapping");
    let linux = LinuxBuilder::default()
        .namespaces(namespaces_for_lifecycle())
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .build()
        .expect("build linux section");

    let mut builder = SpecBuilder::default()
        .version("1.0.2")
        .root(RootBuilder::default().path("rootfs").build().expect("build root"))
        .process(
            ProcessBuilder::default()
                .args(args)
                .cwd("/")
                .build()
                .expect("build process"),
        )
        .linux(linux);
    if let Some(hooks) = hooks {
        builder = builder.hooks(hooks);
    }
    builder.build().expect("build spec")
}

/// Builds a real, on-disk bundle: `bundle_dir/rootfs` (the synthetic
/// rootfs containing the statically-linked `lifecycle_fixture` at
/// `/fixture`, via `common::build_synthetic_rootfs`) and
/// `bundle_dir/config.json` (so `delete()`'s bundle-reload path — used to
/// re-derive the namespace plan and find `poststop` hooks — has a real
/// file to read, matching `delete_teardown.rs`'s own
/// `bundle_with_namespaces` precedent).
fn build_bundle(bundle_dir: &Path, spec: kestrel_oci::runtime::Spec) -> Bundle {
    common::build_synthetic_rootfs(&bundle_dir.join("rootfs"));

    let raw = RawSpec {
        spec: spec.clone(),
        extra: serde_json::Map::new(),
    };
    std::fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_vec_pretty(&raw).expect("serialize config.json"),
    )
    .expect("write config.json");

    Bundle {
        path: bundle_dir.to_path_buf(),
        spec: raw,
    }
}

/// Mounts a real cgroup2 view at `data_dir()/cgroups` (idempotent across
/// tests: unmounted by the returned `MountGuard`'s `Drop` at the end of
/// each `#[test]` fn, before the next one runs — this crate's suite is
/// always run with `--test-threads=1`). Returns a fresh `run_dir`
/// tempdir alongside it.
fn setup() -> (tempfile::TempDir, MountGuard) {
    let cgroups_mount = data_dir().join("cgroups");
    std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
    let mount_status = Command::new("mount")
        .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
        .status()
        .expect("spawning mount(8)");
    assert!(
        mount_status.success(),
        "mounting a second cgroup2 view at {} failed — this test must run as root",
        cgroups_mount.display()
    );
    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    (run_dir, MountGuard(cgroups_mount))
}

/// Removes the synthetic per-container bundle layer this test's
/// `create()` call staged under `data_dir()/layers/bundle-<id>/` — hygiene
/// only (`delete()` itself only removes `data_dir()/snapshots/<id>`, not
/// the layer store entry, since layers are meant to be
/// shared/content-addressed and outlive any one container in general).
/// Leaves behind one dangling symlink in the link farm
/// (`data_dir()/l/<short>`) pointing at the now-removed diff dir — a
/// small, inert byproduct consistent with how this project treats "an
/// unused stray file" elsewhere (`LayerStore::ensure_link`'s own doc
/// comment already anticipates dangling-symlink handling as normal).
fn cleanup_synthetic_layer(id: &str) {
    let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir());
    let _ = std::fs::remove_dir_all(layer_store.layer_dir(&format!("bundle-{id}")));
}

fn unique_id(label: &str) -> String {
    format!("lc-{label}-{}", nix::unistd::getpid().as_raw())
}

/// The host-visible path a WRITE to `container_path` (from inside the
/// container, post-`pivot_root`) physically lands at: overlayfs writes
/// new files into `upperdir`, and `kestrel_rootfs::snapshot::Snapshotter::
/// prepare_snapshot`'s `upper` directory is a pure, deterministic function
/// of `data_dir` + container id (`data_dir/snapshots/<id>/upper`) — no
/// need to ask `kestrel-init` anything at runtime. See
/// `crates/kestrel-rootfs/src/snapshot.rs`'s `prepare_snapshot` and
/// `crates/kestrel-rootfs/src/overlay.rs`'s `build_overlay_opts` for the
/// formula this mirrors.
fn upper_path(id: &str, container_path: &str) -> PathBuf {
    data_dir()
        .join("snapshots")
        .join(id)
        .join("upper")
        .join(container_path.trim_start_matches('/'))
}

fn state_json_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join(id).join("state.json")
}

fn poll_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Same shape as [`poll_until`], but for a probe that produces a VALUE once
/// ready (e.g. "read this file's content, once it has any") rather than a
/// plain boolean — avoids the TOCTOU gap between a separate `.exists()`
/// poll and a later one-shot read of the same resource. Retries on EVERY
/// `None` the probe returns, whatever the caller's closure considers "not
/// ready yet" — for the byte-content use case below, that includes both
/// "file doesn't exist" AND "file exists but is still empty" (the
/// create-then-truncate-then-write gap this helper exists to close), by
/// having the closure itself filter out empty reads via `.filter(|c|
/// !c.is_empty())`.
fn poll_until_some<T, F: FnMut() -> Option<T>>(timeout: Duration, mut probe: F) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Polls `state.json` until `status == want`, returning the observed
/// `State` — or `None` on timeout.
fn poll_status(state_path: &Path, want: Status, timeout: Duration) -> Option<State> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = State::read(state_path) {
            if s.status == want {
                return Some(s);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// =======================================================================
// Test 1 — test_create_then_start
// =======================================================================

#[test]
#[ignore = "requires root"]
fn test_create_then_start() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();
        let id = unique_id("create-start");
        let (run_dir, _mount_guard) = setup();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let spec = build_spec(
            vec!["/fixture".into(), "marker".into(), "/marker".into()],
            None,
        );
        let bundle = build_bundle(bundle_dir.path(), spec);

        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        assert_eq!(created.status, Status::Created);
        let init_pid = Pid::from_raw(created.pid.expect("state.json must carry a pid after create()"));
        let _process_guard = ProcessGuard(init_pid);

        let marker_host_path = upper_path(&id, "/marker");
        assert!(
            !marker_host_path.exists(),
            "marker file must not exist before start(): {}",
            marker_host_path.display()
        );

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        // Poll for the marker's FINAL content directly, not merely its
        // existence: `std::fs::write` in the fixture is `open(O_CREAT|
        // O_TRUNC)` immediately followed by a separate `write()` — two
        // distinct syscalls with a real (if usually tiny) gap between
        // them. A plain `.exists()` poll can observe the file in that gap
        // (created, still zero bytes) and return early, occasionally
        // making the subsequent one-shot `std::fs::read` below race a
        // still-in-progress write and see an empty file — reproduced
        // directly (Phase 8 Task 16) once this container's whole
        // create-to-marker-write lifecycle got fast enough (after fixing
        // `start()`'s own unnecessary multi-second delay) for that gap to
        // occasionally land on a poll tick. Polling for the CONTENT itself
        // makes this robust regardless of how fast the container runs.
        let content = poll_until_some(Duration::from_secs(20), || {
            std::fs::read(&marker_host_path).ok().filter(|c| !c.is_empty())
        })
        .unwrap_or_else(|| panic!("marker file never appeared with readable content at {}", marker_host_path.display()));
        assert_eq!(content, b"ran", "marker file has unexpected content");

        // Full lifecycle proof + cleanup: wait for the fixture's natural
        // exit (its "marker" branch exits 0 right after writing), reap
        // kestrel-init explicitly (see ProcessGuard's own doc comment for
        // why this test process must do this itself), then delete().
        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(20))
            .expect("container never reached Status::Stopped");
        assert_eq!(stopped.exit_code, Some(0), "unexpected exit_code: {stopped:?}");
        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        cleanup_synthetic_layer(&id);
    });
}

// =======================================================================
// Test 2 — test_exit_code_propagates
// =======================================================================

#[test]
#[ignore = "requires root"]
fn test_exit_code_propagates() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();
        let id = unique_id("exit-code");
        let (run_dir, _mount_guard) = setup();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let spec = build_spec(vec!["/fixture".into(), "exit".into(), "42".into()], None);
        let bundle = build_bundle(bundle_dir.path(), spec);

        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        let init_pid = Pid::from_raw(created.pid.expect("pid recorded after create()"));
        let _process_guard = ProcessGuard(init_pid);

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(20))
            .expect("container never reached Status::Stopped");
        assert_eq!(
            stopped.exit_code,
            Some(42),
            "expected exit_code 42 to propagate from the fixture's `exit 42`, got {stopped:?}"
        );

        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        cleanup_synthetic_layer(&id);
    });
}

// =======================================================================
// Test 3 — test_signal_exit_code
// =======================================================================

#[test]
#[ignore = "requires root"]
fn test_signal_exit_code() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();
        let id = unique_id("signal-exit");
        let (run_dir, _mount_guard) = setup();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let spec = build_spec(vec!["/fixture".into(), "sleep".into(), "30".into()], None);
        let bundle = build_bundle(bundle_dir.path(), spec);

        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        let init_pid = Pid::from_raw(created.pid.expect("pid recorded after create()"));
        let _process_guard = ProcessGuard(init_pid);

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        // `kill.rs`'s non-`--all` path signals whatever pid is CURRENTLY
        // recorded in state.json. `kestrel-init` (this file's fix, see
        // `crates/kestrel-init/src/main.rs`'s post-fork write and
        // `kestrel-oci/src/state.rs`'s updated `pid` field doc comment)
        // overwrites that field with the entrypoint's OWN pid right after
        // forking it — specifically so this call reaches the "sleep 30"
        // fixture process itself, not `kestrel-init`/PID 1 (SIGKILLing
        // PID 1 of a pid namespace would make the kernel immediately
        // SIGKILL every other process in it too, including the fixture,
        // but `kestrel-init` itself would die in the same instant and
        // never survive to record anything — see that fix's own comment
        // for the full reasoning). Poll first: `start()`'s FIFO write and
        // `kestrel-init`'s own post-fork write race harmlessly (both
        // settle to the same final value once the entrypoint truly
        // exists), but this call must not run before the entrypoint pid
        // is actually recorded.
        assert!(
            poll_until(Duration::from_secs(10), || {
                State::read(&state_path)
                    .map(|s| s.pid != created.pid)
                    .unwrap_or(false)
            }),
            "state.json's pid was never updated from kestrel-init's own pid ({:?}) to the \
             entrypoint's real pid",
            created.pid
        );

        let kill_result =
            kestrel_runtime::kill::kill(&id, run_dir.path(), &data_dir(), Signal::SIGKILL, false);
        assert!(kill_result.is_ok(), "kill() failed: {:?}", kill_result.err());

        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(20))
            .expect("container never reached Status::Stopped after SIGKILL");
        assert_eq!(
            stopped.exit_code,
            Some(137),
            "expected exit_code 137 (128 + SIGKILL) after signaling the entrypoint, got {stopped:?}"
        );

        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        cleanup_synthetic_layer(&id);
    });
}

// =======================================================================
// Test 4 — test_zombie_reaping
// =======================================================================

#[test]
#[ignore = "requires root"]
fn test_zombie_reaping() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();
        let id = unique_id("zombie-reap");
        let (run_dir, _mount_guard) = setup();

        const SPAWN_TARGET: usize = 10_000;

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let spec = build_spec(
            vec![
                "/fixture".into(),
                "spawn-abandon".into(),
                SPAWN_TARGET.to_string(),
                "/spawn-count".into(),
            ],
            None,
        );
        let bundle = build_bundle(bundle_dir.path(), spec);

        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        let init_pid = Pid::from_raw(created.pid.expect("pid recorded after create()"));
        let _process_guard = ProcessGuard(init_pid);

        let cgroup =
            kestrel_cgroup::manager::CgroupManager::new(data_dir().join("cgroups"), &id).expect("cgroup manager");

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        // ---- rise: wait for the fixture to report how many children it
        // actually achieved (its fork loop can fail partway, e.g. under
        // this VM's process-limit headroom — assert the REAL achieved
        // count, not blindly 10,000) ----
        let count_host_path = upper_path(&id, "/spawn-count");
        assert!(
            poll_until(Duration::from_secs(20), || count_host_path.exists()),
            "spawn-abandon count file never appeared at {}",
            count_host_path.display()
        );
        let achieved: usize = std::fs::read_to_string(&count_host_path)
            .expect("read spawn-count file")
            .trim()
            .parse()
            .expect("spawn-count file did not contain a plain integer");
        assert!(achieved > 0, "fixture achieved 0 forked children — nothing to reap");
        eprintln!("test_zombie_reaping: fixture achieved {achieved}/{SPAWN_TARGET} forked children");

        // While the fixture is still in its 2-second post-spawn sleep,
        // every one of `achieved` children is a zombie parented to the
        // FIXTURE (not yet reparented to kestrel-init — see
        // `lifecycle_fixture.rs`'s own doc comment) but still a member of
        // the SAME cgroup (cgroup membership is unaffected by
        // reparenting) — so `pids.current` must already reflect them.
        let risen = poll_until(Duration::from_secs(3), || {
            cgroup.pids_current().map(|n| n > achieved as u64).unwrap_or(false)
        });
        let pids_while_alive = cgroup.pids_current().unwrap_or(0);
        assert!(
            risen,
            "pids.current ({pids_while_alive}) never rose to reflect the {achieved} zombie \
             children plus the fixture itself while they were still alive"
        );

        // ---- fall: once the fixture itself exits (after its 2s sleep),
        // its children reparent to kestrel-init in the same instant, and
        // kestrel-init's reaper (a single SIGCHLD wakeup, WNOHANG-looped
        // via drain_dead_children) must drain all of them — pids.current
        // must fall back to a low baseline (kestrel-init alone, or 0 once
        // kestrel-init itself has also exited and been reaped). ----
        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(30))
            .expect("container never reached Status::Stopped after the fixture's spawn-abandon run");
        assert_eq!(stopped.exit_code, Some(0), "unexpected exit_code: {stopped:?}");

        let fell = poll_until(Duration::from_secs(10), || {
            cgroup.pids_current().map(|n| n <= 1).unwrap_or(false)
        });
        let pids_after_reap = cgroup.pids_current().unwrap_or(u64::MAX);
        assert!(
            fell,
            "pids.current ({pids_after_reap}) never fell back to a low baseline (<=1) after the \
             fixture exited — reaper did not drain the {achieved} reparented zombie children \
             (rose to {pids_while_alive} while alive)"
        );
        eprintln!(
            "test_zombie_reaping: pids.current rose to {pids_while_alive} while children were \
             alive, fell back to {pids_after_reap} after the reaper drained them"
        );

        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        cleanup_synthetic_layer(&id);
    });
}

// =======================================================================
// Test 5 — test_hooks_fire_in_order
// =======================================================================

/// Host-executable hook (`createRuntime`/`poststart`/`poststop`, all
/// runtime-namespace per SPEC.md §9.3's table): appends `phase` to
/// `log_path` via `/bin/sh -c`. Reachable regardless of pivot state
/// because `log_path` lives in `bundle_dir` (a plain host tempdir path,
/// never inside the container's overlay/rootfs at all).
fn host_echo_hook(log_path: &Path, phase: &str) -> kestrel_oci::runtime::Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo {phase} >> '{}'", log_path.display()),
        ])
        .build()
        .expect("build host echo hook")
}

/// Builds all 5 hooks for `test_hooks_fire_in_order`. `log_path` is the
/// ONE final shared file the test asserts on; `inner_host_path` is the
/// real, already-resolved HOST path `startContainer`'s marker physically
/// lands at (computed by the caller via `upper_path`, since only the
/// caller knows `data_dir()`/`id` at hook-build time — see this
/// function's own comments for why `startContainer` can't reach
/// `log_path` directly).
fn build_test5_hooks(log_path: &Path, inner_container_path: &str, inner_host_path: &Path) -> kestrel_oci::runtime::Hooks {
    // `createRuntime` (`kestrel-runtime`, host-side, runs synchronously
    // and completes before `create()` ever returns) and `createContainer`
    // (`kestrel-init`, but BEFORE `pivot_root` completes — SPEC.md §9.3's
    // table + this project's own resolved ordering in
    // `crates/kestrel-init/src/main.rs`) can both reach `log_path`
    // directly: pre-pivot, the container's freshly-unshared-but-not-yet-
    // pivoted mount namespace is still an exact copy of the host's mount
    // tree (confirmed against `mounts.rs`'s `stage_rootfs`, called
    // strictly before the `createContainer` hook, and `pivot`, called
    // strictly after — no host path becomes unreachable until `pivot`
    // itself runs), so `log_path` (a plain host tempdir path under
    // `bundle_dir`) is reachable from both.
    let create_runtime = host_echo_hook(log_path, "createRuntime");
    let create_container = host_echo_hook(log_path, "createContainer");

    // `startContainer` (`kestrel-init`, immediately before `execve`) runs
    // strictly AFTER `pivot_root` — the container's root is now the tiny
    // synthetic rootfs (`/fixture` only, no `/bin/sh`), so it can only
    // write to a CONTAINER path, which lands physically in the overlay's
    // upperdir at `inner_host_path` — a different physical file than
    // `log_path`, and one `delete()`'s step 7 will remove. `poststart`
    // below bridges the two.
    let start_container = HookBuilder::default()
        .path("/fixture")
        .args(vec![
            "fixture".to_string(),
            "hook-marker".to_string(),
            inner_container_path.to_string(),
            "startContainer".to_string(),
        ])
        .build()
        .expect("build startContainer hook");

    // `poststart` (`kestrel-runtime`, host-side, runs synchronously as
    // part of `start()` right after the FIFO write unblocks
    // `kestrel-init`). There is no explicit synchronization between THIS
    // hook firing and `kestrel-init`'s own `startContainer` hook having
    // already finished writing `inner_host_path` — both are triggered by
    // the very same FIFO-write event, in two different processes, with
    // nothing else serializing them. `createContainer`/`createRuntime`
    // are NOT subject to this race (both are strictly, causally ordered
    // before the FIFO handshake can even complete at all — see above).
    // This bounded wait-loop (well under `poststart`'s own 30s default
    // hook timeout) closes that one specific gap: only once
    // `inner_host_path` is observed does this hook copy its content into
    // `log_path`, immediately followed by its own "poststart" line — so
    // the final file's line order is deterministic regardless of which
    // process's hook actually wins the race in real wall-clock time.
    let poststart_script = format!(
        "i=0; while [ $i -lt 100 ]; do [ -f '{inner}' ] && break; sleep 0.05; i=$((i+1)); done; \
         cat '{inner}' >> '{log}' 2>/dev/null; echo poststart >> '{log}'",
        inner = inner_host_path.display(),
        log = log_path.display(),
    );
    let poststart = HookBuilder::default()
        .path("/bin/sh")
        .args(vec!["sh".to_string(), "-c".to_string(), poststart_script])
        .build()
        .expect("build poststart hook");

    let poststop = host_echo_hook(log_path, "poststop");

    HooksBuilder::default()
        .create_runtime(vec![create_runtime])
        .create_container(vec![create_container])
        .start_container(vec![start_container])
        .poststart(vec![poststart])
        .poststop(vec![poststop])
        .build()
        .expect("build hooks")
}

#[test]
#[ignore = "requires root"]
fn test_hooks_fire_in_order() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();
        let id = unique_id("hooks-order");
        let (run_dir, _mount_guard) = setup();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let log_path = bundle_dir.path().join("hooks.log");
        let inner_container_path = "/hooks-inner-marker";
        let inner_host_path = upper_path(&id, inner_container_path);

        let hooks = build_test5_hooks(&log_path, inner_container_path, &inner_host_path);
        let spec = build_spec(vec!["/fixture".into(), "exit".into(), "0".into()], Some(hooks));
        let bundle = build_bundle(bundle_dir.path(), spec);

        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(create_result.is_ok(), "create() failed: {:?}", create_result.err());

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        let init_pid = Pid::from_raw(created.pid.expect("pid recorded after create()"));
        let _process_guard = ProcessGuard(init_pid);

        // createRuntime must already have fired (create() runs it
        // synchronously, host-side, before create() ever returns).
        let after_create = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert_eq!(
            after_create.lines().collect::<Vec<_>>(),
            vec!["createRuntime"],
            "expected only createRuntime to have fired by the time create() returns, got: {after_create:?}"
        );

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        // Wait for the trivial `exit 0` entrypoint to run and exit
        // naturally, and for poststart's own wait-loop (bounded at ~5s)
        // to have completed as part of start() returning — start() only
        // returns once poststart hooks have finished, so by the time
        // start_result is Ok, poststart (and therefore, transitively, its
        // wait for startContainer's marker) has already completed.
        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(20))
            .expect("container never reached Status::Stopped");
        assert_eq!(stopped.exit_code, Some(0), "unexpected exit_code: {stopped:?}");
        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        let final_content = std::fs::read_to_string(&log_path).expect("read final hooks.log");
        let lines: Vec<&str> = final_content.lines().collect();
        assert_eq!(
            lines,
            vec!["createRuntime", "createContainer", "startContainer", "poststart", "poststop"],
            "hooks did not fire in the expected order; full log content: {final_content:?}"
        );

        cleanup_synthetic_layer(&id);
    });
}
