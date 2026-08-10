// crates/kestrel-runtime/tests/create_from_layers.rs
//
//! Root-gated regression/coverage test for Phase 9 Task 3's gap-fill in
//! `create.rs`'s `stage_bundle_rootfs_as_synthetic_layer`: a bundle whose
//! `config.json` carries the `kestrel.lowerChainIds` annotation must reuse
//! those already-pulled layer chain-ids directly (no `ensure_layer`, no
//! recursive copy of a `rootfs/` directory that need not even exist), and
//! `kestrel-init`'s own overlay mount must genuinely merge every layer the
//! annotation names — not just the first one.
//!
//! Uses the REAL `kestrel-init` and the REAL, statically-linked
//! `lifecycle_fixture` binary (same two artifacts `tests/lifecycle.rs`
//! needs — see that file's own doc comment for the exact `make` targets
//! and the "why `data_dir` is the real `/var/lib/kestrel`" rationale,
//! which applies identically here since `kestrel-init`'s own `main.rs`
//! hardcodes that path regardless of which test drives it).
//!
//! Prerequisites — build BOTH before running this file, same as
//! `tests/lifecycle.rs`:
//! ```text
//! make build-kestrel-init-static
//! make build-lifecycle-fixture-static
//! ```
//! Run as root inside the Lima VM:
//! ```text
//! sudo -E timeout -k 5 120 cargo test -p kestrel-runtime --test create_from_layers -- --ignored --test-threads=1
//! ```
//!
//! ## How this proves a REAL multi-layer merge, not just "create() didn't error"
//!
//! Two independent layers are staged directly via `LayerStore::ensure_layer`
//! (simulating what a prior `kestreld` image pull would have already done)
//! — one contributes the container's entrypoint binary (`/fixture`, a copy
//! of the statically-linked `lifecycle_fixture`), the other contributes a
//! plain data file (`/rootB-marker`) with known content. Neither layer
//! alone has both files. The bundle's `config.json` names both layers'
//! chain-ids via `kestrel.lowerChainIds` (comma-joined) and has NO
//! `rootfs/` directory on disk at all — proving `create()`'s fast path
//! never reads `bundle.path.join(root.path())` (if it did, `create()`
//! would fail immediately with an I/O error instead of succeeding). The
//! container's entrypoint is `/fixture copy /rootB-marker /out` — for that
//! `copy` to succeed at all, `/fixture` (from layer A) must have actually
//! executed AND been able to read `/rootB-marker` (from layer B) from the
//! SAME merged rootfs view. `/out`'s content, read back from the host side
//! via the overlay's upperdir, is the real proof both layers landed in one
//! merged mount.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use kestrel_oci::default_spec::default_namespaces;
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder,
    RootBuilder, SpecBuilder,
};
use kestrel_oci::state::{State, Status};
use kestrel_runtime::bundle::Bundle;
use nix::unistd::Pid;

/// Matches `tests/lifecycle.rs`'s own rationale exactly: the REAL
/// `kestrel-init` hardcodes `/var/lib/kestrel` as its `data_dir`
/// (`Bootstrap` carries no `data_dir` field at all, by design), so both
/// the layers this test stages AND the `create()` call driving them must
/// agree on that same real path.
fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/kestrel")
}

// ---------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------

struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// Kills+reaps the container's `kestrel-init` on drop, best-effort — same
/// rationale as `tests/lifecycle.rs`'s own `ProcessGuard`.
struct ProcessGuard(Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

// ---------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------

/// Path to the statically-linked `lifecycle_fixture` artifact — same
/// formula as `tests/common/mod.rs::static_fixture_path` (private to that
/// module, so duplicated here rather than reused, matching this crate's
/// existing per-file-duplication convention for root-gated test
/// boilerplate).
fn static_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture")
}

/// Installs the REAL, statically-linked `kestrel-init` as a sibling of
/// THIS test binary — identical to `tests/lifecycle.rs`'s own
/// `install_real_kestrel_init`, duplicated here for the same reason
/// (private to that file, and this crate's established convention is
/// per-file duplication of this boilerplate rather than a shared `pub`
/// helper).
fn install_real_kestrel_init() -> PathBuf {
    let real = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/aarch64-unknown-linux-gnu/debug/kestrel-init");
    if !real.exists() {
        panic!(
            "real statically-linked kestrel-init not found at {}\nRun `make build-kestrel-init-static` first.",
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
            "kestrel-init at {} does not look statically linked (`file` reported: {:?}).\nRebuild it with `make build-kestrel-init-static`.",
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
/// User namespace. `NsType::Mount` is deliberately KEPT (unlike
/// `create_pins_namespaces.rs`'s filtered set): `kestrel-init` always
/// mounts the overlay + `pivot_root`s regardless of the annotation fast
/// path, so a real Mount namespace is required here exactly as it is in
/// `tests/lifecycle.rs`.
fn namespaces_for_this_test() -> Vec<kestrel_oci::runtime::LinuxNamespace> {
    let mut namespaces = default_namespaces();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()
            .expect("build user namespace"),
    );
    namespaces
}

/// Stages a single real layer directly via `LayerStore::ensure_layer`
/// (simulating a prior `kestreld` image pull) containing exactly one file
/// at `container_path` with `content`, under the already-chosen `chain_id`.
fn stage_layer(chain_id: &str, container_path: &str, content: &[u8], executable: bool) {
    let store = kestrel_rootfs::snapshot::LayerStore::new(data_dir());
    let diff = store
        .ensure_layer(chain_id, None)
        .unwrap_or_else(|e| panic!("ensure_layer({chain_id}): {e}"));
    let dest = diff.join(container_path.trim_start_matches('/'));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&dest, content).unwrap_or_else(|e| panic!("writing {}: {e}", dest.display()));
    if executable {
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn cleanup_layer(chain_id: &str) {
    let store = kestrel_rootfs::snapshot::LayerStore::new(data_dir());
    let _ = std::fs::remove_dir_all(store.layer_dir(chain_id));
}

/// Builds a bundle whose `config.json` carries the
/// `kestrel.lowerChainIds` annotation (comma-joined, bottom-to-top) and
/// has NO `rootfs/` directory anywhere on disk — `bundle_dir` itself is
/// created, but nothing is ever written under a `rootfs/` child of it.
fn build_bundle_from_layer_annotation(bundle_dir: &Path, lower_chain_ids: &[&str], args: Vec<String>) -> Bundle {
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
        .namespaces(namespaces_for_this_test())
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .build()
        .expect("build linux section");

    let mut annotations = std::collections::HashMap::new();
    annotations.insert("kestrel.lowerChainIds".to_string(), lower_chain_ids.join(","));

    let spec = SpecBuilder::default()
        .version("1.0.2")
        // `root` is set to a path that is never created on disk anywhere
        // in this test — proving the fast path never dereferences it.
        // `bundle::load`/`validate()` are never called by this test (the
        // `Bundle` is constructed directly, same as
        // `create_pins_namespaces.rs`/`tests/lifecycle.rs`), so an
        // on-disk-nonexistent `root.path()` is never itself a problem.
        .root(RootBuilder::default().path("rootfs").build().expect("build root"))
        .process(
            ProcessBuilder::default()
                .args(args)
                .cwd("/")
                .build()
                .expect("build process"),
        )
        .linux(linux)
        .annotations(annotations)
        .build()
        .expect("build spec");

    let raw = RawSpec {
        spec,
        extra: serde_json::Map::new(),
    };
    // A real config.json IS written (matching what `kestreld` would
    // actually produce on disk), just never a `rootfs/` sibling directory.
    std::fs::create_dir_all(bundle_dir).unwrap();
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

/// Same rationale as `tests/lifecycle.rs`'s own `upper_path`: a write to
/// `container_path` from inside the container lands physically at
/// `data_dir/snapshots/<id>/upper/<container_path>` — a plain directory,
/// always host-readable regardless of the container's own (possibly
/// private) mount namespace, since it's the overlay's UPPERDIR, not the
/// mount itself.
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

fn unique_id(label: &str) -> String {
    format!("cfl-{label}-{}", nix::unistd::getpid().as_raw())
}

// =======================================================================
// The test
// =======================================================================

#[test]
#[ignore = "requires root"]
fn test_create_from_pre_existing_layer_chain_merges_both_layers() {
    kestrel_ns::test_util::run_isolated(|| {
        install_real_kestrel_init();

        let pid = nix::unistd::getpid().as_raw();
        let layer_fixture = format!("phase9task3fixturelayer{pid}");
        let layer_marker = format!("phase9task3markerlayer{pid}");

        // ---- stage two real, independent layers directly (simulating a
        // prior `kestreld` image pull) — NOT via create()'s fallback copy
        // path at all ----
        let fixture_bytes = std::fs::read(static_fixture_path()).unwrap_or_else(|e| {
            panic!(
                "static lifecycle_fixture artifact not found at {}: {e}\nRun `make build-lifecycle-fixture-static` first.",
                static_fixture_path().display()
            )
        });
        stage_layer(&layer_fixture, "/fixture", &fixture_bytes, true);
        const MARKER_CONTENT: &[u8] = b"from-layer-b";
        stage_layer(&layer_marker, "/rootB-marker", MARKER_CONTENT, false);

        let id = unique_id("merge");
        let (run_dir, _mount_guard) = setup();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let bundle = build_bundle_from_layer_annotation(
            bundle_dir.path(),
            &[&layer_fixture, &layer_marker],
            vec![
                "/fixture".into(),
                "copy".into(),
                "/rootB-marker".into(),
                "/out".into(),
            ],
        );

        // ---- the real proof this task exists for: no `rootfs/` directory
        // exists anywhere under this bundle, before OR after create() ----
        assert!(
            !bundle_dir.path().join("rootfs").exists(),
            "precondition: this bundle must never have a rootfs/ directory at all"
        );

        // ---- the real call under test ----
        let create_result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), &data_dir());
        assert!(
            create_result.is_ok(),
            "create() should succeed via the annotation fast path (no rootfs/ dir needed): {:?}",
            create_result.err()
        );
        assert!(
            !bundle_dir.path().join("rootfs").exists(),
            "create() must never have created a rootfs/ directory itself either"
        );

        let state_path = state_json_path(run_dir.path(), &id);
        let created = State::read(&state_path).expect("read state.json after create()");
        assert_eq!(created.status, Status::Created);
        let init_pid = Pid::from_raw(created.pid.expect("state.json must carry a pid after create()"));
        let _process_guard = ProcessGuard(init_pid);

        let out_host_path = upper_path(&id, "/out");
        assert!(
            !out_host_path.exists(),
            "/out must not exist before start(): {}",
            out_host_path.display()
        );

        let start_result = kestrel_runtime::start::start(&id, run_dir.path());
        assert!(start_result.is_ok(), "start() failed: {:?}", start_result.err());

        // ---- THE assertion this test exists for: /fixture (layer A) ran
        // and successfully read /rootB-marker (layer B) from the SAME
        // merged rootfs view, proving both layers were genuinely mounted
        // together, not just that create() returned Ok ----
        let content = poll_until_some(Duration::from_secs(20), || {
            std::fs::read(&out_host_path).ok().filter(|c| !c.is_empty())
        })
        .unwrap_or_else(|| {
            panic!(
                "/out never appeared with readable content at {} — /fixture (layer A) could not \
                 read /rootB-marker (layer B), meaning the two layers were not actually merged \
                 into one overlay",
                out_host_path.display()
            )
        });
        assert_eq!(
            content, MARKER_CONTENT,
            "content copied by /fixture from /rootB-marker does not match what was staged into \
             the marker layer"
        );

        let stopped = poll_status(&state_path, Status::Stopped, Duration::from_secs(20))
            .expect("container never reached Status::Stopped");
        assert_eq!(stopped.exit_code, Some(0), "unexpected exit_code: {stopped:?}");
        let _ = nix::sys::wait::waitpid(init_pid, None);

        let delete_result = kestrel_runtime::delete::delete(&id, run_dir.path(), &data_dir(), false);
        assert!(delete_result.is_ok(), "delete() failed: {:?}", delete_result.err());

        cleanup_layer(&layer_fixture);
        cleanup_layer(&layer_marker);
    });
}
