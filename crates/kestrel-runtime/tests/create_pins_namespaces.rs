// crates/kestrel-runtime/tests/create_pins_namespaces.rs
//
//! Root-gated regression/coverage tests for the namespace-pinning gap
//! fixed in `create.rs`: proves that a SUCCESSFUL `create()` call
//! genuinely bind-mounts every namespace in its `NamespacePlan` onto
//! `run_dir/<id>/ns/<type>` (SPEC.md §4.4's convention), that those pin
//! files are real, independently usable `setns(2)` targets, AND that
//! `create()` tolerates the one specific, environment-caused Mount pin
//! failure documented below rather than leaking the container it already
//! started.
//!
//! ## `NsType::Mount` and this Lima VM
//!
//! `crates/kestrel-ns/tests/join.rs` already documents a real, pre-
//! existing environment limitation: this Lima VM (Ubuntu 24.04, kernel
//! 6.8.0-136-generic, aarch64/vz) cannot bind-mount ANY mount namespace
//! via nsfs — `mount(2)` with `MS_BIND` always fails with `EINVAL` for
//! `NsType::Mount` specifically, while every other namespace type binds
//! fine. Independently re-verified here (via plain `unshare(1)` +
//! `mount --bind`, no kestrel code involved at all) before writing these
//! tests: with a genuinely distinct child mount namespace confirmed via
//! `/proc/<pid>/ns/mnt`'s differing inode, `mount --bind` on it still
//! fails with `EINVAL`, while the identical operation on uts/ipc/pid/
//! net/cgroup/user namespaces of the SAME child all succeed. This is a
//! real environment limitation, not a bug in `kestrel_ns::pin` or in
//! `create.rs`'s `pin_namespaces` — the exact same `pin_namespace`
//! building block Phase 2 already validated for the other 6 types is
//! used for Mount too; nothing about it is namespace-type-specific.
//!
//! `create.rs`'s `pin_namespaces` now specifically tolerates a Mount pin
//! failure whose underlying errno is EINVAL (see its own doc comment):
//! it logs a warning and moves on instead of rolling back and failing
//! `create()` outright, because by the time pinning runs the container's
//! `kestrel-init` is already a real, live, running process — failing
//! `create()` here would leak it (and its cgroup) with no cleanup path.
//! The second test below (`test_create_tolerates_unpinnable_mount_
//! namespace_and_pins_the_rest`) exploits this SAME deterministic
//! EINVAL-on-Mount behavior as its proof: a plan that includes
//! `NsType::Mount` now reliably makes `create()` succeed anyway, with
//! every OTHER requested type still genuinely pinned and no `mnt` pin
//! file left behind. (The complementary case — a genuine, non-Mount pin
//! failure still triggering the full rollback-and-fail path exactly as
//! before — is covered by `test_pin_namespaces_rolls_back_on_a_genuine_
//! non_mount_failure` in `create.rs`'s own unit tests, via directory-
//! collision fault injection that's unrelated to this VM's Mount/EINVAL
//! quirk and therefore portable to any environment.)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use kestrel_oci::default_spec::{default_namespaces, default_spec};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType};
use kestrel_oci::state::{State, Status};
use kestrel_ns::types::NsType;
use kestrel_runtime::bundle::Bundle;

struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

struct CgroupGuard(kestrel_cgroup::manager::CgroupManager);
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let _ = self.0.destroy();
    }
}

/// Kills (SIGKILL) and reaps the spawned container process on drop,
/// best-effort. The stub init the tests exec into blocks forever, so
/// without this the process leaks (root-owned, blocking forever) any
/// time a test panics before reaching its manual cleanup — this makes
/// that cleanup unconditional instead of "only on the happy path".
struct ProcessGuard(nix::unistd::Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

/// Installs `fixture-stub-init` as a sibling of THIS test binary, named
/// literally `kestrel-init` — matching `create.rs`'s
/// `resolve_kestrel_init_path`'s sibling-binary convention
/// (`current_exe().parent().join("kestrel-init")`). `child_action` runs
/// this lookup post-fork-pre-exec, so it resolves relative to the SAME
/// test binary path this function itself observes via `current_exe()`.
///
/// Copy-to-a-unique-tmp-name-then-rename, not a direct write: this
/// `deps/` directory is shared by every test binary in the workspace, so
/// two test processes racing to install the same well-known
/// `kestrel-init` path concurrently must never let a THIRD, unrelated
/// process observe a partially-written file there. `rename(2)` within
/// the same directory is atomic; the content is deterministic (the same
/// fixture binary every time), so a "loser" of the race harmlessly
/// renames identical bytes over the "winner"'s.
///
/// Deliberately never removed afterward: it's a static, deterministic
/// file, other tests may still be relying on it existing concurrently,
/// and leaving it behind is no different from any other cargo build
/// artifact already living in `deps/`.
fn install_stub_kestrel_init() -> PathBuf {
    let stub = PathBuf::from(env!("CARGO_BIN_EXE_fixture-stub-init"));
    let current_exe = std::env::current_exe().expect("current_exe");
    let sibling_dir = current_exe
        .parent()
        .expect("current_exe has a parent directory")
        .to_path_buf();
    let target = sibling_dir.join("kestrel-init");
    let tmp = sibling_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
    std::fs::copy(&stub, &tmp).expect("copy fixture-stub-init to tmp");
    std::fs::rename(&tmp, &target).expect("rename tmp into place as sibling kestrel-init");
    target
}

fn stat_ns_identity(path: &Path) -> (u64, u64) {
    let st = nix::sys::stat::stat(path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
    (st.st_dev, st.st_ino)
}

/// Builds a minimal-but-real `Bundle` with the given namespace list (plus
/// a trivial identity uid/gid map, since every caller here includes
/// `NsType::User`) and no hooks — `create()`'s createRuntime hook step
/// then trivially succeeds, so the go-ahead is always sent and
/// `child_action` always execs into the installed stub `kestrel-init`.
fn bundle_with_namespaces(bundle_dir: &Path, namespaces: Vec<LinuxNamespace>) -> Bundle {
    std::fs::create_dir_all(bundle_dir.join("rootfs")).expect("mkdir rootfs");

    let mut spec = default_spec();
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
        .namespaces(namespaces)
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .build()
        .expect("build linux section");
    spec.set_linux(Some(linux));

    Bundle {
        path: bundle_dir.to_path_buf(),
        spec: RawSpec {
            spec,
            extra: serde_json::Map::new(),
        },
    }
}

/// `default_namespaces()` (Pid, Network, Ipc, Uts, Mount, Cgroup) plus a
/// User namespace — required to route around the pre-existing
/// `stage0_inner`/`plan.has_user_ns()` mismatch documented in
/// `create_hook_failure_no_hang.rs` (stage0_inner unconditionally expects
/// a `Sync::RequestMaps` message that stage1 only sends when a User
/// namespace is in the plan).
fn default_namespaces_plus_user() -> Vec<LinuxNamespace> {
    let mut namespaces = default_namespaces();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()
            .expect("build user namespace"),
    );
    namespaces
}

/// Same as [`default_namespaces_plus_user`], minus `Mount` — see this
/// file's module doc comment for why: this Lima VM cannot bind-mount
/// mount namespaces at all, so a plan containing one makes
/// `pin_namespaces` (and therefore `create()`) fail here.
fn namespaces_without_mount_plus_user() -> Vec<LinuxNamespace> {
    default_namespaces_plus_user()
        .into_iter()
        .filter(|ns| ns.typ() != LinuxNamespaceType::Mount)
        .collect()
}

/// Sets up the shared plumbing every test below needs: a real cgroup2
/// mount at `data_dir/cgroups` (same technique as
/// `create_hook_failure_no_hang.rs`), a fresh `run_dir`, and a
/// destroy-on-drop cgroup guard for `id`. Returns the guards (which must
/// outlive the `create()` call and any assertions) plus the two
/// directories.
fn setup_dirs(id: &str) -> (tempfile::TempDir, tempfile::TempDir, MountGuard, CgroupGuard) {
    let data_dir = tempfile::tempdir().expect("data_dir tempdir");
    let cgroups_mount = data_dir.path().join("cgroups");
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
    let mount_guard = MountGuard(cgroups_mount.clone());

    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let cgroup_guard = CgroupGuard(
        kestrel_cgroup::manager::CgroupManager::new(data_dir.path().join("cgroups"), id)
            .expect("valid cgroup id"),
    );

    (run_dir, data_dir, mount_guard, cgroup_guard)
}

#[test]
#[ignore = "requires root"]
fn test_create_pins_every_namespace_and_pins_are_real_setns_targets() {
    // `run_stages` (deep inside `create()`) requires a single-threaded
    // calling process — cargo test's harness never is. Same isolation
    // pattern as `create_hook_failure_no_hang.rs`.
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        // NsType::Mount deliberately excluded — see module doc comment.
        let bundle = bundle_with_namespaces(bundle_dir.path(), namespaces_without_mount_plus_user());

        let id = format!("pins-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard, cgroup_guard) = setup_dirs(&id);

        // ---- the real call under test: must SUCCEED this time ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(
            result.is_ok(),
            "create() should succeed (no createRuntime hooks configured, no Mount namespace in \
             this environment): {:?}",
            result.err()
        );

        // ---- state.json must report Created + a real pid ----
        let state_path = run_dir.path().join(&id).join("state.json");
        let state = State::read(&state_path).expect("read state.json");
        assert_eq!(state.status, Status::Created);
        let target_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        // Guard the spawned process from here on, as early as its pid is
        // knowable — it blocks forever, so a panic in any assertion below
        // must not leak it. Explicitly dropped further down (see there)
        // to keep it killed/reaped before the cgroup/mount guards run.
        let process_guard = ProcessGuard(target_pid);

        // ---- step 1: every pin file exists and matches the container's
        // real namespace identity ----
        let ns_dir = run_dir.path().join(&id).join("ns");
        let ns_types = [
            NsType::Pid,
            NsType::Net,
            NsType::Ipc,
            NsType::Uts,
            NsType::Cgroup,
            NsType::User,
        ];
        let mut pins: BTreeMap<NsType, PathBuf> = BTreeMap::new();
        for &ns in &ns_types {
            let pin_path = ns_dir.join(ns.proc_name());
            assert!(
                pin_path.exists(),
                "expected a pin file for {ns:?} at {}",
                pin_path.display()
            );
            let pin_identity = stat_ns_identity(&pin_path);
            let real_identity =
                stat_ns_identity(Path::new(&format!("/proc/{target_pid}/ns/{}", ns.proc_name())));
            assert_eq!(
                pin_identity, real_identity,
                "pin file for {ns:?} does not match the container's real namespace"
            );
            pins.insert(ns, pin_path);
        }
        assert!(
            !ns_dir.join("mnt").exists(),
            "no Mount namespace was in this test's plan; there should be no mnt pin file"
        );

        // ---- step 2: setns via the pins alone, from an unrelated fresh
        // process, genuinely lands in the container's namespaces ----
        //
        // NsType::Pid is pinned and identity-checked in step 1 above, but
        // deliberately excluded here: entering a PID namespace via
        // `setns(CLONE_NEWPID)` does not retroactively change the CALLING
        // process's own `/proc/self/ns/pid` — only its `pid_for_children`
        // (i.e. the namespace of children it forks afterward). That's
        // documented kernel behavior (`pid_namespaces(7)`), not a gap
        // here.
        let checked_via_setns = [NsType::Net, NsType::Ipc, NsType::Uts, NsType::Cgroup, NsType::User];
        let pins_for_join = pins.clone();
        kestrel_ns::test_util::run_isolated(move || {
            let pins = pins_for_join;
            // Baseline, captured BEFORE joining anything: this freshly
            // forked process starts out in the HOST's namespaces
            // (run_isolated only forks — it never unshares/setns's on its
            // own), so a match against the pin here would be a false
            // positive we need to rule out.
            let baseline: BTreeMap<NsType, (u64, u64)> = checked_via_setns
                .iter()
                .map(|&ns| {
                    let p = format!("/proc/self/ns/{}", ns.proc_name());
                    (ns, stat_ns_identity(Path::new(&p)))
                })
                .collect();

            kestrel_ns::join::join_namespaces(&pins).expect("join_namespaces via the pin files");

            for &ns in &checked_via_setns {
                let after = stat_ns_identity(Path::new(&format!("/proc/self/ns/{}", ns.proc_name())));
                let pin_identity = stat_ns_identity(&pins[&ns]);
                assert_eq!(
                    after, pin_identity,
                    "after setns, this process's own {ns:?} namespace should match the pin file"
                );
                assert_ne!(
                    after, baseline[&ns],
                    "after setns, this process's own {ns:?} namespace should have changed from \
                     its host baseline — otherwise this proves nothing"
                );
            }
        });

        // ---- cleanup: kill+reap the stub container process (it blocks
        // forever), unpin, then tear down the cgroup/mount/tempdir guards ----
        drop(process_guard);
        for pin_path in pins.values() {
            let _ = kestrel_ns::pin::unpin_namespace(pin_path);
        }

        drop(cgroup_guard);
        drop(mount_guard);
    });
}

#[test]
#[ignore = "requires root"]
fn test_create_tolerates_unpinnable_mount_namespace_and_pins_the_rest() {
    // Exploits the real, deterministic Mount-namespace-bind-mount
    // limitation documented in this file's module doc comment: a plan
    // that includes `NsType::Mount` reliably makes the Mount pin fail
    // with EINVAL partway through `pin_namespaces` in THIS environment.
    // Proves the fix for the design gap this file's Task 16 prep
    // uncovered: `create()` must SUCCEED anyway (not roll back and fail,
    // which used to leak the already-running `kestrel-init` process and
    // its cgroup), every OTHER requested namespace type must still be
    // genuinely pinned, and specifically NO pin file must exist for
    // Mount.
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let bundle = bundle_with_namespaces(bundle_dir.path(), default_namespaces_plus_user());

        let id = format!("pins-mount-tolerant-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard, cgroup_guard) = setup_dirs(&id);

        // ---- the real call under test: must SUCCEED despite Mount being
        // unpinnable here ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(
            result.is_ok(),
            "create() should tolerate the Mount/EINVAL pin failure and succeed anyway \
             (see create.rs's pin_namespaces doc comment): {:?}",
            result.err()
        );

        // ---- state.json must report Created + a real pid: create()
        // genuinely completed, it did not bail out early ----
        let state_path = run_dir.path().join(&id).join("state.json");
        let state = State::read(&state_path).expect("read state.json");
        assert_eq!(state.status, Status::Created);
        let target_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        // Guard the spawned process from here on — it blocks forever, so
        // a panic in any assertion below must not leak it.
        let process_guard = ProcessGuard(target_pid);

        // ---- every namespace type OTHER than Mount must be genuinely
        // pinned, with a pin file whose identity matches the real
        // container namespace ----
        let ns_dir = run_dir.path().join(&id).join("ns");
        let ns_types = [
            NsType::Pid,
            NsType::Net,
            NsType::Ipc,
            NsType::Uts,
            NsType::Cgroup,
            NsType::User,
        ];
        for &ns in &ns_types {
            let pin_path = ns_dir.join(ns.proc_name());
            assert!(
                pin_path.exists(),
                "expected a pin file for {ns:?} at {} even though Mount could not be pinned",
                pin_path.display()
            );
            let pin_identity = stat_ns_identity(&pin_path);
            let real_identity =
                stat_ns_identity(Path::new(&format!("/proc/{target_pid}/ns/{}", ns.proc_name())));
            assert_eq!(
                pin_identity, real_identity,
                "pin file for {ns:?} does not match the container's real namespace"
            );
        }

        // ---- the real proof: no pin file exists for Mount specifically ----
        let mount_pin = ns_dir.join(NsType::Mount.proc_name());
        assert!(
            !mount_pin.exists(),
            "Mount could not be pinned in this environment (EINVAL, tolerated by \
             pin_namespaces); there must be no {} pin file left behind",
            mount_pin.display()
        );

        // ---- cleanup: kill+reap the stub container process, unpin what
        // was actually pinned, then tear down the cgroup/mount guards ----
        drop(process_guard);
        for &ns in &ns_types {
            let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
        }

        drop(cgroup_guard);
        drop(mount_guard);
    });
}
