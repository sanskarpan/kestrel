// crates/kestrel-runtime/tests/create_hook_failure_no_hang.rs
//
//! Root-gated regression test for the createRuntime-hook-failure hang bug
//! fixed in `create.rs`: proves the process `run_stages` forks (which
//! becomes `child_action`, later PID 1 of the container's new namespaces)
//! actually EXITS once `create()` aborts after a failed `createRuntime`
//! hook, rather than hanging forever blocked in `recv_go_ahead`'s `read()`.
//!
//! Why this can't just check `create()`'s own return value: `create()`
//! already returns `Err` today even with the bug present (the bug is a
//! background leak in the forked child, which `create()`'s own `Result`
//! says nothing about — the host side successfully observes its own
//! `bail!` regardless of whether the child it forked earlier is hung or
//! not). The only real proof is observing the forked process itself.
//!
//! How the forked process is observed without `create()` exposing its pid
//! on the error path: `run_stages` marks its caller (this test, once
//! `run_isolated` below has forked it into its own single-threaded
//! process) as a `PR_SET_CHILD_SUBREAPER`. Its two-level fork (stage1,
//! which reports the real pid and exits immediately, then stage2 /
//! `child_action`, which is what actually blocks in `recv_go_ahead`) means
//! stage2 gets reparented directly to us the moment stage1 exits — which
//! happens synchronously, well before `run_stages` even returns to
//! `create()`. So by the time `create()` returns (successfully or not),
//! stage2 is already a direct child of this test process and shows up in
//! `/proc/<us>/task/<us>/children`. Diffing that file against a
//! pre-`create()` baseline gives us the real pid to watch.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use kestrel_oci::default_spec::{default_namespaces, default_spec};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    HookBuilder, HooksBuilder, LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder,
    LinuxNamespaceType,
};
use kestrel_runtime::bundle::Bundle;

/// Best-effort `umount` on drop — guarantees the secondary cgroup2 mount
/// this test creates (see `test_create_hook_failure_does_not_hang_child`'s
/// own comment on why it's needed) never leaks into the host's real mount
/// namespace, even if an assertion above panics before reaching the
/// explicit cleanup at the end of the test body. Runs inside
/// `run_isolated`'s `catch_unwind`, so a panic anywhere in the test body
/// still unwinds through this `Drop` before that process `_exit`s.
struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// Same rationale as `MountGuard`, for the leaf cgroup directory itself.
struct CgroupGuard(kestrel_cgroup::manager::CgroupManager);
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let _ = self.0.destroy();
    }
}

/// Polls `/proc/<own_pid>/task/<own_pid>/children` until a pid NOT present
/// in `baseline` shows up, or `timeout` elapses.
fn wait_for_new_child(own_pid: i32, baseline: &HashSet<i32>, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) =
            std::fs::read_to_string(format!("/proc/{own_pid}/task/{own_pid}/children"))
        {
            for tok in contents.split_whitespace() {
                if let Ok(pid) = tok.parse::<i32>() {
                    if !baseline.contains(&pid) {
                        return Some(pid);
                    }
                }
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// WNOHANG-polls `pid` for up to `timeout`. `Some(code)` if it exits in
/// time (this is the "fix worked, no hang" outcome); `None` if it's still
/// alive when the deadline passes (this is the bug: hung in `read()`).
fn wait_for_exit(pid: i32, timeout: Duration) -> Option<i32> {
    let target = nix::unistd::Pid::from_raw(pid);
    let deadline = Instant::now() + timeout;
    loop {
        match nix::sys::wait::waitpid(target, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => return Some(code),
            Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => return Some(-(sig as i32)),
            Ok(_) => {} // StillAlive, Stopped, Continued — keep polling
            Err(_) => return None,
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn own_children_snapshot(own_pid: i32) -> HashSet<i32> {
    std::fs::read_to_string(format!("/proc/{own_pid}/task/{own_pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

#[test]
#[ignore = "requires root"]
fn test_create_hook_failure_does_not_hang_child() {
    // `run_stages` (called deep inside `create()`) requires the calling
    // PROCESS to be single-threaded — cargo test's harness never is (one
    // thread per test). `run_isolated` forks first so everything below
    // runs in a fresh, single-threaded process, matching every other
    // root-gated `run_stages`-based test in this workspace
    // (kestrel-ns/tests/dance.rs, kestrel-init/tests/exec_via_kestrel_init.rs).
    kestrel_ns::test_util::run_isolated(|| {
        // ---- bundle: minimal but real, config.json equivalent built in-memory ----
        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        // `create()`'s stage_bundle_rootfs_as_synthetic_layer copies this
        // directory's contents into a layer diff dir — empty is enough
        // (and deliberately keeps this test from needing a real rootfs,
        // since the point under test never reaches pivot_root/exec).
        std::fs::create_dir_all(bundle_dir.path().join("rootfs")).expect("mkdir rootfs");

        let mut spec = default_spec();

        // Add a User namespace with a trivial identity map (root's own
        // uid/gid, since this test runs as root via `#[ignore = "requires
        // root"]`). This is NOT strictly needed for the bug under test
        // (the go-ahead-socket hang/fix is unrelated to user namespaces),
        // but it sidesteps a separate, pre-existing issue in
        // `kestrel_ns::stages::stage0_inner`: it unconditionally expects a
        // `Sync::RequestMaps` message first, while `stage1` only sends one
        // when `plan.has_user_ns()` — so a namespace plan with no User
        // namespace (e.g. `default_spec()`'s own default 6-namespace,
        // non-rootless set) currently makes `stage0_inner` bail with
        // "unexpected sync from stage1: ReportPid(..)" before `create()`
        // even reaches its own createRuntime-hooks/host_end logic at all.
        // That bug is out of scope here (this task is scoped to the
        // host_end close-order fix in create.rs only) — adding a User
        // namespace is the minimal way to route around it and reach the
        // actual code path this test exists to exercise.
        let mut namespaces = default_namespaces();
        namespaces.push(
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()
                .expect("build user namespace"),
        );
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

        let bad_hook = HookBuilder::default()
            // Deliberately nonexistent — `kestrel_oci::hooks::run_one_hook`'s
            // `Command::spawn()` fails immediately with ENOENT, which is
            // exactly the "createRuntime hooks failed" path `create()`
            // handles by dropping `host_end` without ever writing the
            // go-ahead byte.
            .path(PathBuf::from(
                "/nonexistent/kestrel-integration-test-hook-does-not-exist",
            ))
            .build()
            .expect("build bad hook");
        let hooks = HooksBuilder::default()
            .create_runtime(vec![bad_hook])
            .build()
            .expect("build hooks");
        spec.set_hooks(Some(hooks));

        let bundle = Bundle {
            path: bundle_dir.path().to_path_buf(),
            spec: RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        };

        // ---- data_dir: create() uses ONE data_dir for two very different
        // purposes — kestrel_rootfs::snapshot::LayerStore (needs a REAL
        // filesystem: it writes regular files/symlinks) AND
        // kestrel_cgroup::manager::CgroupManager (needs `<data_dir>/cgroups`
        // to actually BE cgroupfs: it writes cgroup.subtree_control /
        // cgroup.procs, and mkdir under cgroupfs creates a real cgroup,
        // not a plain directory). A plain tempdir satisfies the first; to
        // satisfy the second too, mount a second view of the (single,
        // unified) cgroup2 hierarchy at `<data_dir>/cgroups` — same
        // technique as bind-mounting a delegated subtree, just simpler
        // since cgroup2 has exactly one hierarchy so any mount of it
        // reaches the same tree kestrel_cgroup's own
        // `tests/integration.rs` already exercises directly against
        // `/sys/fs/cgroup`. ----
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
        let _mount_guard = MountGuard(cgroups_mount.clone());

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let id = format!("hookfail-{}", nix::unistd::getpid().as_raw());

        // Guard the (about-to-be-created) leaf cgroup so it's always
        // cleaned up, however this test exits.
        let cgroup_guard = CgroupGuard(
            kestrel_cgroup::manager::CgroupManager::new(data_dir.path().join("cgroups"), &id)
                .expect("valid cgroup id"),
        );

        // ---- baseline: our own children before create() ever forks anything ----
        let own_pid = nix::unistd::getpid().as_raw();
        let baseline = own_children_snapshot(own_pid);

        // ---- the real call under test ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(
            result.is_err(),
            "create() should fail: its createRuntime hook points at a nonexistent binary"
        );
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("createRuntime hooks failed"),
            "expected the createRuntime-hook-failure error, got: {err_msg}"
        );

        // ---- find the forked child_action process (see module doc comment
        // for why it's already reparented to us by this point) ----
        let child_pid = wait_for_new_child(own_pid, &baseline, Duration::from_secs(2)).expect(
            "run_stages' forked child (stage2 / child_action, PID 1 of the container's new \
             namespaces) never showed up as our child within 2s — either run_stages itself \
             failed in an unexpected way, or the subreaper-reparenting this test relies on \
             to observe the pid did not happen as expected",
        );

        // ---- THE ASSERTION THIS TEST EXISTS FOR: it must exit promptly on
        // its own, not hang forever blocked in recv_go_ahead's read(). ----
        let exit_code = wait_for_exit(child_pid, Duration::from_secs(5));

        // If it's still alive, the cgroup is still occupied and the
        // secondary cgroup2 mount will refuse to unmount (EBUSY) — kill
        // and reap it FIRST, before the guards below run, so cleanup
        // always succeeds regardless of whether this test is about to
        // pass or fail. (This only ever matters on the buggy/reverted
        // code path — with the real fix in place, `exit_code` is always
        // `Some` here.)
        if exit_code.is_none() {
            let target = nix::unistd::Pid::from_raw(child_pid);
            let _ = nix::sys::signal::kill(target, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(target, None);
        }

        drop(cgroup_guard);
        drop(_mount_guard);

        match exit_code {
            Some(code) => {
                // child_action's abort branch (`_ => std::process::exit(1)`,
                // reached because recv_go_ahead observed EOF, i.e. `Ok(false)`)
                // is the only way this process should ever exit here.
                assert_eq!(
                    code, 1,
                    "child_action exited, but not via its expected abort path (exit code 1) — \
                     got {code} instead"
                );
            }
            None => {
                panic!(
                    "BUG REPRODUCED: child_action (pid {child_pid}) did not exit within 5s of \
                     create() aborting after a failed createRuntime hook — it is hung, blocked \
                     in recv_go_ahead's read(), exactly the leaked-forked-process bug this test \
                     guards against (it has now been forcibly SIGKILLed so this test run doesn't \
                     itself leak it)"
                );
            }
        }
    });
}
