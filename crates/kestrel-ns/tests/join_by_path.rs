// crates/kestrel-ns/tests/join_by_path.rs
//
// Root-gated proof of Phase 9 Task 4's `NamespacePlan.join` mechanism:
// `stages::stage1` performs every `plan.join` `setns()` as its absolute
// first action, before any `unshare()` call (including before
// `CLONE_NEWUSER`). This file has two tests:
//
//   1. `test_setns_into_host_owned_ns_succeeds_before_unshare_newuser_fails_after`
//      is a minimal, `run_stages`-independent empirical check of the raw
//      kernel privilege-ordering claim from the implementation plan/design
//      doc §4a: does `setns()` into a namespace owned by the host's
//      original (`init`) user namespace actually succeed before
//      `unshare(CLONE_NEWUSER)` and fail (EPERM) after it? This is checked
//      directly with raw `setns()` calls, independent of any of this
//      crate's own code, so it stands on its own as evidence for the
//      ordering reasoning regardless of whether `stage1`'s own
//      implementation is correct.
//
//   2. `test_run_stages_join_reaches_pinned_namespace_not_hosts_own` is the
//      real, end-to-end proof the plan's Step 4 asks for: a `NamespacePlan`
//      that both creates a fresh User namespace (so `stage1`'s
//      `has_user_ns()` / `unshare(CLONE_NEWUSER)` block is genuinely
//      exercised) AND joins a pre-existing UTS namespace pinned by a
//      separate, already-running helper process — proving the resulting
//      `init_pid` ends up in the pinned namespace, not the host's own.
//      If `stage1` performed the join in the wrong order (after
//      `CLONE_NEWUSER`), this test would fail outright (`run_stages`
//      itself would return `Err` from the `setns` `EPERM`), so a passing
//      run here is itself further empirical confirmation of test 1's
//      claim, from inside the real code path this task modifies.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use kestrel_ns::pin::pin_namespace;
use kestrel_ns::stages::run_stages;
use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};
use nix::sched::CloneFlags;

fn ns_inode(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .ino()
}

/// Empirical check of the raw kernel semantics the ordering fix depends on
/// (see module doc comment, test 1). Uses two independent forked
/// (`run_isolated`) processes so each starts from the same, unmodified
/// starting privileges instead of one contaminating the other.
#[test]
#[ignore = "requires root"]
fn test_setns_into_host_owned_ns_succeeds_before_unshare_newuser_fails_after() {
    // Case 1: setns while still holding the caller's ORIGINAL privileges
    // (before any unshare(CLONE_NEWUSER)) must succeed. The target here is
    // the process's own current UTS namespace, opened by path — a
    // namespace owned by the host's real `init_user_ns` for a process
    // launched directly under `sudo`/root, with no ancestor user namespace
    // of its own. setns-ing "into" the namespace you're already in is a
    // trivial no-op operation-wise, but it exercises the exact same
    // permission check (`ns_capable` against the target's owning user
    // namespace) as setns-ing into any other namespace owned by that same
    // user namespace (e.g. a netns pinned by a separate host-level
    // process) — the kernel's decision is about capabilities relative to
    // the OWNING userns, not about "is this fd the same namespace as
    // current".
    run_isolated(|| {
        let target = std::fs::File::open("/proc/self/ns/uts")
            .expect("open own uts ns before any unshare");
        let result = nix::sched::setns(&target, CloneFlags::CLONE_NEWUTS);
        assert!(
            result.is_ok(),
            "setns into a host-owned namespace should succeed while the caller \
             still holds its original (pre-unshare) privileges, got: {result:?}"
        );
    });

    // Case 2: unshare(CLONE_NEWUSER) FIRST, then attempt the identical
    // setns into the SAME host-owned namespace fd. Per user_namespaces(7)
    // / cap_capable()'s ancestor-walk: after unshare(CLONE_NEWUSER), the
    // calling process's cred->user_ns is the new, deeper-level namespace;
    // the target's owning userns (`init_user_ns`) is now an ANCESTOR of
    // that (lower level, not equal, not a descendant), so the capability
    // check fails immediately (EPERM) even though the process is real
    // root and was fully privileged in the host namespace a moment ago.
    run_isolated(|| {
        let target = std::fs::File::open("/proc/self/ns/uts")
            .expect("open own uts ns before any unshare");
        nix::sched::unshare(CloneFlags::CLONE_NEWUSER).expect("unshare(CLONE_NEWUSER)");
        let result = nix::sched::setns(&target, CloneFlags::CLONE_NEWUTS);
        assert!(
            result.is_err(),
            "setns into a host-owned namespace should FAIL once the caller has \
             already unshared into a new user namespace, got: {result:?}"
        );
        assert_eq!(
            result.unwrap_err(),
            nix::errno::Errno::EPERM,
            "expected EPERM specifically"
        );
    });
}

/// The real proof Task 4's Step 4 asks for: `run_stages` with a plan that
/// both creates a fresh User namespace (genuinely exercising `stage1`'s
/// `unshare(CLONE_NEWUSER)` path) and joins a pre-existing UTS namespace
/// pinned by a separate, already-running helper — confirm the resulting
/// `init_pid` really is inside the pinned namespace (by inode), not the
/// host's own, and not some other freshly-created one.
#[test]
#[ignore = "requires root"]
fn test_run_stages_join_reaches_pinned_namespace_not_hosts_own() {
    run_isolated(|| {
        // ---- Helper: a plain host-level process (NO new user namespace,
        // matching how kestrel-net's create_netns pins a netns today —
        // "created by a plain host-level helper process, not inside any
        // container's fresh user namespace", design doc §4a) that unshares
        // a fresh UTS namespace and sets a distinguishable hostname, then
        // parks so we can pin and later join it.
        let helper_plan = NamespacePlan {
            create: vec![NsType::Uts],
            join: vec![],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        let helper = run_stages(&helper_plan, None, || {
            nix::unistd::sethostname("kestrel-join-target").expect("sethostname");
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        })
        .expect("run_stages (helper)");

        let dir = std::env::temp_dir().join(format!("kestrel-join-by-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pin_target = dir.join("uts");
        pin_namespace(helper.init_pid, NsType::Uts, &pin_target).expect("pin_namespace");

        // Record the host test process's own UTS namespace inode BEFORE
        // calling run_stages below, as the "not the host's own" baseline —
        // run_stages/stage1 runs in forked children, so this process's own
        // namespace is unaffected by any of this, but let's be explicit
        // about what we're proving against.
        let host_uts_inode = ns_inode(std::path::Path::new("/proc/self/ns/uts"));
        let pinned_uts_inode = ns_inode(&pin_target);
        assert_ne!(
            host_uts_inode, pinned_uts_inode,
            "sanity check: the helper's freshly-unshared UTS namespace must \
             differ from the host test process's own"
        );

        // ---- Container-like plan under test: creates a fresh User (+
        // Mount) namespace as normal, AND joins the helper's pinned UTS
        // namespace. `has_user_ns()` is true here, so stage1's
        // unshare(CLONE_NEWUSER) block genuinely runs — if the join
        // happened AFTER that block instead of before, this setns would
        // fail with EPERM and `run_stages` below would return `Err`,
        // failing this test outright.
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Mount],
            join: vec![(NsType::Uts, pin_target.clone())],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };

        let result = run_stages(&plan, None, || {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        })
        .expect(
            "run_stages must succeed: the join must happen before \
             unshare(CLONE_NEWUSER), not after",
        );

        let init_ns_path = PathBuf::from(format!("/proc/{}/ns/uts", result.init_pid));
        let init_uts_inode = ns_inode(&init_ns_path);

        assert_eq!(
            init_uts_inode, pinned_uts_inode,
            "init_pid's UTS namespace must match the pre-existing PINNED one \
             (joined via plan.join), not a freshly-unshared or host-inherited one"
        );
        assert_ne!(
            init_uts_inode, host_uts_inode,
            "init_pid's UTS namespace must NOT be the host test process's own \
             (which is what a silently-dropped join, i.e. the pre-Task-4 bug, \
             would produce)"
        );

        // Cleanup.
        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).ok();
        nix::sys::wait::waitpid(result.init_pid, None).ok();
        nix::sys::signal::kill(helper.init_pid, nix::sys::signal::Signal::SIGKILL).ok();
        nix::sys::wait::waitpid(helper.init_pid, None).ok();
        kestrel_ns::pin::unpin_namespace(&pin_target).ok();
        std::fs::remove_dir_all(&dir).ok();
    });
}
