use std::collections::BTreeMap;
use std::time::Duration;

use kestrel_ns::join::join_namespaces;
use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::stages::run_stages;
use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};
use nix::sched::CloneFlags;

// NsType::Mount is deliberately excluded from this test's namespace set.
// This Lima VM (Ubuntu 24.04, kernel 6.8.0-136-generic, aarch64/vz) cannot
// bind-mount ANY mount namespace via nsfs (EINVAL on mount(2) MS_BIND),
// verified independently against multiple distinct mount namespaces via
// raw syscalls — a real environment limitation, not a bug in this crate's
// code. join_namespaces() itself still handles NsType::Mount correctly in
// its ORDER array; only this test's namespace-pinning setup is affected.
fn pin_all(
    init_pid: nix::unistd::Pid,
    dir: &std::path::Path,
) -> BTreeMap<NsType, std::path::PathBuf> {
    let mut pins = BTreeMap::new();
    for ns in [NsType::User, NsType::Uts] {
        let target = dir.join(ns.proc_name());
        pin_namespace(init_pid, ns, &target).expect("pin");
        pins.insert(ns, target);
    }
    pins
}

/// Reverses [`pin_all`]: unmounts and removes every pin's backing file.
/// Must run before the pins' parent directory is removed — `unpin_namespace`
/// unmounts the nsfs bind mount before deleting the file it's mounted on;
/// skipping straight to `remove_dir_all` unlinks the file but leaves the
/// bind mount active, leaking it.
fn unpin_all(pins: &BTreeMap<NsType, std::path::PathBuf>) {
    for target in pins.values() {
        unpin_namespace(target).expect("unpin_namespace");
    }
}

// This test documents the runc-#4390 ordering bug (joining a user
// namespace before the others makes the subsequent joins fail), but it
// cannot actually reproduce that failure in this suite: `pin_namespace`
// requires real CAP_SYS_ADMIN, so the whole test binary — including the
// `unshare(CLONE_NEWUSER)` inside `run_stages` that creates the pinned
// user namespace — runs under `sudo` as real root (uid 0). Per
// `user_namespaces(7)`'s ownership rule, a process whose effective UID
// matches the owner of a user namespace has all capabilities in it; since
// root both creates and later `setns()`-joins this namespace, it retains
// full capabilities the whole way through (confirmed empirically via
// `/proc/self/status`'s CapEff, which stays the full set after the
// `setns(CLONE_NEWUSER)` join). The real bug only manifests for a
// genuinely unprivileged real uid that gains capabilities solely by being
// mapped to container-uid 0 inside the namespace — reproducing that here
// would mean creating the namespace as a non-root real uid while still
// using root only for the `pin_namespace` step, which is a real
// restructuring of this test's privilege model, not a small fix. Left
// `#[ignore]`d rather than deleted so the intent stays documented for
// whoever revisits this.
#[test]
#[ignore = "cannot reproduce under root — see the comment above this test"]
fn test_join_order_matters() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts],
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
        let result = run_stages(&plan, None, || loop {
            std::thread::sleep(Duration::from_secs(3600));
        })
        .expect("run_stages");

        let dir = std::env::temp_dir().join(format!("kestrel-join-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pins = pin_all(result.init_pid, &dir);

        // User-namespace-first: join user, then try uts — joining CLONE_NEWUTS
        // requires CAP_SYS_ADMIN, a capability the userns join has just
        // dropped — expect failure.
        let user_first_fails = {
            let f = std::fs::File::open(&pins[&NsType::User]).unwrap();
            let user_join_ok = nix::sched::setns(&f, CloneFlags::CLONE_NEWUSER).is_ok();
            let uts_join_ok = std::fs::File::open(&pins[&NsType::Uts])
                .ok()
                .map(|f| nix::sched::setns(&f, CloneFlags::CLONE_NEWUTS).is_ok())
                .unwrap_or(false);
            user_join_ok && !uts_join_ok
        };
        assert!(
            user_first_fails,
            "joining user-namespace first should break the subsequent join"
        );

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).ok();
        unpin_all(&pins);
        std::fs::remove_dir_all(&dir).ok();
    });
}

#[test]
#[ignore = "requires root"]
fn test_join_namespaces_canonical_order_succeeds() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts],
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
        let result = run_stages(&plan, None, || loop {
            std::thread::sleep(Duration::from_secs(3600));
        })
        .expect("run_stages");

        let dir = std::env::temp_dir().join(format!("kestrel-join-test-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pins = pin_all(result.init_pid, &dir);

        // A second isolated fork so this join attempt doesn't corrupt the
        // caller's own namespaces for the rest of the test process.
        run_isolated(|| {
            join_namespaces(&pins).expect("canonical-order join must succeed");
        });

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).ok();
        unpin_all(&pins);
        std::fs::remove_dir_all(&dir).ok();
    });
}
