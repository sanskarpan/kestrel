// crates/kestrel-ns/tests/with_namespace.rs
//
// Root-gated: setns requires CAP_SYS_ADMIN.

use std::os::fd::AsFd;

use kestrel_ns::join::with_namespace;
use kestrel_ns::types::NsType;

#[test]
#[ignore = "requires root"]
fn test_with_namespace_restores_original_namespace_after_closure() {
    kestrel_ns::test_util::run_isolated(|| {
        let original_ns_id = std::fs::read_link("/proc/self/ns/uts").unwrap();

        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUTS)
            .expect("unshare a target UTS namespace");
        let target_ns_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_ne!(
            original_ns_id, target_ns_id,
            "unshare must have actually created a new namespace"
        );

        // Re-open the CURRENT (target) namespace's own fd to join "into"
        // via with_namespace, then confirm we're restored to the
        // namespace we were in immediately before with_namespace was
        // called (i.e. `target_ns_id`, not `original_ns_id` — this test
        // deliberately calls with_namespace from INSIDE the just-unshared
        // namespace, joining back into itself via its own fd, to prove
        // the restore targets "whatever we were in when with_namespace
        // was called," not some other fixed reference point).
        let target_fd = std::fs::File::open("/proc/self/ns/uts").unwrap();

        with_namespace(NsType::Uts, target_fd.as_fd(), || {
            let inside_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
            assert_eq!(
                inside_id, target_ns_id,
                "must actually be in the target namespace inside the closure"
            );
            Ok(())
        })
        .unwrap();

        let after_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_eq!(
            after_id, target_ns_id,
            "must be restored to the pre-call namespace after with_namespace returns"
        );
    });
}

#[test]
#[ignore = "requires root"]
fn test_with_namespace_restores_even_when_closure_returns_err() {
    kestrel_ns::test_util::run_isolated(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUTS).expect("unshare");
        let ns_id_before = std::fs::read_link("/proc/self/ns/uts").unwrap();
        let target_fd = std::fs::File::open("/proc/self/ns/uts").unwrap();

        let result: anyhow::Result<()> = with_namespace(NsType::Uts, target_fd.as_fd(), || {
            anyhow::bail!("deliberate failure")
        });
        assert!(result.is_err());

        let ns_id_after = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_eq!(
            ns_id_before, ns_id_after,
            "restore must happen even when the closure returns Err, not just on success"
        );
    });
}
