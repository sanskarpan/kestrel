// crates/kestrel-security/tests/rlimits.rs

use kestrel_oci::runtime::{PosixRlimitBuilder, PosixRlimitType};
use kestrel_security::rlimits::{apply_rlimits, set_oom_score_adj};

#[test]
fn test_apply_rlimits_none_is_a_no_op() {
    apply_rlimits(None).expect("None must be a clean no-op");
}

#[test]
fn test_apply_rlimits_lowers_nofile_limit() {
    kestrel_ns::test_util::run_isolated(|| {
        let current = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        let lower_soft = current.0.saturating_sub(1);
        assert!(lower_soft < current.0, "test assumes RLIMIT_NOFILE's current soft limit is > 0");
        let limit = PosixRlimitBuilder::default()
            .typ(PosixRlimitType::RlimitNofile)
            .soft(lower_soft)
            .hard(current.1) // hard limit unchanged — no privilege needed
            .build()
            .unwrap();
        apply_rlimits(Some(&[limit])).expect("lowering an rlimit never needs privilege");

        let after = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        assert_eq!(after.0, lower_soft);
    });
}

#[test]
fn test_set_oom_score_adj_rejects_out_of_range() {
    assert!(set_oom_score_adj(1001).is_err());
    assert!(set_oom_score_adj(-1001).is_err());
}

#[test]
fn test_set_oom_score_adj_writes_own_proc_file() {
    kestrel_ns::test_util::run_isolated(|| {
        set_oom_score_adj(500).expect("setting your own oom_score_adj upward from the default needs no privilege");
        let content = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        assert_eq!(content.trim(), "500");
    });
}
