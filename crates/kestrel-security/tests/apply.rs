// crates/kestrel-security/tests/apply.rs
//
// Root-gated: covers apply_all()'s step 4 (user/group), which is the one
// step of the pipeline written as raw inline logic rather than delegating
// to an already-independently-tested primitive (steps 1/2/3/5 each have
// their own dedicated tests in rlimits.rs/caps.rs/notify.rs/seccomp.rs).
// Task 13's lifecycle test proves the full 5-step composition runs
// end-to-end on one happy path; these tests specifically exercise step 4's
// own branches (nonempty additional_gids, and the empty/unset guard that
// exists to avoid ever calling the real setgroups(&[])).

use kestrel_oci::runtime::{Process, ProcessBuilder, UserBuilder};
use kestrel_security::apply::apply_all;
use nix::unistd::{getgroups, getresgid, getresuid, Gid};

/// Builds a minimal `Process` whose only interesting field is `user`, with
/// steps 1-3 of `apply_all` forced to true no-ops so this test is only
/// about step 4.
///
/// `ProcessBuilder::default().build()` is NOT a blank slate: oci-spec's own
/// hand-written `impl Default for Process` backs every unset field, which
/// notably includes `capabilities = Some({NET_BIND_SERVICE, AUDIT_WRITE,
/// KILL})` (a bounding set that does NOT include CAP_SETGID/CAP_SETUID) and
/// `no_new_privileges = Some(true)`. Left alone, apply_all's step 2 would
/// legitimately (and correctly) drop CAP_SETGID/CAP_SETUID from the
/// bounding set before step 4 ever runs, making setresgid/setresuid fail
/// with EPERM regardless of step 4's own logic — discovered empirically by
/// a first version of this test that didn't clear these fields and failed
/// for that reason, not a bug in apply_all. Explicitly resetting
/// capabilities/rlimits/no_new_privileges via the getset `set_*` mutators
/// (not the builder's `strip_option` setters, which can't express "set to
/// None") keeps this test isolated to step 4.
fn process_for_user(uid: u32, gid: u32, additional_gids: Option<Vec<u32>>) -> Process {
    // UserBuilder uses derive_builder's "owned" pattern: each setter
    // consumes and returns `Self`, so building up conditionally requires
    // reassigning the binding rather than mutating in place.
    let mut user_builder = UserBuilder::default().uid(uid).gid(gid);
    if let Some(gids) = additional_gids {
        user_builder = user_builder.additional_gids(gids);
    }
    let user = user_builder.build().unwrap();

    let mut process = ProcessBuilder::default().args(vec!["true".to_string()]).cwd("/").user(user).build().unwrap();
    process.set_capabilities(None);
    process.set_rlimits(None);
    process.set_no_new_privileges(None);
    process
}

#[test]
#[ignore = "requires root"]
fn test_apply_all_sets_uid_gid_and_supplementary_groups() {
    kestrel_ns::test_util::run_isolated(|| {
        // Deliberately non-root/non-zero targets, distinct from each other,
        // so a swapped uid/gid assignment would be caught.
        let target_uid = 65534;
        let target_gid = 65533;
        let extra_gid = 100;

        let process = process_for_user(target_uid, target_gid, Some(vec![extra_gid]));
        apply_all(&process, None).expect("apply_all");

        let resuid = getresuid().expect("getresuid");
        assert_eq!(resuid.real.as_raw(), target_uid, "real uid must land on the target");
        assert_eq!(resuid.effective.as_raw(), target_uid, "effective uid must land on the target");
        assert_eq!(resuid.saved.as_raw(), target_uid, "saved uid must land on the target");

        let resgid = getresgid().expect("getresgid");
        assert_eq!(resgid.real.as_raw(), target_gid, "real gid must land on the target");
        assert_eq!(resgid.effective.as_raw(), target_gid, "effective gid must land on the target");
        assert_eq!(resgid.saved.as_raw(), target_gid, "saved gid must land on the target");

        let groups = getgroups().expect("getgroups");
        assert_eq!(groups, vec![Gid::from_raw(extra_gid)], "supplementary groups must equal exactly what was requested");
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_all_empty_additional_gids_is_a_setgroups_no_op() {
    // Proves the `if !additional.is_empty()` guard in apply_all's step 4
    // actually works: an empty (or unset) additional_gids must NOT call the
    // real setgroups(&[]), which would destructively clear whatever
    // supplementary groups the process already had. Exercises both the
    // unset (None) and explicit-empty (Some(vec![])) shapes, since
    // `.as_deref().filter(...)` treats them identically.
    kestrel_ns::test_util::run_isolated(|| {
        let before = getgroups().expect("getgroups before");

        let process = process_for_user(65534, 65534, None);
        apply_all(&process, None).expect("apply_all with unset additional_gids");

        let after_unset = getgroups().expect("getgroups after unset additional_gids");
        assert_eq!(after_unset, before, "unset additional_gids must leave supplementary groups untouched");
    });

    kestrel_ns::test_util::run_isolated(|| {
        let before = getgroups().expect("getgroups before");

        let process = process_for_user(65534, 65534, Some(vec![]));
        apply_all(&process, None).expect("apply_all with empty additional_gids");

        let after_empty = getgroups().expect("getgroups after empty additional_gids");
        assert_eq!(after_empty, before, "explicitly-empty additional_gids must leave supplementary groups untouched");
    });
}
