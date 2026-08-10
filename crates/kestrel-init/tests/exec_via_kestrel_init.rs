// crates/kestrel-init/tests/exec_via_kestrel_init.rs

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use kestrel_init::exec::exec_into;
use kestrel_oci::runtime::{
    Arch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, ProcessBuilder,
    UserBuilder,
};

// No generic `fixture_path(name)` helper — `CARGO_BIN_EXE_<name>` must be a
// literal argument to `env!()`, resolved at compile time; it can't be
// composed from a runtime string. Each test below inlines its own
// `env!("CARGO_BIN_EXE_fixture-...")` call directly instead.

#[test]
#[ignore = "requires root"]
fn test_no_new_privs_blocks_setuid_elevation() {
    let fixture = std::path::PathBuf::from(env!("CARGO_BIN_EXE_fixture-setuid-check"));

    // The `TempDir` (and everything inside it) is created HERE, in the
    // real, un-forked test process — deliberately NOT inside
    // `run_isolated`'s closure. `exec_into`'s success path replaces the
    // forked child's process image entirely (`execve` never returns to
    // unwind through it), so a `TempDir` guard created inside that child
    // would never run its `Drop` — permanently leaking this root-owned,
    // setuid-root binary into `/tmp` on every passing run. Creating it
    // out here means the real parent's normal `TempDir::drop` runs when
    // this function returns, regardless of what happens inside the fork.
    // Same "parent owns the tempdir" pattern already used by
    // kestrel-rootfs's pivot/mask tests and
    // kestrel-security/tests/rlimits.rs. Only the resolved `PathBuf`
    // (`target`, below) moves into the closure.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("setuid-check");

    // Copy the fixture to that scratch location and make it setuid-root —
    // both need real root, which this whole test already runs as.
    // Copying (rather than chmod'ing the CARGO_BIN_EXE_ path in place)
    // matters for TWO reasons: it avoids mutating cargo's own build
    // output, and — the one that actually makes this test valid —
    // `std::fs::copy` preserves permissions but the COPY's owner is
    // whichever user creates it, which is root here since this test
    // itself only runs as root (`#[ignore = "requires root"]`, driven
    // via `sudo -E cargo test ... -- --ignored`). setuid only
    // re-elevates to the FILE OWNER's uid, so this fixture is only a
    // meaningful proof of "no_new_privs blocks setuid elevation" if
    // the copy is actually owned by root (uid 0) at exec time — a
    // setuid bit on a non-root-owned file would prove nothing.
    std::fs::copy(&fixture, &target).expect("copy fixture");
    assert_eq!(
        std::fs::metadata(&target).unwrap().uid(),
        0,
        "fixture copy must be owned by root for the setuid bit to mean anything \
         (this test must run as root via sudo, not just be launched by a root shell \
         whose umask/ownership assumptions could be wrong)"
    );
    let mut perms = std::fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o4755); // setuid + rwxr-xr-x
    std::fs::set_permissions(&target, perms).expect("chmod u+s");

    kestrel_ns::test_util::run_isolated(move || {
        let user = UserBuilder::default().uid(1000u32).gid(1000u32).build().unwrap();
        let mut process = ProcessBuilder::default()
            .user(user)
            .args(vec![target.to_string_lossy().into_owned()])
            .cwd(std::path::PathBuf::from("/"))
            // Explicit here for documentation/clarity, but currently
            // REDUNDANT: `ProcessBuilder::default()` already resolves
            // `no_new_privileges` to `Some(true)` via oci-spec's own
            // `impl Default for Process` (runtime/process.rs). So
            // commenting out just this line does NOT make this test
            // fail — that's not a sign the test is vacuous, it's a sign
            // the probe point is a no-op. Real coverage of apply_all's
            // step (3) was confirmed by fault-injecting at the actual
            // enforcement point instead: temporarily disabling
            // `set_no_new_privs()` inside `apply_all` itself, which DID
            // make this test fail as expected.
            .no_new_privileges(true)
            .build()
            .unwrap();
        // `ProcessBuilder::default().build()` is NOT a blank slate: oci-spec's
        // own hand-written `impl Default for Process` sets
        // `capabilities = Some({NET_BIND_SERVICE, AUDIT_WRITE, KILL})` — a
        // bounding set that does NOT include CAP_SETUID/CAP_SETGID. Left in
        // place, apply_all's step (2) would legitimately drop those
        // capabilities from the bounding set BEFORE step (4) tries
        // `setresuid`/`setresgid` to 1000/1000, making the uid/gid change
        // itself fail with EPERM — a bug in this test's setup, not a
        // meaningful signal about no_new_privs. Same pitfall documented at
        // crates/kestrel-security/tests/apply.rs's `process_for_user` helper;
        // clearing it here keeps this test isolated to what it actually
        // claims to prove.
        process.set_capabilities(None);

        // exec_into replaces THIS (already-forked, disposable) process's
        // image entirely — its exit code IS the test result, observed by
        // run_isolated's own waitpid in the real parent process.
        let _ = exec_into(&process, None, None);
        unreachable!("exec_into only returns on failure");
    });

    // `tmp` drops here, in the real parent process — removing the
    // scratch directory and the setuid-root binary inside it — regardless
    // of what happened inside the forked child above.
}

#[test]
#[ignore = "requires root"]
fn test_seccomp_filter_is_active_before_entrypoints_first_syscall() {
    let fixture = std::path::PathBuf::from(env!("CARGO_BIN_EXE_fixture-denied-syscall"));

    kestrel_ns::test_util::run_isolated(move || {
        // Denies `personality` via SCMP_ACT_ERRNO, matching the fixture's
        // own hardcoded choice — same construction as Task 8's
        // deny_personality_profile(), duplicated here rather than shared
        // across crates since kestrel-init's tests don't otherwise need a
        // dependency on kestrel-security's test-only code.
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["personality".to_string()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EPERM as u32)
            .build()
            .unwrap();
        let seccomp = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();

        let process = ProcessBuilder::default()
            .args(vec![fixture.to_string_lossy().into_owned()])
            .cwd(std::path::PathBuf::from("/"))
            .build()
            .unwrap();

        let _ = exec_into(&process, Some(&seccomp), None);
        unreachable!("exec_into only returns on failure");
    });
}
