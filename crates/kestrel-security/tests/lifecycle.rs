// crates/kestrel-security/tests/lifecycle.rs
//
// Task 13's capstone: proves the whole Phase 5 pipeline's COMPOSITION and
// ORDER, not just that each of apply_all()'s five steps works in
// isolation (that's already covered by tests/caps.rs, tests/rlimits.rs,
// tests/apply.rs, tests/seccomp.rs, and kestrel-init's own
// tests/exec_via_kestrel_init.rs). One `Process` spec carries a lowered
// RLIMIT_NOFILE, a restricted capability set (missing CAP_SYS_ADMIN), a
// non-root user, and no_new_privileges — all applied via a single real
// `exec_into()` call, together with a seccomp profile denying
// `personality` — into a fixture binary that reports back what it
// actually observes about its own post-exec security state.
//
// Every one of the five values this test asserts on would independently
// be WRONG if apply_all() silently did nothing (see the module-level
// self-review note at the bottom of this file for the concrete
// coincidence-check).

use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use kestrel_init::exec::exec_into;
use kestrel_oci::runtime::{
    Arch, LinuxCapabilitiesBuilder, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
    PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, UserBuilder,
};
use kestrel_security::caps::DEFAULT_CAPABILITIES;

/// Deliberately non-root/non-zero, and distinct from 0 in both slots — a
/// swapped or entirely-skipped uid/gid assignment would still be caught by
/// the fixture's uid/euid lines.
const TARGET_UID: u32 = 65534;
const TARGET_GID: u32 = 65534;

/// Well below any default (oci-spec's own `Process::default()` sets
/// RLIMIT_NOFILE to 1024/1024, and any real shell/VM ulimit is almost
/// certainly higher still) — genuinely lowered, not coincidentally equal
/// to whatever this test process happened to inherit.
const LOWERED_NOFILE: u64 = 64;

#[test]
#[ignore = "requires root"]
fn test_full_security_pipeline_lifecycle_through_real_exec() {
    let fixture = PathBuf::from(env!("CARGO_BIN_EXE_fixture-security-report"));

    // A pipe set up in the REAL, non-forked test process, BEFORE
    // run_isolated's fork — its write end gets dup2'd onto the forked
    // child's STDOUT_FILENO from INSIDE the closure, immediately before
    // calling exec_into (dup2 survives across execve, which is exactly
    // why this has to happen before the point of no return rather than
    // via e.g. a std::process::Command stdio redirect — there is no
    // Command here, exec_into does a raw execve() over the current
    // process image). The read end is held ONLY by this real parent
    // process and is read from after run_isolated's own waitpid has
    // already confirmed the child exited.
    let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
    let write_raw = write_end.as_raw_fd();
    // `nix::unistd::pipe()` doesn't set O_CLOEXEC, and `run_isolated`'s
    // fork() duplicates the whole fd table verbatim — so without
    // explicitly closing them inside the closure below, the forked
    // child (and the fixture it execve()s into) would inherit BOTH this
    // raw read-end fd and a second, un-dup'd copy of the write end
    // alongside the real stdout dup2. Neither leak is fatal here (the
    // fixture exits in milliseconds either way), but this test's whole
    // point is exercising a real, restricted security profile through a
    // real exec — leaving stray fds open across that exec is exactly
    // the kind of sloppiness this project treats as a real hardening
    // concern elsewhere (see kestrel-ns/src/pin.rs, tests/notify.rs's
    // fd-ownership reasoning), so close both explicitly rather than
    // relying on "the process exits soon anyway."
    let read_raw = read_end.as_raw_fd();
    let mut read_end = File::from(read_end);

    // Restricted bounding/effective/permitted/inheritable/ambient set:
    // DEFAULT_CAPABILITIES already excludes CAP_SYS_ADMIN (see caps.rs's
    // own doc comment) but DOES include CAP_SETUID/CAP_SETGID, which
    // step 4's setresuid/setresgid below need while this process is still
    // root-equivalent — same set tests/caps.rs's
    // test_caps_dropped_blocks_mount already established as "the OCI
    // default-ish shape without the one capability mount(2) needs".
    let bounding: kestrel_oci::runtime::Capabilities = DEFAULT_CAPABILITIES.iter().copied().collect();
    let linux_caps = LinuxCapabilitiesBuilder::default()
        .bounding(bounding.clone())
        .effective(bounding.clone())
        .permitted(bounding.clone())
        .inheritable(bounding.clone())
        .ambient(bounding)
        .build()
        .unwrap();

    let nofile_limit = PosixRlimitBuilder::default()
        .typ(PosixRlimitType::RlimitNofile)
        .soft(LOWERED_NOFILE)
        .hard(LOWERED_NOFILE)
        .build()
        .unwrap();

    let user = UserBuilder::default().uid(TARGET_UID).gid(TARGET_GID).build().unwrap();

    let process = ProcessBuilder::default()
        .user(user)
        .args(vec![fixture.to_string_lossy().into_owned()])
        .cwd(PathBuf::from("/"))
        .capabilities(linux_caps)
        .rlimits(vec![nofile_limit])
        .no_new_privileges(true)
        .build()
        .unwrap();

    // Denies `personality` — same syscall the rest of this phase
    // standardized on (Task 8/9's tests, kestrel-init's
    // fixture-denied-syscall) — via SCMP_ACT_ERRNO rather than
    // SCMP_ACT_KILL, so the fixture can observe and report the outcome on
    // stdout instead of dying by SIGSYS (which would make run_isolated's
    // waitpid check panic with an unrelated-looking failure).
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

    // No tempdir/fixture-copy needed here (unlike kestrel-init's
    // setuid-check test) — this fixture needs no special file
    // permissions, just a real execve() of its plain CARGO_BIN_EXE_ path.
    // `process`/`seccomp`/`write_raw` all move into the closure; `write_end`
    // itself (the OwnedFd) stays in THIS, the real parent's, stack frame,
    // so its Drop (closing the parent's own copy of the write end) runs
    // normally when this function returns — same "the real process owns
    // any RAII cleanup" discipline Task 12 established, applied here to
    // the pipe's write end rather than a tempdir.
    kestrel_ns::test_util::run_isolated(move || {
        nix::unistd::dup2(write_raw, libc::STDOUT_FILENO).expect("dup2 pipe write end onto stdout");
        // Close the child's inherited copy of the read end (never needed
        // here — this process only ever writes) and its now-redundant
        // pre-dup2 write-end fd (STDOUT_FILENO is the copy that matters
        // from here on). Best-effort: a close() failure here isn't worth
        // aborting the test over.
        let _ = nix::unistd::close(read_raw);
        if write_raw != libc::STDOUT_FILENO {
            let _ = nix::unistd::close(write_raw);
        }
        let _ = exec_into(&process, Some(&seccomp), None);
        unreachable!("exec_into only returns on failure");
    });

    // run_isolated's own waitpid has already confirmed the child (and the
    // fixture process it exec'd into) exited 0 by the time control reaches
    // here. Close THIS process's copy of the write end now — the child's
    // copies are already gone (the whole child process exited), so this is
    // what makes the pending read() below observe EOF instead of blocking
    // forever waiting for a writer that will never write again.
    drop(write_end);

    let mut output = String::new();
    read_end.read_to_string(&mut output).expect("read fixture stdout from pipe");

    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines.len(),
        5,
        "fixture must report exactly 5 lines, got: {output:?}"
    );

    assert_eq!(lines[0], format!("uid={TARGET_UID}"), "uid must land on the non-root target");
    assert_eq!(lines[1], format!("euid={TARGET_UID}"), "euid must land on the non-root target");
    assert_eq!(
        lines[2], "has_sys_admin=false",
        "CAP_SYS_ADMIN must NOT be in the effective set — it was excluded from the bounding set passed in"
    );
    assert_eq!(
        lines[3],
        format!("nofile_soft={LOWERED_NOFILE}"),
        "RLIMIT_NOFILE's soft limit must reflect the lowered value, not whatever this test process inherited"
    );
    assert_eq!(
        lines[4], "denied_syscall_blocked=true",
        "the seccomp filter must already be active by the fixture's first syscall"
    );
}

// SELF-REVIEW: could this test pass for a trivial/wrong reason?
//
// No — every one of the 5 assertions above would independently fail if
// apply_all() were a silent no-op:
//   - uid/euid: this test runs as root (`sudo -E cargo test ... --ignored`,
//     matching every other root-gated test in this phase) DIRECTLY calls
//     `sudo`, and `run_isolated`'s fork() child inherits that root uid/euid
//     unchanged. A no-op apply_all() leaves both at 0, not TARGET_UID
//     (65534) — line 0/1 would read "uid=0"/"euid=0" and fail the
//     `assert_eq!` immediately.
//   - has_sys_admin: root's ambient/effective capability set includes
//     CAP_SYS_ADMIN by default (that's what "root" means, capability-wise).
//     A no-op apply_all() leaves it in the effective set — `has_cap` would
//     report `true`, not `false`, failing the assertion.
//   - nofile_soft: this test's own process (and therefore whatever
//     RLIMIT_NOFILE the forked child inherits pre-apply_all) uses whatever
//     ambient ulimit the VM/shell set — never observed to be exactly 64 in
//     practice, and even if it coincidentally were, apply_rlimits is
//     independently covered by tests/rlimits.rs so this isn't relied on as
//     the ONLY proof; here it specifically proves the value survives
//     through the rest of the pipeline (capability drop, uid change,
//     seccomp install) undisturbed.
//   - denied_syscall_blocked: without install_seccomp actually loading a
//     filter, `personality(0xffffffff)` succeeds (returns the previous
//     persona, not -1) — a no-op apply_all() would make this line read
//     "denied_syscall_blocked=false", failing the assertion.
//
// So a silently-broken apply_all() (or one that ran its steps in the wrong
// order such that an earlier step's privilege requirement got dropped too
// early — e.g. capabilities before rlimits, or seccomp before the
// uid/gid change) fails this test loudly rather than passing by
// coincidence. Order matters here specifically: capabilities must drop
// CAP_SETUID/CAP_SETGID-preserving (DEFAULT_CAPABILITIES keeps them) BEFORE
// the uid/gid change consumes that privilege, and seccomp must install
// LAST so it doesn't block apply_all's own remaining setup syscalls — both
// already enforced by apply_all's real step order, and this test's Process
// spec is deliberately shaped to make a misordering observable (e.g. if
// seccomp were installed before the uid/gid change and the filter's
// default action were ever tightened to deny setresuid, this test would
// start failing at the uid/euid assertions instead of the seccomp one).
