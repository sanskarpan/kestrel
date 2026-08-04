// crates/kestrel-init/tests/fixtures/denied_syscall.rs

//! Test fixture, not part of the real kestrel-init binary. Calls a
//! syscall the accompanying test's seccomp profile denies via
//! SCMP_ACT_ERRNO (chosen over SCMP_ACT_KILL specifically so this fixture
//! can observe and report the outcome via its own exit code, rather than
//! dying by SIGSYS — which `kestrel_ns::test_util::run_isolated`'s parent-
//! side waitpid check would otherwise interpret as an unrelated test
//! failure rather than "the syscall was correctly blocked"). Exits 0 if
//! the syscall fails with the configured errno (correctly blocked before
//! this fixture's own code could do anything else), exits 1 if it
//! unexpectedly succeeds.
fn main() {
    // Use the SAME syscall Task 8/9 settled on (e.g. `personality`) for
    // consistency across the whole seccomp test suite.
    let ret = unsafe { libc::personality(0xffffffff) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    std::process::exit(if ret == -1 && errno == Some(libc::EPERM) { 0 } else { 1 });
}
