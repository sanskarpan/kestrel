// crates/kestrel-security/tests/fixtures/security_report.rs
//
// Test fixture, not part of any real kestrel binary. Meant to be
// exec_into()'d with a full security profile applied (Task 13's
// lifecycle test), and reports back — on stdout, one distinct line per
// value — exactly what it observes about its OWN post-apply_all() state:
// uid/euid (step 4, user/group), whether CAP_SYS_ADMIN survived into the
// effective set (step 2, capabilities), the RLIMIT_NOFILE soft limit
// (step 1, rlimits), and whether a syscall the accompanying seccomp
// profile denies (step 5) actually fails with EPERM. Five real, verifiable
// facts about ITS OWN address space and syscall behavior — not five
// separate exec cycles, and not the test process's own state.
fn main() {
    println!("uid={}", nix::unistd::getuid());
    println!("euid={}", nix::unistd::geteuid());
    println!(
        "has_sys_admin={}",
        caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN).unwrap_or(false)
    );
    let (soft, _hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
    println!("nofile_soft={soft}");
    // Same syscall the rest of this phase standardized on (Task 8/9's
    // seccomp tests, kestrel-init's fixture-denied-syscall) — personality()
    // is harmless to call, takes one plain integer argument, and has no
    // legitimate reason to be denied outside a test, which is exactly why
    // it's a safe, unambiguous probe for "is a seccomp filter active".
    let ret = unsafe { libc::personality(0xffffffff) };
    println!(
        "denied_syscall_blocked={}",
        ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    );
}
