// crates/kestrel-security/tests/seccomp.rs
//
// Root-gated: install_seccomp() calls seccomp_load(2) via libseccomp, which
// (without NO_NEW_PRIVS already set on the calling thread) requires
// CAP_SYS_ADMIN — hence `run_isolated` (fork) so each test's filter is
// installed on a throwaway child process, never contaminating the test
// runner itself, and `#[ignore = "requires root"]` gating both.

use std::os::fd::AsRawFd;

use kestrel_oci::runtime::{Arch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};
use kestrel_security::seccomp::install_seccomp;

fn deny_personality_profile() -> kestrel_oci::runtime::LinuxSeccomp {
    let rule = LinuxSyscallBuilder::default()
        .names(vec!["personality".to_string()])
        .action(LinuxSeccompAction::ScmpActErrno)
        .errno_ret(libc::EPERM as u32)
        .build()
        .unwrap();
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
        .syscalls(vec![rule])
        .build()
        .unwrap()
}

#[test]
#[ignore = "requires root"]
fn test_seccomp_blocks_syscall_with_configured_errno() {
    kestrel_ns::test_util::run_isolated(|| {
        install_seccomp(&deny_personality_profile()).expect("install_seccomp");
        let ret = unsafe { libc::personality(0xffffffff) };
        assert_eq!(ret, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    });
}

#[test]
#[ignore = "requires root"]
fn test_install_seccomp_unknown_syscall_name_is_skipped_not_fatal() {
    kestrel_ns::test_util::run_isolated(|| {
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["this_syscall_does_not_exist_kestrel_test".to_string(), "personality".to_string()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EPERM as u32)
            .build()
            .unwrap();
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();
        install_seccomp(&profile).expect("must not fail on an unknown syscall name mixed in with a real one");
        // The real name in the same rule must still have been applied.
        let ret = unsafe { libc::personality(0xffffffff) };
        assert_eq!(ret, -1);
    });
}

/// Covers `install_seccomp`'s `Some(OwnedFd)` branch — the only `unsafe`
/// block in seccomp.rs (`OwnedFd::from_raw_fd` on the raw fd libseccomp
/// hands back from `get_notify_fd`). The other two tests above only ever
/// exercise `ScmpActErrno`, so without this test that branch would ship
/// with zero coverage from this task (it's slated to get exercised
/// end-to-end by Task 9's notify-loop test too, but this project doesn't
/// ship untested `unsafe` code even briefly). Reuses the `personality`
/// syscall choice from the other tests here for consistency, but doesn't
/// need to actually trigger the notification — just prove the fd comes
/// back live.
#[test]
#[ignore = "requires root"]
fn test_install_seccomp_returns_live_notify_fd_when_profile_uses_notify() {
    kestrel_ns::test_util::run_isolated(|| {
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["personality".to_string()])
            .action(LinuxSeccompAction::ScmpActNotify)
            .build()
            .unwrap();
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();
        let fd = install_seccomp(&profile).expect("install_seccomp").expect("profile uses SCMP_ACT_NOTIFY, so install_seccomp must return Some(fd)");
        // Confirm the fd is genuinely live (not e.g. a stale/closed
        // descriptor number reused by coincidence): F_GETFD only succeeds
        // on an open fd.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1, "notify fd must be a live, open file descriptor");
        // fd drops here, exercising OwnedFd's close-on-drop.
    });
}
