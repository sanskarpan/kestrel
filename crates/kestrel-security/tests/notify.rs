// crates/kestrel-security/tests/notify.rs
//
// Root-gated: install_seccomp() calls seccomp_load(2) via libseccomp, which
// (without NO_NEW_PRIVS already set on the calling thread) requires
// CAP_SYS_ADMIN — hence `run_isolated` (fork) so the filter is installed on
// a throwaway child process, never contaminating the test runner itself,
// and `#[ignore = "requires root"]` gating.
//
// This test additionally forks a *second* time inside `run_isolated`'s
// child: `install_seccomp` affects only the calling process/thread's own
// filter, and fork() inherits an installed filter, so the notify fd
// obtained here stays valid and meaningful for a grandchild that forks
// AFTER installation — exactly what's needed to have a separate process
// whose notified syscall we can wait on and whose pid we can independently
// confirm in the decoded event.

use std::os::fd::{AsFd, AsRawFd};

use kestrel_oci::runtime::{Arch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};
use kestrel_security::notify::{handle_one_notification, run_notify_loop};
use kestrel_security::seccomp::install_seccomp;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, write, ForkResult};

/// Builds the same `ScmpActNotify`-on-`personality` profile both tests in
/// this file use, for consistency with Task 8's `seccomp.rs` tests.
fn notify_personality_profile() -> kestrel_oci::runtime::LinuxSeccomp {
    let rule = LinuxSyscallBuilder::default()
        .names(vec!["personality".to_string()])
        .action(LinuxSeccompAction::ScmpActNotify)
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
fn test_handle_one_notification_captures_pid_syscall_and_args() {
    kestrel_ns::test_util::run_isolated(|| {
        let notify_fd = install_seccomp(&notify_personality_profile()).expect("install_seccomp").expect("profile uses notify, fd must be Some");

        // SAFETY: fork() duplicates the process; the child below only
        // calls the one notified syscall and exits, no other
        // non-async-signal-safe work happens between fork and exit,
        // matching kestrel-ns's own run_isolated convention for what's
        // safe in this window.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                // Blocks until the parent responds below. The exit code
                // encodes whether the syscall actually came back with the
                // ENOSYS response `handle_one_notification` is supposed to
                // send — a bare `waitpid(..) == Exited(_, 0)` on an
                // unconditional `exit(0)` would pass regardless of what
                // `personality()` returned (wrong id, wrong errno, even a
                // spoofed success), so the pass/fail signal has to be
                // derived from the actual return value here, not just from
                // "the process eventually unblocked and ran to completion".
                let ret = unsafe { libc::personality(0xffffffff) };
                let errno = std::io::Error::last_os_error().raw_os_error();
                let ok = ret == -1 && errno == Some(libc::ENOSYS);
                std::process::exit(if ok { 0 } else { 1 });
            }
            ForkResult::Parent { child } => {
                let event = handle_one_notification(notify_fd.as_fd()).expect("handle_one_notification");
                assert_eq!(event.pid, child.as_raw() as u32, "event must report the actual notified process's pid");
                assert_eq!(event.syscall, "personality");

                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(p, 0)) if p == child => {}
                    other => panic!(
                        "notified child did not observe the expected ENOSYS response \
                         (exit code 0 means personality() returned -1/ENOSYS as expected; \
                         exit code 1 means it didn't): {other:?}"
                    ),
                }
            }
        }
    });
}

/// Proves the fix for the availability bug the code-quality review caught:
/// `run_notify_loop` must not treat one stale/failed notify request as "the
/// whole fd is gone" and abandon every other process sharing the same
/// filter. Manufactures exactly that scenario — child1's notify request
/// becomes stale (its process gets SIGKILLed before the loop ever gets to
/// it) — while child2's live, valid request is also pending on the same
/// fd, then asserts child2 still gets serviced (and that child1's failed
/// request was silently skipped, never delivered to `on_event`).
///
/// The test ends by closing the fd from inside `on_event` once child2 has
/// been serviced, to make `run_notify_loop` stop rather than block forever
/// waiting for a third notification that's never coming. Per this module's
/// own diagnostics while building the fix (see `notify.rs`'s correction
/// #7), a closed fd surfaces as the exact same `SeccompErrno::ECANCELED`
/// as a live target dying mid-flight, so `run_notify_loop` retries it too
/// — meaning this deliberate closure is expected to eventually trip the
/// circuit breaker and return `Err`, not a clean `Ok(())`. That `Err` is
/// this test's own doing (an artifact of how it ends the loop), not a
/// sign of the bug under test recurring — the property actually being
/// proven is `serviced == 1` with child2's pid, asserted from inside
/// `on_event` before the deliberate close ever happens.
#[test]
#[ignore = "requires root"]
fn test_run_notify_loop_continues_after_one_stale_request() {
    kestrel_ns::test_util::run_isolated(|| {
        let notify_fd = install_seccomp(&notify_personality_profile()).expect("install_seccomp").expect("profile uses notify, fd must be Some");

        let (sync_read, sync_write) = pipe().expect("pipe");

        // SAFETY: fork() duplicates the process; the child below only does
        // async-signal-safe work (one write(2), the notified syscall, then
        // _exit via process::exit) before terminating, matching
        // kestrel-ns's own run_isolated convention for what's safe here.
        match unsafe { fork() }.expect("fork child1") {
            ForkResult::Child => {
                drop(sync_read);
                // Tell the parent we're about to make the notified
                // syscall. The parent still waits a short grace period
                // after this before sending SIGKILL, to let the kernel
                // actually suspend us inside the syscall (see below).
                let _ = write(&sync_write, &[1u8]);
                let _ = unsafe { libc::personality(0xffffffff) };
                std::process::exit(0); // unreachable if killed as intended
            }
            ForkResult::Parent { child: child1 } => {
                drop(sync_write);
                let mut buf = [0u8; 1];
                read(sync_read.as_raw_fd(), &mut buf).expect("sync read from child1");
                drop(sync_read);
                // Best-effort grace period for the kernel to have actually
                // suspended child1 inside the notified syscall — the write
                // above only proves child1 reached the line just before
                // calling it, not that the kernel has finished suspending
                // it yet. In practice that gap is far below a millisecond;
                // this margin is generous.
                std::thread::sleep(std::time::Duration::from_millis(50));
                kill(child1, Signal::SIGKILL).expect("kill child1");
                // Reap child1 right away (rather than after run_notify_loop
                // returns) so it isn't sitting around as a zombie for the
                // rest of the test; the SIGKILL assertion is the one
                // meaningful check on it, so making it early vs. late
                // doesn't change what's being proven.
                match waitpid(child1, None) {
                    Ok(WaitStatus::Signaled(p, Signal::SIGKILL, _)) if p == child1 => {}
                    other => panic!("child1 should have been killed by SIGKILL: {other:?}"),
                }

                // Child 2: a second, unrelated process making the same
                // notified syscall — the one whose successful servicing
                // proves the loop kept going after child1's request failed.
                //
                // SAFETY: same reasoning as the child1 fork above.
                match unsafe { fork() }.expect("fork child2") {
                    ForkResult::Child => {
                        let ret = unsafe { libc::personality(0xffffffff) };
                        let errno = std::io::Error::last_os_error().raw_os_error();
                        let ok = ret == -1 && errno == Some(libc::ENOSYS);
                        std::process::exit(if ok { 0 } else { 1 });
                    }
                    ForkResult::Parent { child: child2 } => {
                        let raw_fd = notify_fd.as_raw_fd();
                        let mut serviced = 0u32;
                        let result = run_notify_loop(notify_fd.as_fd(), |event| {
                            serviced += 1;
                            assert_eq!(
                                event.pid,
                                child2.as_raw() as u32,
                                "the only event ever delivered to on_event must be child2's — \
                                 child1's stale request must have been skipped internally, \
                                 never delivered"
                            );
                            assert_eq!(event.syscall, "personality");

                            // SAFETY: closes the real fd out from under the
                            // `BorrowedFd` run_notify_loop is still
                            // (type-level) holding for the rest of its
                            // call — deliberate, test-only: nothing else in
                            // this test will ever close this fd, and
                            // without this the loop would block forever
                            // waiting for a third notification that's
                            // never coming. `notify_fd`'s own `Drop` is
                            // neutralized below via `mem::forget` so it
                            // doesn't double-close this same fd number.
                            unsafe { libc::close(raw_fd) };
                        });
                        std::mem::forget(notify_fd);

                        // See this test's doc comment: closing the fd above
                        // is expected to eventually trip the circuit
                        // breaker (Err), not end the loop cleanly (Ok) —
                        // that's a property of how THIS test ends the
                        // loop, not of the fix being proven here.
                        let err = result.expect_err(
                            "closing the fd from on_event is expected to eventually trip \
                             run_notify_loop's ECANCELED circuit breaker and return Err, not Ok",
                        );
                        let msg = err.to_string();
                        assert!(
                            msg.contains("ECANCELED") || msg.contains("consecutive"),
                            "expected the circuit-breaker error message, got: {msg}"
                        );
                        assert_eq!(serviced, 1, "on_event must have been invoked exactly once (for child2 only), before the deliberate close");

                        match waitpid(child2, None) {
                            Ok(WaitStatus::Exited(p, 0)) if p == child2 => {}
                            other => panic!("child2 did not observe the expected ENOSYS response: {other:?}"),
                        }
                    }
                }
            }
        }
    });
}

/// Proves `run_notify_loop`'s circuit breaker: a genuinely closed/invalid
/// fd makes every `receive()` attempt fail with the exact same
/// `SeccompErrno::ECANCELED` as the recoverable "one target died
/// mid-flight" case (confirmed live while building this fix — see
/// `notify.rs`'s module-level correction #7), so an unconditional "retry
/// forever on ECANCELED" would spin the CPU at 100% indefinitely instead
/// of terminating. This test closes the fd before `run_notify_loop` ever
/// gets to use it, then asserts the call returns promptly (bounded by the
/// retry cap, not hanging) with an `Err` — the circuit breaker tripping,
/// not a silent `Ok(())` "fd cleanly closed" ending, since this is a
/// judgment call worth surfacing to the caller.
#[test]
#[ignore = "requires root"]
fn test_run_notify_loop_circuit_breaks_on_permanently_broken_fd() {
    kestrel_ns::test_util::run_isolated(|| {
        let notify_fd = install_seccomp(&notify_personality_profile()).expect("install_seccomp").expect("profile uses notify, fd must be Some");

        // Close the fd immediately — nothing ever gets a chance to make
        // the notified syscall, so run_notify_loop will only ever see the
        // permanently-broken-fd failure mode, never a real request.
        let raw_fd = notify_fd.as_raw_fd();
        unsafe { libc::close(raw_fd) };
        std::mem::forget(notify_fd); // already closed above; don't double-close on drop

        // SAFETY: BorrowedFd::borrow_raw requires the fd to be valid for
        // the lifetime of the borrow, which is normally the caller's
        // responsibility — but here we're deliberately testing behavior
        // against an INVALID fd number (that's the whole point of this
        // test), and run_notify_loop only ever performs read-only ioctl
        // calls against it that fail safely (returning an OS error, not
        // triggering UB) on a bad fd, so this is sound for this
        // diagnostic-style use even though the fd itself is dead.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) };

        let start = std::time::Instant::now();
        let mut events = 0u32;
        let result = run_notify_loop(borrowed, |_event| events += 1);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "run_notify_loop must return Err when the circuit breaker trips, not Ok(())");
        assert_eq!(events, 0, "a permanently broken fd must never produce a real event");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "circuit breaker must trip quickly (bounded retries, not a hang or a slow leak): took {elapsed:?}"
        );
    });
}
