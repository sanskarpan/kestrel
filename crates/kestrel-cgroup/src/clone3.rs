//! `clone3(2)` with `CLONE_INTO_CGROUP` — atomically places a newly-created
//! child into a target cgroup before its first instruction runs.
//!
//! The classic `fork()`-then-write-`cgroup.procs` sequence leaves a window
//! where the child runs with NO limits: a memory bomb on the entrypoint's
//! first line can escape `memory.max` before the parent gets a chance to
//! move it into the cgroup. `clone3(CLONE_INTO_CGROUP)` closes that window
//! by making cgroup placement part of process creation itself.

use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::unistd::Pid;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

// Per `include/uapi/linux/sched.h`: `CLONE_CLEAR_SIGHAND` is bit 32
// (0x1_0000_0000) and `CLONE_INTO_CGROUP` is bit 33 (0x2_0000_0000) — NOT
// 0x2000_0000_0000 (bit 45), which was the original value written here and
// was verified wrong against a real kernel: the kernel rejects any
// unrecognized flag bit in `clone3_args_valid()` with EINVAL *before* it
// ever resolves the `cgroup` fd, so a wrong flag value here manifests as
// EINVAL regardless of whether the fd argument is valid, garbage, or even
// the real root cgroup fd — all three produced identical EINVAL until this
// was corrected. See the manual sanity check referenced in the Task 10
// report for the strace evidence. `clone_into_cgroup_flag_matches_kernel`
// in the tests module below pins this value so a future edit can't
// silently drift back to a wrong bit without a test failing.
//
// NOT `libc::CLONE_INTO_CGROUP` — that constant exists in this project's
// resolved libc version but is `#[deprecated]` and evaluates to 0 as a
// `c_int` (libc's own overflow bug). Using it would silently disable
// cgroup placement with no error, which is worse than the wrong-bit bug
// this hand-rolled value was already found and fixed to replace — do not
// "clean this up" by substituting the libc constant back in.
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Forks via `clone3(2)` with `CLONE_INTO_CGROUP`, placing the child in
/// `cgroup_fd`'s cgroup atomically — before its first instruction runs, so
/// there is no window where the child is unconstrained by the cgroup's
/// limits (unlike fork()-then-write-cgroup.procs).
///
/// `exit_signal` should be `SIGCHLD` (as `libc::SIGCHLD as u64`) to preserve
/// normal `fork()`/`waitpid` semantics on the resulting child — `clone3`
/// allows an arbitrary signal here, or none at all, and picking wrong would
/// silently break reaping (a parent `waitpid`ing for `SIGCHLD` would never
/// be notified, or would be notified with a different signal than callers
/// of this crate expect).
///
/// # Safety
/// Caller must be single-threaded (same requirement as `fork()` elsewhere
/// in this project — clone3 has the same multithreading hazards). The
/// child branch (return value `Ok(None)`) must not touch any state that
/// assumes a parent context, matching `nix::unistd::fork()`'s own
/// documented child-side restrictions (only async-signal-safe operations
/// until the child calls `_exit`/`execve`).
pub unsafe fn clone_into_cgroup(exit_signal: u64, cgroup_fd: RawFd) -> Result<Option<Pid>> {
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP,
        exit_signal,
        cgroup: cgroup_fd as u64,
        ..Default::default()
    };
    // SAFETY: `args` is a valid, correctly-sized CloneArgs on the stack for
    // the duration of this call; SYS_clone3 either returns -1 (parent,
    // error), 0 (child), or the child's pid (parent, success) per clone3(2)
    // — the same three-way return convention as fork(2), handled below the
    // same way nix::unistd::fork() handles it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    match rc {
        -1 => Err(std::io::Error::last_os_error()).context("clone3(CLONE_INTO_CGROUP)"),
        0 => Ok(None),                          // child
        n => Ok(Some(Pid::from_raw(n as i32))), // parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_into_cgroup_flag_matches_kernel() {
        assert_eq!(CLONE_INTO_CGROUP, 0x2_0000_0000);
    }
}
