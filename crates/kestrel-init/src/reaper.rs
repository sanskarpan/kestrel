// crates/kestrel-init/src/reaper.rs
//
//! The SIGCHLD reap loop. Signal blocking + signalfd creation happen in
//! main.rs BEFORE the entrypoint is forked (a later task) — this module
//! only consumes an already-armed SignalFd, per the Phase 8 design doc's
//! explicit resolution of SPEC.md §12's skeleton ordering.

use nix::sys::signal::{kill, Signal};
use nix::sys::signalfd::SignalFd;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Drains every already-dead child via non-blocking `waitpid(-1,
/// WNOHANG)`, looping because a single SIGCHLD delivery can represent
/// MULTIPLE child deaths — POSIX signals don't queue, so N children
/// dying while SIGCHLD is blocked (or simply while this process is busy
/// elsewhere) collapse into exactly one pending/delivered signal, and
/// only an explicit drain-until-empty loop reaps all of them. Returns
/// every `(pid, exit-code)` pair observed, where exit-code is the raw
/// exit code for a normal exit or 128+signum for a signal death — this
/// is the exact convention `run_init` uses for its own return value.
/// Stops on `StillAlive` (no zombie ready right now) or `ECHILD` (no
/// children left at all); both are ordinary loop-ending conditions, not
/// errors.
fn drain_dead_children() -> anyhow::Result<Vec<(Pid, i32)>> {
    let mut reaped = Vec::new();
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) => reaped.push((pid, code)),
            Ok(WaitStatus::Signaled(pid, sig, _)) => reaped.push((pid, 128 + sig as i32)),
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
            Ok(_) => continue, // Stopped/Continued etc. — not a death, keep draining
            Err(e) => return Err(e.into()),
        }
    }
    Ok(reaped)
}

/// Runs until `entrypoint` has exited AND been reaped, forwarding every
/// other received signal to it, reaping every other dead child
/// (orphans reparented to PID 1) along the way. Returns the entrypoint's
/// own exit code (raw exit code, or 128+signum if it died by signal).
pub fn run_init(entrypoint: Pid, sfd: &SignalFd) -> anyhow::Result<i32> {
    let mut entrypoint_exit: Option<i32> = None;

    loop {
        let siginfo = match sfd.read_signal()? {
            Some(si) => si,
            None => continue, // shouldn't happen on a blocking signalfd; defensive
        };
        let signo = siginfo.ssi_signo as i32;

        if signo == libc::SIGCHLD {
            for (pid, code) in drain_dead_children()? {
                if pid == entrypoint {
                    entrypoint_exit = Some(code);
                }
            }
            if let Some(code) = entrypoint_exit {
                return Ok(code);
            }
        } else if let Ok(sig) = Signal::try_from(signo) {
            // Forward every other received signal to the entrypoint.
            let _ = kill(entrypoint, sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::SigSet;
    use nix::sys::signalfd::SignalFd;
    use nix::unistd::{fork, ForkResult};

    use super::*;

    /// Focused unit-level test for the "one SIGCHLD delivery can cover
    /// multiple deaths" case specifically, isolated from the rest of
    /// `run_init` (which needs real entrypoint-forking/signal-forwarding
    /// machinery most meaningfully tested end-to-end — deferred to the
    /// Task 16 capstone). This test proves `drain_dead_children`'s
    /// WNOHANG-loop logic alone: fork several children that all exit
    /// near-simultaneously *before* SIGCHLD is ever consumed, then
    /// confirm a SINGLE `signalfd` read followed by ONE call to
    /// `drain_dead_children` reaps every one of them.
    ///
    /// Non-root: `fork`, `sigprocmask`/`thread_block`, and `signalfd` all
    /// need no special privilege. Wrapped in
    /// `kestrel_ns::test_util::run_isolated` for the same fork-safety
    /// reason `fifo.rs`'s test is (see that file's test doc comment) —
    /// SIGCHLD is blocked and a signalfd created inside the isolated
    /// child, not in cargo test's own possibly-multi-threaded harness
    /// process.
    #[test]
    fn test_drain_dead_children_reaps_all_from_one_sigchld_read() {
        kestrel_ns::test_util::run_isolated(|| {
            // Block SIGCHLD on this (isolated, single-threaded) process
            // BEFORE forking any children, so every one of their deaths
            // coalesces into a single pending signal instead of
            // interrupting anything mid-loop below.
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGCHLD);
            mask.thread_block().expect("thread_block(SIGCHLD)");

            let sfd = SignalFd::new(&mask).expect("SignalFd::new");

            const N: usize = 8;
            let mut children = Vec::with_capacity(N);
            for _ in 0..N {
                // SAFETY: fork() duplicates the calling (already-
                // isolated, single-threaded) process; the child branch
                // below performs only the async-signal-safe `_exit`
                // before terminating, matching this crate's existing
                // fork-safety convention.
                match unsafe { fork() }.expect("fork") {
                    // SAFETY: _exit() is async-signal-safe and never
                    // returns; used instead of process::exit() so this
                    // child never re-runs Rust's normal unwind/drop
                    // machinery on top of run_isolated's own child branch
                    // (this fork happens *inside* that branch).
                    ForkResult::Child => unsafe { libc::_exit(0) },
                    ForkResult::Parent { child } => children.push(child),
                }
            }

            // Give every child a chance to actually run and exit while
            // SIGCHLD stays blocked (pending, uncollapsed further, but
            // also un-consumed) on this process.
            std::thread::sleep(std::time::Duration::from_millis(200));

            // Exactly ONE read_signal() call — proving it's the drain
            // loop below, not repeated signalfd reads, that reaps every
            // child.
            let siginfo = sfd.read_signal().expect("read_signal").expect("a SIGCHLD should be pending");
            assert_eq!(siginfo.ssi_signo as i32, libc::SIGCHLD, "unexpected signal number");

            let reaped = drain_dead_children().expect("drain_dead_children");
            assert_eq!(
                reaped.len(),
                N,
                "expected all {N} children reaped from a single SIGCHLD read, got {reaped:?}"
            );
            for c in &children {
                assert!(
                    reaped.iter().any(|(pid, _)| pid == c),
                    "child {c} not present among reaped pids {reaped:?}"
                );
            }
            for (_, code) in &reaped {
                assert_eq!(*code, 0, "expected every child to have exited with code 0");
            }
        });
    }
}
