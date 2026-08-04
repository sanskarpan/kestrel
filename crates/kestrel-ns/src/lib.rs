#![deny(clippy::undocumented_unsafe_blocks)]

//! Namespace creation, id-map writing, pinning, and setns ordering for
//! kestrel. See docs/superpowers/specs/2026-07-31-phase2-namespaces-design.md.

pub mod idmap;
pub mod inode;
pub mod join;
pub mod pin;
pub mod rootless;
pub mod stages;
pub mod sync;
pub mod threading;
pub mod types;

/// Fork-based test isolation. Not `#[cfg(test)]`-gated because
/// `tests/*.rs` integration test binaries compile against the crate's
/// normal public API, not its unit-test cfg — see Task 1 of
/// docs/superpowers/plans/2026-08-01-phase2-namespaces.md for why. Intended
/// for test code only; not part of the crate's operational surface.
#[doc(hidden)]
pub mod test_util {
    use std::panic;

    /// Forks the calling process and runs `f` in the child. `unshare` with
    /// `CLONE_NEWUSER` fails with EINVAL if the calling PROCESS is
    /// multithreaded, and cargo test's harness always is (it spawns a
    /// thread per test) — forking guarantees the child starts with exactly
    /// one thread regardless of the parent's thread count, so anything that
    /// needs single-threadedness must run inside this closure, not directly
    /// in a `#[test]` fn. Panics in the parent if the child's exit code is
    /// nonzero; a panic inside `f` itself is caught, printed (via the
    /// default panic hook, before `catch_unwind` returns), and mapped to
    /// exit code 101 so it still fails the parent-side assertion.
    pub fn run_isolated<F: FnOnce() + panic::UnwindSafe>(f: F) {
        // SAFETY: fork() duplicates the whole process; the child below only
        // calls async-signal-safe operations before exiting (catch_unwind's
        // internal bookkeeping and the final _exit are the only things that
        // run here, no allocation-heavy or non-async-signal-safe code paths
        // are reachable between fork and _exit besides `f` itself, which
        // callers are responsible for keeping fork-safe).
        match unsafe { nix::unistd::fork() }.expect("fork failed") {
            nix::unistd::ForkResult::Child => {
                let result = panic::catch_unwind(f);
                // 101 matches Rust's own default process exit code on an
                // unhandled panic, so a failure here reads the same way a
                // bare `#[test]` panic would.
                let code = if result.is_ok() { 0 } else { 101 };
                // SAFETY: _exit() is async-signal-safe and never returns;
                // called instead of a normal process exit so the child never
                // runs Rust's normal unwind/drop machinery a second time or
                // falls through into the parent's post-fork code path.
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = loop {
                    match nix::sys::wait::waitpid(child, None) {
                        Err(nix::errno::Errno::EINTR) => continue,
                        other => break other.expect("waitpid failed"),
                    }
                };
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 0) => {}
                    other => panic!("isolated test child failed: {other:?}"),
                }
            }
        }
    }
}
