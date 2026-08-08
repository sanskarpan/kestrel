// crates/kestrel-init/src/fifo.rs

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

/// Blocks until `kestrel start` opens the FIFO's host-side path for
/// writing (SPEC.md §9.1's own snippet, adapted to the container-
/// relative path this plan's bind-mount fix requires — see Task 5).
///
/// `OpenOptions::open` itself is the blocking step: opening a FIFO
/// read-only blocks in the kernel until some other process opens the
/// same path for writing (standard `fifo(7)` semantics) — no polling or
/// explicit wait is needed. The one-byte read that follows just consumes
/// the readiness byte `kestrel start` writes; its content is not
/// meaningful, only the fact that it arrived.
pub fn block_until_started(fifo_path: &Path) -> Result<()> {
    let mut f = OpenOptions::new().read(true).open(fifo_path).with_context(|| format!("opening {}", fifo_path.display()))?;
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).context("blocking read on exec fifo")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use nix::sys::stat::Mode;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, mkfifo, write, ForkResult};

    use super::*;

    /// Non-root: `mkfifo` and `fork` both need no special privilege. Uses
    /// a FORKED CHILD (not a thread) to open the writer side after a
    /// short delay, matching this project's established fork-safety
    /// precedent (e.g. the Phase 7 `netns-helper` subprocess pattern) —
    /// see this task's own resolved Rule #2 scope note for why a thread
    /// was deliberately avoided here even though nothing in this test
    /// touches PID-1 or signal masks itself.
    ///
    /// Wrapped in `kestrel_ns::test_util::run_isolated` so the fork below
    /// happens inside a freshly-forked, single-threaded child process
    /// rather than directly inside cargo test's own (possibly
    /// multi-threaded) harness process — the same fork-safety concern
    /// `mounts.rs` and `pdeathsig.rs`'s tests already document.
    #[test]
    fn test_block_until_started_unblocks_when_writer_opens() {
        kestrel_ns::test_util::run_isolated(|| {
            let tmp = tempfile::tempdir().expect("tempdir");
            let fifo_path = tmp.path().join("exec.fifo");
            mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");

            const WRITER_DELAY: Duration = Duration::from_millis(300);

            // SAFETY: fork() duplicates the calling (already-isolated,
            // single-threaded) process; the child branch below only
            // performs async-signal-safe / fork-safe operations (sleep,
            // open, write, _exit) before terminating, matching this
            // crate's existing fork-safety convention.
            match unsafe { fork() }.expect("fork") {
                ForkResult::Child => {
                    // Writer: delay first so the parent's blocking read
                    // genuinely has to wait, not race a same-instant open.
                    std::thread::sleep(WRITER_DELAY);
                    let w = OpenOptions::new().write(true).open(&fifo_path).expect("open fifo for writing");
                    write(&w, b"R").expect("write readiness byte");
                    // SAFETY: _exit() is async-signal-safe and never
                    // returns; called instead of process::exit() so the
                    // child never re-runs Rust's normal unwind/drop
                    // machinery a second time on top of run_isolated's
                    // own child branch (this fork happens *inside* that
                    // branch).
                    unsafe { libc::_exit(0) };
                }
                ForkResult::Parent { child } => {
                    let start = Instant::now();
                    block_until_started(&fifo_path).expect("block_until_started");
                    let elapsed = start.elapsed();

                    assert!(
                        elapsed >= WRITER_DELAY,
                        "block_until_started returned after {elapsed:?}, before the writer's \
                         {WRITER_DELAY:?} delay even elapsed — the read did not actually block"
                    );

                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, 0)) => {}
                        other => panic!("writer child exited abnormally: {other:?}"),
                    }
                }
            }
        });
    }
}
