// crates/kestrel-init/tests/pdeathsig.rs

use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, write, ForkResult};

use kestrel_init::pdeathsig::set_parent_death_signal;

/// Blocking `read(2)` of up to `buf_len` bytes on `fd`, run on a helper
/// thread so the caller can bound how long it waits. `None` means the
/// timeout elapsed with no data (and no EOF) observed. Used below so a
/// genuine bug in the PDEATHSIG delivery path fails the test fast with a
/// clear message instead of wedging `cargo test` indefinitely.
fn read_with_timeout(fd: RawFd, buf_len: usize, timeout: Duration) -> Option<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = vec![0u8; buf_len];
        let result = nix::unistd::read(fd, &mut buf).map(|n| buf[..n].to_vec());
        // Best-effort: if the receiver already timed out and dropped, this
        // send fails silently — nothing further to clean up, and the whole
        // test process exits shortly after via run_isolated's own _exit().
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(bytes)) => Some(bytes),
        Ok(Err(e)) => panic!("read(2) failed: {e}"),
        Err(mpsc::RecvTimeoutError::Timeout) => None,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("read helper thread died without sending a result")
        }
    }
}

#[test]
#[ignore = "requires root"]
fn test_pdeathsig_delivers_when_parent_dies() {
    kestrel_ns::test_util::run_isolated(|| {
        // Process tree built here, all inside run_isolated's own forked
        // child ("G", this closure):
        //
        //   G (this closure)
        //   `-- P  (forked below; SIGKILLed by G)
        //       `-- C (forked by P; arms PDEATHSIG(SIGUSR1))
        //
        // C is P's child, not G's — SIGKILLing P and observing C's death
        // from G (two levels removed) is exactly the parent-then-child
        // scenario PDEATHSIG exists for.
        //
        // Liveness of C is proven via pipe EOF rather than polling
        // `/proc/<pid>/exists`: a /proc check is vulnerable to PID reuse in
        // the window between C dying and the check running (the kernel is
        // free to hand C's old PID to an unrelated new process before we
        // look). A pipe whose write end *only* C holds has no such
        // ambiguity — the kernel reports EOF exactly when every holder of
        // the write end (here, just C, since both G and P drop their own
        // copies below) has exited or closed it, full stop. It also lets
        // us measure *when* C died: well before its 5s fallback sleep
        // proves PDEATHSIG fired, rather than C merely running to
        // completion on its own.
        let (r, w) = pipe().expect("pipe");

        // SAFETY: fork() duplicates the calling process; both branches
        // below only perform async-signal-safe / fork-safe operations
        // (prctl, pipe read/write, sleep, kill, waitpid, process::exit)
        // before the process in question terminates, matching this
        // crate's existing fork-safety convention (see
        // kestrel_ns::test_util::run_isolated).
        match unsafe { fork() }.expect("fork (G -> P)") {
            ForkResult::Child => {
                // P: never reads from the pipe.
                drop(r);

                // SAFETY: see the fork() SAFETY comment above; same
                // reasoning applies one level down.
                match unsafe { fork() }.expect("fork (P -> C)") {
                    ForkResult::Child => {
                        // C: arm PDEATHSIG for SIGUSR1 *before* signaling
                        // readiness, so G never kills P until C is
                        // definitely armed. (Whether prctl still "works"
                        // if the real parent already died is a separate,
                        // documented edge case — not what this test is
                        // checking; synchronizing here sidesteps it.)
                        set_parent_death_signal(Signal::SIGUSR1).expect("set_parent_death_signal");
                        write(&w, b"R").expect("write ready byte");

                        // Fallback path: reached only if PDEATHSIG never
                        // fires. Process exit closes `w` regardless, which
                        // is what the grandparent's EOF read is watching
                        // for either way.
                        std::thread::sleep(Duration::from_secs(5));
                        std::process::exit(111); // only reached if PDEATHSIG never fired
                    }
                    ForkResult::Parent { .. } => {
                        // P: drop its own copy of the write end so C is
                        // left holding the *only* reference to it — this
                        // is what makes G's later EOF read unambiguous.
                        drop(w);
                        // Idle until G SIGKILLs us. SIGKILL can't be caught
                        // or ignored, so there's nothing to coordinate.
                        loop {
                            std::thread::sleep(Duration::from_secs(30));
                        }
                    }
                }
            }
            ForkResult::Parent { child: p_pid } => {
                // G: drop its own copy of the write end (same reasoning as
                // P above) before doing anything else.
                drop(w);

                // Wait for C's readiness signal before touching P at all —
                // otherwise we could kill P before C has even called
                // set_parent_death_signal.
                let ready = read_with_timeout(r.as_raw_fd(), 1, Duration::from_secs(5));
                assert_eq!(
                    ready.as_deref(),
                    Some(b"R".as_slice()),
                    "did not observe C's readiness byte before timeout"
                );

                let kill_time = Instant::now();
                kill(p_pid, Signal::SIGKILL).expect("kill P");
                match waitpid(p_pid, None) {
                    Ok(WaitStatus::Signaled(_, Signal::SIGKILL, _)) => {}
                    other => panic!("expected P killed by SIGKILL, got {other:?}"),
                }

                // Blocking (bounded) read for EOF: resolves to Some(vec![])
                // once every holder of the write end (just C, by
                // construction) has exited. Bounded comfortably above what
                // PDEATHSIG delivery should ever take, but well below C's
                // 5s fallback sleep, so a regression fails with a clear
                // "timed out" message instead of hanging.
                let eof = read_with_timeout(r.as_raw_fd(), 1, Duration::from_secs(3));
                let elapsed = kill_time.elapsed();

                match eof {
                    Some(bytes) if bytes.is_empty() => {}
                    Some(bytes) => panic!(
                        "expected EOF on the pipe, got {} unexpected byte(s): {bytes:?}",
                        bytes.len()
                    ),
                    None => panic!(
                        "timed out waiting for C to die (pipe never hit EOF within 3s of killing P)"
                    ),
                }

                assert!(
                    elapsed < Duration::from_secs(2),
                    "C's write end closed after {elapsed:?}, too close to (or past) its 5s \
                     fallback sleep — this looks like C survived P's death instead of being \
                     killed by PDEATHSIG"
                );

                drop(r);
            }
        }
    });
}
