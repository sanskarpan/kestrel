// crates/kestrel-shim/tests/shim_lifecycle.rs
//
//! Task 2's own tests (plan Step 5): durable log writing, `attach.sock`
//! framing, and the PTY-EIO-vs-pipe-EOF exit condition, exercised against
//! the REAL compiled `kestrel-shim` binary.
//!
//! None of these need root: they don't touch namespaces/cgroups (that's
//! `kestrel-runtime`'s job — this crate is deliberately agnostic to what
//! command it wraps, per design doc §2's "own one container's stdio...
//! nothing more"), just plain process spawning, PTYs, and a Unix socket in
//! a tempdir.
//!
//! Tests 1 and 2 run `kestrel-shim` against a SHORT-LIVED command directly
//! (standing in for what would realistically be `kestrel-runtime create`)
//! and let it run to completion, then inspect the result — this is the
//! same "no real kestrel-runtime needed" shape Task 1's own
//! `status_handshake.rs` tests use.
//!
//! Tests 3 and 4 need the shim to still be alive (and `attach.sock`
//! reachable) WHILE we interact with it, which the direct-command shape
//! above can't give us: `main.rs` waits synchronously for the wrapped
//! command to exit before daemonizing/serving `attach.sock` at all (design
//! doc §2 steps 3-6) — exactly mirroring real production, where
//! `kestrel-runtime create` itself returns quickly while the actual
//! long-lived holder of the container's stdio is `kestrel-init`, a
//! GRANDCHILD that create() forks off and which survives create's own
//! process exiting (reparented, not waited on). We reproduce that same
//! shape with plain shell backgrounding: `/bin/sh -c '<long-lived-cmd> &'`
//! — the `sh` itself (what the shim directly spawns and waits on) exits
//! almost immediately, while the backgrounded command survives as an
//! orphan holding its own independently-dup'd copy of the PTY slave, which
//! is exactly what keeps the shim's read loop (and therefore `attach.sock`)
//! alive long enough to attach to.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use kestrel_shim::framing::{read_frame, write_frame, Frame};
use serde_json::Value;
use tokio::net::UnixStream;

fn shim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kestrel-shim")
}

/// Polls for `path` to exist, up to `bound`. Used to wait for
/// `attach.sock` to be bound by a still-running shim before connecting.
async fn wait_for_path(path: &Path, bound: Duration) {
    let deadline = tokio::time::Instant::now() + bound;
    while !path.exists() {
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out after {bound:?} waiting for {} to exist", path.display());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Reads `Frame::Data` chunks off `read_half`, accumulating their
/// (lossily-decoded) bytes into a string, until `needle` appears or
/// `bound` elapses (in which case the test fails with a clear message
/// rather than hanging).
async fn read_until_contains(read_half: &mut (impl tokio::io::AsyncRead + Unpin), needle: &str, bound: Duration) -> String {
    let fut = async {
        let mut acc = String::new();
        loop {
            match read_frame(read_half).await {
                Ok(Frame::Data(bytes)) => {
                    acc.push_str(&String::from_utf8_lossy(&bytes));
                    if acc.contains(needle) {
                        return acc;
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("attach socket read failed before seeing {needle:?}: {e} (accumulated so far: {acc:?})"),
            }
        }
    };
    match tokio::time::timeout(bound, fut).await {
        Ok(acc) => acc,
        Err(_) => panic!("timed out after {bound:?} waiting for {needle:?} over attach.sock"),
    }
}

#[test]
fn test_shim_captures_output_and_survives_kestreld_analog() {
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");
    let id = "pipes-eof";

    let output = Command::new(shim_bin())
        .args(["--id", id])
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--tty", "false"])
        .arg("--")
        .args(["/bin/sh", "-c", "echo one; sleep 1; echo two"])
        .output()
        .expect("run kestrel-shim");

    assert!(
        output.status.success(),
        "shim exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // The shim process only exits once daemon::run's read loop has
    // observed EOF and flushed the log — by the time `output()` returns,
    // output.jsonl is fully written, no polling needed.
    let log_path = data_dir.path().join("containers").join(id).join("output.jsonl");
    let contents = std::fs::read_to_string(&log_path).unwrap_or_else(|e| panic!("reading {}: {e}", log_path.display()));

    let lines: Vec<Value> = contents
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("invalid JSON log line {l:?}: {e}")))
        .collect();

    assert_eq!(lines.len(), 2, "expected exactly 2 log lines, got: {contents}");
    assert_eq!(lines[0]["stream"], "stdout");
    assert_eq!(lines[0]["msg"], "one");
    assert!(lines[0]["ts"].is_string());
    assert_eq!(lines[1]["stream"], "stdout");
    assert_eq!(lines[1]["msg"], "two");
    assert!(lines[1]["ts"].is_string());
}

#[test]
fn test_pty_eof_via_eio_exits_cleanly() {
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");

    let start = std::time::Instant::now();
    let output = Command::new(shim_bin())
        .args(["--id", "pty-eio"])
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--tty", "true"])
        .arg("--")
        .args(["/bin/sh", "-c", "echo hi; exit 0"])
        .output()
        .expect("run kestrel-shim");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "shim exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "shim took too long to exit after PTY EIO ({elapsed:?}) — read loop may not be treating EIO as EOF"
    );
}

#[tokio::test]
async fn test_attach_sock_relays_bytes_both_ways() {
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");
    let id = "attach-relay";

    let mut child = Command::new(shim_bin())
        .args(["--id", id])
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--tty", "true"])
        .arg("--")
        // `sh` itself exits immediately; the backgrounded `cat` survives
        // as an orphan, keeping the shim's PTY read loop (and attach.sock)
        // alive — see the module doc comment for why this shape is needed.
        //
        // `<&1` is required for the same reason as the resize test below:
        // per POSIX, an asynchronous list's stdin is implicitly
        // `/dev/null` unless redirected (confirmed empirically against
        // dash) — without it, `cat` sees immediate EOF on its real stdin
        // and exits right away instead of relaying anything.
        .args(["/bin/sh", "-c", "cat <&1 &"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kestrel-shim");

    let attach_sock = run_dir.path().join(id).join("attach.sock");
    wait_for_path(&attach_sock, Duration::from_secs(5)).await;

    let stream = UnixStream::connect(&attach_sock).await.expect("connect to attach.sock");
    let (mut read_half, mut write_half) = stream.into_split();

    write_frame(&mut write_half, &Frame::Data(b"hello\n".to_vec()))
        .await
        .expect("write Data frame");

    // Full loop this proves: our write -> PTY master -> PTY slave -> cat's
    // stdin -> cat's stdout -> PTY master -> broadcast -> back over the
    // socket to us.
    let received = read_until_contains(&mut read_half, "hello", Duration::from_secs(5)).await;
    assert!(received.contains("hello"), "expected echoed 'hello' in attach stream, got: {received:?}");

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn test_resize_issues_tiocswinsz() {
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");
    let id = "attach-resize";

    let mut child = Command::new(shim_bin())
        .args(["--id", id])
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--tty", "true"])
        .arg("--")
        // Same backgrounding shape as the relay test, but the surviving
        // orphan repeatedly reports its own window size via `stty size`
        // (reads directly off the PTY, no SIGWINCH/ctty dependency) — an
        // externally-observable proof that TIOCSWINSZ actually changed the
        // PTY's real window size, without needing to reach into the
        // shim's own fd table from the test process.
        //
        // `<&1` is required: per POSIX, an asynchronous list's (`(...) &`)
        // standard input is implicitly `/dev/null` unless redirected —
        // confirmed empirically against dash (`/bin/sh` here) — so plain
        // `stty size` fails with "Inappropriate ioctl for device" (ENOTTY
        // on /dev/null). fd 1 (stdout) is unaffected by that rule and is
        // still the PTY slave, so duplicating it onto stdin for just this
        // command gives `stty` a real tty to query.
        //
        // Bounded (100 iterations x 0.05s =~ 5s max), NOT `while true`:
        // confirmed empirically that `TIOCGWINSZ` (what `stty size` reads)
        // keeps succeeding off the PTY SLAVE even after the shim (and
        // therefore the PTY MASTER) is gone — window size is kernel state
        // attached to the tty pair, not something that requires the
        // master to still be open to query. So an unconditional `while
        // true` loop here would never self-terminate and leak an orphaned
        // process forever after every test run; capping the iteration
        // count guarantees this process exits on its own well within the
        // test's own lifetime, independent of the shim's/PTY's fate.
        .args(["/bin/sh", "-c", "(i=0; while [ $i -lt 100 ]; do stty size <&1; sleep 0.05; i=$((i+1)); done) &"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kestrel-shim");

    let attach_sock = run_dir.path().join(id).join("attach.sock");
    wait_for_path(&attach_sock, Duration::from_secs(5)).await;

    let stream = UnixStream::connect(&attach_sock).await.expect("connect to attach.sock");
    let (mut read_half, mut write_half) = stream.into_split();

    write_frame(&mut write_half, &Frame::Resize { rows: 40, cols: 120 })
        .await
        .expect("write Resize frame");

    // `stty size` prints "<rows> <cols>" — "40 120" only appears once
    // TIOCSWINSZ has genuinely taken effect on the PTY.
    let received = read_until_contains(&mut read_half, "40 120", Duration::from_secs(5)).await;
    assert!(
        received.contains("40 120"),
        "expected 'stty size' to report the resized window (40 120), got: {received:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
