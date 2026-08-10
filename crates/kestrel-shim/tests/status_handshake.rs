// crates/kestrel-shim/tests/status_handshake.rs
//
//! Task 1's own scaffolding test (Step 5 of the plan): spawn
//! `kestrel-shim` against a trivial, always-succeeding command and assert
//! the shim's OWN stdout is exactly the single-line `{"ok":true}` status
//! handshake. This deliberately does NOT check the container's own
//! captured stdout (that lives in the PTY/pipes `kestrel_shim::io`
//! allocated, which `daemon::run` would read from) — `daemon::run` is
//! still a Task-2 stub that returns immediately, so nothing reads that
//! side yet. It also covers the failure path (non-zero exit -> `{"ok":
//! false, ...}` line plus the shim's own non-zero exit code).

use std::process::Command;

#[test]
fn shim_reports_ok_status_for_successful_command() {
    let shim = env!("CARGO_BIN_EXE_kestrel-shim");
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");

    let output = Command::new(shim)
        .arg("--id")
        .arg("t1")
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--tty")
        .arg("false")
        .arg("--")
        .arg("/bin/echo")
        .arg("hello")
        .output()
        .expect("run kestrel-shim");

    assert!(
        output.status.success(),
        "shim exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "{\"ok\":true}\n",
        "unexpected shim stdout (stderr={})",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn shim_reports_error_status_and_exits_nonzero_for_failing_command() {
    let shim = env!("CARGO_BIN_EXE_kestrel-shim");
    let run_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempfile::tempdir().expect("tempdir");

    let output = Command::new(shim)
        .arg("--id")
        .arg("t2")
        .arg("--run-dir")
        .arg(run_dir.path())
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--tty")
        .arg("false")
        .arg("--")
        .arg("/bin/false")
        .output()
        .expect("run kestrel-shim");

    assert!(!output.status.success(), "expected non-zero shim exit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("{\"ok\":false"),
        "unexpected shim stdout: {stdout}"
    );
}
