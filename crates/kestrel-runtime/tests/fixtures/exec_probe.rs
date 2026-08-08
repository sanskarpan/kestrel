// crates/kestrel-runtime/tests/fixtures/exec_probe.rs
//
//! Exec target used only by `tests/exec_cmd.rs`. Once `exec_cmd::exec()`'s
//! `execve` replaces this process's image there is no longer any distinct,
//! separately-inspectable process on the test's side to query — so the
//! only way to prove `exec_cmd::exec` genuinely joined the container's
//! namespaces (rather than merely returning success) is to have the
//! exec'd process itself report its own `/proc/self/ns/*` identities
//! somewhere the test can read them back afterward. That's this binary's
//! whole job; it also supports exiting with a caller-chosen code, or
//! self-signaling, so the same fixture covers `exec_cmd::exec`'s exit-code
//! propagation (both the plain-exit and signal-death encodings) without
//! needing a second binary.
//!
//! Env vars (all optional; absent all three, behaves like `/bin/true`):
//! - `KESTREL_TEST_NS_OUTPUT`: a file path. If set, writes one line per
//!   namespace type — `<proc_name> <st_dev> <st_ino>` from `stat`ing
//!   `/proc/self/ns/<proc_name>` — for ipc/uts/net/cgroup/user/pid (the
//!   types `tests/exec_cmd.rs`'s test containers pin; see that file's
//!   `namespaces_without_mount_plus_user`). Written before either of the
//!   exit paths below, so it's observable regardless of which one fires.
//! - `KESTREL_TEST_EXIT_CODE`: parsed as `i32`, passed to
//!   `std::process::exit`. Defaults to 0 if unset.
//! - `KESTREL_TEST_SIGNAL`: if set to `KILL`, sends SIGKILL to itself
//!   instead of reaching the exit-code path above. SIGKILL can't be
//!   caught or ignored, so this never returns.

use std::io::Write;

const NS_PROC_NAMES: [&str; 6] = ["ipc", "uts", "net", "cgroup", "user", "pid"];

fn main() {
    if let Ok(output_path) = std::env::var("KESTREL_TEST_NS_OUTPUT") {
        let mut report = String::new();
        for name in NS_PROC_NAMES {
            let path = format!("/proc/self/ns/{name}");
            let st = nix::sys::stat::stat(path.as_str())
                .unwrap_or_else(|e| panic!("stat {path}: {e}"));
            report.push_str(&format!("{name} {} {}\n", st.st_dev, st.st_ino));
        }
        let mut f = std::fs::File::create(&output_path)
            .unwrap_or_else(|e| panic!("create {output_path}: {e}"));
        f.write_all(report.as_bytes()).expect("write ns report");
        f.sync_all().expect("sync ns report to disk");
    }

    if let Ok(sig) = std::env::var("KESTREL_TEST_SIGNAL") {
        assert_eq!(sig, "KILL", "this fixture only knows how to self-signal KILL");
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL).expect("raise SIGKILL");
        unreachable!("SIGKILL cannot be caught or ignored");
    }

    let code = std::env::var("KESTREL_TEST_EXIT_CODE")
        .ok()
        .map(|s| s.parse::<i32>().expect("KESTREL_TEST_EXIT_CODE must parse as i32"))
        .unwrap_or(0);
    std::process::exit(code);
}
