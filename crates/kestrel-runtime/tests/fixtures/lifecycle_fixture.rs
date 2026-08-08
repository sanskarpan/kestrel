// crates/kestrel-runtime/tests/fixtures/lifecycle_fixture.rs

//! Reused across `test_create_then_start` / `test_exit_code_propagates` /
//! `test_signal_exit_code` / `test_zombie_reaping` / `test_hooks_fire_in_order`
//! (Task 16) via argv-selected behavior, matching this project's established
//! "one parameterized fixture, not N single-purpose ones" pattern
//! (Phase 5's `kestrel-init/tests/fixtures/*.rs`, this crate's own
//! `tests/fixtures/exec_probe.rs`).
//!
//! This binary is exec'd fresh (as `process.args`/entrypoint) by an
//! ALREADY-`pivot_root`'d `kestrel-init` running inside the container's
//! own mount namespace, at the fixed path `/fixture` inside the synthetic
//! rootfs `tests/common/mod.rs::build_synthetic_rootfs` builds. Unlike
//! `kestrel-init` itself — which must survive `pivot_root` and therefore
//! cannot depend on any dynamic linker/`.so` that might not exist in the
//! new root — this fixture runs AFTER `pivot_root` has already completed,
//! so it only needs to work inside whatever the synthetic rootfs
//! contains. Empirically verified (Task 15, see that task's report) that
//! a `chroot` into a rootfs containing ONLY a plain dynamically-linked
//! copy of this binary (no `/lib`, no loader) fails with ENOENT at exec
//! time, because the dynamic linker itself is missing — so this binary
//! DOES need the same static-linking treatment as `kestrel-init` (built
//! via a `RUSTFLAGS="-C target-feature=+crt-static"` build against the
//! `aarch64-unknown-linux-gnu` target, matching the Makefile's
//! `build-kestrel-init-static` target) UNLESS the synthetic rootfs is
//! additionally populated with a loader + libc (which
//! `build_synthetic_rootfs` deliberately does not do, since a
//! self-contained static binary is simpler and matches this project's
//! existing precedent). Task 16 must build this fixture the same way
//! `kestrel-init` is built for capstone tests — a plain `cargo build
//! --tests` binary will NOT run once `chroot`/`pivot_root`'d into the
//! synthetic rootfs.
//!
//! argv[1] selects behavior:
//!
//! - `marker <path>` (test_create_then_start): writes the bytes `ran` to
//!   `<path>`, proving this process actually ran its entrypoint body, not
//!   just that the process exists. Exits 0.
//! - `exit <code>` (test_exit_code_propagates): exits immediately with
//!   `<code>` (parsed as `i32`).
//! - `sleep <secs>` (test_signal_exit_code): sleeps for `<secs>` seconds
//!   then exits 0 — gives the test time to deliver a signal (e.g.
//!   SIGKILL) before natural exit.
//! - `spawn-abandon <n> [count-path]` (test_zombie_reaping): forks `<n>`
//!   children, each of which exits immediately. This process (the
//!   parent) never `wait()`s on any of them, so each becomes a zombie
//!   the instant it exits — but Linux only reparents a zombie to PID 1
//!   once ITS OWN PARENT (this fixture process) itself exits, NOT
//!   immediately at fork time and NOT just because the child happened to
//!   exit first. Experimentally confirmed (Task 15 spec-compliance
//!   review): for the entire duration of this fixture's run — including
//!   the 2-second sleep below — every spawned child sits as a zombie
//!   (`Z <defunct>` in `ps`) parented to THIS fixture's own PID, not to
//!   PID 1, and is therefore NOT yet visible to `kestrel-init`'s reaper
//!   at all. Only once this fixture calls `process::exit` (after the
//!   sleep) does the kernel tear down its own process-table entry and
//!   reparent any still-unwaited children to PID 1 — that is the exact
//!   moment `kestrel-init`'s reaper first gets a chance to observe and
//!   reap them. Task 16's `test_zombie_reaping` must account for this:
//!   it can only assert reaping has happened AFTER this fixture process
//!   itself has exited, not while it's still in its 2-second sleep.
//!   Because `fork()` can fail (e.g. under cgroup `pids.max` pressure,
//!   which `test_zombie_reaping` deliberately courts, per this phase's
//!   plan), a failed `fork()` stops the spawn loop immediately (rather
//!   than looping past the failure) without panicking, and prints a
//!   message to stderr. If `[count-path]` is supplied, this fixture
//!   writes the ACTUAL number of children successfully forked (a plain
//!   decimal string, no trailing newline) to that path once the spawn
//!   loop ends, so a real test can assert against the achieved count
//!   instead of assuming all `<n>` always succeed.
//! - `hook-marker <file-path> <phase-label>` (test_hooks_fire_in_order,
//!   Task 16): opens `<file-path>` in append mode (creating it if
//!   absent) and writes `<phase-label>\n` to it, then exits 0. Intended
//!   to be wired as the `args` of an OCI hook (`createRuntime`,
//!   `createContainer`, `startContainer`, `poststart`, `poststop`) so
//!   each hook invocation appends its own phase label to a single shared
//!   file — Task 16 can then read that file back after the full
//!   lifecycle and assert the phase labels appear in the exact expected
//!   order. `<phase-label>` is an opaque string chosen by the caller
//!   (e.g. "createRuntime", "poststart") — this fixture does not
//!   validate or interpret it. Note: `createContainer`/`startContainer`
//!   hooks run INSIDE the container's namespaces (per
//!   `kestrel-init::main`'s hook-running order), so `<file-path>` for
//!   those two phases must be a path valid inside the container's
//!   mount namespace (e.g. bind-mounted or otherwise reachable from the
//!   synthetic rootfs), NOT assumed to be the same host path used for
//!   the `createRuntime`/`poststart`/`poststop` hooks, which run on the
//!   host side.
//! - anything else (including no argv[1] at all): no-op, exits 0
//!   (behaves like `/bin/true`).

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("marker") => {
            let path = args.get(2).expect("marker requires a <path> argument");
            std::fs::write(path, b"ran").unwrap_or_else(|e| panic!("write marker file {path}: {e}"));
        }
        Some("exit") => {
            let code_str = args.get(2).expect("exit requires a <code> argument");
            let code: i32 = code_str.parse().unwrap_or_else(|e| panic!("parse exit code {code_str:?}: {e}"));
            std::process::exit(code);
        }
        Some("sleep") => {
            let secs_str = args.get(2).expect("sleep requires a <secs> argument");
            let secs: u64 = secs_str.parse().unwrap_or_else(|e| panic!("parse sleep secs {secs_str:?}: {e}"));
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        Some("spawn-abandon") => {
            let n_str = args.get(2).expect("spawn-abandon requires an <n> argument");
            let n: usize = n_str.parse().unwrap_or_else(|e| panic!("parse spawn-abandon count {n_str:?}: {e}"));
            let count_path = args.get(3);
            let mut spawned: usize = 0;
            for _ in 0..n {
                // SAFETY: plain fork() with no shared state manipulated
                // between the fork and the child's immediate exit; safe
                // in both parent and child.
                let pid = unsafe { libc::fork() };
                if pid == -1 {
                    // fork() failed (e.g. cgroup pids.max pressure, which
                    // test_zombie_reaping deliberately courts). Stop
                    // spawning further children rather than looping past
                    // a failure. Don't panic/abort here: a partial-
                    // success count is more useful to the caller than a
                    // hard crash, but make the failure visible on
                    // stderr in case anyone is watching interactively.
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "spawn-abandon: fork() failed after spawning {spawned}/{n} children: {err}"
                    );
                    break;
                }
                if pid == 0 {
                    // Child: exit immediately WITHOUT waiting on anything
                    // or spawning further children. This process (the
                    // parent) never wait()s on this pid either, so it
                    // becomes a zombie the instant it exits — but that
                    // zombie stays parented to THIS fixture process, NOT
                    // PID 1, until this fixture itself exits. Linux only
                    // reparents an orphaned/unwaited child to PID 1 (and
                    // hence makes it visible to kestrel-init's reaper)
                    // once the child's actual parent exits — not
                    // immediately at fork time, and not merely because
                    // the child exited before the parent did. See this
                    // file's top-level doc comment for the full
                    // explanation.
                    std::process::exit(0);
                }
                spawned += 1;
            }
            if let Some(path) = count_path {
                // File-based signal (same precedent as the `marker` and
                // `hook-marker` branches above): lets a real test learn
                // the ACTUAL achieved fork count rather than assuming
                // all `n` always succeed. Written now (before the sleep
                // below) so the count is available as soon as spawning
                // finishes, not only after this process exits.
                std::fs::write(path, spawned.to_string())
                    .unwrap_or_else(|e| panic!("write spawn-abandon count file {path}: {e}"));
            }
            // Deliberately never wait() on any of them. This sleep is a
            // grace window during which every spawned child remains a
            // zombie parented to THIS fixture's own PID (not PID 1) —
            // see the doc comment above for why kestrel-init's reaper
            // cannot observe them yet during this window. Reparenting to
            // PID 1, and therefore the reaper's first chance to reap
            // them, happens only once this fixture itself exits below.
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        Some("hook-marker") => {
            let path = args.get(2).expect("hook-marker requires a <file-path> argument");
            let phase = args.get(3).expect("hook-marker requires a <phase-label> argument");
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| panic!("open hook-marker file {path}: {e}"));
            writeln!(f, "{phase}").unwrap_or_else(|e| panic!("append to hook-marker file {path}: {e}"));
        }
        _ => {}
    }
}
