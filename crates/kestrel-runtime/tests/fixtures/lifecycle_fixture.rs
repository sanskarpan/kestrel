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
//! - `copy <src> <dst>` (Phase 9 Task 3's `create_from_layers.rs`): reads
//!   the full byte content of `<src>` and writes it verbatim to `<dst>`,
//!   then exits 0. Intended to be run as the container entrypoint with
//!   `<src>` a path contributed by a DIFFERENT overlay lower layer than
//!   the one this binary itself lives in (`/fixture`) — successfully
//!   reading `<src>` and having its content show up at the host-visible
//!   `<dst>` (in the overlay's upperdir) is the real proof that a
//!   multi-entry `lower_chain_ids` list actually merged more than one
//!   layer into the container's rootfs, not just that `create()` returned
//!   `Ok`.
//! - `ignore-sigterm <secs>` (Phase 9 Task 9's `kestreld` stop-grace-period
//!   test): installs `SIG_IGN` for `SIGTERM` (via a raw `libc::signal`
//!   call — this fixture has no need for a full `sigaction`-based handler,
//!   just "don't die"), then sleeps for `<secs>` seconds and exits 0 if
//!   never otherwise killed. Gives a real test a genuine, on-disk OCI
//!   container entrypoint that survives `kestrel-runtime kill <id>
//!   SIGTERM` (proving `kestreld`'s `POST /containers/:id/stop` grace-
//!   period path genuinely has to escalate to SIGKILL, rather than
//!   trivially succeeding on the first signal) while still dying
//!   immediately on SIGKILL, which cannot be caught or ignored.
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
//! - `echo-stdin` (Phase 9 Task 12's `kestreld` attach WS test): puts its
//!   own stdin (fd 0) into raw mode (`cfmakeraw`, i.e. `!ICANON &&
//!   !ECHO && ...`) if it's a tty — best-effort; a plain pipe stdin
//!   (`tcgetattr` fails with `ENOTTY`) just skips this step and falls
//!   through to the same byte-copy loop below — then reads whatever bytes
//!   arrive on stdin and writes them back to stdout verbatim, in a loop,
//!   until stdin hits EOF, then exits 0. Gives `kestreld`'s attach WS
//!   bridge test a real, on-disk OCI container entrypoint whose output is
//!   a deterministic, byte-for-byte echo of whatever the test sends over
//!   the WS connection. The raw-mode step specifically matters for the
//!   tty case: `nix::pty::openpty(None, None)` (`kestrel-shim/src/io.rs`)
//!   allocates a PTY with the kernel's default canonical-mode-plus-echo
//!   line discipline, same as a freshly-opened terminal — left as-is, the
//!   kernel itself would ALSO echo every byte written to the master back
//!   out (independent of, and IN ADDITION to, this fixture's own explicit
//!   echo below), doubling the output, and `ICANON` would additionally
//!   buffer input until a newline, which arbitrary test payloads aren't
//!   guaranteed to contain. Disabling both up front makes this fixture the
//!   ONLY source of echoed bytes and gives byte-at-a-time (not
//!   line-buffered) reads, so a test can assert an exact round-trip match.
//! - `alloc-hold <mib>` (Phase 9 Task 13's `kestreld` metrics-sampler
//!   tests — PSI-threshold detection and the OOM watcher): allocates
//!   `<mib>` mebibytes of memory in 1 MiB increments, each step written
//!   with a non-zero byte pattern (`0xAB`) and immediately
//!   `std::hint::black_box`ed — the SAME technique `kestrel-cgroup`'s own
//!   `crates/kestrel-cgroup/tests/integration.rs::test_memory_limit_ooms`
//!   established: a plain `vec![0u8; N]` for a large `N` specializes to
//!   Rust's `alloc_zeroed` (calloc-equivalent) fast path, whose pages
//!   stay backed by the kernel's shared read-only zero page until
//!   genuinely written — `memory.current` would never actually rise and
//!   no real memory pressure or OOM would ever occur with an all-zero
//!   vec. A short, fixed delay after each 1 MiB step gives a concurrent
//!   poller (`kestreld`'s metrics sampler) a real chance to observe the
//!   climb, rather than racing a near-instantaneous allocation loop. If
//!   this process is still alive once the full `<mib>` has been
//!   allocated (i.e. it was NOT OOM-killed along the way — either
//!   `<mib>` didn't actually exceed the caller's configured `memory.max`,
//!   or reclaim kept up), it holds the allocation and sleeps for a long,
//!   fixed window so a real test has ample time to observe whatever it's
//!   checking for before this process would otherwise exit on its own.
//! - `copyup-write <path> <delay-ms>` (Phase 9 Task 15's `kestreld`
//!   copy-up scanner test): writes a fixed, known byte string to `<path>`
//!   (intended to be a path that already exists in the container's LOWER
//!   overlay layer, so this first write is a real overlayfs copy-up),
//!   sleeps `<delay-ms>` milliseconds, then writes a second, different
//!   fixed byte string to the SAME `<path>` (a plain rewrite of an
//!   already-copied-up file — no NEW copy-up, since the path already
//!   exists in the upperdir), then sleeps a further 5 seconds so a real
//!   test has ample time to poll for (or rule out) events after each
//!   write before this process exits.
//! - `trigger-personality` (Phase 9 Task 16's `kestreld` seccomp-notify
//!   end-to-end test): calls `personality(0xffffffff)` — the exact same
//!   syscall Phase 5's own `kestrel-security/tests/notify.rs`/`seccomp.rs`
//!   use for their own `SCMP_ACT_NOTIFY` tests, chosen here for the same
//!   reason (harmless, side-effect-free, and unlikely to already be
//!   filtered/emulated by anything else in the call path). Blocks until
//!   the container's real seccomp-notify supervisor chain (`kestrel-init`'s
//!   `exec_into` -> `SCM_RIGHTS` -> `kestrel-shim`'s `run_notify_loop`)
//!   responds — libseccomp's default `ENOSYS` response, per `kestrel-
//!   security::notify::decode_and_respond`. Ignores whatever `personality`
//!   itself returns (this fixture doesn't assert on it — the REAL
//!   assertion, that a `seccomp.violation` event reached `kestreld`'s
//!   event bus with the right syscall name, happens entirely on the test's
//!   own side), then sleeps briefly so a real test has a comfortable
//!   window to observe the resulting event before this process exits.
//!   Confirmed via a real, instrumented reproduction during this task's
//!   own development that the whole notify round trip (kernel suspends
//!   the syscall -> `kestrel-shim`'s supervisor receives, decodes, and
//!   responds -> kernel resumes the caller with `-ENOSYS`) completes in
//!   roughly **tens of microseconds** once the shim is already blocked
//!   waiting on `receive()` — comfortably faster than an HTTP-round-trip-
//!   driven test can react to after `start` returns. The real capstone
//!   test (`crates/kestreld/src/main.rs`) accounts for this by opening its
//!   attach WS connection (the only thing that makes `kestreld` a live
//!   subscriber to the shim's seccomp-event broadcast — see `api::attach`'s
//!   own doc comment) BEFORE calling `start`, not after.
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
        Some("ignore-sigterm") => {
            let secs_str = args.get(2).expect("ignore-sigterm requires a <secs> argument");
            let secs: u64 = secs_str
                .parse()
                .unwrap_or_else(|e| panic!("parse ignore-sigterm secs {secs_str:?}: {e}"));
            // SAFETY: installing SIG_IGN for SIGTERM via the raw libc
            // `signal(2)` wrapper. No other signal handling exists in this
            // process to interact badly with, and nothing between this
            // call and the plain `thread::sleep` below touches any
            // non-async-signal-safe state from a handler context (there is
            // no handler at all — SIG_IGN is a kernel-level disposition,
            // not a callback) — a plain FFI call with no aliasing/lifetime
            // hazards.
            let prev = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            if prev == libc::SIG_ERR {
                panic!(
                    "installing SIG_IGN for SIGTERM failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        Some("copy") => {
            let src = args.get(2).expect("copy requires a <src> argument");
            let dst = args.get(3).expect("copy requires a <dst> argument");
            let content = std::fs::read(src).unwrap_or_else(|e| panic!("read copy src {src}: {e}"));
            std::fs::write(dst, content).unwrap_or_else(|e| panic!("write copy dst {dst}: {e}"));
        }
        Some("echo-stdin") => {
            // Best-effort: put stdin (fd 0) into raw mode if it's a tty —
            // see this file's own top-level doc comment for exactly why
            // (avoiding the kernel's own PTY-echo doubling this fixture's
            // own echo below, and avoiding ICANON's newline-buffering).
            // `tcgetattr` failing (ENOTTY, the non-tty/pipe-stdin case) is
            // expected and fine: just skip straight to the byte-copy loop.
            //
            // SAFETY: `term` is a valid, fully-initialized (zeroed, then
            // populated by a successful `tcgetattr`) `libc::termios` for
            // the duration of both raw calls; fd 0 is this process's own
            // stdin, valid for the process's entire lifetime.
            unsafe {
                let mut term: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(0, &mut term) == 0 {
                    libc::cfmakeraw(&mut term);
                    libc::tcsetattr(0, libc::TCSANOW, &term);
                }
            }
            use std::io::{Read, Write};
            let mut stdin = std::io::stdin();
            let mut stdout = std::io::stdout();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if stdout.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = stdout.flush();
                    }
                    Err(_) => break,
                }
            }
        }
        Some("alloc-hold") => {
            let mib_str = args.get(2).expect("alloc-hold requires a <mib> argument");
            let mib: usize = mib_str.parse().unwrap_or_else(|e| panic!("parse alloc-hold mib {mib_str:?}: {e}"));
            const ONE_MIB: usize = 1024 * 1024;
            const STEP_DELAY: std::time::Duration = std::time::Duration::from_millis(8);
            // Grown incrementally (not one big `vec![0xAB; mib * ONE_MIB]`)
            // specifically so each step's real page-fault/reclaim cost is
            // spread out over wall-clock time via the delay below, giving a
            // concurrent poller a real chance to observe the climb — see
            // this file's own top-level doc comment for the full
            // reasoning (both on why non-zero bytes are required at all,
            // and why incremental+delayed rather than one big allocation).
            let mut v: Vec<u8> = Vec::new();
            for _ in 0..mib {
                v.extend(std::iter::repeat_n(0xABu8, ONE_MIB));
                std::hint::black_box(&v);
                std::thread::sleep(STEP_DELAY);
            }
            std::hint::black_box(&v);
            // Not OOM-killed along the way (e.g. `<mib>` didn't actually
            // exceed the caller's memory.max) — hold the allocation and
            // give a real test ample time to observe whatever it's
            // checking for before this process would otherwise exit.
            std::thread::sleep(std::time::Duration::from_secs(300));
        }
        Some("copyup-write") => {
            let path = args.get(2).expect("copyup-write requires a <path> argument");
            let delay_ms_str = args.get(3).expect("copyup-write requires a <delay-ms> argument");
            let delay_ms: u64 = delay_ms_str
                .parse()
                .unwrap_or_else(|e| panic!("parse copyup-write delay-ms {delay_ms_str:?}: {e}"));
            std::fs::write(path, b"first-write-triggers-copy-up")
                .unwrap_or_else(|e| panic!("write {path} (first write): {e}"));
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            std::fs::write(path, b"second-write-same-path-no-new-copyup")
                .unwrap_or_else(|e| panic!("write {path} (second write): {e}"));
            std::thread::sleep(std::time::Duration::from_secs(5));
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
        Some("trigger-personality") => {
            let _ = unsafe { libc::personality(0xffffffff) };
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        _ => {}
    }
}
