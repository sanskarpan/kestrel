// crates/kestrel-runtime/src/start.rs
//
//! `start` — unblocks the exec FIFO `kestrel-init` is blocked reading (see
//! `create.rs`'s own doc comment and `kestrel-init`'s `fifo::block_until_started`),
//! writes the `Running` state.json, then runs `poststart` hooks. Per
//! SPEC.md §9.3's hook-ordering table, `poststart` hooks run AFTER `start`
//! returns (i.e. after the container process has actually been unblocked),
//! not before.

use std::io::Write;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kestrel_oci::state::{State, Status};

/// Total budget [`open_fifo_for_write_bounded`] allows for a reader to show
/// up on the exec FIFO before giving up. Generous relative to how fast a
/// healthy `kestrel-init` reaches `fifo::block_until_started` (rootfs
/// staging + `createContainer` hooks + `pivot_root`, all local filesystem
/// work), but still a hard, human-perceptible bound rather than "forever".
const FIFO_READER_WAIT_BUDGET: Duration = Duration::from_secs(10);

/// How long to sleep between non-blocking open probes while waiting for a
/// reader. Short enough that the bound above is actually honored promptly
/// once a reader (or the death of the container process) shows up.
const FIFO_READER_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Total budget [`resolve_entrypoint_host_pid`] allows for `kestrel-init`
/// to actually fork the entrypoint (it still has `startContainer` hooks to
/// run first) before giving up. Best-effort only — see that function's own
/// doc comment for what happens on timeout.
const ENTRYPOINT_PID_WAIT_BUDGET: Duration = Duration::from_secs(5);
const ENTRYPOINT_PID_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub fn start(id: &str, run_dir: &Path) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = State::read(&state_json_path)?;
    anyhow::ensure!(
        state.status == Status::Created,
        "cannot start container {id}: status is {:?}, expected Created",
        state.status
    );

    // Same host-path formula `create.rs` uses to `mkfifo` this file:
    // `run_dir.join(id).join("exec.fifo")`. Must match byte-for-byte since
    // `create.rs` created the FIFO at exactly this path.
    let fifo_host_path = run_dir.join(id).join("exec.fifo");
    let mut fifo = open_fifo_for_write_bounded(
        &fifo_host_path,
        state.pid,
        FIFO_READER_WAIT_BUDGET,
        FIFO_READER_POLL_INTERVAL,
    )
    .with_context(|| format!("opening {}", fifo_host_path.display()))?;
    let kestrel_init_host_pid = state.pid;
    fifo.write_all(&[0u8])
        .context("unblocking kestrel-init via exec fifo")?;

    // Write `Running` IMMEDIATELY — before attempting to resolve the
    // entrypoint's real pid below, not after. A short-lived container can
    // run its ENTIRE lifecycle (fork, exec, exit, get reaped, final
    // `Stopped`/`exit_code` write) in well under a second — faster than
    // this function's own pid-resolution polling loop, in the worst case,
    // takes to give up. Writing `Running` first, then treating the
    // pid-resolution step below as a separate, later, NON-clobbering
    // update (re-reading fresh state rather than reusing this stale
    // in-memory copy) avoids a real race this task hit directly: writing
    // `Running` only AFTER the (slow, best-effort) pid resolution finishes
    // could stomp back over a `Stopped` status kestrel-init's reaper had
    // already written in the meantime, permanently corrupting state.json
    // for an already-finished container.
    state.status = Status::Running;
    state.write_atomic(&state_json_path)?;

    // Best-effort: resolve the entrypoint's real, HOST-namespace pid and
    // record it in place of kestrel-init's own — see
    // `resolve_entrypoint_host_pid`'s own doc comment for why this must
    // happen HERE (host-side), not inside `kestrel-init` itself. Failure
    // to resolve within budget is NOT fatal to `start()`: `state.pid`
    // simply keeps its prior value (kestrel-init's own pid) in that case,
    // exactly as it always did before this pid-tracking feature existed.
    if let Some(entrypoint_pid) = kestrel_init_host_pid
        .and_then(|p| resolve_entrypoint_host_pid(p, ENTRYPOINT_PID_WAIT_BUDGET, ENTRYPOINT_PID_POLL_INTERVAL))
    {
        // Re-read fresh rather than reusing the in-memory `state` from
        // above: kestrel-init's reaper may have ALREADY advanced
        // status/exit_code by the time this resolves (same short-lived-
        // container race described above), and this merge must only ever
        // touch the `pid` field, never regress status/exit_code back to
        // what they were at the top of this function. Best-effort:
        // swallow a read/write failure here rather than failing `start()`
        // over a pid-tracking nicety — the container is already correctly
        // running (or finished) regardless of whether this refinement
        // lands.
        if let Ok(mut latest) = State::read(&state_json_path) {
            latest.pid = Some(entrypoint_pid);
            let _ = latest.write_atomic(&state_json_path);
        }
    }

    // poststart hooks — run AFTER the FIFO write above (per SPEC.md
    // §9.3's table: "after start returns"), using kestrel_oci::hooks::run_hooks
    // (already built in Task 4, lives in kestrel-oci).
    let bundle = crate::bundle::load(&state.bundle)?;
    kestrel_oci::hooks::run_hooks(&poststart_hooks(&bundle), &[])?;

    Ok(())
}

/// Opens `fifo_host_path` for writing without the risk of blocking forever.
///
/// A plain blocking `open(..., O_WRONLY)` on a FIFO does not return until
/// some OTHER process has the same FIFO open for reading — normally
/// `kestrel-init`'s `fifo::block_until_started`, reached only after it
/// finishes staging the rootfs, running `createContainer` hooks, and
/// `pivot_root`. If `kestrel-init` dies anywhere in that sequence (a bad
/// rootfs, a failing hook, a mount error — anything) BEFORE it ever opens
/// the FIFO for reading, no reader will EVER appear, and a plain blocking
/// open here hangs this call — and its caller — forever with zero
/// diagnostic signal. This is a real failure mode this project's own Task
/// 16 capstone testing hit directly (a `devpts` `EINVAL` bug that killed
/// `kestrel-init` mid-bootstrap, which turned a five-minute test failure
/// into a multi-hour, silent hang).
///
/// Instead: probe with a non-blocking open in a loop. `open(2)`'s own
/// documented behavior for a write-only, non-blocking open on a FIFO with
/// no reader is to fail immediately with `ENXIO` rather than block — so
/// each failed probe is cheap, and this function's own liveness check
/// (`kill(pid, 0)`, the standard "is this process still there" idiom) can
/// run between attempts to fail fast with a clear error the moment the
/// container process is confirmed dead, instead of waiting out the full
/// timeout. If the process is still alive but no reader ever shows up
/// within [`FIFO_READER_WAIT_BUDGET`], this still gives up with a clear,
/// bounded error rather than hanging — a stuck-but-alive `kestrel-init` is
/// just as much a "don't block the caller forever" case as a dead one.
///
/// `container_pid` is `state.json`'s `pid` field at `Created` status —
/// `create.rs` records `kestrel-init`'s own (PID-1, host-namespace-visible)
/// pid there before the entrypoint exists, which is exactly the process
/// this function needs to watch (kestrel-init is the one that will open
/// the FIFO for reading). `None` (a `state.json` with no pid recorded,
/// which `create()` never actually produces but which this function does
/// not otherwise assume) simply skips the liveness check and relies on the
/// timeout alone.
///
/// `wait_budget`/`poll_interval` are parameters (rather than using the
/// module consts directly) purely so the unit tests below can exercise the
/// timeout path in milliseconds instead of actually waiting out
/// [`FIFO_READER_WAIT_BUDGET`]; `start()` itself always calls this with the
/// two module consts.
fn open_fifo_for_write_bounded(
    fifo_host_path: &Path,
    container_pid: Option<i32>,
    wait_budget: Duration,
    poll_interval: Duration,
) -> Result<std::fs::File> {
    use nix::errno::Errno;
    use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
    use nix::sys::stat::Mode;

    let start = Instant::now();
    loop {
        match open(fifo_host_path, OFlag::O_WRONLY | OFlag::O_NONBLOCK, Mode::empty()) {
            Ok(raw_fd) => {
                // A reader is present. Clear O_NONBLOCK before handing the
                // fd back — the caller's subsequent `write_all` expects
                // ordinary blocking-write semantics, not EAGAIN on a full
                // pipe buffer (irrelevant here in practice, since only a
                // single byte is ever written, but there is no reason to
                // hand back a surprising non-blocking fd).
                let flags = OFlag::from_bits_truncate(fcntl(raw_fd, FcntlArg::F_GETFL).context("fcntl F_GETFL on exec fifo")?);
                fcntl(raw_fd, FcntlArg::F_SETFL(flags & !OFlag::O_NONBLOCK))
                    .context("fcntl F_SETFL clearing O_NONBLOCK on exec fifo")?;
                // SAFETY: `raw_fd` was just returned by a successful `open`
                // above and is not otherwise tracked or closed anywhere
                // else — `File` takes sole ownership of it here.
                return Ok(unsafe { std::fs::File::from_raw_fd(raw_fd) });
            }
            Err(Errno::ENXIO) => {
                // No reader (yet). Distinguish "still starting up" from
                // "already dead" before deciding whether to keep waiting.
                if let Some(pid) = container_pid {
                    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                        anyhow::bail!(
                            "container process (pid {pid}) is no longer alive, and never opened \
                             the exec fifo for reading — it likely died during its own startup \
                             (rootfs staging, createContainer hooks, or pivot_root) before \
                             reaching its ready state; refusing to block forever waiting for a \
                             reader that will now never arrive"
                        );
                    }
                }
                if start.elapsed() >= wait_budget {
                    anyhow::bail!(
                        "timed out after {wait_budget:?} waiting for the container \
                         process to open the exec fifo for reading; the process is still alive \
                         but never reached its ready state in time"
                    );
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(e).with_context(|| format!("opening {} (non-blocking probe)", fifo_host_path.display()));
            }
        }
    }
}

/// Resolves the container entrypoint's pid AS SEEN FROM THIS (the
/// RUNTIME's, i.e. host) pid namespace, by polling
/// `/proc/<kestrel_init_host_pid>/task/<kestrel_init_host_pid>/children` —
/// the kernel's own "list this task's direct children" file, which (read
/// from here, the host namespace) reports pids relative to the READER's
/// namespace, not the target task's. This is the ONLY correct way to learn
/// this value: `kestrel-init` cannot determine it itself (see
/// `kestrel-init/src/main.rs`'s own note at the spot this responsibility
/// used to live, and `kestrel_oci::state::State::pid`'s doc comment) since
/// it runs inside a freshly unshared pid namespace with no visibility into
/// any ancestor namespace's view of its own children.
///
/// `kestrel-init` forks exactly one child in its whole lifetime (the
/// entrypoint, immediately after `startContainer` hooks complete) — so the
/// FIRST (and, in practice, only) entry ever seen in this children list is
/// unambiguously the entrypoint, no PID-matching heuristics needed.
///
/// Best-effort: `kestrel-init` still has real work to do (the
/// `startContainer` hooks, then the fork itself) between this function
/// being called and the child actually existing, so this polls up to
/// `wait_budget` rather than assuming the child is there instantly. `None`
/// on timeout — the caller must NOT treat that as fatal to `start()`
/// itself (the container is still starting up fine; only the pid-tracking
/// convenience this enables is degraded).
fn resolve_entrypoint_host_pid(kestrel_init_host_pid: i32, wait_budget: Duration, poll_interval: Duration) -> Option<i32> {
    let children_path = format!("/proc/{kestrel_init_host_pid}/task/{kestrel_init_host_pid}/children");
    let deadline = Instant::now() + wait_budget;
    loop {
        if let Ok(content) = std::fs::read_to_string(&children_path) {
            if let Some(pid) = content.split_whitespace().next().and_then(|s| s.parse::<i32>().ok()) {
                return Some(pid);
            }
        }
        // Early exit once `kestrel-init` itself is gone (exited — INCLUDING
        // "exited but not yet reaped", a zombie): a very short-lived
        // entrypoint can be forked, run, exit, get reaped, AND have
        // `kestrel-init` itself exit (after its own final `Stopped`/
        // `exit_code` write) all within a fraction of a second — much
        // faster than `wait_budget`, and nothing here reaps `kestrel-init`
        // itself (that is the caller's caller's job, well after `start()`
        // returns), so it can sit as a zombie for a while. Once
        // `kestrel-init` has exited there is nothing left to ever discover
        // here (the children list will stay permanently empty either way),
        // so continuing to poll would just burn the full budget for no
        // benefit — and, since this runs on the hot path of every
        // `start()` call, needlessly slow down every ordinary, successful
        // start of a short-lived container. A PLAIN `kill(pid, 0)`
        // liveness probe is NOT enough on its own here — it reports a
        // zombie as still "alive" (the process table entry exists until
        // reaped) — so this checks `/proc/<pid>/stat`'s own process-state
        // field for `Z` (zombie) too, in addition to the process being
        // gone entirely.
        if !kestrel_init_still_has_work_left(kestrel_init_host_pid) {
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(poll_interval);
    }
}

/// `true` unless `pid` is completely gone OR already a zombie (`/proc/<pid>
/// /stat`'s process-state field is `Z`) — see
/// `resolve_entrypoint_host_pid`'s own comment for why a plain
/// `kill(pid, 0)` liveness probe alone is not sufficient here. Parses
/// `/proc/<pid>/stat`'s `(comm)` field by searching for the LAST `)` (the
/// command name itself can contain spaces or parentheses, but nothing
/// after it can — `proc(5)`'s own documented parsing strategy) rather than
/// splitting naively on whitespace or the first `)`.
fn kestrel_init_still_has_work_left(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false; // process is completely gone
    };
    let Some(after_comm) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
        return true; // unparseable; assume still alive rather than give up early
    };
    !after_comm.trim_start().starts_with('Z')
}

/// `Hooks::poststart()` (a `getset`-derived `Getters` accessor) returns
/// `&Option<Vec<Hook>>`; `Spec::hooks()` likewise returns `&Option<Hooks>`.
/// Verified directly against the vendored `oci-spec-0.10.0` source
/// (`runtime/hooks.rs`'s `Hooks` struct and `runtime/mod.rs`'s `Spec`
/// struct, both `#[getset(get = "pub")]`) — same chain shape `create.rs`'s
/// own `bundle_create_runtime_hooks` already uses for `create_runtime()`.
fn poststart_hooks(bundle: &crate::bundle::Bundle) -> Vec<kestrel_oci::runtime::Hook> {
    bundle
        .spec
        .spec
        .hooks()
        .as_ref()
        .and_then(|h| h.poststart().clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::raw::RawSpec;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::io::Read;

    /// Builds a real, valid, minimal bundle on disk (config.json from
    /// `default_spec()`, matching `bundle.rs`'s own test pattern) plus a
    /// hand-written `Created`-status `state.json` and a real FIFO at the
    /// matching host path — exactly the prerequisite state Task 16's
    /// capstone will instead build via a real `create()` call, per this
    /// task's own scope note.
    fn setup(run_dir: &Path, bundle_dir: &Path, id: &str) {
        let spec = kestrel_oci::default_spec::default_spec();
        let raw = RawSpec {
            spec,
            extra: serde_json::Map::new(),
        };
        std::fs::create_dir_all(bundle_dir).unwrap();
        std::fs::write(
            bundle_dir.join("config.json"),
            serde_json::to_vec_pretty(&raw).unwrap(),
        )
        .unwrap();

        let container_dir = run_dir.join(id);
        std::fs::create_dir_all(&container_dir).unwrap();
        nix::unistd::mkfifo(
            &container_dir.join("exec.fifo"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();

        let state = State {
            oci_version: "1.0.2".to_string(),
            id: id.to_string(),
            status: Status::Created,
            pid: None,
            bundle: bundle_dir.to_path_buf(),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir, id))
            .unwrap();
    }

    /// Uses a FORKED CHILD (not a thread) to block-read the FIFO the way
    /// `kestrel-init`'s `fifo::block_until_started` would, matching this
    /// project's established fork-safety convention (see e.g.
    /// `kestrel-init/src/fifo.rs`'s own test). `start()` itself runs in
    /// the main test process (the "host side"); the forked child stands
    /// in for `kestrel-init`.
    #[test]
    fn test_start_unblocks_fifo_reader_and_writes_running_state() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        let bundle_dir = tmp.path().join("bundle");
        let id = "abc123";
        setup(&run_dir, &bundle_dir, id);

        let fifo_path = run_dir.join(id).join("exec.fifo");

        // SAFETY: fork() duplicates the (single-threaded, at this point in
        // the test) process; the child branch below only performs a
        // blocking open+read and then exits, no other non-async-signal-safe
        // work between fork and exit.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let result = (|| -> std::io::Result<()> {
                    let mut f = std::fs::OpenOptions::new().read(true).open(&fifo_path)?;
                    let mut buf = [0u8; 1];
                    f.read_exact(&mut buf)?;
                    Ok(())
                })();
                // SAFETY: _exit() is async-signal-safe and never returns;
                // used instead of std::process::exit so the forked child
                // never re-runs the parent's normal unwind/drop machinery.
                unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
            }
            ForkResult::Parent { child } => {
                start(id, &run_dir).expect("start should succeed");

                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => {}
                    other => panic!("fifo reader child exited abnormally: {other:?}"),
                }

                let state = State::read(&crate::state::state_json_path(&run_dir, id)).unwrap();
                assert_eq!(state.status, Status::Running);
            }
        }
    }

    #[test]
    fn test_start_rejects_non_created_status() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        let bundle_dir = tmp.path().join("bundle");
        let id = "abc123";
        setup(&run_dir, &bundle_dir, id);

        let state_json_path = crate::state::state_json_path(&run_dir, id);
        let mut state = State::read(&state_json_path).unwrap();
        state.status = Status::Running;
        state.write_atomic(&state_json_path).unwrap();

        let result = start(id, &run_dir);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    /// Reproduces, deterministically and without root, the exact failure
    /// mode `open_fifo_for_write_bounded`'s own doc comment describes: a
    /// container process that died before it ever opened the exec fifo for
    /// reading (standing in for a real `kestrel-init` that crashed
    /// mid-bootstrap, e.g. the real `devpts` `EINVAL` bug this task
    /// root-caused). Before this fix, `start()`'s plain blocking
    /// `OpenOptions::write(true).open(...)` would hang here FOREVER — no
    /// process will ever open the fifo for reading, since the pid recorded
    /// in `state.json` is already gone. After the fix, `start()` must
    /// return a clear `Err` promptly instead.
    ///
    /// The "already dead" pid is obtained the ordinary way — fork a child
    /// that exits immediately, then `waitpid` it so it is fully reaped —
    /// rather than fabricating an arbitrary pid number, so this stays a
    /// faithful proxy for "a real process that genuinely no longer exists"
    /// rather than relying on a made-up value never having been a pid.
    #[test]
    fn test_start_fails_fast_instead_of_hanging_when_container_process_already_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        let bundle_dir = tmp.path().join("bundle");
        let id = "dead-before-start";
        setup(&run_dir, &bundle_dir, id);

        // A real pid that is guaranteed to no longer exist by the time
        // `start()` runs: fork, exit immediately, reap.
        let dead_pid = match unsafe { fork() }.expect("fork") {
            ForkResult::Child => unsafe { libc::_exit(0) },
            ForkResult::Parent { child } => {
                waitpid(child, None).expect("reap the short-lived child");
                child
            }
        };

        let state_json_path = crate::state::state_json_path(&run_dir, id);
        let mut state = State::read(&state_json_path).unwrap();
        state.pid = Some(dead_pid.as_raw());
        state.write_atomic(&state_json_path).unwrap();

        // Bounded: if the hang-safety fix regressed, this call blocks
        // forever and the test itself would hang rather than fail cleanly
        // — that is an acceptable (if unfortunate) failure signature for a
        // regression test whose entire point is "must not hang", but to
        // keep the normal passing run fast this asserts completion well
        // under the (10s) production wait budget.
        let started_at = Instant::now();
        let result = start(id, &run_dir);
        let elapsed = started_at.elapsed();

        assert!(
            result.is_err(),
            "expected start() to fail when the container process is already dead, got {result:?}"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("no longer alive"),
            "expected a clear dead-process error message, got: {msg}"
        );
        assert!(
            elapsed < FIFO_READER_WAIT_BUDGET,
            "a dead process must be detected via the liveness check on the very first probe, \
             well before the full {FIFO_READER_WAIT_BUDGET:?} timeout budget elapses — took {elapsed:?}"
        );

        // No reader ever showed up, so state.json must NOT have been
        // advanced to Running.
        let state = State::read(&state_json_path).unwrap();
        assert_eq!(state.status, Status::Created);
    }

    /// The other half of the same robustness guarantee: even a container
    /// process that is genuinely still alive (this test process's own pid
    /// stands in for it) but that never opens the fifo for reading must not
    /// be waited on forever — `open_fifo_for_write_bounded` must give up
    /// once its wait budget elapses. Exercises the helper directly (rather
    /// than through `start()`) with a short, test-local budget so this
    /// doesn't have to actually wait out the real 10s production default.
    #[test]
    fn test_open_fifo_for_write_bounded_times_out_when_process_alive_but_no_reader_appears() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo_path = tmp.path().join("exec.fifo");
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();

        let own_pid = nix::unistd::getpid().as_raw();
        let budget = Duration::from_millis(200);
        let poll_interval = Duration::from_millis(20);

        let started_at = Instant::now();
        let result = open_fifo_for_write_bounded(&fifo_path, Some(own_pid), budget, poll_interval);
        let elapsed = started_at.elapsed();

        assert!(
            result.is_err(),
            "expected a timeout error when nothing ever reads the fifo, got {result:?}"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("timed out"),
            "expected a clear timeout error message, got: {msg}"
        );
        assert!(
            elapsed >= budget,
            "must not give up before the wait budget elapses — took {elapsed:?}, budget was {budget:?}"
        );
        assert!(
            elapsed < budget * 5,
            "must not overshoot the wait budget by a large margin — took {elapsed:?}, budget was {budget:?}"
        );
    }
}
