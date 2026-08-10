// crates/kestrel-ns/src/stages.rs
//
//! The three-stage fork/unshare dance that turns a [`NamespacePlan`] into a
//! running init process inside the requested namespaces.
//!
//! ```text
//! stage0 (runtime, host namespaces)
//!   `-- fork --> stage1 (all namespaces except PID; still has old PID)
//!                  `-- unshare(CLONE_NEWUSER), write id maps via stage0
//!                  `-- unshare(rest)
//!                  `-- unshare(CLONE_NEWPID)   (doesn't move the caller)
//!                  `-- fork --> stage2 == PID 1 of the new pid namespace
//!                                 `-- child_action() [never returns]
//!                  `-- report stage2's pid back to stage0, then _exit(0)
//! ```
//!
//! Splitting `CLONE_NEWPID` out of stage1's own `unshare()` call and into a
//! second `fork()` is not optional: `unshare(CLONE_NEWPID)` only changes
//! which namespace *future children* of the caller are born into — the
//! caller itself stays in its original PID namespace. The only way to get a
//! process that is actually PID 1 of the new namespace is to fork again
//! after that unshare.

use std::os::fd::RawFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, setresgid, setresuid, ForkResult, Gid, Pid, Uid};

use crate::idmap::write_id_maps;
use crate::sync::{recv_sync_timeout, send_sync, Sync};
use crate::threading::assert_single_threaded;
use crate::types::NamespacePlan;

pub struct StageResult {
    pub init_pid: Pid,
    pub stage1_pid: Pid,
}

/// `child_action` must never return (it becomes stage2 / PID 1 of the new
/// namespace and its only legitimate exits are `_exit`/`exec`/a fatal
/// signal). The plan text specified `impl FnOnce() -> !` to make that a
/// compiler-enforced contract, but on the installed toolchain
/// (`rustc 1.97.1`) using the never type `!` as the `Output` of a `Fn*`
/// trait bound still hits `E0658: the `!` type is experimental`
/// (rust-lang/rust#35121) — `-> !` is stable for a concrete fn/closure
/// item's own signature, but not yet for unifying a generic bound's
/// associated `Output` type with `!`. `impl FnOnce()` (`Output = ()`)
/// accepts the same closures unchanged, since a real `-> !` expression
/// (`loop {}`, `libc::_exit(..)`) coerces to `()` at the call site just as
/// readily as it coerces to any other type. The never-returns contract is
/// therefore enforced at the one call site instead (see `stage1` below):
/// if `child_action` ever did return, control falls through to an explicit
/// `_exit` rather than back into stage1's own code.
///
/// Side effect: marks the CALLING process as a `PR_SET_CHILD_SUBREAPER`
/// permanently (see the comment at the `set_child_subreaper` call below for
/// what that means in practice — it is process-wide and outlives this
/// call).
pub fn run_stages(
    plan: &NamespacePlan,
    cgroup_fd: Option<RawFd>,
    child_action: impl FnOnce() + 'static,
) -> Result<StageResult> {
    assert_single_threaded()?;

    // A NamespacePlan with id maps but no User namespace, or a User
    // namespace but no id maps, is an inconsistent caller error: the maps
    // would be silently ignored by stage1's has_user_ns() gating below,
    // which is exactly the kind of "quietly runs without a user namespace"
    // bug worth catching here instead of downstream.
    if plan.has_user_ns() {
        anyhow::ensure!(
            !plan.uid_maps.is_empty() && !plan.gid_maps.is_empty(),
            "NamespacePlan requests a user namespace but uid_maps/gid_maps are empty"
        );
    } else {
        anyhow::ensure!(
            plan.uid_maps.is_empty() && plan.gid_maps.is_empty(),
            "NamespacePlan has id maps set but does not request a user namespace \
             — the maps would be silently ignored"
        );
    }

    // The caller of `run_stages` must be a "child subreaper"
    // (`prctl(PR_SET_CHILD_SUBREAPER)`) *before* stage1 is forked. Without
    // it, Linux's orphan-reparenting rule ("man 2 prctl") skips straight
    // past every live ancestor and hands an orphaned process to the
    // namespace's real PID 1 — it does NOT fall back to the nearest live
    // grandparent. Stage1 deliberately `_exit`s right after handing off
    // `init_pid`, which orphans stage2 on purpose; without this call, the
    // returned `init_pid` would no longer be a child of this process by
    // the time the caller tries to `waitpid` on it (observed as ECHILD
    // while developing this: the plan text omitted this call, which is a
    // real gap, not a hypothetical one). Not gated behind
    // `plan.has_pid_ns()` — stage1 always deliberately exits between
    // forking stage2 and the caller observing `init_pid`, regardless of
    // whether a *new* PID namespace was requested, so the same reparenting
    // hazard applies either way.
    //
    // Scope, per `man prctl`: this marks the CALLING PROCESS (not just this
    // invocation, not this call's descendants specifically) as a subreaper,
    // PERMANENTLY — the attribute is NOT inherited by fork/clone children
    // (so stage1/stage2/`init_pid` are unaffected by it themselves), but it
    // IS process-wide state on the caller that persists until an explicit
    // `set_child_subreaper(false)`, which this code never issues. From this
    // point on, *every* orphan of this process — not just descendants of
    // this particular `run_stages` call — reparents here instead of to
    // PID 1. A future runtime binary (Phase 8) that also spawns unrelated
    // subprocesses will get their orphans subreaped here too; that is a
    // deliberate tradeoff for now (the call itself is idempotent and cheap
    // to repeat), not an oversight — but callers should not assume this can
    // be scoped to one container or undone per call.
    nix::sys::prctl::set_child_subreaper(true).context("prctl(PR_SET_CHILD_SUBREAPER)")?;

    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("creating sync socketpair")?;
    let parent_sock = UnixDatagram::from(a);
    let child_sock = UnixDatagram::from(b);

    // Everything EXCEPT CLONE_NEWPID. PID ns is unshared in stage1, because
    // the caller of unshare(CLONE_NEWPID) stays in the old namespace — only
    // its subsequent children land in the new one.
    let mut flags = plan.clone_flags();
    flags.remove(CloneFlags::CLONE_NEWPID);

    // SAFETY: `fork()` duplicates the whole address space. Between this
    // fork and the child's eventual `_exit`, the child path below only
    // performs: dropping a socket (a plain `close(2)`, async-signal-safe),
    // calling `stage1` (which itself does only async-signal-safe work up to
    // its own `_exit` — see the SAFETY comments in `stage1`), and on error,
    // serializing a short string and doing a `send(2)` over the sync
    // socket before `_exit`. None of that touches the parent's in-flight
    // heap state or holds a lock the parent might have held at fork time
    // (both sockets and the plan/child_action closure are either moved in
    // or already fully constructed before the fork), so there is no
    // fork-safety hazard here.
    match unsafe { fork() }.context("fork (stage1)")? {
        ForkResult::Child => {
            drop(parent_sock);
            // Any error here must be REPORTED over the socket, not just
            // exited on, or the parent hangs forever on the sync read with
            // no diagnosis. If the report itself fails too (e.g. the
            // parent already gave up and the socket is gone), fall back to
            // a stderr breadcrumb rather than losing the error entirely —
            // safe here since this is well after fork, still
            // single-threaded, and not running in a signal handler.
            if let Err(e) = stage1(&child_sock, flags, plan, cgroup_fd, child_action) {
                if send_sync(&child_sock, &Sync::Error(format!("{e:#}"))).is_err() {
                    eprintln!("kestrel: stage1 failed and could not report it: {e:#}");
                }
            }
            // SAFETY: `_exit(2)` is async-signal-safe and never returns. It
            // is used here instead of a normal return/panic because this
            // process is a forked copy of the test/runtime process: letting
            // control fall back through Rust's normal unwind/drop/return
            // path would re-run the parent's remaining stack frames and
            // Drop impls a second time in this process (e.g. double-closing
            // fds, re-entering the parent's test harness), and a panic here
            // would print a duplicate/misleading panic message attributed
            // to the wrong process. `_exit` guarantees this process's life
            // ends exactly here with no further code executed.
            unsafe { libc::_exit(1) };
        }
        ForkResult::Parent { child: stage1_pid } => {
            drop(child_sock);
            stage0(&parent_sock, stage1_pid, plan).map(|init_pid| StageResult {
                init_pid,
                stage1_pid,
            })
        }
    }
}

// ─────────────────────────── STAGE 0 (runtime, host namespaces) ───────────
/// Thin wrapper around [`stage0_inner`] that guarantees `stage1_pid` (and,
/// transitively, any not-yet-reported stage2 it may have already forked) is
/// killed and reaped on every error path, not just left to leak.
/// `stage0_inner`'s only success path reaps `stage1_pid` itself (stage1 has
/// already `_exit`ed by the time `ReportPid` is read, so that reap is
/// immediate) — but every early `bail!`/`?` in between (a timed-out
/// `RequestMaps`, a failed `write_id_maps`, a malformed sync message, a
/// timed-out `ReportPid`) previously returned straight past that without
/// touching `stage1_pid` at all. If the `ReportPid` timeout specifically
/// fires *after* stage1 already forked stage2, this also SIGKILLs stage1 —
/// note this cannot reach into stage2 itself (we never learned its pid), so
/// a stage2 that's already running and detached from stage1 at that point
/// is not addressed here; that gap is inherent to not having an `init_pid`
/// to act on, not something this wrapper can close.
fn stage0(sock: &UnixDatagram, stage1_pid: Pid, plan: &NamespacePlan) -> Result<Pid> {
    let result = stage0_inner(sock, stage1_pid, plan);
    if result.is_err() {
        // Best-effort — stage1 may still be alive if we're bailing out
        // early; don't leave it running or unreaped.
        let _ = nix::sys::signal::kill(stage1_pid, nix::sys::signal::Signal::SIGKILL);
        let _ = waitpid(stage1_pid, None);
    }
    result
}

fn stage0_inner(sock: &UnixDatagram, stage1_pid: Pid, plan: &NamespacePlan) -> Result<Pid> {
    // Mirror stage1's own `if plan.has_user_ns()` gating exactly: stage1
    // only sends `RequestMaps` (and later waits for `MapsDone`) when it's
    // about to unshare a user namespace. When the plan has no user
    // namespace, stage1 skips that whole handshake and goes straight to
    // `ReportPid` — so stage0 must skip the same handshake in lockstep, or
    // it blocks on a `RequestMaps` that will never arrive until the
    // timeout fires.
    if plan.has_user_ns() {
        match recv_sync_timeout(sock, Duration::from_secs(10))? {
            Sync::RequestMaps => {}
            Sync::Error(e) => bail!("stage1 failed before maps: {e}"),
            other => bail!("unexpected sync from stage1: {other:?}"),
        }

        write_id_maps(stage1_pid, &plan.uid_maps, &plan.gid_maps)?;
        send_sync(sock, &Sync::MapsDone)?;
    }

    let init_pid = match recv_sync_timeout(sock, Duration::from_secs(30))? {
        Sync::ReportPid(p) => Pid::from_raw(p),
        Sync::Error(e) => bail!("stage1 failed after maps: {e}"),
        other => bail!("expected ReportPid, got {other:?}"),
    };

    // Stage1 exits immediately after reporting; reap it so it does not
    // linger as a zombie in the runtime's process table.
    let _ = waitpid(stage1_pid, None);
    Ok(init_pid)
}

// ─────────── STAGE 1 (all namespaces except PID; still has old PID) ───────
fn stage1(
    sock: &UnixDatagram,
    flags: CloneFlags,
    plan: &NamespacePlan,
    cgroup_fd: Option<RawFd>,
    child_action: impl FnOnce() + 'static,
) -> Result<()> {
    // Join every pre-existing namespace in `plan.join` FIRST — before any
    // unshare() below, including before unshare(CLONE_NEWUSER). `setns()`
    // into a namespace owned by the HOST's original user namespace requires
    // capabilities in that owning user namespace. If we unshared a new user
    // namespace first (as the `plan.has_user_ns()` block below does), our
    // capabilities would become relative to that new, unprivileged-from-
    // the-host's-perspective namespace, and a subsequent `setns()` into a
    // host-owned namespace (e.g. a netns pinned by a plain host-level
    // helper process, not created inside any container's fresh user
    // namespace) would fail with EPERM. At this point in stage1 we still
    // hold whatever privileges `run_stages` was invoked with (real root,
    // per this project's rootful-only current scope) — this is the same
    // "join needs privilege in the target's owning userns" principle
    // `kestrel_ns::join::join_namespaces`'s own `JOIN_ORDER` doc comment
    // establishes for the `kestrel exec` call path, applied here for the
    // CREATE-time path for the first time. Empirically verified (see
    // `crates/kestrel-ns/tests/join_by_path.rs`,
    // `test_setns_into_host_owned_ns_succeeds_before_unshare_newuser_fails_after`
    // and `test_run_stages_join_reaches_pinned_namespace_not_hosts_own`):
    // setns() into a host-owned namespace succeeds before
    // unshare(CLONE_NEWUSER) and fails with EPERM after it, confirming the
    // ordering is load-bearing, not just a theoretical concern.
    for (ns_type, path) in &plan.join {
        let f = std::fs::File::open(path)
            .with_context(|| format!("opening namespace join target {}", path.display()))?;
        nix::sched::setns(&f, ns_type.clone_flag())
            .with_context(|| format!("setns into pre-existing {ns_type:?} namespace at {}", path.display()))?;
    }

    // Create the user namespace FIRST and alone. Combining it with the
    // others in one unshare() works, but separating makes the ordering
    // explicit and the failure modes far easier to read.
    if plan.has_user_ns() {
        unshare(CloneFlags::CLONE_NEWUSER).context("unshare(CLONE_NEWUSER)")?;
        send_sync(sock, &Sync::RequestMaps)?;
        match recv_sync_timeout(sock, Duration::from_secs(10))? {
            Sync::MapsDone => {}
            other => bail!("expected MapsDone, got {other:?}"),
        }
        // We are mapped to 0 inside the userns but our euid is still the
        // old value. setresuid makes us actually root in here, which the
        // remaining unshares require.
        setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
            .context("setresuid(0,0,0)")?;
        setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))
            .context("setresgid(0,0,0)")?;
    }

    // Everything else, minus user (already done) and pid (handled next).
    let rest = flags - CloneFlags::CLONE_NEWUSER;
    if !rest.is_empty() {
        unshare(rest).with_context(|| format!("unshare({rest:?})"))?;
    }

    // Does NOT move us. Our next child becomes PID 1 of the new namespace.
    if plan.has_pid_ns() {
        unshare(CloneFlags::CLONE_NEWPID).context("unshare(CLONE_NEWPID)")?;
    }

    let init_pid = match cgroup_fd {
        Some(fd) => {
            // SAFETY: stage1 runs single-threaded (assert_single_threaded()
            // was checked at the top of run_stages, and nothing in stage1
            // spawns a thread before reaching here).
            match unsafe { kestrel_cgroup::clone3::clone_into_cgroup(libc::SIGCHLD as u64, fd) }
                .context("stage1: placing PID 1 into cgroup via clone3")?
            {
                None => {
                    // STAGE 2 — we are PID 1, placed atomically in the
                    // cgroup before this instruction ran. `child_action` is
                    // documented to never return (see `run_stages`' doc
                    // comment for why this isn't the compiler-enforced `->
                    // !` the plan originally specified); if it somehow did,
                    // fall through to an explicit `_exit` rather than back
                    // into stage1's own frame, mirroring the fork()
                    // fallback arm below.
                    child_action();
                    // SAFETY: `_exit(2)` is async-signal-safe and never
                    // returns. Reached only if `child_action` broke its
                    // documented contract and returned instead of
                    // diverging — see the matching SAFETY comment on the
                    // fork() fallback arm below for the full rationale.
                    unsafe { libc::_exit(125) };
                }
                Some(pid) => pid,
            }
        }
        // SAFETY: `fork()` duplicates the whole address space. The child
        // arm below (stage2 == PID 1 of the new namespace) calls
        // `child_action()`, which by documented contract never returns
        // (its concrete callers always end in `loop {}` or `libc::_exit`)
        // and is the caller's responsibility to keep async-signal-safe/
        // fork-safe, same contract as `test_util::run_isolated`'s closure.
        // The `_exit` immediately below is an unreachable-in-practice
        // safety net (see its own SAFETY comment), not additional logic —
        // so no code from this function runs after `child_action()`
        // returns control to Rust in that child under any expected
        // circumstance. No lock or heap state from the parent (stage1) is
        // touched beyond what `child_action` itself captured before the
        // fork.
        None => match unsafe { fork() }.context("fork (stage2)")? {
            ForkResult::Child => {
                // STAGE 2 — we are PID 1. `child_action` is documented to
                // never return (see `run_stages`' doc comment for why this
                // isn't the compiler-enforced `-> !` the plan originally
                // specified).
                child_action();
                // SAFETY: `_exit(2)` is async-signal-safe and never
                // returns. Reached only if `child_action` broke its
                // documented contract and returned instead of diverging —
                // in that case we must not let control fall back into
                // stage1's own frame (which belongs to a different logical
                // process at this point) or return `()` where a `Pid` is
                // expected; `_exit` guarantees this process ends here with
                // a distinctive, greppable status instead.
                unsafe { libc::_exit(125) };
            }
            ForkResult::Parent { child } => child,
        },
    };

    send_sync(sock, &Sync::ReportPid(init_pid.as_raw()))?;

    // SAFETY: `_exit(2)` is async-signal-safe and never returns. Used here
    // instead of a normal `Ok(())` return so stage1 terminates immediately
    // after reporting the init pid, rather than unwinding back into
    // `run_stages`' `ForkResult::Child` arm (the caller of `stage1` in this
    // same forked process): that arm treats any return from `stage1` —
    // `Ok` included — as "done, fall through to `unsafe { libc::_exit(1)
    // }`", which would make this process (correctly) report success over
    // the socket and then (incorrectly) exit with status 1, misreporting
    // stage1 as failed to anything watching its exit status. `_exit(0)`
    // here guarantees stage1's process ends exactly here with the correct
    // status, cleanly orphaning PID 1 (the `child_action` process, reaped
    // by the subreaper set up in `run_stages`) without stage1 lingering.
    unsafe { libc::_exit(0) };
}
