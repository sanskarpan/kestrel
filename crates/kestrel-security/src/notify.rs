//! Seccomp userspace notification: receive one notified syscall request,
//! decode it, and respond with ENOSYS. See
//! docs/superpowers/specs/2026-08-03-phase5-security-design.md §4a and
//! SPEC.md §8.3.
//!
//! [`handle_one_notification`] does one receive/decode/respond cycle on an
//! already-installed notify fd (as returned by
//! [`crate::seccomp::install_seccomp`]); [`run_notify_loop`] is a thin
//! wrapper that repeats it until the fd errors out (e.g. because the
//! filtered process exited and the fd was closed).
//!
//! Corrections made vs. the plan's best-effort sketch of the libseccomp
//! notify API (verified against the vendored source under
//! `~/.cargo/registry/src/*/libseccomp-0.3.0/src/notify.rs`, plus that
//! crate's own `tests/notify.rs`, inside the Lima VM — this was flagged in
//! the plan as the single highest-uncertainty API surface in the whole
//! phase):
//!
//!   1. `ScmpNotifResp::new_error` takes **three** arguments —
//!      `(id: u64, error: i32, flags: ScmpNotifRespFlags)` — not the two
//!      the plan's sketch called it with (`new_error(req.id, libc::ENOSYS)`
//!      would not compile). Fixed by passing `ScmpNotifRespFlags::empty()`
//!      as the third argument, matching `tests/notify.rs`'s own usage.
//!   2. The `error` argument to `new_error` must be **negative** —
//!      `ScmpNotifResp::new_error` has `debug_assert!(error.is_negative())`
//!      in the vendored source. The plan's sketch passed `libc::ENOSYS`
//!      unmodified, which is the positive errno constant; this would trip
//!      the debug assertion in a debug build. Fixed by passing
//!      `-libc::ENOSYS`.
//!   3. The plan's sketch was missing `ScmpNotifRespFlags` from its
//!      `use libseccomp::{...}` line even though it's required for (1)
//!      above; added it. All of `ScmpNotifReq`, `ScmpNotifResp`,
//!      `ScmpNotifRespFlags`, and `notify_id_valid` are re-exported at the
//!      `libseccomp` crate root via `pub use notify::*;` in that crate's
//!      `src/lib.rs`, so a single `use libseccomp::{...}` line reaches all
//!      of them.
//!   4. Everything else in the plan's sketch matched the real API exactly:
//!      `ScmpNotifReq::receive(fd: ScmpFd) -> Result<Self>` with public
//!      fields `id: u64`, `pid: u32`, `data: ScmpNotifData` (itself with
//!      public `syscall: ScmpSyscall` and `args: [u64; 6]`);
//!      `notify_id_valid(fd: ScmpFd, id: u64) -> Result<()>`; `ScmpFd` is a
//!      plain `RawFd` (`i32`) type alias, so `fd.as_raw_fd()` is the right
//!      way to get one from a `BorrowedFd`; and
//!      `ScmpSyscall::get_name(self) -> Result<String>` (the syscall name
//!      lookup used to populate `NotifyEvent::syscall`).
//!
//! Post-review correction (code-quality pass after initial implementation):
//!
//!   5. `run_notify_loop` originally called [`handle_one_notification`] as
//!      one opaque unit and treated *any* error from it — including
//!      `notify_id_valid` failing for a single stale/raced request — as
//!      "the fd is closed, stop the whole loop." That's wrong: the notify
//!      fd is shared by every process governed by the filter, not
//!      per-process, so one dead process racing the TOCTOU window (this
//!      module's own doc comment on `handle_one_notification` already
//!      called that race out as expected/advisory) would silently kill the
//!      supervisor loop for every OTHER still-alive process sharing that
//!      filter, leaving their blocked syscalls hanging forever. Fixed by
//!      splitting into [`receive_request`] (its failure is the real
//!      "no more data is ever coming from this fd" signal — `run_notify_loop`
//!      ends on it) and [`decode_and_respond`] (its failure means only this
//!      one request was bad — `run_notify_loop` logs a warning and
//!      continues). `handle_one_notification` is kept as a public
//!      receive-then-respond convenience (used by callers, and this
//!      module's own tests, that want a single request/response cycle) but
//!      `run_notify_loop` no longer routes through it, so it can tell the
//!      two failure classes apart.
//!   6. `NotifyEvent.syscall`'s unknown-syscall fallback used
//!      `format!("syscall#{:?}", req.data.syscall)`. `ScmpSyscall` is
//!      `struct ScmpSyscall { nr: i32 }` with a private field, so its
//!      derived `Debug` renders as `"syscall#ScmpSyscall { nr: 59 }"`, not
//!      the clean `"syscall#59"` the code was trying to produce. Fixed
//!      using the crate's `impl From<ScmpSyscall> for i32` instead:
//!      `format!("syscall#{}", i32::from(req.data.syscall))`.
//!   7. The receive-vs-decode split in (5) above was still not quite right:
//!      a live root-gated repro (kill a process while its notify request is
//!      still queued, *before* anything ever calls `receive()` for it) shows
//!      that `ScmpNotifReq::receive()` **itself** can fail with the SAME
//!      per-process, non-fatal condition — not just `notify_id_valid`/
//!      `respond()` afterward. Confirmed against both the observed error
//!      (`SeccompErrno::ECANCELED`, "There was a system failure beyond the
//!      control of the library, check the errno value") and the kernel's
//!      own `seccomp_unotify(2)` man page inside the VM, which documents
//!      `SECCOMP_IOCTL_NOTIF_RECV` (the raw ioctl `receive()` wraps) as
//!      failing with `ENOENT` when "The target thread was killed by a
//!      signal as the notification information was being generated, or the
//!      target's (blocked) system call was interrupted by a signal
//!      handler" — libseccomp's C library collapses that (and other
//!      library-internal failures) into the single generic `-ECANCELED`
//!      return code rather than surfacing the raw kernel errno. So
//!      `ECANCELED` from `receive()` is, like a `notify_id_valid` failure,
//!      *usually* a **per-request** hiccup (this one target died
//!      mid-flight), not proof the fd/filter itself is gone.
//!
//!      HOWEVER — a second live repro (close the notify fd outright, then
//!      call `ScmpNotifReq::receive()` on the now-invalid fd number) shows
//!      libseccomp reports the EXACT SAME `SeccompErrno::ECANCELED` for a
//!      **genuinely, permanently broken fd** as it does for the
//!      recoverable one-process-died case — every single attempt, forever.
//!      There is no error-level way to tell these two situations apart; a
//!      bare "retry forever on ECANCELED" would therefore turn a
//!      closed/invalid fd into an infinite, non-blocking, 100%-CPU retry
//!      loop — strictly worse than the original bug (5) (which at least
//!      terminated). A third repro (this module's own root-gated test
//!      suite, building the actual one-dead-one-live-process scenario end
//!      to end) confirmed the *recoverable* case does resolve quickly in
//!      practice — typically the very next `receive()` call, sometimes
//!      immediately with no `ECANCELED` at all, returns the OTHER, live
//!      request directly. `run_notify_loop` therefore treats `ECANCELED`
//!      as retryable but bounds the retry count (see
//!      `MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS`): comfortably more than
//!      the handful of retries the recoverable case needs, but still small
//!      enough that a permanently broken fd fails fast (as a surfaced
//!      `Err`, not a silent, infinite spin) rather than pegging a CPU core
//!      forever. One consequence worth calling out for callers: closing
//!      the fd is itself one of the "permanently broken" cases, so a
//!      caller that ends the loop by closing the fd out from under it
//!      (as this module's own tests do) should expect `run_notify_loop` to
//!      return `Err` (the circuit breaker tripping) rather than a clean
//!      `Ok(())` — there is no way, with this library, to distinguish
//!      "deliberately closed" from any other permanently-broken-fd cause
//!      at this layer.

use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::time::SystemTime;

use anyhow::{Context, Result};
use libseccomp::error::SeccompErrno;
use libseccomp::{notify_id_valid, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};

/// One decoded seccomp-notify event: which process triggered it, which
/// syscall, with what arguments, and when this process observed it.
#[derive(Debug, Clone)]
pub struct NotifyEvent {
    pub pid: u32,
    pub syscall: String,
    pub args: [u64; 6],
    pub timestamp: SystemTime,
}

/// Blocks until one seccomp-notify request arrives on `fd`. Returns the raw
/// `libseccomp` error (not wrapped in `anyhow`) so callers — specifically
/// [`run_notify_loop`] — can inspect `.errno()` and distinguish "this one
/// request's target died mid-flight" (`SeccompErrno::ECANCELED`, see the
/// module-level correction #7) from a genuinely fatal, fd-is-gone failure.
fn receive_request(raw_fd: RawFd) -> std::result::Result<ScmpNotifReq, libseccomp::error::SeccompError> {
    ScmpNotifReq::receive(raw_fd)
}

/// Given an already-received request, does the TOCTOU-safe `notify_id_valid`
/// check, decodes it into a [`NotifyEvent`], and responds with ENOSYS (so
/// the calling process's blocked syscall returns a real, well-defined error
/// rather than hanging forever).
///
/// The TOCTOU check (`notify_id_valid`) is required by libseccomp's own
/// documented usage pattern — the notifying process may have been killed
/// or the notification ID may have been reused between the request
/// arriving and this function responding to it; skipping the check risks
/// responding to a stale or wrong request. This is expected to fail
/// occasionally in normal operation (a process can die at any point in that
/// window) — it is NOT a sign that the fd itself is broken, so callers must
/// not treat it the same as a [`receive_request`] failure.
fn decode_and_respond(raw_fd: RawFd, req: ScmpNotifReq) -> Result<NotifyEvent> {
    notify_id_valid(raw_fd, req.id).context("notify_id_valid check failed — request is stale")?;

    let syscall_name = req
        .data
        .syscall
        .get_name()
        .unwrap_or_else(|_| format!("syscall#{}", i32::from(req.data.syscall)));

    let event = NotifyEvent {
        pid: req.pid,
        syscall: syscall_name,
        args: req.data.args,
        timestamp: SystemTime::now(),
    };

    // `error` must be negative (ScmpNotifResp::new_error debug-asserts
    // this); `libc::ENOSYS` is the positive errno constant, so negate it.
    let resp = ScmpNotifResp::new_error(req.id, -libc::ENOSYS, ScmpNotifRespFlags::empty());
    resp.respond(raw_fd).context("responding to seccomp notif request")?;

    Ok(event)
}

/// How many consecutive `SeccompErrno::ECANCELED` failures [`run_notify_loop`]
/// will retry through before giving up and returning an error. See
/// module-level correction #7: `ECANCELED` from `receive()` is ambiguous
/// between "one target died mid-flight" (recoverable — confirmed to
/// resolve quickly in practice, typically within a retry or two) and "the
/// fd is genuinely closed/invalid" (never recoverable — confirmed to fail
/// identically on every attempt, forever). This bound is comfortably above
/// what the recoverable case needs, while still being small enough that
/// the unrecoverable case (each attempt on a closed fd returns
/// immediately, with no blocking) fails fast rather than spinning forever.
const MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS: u32 = 32;

/// Blocks until one seccomp-notify request arrives on `fd`, decodes it,
/// responds with ENOSYS, and returns the decoded event. A convenience
/// wrapper combining [`receive_request`] and [`decode_and_respond`] into a
/// single request/response cycle, for callers (and this module's own
/// tests) that want exactly one notification handled and don't need to
/// distinguish "fd is gone" from "this one request was stale" the way
/// [`run_notify_loop`] does.
pub fn handle_one_notification(fd: BorrowedFd) -> Result<NotifyEvent> {
    let raw_fd = fd.as_raw_fd();
    let req = receive_request(raw_fd).context("receiving seccomp notif request")?;
    decode_and_respond(raw_fd, req)
}

/// Repeatedly receives and responds to seccomp-notify requests on `fd`,
/// invoking `on_event` for each successfully decoded notification, until
/// the fd itself is genuinely exhausted (e.g. because it was closed).
///
/// Deliberately does NOT end the loop just because one particular request
/// failed — the notify fd is shared by every process the filter governs, so
/// a single bad request must not stop the supervisor from continuing to
/// service every other still-alive process sharing it. Two distinct
/// per-request failure shapes are both treated as "log and keep going":
///
///   - [`decode_and_respond`] failing (most commonly `notify_id_valid` or
///     `respond()` itself returning an error because that one target died
///     in the TOCTOU window between receiving and responding).
///   - [`receive_request`] itself failing with `SeccompErrno::ECANCELED`
///     (module-level correction #7): confirmed against the kernel's
///     `seccomp_unotify(2)` man page and a live repro that this specific
///     error USUALLY means "the target for the request the kernel was
///     about to hand back died or was signaled mid-flight," not "the
///     fd/filter is gone" — libseccomp's C library collapses several
///     internal failure modes into this one generic code, and a dead
///     single target is one of them. Retried, but only up to
///     [`MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS`] times in a row — see that
///     constant's doc for why an unbounded retry here would be its own,
///     worse bug.
///
/// Any OTHER error from [`receive_request`] — or `ECANCELED` recurring
/// [`MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS`] times with no successful
/// receive in between — is treated as fatal to the loop and ends it. A
/// clean "no more data, fd was closed" ending returns `Ok(())`; the
/// circuit breaker tripping returns `Err` instead, since — unlike a clean
/// close — it's a judgment call (we could be wrong that the fd is
/// actually dead) that's worth surfacing to the caller rather than
/// silently swallowing.
///
/// `kestreld` (Phase 9) is expected to call this from its own thread and
/// forward each event over SSE — this function itself has no HTTP/async
/// dependency, matching the design doc's split between the mechanism
/// (here) and the transport (later, in the daemon).
pub fn run_notify_loop(fd: BorrowedFd, mut on_event: impl FnMut(NotifyEvent)) -> Result<()> {
    let raw_fd = fd.as_raw_fd();
    let mut consecutive_cancellations = 0u32;
    loop {
        let req = match receive_request(raw_fd) {
            Ok(req) => {
                consecutive_cancellations = 0;
                req
            }
            Err(e) if e.errno() == Some(SeccompErrno::ECANCELED) && consecutive_cancellations < MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS => {
                consecutive_cancellations += 1;
                tracing::warn!(
                    error = %e,
                    attempt = consecutive_cancellations,
                    "seccomp-notify receive failed for one request (its target likely died or \
                     was signaled while the notification was being generated — see \
                     seccomp_unotify(2)'s SECCOMP_IOCTL_NOTIF_RECV ENOENT case); retrying so \
                     other processes sharing this filter keep being serviced"
                );
                continue;
            }
            Err(e) if e.errno() == Some(SeccompErrno::ECANCELED) => {
                anyhow::bail!(
                    "notify loop giving up after {MAX_CONSECUTIVE_RECEIVE_CANCELLATIONS} \
                     consecutive ECANCELED receives with no successful receive in between — \
                     treating this as a genuinely broken/closed fd rather than a run of \
                     coincidentally-dying targets: {e}"
                );
            }
            Err(e) => {
                tracing::info!(error = %e, "notify loop ending (fd exhausted/closed)");
                return Ok(());
            }
        };

        match decode_and_respond(raw_fd, req) {
            Ok(event) => on_event(event),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "one seccomp-notify request failed to decode/respond to (likely a stale \
                     request from a process that died mid-flight); continuing to service other \
                     processes sharing this filter"
                );
            }
        }
    }
}
