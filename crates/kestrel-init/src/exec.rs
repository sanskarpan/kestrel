// crates/kestrel-init/src/exec.rs

use std::convert::Infallible;
use std::ffi::CString;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use anyhow::{Context, Result};
use kestrel_oci::runtime::{LinuxSeccomp, Process};
use nix::unistd::execve;

/// Connects to `path` (a `SOCK_STREAM` Unix socket `kestrel-shim` is
/// already listening on, per design doc §7 / Phase 9 Task 16) and returns
/// the live connection.
///
/// **Must be called BEFORE `pivot_root`**, NOT from inside [`exec_into`]
/// itself — a real gap this task's own implementation hit and root-caused:
/// `path` (`bootstrap.seccomp_notify_sink`) is a HOST path
/// (`run_dir/<id>/seccomp.sock`), exactly like `bootstrap.state_json_path`
/// (see `main.rs`'s own extensive doc comment on that field for the
/// identical underlying issue). `exec_into` runs inside the forked
/// entrypoint child, which by that point has ALREADY gone through
/// `kestrel_init::mounts::pivot` — the host path is simply gone from that
/// process's mount namespace, and a `connect()` against it fails with
/// `ENOENT`, which (undetectably, since `kestrel-init`'s child branch
/// silently discards `exec_into`'s error before its own
/// `std::process::exit(127)`) looked like a generic exec failure until a
/// real end-to-end reproduction (`kestreld`'s own Task 16 capstone test)
/// surfaced it via the container's `exit_code` landing at 127 instead of
/// ever reaching `Running` in a healthy state.
///
/// The fix mirrors `main.rs`'s own `state_dir_fd` precedent but is simpler:
/// unlike a path (which needs the `/proc/self/fd/<fd>` "magic symlink"
/// trick to remain resolvable after a mount-namespace change), a
/// **connected socket** has no ongoing dependency on the path it was
/// connected through — once `connect()` returns, the fd is just a live
/// connection, fully independent of mount-namespace/`pivot_root` state.
/// `main.rs` calls this once, pre-pivot, and keeps the resulting `OwnedFd`
/// alive across the later `fork()` (fork duplicates the whole fd table
/// regardless of `pivot_root`/mount-namespace changes in between) so
/// [`exec_into`] can use the ALREADY-established connection instead of
/// trying (and failing) to make a fresh one post-pivot.
///
/// **Retries on `ConnectionRefused`/`NotFound` for up to
/// [`NOTIFY_SINK_CONNECT_BUDGET`]** — a SECOND real race found and
/// root-caused during this same task's end-to-end testing, distinct from
/// the pivot/mount-namespace issue above: this function is called from
/// `main.rs` immediately after receiving the `Bootstrap` payload, which
/// happens as part of `kestrel-runtime create`'s OWN internal
/// `run_stages()` call — i.e. DURING `create`, potentially seconds before
/// `kestrel-runtime start` ever runs. But `kestrel-shim`'s
/// `daemon::run` (and therefore its `seccomp.sock` bind) only starts AFTER
/// the ENTIRE `kestrel-runtime create` subprocess it spawned has exited
/// (`main.rs`'s own `cmd.status().await`) — and `kestrel-init`, once
/// forked off by `run_stages`, proceeds independently and in PARALLEL with
/// the REST of `create()`'s own remaining host-side work (hooks,
/// `pin_namespaces`, the final `state.json` write). A real, live
/// reproduction (this task's own `kestreld` capstone test, inspecting
/// `<data_dir>/containers/<id>/output.jsonl` — `kestrel-init`'s own stderr,
/// which lands there because it inherits `kestrel-runtime create`'s stdio,
/// which the shim wired into the container's own captured stdio) showed
/// `kestrel-init` reaching this connect call BEFORE the shim had bound
/// `seccomp.sock` at all, failing with a genuine `ECONNREFUSED` every
/// time — not a one-off flake, but a real, structural ordering gap in how
/// early `kestrel-init` can legitimately reach this point relative to how
/// late the shim binds its listener. A short, bounded retry (matching
/// `kestrel-runtime`'s own `start.rs::open_fifo_for_write_bounded` /
/// `FIFO_READER_WAIT_BUDGET` precedent for "the other side of a real IPC
/// handshake might not be ready yet, briefly") is the correct fix here —
/// this always resolves in well under a second in practice (the shim binds
/// the listener almost immediately once `kestrel-runtime create` exits),
/// so the budget below is generous headroom, not an expected steady-state
/// wait.
const NOTIFY_SINK_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
const NOTIFY_SINK_CONNECT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

pub fn connect_notify_sink(path: &Path) -> Result<OwnedFd> {
    let deadline = std::time::Instant::now() + NOTIFY_SINK_CONNECT_BUDGET;
    loop {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => return Ok(stream.into()),
            Err(e) if is_retryable_connect_error(&e) && std::time::Instant::now() < deadline => {
                std::thread::sleep(NOTIFY_SINK_CONNECT_POLL_INTERVAL);
            }
            Err(e) => {
                return Err(e).with_context(|| format!("connecting to seccomp-notify sink at {}", path.display()));
            }
        }
    }
}

/// `ConnectionRefused` (the socket file exists but nothing is listening
/// yet — `kestrel-shim` hasn't called `bind`/`listen` yet) and `NotFound`
/// (the socket file itself doesn't exist yet — `kestrel-shim` hasn't even
/// created `<run_dir>/<id>/` yet) are both real, expected "the other side
/// isn't ready yet" states worth retrying through; any other error is a
/// genuine, non-transient failure.
fn is_retryable_connect_error(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound)
}

/// Applies the full Phase 5 security pipeline to the CURRENT process, then
/// execve()s into `process.args()`. Never returns on success (the process
/// image is replaced) — the `Result<Infallible>` return type makes that
/// contract checkable by the compiler at every call site, matching the
/// convention `Ok(x): Infallible` establishes elsewhere in Rust's std for
/// "this either diverges or errors."
///
/// `notify_conn` (Phase 9 Task 16): `Some(conn)` — an ALREADY-CONNECTED
/// socket to `kestrel-shim`'s `seccomp.sock` (see [`connect_notify_sink`]'s
/// doc comment for why this must be pre-established, pre-pivot, rather than
/// connected here) — when `bootstrap.seccomp_notify_sink` was set (the
/// process's seccomp profile uses `SCMP_ACT_NOTIFY` somewhere). When
/// `apply_all` below returns `Some(fd)` (the notify fd) alongside a
/// `Some(conn)`, this function hands the fd over `conn` via `SCM_RIGHTS`
/// before execve — see [`send_fd_over_connection`].
pub fn exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>, notify_conn: Option<BorrowedFd>) -> Result<Infallible> {
    // `main.rs` blocks nearly every signal (`SigSet::all()` minus the
    // synchronous-fault signals) on kestrel-init's own main thread, BEFORE
    // forking this process, so its signalfd-based reap loop never misses a
    // delivery. `fork(2)` duplicates that blocked-signal mask verbatim,
    // and — this is the part that matters here — `execve(2)` does NOT
    // reset it: POSIX only resets the DISPOSITION of signals that had a
    // custom handler installed back to `SIG_DFL`; a signal's blocked/
    // pending status is untouched by exec. Left alone, the container's
    // own entrypoint would silently inherit kestrel-init's blocked mask
    // and never actually receive SIGTERM (or almost anything else short
    // of the unblockable SIGKILL/SIGSTOP) — breaking every graceful-stop
    // path in this project (`kestrel kill <id> SIGTERM`, `kestreld`'s
    // `POST /containers/:id/stop`) silently: the signal would be sent
    // successfully (no error anywhere), just never delivered. Found via a
    // real reproduction (Phase 9 Task 9's `kestreld` stop-grace-period
    // test): a container ignoring SIGTERM on purpose and one that never
    // installed a handler at all were indistinguishable from the caller's
    // side before this fix, both silently requiring escalation to
    // SIGKILL. Real container runtimes (runc/crun) reset the inherited
    // mask before exec'ing the user's process for exactly this reason;
    // this is kestrel-init's equivalent. Resetting to `SigSet::empty()`
    // (not restoring some saved pre-block mask) is correct: this process
    // had no meaningful blocked set of its own before kestrel-init's
    // PID-1-specific block, and an empty mask is the ordinary, unsurprising
    // starting point any exec'd program expects.
    nix::sys::signal::SigSet::empty()
        .thread_set_mask()
        .context("resetting the entrypoint's inherited (kestrel-init-blocked) signal mask before execve")?;

    std::env::set_current_dir(process.cwd())
        .with_context(|| format!("chdir to {}", process.cwd().display()))?;

    // apply_all runs BEFORE the chdir above is questioned further — cwd
    // itself needs no special privilege, so its exact position relative to
    // apply_all's five steps doesn't matter; done first here simply
    // because a failed chdir should abort before we've dropped anything.
    //
    // The returned `Option<OwnedFd>` used to be silently dropped/closed
    // here as an unnamed temporary (Phase 9 Task 16's real gap, confirmed
    // during design grounding) — bound to `notify_fd` now so it can be
    // handed off below, immediately before execve, rather than lost.
    let notify_fd = kestrel_security::apply::apply_all(process, seccomp).context("apply_all")?;
    if let (Some(fd), Some(conn)) = (notify_fd, notify_conn) {
        send_fd_over_connection(&fd, conn).context("sending seccomp-notify fd to shim")?;
        // `fd` drops here (ordinary `OwnedFd` close-on-drop) — this
        // process's own copy is no longer needed once the shim holds its
        // own, `dup`'d-by-the-kernel copy from the `SCM_RIGHTS` transfer;
        // `apply_all`'s notify fd was never meant to survive this
        // process's own `execve` in the first place (nothing in the
        // container's entrypoint has any use for it).
    }

    let args = process
        .args()
        .as_deref()
        .filter(|a| !a.is_empty())
        .context("process.args must specify at least the program to exec")?;
    let program = CString::new(args[0].as_str()).context("program path contains a NUL byte")?;
    let argv: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("an argument contains a NUL byte")?;
    let envp: Vec<CString> = process
        .env()
        .iter()
        .flatten()
        .map(|e| CString::new(e.as_str()))
        .collect::<Result<_, _>>()
        .context("an env entry contains a NUL byte")?;

    // nix::unistd::execve's return type is `Result<Infallible, Errno>` —
    // it genuinely cannot construct `Ok` (a successful exec replaces this
    // process image and never returns to this stack frame at all), so
    // `.with_context()` propagating straight through to this function's
    // own `Result<Infallible>` return type is correct as-is, with no
    // `expect_err` unwrapping dance needed.
    execve(&program, &argv, &envp)
        .with_context(|| format!("execve({:?}, {:?})", program, argv))
}

/// Hands `fd` over `conn` (an already-connected `SOCK_STREAM` socket to
/// `kestrel-shim`'s `seccomp.sock`, per design doc §7 / Phase 9 Task 16)
/// via `SCM_RIGHTS`, synchronously, one-shot, before this process's caller
/// execve()s. See [`connect_notify_sink`]'s doc comment for why `conn` must
/// already be connected (established pre-pivot) rather than connected here.
///
/// Real API shape verified against the vendored `nix` 0.29.0 source inside
/// the Lima VM (`nix-0.29.0/test/sys/test_socket.rs::test_scm_rights`,
/// plus `sys/socket/mod.rs`'s own `sendmsg` doc example) rather than
/// assumed:
///   - `sendmsg<S: SockaddrLike>(fd, iov, cmsgs, flags, addr) -> Result<usize>`,
///     with `ControlMessage::ScmRights(&[RawFd])`; `S = ()` (turbofish
///     `sendmsg::<()>`) when not directing at a specific address, which is
///     this call's case (a `connect()`ed `SOCK_STREAM` socket).
///   - Critically: `test_scm_rights` sends a REAL, non-empty `IoSlice`
///     (`b"hello"`) alongside the `ScmRights` control message, not an
///     empty one — an ancillary-data-only message is a known footgun for
///     `SCM_RIGHTS` (some platforms/socket types can silently drop the fd
///     if there's no real payload riding alongside it). This function
///     follows that same precedent with a single marker byte (the
///     receiver, `kestrel-shim`'s `daemon::handle_seccomp_conn`, reads and
///     discards it) rather than assuming an empty payload works on Linux.
fn send_fd_over_connection(fd: &OwnedFd, conn: BorrowedFd) -> Result<()> {
    let marker = [0u8];
    let iov = [IoSlice::new(&marker)];
    let fds = [fd.as_raw_fd()];
    let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
    nix::sys::socket::sendmsg::<()>(
        conn.as_raw_fd(),
        &iov,
        &cmsg,
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .context("sendmsg(SCM_RIGHTS) sending seccomp-notify fd")?;

    Ok(())
}

#[cfg(test)]
mod connect_notify_sink_tests {
    use super::*;

    /// Proves the real bug this task's own end-to-end testing found: a
    /// caller reaching `connect_notify_sink` BEFORE the listener exists
    /// yet must not fail immediately — it must retry until the listener
    /// shows up (bounded by `NOTIFY_SINK_CONNECT_BUDGET`), not treat a
    /// momentarily-not-ready peer as a hard error. No root required.
    #[test]
    fn test_connect_notify_sink_retries_until_a_late_listener_appears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("seccomp.sock");
        let sock_path_for_thread = sock_path.clone();

        // Deliberately does NOT bind the listener until well after
        // `connect_notify_sink` (below) has already started trying —
        // reproducing the real ordering this task's own root-gated
        // capstone test hit (kestrel-init reaching this connect before
        // kestrel-shim has bound `seccomp.sock` yet).
        let bind_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let listener = std::os::unix::net::UnixListener::bind(&sock_path_for_thread).expect("bind");
            listener.accept().expect("accept")
        });

        let start = std::time::Instant::now();
        let conn = connect_notify_sink(&sock_path).expect("connect_notify_sink should retry through the late bind and eventually succeed");
        let elapsed = start.elapsed();

        bind_thread.join().expect("bind thread panicked");
        drop(conn);

        assert!(
            elapsed >= std::time::Duration::from_millis(150),
            "connect succeeded suspiciously fast ({elapsed:?}) — the retry-until-listener-appears behavior may not be real"
        );
        assert!(
            elapsed < NOTIFY_SINK_CONNECT_BUDGET,
            "connect took {elapsed:?}, which should be well under the {NOTIFY_SINK_CONNECT_BUDGET:?} budget for a listener that appears after only 200ms"
        );
    }

    /// A path that's never going to have anything bound to it must still
    /// fail eventually (bounded by the retry budget), not hang forever.
    /// Uses a short, temporarily-shadowed budget via a scaled-down direct
    /// call pattern is not available (the const is a real, fixed
    /// production value) — this test instead just confirms the failure
    /// mode is a real, well-formed error (not a panic/hang) for a
    /// genuinely-never-appearing peer, bounded implicitly by this test's
    /// own harness timeout rather than re-asserting the exact budget
    /// twice.
    #[test]
    #[ignore = "slow: exercises the real ~10s retry budget end to end"]
    fn test_connect_notify_sink_eventually_gives_up_on_a_path_nothing_ever_binds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("nobody-home.sock");
        let result = connect_notify_sink(&sock_path);
        assert!(result.is_err(), "connecting to a path nothing ever binds must eventually return Err, not hang or succeed");
    }
}

#[cfg(test)]
mod notify_fd_scm_rights_tests {
    use super::*;
    use std::os::fd::{AsFd, FromRawFd};

    /// Proves the `SCM_RIGHTS` mechanism itself works end to end — a real
    /// Unix socket connection (established via [`connect_notify_sink`],
    /// exactly like `main.rs` does pre-pivot), a real fd sent by
    /// [`send_fd_over_connection`], received back via the same
    /// `nix::sys::socket::recvmsg` shape `kestrel-shim`'s own
    /// `daemon::handle_seccomp_conn` uses (Phase 9 Task 16), and confirmed
    /// to be a genuinely working duplicate of the original fd (not just a
    /// syntactically-valid fd number) by writing through the sender's
    /// original fd and reading the SAME bytes back through the received
    /// one. No root required — plain `SOCK_STREAM` fd-passing needs no
    /// privilege, unlike the real seccomp-notify fd this mechanism is
    /// built to carry in production.
    #[test]
    fn test_send_fd_over_connection_transfers_a_genuinely_working_fd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("seccomp.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind");

        // A real, independently-verifiable fd to send: a temp file with
        // known content already written to it.
        let file_path = dir.path().join("payload");
        std::fs::write(&file_path, b"hello-scm-rights").expect("write payload file");
        let file = std::fs::File::open(&file_path).expect("open payload file");
        let owned_fd: OwnedFd = file.into();

        let accept_thread = std::thread::spawn(move || {
            let (conn, _addr) = listener.accept().expect("accept");
            recv_fd_via_scm_rights(conn)
        });

        let conn = connect_notify_sink(&sock_path).expect("connect_notify_sink");
        send_fd_over_connection(&owned_fd, conn.as_fd()).expect("send_fd_over_connection");
        drop(owned_fd); // our own copy is no longer needed, matching exec_into's own real usage
        drop(conn);

        let received_fd = accept_thread
            .join()
            .expect("accept thread panicked")
            .expect("recv_fd_via_scm_rights");

        // SAFETY: `received_fd` is a valid, just-received, owned fd — the
        // sole owner-transfer point for it in this test.
        let mut received_file = unsafe { std::fs::File::from_raw_fd(received_fd) };
        use std::io::Read;
        let mut buf = Vec::new();
        received_file.read_to_end(&mut buf).expect("read via received fd");
        assert_eq!(buf, b"hello-scm-rights", "the received fd must be a genuinely working duplicate of the original");
    }

    /// Minimal `recvmsg`-based receiver, mirroring `kestrel-shim`'s own
    /// `daemon::handle_seccomp_conn`/`recv_fd_via_scm_rights` shape exactly
    /// (same `cmsg_space!`/`IoSliceMut`/`ControlMessageOwned::ScmRights`
    /// pattern) — duplicated here rather than imported since `kestrel-shim`
    /// is a separate crate this one doesn't (and shouldn't) depend on; this
    /// is purely a same-shape sanity check of the sender half.
    fn recv_fd_via_scm_rights(stream: std::os::unix::net::UnixStream) -> Result<std::os::fd::RawFd> {
        use nix::cmsg_space;
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
        use std::io::IoSliceMut;

        let raw_fd = stream.as_raw_fd();
        let mut cmsg_buffer = cmsg_space!([std::os::fd::RawFd; 1]);
        let mut iov_buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut iov_buf)];
        let msg = recvmsg::<()>(raw_fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())
            .context("recvmsg")?;

        for cmsg in msg.cmsgs().context("iterating control messages")? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                if let Some(&fd) = fds.first() {
                    return Ok(fd);
                }
            }
        }
        anyhow::bail!("no fd received in SCM_RIGHTS control message")
    }
}
