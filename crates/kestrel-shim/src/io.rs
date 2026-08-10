// crates/kestrel-shim/src/io.rs
//
//! PTY/pipe allocation for a single container's stdio. See design doc §2
//! step 1: a PTY (`--tty`) or two plain pipes plus `/dev/null` for stdin
//! (non-interactive default) — this module allocates the master/read
//! side the shim keeps; `main.rs` dup's the slave/write side into the
//! spawned child's stdio.
//!
//! `nix::pty::openpty`'s real signature, verified against the vendored
//! `nix` 0.29 source (`~/.cargo/registry/.../nix-0.29.0/src/pty.rs`):
//! `pub fn openpty<'a, 'b, T: Into<Option<&'a Winsize>>, U: Into<Option<&'b
//! Termios>>>(winsize: T, termios: U) -> Result<OpenptyResult>`, where
//! `OpenptyResult { pub master: OwnedFd, pub slave: OwnedFd }` — matches
//! the plan's sketch exactly (both fields are already `OwnedFd`, no raw
//! fds to wrap). The `pty` module itself (and therefore `openpty`) is
//! gated behind nix's `"term"` feature (`lib.rs`: `feature! { #![feature
//! = "term"] pub mod pty; }`), which this crate's `Cargo.toml` enables.

use std::os::fd::{AsRawFd, OwnedFd};

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

/// What the shim allocated for the container's stdio: either a PTY
/// (master kept, slave handed to the child) or two plain pipes
/// (stdout/stderr read ends kept, write ends handed to the child) plus
/// `/dev/null` for stdin (non-interactive default — see design doc §2
/// step 1).
pub enum ContainerIo {
    Pty {
        master: OwnedFd,
        slave: OwnedFd,
    },
    Pipes {
        stdout_read: OwnedFd,
        stdout_write: OwnedFd,
        stderr_read: OwnedFd,
        stderr_write: OwnedFd,
    },
}

/// What `daemon::run` actually owns long-term: just the shim's read (and,
/// for `Pty`, read/write) side of the container's stdio. Produced by
/// `ContainerIo::into_daemon_io`, which explicitly closes the shim's own
/// copy of whatever `main.rs` dup'd into the spawned child's stdio (the PTY
/// slave; the pipes' write ends) — see that method's doc comment for why
/// this matters.
pub enum DaemonIo {
    /// PTY master only — the shim's own copy of the slave has already been
    /// closed.
    Pty(OwnedFd),
    /// Pipe read ends only — the shim's own copies of the write ends have
    /// already been closed.
    Pipes {
        stdout_read: OwnedFd,
        stderr_read: OwnedFd,
    },
}

impl ContainerIo {
    /// Consumes the allocated stdio and hands back just the long-term
    /// read/write side `daemon::run` needs, explicitly closing the shim's
    /// OWN copy of the slave (tty) / write-ends (pipes) in the process.
    ///
    /// **Why this exists (real gap flagged by Task 1's own implementer):**
    /// `main.rs` `nix::unistd::dup`s the slave/write-end fds into the
    /// spawned child's stdio — that's a fresh, independent copy in the
    /// kernel's eyes, NOT a transfer of the original. The original
    /// `OwnedFd`s inside `ContainerIo` (`slave`, `stdout_write`,
    /// `stderr_write`) are never touched by that `dup` and would otherwise
    /// stay open for `daemon::run`'s entire lifetime once `io` is moved in
    /// whole. A pipe/PTY only reports EOF (`Ok(0)`) / EIO once **every**
    /// writer's copy of the fd is closed — if the shim keeps its own
    /// original slave/write-end copy open, that copy alone keeps the
    /// pipe/PTY "held open" forever from the kernel's point of view, even
    /// after the real container (`kestrel-init` + the entrypoint) has
    /// fully exited and closed every copy IT holds. That would silently
    /// mask the exit condition design doc §2 step 7 depends on: the shim
    /// would just hang forever, reading nothing further but never seeing
    /// EOF/EIO either.
    ///
    /// Must be called before daemonizing / starting the read loop — this
    /// is why `daemon::run` calls it as literally its first action, before
    /// even `setsid()`. Mirrors this project's established fd-hygiene
    /// idiom (`create.rs`'s explicit `drop(host_end)` / `close(host_end_raw)`
    /// calls, each with a comment justifying exactly which copy is being
    /// closed and why).
    pub fn into_daemon_io(self) -> DaemonIo {
        match self {
            ContainerIo::Pty { master, slave } => {
                // Shim's own original copy. The spawned child (and, deeper
                // down, kestrel-init/the entrypoint) has its own
                // independently dup'd copy from `main.rs` — closing this
                // one has zero effect on theirs.
                drop(slave);
                DaemonIo::Pty(master)
            }
            ContainerIo::Pipes {
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
            } => {
                drop(stdout_write);
                drop(stderr_write);
                DaemonIo::Pipes {
                    stdout_read,
                    stderr_read,
                }
            }
        }
    }
}

/// Sets `O_NONBLOCK` on `fd` via `fcntl(F_GETFL)` + `fcntl(F_SETFL)`
/// (read-modify-write, so any other already-set flags are preserved).
///
/// Required ahead of Task 2's needs: Task 2's `daemon::run` wraps every
/// fd this module allocates in `tokio::io::unix::AsyncFd`, which requires
/// the underlying fd to already be non-blocking — `AsyncFd` does not set
/// this itself. Setting it here, immediately after allocation, means
/// Task 2 doesn't need to (and its own plan text assumes this is already
/// done by the time it runs).
fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let raw = fd.as_raw_fd();
    let current = fcntl(raw, FcntlArg::F_GETFL).context("fcntl F_GETFL")?;
    let current = OFlag::from_bits_truncate(current);
    fcntl(raw, FcntlArg::F_SETFL(current | OFlag::O_NONBLOCK)).context("fcntl F_SETFL O_NONBLOCK")?;
    Ok(())
}

/// Allocates the container's stdio: a PTY if `tty`, else two pipes. The
/// fd(s) the shim itself will keep reading from long-term (the PTY
/// master; both pipes' read ends) are set non-blocking here — see
/// `set_nonblocking`'s doc comment. The fd(s) handed to the child (the
/// PTY slave; both pipes' write ends) are left blocking, since the child
/// process (ultimately `kestrel-init`/the container entrypoint) expects
/// ordinary blocking stdio semantics.
pub fn allocate(tty: bool) -> Result<ContainerIo> {
    if tty {
        // nix::pty::openpty returns OpenptyResult { master: OwnedFd, slave: OwnedFd }.
        let result = nix::pty::openpty(None, None).context("openpty")?;
        set_nonblocking(&result.master).context("set PTY master non-blocking")?;
        Ok(ContainerIo::Pty {
            master: result.master,
            slave: result.slave,
        })
    } else {
        let (stdout_read, stdout_write) = nix::unistd::pipe().context("stdout pipe")?;
        let (stderr_read, stderr_write) = nix::unistd::pipe().context("stderr pipe")?;
        set_nonblocking(&stdout_read).context("set stdout pipe read end non-blocking")?;
        set_nonblocking(&stderr_read).context("set stderr pipe read end non-blocking")?;
        Ok(ContainerIo::Pipes {
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
        })
    }
}
