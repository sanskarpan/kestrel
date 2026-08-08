//! The payload `kestrel-runtime`'s `create` command sends to `kestrel-init`
//! across the `execve` boundary, over a dedicated Phase-8 socketpair — see
//! docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md §1.
//! Distinct from Phase 2's own internal id-map sync socket
//! (kestrel_ns::sync), which is a different, narrower protocol local to
//! the three-stage dance itself.
//!
//! Socket type: a `SOCK_STREAM` socketpair, not the `SOCK_SEQPACKET`
//! (`UnixDatagram`) pattern `kestrel_ns::sync` uses. That precedent fits
//! `kestrel_ns::sync::Sync` because every variant is a few bytes of JSON
//! that comfortably fits in one datagram read against a fixed buffer.
//! `Bootstrap` is different: it embeds a full `Process`, optional
//! `LinuxCapabilities`/`LinuxSeccomp` (syscall rule lists can be long),
//! and hook lists, so its serialized size is unbounded in practice. The
//! `send_bootstrap`/`recv_bootstrap` framing below is a 4-byte
//! length-prefix followed by exactly that many payload bytes, read via
//! `Read::read_exact` — which loops over multiple partial `read()`s to
//! fill the buffer. That looping is only correct over byte-stream
//! semantics (`SOCK_STREAM`): a message (`SOCK_SEQPACKET`) or datagram
//! (`SOCK_DGRAM`) socket hands back one whole datagram per `recv()`
//! call and would desynchronize `read_exact`'s internal loop (the first
//! short read would consume the rest of the *next* datagram instead of
//! the rest of the current message, exactly the kind of truncation
//! `kestrel_ns::sync`'s own doc comments warn about for its fixed
//! 4096-byte buffer). `SOCK_STREAM` sidesteps that entirely: the length
//! prefix bounds the read, and there's no per-message size ceiling to
//! exceed.

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::runtime::{Hook, LinuxCapabilities, LinuxSeccomp, Process};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountPlan {
    pub lower_chain_ids: Vec<String>,
    pub rootless: bool,
}

/// `Vec<Hook>` is used directly rather than through a plain-data mirror
/// type: `oci_spec::runtime::Hook` already derives `Serialize` +
/// `Deserialize` (confirmed against the vendored 0.10.0 source, along
/// with `Clone`/`Debug`/`Default`/`PartialEq`/`Eq`), and its `camelCase`
/// rename attributes are irrelevant here — `Bootstrap` is JSON on a
/// private internal socket, not `config.json`, and the two forms of
/// JSON never need to interoperate byte-for-byte. There was no real
/// reason found to add a wrapper type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HookSet {
    pub create_container: Vec<Hook>,
    pub start_container: Vec<Hook>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bootstrap {
    pub container_id: String,
    pub mount_plan: MountPlan,
    pub process: Process,
    pub capabilities: Option<LinuxCapabilities>,
    pub seccomp: Option<LinuxSeccomp>,
    pub hooks: HookSet,
    pub hostname: Option<String>,
    /// Raw lines for `/proc/self/timens_offsets`, already formatted —
    /// see this plan's Task 5 note on verifying the real format before
    /// trusting a specific string shape here.
    pub timens_offsets: Vec<String>,
    /// Host-side path to the exec FIFO (created by `create.rs` via
    /// `mkfifo`) — used by kestrel-init to know what to bind-mount, not
    /// what to open for reading (it opens `fifo_container_path` instead,
    /// post-pivot).
    pub fifo_host_path: PathBuf,
    pub fifo_container_path: PathBuf,
    /// Where kestrel-init should write exit_code/status once the
    /// entrypoint dies.
    pub state_json_path: PathBuf,
}

/// Sends `bootstrap` as a length-prefixed JSON message over `fd`. Called
/// by `create.rs`'s `child_action` closure — NOT by kestrel-init.
///
/// Takes a raw `RawFd` rather than a borrowed socket type (`&UnixStream`
/// or `BorrowedFd`) deliberately: the fd this wraps is meant to survive
/// an `execve` (kestrel-init's `main` calls `recv_bootstrap` on the
/// *other* end after its own process image has already been replaced,
/// at which point only a raw fd number — not any Rust ownership
/// wrapper — exists to name it). Using `RawFd` end-to-end keeps
/// `send_bootstrap`/`recv_bootstrap` symmetric across that boundary
/// instead of having one side take a borrowed type and the other a raw
/// number. The `File::from_raw_fd` + `mem::forget` pair below is how
/// that "borrowed, not owned" intent is expressed on the send side: it
/// borrows `Read`/`Write` from `std::fs::File` without taking ownership
/// of the fd, so the caller's own idea of when the fd should close
/// (immediately after sending here vs. carried across `execve` by
/// `create.rs`'s fork/exec machinery) is left alone. Flagged in the
/// plan as worth revisiting once `create.rs` (Task 8) and kestrel-init's
/// `main` (Task 7) exist and their real call sites show whether a
/// `BorrowedFd`-based API would actually be cleaner in practice — no
/// such call site exists yet, so this keeps the plan's original shape.
pub fn send_bootstrap(fd: RawFd, bootstrap: &Bootstrap) -> Result<()> {
    let json = serde_json::to_vec(bootstrap).context("serializing Bootstrap")?;
    let len = (json.len() as u32).to_be_bytes();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&len)
        .context("writing bootstrap length prefix")?;
    file.write_all(&json).context("writing bootstrap payload")?;
    std::mem::forget(file); // don't close the fd — execve needs it to survive
    Ok(())
}

pub fn recv_bootstrap(fd: RawFd) -> Result<Bootstrap> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)
        .context("reading bootstrap length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut json_buf = vec![0u8; len];
    file.read_exact(&mut json_buf)
        .context("reading bootstrap payload")?;
    std::mem::forget(file);
    serde_json::from_slice(&json_buf).context("parsing Bootstrap")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    use std::os::fd::IntoRawFd;

    fn sample_bootstrap() -> Bootstrap {
        Bootstrap {
            container_id: "abc123".into(),
            mount_plan: MountPlan {
                lower_chain_ids: vec!["sha256:aaa".into(), "sha256:bbb".into()],
                rootless: true,
            },
            process: Process::default(),
            capabilities: None,
            seccomp: None,
            hooks: HookSet {
                create_container: vec![],
                start_container: vec![],
            },
            hostname: Some("kestrel-box".into()),
            timens_offsets: vec!["monotonic 100 0".into(), "boottime 100 0".into()],
            fifo_host_path: "/run/kestrel/abc123/exec.fifo".into(),
            fifo_container_path: "/exec.fifo".into(),
            state_json_path: "/run/kestrel/abc123/state.json".into(),
        }
    }

    #[test]
    fn test_send_recv_round_trips_over_socketpair() {
        // SOCK_STREAM, per this module's doc comment: Bootstrap's size is
        // unbounded (embeds Process/LinuxCapabilities/LinuxSeccomp/hooks),
        // so length-prefixed read_exact framing needs real byte-stream
        // semantics, not one-datagram-per-recv semantics.
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair");

        let sent = sample_bootstrap();
        send_bootstrap(a.into_raw_fd(), &sent).expect("send_bootstrap");
        let received = recv_bootstrap(b.into_raw_fd()).expect("recv_bootstrap");

        assert_eq!(received, sent);
    }

    #[test]
    fn test_send_recv_round_trips_with_capabilities_and_seccomp_present() {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair");

        let mut sent = sample_bootstrap();
        sent.capabilities = Some(LinuxCapabilities::default());
        sent.seccomp = Some(LinuxSeccomp::default());

        send_bootstrap(a.into_raw_fd(), &sent).expect("send_bootstrap");
        let received = recv_bootstrap(b.into_raw_fd()).expect("recv_bootstrap");

        assert_eq!(received, sent);
    }
}
