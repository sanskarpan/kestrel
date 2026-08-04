//! `Sync` protocol: small enum of control messages exchanged over an
//! `AF_UNIX SOCK_SEQPACKET` socketpair during namespace setup. `SOCK_SEQPACKET`
//! preserves message boundaries at the `send`/`recv` syscall level, so this is
//! wrapped in `std::os::unix::net::UnixDatagram` (constructed `From<OwnedFd>`)
//! to get `send`/`recv`/`set_read_timeout` for free instead of hand-rolling
//! `poll()`-based timeout logic.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sync {
    RequestMaps,
    MapsDone,
    ReportPid(i32),
    Ready,
    Error(String),
}

pub fn send_sync(sock: &UnixDatagram, msg: &Sync) -> Result<()> {
    let bytes = serde_json::to_vec(msg).context("serializing sync message")?;
    debug_assert!(
        bytes.len() < 4096,
        "sync message is {} bytes, too large for the fixed 4096-byte receive buffer",
        bytes.len()
    );
    sock.send(&bytes).context("sending sync message")?;
    Ok(())
}

/// Every sync-socket read has a timeout — a wedged stage must fail loudly,
/// never block the caller forever.
pub fn recv_sync_timeout(sock: &UnixDatagram, timeout: Duration) -> Result<Sync> {
    sock.set_read_timeout(Some(timeout))
        .context("setting sync read timeout")?;
    // 4096 bytes is believed sufficient for every `Sync` variant: the
    // fixed-size variants are a few bytes of JSON, and `Error`/`ReportPid`
    // carry only short diagnostic strings/ints in practice. Fix #1 below
    // makes that assumption provable instead of just assumed — a message
    // that fills the buffer is treated as (possibly) truncated and rejected
    // rather than silently handed to the JSON parser.
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            anyhow::anyhow!("sync recv timed out after {timeout:?}")
        }
        _ => anyhow::Error::from(e).context("receiving sync message"),
    })?;
    // SOCK_SEQPACKET's recv() does not error when a message exceeds the
    // buffer — it silently truncates to buf.len() and discards the rest.
    // A message that exactly fills the buffer is indistinguishable from one
    // that was longer and got truncated to exactly this length, so treat
    // the boundary case as suspicious too (`<`, not `<=`).
    anyhow::ensure!(
        n < buf.len(),
        "sync message filled the entire {}-byte receive buffer — it may have \
         been truncated; increase the buffer size or bound the message size \
         at the sender",
        buf.len()
    );
    serde_json::from_slice(&buf[..n]).context("deserializing sync message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    fn pair() -> (UnixDatagram, UnixDatagram) {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        (UnixDatagram::from(a), UnixDatagram::from(b))
    }

    #[test]
    fn test_round_trip_each_variant() {
        let (a, b) = pair();
        for msg in [
            Sync::RequestMaps,
            Sync::MapsDone,
            Sync::ReportPid(4242),
            Sync::Ready,
            Sync::Error("boom".to_string()),
        ] {
            send_sync(&a, &msg).unwrap();
            let got = recv_sync_timeout(&b, Duration::from_secs(1)).unwrap();
            assert_eq!(got, msg);
        }
    }

    #[test]
    fn test_recv_times_out_when_nothing_sent() {
        let (_a, b) = pair();
        let err = recv_sync_timeout(&b, Duration::from_millis(100)).unwrap_err();
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_oversized_message_is_detected_not_silently_truncated() {
        let (a, b) = pair();
        // Bypass send_sync's debug_assert by sending raw bytes directly —
        // this simulates what a future caller with a very long Sync::Error
        // string could otherwise trigger.
        let oversized = vec![b'"'; 5000]; // not valid JSON, but that's not the point
        a.send(&oversized).unwrap();
        let err = recv_sync_timeout(&b, Duration::from_secs(1)).unwrap_err();
        assert!(
            err.to_string().contains("truncated") || err.to_string().contains("buffer"),
            "expected a clear truncation error, got: {err}"
        );
    }
}
