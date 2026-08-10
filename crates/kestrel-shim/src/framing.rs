// crates/kestrel-shim/src/framing.rs
//
//! `attach.sock` wire framing. See
//! docs/superpowers/specs/2026-08-09-phase9-daemon-design.md §5: 1-byte
//! type tag + `u32` LE length + payload, both directions. Used by
//! `kestreld` (WS<->attach.sock bridge, a later task) and directly by this
//! crate's own `daemon::accept_loop` / integration tests.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_RESIZE: u8 = 0x02;
pub const TYPE_CLOSE: u8 = 0x03;
pub const TYPE_SECCOMP_EVENT: u8 = 0x04; // Task 16, not this task's concern
pub const TYPE_READY: u8 = 0x05; // Task 16 adversarial-review round 2 fix, see `Frame::Ready`

/// Defensive cap on a single frame's payload size — an attach client can't
/// make the shim allocate unboundedly on a corrupt/malicious length prefix.
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Close,
    SeccompEvent(Vec<u8>), // serde_json-encoded NotifyEvent, Task 16
    /// Sent by `kestrel-shim`'s `daemon::handle_attach_conn` as literally
    /// the first frame on a freshly-accepted `attach.sock` connection,
    /// once (and only once) it has genuinely finished subscribing to both
    /// the stdio (`tx`) and seccomp-notify (`seccomp_hub`) broadcast
    /// channels — never sent by a client, never meaningful inbound. Exists
    /// purely as a real, observable synchronization point: a connected
    /// peer that has received this frame knows, with certainty (not a
    /// guess), that a seccomp-notify violation firing from this moment
    /// onward will be seen live by this connection — see `kestreld`'s
    /// `api::attach::run_attach_session`, the one real consumer, for how
    /// it's used (Task 16 adversarial-review round 2 fix).
    Ready,
}

pub async fn write_frame(w: &mut (impl tokio::io::AsyncWrite + Unpin), frame: &Frame) -> Result<()> {
    let (ty, payload): (u8, Vec<u8>) = match frame {
        Frame::Data(bytes) => (TYPE_DATA, bytes.clone()),
        Frame::Resize { rows, cols } => {
            let mut p = Vec::with_capacity(4);
            p.extend_from_slice(&rows.to_le_bytes());
            p.extend_from_slice(&cols.to_le_bytes());
            (TYPE_RESIZE, p)
        }
        Frame::Close => (TYPE_CLOSE, Vec::new()),
        Frame::SeccompEvent(bytes) => (TYPE_SECCOMP_EVENT, bytes.clone()),
        Frame::Ready => (TYPE_READY, Vec::new()),
    };
    w.write_u8(ty).await?;
    w.write_u32_le(payload.len() as u32).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Frame> {
    let ty = r.read_u8().await.context("reading frame type")?;
    let len = r.read_u32_le().await.context("reading frame length")? as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame length {len} exceeds {MAX_FRAME_LEN} byte cap");
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.context("reading frame payload")?;
    match ty {
        TYPE_DATA => Ok(Frame::Data(payload)),
        TYPE_RESIZE => {
            if payload.len() != 4 {
                bail!("RESIZE frame must be 4 bytes, got {}", payload.len());
            }
            let rows = u16::from_le_bytes([payload[0], payload[1]]);
            let cols = u16::from_le_bytes([payload[2], payload[3]]);
            Ok(Frame::Resize { rows, cols })
        }
        TYPE_CLOSE => Ok(Frame::Close),
        TYPE_SECCOMP_EVENT => Ok(Frame::SeccompEvent(payload)),
        TYPE_READY => Ok(Frame::Ready),
        other => bail!("unknown frame type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_data_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Data(b"hello".to_vec())).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Frame::Data(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn round_trips_resize_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Resize { rows: 40, cols: 120 }).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Frame::Resize { rows: 40, cols: 120 });
    }

    #[tokio::test]
    async fn round_trips_close_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Close).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Frame::Close);
    }

    #[tokio::test]
    async fn round_trips_ready_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Ready).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Frame::Ready);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix() {
        let mut buf = Vec::new();
        buf.push(TYPE_DATA);
        buf.extend_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn rejects_malformed_resize_length() {
        let mut buf = Vec::new();
        buf.push(TYPE_RESIZE);
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 3]);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(err.to_string().contains("RESIZE frame must be 4 bytes"));
    }
}
