// crates/kestrel-shim/src/lib.rs
//
//! `kestrel-shim` library surface. See
//! docs/superpowers/specs/2026-08-09-phase9-daemon-design.md §2 for the
//! shim's role: own one container's stdio (PTY or pipes) for its entire
//! lifetime, independent of `kestreld`'s own process lifetime, so a
//! `kestreld` restart never SIGPIPEs the container's entrypoint or loses
//! live-attach capability for an already-running container.
//!
//! `io` provides PTY/pipe allocation and the fd-ownership handoff into the
//! daemon stage; `daemon` daemonizes and runs the durable
//! log-capture/`attach.sock` event loop; `framing` implements the
//! `attach.sock` wire protocol (design doc §5) both this crate's own
//! `daemon::accept_loop` and `kestreld`'s future WS bridge use.

pub mod daemon;
pub mod framing;
pub mod io;
