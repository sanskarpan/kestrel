//! `kestreld` — the kestrel daemon. Owns container lifecycle orchestration,
//! log capture, live attach, metrics/event streaming, and image management,
//! exposed over both a Unix socket and a TCP address (SPEC.md §13).
//!
//! `kestreld` never links `kestrel-runtime` as a library — it always
//! `fork+exec`s it (via `kestrel-shim`) as a subprocess. See
//! `docs/superpowers/specs/2026-08-09-phase9-daemon-design.md` for the full
//! architecture.
//!
//! This crate is currently just the configuration-parsing + dual-listener
//! skeleton (Phase 9 Task 6). Later tasks add the container registry, HTTP
//! routes, and background tasks on top of it.

pub mod config;

pub use config::Config;
