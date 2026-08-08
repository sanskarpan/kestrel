#![deny(clippy::undocumented_unsafe_blocks)]

//! kestrel-init library surface. Phase 5 contributed security-profile
//! application immediately before execve() and PR_SET_PDEATHSIG self-
//! protection — see
//! docs/superpowers/specs/2026-08-03-phase5-security-design.md §4b for why
//! the PID-1 reaper (signal forwarding, zombie reaping) was deliberately
//! split out of that phase. Phase 8 adds that reaper (`reaper.rs`), the
//! exec-FIFO readiness gate (`fifo.rs`), and rootfs/mount staging
//! (`mounts.rs`).

pub mod bootstrap;
pub mod exec;
pub mod mounts;
pub mod pdeathsig;
