#![deny(clippy::undocumented_unsafe_blocks)]

//! Minimal kestrel-init library surface for Phase 5: applying the security
//! profile immediately before execve(), and PR_SET_PDEATHSIG self-
//! protection. The PID-1 reaper (signal forwarding, zombie reaping) is
//! Phase 8's job — see docs/superpowers/specs/2026-08-03-phase5-security-design.md
//! §4b for why that split is deliberate.

pub mod exec;
pub mod pdeathsig;
