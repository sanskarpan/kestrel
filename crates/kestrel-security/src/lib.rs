#![deny(clippy::undocumented_unsafe_blocks)]

//! Capabilities, no_new_privs, rlimits, and seccomp for kestrel. See
//! docs/superpowers/specs/2026-08-03-phase5-security-design.md.

pub mod apply;
pub mod caps;
pub mod noprivs;
pub mod notify;
pub mod rlimits;
pub mod seccomp;
