#![deny(clippy::undocumented_unsafe_blocks)]
//! cgroup v2 manager: resource limits, freezer, PSI, OOM detection, and
//! CLONE_INTO_CGROUP. See docs/superpowers/specs/2026-08-01-phase3-cgroups-design.md.

pub mod clone3;
pub mod control;
pub mod manager;
pub mod psi;
pub mod resources;
pub mod stats;
