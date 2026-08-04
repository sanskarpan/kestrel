#![deny(clippy::undocumented_unsafe_blocks)]

//! OverlayFS snapshotter, mounts, pivot_root, and masked/read-only path
//! application for kestrel. See
//! docs/superpowers/specs/2026-08-03-phase4-rootfs-design.md.

pub mod bindmount;
pub mod copyup;
pub mod mask;
pub mod mounts;
pub mod overlay;
pub mod pivot;
pub mod snapshot;
