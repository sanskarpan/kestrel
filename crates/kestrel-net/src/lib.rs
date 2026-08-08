//! kestrel-net — network namespace lifecycle, bridge/veth data path,
//! IPAM, NAT, and DNS for kestrel containers. See
//! docs/superpowers/specs/2026-08-05-phase7-networking-design.md.

pub mod bridge;
pub mod hosts;
pub mod ipam;
pub mod modes;
pub mod nat;
pub mod netns;
pub mod veth;
