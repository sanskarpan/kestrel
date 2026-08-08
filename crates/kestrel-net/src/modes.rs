// crates/kestrel-net/src/modes.rs
//
//! Network mode configuration and `container:<id>` reference validation.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Result};
use ipnetwork::Ipv4Network;

#[derive(Debug, Clone)]
pub enum NetworkConfig {
    Bridge { bridge_name: String, gateway: Ipv4Addr, subnet: Ipv4Network, published: Vec<(u16, u16)> },
    Host,
    None,
    Container(String),
}

/// A container's OWN recorded network mode — the minimal information
/// `resolve_container_mode` needs to enforce the one-hop-only rule from
/// the design doc. In this phase, callers (tests, later Phase 8 wiring)
/// supply this directly; a real "look up container X's mode" store is
/// Phase 8/9's daemon-state concern, out of scope here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeKind {
    Bridge,
    Host,
    None,
    Container,
}

/// Validates a `container:<id>` reference against the referenced
/// container's OWN mode, per the design doc's one-hop-only rule.
/// Returns the netns pin path to join if valid.
pub fn resolve_container_mode(run_dir: &Path, referenced_id: &str, referenced_mode: ModeKind) -> Result<std::path::PathBuf> {
    match referenced_mode {
        ModeKind::Bridge | ModeKind::None => Ok(run_dir.join("netns").join(referenced_id)),
        ModeKind::Host => bail!("cannot join network of container {referenced_id}: it has no network namespace (mode=host)"),
        ModeKind::Container => bail!(
            "cannot join network of container {referenced_id}: it is itself in container:<id> mode \
             (chained container-network references are not supported — reference the ultimate owner directly)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_container_mode_bridge_succeeds_with_expected_path() {
        let run_dir = Path::new("/run/kestrel");
        let path = resolve_container_mode(run_dir, "abc123", ModeKind::Bridge).unwrap();
        assert_eq!(path, run_dir.join("netns").join("abc123"));
    }

    #[test]
    fn test_resolve_container_mode_none_succeeds_with_expected_path() {
        let run_dir = Path::new("/run/kestrel");
        let path = resolve_container_mode(run_dir, "xyz789", ModeKind::None).unwrap();
        assert_eq!(path, run_dir.join("netns").join("xyz789"));
    }

    #[test]
    fn test_resolve_container_mode_host_errors() {
        let run_dir = Path::new("/run/kestrel");
        let err = resolve_container_mode(run_dir, "abc123", ModeKind::Host).unwrap_err();
        assert!(err.to_string().contains("mode=host"));
    }

    #[test]
    fn test_resolve_container_mode_container_errors() {
        let run_dir = Path::new("/run/kestrel");
        let err = resolve_container_mode(run_dir, "abc123", ModeKind::Container).unwrap_err();
        assert!(err.to_string().contains("chained container-network references"));
    }
}
