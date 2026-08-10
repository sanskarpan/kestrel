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
///
/// `Bridge` and `None` referenced-modes resolve to genuinely DIFFERENT pin
/// path shapes — they are NOT interchangeable, despite both being "the
/// referenced container has its own private netns" cases:
///
/// - A `Bridge`-mode container's netns is created via this crate's own
///   `netns::create_netns`, which pins it at `<run_dir>/netns/<id>` (see
///   `netns.rs`'s own private `pin_path` helper — that convention is
///   duplicated here rather than imported since `pin_path` is not `pub`,
///   and this function needs to build the SAME path for a container it
///   never itself pinned).
/// - A `None`-mode container's netns is a plain "create fresh" namespace.
///   It is never touched by this crate at all — it's created by
///   `kestrel-ns`'s stage1 (via `NamespacePlan.create`) and pinned by
///   `kestrel-runtime`'s `create.rs::pin_namespaces` at
///   `<run_dir>/<id>/ns/<NsType::proc_name()>`, i.e.
///   `<run_dir>/<id>/ns/net` for the network namespace specifically. Since
///   `None` is the DEFAULT network mode when unspecified, this is the
///   COMMON case, not an edge case — treating it as if it shared `Bridge`'s
///   path shape (a bug fixed here) meant `container:<id>` referencing any
///   typical, default-network-mode container resolved to a pin path that
///   was never created.
///
/// This function relies on the CALLER (`kestreld`'s `bundle.rs`, per this
/// function's own module-level design: `kestrel-net` has no visibility
/// into `kestreld`'s persisted container metadata) to have already looked
/// up the referenced container's real, persisted mode and passed it in as
/// `referenced_mode` — so no on-disk existence probing is needed or
/// wanted here. Probing "does <run_dir>/netns/<id> exist, else fall back
/// to <run_dir>/<id>/ns/net" was considered and rejected: it would work
/// (the two conventions are genuinely mutually exclusive per container,
/// since a container is created under exactly one mode and therefore its
/// netns can only ever have been pinned by ONE of `create_netns` or
/// `pin_namespaces`, never both), but it's strictly worse than just using
/// the `referenced_mode` this function already requires its caller to
/// supply — it would silently paper over a caller bug (passing the wrong
/// `ModeKind`) instead of trusting/using the parameter that exists
/// specifically to avoid that ambiguity.
pub fn resolve_container_mode(run_dir: &Path, referenced_id: &str, referenced_mode: ModeKind) -> Result<std::path::PathBuf> {
    match referenced_mode {
        ModeKind::Bridge => Ok(run_dir.join("netns").join(referenced_id)),
        ModeKind::None => Ok(run_dir
            .join(referenced_id)
            .join("ns")
            .join(kestrel_ns::types::NsType::Net.proc_name())),
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
        // A `None`-mode container's netns is pinned by
        // `kestrel-runtime`'s `create.rs::pin_namespaces` at
        // `<run_dir>/<id>/ns/net`, NOT `<run_dir>/netns/<id>` (that's the
        // `Bridge`-mode/`create_netns` shape, a DIFFERENT convention — see
        // `resolve_container_mode`'s own doc comment for the full
        // reasoning). This is the regression test for the bug where both
        // arms of the match were incorrectly collapsed into one.
        let run_dir = Path::new("/run/kestrel");
        let path = resolve_container_mode(run_dir, "xyz789", ModeKind::None).unwrap();
        assert_eq!(path, run_dir.join("xyz789").join("ns").join("net"));
        assert_ne!(
            path,
            run_dir.join("netns").join("xyz789"),
            "a None-mode container's netns pin must NOT be confused with Bridge-mode's path shape"
        );
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
