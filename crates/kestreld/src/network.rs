// crates/kestreld/src/network.rs
//
//! Phase 9 Task 17: bridge-mode network attachment. `kestreld`'s own
//! bookkeeping of what it set up for each container (design doc §4a/§8) —
//! `kestrel-net` has almost no read-back/introspection API (everything is
//! create/ensure/delete-oriented), so `kestreld` remembering what it did
//! is the pragmatic choice, not a kernel re-derivation.
//!
//! `attach` is called by `api::containers::create_container` (Task 8)
//! AFTER `kestrel-runtime create` has genuinely succeeded: Task 8's
//! `bundle.rs` already called `kestrel_net::netns::create_netns` and
//! injected the resulting pin path into `config.json`'s `Network`
//! namespace `path` BEFORE `create()` ran, and Task 4's real
//! `NamespacePlan.join` mechanism means the container's pid 1 is already
//! genuinely inside that namespace by the time `create()` returns — this
//! module only does the POST-create half: veth/bridge/NAT attachment.
//!
//! `teardown` is the real implementation of the `network::teardown(...)`
//! call `api::containers::delete_container` (Task 9) originally stubbed
//! out (this file used to BE that stub — see git history/the previous
//! revision of this file for its own doc comment explaining why it
//! deliberately did nothing yet).
//!
//! Exactly `kestrel-net`'s own real, tested call order
//! (`kestrel-net/tests/lifecycle.rs`): `Ipam::load` + `.allocate(id)` ->
//! `ensure_bridge` -> (netns already created + joined by `bundle.rs`) ->
//! `attach_veth` -> `enable_forwarding_sysctls` -> `ensure_masquerade` ->
//! `add_dnat` per published port. Teardown reuses `kestrel-net`'s own
//! composed `bridge::teardown_bridge_network` (the SAME call
//! `test_teardown_leaves_no_rules` uses), not a hand-rolled
//! reimplementation of its steps.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use ipnetwork::Ipv4Network;
use rtnetlink::Handle;

use crate::registry::ContainerMeta;

/// `kestreld`'s own bookkeeping of one container's bridge-mode network
/// attachment — persisted into `meta.json` (`registry::ContainerMeta`)
/// so it survives a `kestreld` restart, and returned directly by `GET
/// /containers/:id/network`.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkInfo {
    /// "bridge" | "host" | "none" | "container:<id>" — this module only
    /// ever constructs `"bridge"` values (the only mode it attaches
    /// anything for), but the field itself is mode-agnostic per Task 17's
    /// own spec, matching `bundle::NetworkMode`'s four-way shape.
    pub mode: String,
    pub bridge_name: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub published_ports: Vec<(u16, u16)>,
}

/// Daemon-wide IPAM state lives under its own `<data_dir>/network/`
/// subtree — separate from `<data_dir>/containers/<id>/meta.json`
/// (per-container) since the allocation bitmap is shared, subnet-wide
/// state, not something any one container owns.
// `pub(crate)`, not private: this module's own root-gated test
// (`main.rs`) needs to load the exact same IPAM state this module itself
// writes to, to prove a deleted container's IP allocation was genuinely
// released rather than leaked — reusing this function keeps that
// assertion honest (the SAME path convention, not a hand-duplicated
// guess at it).
pub(crate) fn ipam_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("network").join("ipam.json")
}

fn parse_subnet_gateway(cfg: &kestreld::config::NetworkConfig) -> anyhow::Result<(Ipv4Network, Ipv4Addr)> {
    let subnet: Ipv4Network = cfg
        .subnet
        .parse()
        .with_context(|| format!("parsing config.network.subnet {:?}", cfg.subnet))?;
    let gateway: Ipv4Addr = cfg
        .gateway
        .parse()
        .with_context(|| format!("parsing config.network.gateway {:?}", cfg.gateway))?;
    Ok((subnet, gateway))
}

/// Opens a fresh rtnetlink connection and spawns its driving task. One per
/// `attach`/`teardown` call rather than a long-lived `Handle` threaded
/// through `AppState`: bridge-mode attachment/teardown only ever happens
/// at container create/delete time, never a hot path, and a dedicated
/// `AppState` field would mean touching every one of this crate's many
/// existing `AppState { .. }` test-literal construction sites just to
/// satisfy the type, the same churn `AppState.network`'s own addition
/// already required — not worth paying twice for something this
/// infrequently used. A single extra netlink socket per create/delete is
/// negligible.
async fn open_netlink() -> anyhow::Result<Handle> {
    let (connection, handle, _) = rtnetlink::new_connection().context("opening rtnetlink connection")?;
    tokio::spawn(connection);
    Ok(handle)
}

/// Serializes every bridge-mode attach/teardown against every other one.
/// Closes a real race `kestrel-net`'s own `Ipam` has no protection
/// against by itself: `Ipam::load` reads a plain JSON file, mutates an
/// in-memory copy, then persists — two concurrent callers each loading
/// before the other's `allocate()`/`release()` has persisted could
/// otherwise silently hand out the same address (allocate) or clobber
/// each other's write (release). `kestrel-net`'s own tests never hit this
/// because each test is single-threaded within its own isolated process;
/// `kestreld` genuinely serves concurrent HTTP requests, so this module
/// is the right place to close the gap.
static NETWORK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The real post-create bridge-mode attachment sequence (Task 17 Step 2).
/// `netns_pin` is the SAME pin path `bundle.rs`'s `create_netns` call
/// created and `config.json`'s `Network` namespace `path` referenced —
/// the caller (`api::containers::create_container`) already has it via
/// `MaterializedBundle::netns_pin_to_cleanup_on_failure`, which (despite
/// its failure-focused name — see that field's own doc comment) is
/// populated on a SUCCESSFUL create too, since it's the same pin
/// regardless of the eventual outcome.
///
/// On any failure partway through, the IP allocation this call itself
/// made is rolled back (`ipam.release`) before returning — every
/// `kestrel-net` function this calls already cleans up its OWN partial
/// state on error (see `attach_veth`'s and `ensure_bridge`'s own doc
/// comments), so this is the one further layer this function owns: never
/// leak an IPAM allocation for a container whose networking never
/// actually finished attaching. The caller is responsible for the
/// broader rollback (force-deleting the container itself, tearing down
/// the netns pin) — this function only owns IPAM's own state.
///
/// `attach_inner`'s own published-ports loop additionally rolls back any
/// DNAT rule it itself already added before a LATER port's `add_dnat`
/// call fails — a gap found by adversarial review: without it, a stale
/// DNAT rule for an earlier, successfully-added port would survive
/// `ipam.release`'s recycling of `ip` back into the allocatable pool,
/// silently forwarding host traffic to whatever future, unrelated
/// container happens to receive that address next. See `attach_inner`'s
/// own doc comment/body for the detail; this is purely internal to that
/// function's own partial state and doesn't change what this function
/// itself rolls back.
pub async fn attach(
    id: &str,
    netns_pin: &Path,
    data_dir: &Path,
    cfg: &kestreld::config::NetworkConfig,
    published_ports: &[(u16, u16)],
) -> anyhow::Result<NetworkInfo> {
    let _guard = NETWORK_LOCK.lock().await;
    let (subnet, gateway) = parse_subnet_gateway(cfg)?;

    let mut ipam = kestrel_net::ipam::Ipam::load(subnet, gateway, ipam_state_path(data_dir))
        .context("loading IPAM state")?;
    let ip = ipam.allocate(id).context("allocating a container IP")?;

    match attach_inner(id, netns_pin, cfg, subnet, gateway, ip, published_ports).await {
        Ok(()) => Ok(NetworkInfo {
            mode: "bridge".to_string(),
            bridge_name: Some(cfg.bridge.clone()),
            ip: Some(ip),
            gateway: Some(gateway),
            published_ports: published_ports.to_vec(),
        }),
        Err(e) => {
            if let Err(release_err) = ipam.release(ip) {
                tracing::warn!(
                    id,
                    error = %release_err,
                    "failed to release IPAM allocation after a failed network attach"
                );
            }
            Err(e)
        }
    }
}

/// The real, tested call order from `kestrel-net/tests/lifecycle.rs`:
/// `ensure_bridge` -> `attach_veth` -> `enable_forwarding_sysctls` ->
/// `ensure_masquerade` -> `add_dnat` per published port. NAT setup
/// (the last three calls) is skipped entirely when `cfg.iptables` is
/// `false` (SPEC.md §17's `network.iptables` knob) — the veth/bridge
/// attachment itself (container<->container, container<->bridge
/// reachability) is NOT gated by this flag, only the iptables-managed
/// NAT/DNAT rules are.
async fn attach_inner(
    id: &str,
    netns_pin: &Path,
    cfg: &kestreld::config::NetworkConfig,
    subnet: Ipv4Network,
    gateway: Ipv4Addr,
    ip: Ipv4Addr,
    published_ports: &[(u16, u16)],
) -> anyhow::Result<()> {
    let handle = open_netlink().await?;

    let bridge_idx = kestrel_net::bridge::ensure_bridge(&handle, &cfg.bridge, gateway, subnet)
        .await
        .context("ensuring bridge exists")?;

    kestrel_net::veth::attach_veth(&handle, id, netns_pin, bridge_idx, ip, subnet, gateway)
        .await
        .context("attaching veth pair")?;

    if cfg.iptables {
        kestrel_net::nat::enable_forwarding_sysctls().context("enabling ip forwarding sysctls")?;
        kestrel_net::nat::ensure_masquerade(subnet, &cfg.bridge)
            .context("ensuring masquerade/forward rules")?;

        // Track every port that DID succeed as we go, so a LATER port's
        // `add_dnat` failure (duplicate host_port already in use by
        // something else, an iptables resource limit, ...) can be rolled
        // back before the error propagates — otherwise a stale DNAT rule
        // forwarding `host_port` to `ip` would survive in iptables even
        // though the caller (`attach`'s `Err` arm) is about to release
        // `ip` back into the allocatable IPAM pool, silently handing a
        // future, unrelated container that recycled `ip` traffic on a
        // port it never asked to publish. This is purely this function's
        // OWN partial state (this loop's earlier iterations) — it does
        // not duplicate or conflict with `attach`'s outer IPAM-release
        // rollback, which is unaffected by DNAT rules either way.
        let mut added_ports: Vec<(u16, u16)> = Vec::with_capacity(published_ports.len());
        for (host_port, container_port) in published_ports {
            if let Err(e) = kestrel_net::nat::add_dnat(*host_port, ip, *container_port) {
                for (added_host_port, added_container_port) in &added_ports {
                    // `remove_dnat` is confirmed idempotent/safe even for
                    // a rule that was never added, so a failure here (best
                    // effort — logged, not propagated) can't make things
                    // worse than leaving the original error unrolled-back.
                    if let Err(cleanup_err) =
                        kestrel_net::nat::remove_dnat(*added_host_port, ip, *added_container_port)
                    {
                        tracing::warn!(
                            id,
                            host_port = added_host_port,
                            container_port = added_container_port,
                            error = %cleanup_err,
                            "failed to roll back an already-added DNAT rule after a later published-port DNAT failure"
                        );
                    }
                }
                return Err(e)
                    .with_context(|| format!("adding published-port DNAT rule for {host_port}->{container_port}"));
            }
            added_ports.push((*host_port, *container_port));
        }
    }

    Ok(())
}

/// Delete-time teardown (Task 17 Step 3) — the real implementation of the
/// `network::teardown(...)` call `api::containers::delete_container`
/// (Task 9) stubbed out. Reuses `kestrel-net`'s own composed
/// `bridge::teardown_bridge_network` (host-side veth deletion, which also
/// destroys the peer; `remove_dnat` per published port; `Ipam::release`;
/// `teardown_netns`) — the SAME call `kestrel-net`'s own
/// `tests/lifecycle.rs::test_teardown_leaves_no_rules` uses to prove a
/// full bridge-mode lifecycle leaves zero residue, so this is the real,
/// tested teardown path, not a hand-rolled reimplementation of its steps.
///
/// A no-op (not an error) if `meta.network` is `None` or carries no `ip`
/// — e.g. a non-bridge-mode container, or a bridge-mode container whose
/// attach step never got far enough to record a real IP — matching
/// `kestrel-net`'s own established "already gone is success" idiom for
/// release/teardown operations.
pub async fn teardown(
    run_dir: &Path,
    data_dir: &Path,
    id: &str,
    cfg: &kestreld::config::NetworkConfig,
    meta: &ContainerMeta,
) -> anyhow::Result<()> {
    let Some(network) = meta.network.as_ref() else {
        return Ok(());
    };
    let Some(ip) = network.ip else {
        return Ok(());
    };

    let _guard = NETWORK_LOCK.lock().await;
    let (subnet, gateway) = parse_subnet_gateway(cfg)?;
    let mut ipam = kestrel_net::ipam::Ipam::load(subnet, gateway, ipam_state_path(data_dir))
        .context("loading IPAM state")?;

    let handle = open_netlink().await?;
    kestrel_net::bridge::teardown_bridge_network(&handle, run_dir, id, &mut ipam, ip, &network.published_ports)
        .await
        .context("tearing down bridge-mode networking")
}

// ---------------------------------------------------------------------
// Adversarial-review regression test: `attach_inner`'s published-ports
// DNAT loop must roll back every port it itself already added before a
// LATER port's `add_dnat` fails, rather than leaving those rules behind
// for `attach`'s outer IPAM-release rollback to orphan (see `attach`'s
// own doc comment for the full failure scenario). Lives here (a plain
// `#[cfg(test)]` unit test inside this crate, not `crates/kestreld/tests/`)
// since it exercises `attach`/`attach_inner` directly against a real
// netns/bridge/iptables state, the same "directly against the real
// module, real root-gated networking" shape every other Task 17 test in
// this workspace (`kestrel-net/tests/lifecycle.rs`, this crate's own
// `main.rs` root-gated tests) already uses — no HTTP layer is needed to
// prove this specific gap is closed.
#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// Restores the process-wide `PATH` env var on drop. This test
    /// temporarily shadows the real `iptables` binary (see
    /// [`install_poison_iptables`]) for the duration of one `attach()`
    /// call — every root-gated test in this workspace runs serially
    /// (`Makefile`'s `test-root` target passes `--test-threads=1`
    /// specifically so root-gated tests don't interleave), so mutating
    /// this process's own env var for that single call is safe, but it
    /// must still be restored afterward (including on panic/early
    /// return, which `Drop` covers) so it can't leak into whatever test
    /// runs next in the same process.
    struct PathGuard(String);
    impl Drop for PathGuard {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.0);
        }
    }

    /// Writes a fake `iptables` into a fresh directory that forwards
    /// every invocation to the REAL `iptables` binary UNCHANGED, except
    /// one: an `-A` (append) invocation whose `--dport` argument is
    /// `poison_port` is rejected outright (exit 1, no real iptables call
    /// made) instead of actually running.
    ///
    /// This is the fault-injection this test needs to reproduce the bug
    /// for real: `kestrel_net::nat::add_dnat` is internally idempotent
    /// (an already-`-C`-existing rule is treated as success, never an
    /// error) and real `iptables` itself is perfectly happy to append
    /// multiple non-identical rules that all match the same `--dport`
    /// (first-match-wins semantics; no conflict), so there is no way to
    /// make a LATER published port's `add_dnat` genuinely return `Err`
    /// merely by pre-planting a conflicting-looking rule — a real
    /// `add_dnat` failure only actually happens for reasons external to
    /// the rule content itself (an iptables/nftables resource limit,
    /// `xtables` lock contention, ...), which this reproduces
    /// deterministically instead of relying on a racy/environment-
    /// specific condition.
    fn install_poison_iptables(dir: &Path, poison_port: u16) {
        let real_iptables = "/usr/sbin/iptables";
        assert!(
            Path::new(real_iptables).is_file(),
            "expected the real iptables binary at {real_iptables} in this project's Lima VM \
             — adjust this path if that ever changes"
        );
        let script = format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
is_add=false
has_poison=false
prev=""
for a in "$@"; do
    if [[ "$a" == "-A" ]]; then is_add=true; fi
    if [[ "$prev" == "--dport" && "$a" == "{poison_port}" ]]; then has_poison=true; fi
    prev="$a"
done
if [[ "$is_add" == "true" && "$has_poison" == "true" ]]; then
    echo "fake-iptables: injected failure for poison dport {poison_port}" >&2
    exit 1
fi
exec "{real_iptables}" "$@"
"#
        );
        let path = dir.join("iptables");
        std::fs::write(&path, script).expect("writing fake iptables script");
        let mut perms = std::fs::metadata(&path).expect("stat fake iptables script").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod +x fake iptables script");
    }

    /// Reproduces the exact bug an adversarial reviewer found in
    /// `attach_inner`'s published-ports loop: two ports are published,
    /// the FIRST one's `add_dnat` genuinely succeeds (a real DNAT rule is
    /// added to `KESTREL-PREROUTING`), the SECOND one's `add_dnat` is
    /// forced to fail (via [`install_poison_iptables`]) — before the fix,
    /// `attach_inner` propagated that error with the first port's DNAT
    /// rule left behind; `attach`'s own `Err` arm only released the IPAM
    /// allocation, never touching NAT state at all. After the fix,
    /// `attach_inner` itself rolls back every port it already added
    /// before returning the error, so no DNAT rule for EITHER port
    /// should remain.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires root"]
    async fn test_attach_rolls_back_earlier_dnat_rules_on_a_later_port_failure() {
        let bridge_name = "kbr-t17rb0";
        let cfg = kestreld::config::NetworkConfig {
            bridge: bridge_name.to_string(),
            subnet: "172.71.0.0/24".to_string(),
            gateway: "172.71.0.1".to_string(),
            mtu: 1500,
            iptables: true,
            rootless_backend: "pasta".to_string(),
        };

        let run_dir = tempfile::tempdir().expect("run_dir tempdir");
        let data_dir = tempfile::tempdir().expect("data_dir tempdir");
        let id = "rollbck1";

        // Matches production sequencing (`bundle.rs` creates+pins the
        // netns BEFORE `network::attach` is ever called) rather than
        // letting `attach_inner` itself create one.
        let netns_pin = kestrel_net::netns::create_netns(run_dir.path(), id)
            .await
            .expect("creating the container's real netns pin");

        let good_host_port: u16 = 29800;
        let poison_host_port: u16 = 29801;
        let published_ports = vec![(good_host_port, 9800), (poison_host_port, 9801)];

        let fake_bin_dir = tempfile::tempdir().expect("fake bin tempdir");
        install_poison_iptables(fake_bin_dir.path(), poison_host_port);

        let original_path = std::env::var("PATH").expect("PATH must be set in this test environment");
        let path_guard = PathGuard(original_path.clone());
        std::env::set_var("PATH", format!("{}:{original_path}", fake_bin_dir.path().display()));

        let result = attach(id, &netns_pin, data_dir.path(), &cfg, &published_ports).await;

        // Restore the real `iptables` on PATH before inspecting real
        // iptables state below -- everything from here on must observe
        // genuine kernel state, not the fake binary's.
        drop(path_guard);

        assert!(
            result.is_err(),
            "attach() must fail overall when a later published port's add_dnat fails, got: {result:?}"
        );

        // THE assertion this test exists for: no DNAT rule for the
        // EARLIER port (which DID succeed before the later failure) may
        // survive -- otherwise it would silently keep forwarding host
        // traffic on `good_host_port` to `ip` even after `attach`'s
        // `Err` arm releases `ip` back into the allocatable IPAM pool,
        // exactly the residue-outlives-the-address bug this fix closes.
        // Same real-iptables-inspection technique
        // `kestrel-net/tests/lifecycle.rs` already established
        // (`iptables -t <table> -S`, read directly via `Command`).
        let output = std::process::Command::new("iptables")
            .args(["-t", "nat", "-S", kestrel_net::nat::PREROUTING_CHAIN])
            .output()
            .expect("listing KESTREL-PREROUTING rules");
        let rules = String::from_utf8_lossy(&output.stdout);
        assert!(
            !rules.contains(&good_host_port.to_string()),
            "a DNAT rule for the earlier, successfully-added port {good_host_port} must have \
             been rolled back after the later port {poison_host_port}'s add_dnat failed, but \
             KESTREL-PREROUTING still contains it:\n{rules}"
        );
        assert!(
            !rules.contains(&poison_host_port.to_string()),
            "the poisoned port {poison_host_port} itself must never have been left behind either:\n{rules}"
        );

        // ---- cleanup: this test's own bridge/veth/netns/NAT state ----
        let _ = kestrel_net::netns::teardown_netns(run_dir.path(), id);
        let (connection, handle, _) = rtnetlink::new_connection().expect("rtnetlink connection");
        tokio::spawn(connection);
        if let Some(idx) = kestrel_net::bridge::find_link_index(&handle, bridge_name).await.ok().flatten() {
            let _ = handle.link().del(idx).execute().await;
        }
        let _ = kestrel_net::nat::teardown_all(bridge_name);
    }
}
