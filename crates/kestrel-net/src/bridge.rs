// crates/kestrel-net/src/bridge.rs
//
//! Shared-bridge lifecycle: create-if-missing, gateway address
//! assignment, and bring-up (`ensure_bridge`), plus link deletion
//! (`delete_bridge`) and the per-container teardown entrypoint stub
//! (`teardown_bridge_network`).

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use ipnetwork::Ipv4Network;
use rtnetlink::{Handle, LinkBridge, LinkUnspec};

/// Finds a link's kernel ifindex by name, or `None` if it doesn't exist.
///
/// `rtnetlink`'s `match_name` performs a *targeted* `RTM_GETLINK` lookup
/// (not a dump — confirmed by reading `link/get.rs` at the vendored
/// v0.21.0 source: `match_name` sets `dump = false`). For a targeted
/// lookup, a nonexistent link does NOT come back as an empty stream —
/// the kernel replies with an `NLMSG_ERROR` carrying `-ENODEV`, which
/// surfaces here as `Err(rtnetlink::Error::NetlinkError(msg))` with
/// `msg.code == Some(-ENODEV)`. That specific error is therefore treated
/// as "not found" (`Ok(None)`); every other error is propagated.
///
/// Confirmed empirically (kernel 6.8, inside this project's Lima VM):
/// callers must keep `name` within `IFNAMSIZ` (16 bytes including the
/// NUL terminator, i.e. at most 15 characters) — a longer name is
/// rejected by the kernel's own `IFLA_IFNAME` attribute-length
/// validation with `-ERANGE` *before* the "does this device exist"
/// check ever runs, so an over-long name would NOT be treated as "not
/// found" by the `is_enodev` check below and would instead surface as a
/// genuine error.
pub async fn find_link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await {
        Ok(Some(msg)) => Ok(Some(msg.header.index)),
        Ok(None) => Ok(None),
        Err(rtnetlink::Error::NetlinkError(ref msg)) if is_enodev(msg) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("looking up link {name}")),
    }
}

/// True if a netlink `ErrorMessage`'s code is exactly `-ENODEV` — the
/// kernel's "no such device" response to a targeted (non-dump)
/// `RTM_GETLINK`/`RTM_GETADDR` lookup for a link/address that doesn't
/// exist. Netlink error codes are raw negated `errno` values.
///
/// Uses `rtnetlink::packet_core::ErrorMessage` (the crate's own
/// re-export of `netlink_packet_core::ErrorMessage`) rather than adding
/// `netlink-packet-core` as a separate direct dependency just for this
/// one type.
fn is_enodev(msg: &rtnetlink::packet_core::ErrorMessage) -> bool {
    msg.code.map(|c| c.get()) == Some(-libc::ENODEV)
}

/// True if the given link already has `gateway` assigned to it.
///
/// Verified against the real vendored `rtnetlink` v0.21.0 source
/// (`src/addr/handle.rs`, `src/addr/get.rs`) — `AddressHandle::get()`
/// returns an `AddressGetRequest`, which supports `set_link_index_filter`
/// and `set_address_filter` (client-side filters applied to a full
/// `RTM_GETADDR` dump — see `get.rs`'s own comment explaining why
/// filtering is done client-side rather than via a targeted kernel
/// query: unlike links, addresses can't be looked up by an exact
/// kernel-side match). A non-empty resulting stream means the address is
/// already present.
async fn link_has_address(handle: &Handle, index: u32, address: Ipv4Addr) -> Result<bool> {
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .set_address_filter(IpAddr::V4(address))
        .execute();
    addrs
        .try_next()
        .await
        .with_context(|| format!("querying addresses on link index {index}"))
        .map(|maybe| maybe.is_some())
}

/// Creates the bridge if it doesn't already exist, assigns it the
/// gateway address, and brings it up. Idempotent — safe to call on every
/// daemon start / container create.
pub async fn ensure_bridge(
    handle: &Handle,
    name: &str,
    gateway: Ipv4Addr,
    subnet: Ipv4Network,
) -> Result<u32> {
    let idx = match find_link_index(handle, name).await? {
        Some(idx) => idx,
        None => {
            handle
                .link()
                .add(LinkBridge::new(name).build())
                .execute()
                .await
                .with_context(|| format!("creating bridge {name}"))?;
            find_link_index(handle, name)
                .await?
                .with_context(|| format!("bridge {name} not found immediately after creating it"))?
        }
    };

    // Idempotent address assignment: adding the same address twice
    // returns EEXIST from the kernel, which is fine — check first rather
    // than relying on error-code-sniffing, since "does this link already
    // have this address" is a cheap, clear query.
    let already_has_gateway = link_has_address(handle, idx, gateway).await?;

    if !already_has_gateway {
        handle
            .address()
            .add(idx, IpAddr::V4(gateway), subnet.prefix())
            .execute()
            .await
            .with_context(|| format!("assigning gateway {gateway} to bridge {name}"))?;
    }

    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await
        .with_context(|| format!("bringing up bridge {name}"))?;

    Ok(idx)
}

/// Deletes the bridge link. Part of a full daemon-level network
/// teardown, NOT called per-container (the bridge is shared across every
/// bridge-mode container) — kept separate from
/// [`teardown_bridge_network`], which tears down one CONTAINER's
/// networking, not the shared bridge itself.
pub async fn delete_bridge(handle: &Handle, name: &str) -> Result<()> {
    if let Some(idx) = find_link_index(handle, name).await? {
        handle
            .link()
            .del(idx)
            .execute()
            .await
            .with_context(|| format!("deleting bridge {name}"))?;
    }
    Ok(())
}

/// The composed, single-call teardown for ONE container's bridge-mode
/// networking — mirrors `attach_bridge`'s composed setup from the
/// opposite direction: deletes the host-side veth link (which also
/// destroys its peer, since a veth pair is one link with two ends),
/// removes this container's published-port DNAT rules, releases its IP
/// back to IPAM, and tears down its pinned network namespace.
pub async fn teardown_bridge_network(
    handle: &Handle,
    run_dir: &std::path::Path,
    id: &str,
    ipam: &mut crate::ipam::Ipam,
    container_ip: Ipv4Addr,
    published_ports: &[(u16, u16)],
) -> Result<()> {
    // Host-side veth link deletion: deleting the host end also removes
    // the peer (a veth pair is one link with two ends — the kernel tears
    // down both together), so no separate in-netns deletion is needed.
    let (host_if, _peer_if) = crate::veth::veth_names(id);
    if let Some(idx) = find_link_index(handle, &host_if).await? {
        handle.link().del(idx).execute().await.with_context(|| format!("deleting {host_if}"))?;
    }

    for (host_port, container_port) in published_ports {
        crate::nat::remove_dnat(*host_port, container_ip, *container_port)?;
    }

    ipam.release(container_ip)?;
    crate::netns::teardown_netns(run_dir, id)?;
    Ok(())
}
