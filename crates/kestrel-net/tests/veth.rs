// crates/kestrel-net/tests/veth.rs

use std::net::Ipv4Addr;

use futures_util::TryStreamExt;
use ipnetwork::Ipv4Network;
use kestrel_net::bridge::{ensure_bridge, find_link_index};
use kestrel_net::netns::{create_netns, nsenter, teardown_netns};
use kestrel_net::veth::{attach_veth, deterministic_mac};
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::RouteMessageBuilder;

#[path = "common/mod.rs"]
mod common;

#[test]
fn test_deterministic_mac_is_locally_administered_and_stable() {
    let ip: Ipv4Addr = "172.29.0.5".parse().unwrap();
    let mac1 = deterministic_mac(ip);
    let mac2 = deterministic_mac(ip);
    assert_eq!(mac1, mac2, "must be deterministic across calls");
    assert_eq!(mac1[0] & 0x02, 0x02, "must have the locally-administered bit set");
    assert_eq!(mac1[0] & 0x01, 0x00, "must NOT have the multicast bit set (a real unicast MAC)");
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_attach_veth_produces_working_container_networking() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let bridge_name = "kbr-vtest0";
        let gateway: Ipv4Addr = "172.31.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.31.0.0/24".parse().unwrap();
        let container_ip: Ipv4Addr = "172.31.0.7".parse().unwrap();
        let id = "vethtest1";

        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let pin = create_netns(run_dir, id).await.unwrap();

        attach_veth(&handle, id, &pin, bridge_idx, container_ip, subnet, gateway)
            .await
            .expect("attach_veth must succeed against a real kernel");

        // --- Host-side assertions: the host-side veth exists, is
        // enslaved to the bridge, and is up. ---
        let host_if = format!("veth{}", &id[..id.len().min(8)]);
        let host_idx = find_link_index(&handle, &host_if)
            .await
            .unwrap()
            .expect("host-side veth must exist after attach_veth");

        let mut host_links = handle.link().get().match_index(host_idx).execute();
        let host_msg = host_links.try_next().await.unwrap().expect("host-side veth link message");
        assert!(host_msg.header.flags.contains(LinkFlags::Up), "host-side veth must be up");
        let enslaved_to = host_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Controller(idx) => Some(*idx),
            _ => None,
        });
        assert_eq!(enslaved_to, Some(bridge_idx), "host-side veth must be enslaved to the bridge");

        // --- Container-side assertions: nsenter into the container's
        // netns and query it directly via a fresh rtnetlink connection
        // (real rtnetlink queries, not `ip addr`/`ip route`). ---
        let pin_for_closure = pin.clone();
        tokio::task::block_in_place(move || {
            nsenter(&pin_for_closure, move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("building in-netns verification runtime");
                rt.block_on(async move {
                    let (connection, inner_handle, _) = rtnetlink::new_connection().unwrap();
                    tokio::spawn(connection);

                    // eth0 must exist (renamed from the peer veth name).
                    let eth0_idx = find_link_index(&inner_handle, "eth0")
                        .await
                        .unwrap()
                        .expect("eth0 must exist inside the container netns");

                    let mut eth0_links = inner_handle.link().get().match_index(eth0_idx).execute();
                    let eth0_msg = eth0_links.try_next().await.unwrap().expect("eth0 link message");
                    assert!(eth0_msg.header.flags.contains(LinkFlags::Up), "eth0 must be up");

                    let mac = eth0_msg
                        .attributes
                        .iter()
                        .find_map(|a| match a {
                            LinkAttribute::Address(addr) => Some(addr.clone()),
                            _ => None,
                        })
                        .expect("eth0 must have a MAC address attribute");
                    assert_eq!(mac, deterministic_mac(container_ip).to_vec(), "eth0's MAC must be the deterministic MAC for its IP");

                    // eth0 must carry the assigned container IP.
                    let mut addrs = inner_handle.address().get().set_link_index_filter(eth0_idx).execute();
                    let mut found_ip = false;
                    while let Some(addr_msg) = addrs.try_next().await.unwrap() {
                        for attr in &addr_msg.attributes {
                            if let rtnetlink::packet_route::address::AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
                                if *a == container_ip {
                                    found_ip = true;
                                }
                            }
                        }
                    }
                    assert!(found_ip, "eth0 must have the assigned container IP {container_ip}");

                    // lo must be up.
                    let lo_idx = find_link_index(&inner_handle, "lo").await.unwrap().expect("lo must exist");
                    let mut lo_links = inner_handle.link().get().match_index(lo_idx).execute();
                    let lo_msg = lo_links.try_next().await.unwrap().expect("lo link message");
                    assert!(lo_msg.header.flags.contains(LinkFlags::Up), "lo must be up");

                    // A genuine default route (0.0.0.0/0) via the bridge
                    // gateway must be present — queried via
                    // handle.route().get(), a real rtnetlink route dump,
                    // not a shelled-out `ip route show`.
                    let route_query = RouteMessageBuilder::<Ipv4Addr>::new().build();
                    let mut routes = inner_handle.route().get(route_query).execute();
                    let mut found_default_route = false;
                    while let Some(route_msg) = routes.try_next().await.unwrap() {
                        let is_default = route_msg.header.destination_prefix_length == 0
                            && !route_msg.attributes.iter().any(|a| matches!(a, RouteAttribute::Destination(_)));
                        let has_our_gateway = route_msg
                            .attributes
                            .iter()
                            .any(|a| matches!(a, RouteAttribute::Gateway(RouteAddress::Inet(gw)) if *gw == gateway));
                        if is_default && has_our_gateway {
                            found_default_route = true;
                        }
                    }
                    assert!(found_default_route, "must have a genuine default route (0.0.0.0/0) via the bridge gateway {gateway}");

                    Ok::<(), anyhow::Error>(())
                })
            })
        })
        .expect("in-netns verification must succeed");

        teardown_netns(run_dir, id).unwrap();
    })
    .await;
}

/// Self-review item from the task: does `attach_veth` clean up after
/// itself if it fails partway through? This deliberately triggers a
/// REAL failure — an enslave-to-bridge call against a bogus,
/// nonexistent `bridge_idx` — at a point where the peer end has
/// ALREADY been moved into the container's netns (the move-by-fd step
/// runs before the enslave step), which is exactly the scenario the
/// task's self-review flagged. Asserts, via real rtnetlink queries in
/// both namespaces, that no half-attached veth is left behind anywhere:
/// not the host-side link, and not the peer/`eth0` end that was already
/// living inside the container's netns at the moment of failure.
#[tokio::test]
#[ignore = "requires root"]
async fn test_attach_veth_cleans_up_veth_pair_on_partial_failure() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let gateway: Ipv4Addr = "172.32.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.32.0.0/24".parse().unwrap();
        let container_ip: Ipv4Addr = "172.32.0.9".parse().unwrap();
        let id = "vethfail1";

        // Deliberately bogus: no link with this ifindex exists, so the
        // "enslave host_if to the bridge" step (which runs AFTER the
        // peer has already been moved into the container netns) must
        // fail against a real kernel.
        let bogus_bridge_idx: u32 = 0x7fff_fffe;

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let pin = create_netns(run_dir, id).await.unwrap();

        let result = attach_veth(&handle, id, &pin, bogus_bridge_idx, container_ip, subnet, gateway).await;
        assert!(result.is_err(), "attach_veth must fail against a bogus bridge index");

        // Host-side: the veth must be gone, not half-created.
        let host_if = format!("veth{}", &id[..id.len().min(8)]);
        assert!(
            find_link_index(&handle, &host_if).await.unwrap().is_none(),
            "host-side veth must be cleaned up after a partial-attach failure"
        );

        // Container-side: the peer end (already moved into this netns
        // before the failure) must be gone too — deleting the host end
        // of a veth pair destroys BOTH ends, wherever they live.
        let peer_if = format!("{host_if}p");
        let pin_for_closure = pin.clone();
        let leftover_in_netns = tokio::task::block_in_place(move || {
            nsenter(&pin_for_closure, move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("building in-netns verification runtime");
                rt.block_on(async move {
                    let (connection, inner_handle, _) = rtnetlink::new_connection().unwrap();
                    tokio::spawn(connection);
                    let peer_present = find_link_index(&inner_handle, &peer_if).await?.is_some();
                    let eth0_present = find_link_index(&inner_handle, "eth0").await?.is_some();
                    Ok::<bool, anyhow::Error>(peer_present || eth0_present)
                })
            })
        })
        .expect("in-netns verification must succeed");
        assert!(!leftover_in_netns, "no leftover peer/eth0 must remain inside the container netns after cleanup");

        teardown_netns(run_dir, id).unwrap();
    })
    .await;
}
