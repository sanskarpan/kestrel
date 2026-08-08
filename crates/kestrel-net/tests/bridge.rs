// crates/kestrel-net/tests/bridge.rs

use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use kestrel_net::bridge::{delete_bridge, ensure_bridge, find_link_index};

#[path = "common/mod.rs"]
mod common;

#[tokio::test]
#[ignore = "requires root"]
async fn test_ensure_bridge_creates_assigns_and_brings_up() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let name = "kbr-test0";
        let gateway: Ipv4Addr = "172.30.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.30.0.0/24".parse().unwrap();

        let idx = ensure_bridge(&handle, name, gateway, subnet).await.unwrap();
        assert!(find_link_index(&handle, name).await.unwrap().is_some());

        // Idempotent: calling again must not error or duplicate anything.
        let idx2 = ensure_bridge(&handle, name, gateway, subnet).await.unwrap();
        assert_eq!(idx, idx2);

        delete_bridge(&handle, name).await.unwrap();
        assert!(find_link_index(&handle, name).await.unwrap().is_none());
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_find_link_index_returns_none_for_missing_link() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        // Kept within IFNAMSIZ (16 bytes incl. NUL, i.e. <=15 chars) —
        // a longer name gets rejected by the kernel's own IFLA_IFNAME
        // length validation with -ERANGE before it ever reaches the
        // "does this device exist" check that would yield -ENODEV, which
        // would defeat the point of this test (confirmed empirically
        // while developing `find_link_index`'s ENODEV-detection).
        assert!(find_link_index(&handle, "kbr-missing0").await.unwrap().is_none());
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_delete_bridge_is_idempotent_when_absent() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        // Deleting a bridge that was never created must not error. Name
        // kept <=15 chars for the same IFNAMSIZ reason as above.
        delete_bridge(&handle, "kbr-absent0").await.unwrap();
    })
    .await;
}
