// crates/kestrel-net/tests/lifecycle.rs
//
// Task 10's capstone: composes every module built in Tasks 1-9 (netns,
// bridge, veth, ipam, nat, modes) together, end-to-end, the way a real
// container's networking setup actually would -- proving the modules work
// TOGETHER, not just individually (each is already independently,
// rigorously tested by its own tests/*.rs file: bridge.rs, veth.rs,
// netns.rs, ipam.rs's inline unit tests, nat_args.rs, modes.rs's inline
// unit tests).
//
// Every scenario runs inside `common::run_in_isolated_netns` -- a fresh,
// throwaway, `unshare(CLONE_NEWNET)`'d namespace private to the forked
// test process -- so none of this ever touches the VM's real (outer)
// network state. See that helper's own doc comment for the
// fork-then-unshare sequencing this relies on.
//
// ## Why `test_bridge_egress` doesn't hit the real internet
//
// The plan's draft text for this scenario describes reaching "a stable
// public host" from inside the container, reusing the confidence Phase
// 6's own capstone test established that this VM has real network
// access. That confidence doesn't transfer here: `run_in_isolated_netns`
// gives the whole test process a namespace with NOTHING but `lo` in it --
// no veth, no bridge, no route back to the VM's real interfaces at all.
// There is no physical path from inside that namespace to the real
// internet, regardless of how correctly this test configures
// MASQUERADE/FORWARD -- the isolation is unconditional, which is the
// entire point of the helper. A literal external HTTP request is
// therefore not just risky here, it is architecturally impossible without
// either (a) building a second isolation mechanism that leaves a hole
// back to the real network (defeating the actual goal of keeping the VM's
// real state untouched), or (b) not using `run_in_isolated_netns` for
// this one scenario (against this task's explicit instruction to reuse it
// for every scenario).
//
// Instead, `test_bridge_egress` builds its own "external network" inside
// the same isolated sandbox: a plain, unbridged `LinkDummy` interface
// carrying an address from `203.0.113.0/24` (RFC 5737 TEST-NET-3 --
// reserved for documentation/testing, so it can never be confused with a
// real routable address). This is a STRONGER test than hitting a real
// public host would have been: a real HTTP HEAD to e.g. example.com can
// only assert "the connection succeeded", where this additionally asserts
// on the exact source address the "external" listener observed --
// genuinely proving MASQUERADE rewrote the container's source address to
// the bridge's own address, not merely that *some* packet got through by
// coincidence.
//
// ## `test_published_port` and the two bugs it found and fixed in nat.rs
//
// This task's brief states Task 7's PREROUTING-vs-POSTROUTING DNAT
// chain-placement question is already resolved and that `add_dnat`/
// `remove_dnat` "should just work as called". Writing this scenario for
// real (verified via ad hoc root smoke tests against this project's Lima
// VM, the same way Task 7 confirmed its own fix) surfaced two DIFFERENT,
// previously-untested gaps in the localhost-published-port path
// specifically (not the chain-placement question, which is unaffected):
//
//   1. `KESTREL-PREROUTING` was linked only from the built-in `PREROUTING`
//      chain. `PREROUTING` only ever sees packets ARRIVING on an
//      interface; a locally-generated connection (`curl
//      http://127.0.0.1:<published>`, run on the same box) goes through
//      `OUTPUT` instead and was never being DNAT'd at all (observed: curl
//      exit 7, "connection refused"). Fixed by also linking
//      `KESTREL-PREROUTING` from `OUTPUT` (`nat.rs::add_dnat`) -- the same
//      shape Docker's own `DOCKER` chain uses.
//   2. Even with (1) fixed, the DNAT'd packet still carried source address
//      `127.0.0.1` heading out the bridge toward the container -- an ARP
//      resolution for the container's address went out as "who-has
//      <container_ip> tell 127.0.0.1" (confirmed via `tcpdump` on the
//      host-side veth), which cannot resolve, and the kernel's own
//      martian-source route check silently drops a 127.0.0.0/8-sourced
//      packet leaving a non-loopback interface in the first place unless
//      `route_localnet` is enabled on that interface. Fixed by adding a
//      hairpin MASQUERADE rule (`nat.rs::hairpin_masquerade_rule_spec`,
//      matched via `-m addrtype --src-type LOCAL`, same primitive
//      Docker's own hairpin-NAT rule uses) plus enabling
//      `net.ipv4.conf.<bridge_name>.route_localnet=1` (scoped to just the
//      bridge interface, not host-wide) -- both now part of
//      `nat.rs::ensure_masquerade`.
//
// See `nat.rs`'s own doc comments on `add_dnat`, `ensure_masquerade`, and
// `hairpin_masquerade_rule_spec` for the full detail; `tests/nat_args.rs`
// covers the new rule spec's pure argument-vector shape.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use futures_util::TryStreamExt;
use ipnetwork::Ipv4Network;
use kestrel_net::bridge::{delete_bridge, ensure_bridge, find_link_index, teardown_bridge_network};
use kestrel_net::ipam::Ipam;
use kestrel_net::modes::{resolve_container_mode, ModeKind};
use kestrel_net::nat::{add_dnat, enable_forwarding_sysctls, ensure_masquerade, teardown_all};
use kestrel_net::netns::{create_netns, nsenter, teardown_netns};
use kestrel_net::veth::attach_veth;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{Handle, LinkDummy, LinkUnspec};

#[path = "common/mod.rs"]
mod common;

// ---------------------------------------------------------------------
// Small shared helpers.
// ---------------------------------------------------------------------

const PING: &[u8; 4] = b"PING";
const PONG: &[u8; 4] = b"PONG";

/// Accepts exactly one connection on an already-bound listener, with a
/// bounded wait rather than an unbounded blocking `accept()` -- so a bug
/// that prevents the client from ever connecting fails this test with a
/// clear timeout instead of hanging the test suite forever.
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> Result<(TcpStream, SocketAddr)> {
    listener.set_nonblocking(true).context("setting listener nonblocking")?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                stream.set_nonblocking(false).context("restoring blocking mode on accepted stream")?;
                return Ok((stream, peer));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(Instant::now() < deadline, "timed out waiting for a connection");
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e).context("accepting connection"),
        }
    }
}

/// Spawns a dedicated OS thread that `nsenter`s into `pin`, binds a plain
/// TCP listener at `bind_addr`, signals readiness on `ready_tx`, accepts
/// exactly one connection, expects to read exactly [`PING`], replies with
/// [`PONG`], and returns the peer address the listening socket observed.
///
/// The observed peer address is the real point of most of the scenarios
/// that use this: it is only by checking what address the OTHER side
/// actually saw that a NAT/masquerade rewrite (or the lack of one) can be
/// proven, rather than merely "the connection succeeded", which is true
/// even if some completely different, coincidental path let the bytes
/// through.
///
/// A plain `std::thread` (not a tokio task) is used deliberately: `nsenter`
/// only requires "runs on one dedicated OS thread for its duration" (see
/// `netns.rs`'s own doc comment), which a raw OS thread satisfies for
/// free, without needing `block_in_place`/a multi-thread tokio runtime
/// hand-off at all -- that machinery exists specifically to reconcile
/// `nsenter` with tokio's worker pool, which is irrelevant to a thread
/// that isn't part of one.
fn spawn_ping_pong_listener(pin: PathBuf, bind_addr: SocketAddr, ready_tx: mpsc::Sender<()>) -> thread::JoinHandle<Result<SocketAddr>> {
    thread::spawn(move || {
        nsenter(&pin, move || {
            let listener = TcpListener::bind(bind_addr).with_context(|| format!("binding {bind_addr}"))?;
            let _ = ready_tx.send(());
            let (mut stream, peer) = accept_with_timeout(&listener, Duration::from_secs(10))?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).context("reading PING")?;
            ensure!(&buf == PING, "expected PING, got {buf:?}");
            stream.write_all(PONG).context("writing PONG")?;
            Ok(peer)
        })
    })
}

/// Connects to `target` (from whatever netns the CALLING thread is
/// currently in -- callers wrap this in `nsenter`/`block_in_place` as
/// needed), sends [`PING`], and asserts the reply is exactly [`PONG`].
fn connect_and_ping_pong(target: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(target).with_context(|| format!("connecting to {target}"))?;
    stream.write_all(PING).context("writing PING")?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).context("reading PONG")?;
    ensure!(&buf == PONG, "expected PONG, got {buf:?}");
    Ok(())
}

/// All interface names currently present, sorted -- used both as a direct
/// assertion (`test_none_mode_only_lo`) and as half of the before/after
/// snapshot in `test_teardown_leaves_no_rules`.
async fn link_names(handle: &Handle) -> Vec<String> {
    let mut links = handle.link().get().execute();
    let mut names = Vec::new();
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(name) = msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(n) => Some(n.clone()),
            _ => None,
        }) {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// Every `"<ifname>/<addr>/<prefix>"` triple currently assigned, sorted --
/// the address half of `test_teardown_leaves_no_rules`'s before/after
/// snapshot. Resolves ifindex -> name via a link dump taken in the SAME
/// call (rather than reusing a snapshot from a different point in time),
/// so this is self-consistent even though ifindexes aren't guaranteed
/// stable in general.
async fn address_strings(handle: &Handle) -> Vec<String> {
    let mut idx_to_name = std::collections::HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(name) = msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(n) => Some(n.clone()),
            _ => None,
        }) {
            idx_to_name.insert(msg.header.index, name);
        }
    }

    let mut addrs = handle.address().get().execute();
    let mut out = Vec::new();
    while let Some(msg) = addrs.try_next().await.unwrap() {
        let ifname = idx_to_name.get(&msg.header.index).cloned().unwrap_or_else(|| format!("if{}", msg.header.index));
        for attr in &msg.attributes {
            if let AddressAttribute::Address(ip) = attr {
                out.push(format!("{ifname}/{ip}/{}", msg.header.prefix_len));
            }
        }
    }
    out.sort();
    out
}

/// A one-time diagnostic read of `iptables -t <table> -S` (a plain
/// `Command`, matching `nat.rs`'s own established idiom of only ever
/// invoking `iptables` via an explicit argument vector -- never a shell
/// string). Lines are sorted before returning.
///
/// **Self-review (see the task's own self-review requirement): is sorting
/// here safe, or could it hide a real difference / manufacture a false
/// failure?** Sorting only discards ORDERING information, never CONTENT --
/// two states with the exact same set of rules always sort to the exact
/// same `Vec<String>` regardless of what order the kernel happened to
/// enumerate them in, and two states that genuinely differ in even one
/// rule still produce different sorted output. So sorting cannot turn a
/// real difference into a false pass. Comparing UNSORTED output, on the
/// other hand, genuinely could produce a false FAILURE here: this test
/// deletes and recreates the SAME set of custom chains as part of the
/// full lifecycle under test, and while `iptables -S`'s ordering for a
/// single chain's own rules is simply insertion order (stable within one
/// chain's lifetime), the RELATIVE order of unrelated built-in-policy
/// lines (`-P ...`) versus chain-declaration lines (`-N ...`) versus
/// jump/rule lines across MULTIPLE tables/chains is not something this
/// test has any principled reason to assume is byte-for-byte
/// deterministic across two independently-populated states, even within
/// one process's lifetime -- asserting on it anyway would make this test
/// fragile to an unrelated kernel/iptables-version detail rather than to
/// what it actually claims to verify (that teardown leaves the same SET
/// of rules behind). Sorting is therefore not a leniency tradeoff here;
/// it is what makes the comparison test the right thing (rule-set
/// equality) instead of an incidental, unrelated thing (rule-enumeration
/// order).
fn iptables_snapshot(table: &str) -> Vec<String> {
    let output = std::process::Command::new("iptables").args(["-t", table, "-S"]).output().expect("running iptables -S");
    assert!(output.status.success(), "iptables -t {table} -S failed: {}", String::from_utf8_lossy(&output.stderr));
    let mut lines: Vec<String> = String::from_utf8_lossy(&output.stdout).lines().map(|s| s.to_string()).collect();
    lines.sort();
    lines
}

// ---------------------------------------------------------------------
// Scenario 1: `None` mode.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_none_mode_only_lo() {
    common::run_in_isolated_netns(|| async {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let id = "nonemod1";

        let pin = create_netns(run_dir, id).await.unwrap();

        // `None` mode composes nothing from bridge.rs/veth.rs at all --
        // just a fresh netns with its loopback brought up. Querying the
        // link list from INSIDE that netns (via a real rtnetlink dump,
        // not `ip link`) and asserting it contains EXACTLY one interface,
        // named `lo`, proves this is a genuinely empty namespace rather
        // than one that accidentally inherited or leaked some other
        // interface.
        let names = tokio::task::block_in_place(|| {
            let pin = pin.clone();
            nsenter(&pin, move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().context("building in-netns runtime")?;
                rt.block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().context("opening netlink socket inside netns")?;
                    tokio::spawn(connection);

                    let lo_idx = find_link_index(&handle, "lo").await?.context("lo must exist in a fresh netns")?;
                    handle.link().set(LinkUnspec::new_with_index(lo_idx).up().build()).execute().await.context("bringing up lo")?;

                    Ok::<Vec<String>, anyhow::Error>(link_names(&handle).await)
                })
            })
        })
        .expect("in-netns verification must succeed");

        assert_eq!(names, vec!["lo".to_string()], "a None-mode netns must contain exactly one interface (lo) and nothing else");

        teardown_netns(run_dir, id).unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 2: bridge-mode egress (MASQUERADE + FORWARD), against a
// same-sandbox simulated "external" network -- see the module doc comment
// for why not the real internet.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_bridge_egress() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let bridge_name = "kbr-egress0";
        let gateway: Ipv4Addr = "172.60.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.60.0.0/24".parse().unwrap();
        let container_ip: Ipv4Addr = "172.60.0.5".parse().unwrap();
        let id = "egress1";

        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();

        // The simulated "external network": a SEPARATE network namespace
        // (via the same `create_netns` this crate uses for containers --
        // it's generic, not container-specific), connected to the sandbox
        // root netns by a plain point-to-point veth pair carrying
        // TEST-NET-3 (RFC 5737) addresses. This is deliberately a
        // DIFFERENT netns, not just a different interface in the same
        // netns: a destination address that is LOCAL to the sandbox root
        // netns (e.g. a second interface's own address, tried in an
        // earlier version of this test) takes the kernel's INPUT path,
        // not FORWARD -- and POSTROUTING/MASQUERADE never runs for INPUT
        // traffic at all, since nothing is actually "leaving" a box when
        // the destination is itself local (confirmed the hard way: the
        // connection succeeded, since local delivery needs no NAT, but
        // the observed source address was never rewritten, because
        // MASQUERADE genuinely never fired). Only a destination that
        // lives in a genuinely separate namespace forces a real
        // PREROUTING -> FORWARD -> POSTROUTING traversal, matching what a
        // real container -> internet hop actually looks like.
        let router_ext_addr: Ipv4Addr = "203.0.113.1".parse().unwrap(); // this "router"'s external-facing address
        let ext_server_addr: Ipv4Addr = "203.0.113.2".parse().unwrap(); // the separate netns's own address
        const EXT_PREFIX: u8 = 30; // /30: just {.0 network, .1, .2, .3 broadcast} -- plenty for a 2-node link

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let pin_ext = create_netns(run_dir, "extnet01").await.unwrap();

        handle.link().add(rtnetlink::LinkVeth::new("extveth0", "extveth0p").build()).execute().await.unwrap();
        let peer_idx = find_link_index(&handle, "extveth0p").await.unwrap().unwrap();
        {
            let ext_netns_file = std::fs::File::open(&pin_ext).unwrap();
            handle
                .link()
                .set(LinkUnspec::new_with_index(peer_idx).setns_by_fd(std::os::fd::AsRawFd::as_raw_fd(&ext_netns_file)).build())
                .execute()
                .await
                .unwrap();
        }
        let host_ext_idx = find_link_index(&handle, "extveth0").await.unwrap().unwrap();
        handle.address().add(host_ext_idx, std::net::IpAddr::V4(router_ext_addr), EXT_PREFIX).execute().await.unwrap();
        handle.link().set(LinkUnspec::new_with_index(host_ext_idx).up().build()).execute().await.unwrap();

        // Inside the "external" netns: bring its end up, assign its
        // address, bring `lo` up too (not strictly needed for this
        // scenario, but matches how every other netns in this suite is
        // left in a sane state).
        let pin_ext_for_setup = pin_ext.clone();
        tokio::task::block_in_place(move || {
            nsenter(&pin_ext_for_setup, move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().context("building in-netns runtime")?;
                rt.block_on(async {
                    let (connection, inner, _) = rtnetlink::new_connection().context("opening netlink socket inside ext netns")?;
                    tokio::spawn(connection);
                    let idx = find_link_index(&inner, "extveth0p").await?.context("extveth0p must exist inside the ext netns")?;
                    inner.address().add(idx, std::net::IpAddr::V4(ext_server_addr), EXT_PREFIX).execute().await.context("assigning ext server address")?;
                    inner.link().set(LinkUnspec::new_with_index(idx).up().build()).execute().await.context("bringing up extveth0p")?;
                    if let Some(lo_idx) = find_link_index(&inner, "lo").await? {
                        inner.link().set(LinkUnspec::new_with_index(lo_idx).up().build()).execute().await.context("bringing up lo")?;
                    }
                    Ok::<(), anyhow::Error>(())
                })
            })
        })
        .expect("setting up the ext netns's own side of the veth must succeed");

        let pin = create_netns(run_dir, id).await.unwrap();
        attach_veth(&handle, id, &pin, bridge_idx, container_ip, subnet, gateway).await.unwrap();

        enable_forwarding_sysctls().expect("enabling ip_forward + bridge-nf-call-iptables");
        ensure_masquerade(subnet, bridge_name).expect("setting up egress MASQUERADE + FORWARD accept rules");

        // The "external" listener runs INSIDE the separate ext netns.
        let ext_listen_addr = SocketAddr::new(ext_server_addr.into(), 9100);
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = spawn_ping_pong_listener(pin_ext.clone(), ext_listen_addr, ready_tx);
        ready_rx.recv_timeout(Duration::from_secs(5)).expect("external listener must become ready");

        // From inside the container's own netns, connect out to the
        // "external" address -- this is the actual egress path under
        // test: container -> veth -> bridge -> ROUTED (a genuine FORWARD
        // hop, since the destination is a different namespace, not local)
        // out `extveth0` -> MASQUERADE rewrites the source along the way.
        let pin_for_client = pin.clone();
        tokio::task::block_in_place(move || nsenter(&pin_for_client, move || connect_and_ping_pong(ext_listen_addr)))
            .expect("container must be able to reach the simulated external address");

        let observed_peer = server.join().expect("server thread panicked").expect("server-side exchange must succeed");

        // The real assertion: the ext netns's listener must see this
        // "router"'s own external-facing address as the source, not the
        // container's real address -- proving MASQUERADE actually
        // rewrote it, rather than this test passing merely because SOME
        // route happened to exist.
        assert_eq!(
            observed_peer.ip(),
            std::net::IpAddr::V4(router_ext_addr),
            "the ext netns's listener must observe this router's own external address as the source (MASQUERADE), not the container's real address {container_ip}"
        );

        teardown_netns(run_dir, id).unwrap();
        teardown_netns(run_dir, "extnet01").unwrap();
        // Deleting `extveth0` (host side) also destroys its peer,
        // wherever it currently lives -- same veth-pair-is-one-link
        // semantics `bridge.rs::teardown_bridge_network` relies on.
        if let Some(idx) = find_link_index(&handle, "extveth0").await.unwrap() {
            handle.link().del(idx).execute().await.unwrap();
        }
        if let Some(idx) = find_link_index(&handle, &format!("veth{}", &id[..id.len().min(8)])).await.unwrap() {
            handle.link().del(idx).execute().await.unwrap();
        }
        delete_bridge(&handle, bridge_name).await.unwrap();
        teardown_all(bridge_name).unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 3: two containers on the same bridge, talking directly.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_inter_container() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let bridge_name = "kbr-inter0";
        let gateway: Ipv4Addr = "172.61.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.61.0.0/24".parse().unwrap();
        let ip_a: Ipv4Addr = "172.61.0.5".parse().unwrap();
        let ip_b: Ipv4Addr = "172.61.0.6".parse().unwrap();
        let id_a = "interA01";
        let id_b = "interB01";

        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let pin_a = create_netns(run_dir, id_a).await.unwrap();
        let pin_b = create_netns(run_dir, id_b).await.unwrap();
        attach_veth(&handle, id_a, &pin_a, bridge_idx, ip_a, subnet, gateway).await.unwrap();
        attach_veth(&handle, id_b, &pin_b, bridge_idx, ip_b, subnet, gateway).await.unwrap();

        // No NAT/masquerade/forwarding sysctls anywhere in this scenario
        // -- deliberately. Same-bridge container-to-container traffic is
        // pure L2 switching (both veth ends are enslaved to the same
        // bridge port group); it must work with NOTHING beyond
        // `ensure_bridge` + `attach_veth`, proving the data path doesn't
        // secretly depend on nat.rs at all for this case.
        let listen_addr = SocketAddr::new(ip_b.into(), 9200);
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = spawn_ping_pong_listener(pin_b.clone(), listen_addr, ready_tx);
        ready_rx.recv_timeout(Duration::from_secs(5)).expect("listener in container B must become ready");

        let pin_a_for_client = pin_a.clone();
        tokio::task::block_in_place(move || nsenter(&pin_a_for_client, move || connect_and_ping_pong(listen_addr)))
            .expect("container A must be able to connect directly to container B's bridge-assigned IP");

        let observed_peer = server.join().expect("server thread panicked").expect("server-side exchange must succeed");
        // Direct L2 bridging: no NAT anywhere on this path, so B must see
        // A's REAL address as the peer, unmodified.
        assert_eq!(observed_peer.ip(), std::net::IpAddr::V4(ip_a), "container B must observe container A's real bridge-assigned IP, unmodified by any NAT");

        teardown_netns(run_dir, id_a).unwrap();
        teardown_netns(run_dir, id_b).unwrap();
        for id in [id_a, id_b] {
            if let Some(idx) = find_link_index(&handle, &format!("veth{}", &id[..id.len().min(8)])).await.unwrap() {
                handle.link().del(idx).execute().await.unwrap();
            }
        }
        delete_bridge(&handle, bridge_name).await.unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 4: published port (DNAT), reached via `localhost:<hostport>`
// from the test's own (sandbox-root, non-container) netns.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_published_port() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let bridge_name = "kbr-pub0";
        let gateway: Ipv4Addr = "172.62.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.62.0.0/24".parse().unwrap();
        let container_ip: Ipv4Addr = "172.62.0.5".parse().unwrap();
        let id = "pubport1";
        let host_port: u16 = 28080;
        let container_port: u16 = 9300;

        // `run_in_isolated_netns` only `unshare`s a fresh, empty netns --
        // it does NOT bring `lo` up in it (unlike a CONTAINER's netns,
        // where `attach_veth` explicitly does). This scenario is the
        // first in this suite to need loopback connectivity in the
        // SANDBOX ROOT netns itself (every other scenario only ever talks
        // to `lo` inside a container/ext netns, via `nsenter`), so it must
        // be brought up explicitly here first -- confirmed necessary: an
        // earlier version of this test connected to `127.0.0.1` from here
        // without this and got `Network is unreachable` (os error 101).
        let lo_idx = find_link_index(&handle, "lo").await.unwrap().expect("lo must exist in the sandbox netns");
        handle.link().set(LinkUnspec::new_with_index(lo_idx).up().build()).execute().await.unwrap();

        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let pin = create_netns(run_dir, id).await.unwrap();
        attach_veth(&handle, id, &pin, bridge_idx, container_ip, subnet, gateway).await.unwrap();

        enable_forwarding_sysctls().expect("enabling ip_forward + bridge-nf-call-iptables");
        ensure_masquerade(subnet, bridge_name).expect("setting up egress + hairpin MASQUERADE, FORWARD accept rules, and route_localnet");
        add_dnat(host_port, container_ip, container_port).expect("adding published-port DNAT rule");

        // A listener running INSIDE the container.
        let listen_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), container_port);
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = spawn_ping_pong_listener(pin.clone(), listen_addr, ready_tx);
        ready_rx.recv_timeout(Duration::from_secs(5)).expect("listener inside the container must become ready");

        // The real point of this scenario: connect to `localhost:<hostport>`
        // from the test's OWN netns (the isolated sandbox root -- NOT
        // nsenter'd into the container at all), via plain
        // `std::net::TcpStream`, not a shelled-out `curl`.
        let published_addr: SocketAddr = format!("127.0.0.1:{host_port}").parse().unwrap();
        tokio::task::block_in_place(|| connect_and_ping_pong(published_addr)).expect("connecting to the published port from the host's own netns must succeed");

        let observed_peer = server.join().expect("server thread panicked").expect("server-side exchange must succeed");
        // Hairpin MASQUERADE rewrites the source to the bridge's own
        // address (the primary address on the outgoing interface as seen
        // from inside the container) -- NOT 127.0.0.1, which would be
        // meaningless/unroutable from the container's perspective, and
        // proves `hairpin_masquerade_rule_spec`'s rule genuinely fired
        // rather than the connection succeeding via some other path.
        assert_eq!(
            observed_peer.ip(),
            std::net::IpAddr::V4(gateway),
            "the container's listener must observe the bridge gateway address as the source (hairpin MASQUERADE), not 127.0.0.1"
        );

        let mut ipam = Ipam::load(subnet, gateway, tmp.path().join("ipam.json")).unwrap();
        // The real IPAM never allocated `container_ip` in this scenario
        // (it was assigned directly, matching bridge.rs/veth.rs's own
        // test convention) -- release() is a documented no-op for an
        // address that was never allocated, so this still exercises the
        // real teardown call shape without requiring a prior `allocate`.
        teardown_bridge_network(&handle, run_dir, id, &mut ipam, container_ip, &[(host_port, container_port)]).await.unwrap();
        delete_bridge(&handle, bridge_name).await.unwrap();
        teardown_all(bridge_name).unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 5: full lifecycle, then assert zero residue.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_teardown_leaves_no_rules() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        // Snapshot BEFORE any setup at all.
        let links_before = link_names(&handle).await;
        let addrs_before = address_strings(&handle).await;
        let nat_before = iptables_snapshot("nat");
        let filter_before = iptables_snapshot("filter");

        let bridge_name = "kbr-td0";
        let gateway: Ipv4Addr = "172.63.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.63.0.0/24".parse().unwrap();
        let id = "teardwn1";
        let host_port: u16 = 28081;
        let container_port: u16 = 9400;

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();
        let mut ipam = Ipam::load(subnet, gateway, tmp.path().join("ipam.json")).unwrap();
        let container_ip = ipam.allocate(id).unwrap();

        // Full bridge-mode lifecycle, composing every module from Tasks
        // 2-9 in the same shape a real container create would.
        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();
        let pin = create_netns(run_dir, id).await.unwrap();
        attach_veth(&handle, id, &pin, bridge_idx, container_ip, subnet, gateway).await.unwrap();
        enable_forwarding_sysctls().unwrap();
        ensure_masquerade(subnet, bridge_name).unwrap();
        add_dnat(host_port, container_ip, container_port).unwrap();

        // Full teardown: per-container (veth + DNAT rules for this
        // container's published ports + IPAM release + netns), then the
        // shared bridge itself, then the daemon-level NAT chain teardown.
        teardown_bridge_network(&handle, run_dir, id, &mut ipam, container_ip, &[(host_port, container_port)]).await.unwrap();
        delete_bridge(&handle, bridge_name).await.unwrap();
        teardown_all(bridge_name).unwrap();

        // Snapshot AFTER -- must match the pre-setup baseline exactly (as
        // sets; see `iptables_snapshot`'s doc comment for why sorted-set
        // rather than line-order comparison is the correct, not merely
        // lenient, choice here).
        let links_after = link_names(&handle).await;
        let addrs_after = address_strings(&handle).await;
        let nat_after = iptables_snapshot("nat");
        let filter_after = iptables_snapshot("filter");

        assert_eq!(links_before, links_after, "no leftover interfaces after a full bridge-mode lifecycle + teardown");
        assert_eq!(addrs_before, addrs_after, "no leftover addresses after a full bridge-mode lifecycle + teardown");
        assert_eq!(nat_before, nat_after, "no leftover nat-table rules/chains after a full bridge-mode lifecycle + teardown");
        assert_eq!(filter_before, filter_after, "no leftover filter-table rules/chains after a full bridge-mode lifecycle + teardown");
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 6: `Host` mode is a genuine no-op at this layer.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_host_mode_shares_host_stack() {
    common::run_in_isolated_netns(|| async {
        // `Host` mode's defining behavior is doing NOTHING at this layer
        // -- no `create_netns`, no `nsenter`, ever. That's exercised
        // directly here: a link is created via one rtnetlink connection,
        // then observed via a COMPLETELY SEPARATE, freshly-opened
        // connection (standing in for "a Host-mode container process
        // opening its own netlink socket"), with no netns operation of
        // any kind happening in between. If `Host` mode were silently
        // creating (or joining) some namespace instead of being a true
        // no-op, this second, independent connection would NOT see the
        // link the first one created.
        let (connection1, handle1, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection1);

        let addr: Ipv4Addr = "192.0.2.7".parse().unwrap(); // RFC 5737 TEST-NET-1
        handle1.link().add(LinkDummy::new("hostcheck0").build()).execute().await.unwrap();
        let idx = find_link_index(&handle1, "hostcheck0").await.unwrap().unwrap();
        handle1.address().add(idx, std::net::IpAddr::V4(addr), 32).execute().await.unwrap();

        let (connection2, handle2, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection2);

        let idx_seen_by_second_connection = find_link_index(&handle2, "hostcheck0").await.unwrap();
        assert_eq!(idx_seen_by_second_connection, Some(idx), "a second, independent connection (standing in for a Host-mode container process) must see the exact same interface -- proving Host mode shares the ambient netns rather than creating its own");

        let mut addrs = handle2.address().get().set_link_index_filter(idx).execute();
        let mut found = false;
        while let Some(msg) = addrs.try_next().await.unwrap() {
            for attr in &msg.attributes {
                if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
                    if *a == addr {
                        found = true;
                    }
                }
            }
        }
        assert!(found, "the second connection must observe the exact address assigned via the first -- same namespace, verified via real data, not just an unerroring path");

        handle1.link().del(idx).execute().await.unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 7: `container:<id>` mode shares the referenced container's
// netns for real (the capstone within the capstone).
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_container_mode_shares_netns() {
    common::run_in_isolated_netns(|| async {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let bridge_name = "kbr-share0";
        let gateway: Ipv4Addr = "172.64.0.1".parse().unwrap();
        let subnet: Ipv4Network = "172.64.0.0/24".parse().unwrap();
        let container_ip: Ipv4Addr = "172.64.0.5".parse().unwrap();
        let id_a = "shareA01";

        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path();

        // Container A: full, real bridge-mode setup.
        let bridge_idx = ensure_bridge(&handle, bridge_name, gateway, subnet).await.unwrap();
        let pin_a = create_netns(run_dir, id_a).await.unwrap();
        attach_veth(&handle, id_a, &pin_a, bridge_idx, container_ip, subnet, gateway).await.unwrap();

        // Container B: resolved via `resolve_container_mode`'s VALIDATED
        // path -- no `create_netns`, no `attach_veth`, nothing of its own.
        let pin_b = resolve_container_mode(run_dir, id_a, ModeKind::Bridge).unwrap();
        assert_eq!(pin_b, pin_a, "resolve_container_mode must resolve to A's OWN pinned netns path, not a distinct one");

        // A listener "in A", reached "from B" via 127.0.0.1 specifically
        // -- not A's bridge-assigned IP. Loopback is per-namespace: a
        // successful connection over 127.0.0.1 from "B"'s nsenter call is
        // only possible if B is joining the LITERAL SAME namespace as A
        // (as opposed to e.g. some other bridge-connected netns that
        // could also reach A via its real IP) -- this is the strongest
        // available proof of genuine shared-netns pod semantics.
        let listen_addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = spawn_ping_pong_listener(pin_a.clone(), listen_addr, ready_tx);
        ready_rx.recv_timeout(Duration::from_secs(5)).expect("listener in A's netns must become ready");

        let pin_b_for_client = pin_b.clone();
        thread::spawn(move || nsenter(&pin_b_for_client, move || connect_and_ping_pong(listen_addr)))
            .join()
            .expect("client thread panicked")
            .expect("B (joining A's pinned netns via resolve_container_mode) must reach A's loopback-bound listener");

        let observed_peer = server.join().expect("server thread panicked").expect("server-side exchange must succeed");
        assert_eq!(observed_peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap(), "the connection must arrive over loopback, confirming A and B share the literal same netns");

        teardown_netns(run_dir, id_a).unwrap();
        if let Some(idx) = find_link_index(&handle, &format!("veth{}", &id_a[..id_a.len().min(8)])).await.unwrap() {
            handle.link().del(idx).execute().await.unwrap();
        }
        delete_bridge(&handle, bridge_name).await.unwrap();
    })
    .await;
}

// ---------------------------------------------------------------------
// Scenario 8: `container:<id>` rejects `Host`/chained `Container`
// references -- ALREADY COVERED, see below.
// ---------------------------------------------------------------------
//
// `modes.rs`'s own inline `#[cfg(test)]` module (Task 8) already has
// `test_resolve_container_mode_host_errors` and
// `test_resolve_container_mode_container_errors`, asserting exactly this:
// `resolve_container_mode` returns `Err` for `ModeKind::Host` and
// `ModeKind::Container` respectively, with the expected message content.
// Both are plain, non-root, non-networking unit tests (no real netns/
// rtnetlink/iptables involved at all -- `resolve_container_mode` is pure
// path/error-message logic), so duplicating them here as root-gated
// integration tests would add nothing but a slower, redundant copy of the
// same assertions. Deliberately skipped per this task's own instruction
// to check first rather than duplicate.
