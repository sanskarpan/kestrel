// crates/kestrel-net/tests/dns.rs
//
// NOT root-gated — `serve()` takes an explicit `bind_port`, so every
// test here binds to loopback on an unprivileged, dynamically-obtained
// port rather than the production default of 53.
//
// Each scenario is checked TWICE: once via a hand-built raw
// `tokio::net::UdpSocket` query (so we control and can assert on every
// byte of the response), and once via the real `dig`/`nslookup`/`host`
// binaries confirmed present in this project's Lima VM. The second half
// is the actual point of this test file per the phase-7 plan: our own
// parser and our own serializer agreeing with each other proves nothing
// (a symmetric bug would cancel out) — a real, independent DNS client
// successfully resolving against our server is the only real evidence
// the wire format is correct.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kestrel_net::dns::{serve, NameRecords};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Grabs an ephemeral port from the OS by binding a throwaway UDP socket
/// to port 0 and reading back what it was assigned, then releasing it.
/// There's a theoretical race between releasing this socket and `serve`
/// binding the same port, but in practice (single test process, no
/// other UDP traffic on the VM's loopback) this is reliable.
async fn free_udp_port() -> u16 {
    let probe = UdpSocket::bind((LOOPBACK, 0)).await.expect("bind probe socket");
    probe.local_addr().expect("local_addr").port()
}

/// Starts `serve()` as a background task on loopback + a fresh
/// unprivileged port, returning the address to query it at. Gives the
/// server a brief moment to actually bind before returning, so callers
/// don't race the very first query against it.
async fn spawn_resolver(records: NameRecords, upstream: Option<SocketAddr>) -> SocketAddr {
    let port = free_udp_port().await;
    tokio::spawn(async move {
        let _ = serve(LOOPBACK, port, records, upstream).await;
    });
    // Give the spawned task a chance to run and bind before the caller
    // starts sending queries at it.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (LOOPBACK, port).into()
}

fn records_with(entries: &[(&str, &str)]) -> NameRecords {
    let mut map = HashMap::new();
    for (name, ip) in entries {
        map.insert(name.to_string(), ip.parse::<Ipv4Addr>().unwrap());
    }
    Arc::new(RwLock::new(map))
}

/// Encodes a DNS name into length-prefixed labels terminated by a
/// zero-length label, e.g. "foo.bar" -> [3 f o o 3 b a r 0].
fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Hand-builds a standard-query A-record DNS request, matching what a
/// real client like `dig` sends on the wire: 12-byte header (ID,
/// FLAGS=0x0100 "recursion desired", QDCOUNT=1, rest 0), followed by the
/// question section (QNAME, QTYPE=A, QCLASS=IN).
fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&encode_qname(name));
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    out
}

async fn send_query(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind((LOOPBACK, 0)).await.expect("bind client socket");
    client.send_to(query, server).await.expect("send query");
    let mut buf = [0u8; 512];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("response timed out")
        .expect("recv_from failed");
    assert_eq!(from, server, "response came from an unexpected address");
    buf[..len].to_vec()
}

// ---------------------------------------------------------------------
// Raw-socket verification: full control over every byte, so we can
// assert on the exact wire layout described in dns.rs's doc comment.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_raw_socket_known_name_resolves_to_correct_ip() {
    let ip: Ipv4Addr = "172.30.0.7".parse().unwrap();
    let records = records_with(&[("known.kestrel.test", "172.30.0.7")]);
    let server = spawn_resolver(records, None).await;

    let query = build_query(0x1234, "known.kestrel.test");
    let response = send_query(server, &query).await;

    // Header: ID echoed, flags = response/RA/no-error, QDCOUNT=1, ANCOUNT=1.
    assert_eq!(&response[0..2], &0x1234u16.to_be_bytes(), "ID not echoed");
    assert_eq!(&response[2..4], &[0x81, 0x80], "flags: expected response/RA/NOERROR");
    assert_eq!(&response[4..6], &1u16.to_be_bytes(), "QDCOUNT");
    assert_eq!(&response[6..8], &1u16.to_be_bytes(), "ANCOUNT");
    assert_eq!(&response[8..10], &0u16.to_be_bytes(), "NSCOUNT");
    assert_eq!(&response[10..12], &0u16.to_be_bytes(), "ARCOUNT");

    // Question section echoed verbatim.
    let qlen = query.len() - 12;
    assert_eq!(&response[12..12 + qlen], &query[12..], "question section not echoed verbatim");

    // Answer section: compressed-pointer NAME, TYPE=A, CLASS=IN, TTL,
    // RDLENGTH=4, RDATA=ip.
    let ans = 12 + qlen;
    assert_eq!(&response[ans..ans + 2], &[0xC0, 0x0C], "answer NAME should be a pointer to offset 12");
    assert_eq!(&response[ans + 2..ans + 4], &1u16.to_be_bytes(), "answer TYPE should be A");
    assert_eq!(&response[ans + 4..ans + 6], &1u16.to_be_bytes(), "answer CLASS should be IN");
    assert_eq!(&response[ans + 10..ans + 12], &4u16.to_be_bytes(), "RDLENGTH should be 4");
    assert_eq!(&response[ans + 12..ans + 16], &ip.octets(), "RDATA should be the resolved IP");
    assert_eq!(response.len(), ans + 16, "response has unexpected trailing bytes");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_raw_socket_unknown_name_gets_nxdomain() {
    let records = records_with(&[("known.kestrel.test", "172.30.0.7")]);
    let server = spawn_resolver(records, None).await;

    let query = build_query(0x5678, "nonexistent.kestrel.test");
    let response = send_query(server, &query).await;

    assert_eq!(&response[0..2], &0x5678u16.to_be_bytes(), "ID not echoed");
    assert_eq!(&response[2..4], &[0x81, 0x83], "flags: expected response/RA/NXDOMAIN(3)");
    assert_eq!(&response[6..8], &0u16.to_be_bytes(), "ANCOUNT should be 0 for NXDOMAIN");

    let qlen = query.len() - 12;
    assert_eq!(response.len(), 12 + qlen, "NXDOMAIN response should have no answer section");
    assert_eq!(&response[12..12 + qlen], &query[12..], "question section not echoed verbatim");
}

// ---------------------------------------------------------------------
// Real-client verification: the actual point of this test file. `dig`
// and `nslookup` are confirmed present at /usr/bin in this project's
// Lima VM.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_dig_resolves_known_name() {
    let records = records_with(&[("web.kestrel.test", "172.30.0.9")]);
    let server = spawn_resolver(records, None).await;

    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .args([
                &format!("@{}", server.ip()),
                "-p",
                &server.port().to_string(),
                "web.kestrel.test",
                "A",
                "+time=2",
                "+tries=1",
                "+noall",
                "+answer",
                "+comments",
            ])
            .output()
            .expect("failed to run dig")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "dig exited non-zero: {stdout}\nstderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("status: NOERROR"), "expected NOERROR status, got:\n{stdout}");
    assert!(stdout.contains("172.30.0.9"), "expected resolved IP in dig output, got:\n{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dig_reports_nxdomain_for_unknown_name() {
    let records = records_with(&[("web.kestrel.test", "172.30.0.9")]);
    let server = spawn_resolver(records, None).await;

    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .args([
                &format!("@{}", server.ip()),
                "-p",
                &server.port().to_string(),
                "ghost.kestrel.test",
                "A",
                "+time=2",
                "+tries=1",
                "+noall",
                "+comments",
            ])
            .output()
            .expect("failed to run dig")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status: NXDOMAIN"), "expected NXDOMAIN status, got:\n{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_host_binary_resolves_known_name() {
    let records = records_with(&[("api.kestrel.test", "172.30.0.11")]);
    let server = spawn_resolver(records, None).await;

    let output = tokio::task::spawn_blocking(move || {
        Command::new("host")
            .args(["-p", &server.port().to_string(), "-W", "2", "api.kestrel.test", &server.ip().to_string()])
            .output()
            .expect("failed to run host")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "host exited non-zero: {stdout}\nstderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("172.30.0.11"), "expected resolved IP in host output, got:\n{stdout}");
}

// ---------------------------------------------------------------------
// Upstream forwarding: an unknown-to-the-primary name gets forwarded to
// a second "upstream" resolver instance and the relayed answer comes
// back correctly.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_unknown_name_is_forwarded_to_upstream_and_answered() {
    let upstream_records = records_with(&[("external.example.test", "203.0.113.42")]);
    let upstream_addr = spawn_resolver(upstream_records, None).await;

    // Primary resolver knows nothing about "external.example.test" but
    // has `upstream` configured to point at the mock upstream above.
    let primary_records = records_with(&[("known.kestrel.test", "172.30.0.7")]);
    let primary_addr = spawn_resolver(primary_records, Some(upstream_addr)).await;

    // Raw-socket check of the forwarded answer's exact bytes.
    let query = build_query(0xABCD, "external.example.test");
    let response = send_query(primary_addr, &query).await;

    assert_eq!(&response[0..2], &0xABCDu16.to_be_bytes(), "ID not preserved through forwarding");
    assert_eq!(&response[2..4], &[0x81, 0x80], "forwarded response should be NOERROR");
    assert_eq!(&response[6..8], &1u16.to_be_bytes(), "ANCOUNT should be 1");
    let expected_ip: Ipv4Addr = "203.0.113.42".parse().unwrap();
    assert_eq!(&response[response.len() - 4..], &expected_ip.octets(), "forwarded RDATA should match upstream's answer");

    // And confirm the same via a real `dig` against the primary.
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .args([
                &format!("@{}", primary_addr.ip()),
                "-p",
                &primary_addr.port().to_string(),
                "external.example.test",
                "A",
                "+time=2",
                "+tries=1",
                "+noall",
                "+answer",
                "+comments",
            ])
            .output()
            .expect("failed to run dig")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status: NOERROR"), "expected NOERROR from forwarded dig query, got:\n{stdout}");
    assert!(stdout.contains("203.0.113.42"), "expected upstream-forwarded IP in dig output, got:\n{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_name_unknown_to_both_primary_and_upstream_gets_nxdomain() {
    let upstream_records = records_with(&[("external.example.test", "203.0.113.42")]);
    let upstream_addr = spawn_resolver(upstream_records, None).await;

    let primary_records = records_with(&[("known.kestrel.test", "172.30.0.7")]);
    let primary_addr = spawn_resolver(primary_records, Some(upstream_addr)).await;

    let query = build_query(0x9999, "totally.unknown.test");
    let response = send_query(primary_addr, &query).await;

    assert_eq!(&response[0..2], &0x9999u16.to_be_bytes(), "ID not preserved through forwarding");
    assert_eq!(&response[2..4], &[0x81, 0x83], "expected NXDOMAIN relayed from upstream");
}
