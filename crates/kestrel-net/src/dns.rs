//! A minimal, best-effort DNS resolver for container-name lookups,
//! bound to the bridge gateway IP. Handles A-record queries only:
//! resolves a name against the IPAM allocation records passed in,
//! returns NXDOMAIN for anything unrecognized (or forwards upstream to
//! the host's real resolver if `upstream` is configured). No caching, no
//! recursion — deliberately minimal, matching this item's 🟡
//! (best-effort) status.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Name -> IP records this resolver answers from, kept in sync by
/// whatever owns IPAM allocation (kestrel-net doesn't itself own
/// container-name bookkeeping — that's a caller/daemon concern; this
/// type is just what dns::serve reads from).
pub type NameRecords = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

/// How long to wait for an upstream resolver to answer a forwarded
/// query before giving up.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs the resolver until the socket errors or the process is killed —
/// intentionally has no built-in shutdown signal parameter; the caller
/// (whoever `tokio::spawn`s this) is responsible for aborting the
/// resulting `JoinHandle` if a clean shutdown is needed, rather than
/// this function growing its own signal-handling surface. `bind_port`
/// defaults to 53 in production but MUST be overridable for tests (which
/// can't bind privileged port 53 without root) — take it as a parameter,
/// not hardcoded.
pub async fn serve(bind_ip: Ipv4Addr, bind_port: u16, records: NameRecords, upstream: Option<SocketAddr>) -> Result<()> {
    let socket = UdpSocket::bind((bind_ip, bind_port)).await?;
    let mut buf = [0u8; 512]; // DNS-over-UDP's classic (pre-EDNS0) size cap

    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        if let Some(response) = handle_query(&buf[..len], &records, upstream).await {
            let _ = socket.send_to(&response, from).await;
        }
    }
}

async fn handle_query(query: &[u8], records: &NameRecords, upstream: Option<SocketAddr>) -> Option<Vec<u8>> {
    let parsed = parse_query(query)?;
    let ip = records.read().await.get(&parsed.name).copied();
    match ip {
        Some(ip) => Some(build_a_response(&parsed, ip)),
        None => match upstream {
            Some(addr) => forward_query(query, addr).await,
            None => Some(build_nxdomain_response(&parsed)),
        },
    }
}

struct ParsedQuery {
    id: u16,
    name: String,
    /// The raw question section bytes (labels + QTYPE + QCLASS), needed
    /// verbatim to build a spec-compliant response.
    question_bytes: Vec<u8>,
}

fn parse_query(query: &[u8]) -> Option<ParsedQuery> {
    // DNS header is 12 bytes: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2)
    // NSCOUNT(2) ARCOUNT(2).
    if query.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        let label = query.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    let question_end = pos + 4; // QTYPE + QCLASS
    if query.len() < question_end {
        return None;
    }
    let question_bytes = query[12..question_end].to_vec();
    let name = labels.join(".");

    Some(ParsedQuery { id, name, question_bytes })
}

/// Builds a spec-compliant A-record response.
///
/// Wire layout (verified against real `dig`/`nslookup`/`host` queries,
/// see `tests/dns.rs`):
/// - Header (12 bytes): ID (echoed from query), FLAGS (0x8180 =
///   response, recursion-available, no error), QDCOUNT=1, ANCOUNT=1,
///   NSCOUNT=0, ARCOUNT=0.
/// - Question section: echoed verbatim from the query (`q.question_bytes`).
/// - Answer section: NAME as a compressed pointer (0xC0 0x0C — pointing
///   back to offset 12, where the question's name starts, since the
///   answer's name is always identical to the question's name for this
///   resolver), TYPE=A (0x0001), CLASS=IN (0x0001), TTL (4 bytes, 60),
///   RDLENGTH=4 (0x0004), RDATA (4 bytes, the IP's octets).
fn build_a_response(q: &ParsedQuery, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::new();

    // Header.
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x81, 0x80]); // response, recursion available, no error
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section, echoed verbatim.
    out.extend_from_slice(&q.question_bytes);

    // Answer section.
    out.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to offset 12 (question's name)
    out.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    out.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    out.extend_from_slice(&ip.octets()); // RDATA

    out
}

fn build_nxdomain_response(q: &ParsedQuery) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x81, 0x83]); // flags: response, recursion available, NXDOMAIN (rcode 3)
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&q.question_bytes);
    out
}

/// Forwards `query` verbatim to `upstream` and relays its response back.
/// A fresh short-lived socket per forwarded query is fine for this
/// minimal resolver — no connection pooling needed. Times out after
/// [`UPSTREAM_TIMEOUT`] so a dead/unreachable upstream doesn't hang the
/// resolver indefinitely.
async fn forward_query(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let bind_addr: SocketAddr = match upstream {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind_addr).await.ok()?;
    socket.send_to(query, upstream).await.ok()?;

    let mut buf = [0u8; 512];
    let (len, from) = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv_from(&mut buf)).await.ok()?.ok()?;
    if from != upstream {
        // Spoofed/unexpected sender — don't relay it back to the client.
        return None;
    }
    Some(buf[..len].to_vec())
}
