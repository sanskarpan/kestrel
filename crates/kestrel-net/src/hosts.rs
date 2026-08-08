// crates/kestrel-net/src/hosts.rs
//
//! Generates `/etc/hosts`, `/etc/hostname`, and `/etc/resolv.conf`
//! content for a container. Pure/testable — no filesystem I/O here;
//! callers write the returned strings to the actual files.

use std::net::Ipv4Addr;

/// Generates `/etc/hosts` content: loopback entries, the container's own
/// hostname/IP, plus any extra caller-supplied entries.
pub fn generate_hosts(hostname: &str, container_ip: Option<Ipv4Addr>, extra: &[(Ipv4Addr, String)]) -> String {
    let mut out = String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some(ip) = container_ip {
        out.push_str(&format!("{ip}\t{hostname}\n"));
    }
    for (ip, name) in extra {
        out.push_str(&format!("{ip}\t{name}\n"));
    }
    out
}

pub fn generate_hostname(hostname: &str) -> String {
    format!("{hostname}\n")
}

/// `dns_ip` is the bridge gateway when the embedded resolver is active;
/// `None` means fall back to copying the host's real resolv.conf
/// (host/none modes) — the caller passes the already-read host content
/// in that case rather than this function re-reading `/etc/resolv.conf`
/// itself (keeping this function pure/testable).
pub fn generate_resolv_conf(dns_ip: Option<Ipv4Addr>, host_resolv_conf: &str) -> String {
    match dns_ip {
        Some(ip) => format!("nameserver {ip}\n"),
        None => host_resolv_conf.to_string(),
    }
}
