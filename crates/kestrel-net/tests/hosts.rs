use std::net::Ipv4Addr;

use kestrel_net::hosts::{generate_hostname, generate_hosts, generate_resolv_conf};

#[test]
fn test_generate_hosts_includes_loopback_and_container_entry() {
    let ip: Ipv4Addr = "172.29.0.5".parse().unwrap();
    let out = generate_hosts("my-container", Some(ip), &[]);
    assert!(out.contains("127.0.0.1\tlocalhost"));
    assert!(out.contains("172.29.0.5\tmy-container"));
}

#[test]
fn test_generate_hosts_includes_extra_entries() {
    let extra_ip: Ipv4Addr = "172.29.0.9".parse().unwrap();
    let out = generate_hosts("c", None, &[(extra_ip, "sibling".to_string())]);
    assert!(out.contains("172.29.0.9\tsibling"));
}

#[test]
fn test_generate_hostname() {
    assert_eq!(generate_hostname("foo"), "foo\n");
}

#[test]
fn test_generate_resolv_conf_uses_embedded_dns_when_present() {
    let dns_ip: Ipv4Addr = "172.29.0.1".parse().unwrap();
    let out = generate_resolv_conf(Some(dns_ip), "nameserver 8.8.8.8\n");
    assert_eq!(out, "nameserver 172.29.0.1\n");
}

#[test]
fn test_generate_resolv_conf_falls_back_to_host_content() {
    let out = generate_resolv_conf(None, "nameserver 8.8.8.8\n");
    assert_eq!(out, "nameserver 8.8.8.8\n");
}
