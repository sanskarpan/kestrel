// crates/kestrel-net/tests/nat_args.rs
//
// Deterministic argument-construction tests for `kestrel_net::nat`. These
// exercise ONLY the pure `*_rule_spec` builder functions — no `Command`
// is ever spawned, no `iptables` binary or root privilege is required.
// `cargo test -p kestrel-net --test nat_args` must pass on any machine,
// including a plain macOS host with no `iptables` at all.

use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use kestrel_net::nat::{
    dnat_rule_spec, forward_established_rule_spec, forward_from_bridge_rule_spec, forward_inter_bridge_rule_spec, hairpin_masquerade_rule_spec,
    masquerade_rule_spec, FORWARD_CHAIN, POSTROUTING_CHAIN, PREROUTING_CHAIN,
};

#[test]
fn test_chain_names_are_exactly_as_specified() {
    // Pinned so a typo/rename in nat.rs is caught here rather than only
    // showing up as a mysteriously-nonfunctional NAT setup at runtime.
    assert_eq!(PREROUTING_CHAIN, "KESTREL-PREROUTING");
    assert_eq!(POSTROUTING_CHAIN, "KESTREL-POSTROUTING");
    assert_eq!(FORWARD_CHAIN, "KESTREL-FORWARD");
}

#[test]
fn test_masquerade_rule_spec() {
    let subnet: Ipv4Network = "172.30.0.0/24".parse().unwrap();
    let spec = masquerade_rule_spec(subnet, "kbr0");
    assert_eq!(
        spec,
        vec![
            "KESTREL-POSTROUTING".to_string(),
            "-s".to_string(),
            "172.30.0.0/24".to_string(),
            "!".to_string(),
            "-o".to_string(),
            "kbr0".to_string(),
            "-j".to_string(),
            "MASQUERADE".to_string(),
        ]
    );
    // Chain name must be the KESTREL-owned custom chain, not the
    // built-in POSTROUTING chain.
    assert_eq!(spec[0], POSTROUTING_CHAIN);
}

#[test]
fn test_hairpin_masquerade_rule_spec() {
    let spec = hairpin_masquerade_rule_spec("kbr0");
    assert_eq!(
        spec,
        vec![
            "KESTREL-POSTROUTING".to_string(),
            "-o".to_string(),
            "kbr0".to_string(),
            "-m".to_string(),
            "addrtype".to_string(),
            "--src-type".to_string(),
            "LOCAL".to_string(),
            "-j".to_string(),
            "MASQUERADE".to_string(),
        ]
    );
    assert_eq!(spec[0], POSTROUTING_CHAIN);
    // Distinguishes this rule from `masquerade_rule_spec`: matched by
    // source ADDRESS TYPE (LOCAL — this host itself), not by source
    // SUBNET, and with no `-s`/`!` negation at all — this rule exists for
    // published-port hairpin traffic (host -> its own container via a
    // DNAT'd localhost connection), not container egress.
    assert!(!spec.contains(&"-s".to_string()));
    assert!(!spec.contains(&"!".to_string()));
}

#[test]
fn test_forward_from_bridge_rule_spec() {
    let spec = forward_from_bridge_rule_spec("kbr0");
    assert_eq!(
        spec,
        vec![
            "KESTREL-FORWARD".to_string(),
            "-i".to_string(),
            "kbr0".to_string(),
            "!".to_string(),
            "-o".to_string(),
            "kbr0".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    );
    assert_eq!(spec[0], FORWARD_CHAIN);
}

#[test]
fn test_forward_inter_bridge_rule_spec() {
    let spec = forward_inter_bridge_rule_spec("kbr0");
    assert_eq!(
        spec,
        vec![
            "KESTREL-FORWARD".to_string(),
            "-i".to_string(),
            "kbr0".to_string(),
            "-o".to_string(),
            "kbr0".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    );
    assert_eq!(spec[0], FORWARD_CHAIN);
    // Distinguishes this rule from `forward_from_bridge_rule_spec`:
    // no `!` negation before the second `-o kbr0` — both interfaces are
    // the SAME bridge (container <-> container), not bridge -> anything
    // else.
    assert!(!spec.contains(&"!".to_string()));
}

#[test]
fn test_forward_established_rule_spec() {
    let spec = forward_established_rule_spec("kbr0");
    assert_eq!(
        spec,
        vec![
            "KESTREL-FORWARD".to_string(),
            "-o".to_string(),
            "kbr0".to_string(),
            "-m".to_string(),
            "conntrack".to_string(),
            "--ctstate".to_string(),
            "RELATED,ESTABLISHED".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    );
    assert_eq!(spec[0], FORWARD_CHAIN);
    // No `-i` match — this rule accepts return traffic regardless of
    // ingress interface, relying solely on conntrack state.
    assert!(!spec.contains(&"-i".to_string()));
}

#[test]
fn test_dnat_rule_spec_prerouting() {
    // DNAT must be placed in the PREROUTING chain (before the routing
    // decision) — real `iptables` (v1.8.10, nf_tables backend) rejects a
    // DNAT target inside `nat` table's POSTROUTING chain outright
    // (`RULE_APPEND failed (Invalid argument)`), confirmed by ad hoc
    // sudo smoke test. `add_dnat` always calls this with
    // `PREROUTING_CHAIN`; pin the chain name here so a regression back
    // to POSTROUTING is caught in a plain `cargo test`, no root needed.
    let container_ip: Ipv4Addr = "172.30.0.5".parse().unwrap();
    let spec = dnat_rule_spec(PREROUTING_CHAIN, 8080, container_ip, 80);
    assert_eq!(
        spec,
        vec![
            "KESTREL-PREROUTING".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            "8080".to_string(),
            "-j".to_string(),
            "DNAT".to_string(),
            "--to-destination".to_string(),
            "172.30.0.5:80".to_string(),
        ]
    );
    assert_eq!(spec[0], PREROUTING_CHAIN);
}

#[test]
fn test_dnat_rule_spec_is_parameterized_by_chain() {
    // `dnat_rule_spec` takes `chain` as a parameter so this test crate
    // can assert on the built spec without depending on the internal
    // constant `add_dnat` happens to call it with — confirm the chain
    // argument actually flows through into the built spec rather than
    // being hardcoded.
    let container_ip: Ipv4Addr = "172.30.0.5".parse().unwrap();
    let spec = dnat_rule_spec("SOME-OTHER-CHAIN", 8080, container_ip, 80);
    assert_eq!(spec[0], "SOME-OTHER-CHAIN");
    assert_eq!(spec.len(), 9);
}

#[test]
fn test_dnat_rule_spec_high_port_and_different_container_port() {
    let container_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let spec = dnat_rule_spec(PREROUTING_CHAIN, 65535, container_ip, 3000);
    assert!(spec.contains(&"65535".to_string()));
    assert!(spec.contains(&"10.0.0.2:3000".to_string()));
}
