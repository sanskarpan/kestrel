// crates/kestrel-net/src/nat.rs
//
//! NAT via `iptables`, invoked with argument VECTORS only (never a shell
//! string — no injection surface regardless of what values flow in,
//! though in practice every argument here is internally constructed from
//! IPAM/subnet data, never raw user input).
//!
//! Chain structure: three kestrel-owned custom chains —
//! `KESTREL-PREROUTING`, `KESTREL-POSTROUTING`, and `KESTREL-FORWARD` —
//! each linked into its respective built-in chain by exactly one jump
//! rule. `KESTREL-PREROUTING` (linked from the built-in `PREROUTING`
//! chain, `nat` table) holds published-port DNAT rules; DNAT must happen
//! before the kernel's routing decision, so it cannot live in
//! `POSTROUTING` (see [`add_dnat`]'s doc comment for the confirmed
//! failure mode this replaces). `KESTREL-POSTROUTING` (linked from
//! `POSTROUTING`, `nat` table) holds the egress/hairpin MASQUERADE rule.
//! `KESTREL-FORWARD` (linked from `FORWARD`, `filter` table) holds
//! forwarding-accept rules. This is the same shape Docker itself uses
//! (its `DOCKER` chain is likewise linked from `PREROUTING` for DNAT).
//! Every actual DNAT/MASQUERADE/hairpin/FORWARD-accept rule lives inside
//! these three custom chains, so teardown is an exact flush+delete of
//! three chains plus removal of three short, fixed jump rules — never an
//! argument-identical-matching problem against rules planted directly in
//! shared built-in chains.
//!
//! Argument-vector construction is split into pure, dependency-free
//! `*_rule_spec` functions (no `Command`, no I/O) so `tests/nat_args.rs`
//! can assert on the exact argument vectors without root or a real
//! `iptables` binary. Every `Command`-invoking function funnels through
//! these plus the small `add_args`/`check_args`/`delete_args` helpers
//! that wrap a rule spec with `-t <table> -A/-C/-D <chain> ...` — in
//! that order specifically: verified against a real `iptables` binary
//! that `-t <table>` must precede the verb (`-A`/`-C`/`-D`), not follow
//! it.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use ipnetwork::Ipv4Network;

/// `pub` so `tests/nat_args.rs` can assert the exact chain name appears
/// in each built rule spec, rather than hardcoding the literal a second
/// time in the test file (which would drift silently if this ever
/// changed).
pub const PREROUTING_CHAIN: &str = "KESTREL-PREROUTING";
pub const POSTROUTING_CHAIN: &str = "KESTREL-POSTROUTING";
pub const FORWARD_CHAIN: &str = "KESTREL-FORWARD";

// ---------------------------------------------------------------------
// Pure argument-vector construction (no I/O — unit-testable without
// root or a real `iptables` binary).
// ---------------------------------------------------------------------

/// The rule spec (chain name, then match/target flags — everything an
/// `-A`/`-C`/`-D` command needs after `-t <table>`) for the egress
/// MASQUERADE rule: traffic sourced from `subnet` leaving via anything
/// other than `bridge_name` gets masqueraded.
///
/// `pub` (rather than crate-private) specifically so
/// `tests/nat_args.rs` — a separate integration-test crate — can assert
/// on the exact argument vector without root or a real `iptables`
/// binary; see the module-level doc comment.
pub fn masquerade_rule_spec(subnet: Ipv4Network, bridge_name: &str) -> Vec<String> {
    vec![
        POSTROUTING_CHAIN.to_string(),
        "-s".to_string(),
        subnet.to_string(),
        "!".to_string(),
        "-o".to_string(),
        bridge_name.to_string(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]
}

/// The hairpin MASQUERADE rule: traffic that originated on the HOST ITSELF
/// (e.g. a local process connecting to `localhost:<published-port>`,
/// DNAT'd by [`add_dnat`] into `container_ip:container_port`) and is
/// leaving via `bridge_name` gets masqueraded to the bridge's own address.
///
/// **Genuinely required, not defensive-only — confirmed by ad hoc sudo
/// smoke test against this project's Lima VM (real kernel, real
/// `iptables`):** without this rule, a `curl http://127.0.0.1:<published>`
/// scenario DNAT's correctly (confirmed via `iptables -t nat -L OUTPUT -n
/// -v` packet counters incrementing) but the resulting packet still
/// carries source address `127.0.0.1` as it heads out `bridge_name` toward
/// the container — an ARP resolution for the container's address then
/// goes out as "who-has `<container_ip>` tell `127.0.0.1`" (captured via
/// `tcpdump` on the host-side veth), which cannot resolve: `127.0.0.1` is
/// not a sensible/routable L2 peer address for the container (or anything
/// else on the bridge) to answer to. `curl` times out (exit 28) rather
/// than erroring immediately. Adding this rule (matched via
/// `-m addrtype --src-type LOCAL`, the same primitive Docker's own
/// hairpin-NAT rule uses) rewrites the source to the bridge's own address
/// before the packet leaves, which is answerable and routable — confirmed
/// fixing the same scenario end-to-end (`curl` succeeded, 200) once this
/// rule was added alongside `route_localnet` (see [`ensure_masquerade`]'s
/// doc comment for the third piece of this same fix).
///
/// This is a DIFFERENT rule from [`masquerade_rule_spec`]: that one
/// matches on source SUBNET (container egress, `-s <subnet> ! -o
/// <bridge>`), unrelated traffic direction from this one, which matches
/// on source ADDRESS TYPE (`LOCAL`, i.e. "an address owned by this host
/// itself") regardless of subnet, specifically for traffic re-entering the
/// bridge after a published-port DNAT rewrite.
pub fn hairpin_masquerade_rule_spec(bridge_name: &str) -> Vec<String> {
    vec![
        POSTROUTING_CHAIN.to_string(),
        "-o".to_string(),
        bridge_name.to_string(),
        "-m".to_string(),
        "addrtype".to_string(),
        "--src-type".to_string(),
        "LOCAL".to_string(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]
}

/// FORWARD rule 1/3: accept traffic entering via the bridge and leaving
/// via anything else (container -> outside world).
pub fn forward_from_bridge_rule_spec(bridge_name: &str) -> Vec<String> {
    vec![
        FORWARD_CHAIN.to_string(),
        "-i".to_string(),
        bridge_name.to_string(),
        "!".to_string(),
        "-o".to_string(),
        bridge_name.to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

/// FORWARD rule 2/3: accept traffic both entering and leaving via the
/// bridge (container <-> container, same bridge).
pub fn forward_inter_bridge_rule_spec(bridge_name: &str) -> Vec<String> {
    vec![
        FORWARD_CHAIN.to_string(),
        "-i".to_string(),
        bridge_name.to_string(),
        "-o".to_string(),
        bridge_name.to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

/// FORWARD rule 3/3: accept return traffic of already-established/related
/// connections heading back into the bridge (outside world -> container,
/// for connections the container itself initiated).
pub fn forward_established_rule_spec(bridge_name: &str) -> Vec<String> {
    vec![
        FORWARD_CHAIN.to_string(),
        "-o".to_string(),
        bridge_name.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "RELATED,ESTABLISHED".to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

/// The DNAT rule spec for one published port, parameterized over `chain`
/// so the same builder can be exercised in tests against any chain name
/// without duplicating the match/target construction. [`add_dnat`] always
/// calls this with [`PREROUTING_CHAIN`] — the only netfilter-valid
/// placement for a DNAT target (see [`add_dnat`]'s doc comment).
pub fn dnat_rule_spec(chain: &str, host_port: u16, container_ip: Ipv4Addr, container_port: u16) -> Vec<String> {
    vec![
        chain.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--dport".to_string(),
        host_port.to_string(),
        "-j".to_string(),
        "DNAT".to_string(),
        "--to-destination".to_string(),
        format!("{container_ip}:{container_port}"),
    ]
}

/// The (fixed, short) jump-rule spec linking a built-in chain to one of
/// the three KESTREL-owned chains.
fn jump_rule_spec(to_chain: &str) -> Vec<String> {
    vec!["-j".to_string(), to_chain.to_string()]
}

/// Builds the full args for `iptables -t <table> -C <chain> <rulespec>`
/// ("does this rule already exist").
///
/// **Verified against real `iptables` (v1.8.10, nf_tables backend, in
/// this project's Lima VM):** `-t <table>` MUST precede `-C` — the
/// reverse order (`-C -t <table> ...`) is rejected with `Bad argument
/// '<table>'`. [`add_args`]/[`delete_args`] follow the same `-t` before
/// verb convention for consistency.
fn check_args(table: &str, spec: &[String]) -> Vec<String> {
    let mut v = vec!["-t".to_string(), table.to_string(), "-C".to_string()];
    v.extend_from_slice(spec);
    v
}

/// Builds the full args for `iptables -t <table> -A <chain> <rulespec>`.
fn add_args(table: &str, spec: &[String]) -> Vec<String> {
    let mut v = vec!["-t".to_string(), table.to_string(), "-A".to_string()];
    v.extend_from_slice(spec);
    v
}

/// Builds the full args for `iptables -t <table> -D <chain> <rulespec>`.
fn delete_args(table: &str, spec: &[String]) -> Vec<String> {
    let mut v = vec!["-t".to_string(), table.to_string(), "-D".to_string()];
    v.extend_from_slice(spec);
    v
}

// ---------------------------------------------------------------------
// `Command`-invoking plumbing.
// ---------------------------------------------------------------------

fn run_iptables(args: &[String]) -> Result<std::process::Output> {
    Command::new("iptables").args(args).output().with_context(|| format!("running iptables {args:?}"))
}

/// `full_check_args` must already be a complete arg vector (as built by
/// [`check_args`]) including `-t <table> -C <chain> <rulespec>` — this
/// function does not add `-C` itself, since where it belongs relative to
/// `-t` matters to real `iptables` (see [`check_args`]'s doc comment).
fn rule_exists(full_check_args: &[String]) -> Result<bool> {
    // `iptables -C` (check) exits 0 if the rule exists, 1 if it doesn't
    // — NOT the same as a real error (a malformed rule spec also exits
    // nonzero, but with a different, more verbose stderr; this function
    // treats any nonzero exit as "doesn't exist" for simplicity, which
    // is safe here because every rule spec this module builds is
    // internally fixed/well-formed).
    let output = Command::new("iptables").args(full_check_args).output().context("checking rule existence")?;
    Ok(output.status.success())
}

fn ensure_chain_exists(table: &str, chain: &str) -> Result<()> {
    let check = Command::new("iptables").args(["-t", table, "-L", chain, "-n"]).output().context("checking chain existence")?;
    if !check.status.success() {
        let out = run_iptables(&["-t".to_string(), table.to_string(), "-N".to_string(), chain.to_string()])?;
        ensure!(out.status.success(), "creating chain {chain} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

fn ensure_jump_exists(table: &str, from_chain: &str, to_chain: &str) -> Result<()> {
    let spec = jump_rule_spec(to_chain);
    // The jump's "chain" (the `-C`/`-A` target chain) is `from_chain`,
    // not one of the KESTREL chains, so it's prepended separately
    // rather than folded into `jump_rule_spec` (which only knows about
    // the target of the `-j`).
    let mut full_check_spec = vec![from_chain.to_string()];
    full_check_spec.extend_from_slice(&spec);
    if !rule_exists(&check_args(table, &full_check_spec))? {
        let out = run_iptables(&add_args(table, &full_check_spec))?;
        ensure!(out.status.success(), "linking {from_chain} -> {to_chain} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

fn ensure_rule(table: &str, spec: &[String], description: &str) -> Result<()> {
    if !rule_exists(&check_args(table, spec))? {
        let out = run_iptables(&add_args(table, spec))?;
        ensure!(out.status.success(), "adding {description} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------

/// Sets the two kernel forwarding sysctls this whole feature depends on.
/// `bridge-nf-call-iptables` only exists once `br_netfilter` is loaded —
/// fails loudly with a clear message rather than silently no-op-ing if
/// the path is missing, so a misconfigured host produces an obvious
/// error instead of NAT silently not working.
pub fn enable_forwarding_sysctls() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").context("writing net.ipv4.ip_forward=1")?;
    let br_path = "/proc/sys/net/bridge/bridge-nf-call-iptables";
    std::fs::write(br_path, b"1").with_context(|| {
        format!("writing {br_path}=1 — if this path doesn't exist, the br_netfilter kernel module needs to be loaded first (`modprobe br_netfilter`)")
    })?;
    Ok(())
}

/// Ensures the `KESTREL-POSTROUTING`/`KESTREL-FORWARD` chains (the two
/// this function owns — [`add_dnat`] separately owns `KESTREL-PREROUTING`)
/// exist and are linked, that MASQUERADE (egress AND hairpin — see
/// [`hairpin_masquerade_rule_spec`]'s doc comment for why both are needed)
/// is set up for `subnet` via `bridge_name`, and that `route_localnet` is
/// enabled on `bridge_name`. Idempotent.
///
/// **`route_localnet` — confirmed necessary by the same ad hoc sudo smoke
/// test as [`hairpin_masquerade_rule_spec`]:** a locally-originated
/// published-port connection (`curl http://127.0.0.1:<published>`) still
/// carries source address `127.0.0.1` at the moment the kernel re-derives
/// its route after [`add_dnat`]'s DNAT rewrites the destination (hairpin
/// MASQUERADE hasn't run yet at that point — it's a `POSTROUTING` rule,
/// and this re-route happens earlier) — routing a `127.0.0.0/8`-sourced
/// packet out any non-loopback interface is treated as a martian source
/// and silently dropped by default. With
/// `hairpin_masquerade_rule_spec`'s MASQUERADE rule present but
/// `route_localnet` left at its default (`0`), the connection still timed
/// out (curl exit 28) — enabling `net.ipv4.conf.<bridge_name>.route_localnet=1`
/// was independently required, confirmed by toggling it alone against an
/// otherwise-identical rule set. Deliberately set on `bridge_name` only
/// (not `net.ipv4.conf.all.route_localnet`, confirmed sufficient by the
/// same toggle test) — the same surgical, single-interface scope Docker
/// itself uses for this, rather than loosening martian-source protection
/// host-wide.
pub fn ensure_masquerade(subnet: Ipv4Network, bridge_name: &str) -> Result<()> {
    ensure_chain_exists("nat", POSTROUTING_CHAIN)?;
    ensure_chain_exists("filter", FORWARD_CHAIN)?;
    ensure_jump_exists("nat", "POSTROUTING", POSTROUTING_CHAIN)?;
    ensure_jump_exists("filter", "FORWARD", FORWARD_CHAIN)?;

    ensure_rule("nat", &masquerade_rule_spec(subnet, bridge_name), "egress MASQUERADE")?;
    ensure_rule("nat", &hairpin_masquerade_rule_spec(bridge_name), "hairpin MASQUERADE (published-port loopback)")?;
    ensure_rule("filter", &forward_from_bridge_rule_spec(bridge_name), "FORWARD accept (bridge -> outside)")?;
    ensure_rule("filter", &forward_inter_bridge_rule_spec(bridge_name), "FORWARD accept (bridge <-> bridge)")?;
    ensure_rule("filter", &forward_established_rule_spec(bridge_name), "FORWARD accept (established/related)")?;

    let route_localnet_path = format!("/proc/sys/net/ipv4/conf/{bridge_name}/route_localnet");
    std::fs::write(&route_localnet_path, b"1").with_context(|| format!("writing {route_localnet_path}=1"))?;

    Ok(())
}

/// DNAT for one published port: host `host_port` (tcp) -> `container_ip:container_port`.
///
/// Placed in [`PREROUTING_CHAIN`] (linked from the built-in `PREROUTING`
/// chain, `nat` table) — the only netfilter-valid placement for a DNAT
/// target, since DNAT must happen before the kernel's routing decision,
/// and `POSTROUTING` is definitionally after it.
///
/// **CONFIRMED by ad hoc sudo smoke test against this project's Lima VM
/// (real iptables v1.8.10, nf_tables backend):** an earlier version of
/// this function placed the DNAT rule in `KESTREL-POSTROUTING` instead,
/// which the kernel's nftables backend rejected outright — `RULE_APPEND
/// failed (Invalid argument): rule in chain KESTREL-POSTROUTING` — not a
/// partial/edge-case gap, DNAT in `POSTROUTING` cannot work at all. The
/// `PREROUTING_CHAIN` placement below was verified working end-to-end
/// against the same real `iptables` binary (rule visibly present via
/// `iptables -t nat -L KESTREL-PREROUTING -n` after `add_dnat`, gone
/// after `remove_dnat`). This is the same architecture Docker itself
/// uses (its `DOCKER` chain is likewise linked from `PREROUTING`).
///
/// Callers are also expected to have called [`ensure_masquerade`] for
/// the same bridge, so hairpin traffic (a container reaching its own
/// published port via the host/bridge address) is covered by the
/// MASQUERADE rule already installed in `KESTREL-POSTROUTING`.
pub fn add_dnat(host_port: u16, container_ip: Ipv4Addr, container_port: u16) -> Result<()> {
    ensure_chain_exists("nat", PREROUTING_CHAIN)?;
    ensure_jump_exists("nat", "PREROUTING", PREROUTING_CHAIN)?;

    // Locally-originated connections (e.g. `curl http://127.0.0.1:<published>`
    // run on the same host that owns this DNAT rule — the scenario
    // `tests/lifecycle.rs`'s `test_published_port` exercises) never
    // traverse `PREROUTING` at all: that chain only sees packets arriving
    // on an interface, before the routing decision; a packet a LOCAL
    // process generates instead goes through `OUTPUT`. Docker's own
    // published-port DNAT chain (`DOCKER`) is linked from BOTH
    // `PREROUTING` and `OUTPUT` for exactly this reason. Confirmed
    // necessary by ad hoc sudo smoke test against this project's Lima VM:
    // with only the `PREROUTING` jump present, `curl
    // http://127.0.0.1:<published>` connected nowhere (curl exit 7,
    // "connection refused") even though the identical DNAT rule worked
    // correctly for traffic genuinely arriving on an interface; adding
    // this second jump alone (before the hairpin MASQUERADE / route_localnet
    // fixes documented on `ensure_masquerade`) changed the failure mode
    // from "connection refused" to "times out", confirming the DNAT itself
    // started matching. This is additive to (not a replacement for) Task
    // 7's already-resolved PREROUTING-vs-POSTROUTING chain-placement fix —
    // both jump into the SAME `KESTREL-PREROUTING` chain, just from two
    // different built-in chains.
    ensure_jump_exists("nat", "OUTPUT", PREROUTING_CHAIN)?;

    let spec = dnat_rule_spec(PREROUTING_CHAIN, host_port, container_ip, container_port);
    ensure_rule("nat", &spec, "DNAT rule")
}

pub fn remove_dnat(host_port: u16, container_ip: Ipv4Addr, container_port: u16) -> Result<()> {
    let spec = dnat_rule_spec(PREROUTING_CHAIN, host_port, container_ip, container_port);
    let out = run_iptables(&delete_args("nat", &spec))?;
    let _ = out;
    Ok(())
}

/// Full teardown for one container's NAT state — per-container DNAT
/// removal is the caller's responsibility (one remove_dnat call per
/// published port; caller knows which ports THIS container published).
/// This function is the named entrypoint bridge.rs's
/// teardown_bridge_network calls, completed properly in Task 8.
pub fn teardown_network_nat(_id: &str) -> Result<()> {
    Ok(())
}

/// Full daemon-level teardown: flush and delete all three KESTREL chains
/// and their jump-rule links. Only called on daemon shutdown / explicit
/// network reset, never per-container.
///
/// `KESTREL-PREROUTING` is linked from TWO built-in chains — `PREROUTING`
/// and `OUTPUT` (see [`add_dnat`]'s doc comment for why) — so both jumps
/// are removed before the chain itself is flushed/deleted; every other
/// KESTREL chain has exactly one jump. Jump removal is done as a separate
/// first pass over every (table, built-in-chain, KESTREL-chain) link,
/// THEN each KESTREL chain is flushed and deleted exactly once — avoids
/// flushing/deleting `KESTREL-PREROUTING` twice (harmless either way,
/// since every call here is `let _ =`-ignored and a repeat `-F`/`-X` on an
/// already-gone chain just errors "no such chain", but doing it once each
/// is the more obviously-correct shape to read).
pub fn teardown_all(bridge_name: &str) -> Result<()> {
    let _ = bridge_name;

    let jumps = [
        ("nat", "PREROUTING", PREROUTING_CHAIN),
        ("nat", "OUTPUT", PREROUTING_CHAIN),
        ("nat", "POSTROUTING", POSTROUTING_CHAIN),
        ("filter", "FORWARD", FORWARD_CHAIN),
    ];
    for (table, built_in, chain) in jumps {
        let _ = run_iptables(&["-t".to_string(), table.to_string(), "-D".to_string(), built_in.to_string(), "-j".to_string(), chain.to_string()]);
    }

    let chains = [("nat", PREROUTING_CHAIN), ("nat", POSTROUTING_CHAIN), ("filter", FORWARD_CHAIN)];
    for (table, chain) in chains {
        let _ = run_iptables(&["-t".to_string(), table.to_string(), "-F".to_string(), chain.to_string()]);
        let _ = run_iptables(&["-t".to_string(), table.to_string(), "-X".to_string(), chain.to_string()]);
    }
    Ok(())
}
