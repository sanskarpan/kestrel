//! A bitmap allocator over an IPv4 subnet, persisted to disk. Network,
//! broadcast, and gateway addresses are reserved up front and never
//! handed out. Persistence uses the same write-temp-then-rename
//! atomicity `kestrel-image::store::ContentStore` established (Phase 6)
//! — not that type itself (a different crate, different concern), the
//! same PATTERN.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
struct IpamState {
    /// Allocated address (as u32, host order via Ipv4Addr::into) -> owner id.
    allocated: HashMap<u32, String>,
}

pub struct Ipam {
    subnet: Ipv4Network,
    gateway: Ipv4Addr,
    state_path: PathBuf,
    state: IpamState,
}

impl Ipam {
    /// Loads persisted state from `state_path` if it exists, else starts
    /// empty. `gateway` is reserved automatically (in addition to the
    /// subnet's network/broadcast addresses) even on a fresh/empty
    /// state, so it's never handed out as a container address.
    pub fn load(subnet: Ipv4Network, gateway: Ipv4Addr, state_path: PathBuf) -> Result<Self> {
        let state = if state_path.is_file() {
            let data = fs::read(&state_path).with_context(|| format!("reading {}", state_path.display()))?;
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", state_path.display()))?
        } else {
            IpamState::default()
        };
        Ok(Ipam { subnet, gateway, state_path, state })
    }

    fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        ip == self.subnet.network() || ip == self.subnet.broadcast() || ip == self.gateway
    }

    /// Allocates the lowest-numbered free address in the subnet for
    /// `owner_id`, persisting the change before returning it (so a crash
    /// immediately after allocation can't hand the same address out
    /// twice on restart).
    pub fn allocate(&mut self, owner_id: &str) -> Result<Ipv4Addr> {
        for ip in self.subnet.iter() {
            if self.is_reserved(ip) {
                continue;
            }
            let key: u32 = ip.into();
            if let Entry::Vacant(e) = self.state.allocated.entry(key) {
                e.insert(owner_id.to_string());
                self.persist()?;
                return Ok(ip);
            }
        }
        bail!("no free addresses remaining in {}", self.subnet);
    }

    /// Releases `ip`. A no-op (not an error) if it wasn't allocated —
    /// matches this project's established "already gone is success"
    /// idiom for release/teardown operations.
    pub fn release(&mut self, ip: Ipv4Addr) -> Result<()> {
        let key: u32 = ip.into();
        self.state.allocated.remove(&key);
        self.persist()
    }

    /// Reconciles the persisted allocation set against `live_owner_ids`
    /// (container ids actually still running, as determined by the
    /// caller — kestrel-net has no visibility into container lifecycle
    /// itself), releasing anything whose owner isn't in that set. Called
    /// on daemon start to recover from a crash mid-lifecycle. Returns
    /// the addresses actually swept.
    pub fn sweep(&mut self, live_owner_ids: &std::collections::HashSet<String>) -> Result<Vec<Ipv4Addr>> {
        let stale: Vec<u32> = self
            .state
            .allocated
            .iter()
            .filter(|(_, owner)| !live_owner_ids.contains(*owner))
            .map(|(k, _)| *k)
            .collect();
        let mut released = Vec::with_capacity(stale.len());
        for key in stale {
            self.state.allocated.remove(&key);
            released.push(Ipv4Addr::from(key));
        }
        if !released.is_empty() {
            self.persist()?;
        }
        Ok(released)
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp_path = self.state_path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(&self.state).context("serializing IPAM state")?;
        fs::write(&tmp_path, &data).with_context(|| format!("writing {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &self.state_path).with_context(|| format!("renaming {} to {}", tmp_path.display(), self.state_path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(dir: &std::path::Path) -> Ipam {
        let subnet: Ipv4Network = "172.31.0.0/29".parse().unwrap(); // small: 8 addrs, easy to exhaust in tests
        let gateway: Ipv4Addr = "172.31.0.1".parse().unwrap();
        Ipam::load(subnet, gateway, dir.join("ipam.json")).unwrap()
    }

    #[test]
    fn test_allocate_skips_network_broadcast_and_gateway() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let a = ipam.allocate("c1").unwrap();
        assert_ne!(a, "172.31.0.0".parse::<Ipv4Addr>().unwrap(), "must not hand out the network address");
        assert_ne!(a, "172.31.0.1".parse::<Ipv4Addr>().unwrap(), "must not hand out the gateway");
        assert_ne!(a, "172.31.0.7".parse::<Ipv4Addr>().unwrap(), "must not hand out the broadcast address");
    }

    #[test]
    fn test_allocate_never_double_allocates() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let mut seen = std::collections::HashSet::new();
        for i in 0..5 {
            let ip = ipam.allocate(&format!("c{i}")).unwrap();
            assert!(seen.insert(ip), "allocate must never hand out the same address twice");
        }
        assert!(ipam.allocate("overflow").is_err(), "must error once the subnet is exhausted");
    }

    #[test]
    fn test_release_frees_address_for_reuse() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let ip = ipam.allocate("c1").unwrap();
        ipam.release(ip).unwrap();
        let ip2 = ipam.allocate("c2").unwrap();
        assert_eq!(ip, ip2, "a released address should become allocatable again");
    }

    #[test]
    fn test_state_persists_across_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ipam.json");
        let subnet: Ipv4Network = "172.31.0.0/29".parse().unwrap();
        let gateway: Ipv4Addr = "172.31.0.1".parse().unwrap();

        let ip = {
            let mut ipam = Ipam::load(subnet, gateway, path.clone()).unwrap();
            ipam.allocate("c1").unwrap()
        };

        let mut reloaded = Ipam::load(subnet, gateway, path).unwrap();
        let mut seen = std::collections::HashSet::new();
        seen.insert(ip);
        for i in 0..4 {
            let next = reloaded.allocate(&format!("d{i}")).unwrap();
            assert!(seen.insert(next), "reloaded state must remember the earlier allocation");
        }
    }

    #[test]
    fn test_sweep_releases_addresses_of_dead_owners_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let ip_alive = ipam.allocate("alive").unwrap();
        let ip_dead = ipam.allocate("dead").unwrap();

        let mut live = std::collections::HashSet::new();
        live.insert("alive".to_string());

        let released = ipam.sweep(&live).unwrap();
        assert_eq!(released, vec![ip_dead]);

        let mut seen = std::collections::HashSet::new();
        seen.insert(ip_alive);
        seen.insert(ip_dead);
        for i in 0..3 {
            let next = ipam.allocate(&format!("new{i}")).unwrap();
            assert!(!seen.remove(&next) || next == ip_dead, "must not reallocate the still-live address");
        }
    }
}
