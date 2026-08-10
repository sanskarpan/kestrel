// crates/kestreld/src/leak_sweep.rs
//
//! Startup leak sweep (design doc §3, plan Task 7 Step 3): cleans up
//! cgroups, netns pins, and orphaned namespace pins left behind by a
//! previous `kestreld` that crashed (or was killed) before it could tear
//! them down itself, and that `recover_registry` did not claim as a live
//! container.
//!
//! Every individual cleanup here is best-effort: a failure is logged and
//! skipped, never fatal to startup — one stubborn leftover resource must
//! not prevent `kestreld` from serving traffic for everything else.

use std::path::Path;

use crate::registry::Registry;

/// Runs the full sweep. Returns the number of leaked resources actually
/// cleaned, for the startup summary log in `main.rs`.
pub async fn run(run_dir: &Path, data_dir: &Path, registry: &Registry) -> usize {
    let cgroups = sweep_cgroups(data_dir, registry).await;
    let netns_pins = sweep_netns_pins(run_dir, registry).await;
    let ns_pins = sweep_orphaned_ns_pins(run_dir).await;
    cgroups + netns_pins + ns_pins
}

/// For each `<data_dir>/cgroups/kestrel/*` directory with no matching
/// registry entry: attempt `CgroupManager::new(...).destroy()`.
async fn sweep_cgroups(data_dir: &Path, registry: &Registry) -> usize {
    let cgroup_root = data_dir.join("cgroups");
    let kestrel_dir = cgroup_root.join("kestrel");
    let mut cleaned = 0;

    let mut entries = match tokio::fs::read_dir(&kestrel_dir).await {
        Ok(entries) => entries,
        Err(_) => return 0, // nothing to sweep yet (e.g. first boot)
    };

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, dir = %kestrel_dir.display(), "leak sweep: error reading cgroups dir");
                break;
            }
        };
        let id = entry.file_name().to_string_lossy().into_owned();
        if registry.read().await.contains_key(&id) {
            continue;
        }
        match kestrel_cgroup::manager::CgroupManager::new(cgroup_root.clone(), &id) {
            Ok(manager) => match manager.destroy() {
                Ok(()) => {
                    tracing::info!(id, "leak sweep: destroyed orphaned cgroup");
                    cleaned += 1;
                }
                Err(e) => {
                    tracing::warn!(id, error = %e, "leak sweep: failed to destroy orphaned cgroup");
                }
            },
            Err(e) => {
                tracing::warn!(id, error = %e, "leak sweep: skipping invalid cgroup id");
            }
        }
    }
    cleaned
}

/// For each `<run_dir>/netns/*` pin with no matching registry entry:
/// `kestrel_net::netns::teardown_netns`.
async fn sweep_netns_pins(run_dir: &Path, registry: &Registry) -> usize {
    let netns_dir = run_dir.join("netns");
    let mut cleaned = 0;

    let mut entries = match tokio::fs::read_dir(&netns_dir).await {
        Ok(entries) => entries,
        Err(_) => return 0, // no netns pins yet
    };

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, dir = %netns_dir.display(), "leak sweep: error reading netns dir");
                break;
            }
        };
        let id = entry.file_name().to_string_lossy().into_owned();
        if registry.read().await.contains_key(&id) {
            continue;
        }
        match kestrel_net::netns::teardown_netns(run_dir, &id) {
            Ok(()) => {
                tracing::info!(id, "leak sweep: tore down orphaned netns pin");
                cleaned += 1;
            }
            Err(e) => {
                tracing::warn!(id, error = %e, "leak sweep: failed to tear down orphaned netns pin");
            }
        }
    }
    cleaned
}

/// For each `<run_dir>/<id>/ns/*` pin under a container dir that no
/// longer has a `state.json` (orphaned namespace pins from a container
/// whose directory was otherwise cleaned but pins survived — e.g. a
/// `delete()` that crashed partway through): `unpin_namespace` directly.
async fn sweep_orphaned_ns_pins(run_dir: &Path) -> usize {
    let mut cleaned = 0;

    let mut entries = match tokio::fs::read_dir(run_dir).await {
        Ok(entries) => entries,
        Err(_) => return 0,
    };

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, dir = %run_dir.display(), "leak sweep: error reading run dir");
                break;
            }
        };

        let id = entry.file_name().to_string_lossy().into_owned();
        if id == "netns" {
            continue; // not a container dir — handled by sweep_netns_pins
        }
        let container_dir = entry.path();
        if !container_dir.is_dir() {
            continue;
        }
        // Only orphaned once state.json is gone — a Stopped container
        // (which recover_registry deliberately does not register) still
        // has a real state.json and its ns pins are not this sweep's job.
        if container_dir.join("state.json").exists() {
            continue;
        }

        let ns_dir = container_dir.join("ns");
        let mut ns_entries = match tokio::fs::read_dir(&ns_dir).await {
            Ok(entries) => entries,
            Err(_) => continue, // no ns/ dir (or already clean) — nothing to do
        };

        loop {
            let ns_entry = match ns_entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(id, error = %e, "leak sweep: error reading ns dir");
                    break;
                }
            };
            let ns_path = ns_entry.path();
            match kestrel_ns::pin::unpin_namespace(&ns_path) {
                Ok(()) => {
                    tracing::info!(id, ns = %ns_path.display(), "leak sweep: unpinned orphaned namespace pin");
                    cleaned += 1;
                }
                Err(e) => {
                    tracing::warn!(id, ns = %ns_path.display(), error = %e, "leak sweep: failed to unpin orphaned namespace pin");
                }
            }
        }
    }
    cleaned
}
