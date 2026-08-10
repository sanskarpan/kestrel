// crates/kestreld/src/api/introspect.rs
//
//! Phase 9 Task 18: introspection endpoints, part A — namespaces, cgroup,
//! pressure, mounts, capabilities. Every handler here is a READ against
//! either kernel state (`/proc`, `/sys/fs/cgroup`) or the container's own
//! `config.json`; none of them touch the registry's cached `ContainerMeta`
//! beyond looking a container up (`api::containers::get_registered`), and
//! none of them mutate anything.
//!
//! Split from Task 19 (layers/copyups/seccomp/system-namespaces) per
//! adversarial review: Task 18's own half above was the riskier, more
//! novel code (raw `mountinfo` parsing, cross-container inode comparison).
//! Task 19's own steps live below (`get_layers`/`get_copyups`/
//! `get_seccomp`/`get_system_namespaces`, plus the `SeccompLog` ring
//! buffer + its background event-bus consumer) — the more mechanical
//! remainder: two of the four are thin wrappers around already-real,
//! already-tested lower-level code (`LayerStore`'s own diff-dir
//! convention, Task 15's `scan_copy_ups`), and the other two are new but
//! straightforward filesystem/config reads.

use std::collections::{HashMap, VecDeque};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Path as PathParam, State};
use axum::Json;
use serde::Serialize;
use tokio::sync::RwLock;

use kestrel_cgroup::manager::CgroupManager;
use kestrel_cgroup::psi::{Psi, PsiLine, PsiResource};
use kestrel_cgroup::stats::{CpuStat, IoDeviceStat};
use kestrel_ns::join::with_namespace;
use kestrel_ns::types::NsType;
use kestrel_oci::runtime::Spec;
use kestrel_rootfs::copyup::{scan_copy_ups, LowerLayer};
use kestrel_rootfs::snapshot::LayerStore;

use crate::api::containers::get_registered;
use crate::api::AppError;
use crate::events::{Event, EventBus};
use crate::registry;
use crate::AppState;

// ===========================================================================
// Step 1: GET /containers/:id/namespaces
// ===========================================================================

/// Every namespace type `kestrel-runtime`'s own `create.rs::pin_namespaces`
/// (Phase 8) can pin under `<run_dir>/<id>/ns/<proc_name>`. Walked in this
/// fixed order so the response has a stable, predictable shape regardless
/// of `HashMap`/filesystem iteration order.
const NS_TYPES: [NsType; 8] = [
    NsType::Mount,
    NsType::Uts,
    NsType::Ipc,
    NsType::Pid,
    NsType::Net,
    NsType::User,
    NsType::Cgroup,
    NsType::Time,
];

#[derive(Debug, Serialize)]
pub struct NamespaceEntry {
    /// `NsType::proc_name()` — "mnt" | "uts" | "ipc" | "pid" | "net" |
    /// "user" | "cgroup" | "time".
    pub ns_type: String,
    pub inode: u64,
    /// Ids of every OTHER container whose OWN `<run_dir>/<other_id>/ns/
    /// <same type>` pin resolves to this SAME inode. Per this project's own
    /// namespace model (see `bundle.rs`/`create.rs`), a `container:<id>`-
    /// mode container never pins its own second copy of the namespace it
    /// joins (`NamespacePlan.join`, not `.create` — `pin_namespaces` only
    /// ever pins `plan.create` entries) — so this list is expected to be
    /// empty in this codebase's CURRENT design even for network-sharing
    /// containers. It's still computed for real, generically, rather than
    /// hardcoded to `[]`: a genuine future sharing mechanism that DOES pin
    /// two containers onto the same inode under their own `ns/` trees would
    /// be caught by this real comparison, not silently missed.
    pub shared_with: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NamespacesResponse {
    pub namespaces: Vec<NamespaceEntry>,
}

/// `GET /containers/:id/namespaces` (Task 18 Step 1).
pub async fn get_namespaces(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<NamespacesResponse>, AppError> {
    get_registered(&state, &id).await?;

    // Snapshot every OTHER registered container's id up front — the
    // cross-referencing walk below is plain blocking filesystem I/O run on
    // a blocking thread, so it must not hold the registry lock (or borrow
    // from it) across that `.await` boundary.
    let other_ids: Vec<String> = state
        .registry
        .read()
        .await
        .keys()
        .filter(|other_id| **other_id != id)
        .cloned()
        .collect();

    let run_dir = state.run_dir.clone();
    let id_for_walk = id.clone();
    let namespaces = tokio::task::spawn_blocking(move || collect_namespaces(&run_dir, &id_for_walk, &other_ids))
        .await
        .map_err(|e| AppError::internal(format!("namespaces: walk task panicked: {e}")))?;

    Ok(Json(NamespacesResponse { namespaces }))
}

/// `stat()`s `path` for its inode, `None` if the pin doesn't exist — a
/// namespace type that was never in `plan.create` (e.g. `Time`, which this
/// project's `default_namespaces()` never requests), OR the one documented,
/// environment-specific exception (`create.rs::pin_namespaces`'s own doc
/// comment): this dev Lima VM's `EINVAL`-on-Mount-namespace-bind-mount
/// limitation, which means `mnt` is routinely absent here even though a
/// real target host would have it. Either way, "not pinned" is a real,
/// expected state to tolerate, not an error to surface.
fn ns_inode(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.ino())
}

fn collect_namespaces(run_dir: &Path, id: &str, other_ids: &[String]) -> Vec<NamespaceEntry> {
    let ns_dir = run_dir.join(id).join("ns");
    let mut out = Vec::new();
    for ns_type in NS_TYPES {
        let path = ns_dir.join(ns_type.proc_name());
        let Some(inode) = ns_inode(&path) else {
            continue;
        };
        let mut shared_with = Vec::new();
        for other_id in other_ids {
            let other_path = run_dir.join(other_id).join("ns").join(ns_type.proc_name());
            if ns_inode(&other_path) == Some(inode) {
                shared_with.push(other_id.clone());
            }
        }
        out.push(NamespaceEntry {
            ns_type: ns_type.proc_name().to_string(),
            inode,
            shared_with,
        });
    }
    out
}

// ===========================================================================
// Step 2: GET /containers/:id/cgroup
// ===========================================================================

/// Local, `Serialize`-able mirror of `kestrel_cgroup::stats::CpuStat` — that
/// type deliberately doesn't derive `Serialize` itself (it's an internal
/// cgroup-crate type with no HTTP-API concerns), so this endpoint maps its
/// fields across rather than adding an API-shaped dependency to
/// `kestrel-cgroup`.
#[derive(Debug, Serialize)]
pub struct CpuStatOut {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

impl From<CpuStat> for CpuStatOut {
    fn from(s: CpuStat) -> Self {
        CpuStatOut {
            usage_usec: s.usage_usec,
            nr_periods: s.nr_periods,
            nr_throttled: s.nr_throttled,
            throttled_usec: s.throttled_usec,
        }
    }
}

/// Same rationale as `CpuStatOut`: a local mirror of `kestrel_cgroup::
/// stats::IoDeviceStat`.
#[derive(Debug, Serialize)]
pub struct IoDeviceStatOut {
    pub major: u32,
    pub minor: u32,
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub dbytes: u64,
    pub dios: u64,
}

impl From<IoDeviceStat> for IoDeviceStatOut {
    fn from(s: IoDeviceStat) -> Self {
        IoDeviceStatOut {
            major: s.major,
            minor: s.minor,
            rbytes: s.rbytes,
            wbytes: s.wbytes,
            rios: s.rios,
            wios: s.wios,
            dbytes: s.dbytes,
            dios: s.dios,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CgroupResponse {
    pub cpu_stat: CpuStatOut,
    pub memory_current: u64,
    pub pids_current: u64,
    pub io_stat: Vec<IoDeviceStatOut>,
    /// Raw, untrimmed-of-nothing-but-whitespace contents of `cpu.max` — the
    /// CONFIGURED limit (e.g. `"max 100000"` or `"50000 100000"`), not
    /// derived/normalized, per Task 18 Step 2's own wording ("plain file
    /// reads, `fs::read_to_string` is enough").
    pub cpu_max: String,
    pub memory_max: String,
    pub pids_max: String,
}

/// `GET /containers/:id/cgroup` (Task 18 Step 2): `cpu_stat`,
/// `memory_current`, `pids_current`, `io_stat` (Task 5's real reader) for
/// CURRENT usage, plus raw `cpu.max`/`memory.max`/`pids.max` reads for the
/// CONFIGURED limits.
pub async fn get_cgroup(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<CgroupResponse>, AppError> {
    get_registered(&state, &id).await?;

    // Same `<data_dir>/cgroups` root every other cgroup-touching path in
    // this crate uses (`metrics.rs`, `leak_sweep.rs`, `main.rs`'s startup
    // wiring) — NOT `config.cgroup.root`, which no real cgroup-path
    // resolution in this codebase actually reads (see those modules' own
    // doc comments).
    let cgroups_root = state.data_dir.join("cgroups");
    let id_for_read = id.clone();
    let response = tokio::task::spawn_blocking(move || read_cgroup(&cgroups_root, &id_for_read))
        .await
        .map_err(|e| AppError::internal(format!("cgroup: read task panicked: {e}")))??;

    Ok(Json(response))
}

fn read_cgroup(cgroups_root: &Path, id: &str) -> anyhow::Result<CgroupResponse> {
    let cgroup = CgroupManager::new(cgroups_root.to_path_buf(), id)
        .with_context(|| format!("constructing a CgroupManager for {id}"))?;

    let cpu_stat = cgroup.cpu_stat().context("reading cpu_stat")?;
    let memory_current = cgroup.memory_current().context("reading memory_current")?;
    let pids_current = cgroup.pids_current().context("reading pids_current")?;
    let io_stat = cgroup.io_stat().context("reading io_stat")?;

    let cpu_max = std::fs::read_to_string(cgroup.path.join("cpu.max"))
        .with_context(|| format!("reading cpu.max at {}", cgroup.path.join("cpu.max").display()))?;
    let memory_max = std::fs::read_to_string(cgroup.path.join("memory.max"))
        .with_context(|| format!("reading memory.max at {}", cgroup.path.join("memory.max").display()))?;
    let pids_max = std::fs::read_to_string(cgroup.path.join("pids.max"))
        .with_context(|| format!("reading pids.max at {}", cgroup.path.join("pids.max").display()))?;

    Ok(CgroupResponse {
        cpu_stat: cpu_stat.into(),
        memory_current,
        pids_current,
        io_stat: io_stat.into_iter().map(Into::into).collect(),
        cpu_max: cpu_max.trim().to_string(),
        memory_max: memory_max.trim().to_string(),
        pids_max: pids_max.trim().to_string(),
    })
}

// ===========================================================================
// Step 3: GET /containers/:id/pressure
// ===========================================================================

/// Local mirror of `kestrel_cgroup::psi::PsiLine` — same "no
/// `Serialize` on the cgroup-internal type" rationale as `CpuStatOut`.
#[derive(Debug, Serialize)]
pub struct PsiLineOut {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

impl From<PsiLine> for PsiLineOut {
    fn from(l: PsiLine) -> Self {
        PsiLineOut {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total_us: l.total_us,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PsiOut {
    pub some: PsiLineOut,
    /// Absent on older kernels for `cpu.pressure` specifically — see
    /// `kestrel_cgroup::psi::Psi::full`'s own doc comment.
    pub full: Option<PsiLineOut>,
}

impl From<Psi> for PsiOut {
    fn from(p: Psi) -> Self {
        PsiOut {
            some: p.some.into(),
            full: p.full.map(Into::into),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PressureResponse {
    pub cpu: PsiOut,
    pub memory: PsiOut,
    pub io: PsiOut,
}

/// `GET /containers/:id/pressure` (Task 18 Step 3): a direct passthrough of
/// `CgroupManager::pressure` (`kestrel-cgroup`'s real, already-built PSI
/// API) for all three resources.
pub async fn get_pressure(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<PressureResponse>, AppError> {
    get_registered(&state, &id).await?;

    let cgroups_root = state.data_dir.join("cgroups");
    let id_for_read = id.clone();
    let response = tokio::task::spawn_blocking(move || read_pressure(&cgroups_root, &id_for_read))
        .await
        .map_err(|e| AppError::internal(format!("pressure: read task panicked: {e}")))??;

    Ok(Json(response))
}

fn read_pressure(cgroups_root: &Path, id: &str) -> anyhow::Result<PressureResponse> {
    let cgroup = CgroupManager::new(cgroups_root.to_path_buf(), id)
        .with_context(|| format!("constructing a CgroupManager for {id}"))?;

    Ok(PressureResponse {
        cpu: cgroup.pressure(PsiResource::Cpu).context("reading cpu.pressure")?.into(),
        memory: cgroup.pressure(PsiResource::Memory).context("reading memory.pressure")?.into(),
        io: cgroup.pressure(PsiResource::Io).context("reading io.pressure")?.into(),
    })
}

// ===========================================================================
// Step 4: GET /containers/:id/mounts
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountEntry {
    pub mount_id: u32,
    pub parent_id: u32,
    pub major: u32,
    pub minor: u32,
    pub root: String,
    pub mount_point: String,
    pub mount_options: String,
    /// One of `"private"` (no optional fields present — the kernel's own
    /// term for "no `shared:`/`master:`/`propagate_from:` tag"),
    /// `"unbindable"`, or a comma-joined list of the raw `shared:<N>` /
    /// `master:<N>` / `propagate_from:<N>` tag(s) verbatim as they appear in
    /// `/proc/self/mountinfo`'s field 7 — a mount can carry both a
    /// `shared:` and a `master:` tag at once (the "shared subtree that is
    /// also a slave" case), so this deliberately doesn't collapse to a
    /// single enum value.
    pub propagation: String,
    pub fs_type: String,
    pub mount_source: String,
    pub super_options: String,
}

#[derive(Debug, Serialize)]
pub struct MountsResponse {
    pub mounts: Vec<MountEntry>,
}

/// `GET /containers/:id/mounts` (Task 18 Step 4): `setns()`s into the
/// container's PINNED mount namespace (`kestrel_ns::join::with_namespace`,
/// Task 4's real join mechanism — NOT `/proc/<pid>/ns/mnt`, which stops
/// existing once the container's init process exits, unlike the pin) and
/// parses `/proc/self/mountinfo` from inside it.
pub async fn get_mounts(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<MountsResponse>, AppError> {
    get_registered(&state, &id).await?;

    let run_dir = state.run_dir.clone();
    let id_for_join = id.clone();
    let mounts = tokio::task::spawn_blocking(move || read_mounts_in_namespace(&run_dir, &id_for_join))
        .await
        .map_err(|e| AppError::internal(format!("mounts: task panicked: {e}")))??;

    Ok(Json(MountsResponse { mounts }))
}

/// `setns()` genuinely changes the CALLING THREAD's mount namespace (per
/// `with_namespace`'s own doc comment: it opens `/proc/thread-self/ns/mnt`
/// to remember and later restore the original) — this must run on its own
/// dedicated blocking-pool OS thread via `spawn_blocking`, never inline on
/// an async task that might get polled from a shared worker thread also
/// serving other requests.
fn read_mounts_in_namespace(run_dir: &Path, id: &str) -> anyhow::Result<Vec<MountEntry>> {
    let mnt_pin = run_dir.join(id).join("ns").join(NsType::Mount.proc_name());
    let pin_file = std::fs::File::open(&mnt_pin).with_context(|| {
        format!(
            "opening the pinned mount namespace at {} — the container's Mount namespace may \
             never have been successfully pinned (see kestrel-runtime's create.rs::pin_namespaces \
             doc comment for the one known, environment-specific EINVAL exception)",
            mnt_pin.display()
        )
    })?;

    with_namespace(NsType::Mount, pin_file.as_fd(), || {
        let contents = std::fs::read_to_string("/proc/self/mountinfo")
            .context("reading /proc/self/mountinfo inside the container's mount namespace")?;
        Ok(parse_mountinfo(&contents))
    })
}

fn parse_mountinfo(contents: &str) -> Vec<MountEntry> {
    contents.lines().filter_map(parse_mountinfo_line).collect()
}

/// Parses one `/proc/[pid]/mountinfo` line per `proc(5)`'s documented
/// format (verified against a real sample read from this project's own dev
/// VM, not guessed from memory):
///
/// ```text
/// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
/// (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
/// ```
///
/// Fields 1-6 and 8-11 are always present and fixed-count; field 7
/// ("optional fields") is zero-or-more whitespace-separated tags, which is
/// exactly why `proc(5)` documents splitting on the literal `" - "`
/// separator (field 8) rather than counting fields positionally — the
/// technique used here.
fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    let (pre, post) = line.split_once(" - ")?;

    let mut pre_parts = pre.split_whitespace();
    let mount_id: u32 = pre_parts.next()?.parse().ok()?;
    let parent_id: u32 = pre_parts.next()?.parse().ok()?;
    let (major_str, minor_str) = pre_parts.next()?.split_once(':')?;
    let major: u32 = major_str.parse().ok()?;
    let minor: u32 = minor_str.parse().ok()?;
    let root = pre_parts.next()?.to_string();
    let mount_point = pre_parts.next()?.to_string();
    let mount_options = pre_parts.next()?.to_string();
    // Whatever remains (zero or more) is field 7, the optional fields.
    let optional_fields: Vec<&str> = pre_parts.collect();

    let mut post_parts = post.split_whitespace();
    let fs_type = post_parts.next()?.to_string();
    let mount_source = post_parts.next()?.to_string();
    let super_options = post_parts.next()?.to_string();

    Some(MountEntry {
        mount_id,
        parent_id,
        major,
        minor,
        root,
        mount_point,
        mount_options,
        propagation: propagation_from_optional_fields(&optional_fields),
        fs_type,
        mount_source,
        super_options,
    })
}

fn propagation_from_optional_fields(fields: &[&str]) -> String {
    let tags: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|f| f.starts_with("shared:") || f.starts_with("master:") || f.starts_with("propagate_from:") || *f == "unbindable")
        .collect();
    if tags.is_empty() {
        "private".to_string()
    } else {
        tags.join(",")
    }
}

// ===========================================================================
// Step 5: GET /containers/:id/caps
// ===========================================================================

#[derive(Debug, Default, Serialize)]
pub struct CapabilitiesResponse {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
}

/// `GET /containers/:id/caps` (Task 18 Step 5): reads the bundle's
/// `config.json` `process.capabilities` directly — already fully typed via
/// `oci_spec::runtime::LinuxCapabilities` (re-exported as
/// `kestrel_oci::runtime::LinuxCapabilities`), so no new parsing is needed
/// beyond `Spec::load` itself.
pub async fn get_caps(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<CapabilitiesResponse>, AppError> {
    let handle = get_registered(&state, &id).await?;

    let config_path = handle.bundle_path.join("config.json");
    let response = tokio::task::spawn_blocking(move || read_caps(&config_path))
        .await
        .map_err(|e| AppError::internal(format!("caps: read task panicked: {e}")))??;

    Ok(Json(response))
}

fn read_caps(config_path: &Path) -> anyhow::Result<CapabilitiesResponse> {
    let spec = Spec::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;

    let Some(caps) = spec.process().as_ref().and_then(|p| p.capabilities().clone()) else {
        return Ok(CapabilitiesResponse::default());
    };

    Ok(CapabilitiesResponse {
        bounding: caps_to_sorted_strings(caps.bounding()),
        effective: caps_to_sorted_strings(caps.effective()),
        inheritable: caps_to_sorted_strings(caps.inheritable()),
        permitted: caps_to_sorted_strings(caps.permitted()),
        ambient: caps_to_sorted_strings(caps.ambient()),
    })
}

/// Renders a `Capabilities` set (`HashSet<Capability>`, `oci_spec`'s own
/// type) into its canonical, sorted `"CAP_XXX"` string form — the exact
/// spelling `config.json` itself carries (`Capability`'s `#[serde(rename =
/// "CAP_XXX")]` on every variant), obtained via `serde_json::to_value`
/// rather than `Capability`'s `Display`/`to_string()` impl (which — via
/// `strum`'s `SCREAMING_SNAKE_CASE` case conversion of the bare Rust
/// variant name — would render e.g. `AuditWrite` as `"AUDIT_WRITE"`,
/// missing the `CAP_` prefix real `config.json` files and every other tool
/// in this ecosystem actually use). Sorted for a deterministic response
/// (`HashSet` iteration order is not stable across runs).
fn caps_to_sorted_strings(caps: &Option<kestrel_oci::runtime::Capabilities>) -> Vec<String> {
    let Some(caps) = caps else {
        return Vec::new();
    };
    let mut out: Vec<String> = caps
        .iter()
        .filter_map(|c| serde_json::to_value(c).ok().and_then(|v| v.as_str().map(str::to_string)))
        .collect();
    out.sort();
    out
}

// ===========================================================================
// Task 19 Step 1: GET /containers/:id/layers
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct LayerEntry {
    pub chain_id: String,
    /// The real, on-disk `LayerStore::diff_dir(chain_id)` path this
    /// chain-id's content actually lives at — the "origin" Task 19 Step 1
    /// asks for. This codebase keeps no chain-id -> image-reference
    /// provenance record anywhere on disk (checked: neither `kestrel-
    /// image::pull` nor `kestrel_rootfs::snapshot::LayerStore` persists
    /// one), so "origin" here means where this layer's bytes genuinely
    /// live on THIS host — real and verifiable via `fs::metadata` — not a
    /// fabricated pull-history record this codebase has no way to back up.
    pub origin: String,
    /// Real, recursive `fs::metadata` walk of `origin`: every regular
    /// file's `st_size` summed. Symlinks/devices/other special files
    /// contribute `0`, matching `kestrel-runtime create.rs`'s own
    /// `copy_dir_recursive` "skip special files" convention for the same
    /// kind of walk.
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct LayersResponse {
    pub layers: Vec<LayerEntry>,
}

/// `GET /containers/:id/layers` (Task 19 Step 1): reads back the
/// `layers.json` `bundle.rs::materialize_bundle_inner` (Task 8, gap-filled
/// by this same task — see `registry::LayersMeta`'s own doc comment) wrote
/// at create time, then resolves each chain-id's real diff-dir size and
/// location via `LayerStore` — the same content root every other layer-
/// touching path in this workspace (`bundle.rs`, `copyup_scanner.rs`)
/// already reads.
pub async fn get_layers(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<LayersResponse>, AppError> {
    get_registered(&state, &id).await?;

    let data_dir = state.data_dir.clone();
    let id_for_read = id.clone();
    let response = tokio::task::spawn_blocking(move || read_layers(&data_dir, &id_for_read))
        .await
        .map_err(|e| AppError::internal(format!("layers: read task panicked: {e}")))??;

    Ok(Json(response))
}

fn read_layers(data_dir: &Path, id: &str) -> anyhow::Result<LayersResponse> {
    let layers_meta = registry::read_layers(data_dir, id).with_context(|| format!("reading layers.json for {id}"))?;
    let layer_store = LayerStore::new(data_dir.to_path_buf());

    let layers = layers_meta
        .chain_ids
        .into_iter()
        .map(|chain_id| {
            let diff_dir = layer_store.diff_dir(&chain_id);
            let size_bytes = dir_size(&diff_dir)
                .with_context(|| format!("walking diff dir {} for chain-id {chain_id}", diff_dir.display()))?;
            Ok(LayerEntry { chain_id, origin: diff_dir.display().to_string(), size_bytes })
        })
        .collect::<anyhow::Result<Vec<LayerEntry>>>()?;

    Ok(LayersResponse { layers })
}

/// Plain recursive `fs::metadata` walk summing every regular file's real
/// `st_size` under `dir` — no `walkdir` dependency anywhere in this
/// workspace (checked), matching `kestrel-runtime create.rs`'s own
/// `copy_dir_recursive` precedent for hand-rolling this kind of walk
/// rather than pulling in a crate for it. A `dir` that doesn't exist
/// (a `layers.json` chain-id whose diff-dir was somehow never
/// materialized — not expected in this codebase's current design, but not
/// worth hard-failing the whole endpoint over) sizes as `0`, not an error.
fn dir_size(dir: &Path) -> anyhow::Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading directory entry in {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type of {}", entry.path().display()))?;
        if file_type.is_dir() {
            total += dir_size(&entry.path())?;
        } else if file_type.is_file() {
            total += entry.metadata().with_context(|| format!("stat {}", entry.path().display()))?.len();
        }
        // symlinks/devices/fifos/sockets: contribute 0, matching
        // `copy_dir_recursive`'s own "skip special files" convention.
    }
    Ok(total)
}

// ===========================================================================
// Task 19 Step 2: GET /containers/:id/copyups
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct CopyUpEntry {
    pub path: String,
    pub size_bytes: u64,
    pub from_layer: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct CopyUpsResponse {
    pub copy_ups: Vec<CopyUpEntry>,
}

/// `GET /containers/:id/copyups` (Task 19 Step 2): the exact same
/// `kestrel_rootfs::copyup::scan_copy_ups` call Task 15's background
/// scanner (`copyup_scanner.rs`) already uses, run here on demand and
/// returning the FULL current set every time — this endpoint has no
/// previously-seen bookkeeping to diff against (that dedup-against-seen
/// logic is the scanner's own job, not this endpoint's; see Task 19 Step
/// 2's own wording). Lower chain-ids come from `layers.json` (this same
/// task's Step 1 addition) rather than re-parsing `config.json`'s
/// annotation, now that a more direct source of truth exists.
pub async fn get_copyups(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<CopyUpsResponse>, AppError> {
    get_registered(&state, &id).await?;

    let data_dir = state.data_dir.clone();
    let id_for_read = id.clone();
    let response = tokio::task::spawn_blocking(move || read_copyups(&data_dir, &id_for_read))
        .await
        .map_err(|e| AppError::internal(format!("copyups: scan task panicked: {e}")))??;

    Ok(Json(response))
}

fn read_copyups(data_dir: &Path, id: &str) -> anyhow::Result<CopyUpsResponse> {
    let layers_meta = registry::read_layers(data_dir, id).with_context(|| format!("reading layers.json for {id}"))?;
    let layer_store = LayerStore::new(data_dir.to_path_buf());
    let diff_dirs: Vec<std::path::PathBuf> = layers_meta.chain_ids.iter().map(|c| layer_store.diff_dir(c)).collect();
    let lowers: Vec<LowerLayer> = layers_meta
        .chain_ids
        .iter()
        .zip(diff_dirs.iter())
        .map(|(chain_id, diff_dir)| LowerLayer { chain_id: chain_id.as_str(), diff_dir: diff_dir.as_path() })
        .collect();

    // Same `<data_dir>/snapshots/<id>/upper` convention `copyup_scanner.rs`
    // and `kestrel_rootfs::snapshot::Snapshotter::prepare_snapshot` both
    // already establish as load-bearing production behavior — see that
    // scanner module's own doc comment.
    let upper_dir = data_dir.join("snapshots").join(id).join("upper");
    let events = scan_copy_ups(&upper_dir, &lowers).context("scanning for copy-ups")?;

    let copy_ups = events
        .into_iter()
        .map(|e| CopyUpEntry {
            path: e.path.display().to_string(),
            size_bytes: e.size_bytes,
            from_layer: e.from_layer,
            kind: format!("{:?}", e.kind),
        })
        .collect();

    Ok(CopyUpsResponse { copy_ups })
}

// ===========================================================================
// Task 19 Step 3: GET /containers/:id/seccomp
// ===========================================================================

/// How many recent violations `SeccompLog` retains PER CONTAINER before
/// evicting the oldest — an unbounded log would let a container that
/// keeps making a notified syscall grow this daemon's memory without
/// bound for its entire lifetime.
const SECCOMP_LOG_CAPACITY: usize = 200;

/// A small, in-memory, per-container ring buffer of observed seccomp-
/// notify violations (Task 16's real `Event::SeccompViolation`, delivered
/// via Task 14's event bus) — fed by `spawn_seccomp_log_consumer` below,
/// read by `get_seccomp`. Deliberately NOT durable, matching
/// `copyup_scanner.rs`'s own "nothing durable, a restart just starts
/// over" posture for its own per-container `seen` bookkeeping: a
/// `kestreld` restart genuinely loses whatever violation history this
/// specific log had accumulated. That is an accepted gap here, not a
/// correctness bug — the real, durable record of "did a violation happen
/// at all" is `kestrel-shim`'s own `SeccompHub` replay buffer
/// (`kestrel-shim/src/daemon.rs`), not this daemon-side convenience log.
///
/// **Documented limitation** (confirmed by reading `api::attach`'s own
/// module doc comment, not assumed): `Event::SeccompViolation` is only
/// ever published while a client has an attach WS session open against
/// that container — `api::attach::run_attach_session` is the ONLY place
/// that decodes `Frame::SeccompEvent` into this event, and `kestreld`
/// keeps no separate, always-on internal subscriber to any container's
/// `attach.sock` (see that module's own doc comment on why attach
/// connections are on-demand, not persistent). This ring buffer therefore
/// only accumulates violations that occur while SOME client is attached —
/// not necessarily every violation a container has ever triggered. This
/// is a real, inherited gap in the underlying event-sourcing wiring, not
/// something this task's ring buffer introduces or is positioned to fix;
/// this log's job is to genuinely surface whatever real violations it DOES
/// observe, never to fabricate completeness it can't back up.
#[derive(Clone, Default)]
pub struct SeccompLog(Arc<RwLock<HashMap<String, VecDeque<String>>>>);

impl SeccompLog {
    pub fn new() -> Self {
        Self::default()
    }

    async fn record(&self, id: &str, syscall: String) {
        let mut guard = self.0.write().await;
        let entry = guard.entry(id.to_string()).or_default();
        if entry.len() >= SECCOMP_LOG_CAPACITY {
            entry.pop_front();
        }
        entry.push_back(syscall);
    }

    /// Oldest-first snapshot of everything currently retained for `id` —
    /// `Vec::new()` (not an error) for a container with no observed
    /// violations, matching Task 19 Step 3's own "don't hard-fail just
    /// because there's nothing to report" wording.
    async fn snapshot(&self, id: &str) -> Vec<String> {
        self.0.read().await.get(id).map(|d| d.iter().cloned().collect()).unwrap_or_default()
    }

    /// Removes `id`'s entry from the outer map entirely (not merely
    /// draining its `VecDeque`) — called from `delete_container`
    /// (`api::containers`) once a delete has genuinely succeeded, the
    /// same moment the registry drops its own entry for `id`. Without
    /// this, `SeccompLog`'s per-container `SECCOMP_LOG_CAPACITY` bound
    /// only caps how much a single STILL-LIVE container's entry can grow
    /// — the outer `HashMap`'s key set itself was previously never
    /// pruned, so a long-running daemon churning through many
    /// create/delete cycles would accumulate one stale key per deleted
    /// container forever. A container id that was created but never
    /// triggered a violation has no key here to begin with, so this is a
    /// harmless no-op for that (common) case.
    pub(crate) async fn remove(&self, id: &str) {
        self.0.write().await.remove(id);
    }

    /// Test-only: whether `id` still has an entry in the outer map,
    /// distinguishing "no key at all" (post-`remove`, or never violated)
    /// from "key present with an empty log" — `snapshot` alone can't tell
    /// these apart since both return `Vec::new()`.
    #[cfg(test)]
    pub(crate) async fn contains_key(&self, id: &str) -> bool {
        self.0.read().await.contains_key(id)
    }
}

/// Spawns the ONE real consumer of `Event::SeccompViolation` off the event
/// bus for the daemon's entire lifetime, feeding `log` — same "subscribe
/// once at startup, loop forever" shape as `events::spawn_consumer`/
/// `copyup_scanner::spawn`. Must be spawned BEFORE anything can publish a
/// real violation (i.e. at daemon startup, in `main()`) — a `broadcast`
/// channel only delivers to receivers that already existed at publish
/// time.
pub fn spawn_seccomp_log_consumer(event_bus: EventBus, log: SeccompLog) {
    tokio::spawn(async move {
        let mut rx = event_bus.subscribe();
        loop {
            match rx.recv().await {
                Ok(Event::SeccompViolation { id, syscall }) => log.record(&id, syscall).await,
                Ok(_) => {} // every other Event variant: not this log's concern
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "seccomp log consumer lagged — some violations were dropped; continuing");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

#[derive(Debug, Serialize)]
pub struct SeccompSyscallRuleOut {
    pub names: Vec<String>,
    pub action: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SeccompProfileOut {
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompSyscallRuleOut>,
}

#[derive(Debug, Serialize)]
pub struct SeccompResponse {
    /// `None` when `config.json`'s `linux.seccomp` is itself absent — an
    /// entirely ordinary state (no `seccomp_notify_syscalls` given to
    /// `POST /containers`, Task 16's own opt-in knob), not an error.
    pub profile: Option<SeccompProfileOut>,
    /// Oldest-first. See `SeccompLog`'s own doc comment for the real,
    /// documented reason this can be empty even for a container that DID
    /// violate its profile (no attach session was ever open to observe
    /// it) — genuinely empty when there's nothing to report, not stubbed.
    pub violations: Vec<String>,
}

/// `GET /containers/:id/seccomp` (Task 19 Step 3): the active profile
/// straight from `config.json` (already fully typed via `LinuxSeccomp`,
/// same `Spec::load` convention `get_caps` already established) plus
/// whatever this daemon's own `SeccompLog` ring buffer has accumulated for
/// this container. Never hard-fails just because Task 16 might not have
/// landed (it did — see this module's own doc comment on how the ring
/// buffer is fed) or because no seccomp profile was configured — a
/// missing profile is `profile: null`, not a `4xx`/`5xx`.
pub async fn get_seccomp(
    State(state): State<Arc<AppState>>,
    PathParam(id): PathParam<String>,
) -> Result<Json<SeccompResponse>, AppError> {
    let handle = get_registered(&state, &id).await?;

    let config_path = handle.bundle_path.join("config.json");
    let profile = tokio::task::spawn_blocking(move || read_seccomp_profile(&config_path))
        .await
        .map_err(|e| AppError::internal(format!("seccomp: read task panicked: {e}")))??;

    let violations = state.seccomp_log.snapshot(&id).await;

    Ok(Json(SeccompResponse { profile, violations }))
}

fn read_seccomp_profile(config_path: &Path) -> anyhow::Result<Option<SeccompProfileOut>> {
    let spec = Spec::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;

    let Some(seccomp) = spec.linux().as_ref().and_then(|l| l.seccomp().clone()) else {
        return Ok(None);
    };

    let architectures =
        seccomp.architectures().clone().unwrap_or_default().into_iter().map(|a| a.to_string()).collect();
    let syscalls = seccomp
        .syscalls()
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|s| SeccompSyscallRuleOut { names: s.names().clone(), action: s.action().to_string() })
        .collect();

    Ok(Some(SeccompProfileOut { default_action: seccomp.default_action().to_string(), architectures, syscalls }))
}

// ===========================================================================
// Task 19 Step 4: GET /system/namespaces
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct SystemNamespacesResponse {
    /// `{pid (as a string, since JSON object keys must be strings):
    /// {ns_type: inode}}` — per Task 19 Step 4's own wording. Built from a
    /// genuine host-wide `/proc/*/ns/*` scan (distinct from Task 18 Step
    /// 1's per-container, pin-based query, which never touches `/proc` at
    /// all): every numeric entry directly under `/proc` is a real pid,
    /// and every entry under ITS `ns/` subdirectory is a real, kernel-
    /// reported namespace type for that process — nothing here is
    /// enumerated from a fixed, hardcoded list the way Task 18's
    /// `NS_TYPES` is, so a namespace type this scan has never seen before
    /// (e.g. a kernel that adds a new one) is still picked up correctly.
    pub processes: HashMap<String, HashMap<String, u64>>,
}

/// `GET /system/namespaces` (Task 19 Step 4): a genuine host-wide scan,
/// new code (confirmed during grounding: no existing helper in this
/// workspace does this) — every process this daemon can see (`/proc/*`),
/// every namespace type THAT process's own `/proc/<pid>/ns/` directory
/// reports, resolved to its real inode via `fs::metadata` (which follows
/// the `nsfs` "symlink" to the namespace object itself, the same
/// mechanism Task 18 Step 1's `ns_inode` already relies on). A process
/// this daemon can't introspect (exited between the `readdir` and the
/// `stat`, or — for a non-root caller — one it doesn't have permission to
/// read `ns/` for) is silently skipped for that one pid, not a fatal
/// error for the whole scan: a host has many processes, and one transient
/// ENOENT/EACCES must not blank out everyone else's real data.
pub async fn get_system_namespaces() -> Result<Json<SystemNamespacesResponse>, AppError> {
    let processes = tokio::task::spawn_blocking(scan_system_namespaces)
        .await
        .map_err(|e| AppError::internal(format!("system namespaces: scan task panicked: {e}")))?;
    Ok(Json(SystemNamespacesResponse { processes }))
}

fn scan_system_namespaces() -> HashMap<String, HashMap<String, u64>> {
    let mut out = HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else { continue };
        if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue; // not a pid directory (e.g. /proc/self, /proc/cpuinfo, ...)
        }

        let ns_dir = entry.path().join("ns");
        let Ok(ns_entries) = std::fs::read_dir(&ns_dir) else {
            continue; // process exited, or unreadable — skip, not fatal
        };

        let mut ns_map = HashMap::new();
        for ns_entry in ns_entries.flatten() {
            let Some(ns_name) = ns_entry.file_name().to_str().map(str::to_string) else { continue };
            if let Ok(meta) = std::fs::metadata(ns_entry.path()) {
                ns_map.insert(ns_name, meta.ino());
            }
        }
        if !ns_map.is_empty() {
            out.insert(pid_str.to_string(), ns_map);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Step 4: mountinfo parser — verified against a real sample captured
    // from `cat /proc/self/mountinfo` on this project's own dev Lima VM
    // (Ubuntu 24.04, kernel 6.8.0-136-generic), not guessed from memory.
    // -----------------------------------------------------------------

    const REAL_MOUNTINFO_SAMPLE: &str = "\
26 32 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
27 32 0:25 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
28 32 0:5 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=4019396k,nr_inodes=1004849,mode=755,inode64
32 1 253:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,discard,errors=remount-ro,commit=30
34 28 0:22 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:16 - mqueue mqueue rw
";

    #[test]
    fn test_parse_mountinfo_real_sample_has_expected_row_count_and_fields() {
        let mounts = parse_mountinfo(REAL_MOUNTINFO_SAMPLE);
        assert_eq!(mounts.len(), 5);

        let root = mounts.iter().find(|m| m.mount_point == "/").expect("root entry present");
        assert_eq!(root.mount_id, 32);
        assert_eq!(root.parent_id, 1);
        assert_eq!(root.major, 253);
        assert_eq!(root.minor, 1);
        assert_eq!(root.fs_type, "ext4");
        assert_eq!(root.mount_source, "/dev/vda1");
        assert_eq!(root.super_options, "rw,discard,errors=remount-ro,commit=30");
        assert_eq!(root.propagation, "shared:1");

        let sys = mounts.iter().find(|m| m.mount_point == "/sys").expect("/sys entry present");
        assert_eq!(sys.propagation, "shared:7");
        assert_eq!(sys.mount_options, "rw,nosuid,nodev,noexec,relatime");
        assert_eq!(sys.root, "/");
    }

    #[test]
    fn test_parse_mountinfo_line_master_propagation() {
        // The exact example line from proc(5)'s own documentation.
        let line = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue";
        let m = parse_mountinfo_line(line).expect("parses");
        assert_eq!(m.mount_id, 36);
        assert_eq!(m.parent_id, 35);
        assert_eq!(m.major, 98);
        assert_eq!(m.minor, 0);
        assert_eq!(m.root, "/mnt1");
        assert_eq!(m.mount_point, "/mnt2");
        assert_eq!(m.mount_options, "rw,noatime");
        assert_eq!(m.propagation, "master:1");
        assert_eq!(m.fs_type, "ext3");
        assert_eq!(m.mount_source, "/dev/root");
        assert_eq!(m.super_options, "rw,errors=continue");
    }

    #[test]
    fn test_parse_mountinfo_line_no_optional_fields_is_private() {
        let line = "40 32 0:33 / /mnt rw shared_bogus_but_no_real_tag - tmpfs tmpfs rw";
        // Deliberately NOT a real shared:/master: tag (this line's
        // "optional field" is a decoy that doesn't start with a
        // recognized prefix) — must fall back to "private".
        let m = parse_mountinfo_line(line).expect("parses");
        assert_eq!(m.propagation, "private");
    }

    #[test]
    fn test_parse_mountinfo_line_unbindable() {
        let line = "50 32 0:40 / /mnt rw unbindable - tmpfs tmpfs rw";
        let m = parse_mountinfo_line(line).expect("parses");
        assert_eq!(m.propagation, "unbindable");
    }

    #[test]
    fn test_parse_mountinfo_line_shared_and_master_both_present() {
        // A "shared subtree that is also a slave" carries both tags at
        // once — real, documented proc(5) behavior, not a hypothetical.
        let line = "60 32 0:50 / /mnt rw shared:5 master:9 - tmpfs tmpfs rw";
        let m = parse_mountinfo_line(line).expect("parses");
        assert_eq!(m.propagation, "shared:5,master:9");
    }

    #[test]
    fn test_parse_mountinfo_line_malformed_returns_none() {
        assert!(parse_mountinfo_line("not a real mountinfo line").is_none());
        assert!(parse_mountinfo_line("").is_none());
    }

    #[test]
    fn test_caps_to_sorted_strings_renders_cap_prefixed_sorted_names() {
        use kestrel_oci::runtime::Capability;
        let mut set = std::collections::HashSet::new();
        set.insert(Capability::Kill);
        set.insert(Capability::AuditWrite);
        set.insert(Capability::NetBindService);
        let names = caps_to_sorted_strings(&Some(set));
        assert_eq!(names, vec!["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"]);
    }

    #[test]
    fn test_caps_to_sorted_strings_none_is_empty() {
        assert!(caps_to_sorted_strings(&None).is_empty());
    }
}
