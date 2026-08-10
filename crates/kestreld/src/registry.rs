// crates/kestreld/src/registry.rs
//
//! The in-memory container registry: `Arc<RwLock<HashMap<String,
//! ContainerHandle>>>`. Per design doc §3, this is a CACHE, not a second
//! source of truth — the real source of truth is `kestrel-runtime`'s own
//! `<run_dir>/<id>/state.json` (already durable, atomic-write, and
//! already what `kestrel-runtime state`/`ps` read). Every read-path
//! endpoint re-reads `state.json` on demand (`read_state` below) rather
//! than trusting a cached copy, matching `kestrel_runtime::state_cmd`'s
//! own staleness-detection convention.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use kestrel_oci::state::State;
use tokio::sync::RwLock;

/// Small, additive-only metadata `kestreld` itself persists alongside a
/// container, separate from `state.json` (which `kestrel-runtime` owns
/// and writes). `#[serde(default)]` on any field added here later (e.g. a
/// LATER task's `network: Option<crate::network::NetworkInfo>`) keeps
/// this the SAME persisted file both this task's recovery path and that
/// later task's network-attachment path read/write — one mechanism, not
/// two — so this reader/writer never needs to change shape again, only
/// grow.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ContainerMeta {
    pub tty: bool,
    /// The raw `network_mode` string the client gave `POST /containers`
    /// (Task 8) — `"bridge"` | `"host"` | `"none"` | `"container:<id>"`, or
    /// `None` if the client omitted it (treated as `"none"`).
    /// `#[serde(default)]` per this struct's own doc comment above: a
    /// meta.json written before this field existed still deserializes
    /// fine, defaulting to `None`. Read back by a later `container:<id>`-
    /// mode creation (`bundle.rs`'s `referenced_container_mode_kind`) to
    /// resolve which existing netns pin to join, and by later
    /// introspection endpoints.
    #[serde(default)]
    pub network_mode: Option<String>,
    /// Task 17: the real bridge-mode `NetworkInfo` (bridge name, allocated
    /// IP, gateway, published ports) `kestreld` itself set up for this
    /// container — `None` for `host`/`none`/`container:<id>` modes, and
    /// briefly `None` for a `bridge`-mode container between `bundle.rs`'s
    /// FIRST `meta.json` write (before `create()`/network attach have even
    /// run — see that module's own doc comment on why `meta.json` is
    /// written that early) and `create_container`'s second, REAL write
    /// once attachment succeeds. `#[serde(default)]`: a `meta.json` written
    /// before this field existed (any pre-Task-17 container) still parses,
    /// defaulting to `None` — exactly Task 7's original additive-field
    /// promise this struct's own doc comment already made, now exercised
    /// for real.
    #[serde(default)]
    pub network: Option<crate::network::NetworkInfo>,
}

// Real, non-test callers as of Task 8: `bundle.rs`'s
// `materialize_bundle` constructs `ContainerMeta`; `api::containers::
// create_container` constructs a `ContainerHandle` from it and inserts
// into the registry on a successful create. `recover_registry` (Task 7)
// does the same on startup recovery.
#[derive(Clone)]
pub struct ContainerHandle {
    pub id: String,
    pub bundle_path: PathBuf,
    pub meta: ContainerMeta,
}

pub type Registry = Arc<RwLock<HashMap<String, ContainerHandle>>>;

pub fn meta_path(data_dir: &std::path::Path, id: &str) -> PathBuf {
    data_dir.join("containers").join(id).join("meta.json")
}

/// Phase 9 Task 19: the resolved, bottom-to-top layer chain-id list a
/// container was actually built from — written once, at create time
/// (`bundle.rs::materialize_bundle_inner`, Task 8), and read back by
/// `GET /containers/:id/layers` (`api::introspect`, Task 19). This is the
/// durable answer to a question `kestrel-runtime`'s own `MountPlan` can
/// only answer transiently (it's never persisted — see that type's own
/// doc comment): for an `image`-pulled container, this is the exact
/// annotation-fast-path chain-id list `kestreld` itself resolved via
/// `pull_image_chain_ids`; for a plain `bundle_rootfs` container, it's
/// the single synthetic `bundle-<id>` chain-id `kestrel-runtime create.rs`
/// (`stage_bundle_rootfs_as_synthetic_layer`) independently, deterministically
/// derives on its own — this struct's writer mirrors that exact fallback
/// (byte-for-byte the same literal `copyup_scanner.rs`'s own
/// `resolve_lower_chain_ids` already duplicates for the same reason: no
/// single shared import point exists between `kestreld` and
/// `kestrel-runtime`, see that module's doc comment).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LayersMeta {
    pub chain_ids: Vec<String>,
}

pub fn layers_path(data_dir: &std::path::Path, id: &str) -> PathBuf {
    data_dir.join("containers").join(id).join("layers.json")
}

/// Writes `layers.json`, creating `<data_dir>/containers/<id>/` if it
/// doesn't already exist — same shape as `write_meta` (which this always
/// runs alongside, in `bundle.rs::materialize_bundle_inner`).
pub async fn write_layers(data_dir: &std::path::Path, id: &str, layers: &LayersMeta) -> anyhow::Result<()> {
    let path = layers_path(data_dir, id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec(layers).context("serializing layers.json")?;
    tokio::fs::write(&path, bytes)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Synchronous counterpart to `write_layers`, for `api::introspect::
/// get_layers` (Task 19), which already runs its whole handler body inside
/// one `spawn_blocking` closure alongside the real `LayerStore` diff-dir
/// walk — a second, nested async read here would just mean a second
/// blocking-pool hop for no benefit. A missing/corrupt `layers.json` is a
/// real error here (unlike `read_meta`'s deliberately lenient
/// default-on-failure posture): `bundle.rs` has written this file for
/// EVERY container since Task 19 landed, so its absence means either a
/// pre-Task-19 container (a real, reportable gap the client should see,
/// not silently paper over as "zero layers") or genuine on-disk
/// corruption — both are worth a real `5xx`/error message, not a quietly
/// empty response.
pub fn read_layers(data_dir: &std::path::Path, id: &str) -> anyhow::Result<LayersMeta> {
    let path = layers_path(data_dir, id);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Reads `<data_dir>/containers/<id>/meta.json`. Missing/corrupt
/// `meta.json` is non-fatal — a container created by a pre-Task-7
/// `kestreld` binary, or one whose meta write raced a crash, still gets a
/// real (if defaulted) registry entry rather than being dropped from
/// recovery entirely.
pub async fn read_meta(data_dir: &std::path::Path, id: &str) -> ContainerMeta {
    let path = meta_path(data_dir, id);
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => ContainerMeta::default(),
    }
}

/// Writes `meta.json`, creating `<data_dir>/containers/<id>/` if it
/// doesn't already exist. Task 17's real second caller: `bundle.rs`
/// (Task 8) already writes an initial `meta.json` before `create()` ever
/// runs (needed early so a concurrent `container:<id>`-mode create can
/// already look this container up); `api::containers::create_container`
/// calls this a second time, after a bridge-mode container's network
/// attachment (`network::attach`) has genuinely completed, to persist the
/// real `NetworkInfo` — the write half of Task 17's "survives a kestreld
/// restart" requirement.
pub async fn write_meta(data_dir: &std::path::Path, id: &str, meta: &ContainerMeta) -> anyhow::Result<()> {
    let path = meta_path(data_dir, id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec(meta).context("serializing meta.json")?;
    tokio::fs::write(&path, bytes)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Always re-reads state.json rather than trusting any cached copy — see
/// this module's own doc comment (and design doc §3) on why `kestreld`
/// doesn't cache `State` itself.
///
/// Real caller as of Task 8: `api::containers::create_container` re-reads
/// `state.json` after the shim's status handshake reports success, to
/// confirm the container genuinely reached `Created` rather than trusting
/// the handshake alone — the writer half of Task 7's recovery contract
/// this function was originally written for.
pub async fn read_state(run_dir: &std::path::Path, id: &str) -> anyhow::Result<State> {
    let path = run_dir.join(id).join("state.json");
    tokio::task::spawn_blocking(move || State::read(&path)).await?
}
