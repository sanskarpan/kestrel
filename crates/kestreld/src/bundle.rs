// crates/kestreld/src/bundle.rs
//
//! Bundle materialization for `POST /containers` (Task 8, design doc §4a/
//! §4b): given a `CreateContainerRequest`, resolve the container's rootfs
//! (an `image` reference to pull, or a plain already-extracted
//! `bundle_rootfs` directory), build a real `config.json` via
//! `kestrel_oci::default_spec::default_spec()` plus overrides, wire up
//! bridge-mode networking via Task 4's real namespace-join mechanism, and
//! write both the bundle and `<data_dir>/containers/<id>/meta.json`
//! (Task 7's recovery contract) to disk. `api::containers::create_container`
//! is the only production caller — this module never spawns
//! `kestrel-shim`/`kestrel-runtime` itself, it only prepares what they need.

use std::path::{Path, PathBuf};

use anyhow::Context;
use kestrel_net::modes::ModeKind;
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    Arch, LinuxMemoryBuilder, LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder,
    LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, RootBuilder,
};
use kestrel_oci::validate::SpecExt;

use crate::api::containers::CreateContainerRequest;
use crate::registry::{self, ContainerMeta};

/// Annotation key `kestrel-runtime`'s `create.rs` (`create.rs`'s own
/// private `LOWER_CHAIN_IDS_ANNOTATION` const, Phase 9 Task 3) reads to
/// take its already-pulled-layers fast path. Duplicated here as a literal
/// (not imported) because `kestreld` deliberately never depends on
/// `kestrel-runtime` as a library in production (see `lib.rs`'s own doc
/// comment) — this string is the real, load-bearing contract between the
/// two binaries and MUST stay byte-for-byte in sync with that const.
const LOWER_CHAIN_IDS_ANNOTATION: &str = "kestrel.lowerChainIds";

/// Everything `api::containers::create_container` needs after a
/// successful materialization.
pub struct MaterializedBundle {
    pub bundle_dir: PathBuf,
    /// `Some(..)` only when THIS call created a brand new bridge-mode
    /// netns (`kestrel_net::netns::create_netns`) for this container's own
    /// id — `container:<id>`/`host`/`none` modes never set this, since
    /// they either reuse another container's existing pin or never create
    /// one at all. The caller (`create_container`) must tear this down via
    /// `kestrel_net::netns::teardown_netns(run_dir, id)` if the LATER
    /// shim-spawn/`create()` step fails, so a failed `POST /containers`
    /// never leaks a pinned namespace.
    pub netns_pin_to_cleanup_on_failure: Option<PathBuf>,
}

/// Distinguishes client-caused failures (bad `image`/`bundle_rootfs`/
/// `network_mode`, an unknown `container:<id>` reference) from genuine
/// internal errors, so `api::mod::AppError` can map the former to `400`
/// instead of `500`.
#[derive(Debug)]
pub enum BundleError {
    BadRequest(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::BadRequest(msg) => write!(f, "{msg}"),
            BundleError::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<anyhow::Error> for BundleError {
    fn from(err: anyhow::Error) -> Self {
        BundleError::Internal(err)
    }
}

/// Parsed form of `CreateContainerRequest.network_mode`. The request
/// field itself being absent defaults to `NetworkMode::None` (a fresh,
/// empty, unattached netns) rather than `Bridge` — bridge mode spawns an
/// extra `netns-helper` subprocess (`kestrel_net::netns::create_netns`)
/// this daemon has no business doing implicitly for a client that never
/// asked for networking. Real veth/bridge/NAT wiring (making `Bridge`
/// mode actually reach anywhere) is Task 17's job — this task only proves
/// Task 4's join-by-path plumbing works end to end through the real HTTP
/// path.
enum NetworkMode {
    Bridge,
    Host,
    None,
    Container(String),
}

fn parse_network_mode(raw: Option<&str>) -> Result<NetworkMode, BundleError> {
    match raw {
        None | Some("none") => Ok(NetworkMode::None),
        Some("bridge") => Ok(NetworkMode::Bridge),
        Some("host") => Ok(NetworkMode::Host),
        Some(other) => match other.strip_prefix("container:") {
            Some(id) if !id.is_empty() => Ok(NetworkMode::Container(id.to_string())),
            _ => Err(BundleError::BadRequest(format!(
                "invalid network_mode {other:?}: expected \"bridge\", \"host\", \"none\", or \"container:<id>\""
            ))),
        },
    }
}

/// Resolves `container:<id>`'s referenced container's OWN recorded mode
/// (persisted in ITS `meta.json` by this same module, `network_mode:
/// Option<String>` — see `registry::ContainerMeta`'s own doc comment) into
/// the `ModeKind` `kestrel_net::modes::resolve_container_mode` needs to
/// enforce the one-hop-only rule. A referenced id with no `meta.json` at
/// all is a real client error (unknown container), not silently treated
/// as `ModeKind::None`.
async fn referenced_container_mode_kind(data_dir: &Path, referenced_id: &str) -> Result<ModeKind, BundleError> {
    let meta_path = registry::meta_path(data_dir, referenced_id);
    if !tokio::fs::try_exists(&meta_path).await.unwrap_or(false) {
        return Err(BundleError::BadRequest(format!(
            "network_mode references unknown container {referenced_id:?} (no meta.json found)"
        )));
    }
    let meta = registry::read_meta(data_dir, referenced_id).await;
    match meta.network_mode.as_deref() {
        None | Some("none") => Ok(ModeKind::None),
        Some("bridge") => Ok(ModeKind::Bridge),
        Some("host") => Ok(ModeKind::Host),
        Some(s) if s.starts_with("container:") => Ok(ModeKind::Container),
        Some(other) => Err(BundleError::Internal(anyhow::anyhow!(
            "container {referenced_id:?}'s stored meta.json has an unrecognized network_mode {other:?}"
        ))),
    }
}

/// The real entry point. See this module's own doc comment for the full
/// shape of what happens.
pub async fn materialize_bundle(
    id: &str,
    req: &CreateContainerRequest,
    run_dir: &Path,
    data_dir: &Path,
) -> Result<MaterializedBundle, BundleError> {
    // 1. Resolve the rootfs source: an `image` reference to pull (fills in
    // the lowerChainIds annotation, Task 3's fast path) XOR a plain
    // already-extracted `bundle_rootfs` directory (overrides `root.path`
    // directly — see `materialize_bundle_inner`'s own comment on why no
    // `rootfs/` copy is needed for this case either).
    let (lower_chain_ids, root_override) = match (&req.image, &req.bundle_rootfs) {
        (Some(image), None) => {
            let chain_ids = pull_image_chain_ids(image, data_dir).await?;
            (Some(chain_ids), None)
        }
        (None, Some(bundle_rootfs)) => {
            let canon = std::fs::canonicalize(bundle_rootfs)
                .with_context(|| format!("resolving bundle_rootfs path {}", bundle_rootfs.display()))?;
            (None, Some(canon))
        }
        (Some(_), Some(_)) => {
            return Err(BundleError::BadRequest(
                "exactly one of `image` or `bundle_rootfs` must be given, not both".to_string(),
            ));
        }
        (None, None) => {
            return Err(BundleError::BadRequest(
                "one of `image` or `bundle_rootfs` is required".to_string(),
            ));
        }
    };

    let mode = parse_network_mode(req.network_mode.as_deref())?;

    // 2. Bridge-mode netns creation (design doc §4a, Task 4's real join
    // mechanism), BEFORE writing config.json, so the pin path can be set
    // as the Network namespace's `path`. `container:<id>` mode resolves
    // (but does not create) another container's already-pinned path.
    let mut created_netns_pin: Option<PathBuf> = None;
    let network_path: Option<PathBuf> = match &mode {
        NetworkMode::Bridge => {
            let pin = kestrel_net::netns::create_netns(run_dir, id)
                .await
                .context("creating bridge-mode network namespace")?;
            created_netns_pin = Some(pin.clone());
            Some(pin)
        }
        NetworkMode::Container(referenced_id) => {
            let kind = referenced_container_mode_kind(data_dir, referenced_id).await?;
            let path = kestrel_net::modes::resolve_container_mode(run_dir, referenced_id, kind)
                .map_err(|e| BundleError::BadRequest(format!("{e:#}")))?;
            Some(path)
        }
        NetworkMode::Host | NetworkMode::None => None,
    };

    // 3. Build + write config.json and meta.json. Any failure from here
    // on must tear down the netns THIS call just created before
    // returning — the caller only learns about `created_netns_pin` via a
    // successful `Ok` return, which never happens on this path.
    let inner_result = materialize_bundle_inner(id, req, data_dir, root_override, lower_chain_ids, &mode, network_path)
        .await
        .map_err(BundleError::from);
    match inner_result {
        Ok(bundle_dir) => Ok(MaterializedBundle {
            bundle_dir,
            netns_pin_to_cleanup_on_failure: created_netns_pin,
        }),
        Err(e) => {
            if created_netns_pin.is_some() {
                if let Err(unpin_err) = kestrel_net::netns::teardown_netns(run_dir, id) {
                    tracing::warn!(
                        id,
                        error = %unpin_err,
                        "failed to tear down bridge-mode netns after a later materialize_bundle step failed"
                    );
                }
            }
            Err(e)
        }
    }
}

/// Pulls `image` (a blocking pull with progress discarded — refined in a
/// later task that wires real SSE/event-bus progress reporting; dedup
/// against already-present layers happens per-layer, inside `pull_image`
/// itself, via the content store) and returns the bottom-to-top chain-id
/// sequence for its layers.
async fn pull_image_chain_ids(image: &str, data_dir: &Path) -> Result<Vec<String>, BundleError> {
    let reference = kestrel_image::reference::parse(image)
        .map_err(|e| BundleError::BadRequest(format!("invalid image reference {image:?}: {e:#}")))?;
    // Same content root `kestrel-runtime`'s own `create.rs` fast path
    // reads (`LayerStore::new(data_dir)`) — both stores must agree on
    // this root so a layer pulled here is actually where `create()`'s
    // annotation fast path (and `kestrel-init`'s later overlay mount)
    // goes looking for it.
    let store = kestrel_image::store::ContentStore::new(data_dir.to_path_buf());
    let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir.to_path_buf());
    let chain_ids = kestrel_image::pull::pull_image(&reference, &store, &layer_store, false, discard_progress)
        .await
        .with_context(|| format!("pulling image {image:?}"))?;
    Ok(chain_ids)
}

/// A plain, named, non-capturing fn item (not an inline closure) passed as
/// `pull_image`'s `on_progress` callback. Necessary, not just stylistic:
/// an inline closure here (even a fully empty `|_p| {}`) tripped a real
/// rustc HRTB-inference limitation ("implementation of `Send` is not
/// general enough") once this call sat behind axum's `Handler` trait's own
/// generic `Future` bound — a plain fn item's type is already fully
/// resolved with no closure-capture lifetime for the compiler to fail to
/// universally quantify, which sidesteps the issue entirely.
fn discard_progress(_progress: kestrel_image::pull::PullProgress) {}

/// Builds the real `config.json` (default spec + overrides) and writes it,
/// plus `meta.json`, to disk. Split out from `materialize_bundle` purely
/// so that function can localize netns rollback around this call.
#[allow(clippy::too_many_arguments)]
async fn materialize_bundle_inner(
    id: &str,
    req: &CreateContainerRequest,
    data_dir: &Path,
    root_override: Option<PathBuf>,
    lower_chain_ids: Option<Vec<String>>,
    mode: &NetworkMode,
    network_path: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    let mut spec = kestrel_oci::default_spec::default_spec();

    // `bundle_rootfs` fallback case only: point `root.path` at the
    // caller-supplied, already-extracted directory directly.
    // `PathBuf::join` discards the base when the joined path is absolute
    // (which `root_override` always is, via `canonicalize` above), so
    // `create.rs`'s fallback `bundle.path.join(root.path())` resolves to
    // this directory regardless of where the bundle itself lives — no
    // `rootfs/` copy or symlink needed. The `image` case leaves `root`
    // untouched (default_spec()'s relative "rootfs", never dereferenced —
    // Task 3's annotation fast path skips that lookup entirely).
    if let Some(root_path) = root_override {
        let root = RootBuilder::default()
            .path(root_path)
            .readonly(false)
            .build()
            .map_err(|e| anyhow::anyhow!("building root: {e}"))?;
        spec.set_root(Some(root));
    }

    if let Some(mut process) = spec.process().clone() {
        if let Some(cmd) = &req.cmd {
            anyhow::ensure!(!cmd.is_empty(), "cmd must not be empty when given");
            process.set_args(Some(cmd.clone()));
        }
        if let Some(env) = &req.env {
            process.set_env(Some(env.clone()));
        }
        process.set_terminal(Some(req.tty));
        spec.set_process(Some(process));
    }

    // `default_spec()` always sets `linux` (via `LinuxBuilder::default()`
    // in `default_namespaces()`'s caller), so this is never `None` in
    // practice — `unwrap_or_default()` is defensive, not load-bearing.
    let mut linux = spec.linux().clone().unwrap_or_default();
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    match mode {
        NetworkMode::Host => {
            // Matches existing `LinuxNamespaceType` semantics used
            // elsewhere in this codebase (`build_namespace_plan`'s own
            // create/join split): omitting the Network namespace from the
            // list entirely means the container simply runs in the
            // host's own network namespace.
            namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Network);
        }
        NetworkMode::None => {
            // Network namespace stays in the list with no `path` set —
            // `build_namespace_plan` routes it into `plan.create`, so the
            // container gets a fresh, empty, unattached netns via the
            // normal "create" path (not omitted, just unattached).
        }
        NetworkMode::Bridge | NetworkMode::Container(_) => {
            let path = network_path
                .clone()
                .expect("network_path must be Some for Bridge/Container modes");
            for ns in namespaces.iter_mut() {
                if ns.typ() == LinuxNamespaceType::Network {
                    ns.set_path(Some(path.clone()));
                }
            }
        }
    }
    linux.set_namespaces(Some(namespaces));

    if req.memory_bytes.is_some() || req.pids_limit.is_some() {
        let mut resources_builder = LinuxResourcesBuilder::default();
        if let Some(mem) = req.memory_bytes {
            let memory = LinuxMemoryBuilder::default()
                .limit(mem)
                .build()
                .map_err(|e| anyhow::anyhow!("building memory resources: {e}"))?;
            resources_builder = resources_builder.memory(memory);
        }
        if let Some(pids) = req.pids_limit {
            let pids_res = LinuxPidsBuilder::default()
                .limit(pids)
                .build()
                .map_err(|e| anyhow::anyhow!("building pids resources: {e}"))?;
            resources_builder = resources_builder.pids(pids_res);
        }
        let resources = resources_builder
            .build()
            .map_err(|e| anyhow::anyhow!("building resources: {e}"))?;
        linux.set_resources(Some(resources));
    }

    // Phase 9 Task 16: `SCMP_ACT_NOTIFY` on each requested syscall, default
    // action `SCMP_ACT_ALLOW` for everything else — the same shape Phase
    // 5's own `kestrel-security/tests/notify.rs::notify_personality_profile`
    // test fixture uses, so this deliberately narrow knob genuinely
    // exercises `kestrel-runtime`'s real `uses_seccomp_notify`/
    // `seccomp_notify_sink` gap-fill (`create.rs`, this same phase) end to
    // end through the real HTTP API. Both architectures are always listed
    // (rather than resolving the host's own arch) — `install_seccomp`
    // silently no-ops a syscall rule on any arch not in this list, and
    // listing both this project's two real deployment targets costs
    // nothing on the arch that isn't actually running.
    if let Some(syscalls) = req.seccomp_notify_syscalls.as_ref().filter(|s| !s.is_empty()) {
        let rule = LinuxSyscallBuilder::default()
            .names(syscalls.clone())
            .action(LinuxSeccompAction::ScmpActNotify)
            .build()
            .map_err(|e| anyhow::anyhow!("building seccomp-notify syscall rule: {e}"))?;
        let seccomp = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .map_err(|e| anyhow::anyhow!("building seccomp profile: {e}"))?;
        linux.set_seccomp(Some(seccomp));
    }

    spec.set_linux(Some(linux));

    // Phase 9 Task 19: the resolved chain-id list this container is
    // ACTUALLY built from, computed here (before `lower_chain_ids` is
    // consumed by the annotation-insertion below) so `layers.json` can be
    // written once `bundle_dir`/`meta_path` are both known, further down.
    // Mirrors `kestrel-runtime create.rs`'s own `stage_bundle_rootfs_as_
    // synthetic_layer` fallback exactly for the `bundle_rootfs` case (see
    // `registry::LayersMeta`'s own doc comment for why this is a fourth,
    // deliberate copy of that same literal contract, not a new one).
    let resolved_layer_chain_ids = lower_chain_ids
        .clone()
        .unwrap_or_else(|| vec![format!("bundle-{id}")]);

    if let Some(chain_ids) = lower_chain_ids {
        let mut annotations = spec.annotations().clone().unwrap_or_default();
        annotations.insert(LOWER_CHAIN_IDS_ANNOTATION.to_string(), chain_ids.join(","));
        spec.set_annotations(Some(annotations));
    }

    spec.validate()
        .map_err(|e| anyhow::anyhow!("materialized an invalid config.json: {e}"))?;

    let bundle_dir = data_dir.join("bundles").join(id);
    tokio::fs::create_dir_all(&bundle_dir)
        .await
        .with_context(|| format!("creating bundle dir {}", bundle_dir.display()))?;
    let raw = RawSpec {
        spec,
        extra: serde_json::Map::new(),
    };
    let bytes = serde_json::to_vec_pretty(&raw).context("serializing config.json")?;
    tokio::fs::write(bundle_dir.join("config.json"), bytes)
        .await
        .with_context(|| format!("writing {}/config.json", bundle_dir.display()))?;

    // Writer half of Task 7's recovery contract. `network: None` here is
    // correct even for a bridge-mode container: this write happens BEFORE
    // `create()` (and Task 17's post-create veth/bridge/NAT attachment)
    // ever runs — `api::containers::create_container` rewrites this same
    // file (`registry::write_meta`) with the real `NetworkInfo` once
    // attachment genuinely succeeds.
    let meta = ContainerMeta {
        tty: req.tty,
        network_mode: req.network_mode.clone(),
        network: None,
    };
    let meta_path = registry::meta_path(data_dir, id);
    if let Some(parent) = meta_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let meta_bytes = serde_json::to_vec(&meta).context("serializing meta.json")?;
    tokio::fs::write(&meta_path, meta_bytes)
        .await
        .with_context(|| format!("writing {}", meta_path.display()))?;

    // Phase 9 Task 19: `layers.json` — the durable record `GET
    // /containers/:id/layers` reads back (`registry::LayersMeta`'s own doc
    // comment has the full rationale for why this must be persisted here,
    // rather than derived on demand, and why `resolved_layer_chain_ids`
    // above is computed to mirror `kestrel-runtime create.rs`'s own
    // fallback exactly for the `bundle_rootfs` case).
    registry::write_layers(data_dir, id, &registry::LayersMeta { chain_ids: resolved_layer_chain_ids })
        .await
        .with_context(|| format!("writing layers.json for {id}"))?;

    Ok(bundle_dir)
}
