// crates/kestreld/src/api/images.rs
//
//! Phase 9 Task 20: image endpoints — `POST /images/pull`, `GET /images`,
//! `GET /images/:ref`, `GET /images/:ref/layers`, `DELETE /images/:ref`,
//! `GET /images/dedup`.
//!
//! ## The one real gap this module has to fill itself: name -> digest
//!
//! `kestrel_image::store::ContentStore` is purely digest-addressed — it has
//! no notion of a human `name:tag` reference at all (grepped the whole
//! crate: `add_ref`/`remove_ref`/`is_referenced` key everything by
//! `(digest, owner_id)`, and `write_oci_layout`'s `index.json` records only
//! digests, no ref-name annotations). But `GET /images`, `GET /images/:ref`,
//! and `DELETE /images/:ref` all need to resolve a reference string back to
//! "which manifest digest did that pull produce" — there is no missing
//! `kestrel-image` primitive here (confirmed during grounding), just a
//! small piece of bookkeeping this endpoint module owns: a JSON map,
//! persisted at `<data_dir>/content/named-images.json` (a sibling of
//! `ContentStore`'s own `content/blobs`/`content/refs` directories, under a
//! filename it never itself writes to, so there's no collision with its own
//! on-disk layout), from the CANONICAL reference string
//! (`canonical_ref_string`, e.g. `docker.io/library/alpine:latest`) to the
//! manifest digest `pull_image_with_client` produced plus the bottom-to-top
//! chain-id sequence it returned. `GET /images/:ref` etc. re-derive
//! everything else (config digest, per-layer digests/sizes) by reading the
//! manifest blob straight back out of the real `ContentStore` at request
//! time, rather than caching a second copy of it here.
//!
//! ## Refcounting: this module is the first production caller
//!
//! `ContentStore::add_ref`/`remove_ref`/`is_referenced`/
//! `remove_blob_if_unreferenced` already exist and are already tested
//! (`kestrel-image/src/store.rs`), but grepping the whole workspace before
//! this task found zero production callers of `add_ref` — `bundle.rs`'s own
//! `image:` pull path (`POST /containers`) never refs anything it pulls.
//! This module is where that wiring actually starts: a successful `POST
//! /images/pull` calls `add_ref(digest, owner)` for the manifest, the
//! config, and every layer, with `owner` a filesystem-safe encoding of the
//! canonical reference (`sanitize_owner_id`) — so two different named
//! references that happen to share a layer (or even the exact same
//! manifest digest) each hold their own, independent ref, and `DELETE
//! /images/:ref` removing one never zeroes out a blob the other still
//! needs.
//!
//! ## Resolving the manifest digest `pull_image_with_client` doesn't return
//!
//! `pull_image_with_client` (`kestrel-image/src/pull.rs`) only returns the
//! pulled layers' bottom-to-top chain-ids — never the digest of the
//! manifest it wrote into the content store. Its own `PullProgress::
//! ManifestFetched` event fires too early to help either: for a
//! multi-platform reference (a real `alpine:latest` pull IS one, in
//! practice) it reports the INDEX's digest, not the resolved per-platform
//! manifest's digest that actually ends up on disk (`pull_image_with_client`
//! re-fetches by digest internally after `select_platform`, and it's THAT
//! second fetch's bytes that get written to the store). So this module
//! does its own resolution pass first (`resolve_final_manifest`, built only
//! from `kestrel-image`'s already-public helpers:
//! `RegistryClient::fetch_manifest_bytes`, `manifest::is_index_media_type`,
//! `manifest::select_platform`, `manifest::docker_platform_arch` — the
//! exact same steps `pull_image_with_client` itself performs internally,
//! necessarily duplicated rather than reused since `kestrel-image` doesn't
//! expose that resolution as its own function) to learn the concrete
//! digest UP FRONT, then pins `pull_image_with_client`'s own `reference`
//! argument to that exact digest (`ImageReference.manifest_reference()`
//! already prefers a set `digest` over `tag` — see `reference.rs`'s own
//! doc comment) so its internal fetch resolves to the identical manifest,
//! not a possibly-different one if the tag moved in between.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context;
use axum::extract::{Path as PathParam, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::Json;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use kestrel_image::digest::Digest;
use kestrel_image::manifest::{docker_platform_arch, is_index_media_type, select_platform};
use kestrel_image::pull::{pull_image_with_client, PullProgress};
use kestrel_image::reference::{self, ImageReference};
use kestrel_image::registry::RegistryClient;
use kestrel_image::store::ContentStore;
use kestrel_oci::image_spec::{ImageIndex, ImageManifest};
use kestrel_rootfs::snapshot::LayerStore;

use crate::api::AppError;
use crate::events::{self, Event};
use crate::AppState;

// ===========================================================================
// Named-image bookkeeping (this module's own, see module doc comment)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedImage {
    manifest_digest: String,
    /// Bottom-to-top, same order as the resolved manifest's own `layers`
    /// array — `pull_image_with_client`'s Phase B produces `chain_ids` in
    /// exactly that order (see its own doc comment), so `chain_ids[i]`
    /// always corresponds to `manifest.layers()[i]`.
    chain_ids: Vec<String>,
}

type NamedImages = HashMap<String, NamedImage>;

fn named_images_path(data_dir: &Path) -> PathBuf {
    data_dir.join("content").join("named-images.json")
}

/// Serializes every `read_filtered_lines`-style read-modify-write of
/// `named-images.json` (`record_pulled_image`, `delete_image_blocking`)
/// against each other within THIS process — a plain read-then-write with
/// no lock would lose an update if two `POST /images/pull`/`DELETE
/// /images/:ref` calls raced. One process-wide lock, not keyed by
/// `data_dir`: this daemon only ever runs against a single configured
/// `data_dir` in production, and the tiny bit of cross-test serialization
/// this causes for tests using DIFFERENT tempdirs is a harmless, cheap
/// trade-off against the complexity of a `data_dir`-keyed lock table.
fn named_images_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn read_named_images(data_dir: &Path) -> anyhow::Result<NamedImages> {
    let path = named_images_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write-to-temp-then-rename, matching every other atomic-write convention
/// in this codebase (`ContentStore::write_blob`, `State::write_atomic`) —
/// a crash or panic mid-write must never leave a half-written, unparseable
/// `named-images.json` behind for the next read to trip over.
fn write_named_images(data_dir: &Path, images: &NamedImages) -> anyhow::Result<()> {
    let path = named_images_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_file_name(format!(".named-images.json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(images)?).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// The canonical, fully-qualified form of a reference (`registry/
/// repository:tag`) — the key `named-images.json` is indexed by, so that
/// `alpine:latest`, `library/alpine:latest`, and
/// `docker.io/library/alpine:latest` (all genuinely the same image, per
/// `reference::parse`'s own documented Docker-compatible defaulting) all
/// resolve to the exact same entry, regardless of which exact spelling a
/// client used to pull vs. later look up/delete it with. An
/// untagged/undigested reference defaults to `:latest`, mirroring
/// `ImageReference::manifest_reference`'s own identical default.
fn canonical_ref_string(r: &ImageReference) -> String {
    format!("{}/{}:{}", r.registry, r.repository, r.tag.clone().unwrap_or_else(|| "latest".to_string()))
}

/// A filesystem-safe encoding of a canonical reference string, used as
/// `ContentStore::add_ref`/`remove_ref`'s `owner_id` — that parameter
/// becomes a literal filename (`content/refs/<digest-hex>/<owner_id>`), so
/// a canonical reference's own `/`/`:`  characters (always present —
/// `canonical_ref_string` always includes both) must never reach it
/// unescaped. Not required to be reversible: `named-images.json` is the
/// real, canonical name -> digest source of truth; this is only ever used
/// as a stable, collision-resistant-enough refcounting key, matching
/// `kestrel_rootfs::snapshot`'s own `sanitize_chain_id` precedent (replace
/// anything that isn't ASCII-alphanumeric).
fn sanitize_owner_id(reference: &str) -> String {
    reference.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect()
}

fn read_manifest(store: &ContentStore, digest: &Digest) -> anyhow::Result<ImageManifest> {
    let bytes = std::fs::read(store.blob_path(digest)).with_context(|| format!("reading manifest blob {digest}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing manifest JSON for {digest}"))
}

fn lookup_named_image(data_dir: &Path, raw_ref: &str) -> Result<(String, NamedImage), AppError> {
    let reference = reference::parse(raw_ref)
        .map_err(|e| AppError::bad_request(format!("invalid image reference {raw_ref:?}: {e:#}")))?;
    let canonical = canonical_ref_string(&reference);
    let images = read_named_images(data_dir).map_err(AppError::from)?;
    let named = images
        .get(&canonical)
        .cloned()
        .ok_or_else(|| AppError::not_found(format!("image {canonical:?} not found")))?;
    Ok((canonical, named))
}

/// Plain recursive `fs::metadata` walk summing every regular file's real
/// `st_size` under `dir` — the exact same technique (deliberately
/// duplicated, not imported: `api::introspect::dir_size` is private to that
/// module) `api::introspect::get_layers` (Task 19) already established for
/// "how big is this chain-id's extracted content, for real, on this host".
/// A missing dir sizes as `0`, not an error — same posture as that
/// precedent.
fn dir_size(dir: &Path) -> anyhow::Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading directory entry in {}", dir.display()))?;
        let file_type = entry.file_type().with_context(|| format!("reading file type of {}", entry.path().display()))?;
        if file_type.is_dir() {
            total += dir_size(&entry.path())?;
        } else if file_type.is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}

// ===========================================================================
// Step 1: POST /images/pull — real SSE progress + event-bus dual publish
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct PullRequest {
    pub reference: String,
}

/// The SSE wire shape: `PullProgress` itself isn't `Serialize` (it holds
/// `kestrel_image::digest::Digest`, which deliberately isn't either — see
/// that type's own module), so this is a plain, all-`String`/primitive
/// mirror of it, plus one variant `PullProgress` doesn't have at all:
/// `Error`, sent (instead of a `Complete`) when the pull itself fails
/// partway through, so a client watching the SSE stream always gets a
/// terminal event either way rather than the connection just silently
/// closing.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
enum PullProgressWire {
    ManifestFetched { digest: String },
    LayerStart { digest: String, index: usize, total: usize },
    LayerDeduped { digest: String },
    LayerDownloaded { digest: String, bytes: u64 },
    LayerExtracted { digest: String, chain_id: String },
    Complete { chain_ids: Vec<String> },
    Error { message: String },
}

impl From<&PullProgress> for PullProgressWire {
    fn from(p: &PullProgress) -> Self {
        match p {
            PullProgress::ManifestFetched { digest } => PullProgressWire::ManifestFetched { digest: digest.to_string() },
            PullProgress::LayerStart { digest, index, total } => {
                PullProgressWire::LayerStart { digest: digest.to_string(), index: *index, total: *total }
            }
            PullProgress::LayerDeduped { digest } => PullProgressWire::LayerDeduped { digest: digest.to_string() },
            PullProgress::LayerDownloaded { digest, bytes } => {
                PullProgressWire::LayerDownloaded { digest: digest.to_string(), bytes: *bytes }
            }
            PullProgress::LayerExtracted { digest, chain_id } => {
                PullProgressWire::LayerExtracted { digest: digest.to_string(), chain_id: chain_id.clone() }
            }
            PullProgress::Complete { chain_ids } => PullProgressWire::Complete { chain_ids: chain_ids.clone() },
        }
    }
}

/// Human text for `Event::ImagePullProgress.detail` — the event bus's own
/// `Event` enum carries no structured `PullProgress` payload (`events.rs`'s
/// doc comment: `detail: String`), so this is a short, readable summary,
/// not a re-serialization of the wire event (that's what the SSE stream
/// itself already carries, for clients that want the structured form).
fn describe_progress(p: &PullProgress) -> String {
    match p {
        PullProgress::ManifestFetched { digest } => format!("manifest fetched: {digest}"),
        PullProgress::LayerStart { digest, index, total } => format!("layer {}/{total} starting: {digest}", index + 1),
        PullProgress::LayerDeduped { digest } => format!("layer already present, deduped: {digest}"),
        PullProgress::LayerDownloaded { digest, bytes } => format!("layer downloaded: {digest} ({bytes} bytes)"),
        PullProgress::LayerExtracted { digest, chain_id } => format!("layer extracted: {digest} -> {chain_id}"),
        PullProgress::Complete { chain_ids } => format!("pull complete: {} layers", chain_ids.len()),
    }
}

/// `POST /images/pull` — `{"reference": "alpine:latest"}` in, an SSE stream
/// of `PullProgressWire` events out. The reference is parsed (a real `400`
/// for a malformed one) synchronously, before ever spawning anything or
/// opening the SSE response, so a client gets an immediate, ordinary HTTP
/// error rather than an SSE stream that opens and then immediately reports
/// failure as its only event.
pub async fn pull_image_endpoint(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PullRequest>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, AppError> {
    let reference = reference::parse(&req.reference)
        .map_err(|e| AppError::bad_request(format!("invalid image reference {:?}: {e:#}", req.reference)))?;
    let canonical = canonical_ref_string(&reference);

    let (tx, rx) = mpsc::unbounded_channel::<PullProgressWire>();
    tokio::spawn(run_pull_and_report(
        state.data_dir.clone(),
        canonical,
        req.reference.clone(),
        reference,
        state.event_bus.clone(),
        tx,
    ));

    Ok(Sse::new(pull_progress_stream(rx)).keep_alive(KeepAlive::default()))
}

fn pull_progress_stream(
    rx: mpsc::UnboundedReceiver<PullProgressWire>,
) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            let wire = rx.recv().await?;
            let data = serde_json::to_string(&wire).unwrap_or_else(|e| {
                // Every `PullProgressWire` variant is plain, always-
                // serializable data (Strings/numbers) — this branch is not
                // expected to ever actually run; defensive only. Loops
                // rather than ending the stream on this one bad event, so
                // an isolated failure doesn't silently kill an otherwise-
                // healthy pull's SSE connection.
                tracing::error!(error = %e, "failed to serialize PullProgressWire for SSE — dropping it");
                String::new()
            });
            if data.is_empty() {
                continue;
            }
            return Some((Ok(SseEvent::default().data(data)), rx));
        }
    })
}

/// Resolves `reference` down to the concrete, single-platform manifest a
/// pull of it will actually store — see this module's own doc comment for
/// why this duplicates (rather than reuses) `pull_image_with_client`'s own
/// internal index-resolution steps, using only `kestrel-image`'s already-
/// public helpers.
async fn resolve_final_manifest(client: &RegistryClient, reference: &ImageReference) -> anyhow::Result<(Digest, Vec<u8>)> {
    let (bytes, digest, media_type) = client.fetch_manifest_bytes(reference).await.context("fetching manifest")?;
    if !is_index_media_type(&media_type) {
        return Ok((digest, bytes));
    }

    let index: ImageIndex = serde_json::from_slice(&bytes).context("parsing manifest as an index")?;
    let selected = select_platform(&index, "linux", docker_platform_arch(std::env::consts::ARCH), None)?;
    let selected_digest: Digest =
        selected.digest().to_string().parse().context("parsing selected manifest's digest")?;
    let (resolved_bytes, resolved_digest, _media_type) = client
        .fetch_manifest_bytes(&ImageReference { digest: Some(selected_digest.clone()), ..reference.clone() })
        .await
        .context("fetching selected platform manifest")?;
    anyhow::ensure!(
        resolved_digest == selected_digest,
        "selected platform manifest digest mismatch: index said {selected_digest}, fetched bytes hash to {resolved_digest}"
    );
    Ok((resolved_digest, resolved_bytes))
}

/// The real pull, run detached from the HTTP request (`tokio::spawn`d by
/// `pull_image_endpoint`): resolves the manifest, runs the real
/// `pull_image_with_client`, forwarding every `PullProgress` both onto
/// `tx` (this request's own SSE stream) AND onto `event_bus` (Task 14) as
/// `image.pull.progress`/`image.pull.done` — the real dual-publish this
/// task's whole point is. On success, records the pull into
/// `named-images.json` and refs every blob it touched (module doc
/// comment); on any failure, sends a terminal `PullProgressWire::Error`
/// so the SSE stream always ends with SOME terminal event.
async fn run_pull_and_report(
    data_dir: PathBuf,
    canonical: String,
    raw_reference: String,
    reference: ImageReference,
    event_bus: events::EventBus,
    tx: mpsc::UnboundedSender<PullProgressWire>,
) {
    let store = ContentStore::new(data_dir.clone());
    let layer_store = LayerStore::new(data_dir.clone());

    let client = match RegistryClient::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            let _ = tx.send(PullProgressWire::Error { message: format!("building registry client: {e:#}") });
            return;
        }
    };

    let (final_digest, manifest_bytes) = match resolve_final_manifest(&client, &reference).await {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.send(PullProgressWire::Error { message: format!("resolving manifest: {e:#}") });
            return;
        }
    };
    // Pin the pull to the exact digest just resolved — see
    // `resolve_final_manifest`'s own doc comment for why.
    let pinned_reference = ImageReference { digest: Some(final_digest.clone()), ..reference };

    let tx_cb = tx.clone();
    let bus_cb = event_bus.clone();
    let raw_ref_cb = raw_reference.clone();
    let on_progress = move |progress: PullProgress| {
        let wire = PullProgressWire::from(&progress);
        let _ = tx_cb.send(wire);
        match &progress {
            PullProgress::Complete { .. } => {
                events::publish(&bus_cb, Event::ImagePullDone { reference: raw_ref_cb.clone() });
            }
            other => {
                events::publish(
                    &bus_cb,
                    Event::ImagePullProgress { reference: raw_ref_cb.clone(), detail: describe_progress(other) },
                );
            }
        }
    };

    let result = pull_image_with_client(client, &pinned_reference, &store, &layer_store, false, on_progress).await;

    match result {
        Ok(chain_ids) => {
            if let Err(e) = record_pulled_image(&data_dir, &store, &canonical, &final_digest, &manifest_bytes, &chain_ids)
            {
                tracing::warn!(error = %e, canonical, "pull succeeded but recording named-image bookkeeping failed");
                let _ =
                    tx.send(PullProgressWire::Error { message: format!("pull succeeded but bookkeeping failed: {e:#}") });
            }
        }
        Err(e) => {
            let _ = tx.send(PullProgressWire::Error { message: format!("{e:#}") });
        }
    }
}

/// Rolls back every `add_ref` this call already made, in reverse order,
/// before `record_pulled_image` propagates an error from a later step —
/// mirrors the exact idiom `network.rs`'s Task 17 DNAT-rollback fix
/// established (`attach_inner`'s published-ports loop): track successes as
/// you go, best-effort-undo them on a later failure, and log (never
/// propagate/mask the original error with) a cleanup-step failure. Without
/// this, a partial failure inside `record_pulled_image` (a later `add_ref`
/// call, or the trailing `write_named_images`) would leave earlier refs
/// permanently attributed to a reference that never made it into
/// `named-images.json` — a silent, permanent disk leak, since nothing
/// named would ever again call `remove_ref` for them.
fn rollback_added_refs(store: &ContentStore, owner: &str, canonical: &str, added: &[Digest]) {
    for digest in added.iter().rev() {
        if let Err(cleanup_err) = store.remove_ref(digest, owner) {
            tracing::warn!(
                canonical,
                digest = %digest,
                error = %cleanup_err,
                "failed to roll back an already-added content-store ref after record_pulled_image \
                 failed partway through"
            );
        }
    }
}

/// Persists a successful pull's `named-images.json` entry and refs every
/// blob it touched (manifest, config, every layer) under this reference's
/// own sanitized owner id — see this module's own doc comment for both.
///
/// Transactional w.r.t. `ContentStore` refs + `named-images.json`: if any
/// `add_ref` call, or the trailing `write_named_images` call, fails, every
/// ref already added earlier in this same call is rolled back
/// (`rollback_added_refs`) before the error is returned — so a caller
/// observing `Err` from this function is guaranteed `ContentStore` carries
/// zero refs attributable to this call that didn't exist before it, and
/// `named-images.json` has no entry for `canonical`.
fn record_pulled_image(
    data_dir: &Path,
    store: &ContentStore,
    canonical: &str,
    manifest_digest: &Digest,
    manifest_bytes: &[u8],
    chain_ids: &[String],
) -> anyhow::Result<()> {
    let manifest: ImageManifest = serde_json::from_slice(manifest_bytes).context("parsing resolved manifest")?;
    let owner = sanitize_owner_id(canonical);

    // Every digest this pull needs ref'd, in the order they'll be added —
    // computed up front (rather than interleaving parse-then-add) so a
    // digest-parse failure partway through the layer list can't leave the
    // rollback logic guessing which layers were already ref'd vs. not yet
    // even attempted.
    let mut digests_to_ref = Vec::with_capacity(2 + manifest.layers().len());
    digests_to_ref.push(manifest_digest.clone());
    digests_to_ref.push(manifest.config().digest().to_string().parse().context("parsing config digest")?);
    for layer in manifest.layers() {
        digests_to_ref.push(layer.digest().to_string().parse().context("parsing layer digest")?);
    }

    let mut added: Vec<Digest> = Vec::with_capacity(digests_to_ref.len());
    for digest in &digests_to_ref {
        if let Err(e) = store.add_ref(digest, &owner) {
            rollback_added_refs(store, &owner, canonical, &added);
            return Err(e).context("ref-ing blob");
        }
        added.push(digest.clone());
    }

    let _guard = named_images_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut images = match read_named_images(data_dir) {
        Ok(images) => images,
        Err(e) => {
            drop(_guard);
            rollback_added_refs(store, &owner, canonical, &added);
            return Err(e);
        }
    };
    images.insert(canonical.to_string(), NamedImage { manifest_digest: manifest_digest.to_string(), chain_ids: chain_ids.to_vec() });
    if let Err(e) = write_named_images(data_dir, &images) {
        drop(_guard);
        rollback_added_refs(store, &owner, canonical, &added);
        return Err(e);
    }
    Ok(())
}

// ===========================================================================
// Step 2: GET /images
// ===========================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageSummary {
    pub reference: String,
    pub manifest_digest: String,
    pub layer_count: usize,
    /// Sum of this image's own layer descriptors' declared `size` (the
    /// size of each layer blob AS STORED/transmitted — i.e. compressed,
    /// for the common gzip/zstd case) — "how much does `docker pull`-style
    /// accounting say this one image costs", matching `GET /images/dedup`'s
    /// own "logical" vs "physical" distinction below (this field is closer
    /// in spirit to logical: it's this image's OWN claimed size, not
    /// adjusted for what's actually shared on disk with any other image).
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImagesListResponse {
    pub images: Vec<ImageSummary>,
}

/// `GET /images` — a directory walk over this module's own
/// `named-images.json` (see module doc comment for why: no "list pulled
/// images" API exists anywhere in `kestrel-image` to call instead), each
/// entry backed by a real read of its manifest blob straight out of the
/// content store.
pub async fn list_images(State(state): State<Arc<AppState>>) -> Result<Json<ImagesListResponse>, AppError> {
    let data_dir = state.data_dir.clone();
    let response = tokio::task::spawn_blocking(move || list_images_blocking(&data_dir))
        .await
        .map_err(|e| AppError::internal(format!("images: list task panicked: {e}")))??;
    Ok(Json(response))
}

/// Resolves one `named-images.json` entry into its `ImageSummary`, or an
/// error describing exactly why it couldn't be (bad digest, missing/
/// unreadable/corrupted manifest blob, ...) — split out of
/// `list_images_blocking` so that function can treat any one entry's
/// failure as a per-entry skip (`tracing::warn!` + continue) rather than
/// aborting the whole listing, the same "degrade gracefully per item"
/// convention `api::introspect::scan_system_namespaces` (Task 19) already
/// established for `GET /system/namespaces`'s own per-pid errors.
fn resolve_image_summary(store: &ContentStore, reference: &str, named: &NamedImage) -> anyhow::Result<ImageSummary> {
    let manifest_digest: Digest = named.manifest_digest.parse().with_context(|| format!("bad digest for {reference}"))?;
    let manifest = read_manifest(store, &manifest_digest)?;
    let size_bytes: u64 = manifest.layers().iter().map(|d| d.size()).sum();
    Ok(ImageSummary {
        reference: reference.to_string(),
        manifest_digest: named.manifest_digest.clone(),
        layer_count: manifest.layers().len(),
        size_bytes,
    })
}

/// A single corrupted/stale `named-images.json` entry (e.g. one whose
/// manifest blob has since gone missing from `ContentStore`) must not turn
/// a `GET /images` that would otherwise list every OTHER image just fine
/// into a full `500` — see `resolve_image_summary`'s own doc comment for
/// the precedent this follows. The bad entry is logged and skipped, not
/// surfaced in the response body itself (matching that same precedent,
/// which also has no client-visible "errors" field).
fn list_images_blocking(data_dir: &Path) -> anyhow::Result<ImagesListResponse> {
    let images = read_named_images(data_dir)?;
    let store = ContentStore::new(data_dir.to_path_buf());

    let mut summaries = Vec::with_capacity(images.len());
    for (reference, named) in &images {
        match resolve_image_summary(&store, reference, named) {
            Ok(summary) => summaries.push(summary),
            Err(e) => {
                tracing::warn!(
                    reference,
                    manifest_digest = %named.manifest_digest,
                    error = %e,
                    "GET /images: skipping named-images.json entry that could not be resolved"
                );
            }
        }
    }
    summaries.sort_by(|a, b| a.reference.cmp(&b.reference));
    Ok(ImagesListResponse { images: summaries })
}

// ===========================================================================
// Step 3: GET /images/:ref, GET /images/:ref/layers
// ===========================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct LayerDescriptorInfo {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub chain_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageDetail {
    pub reference: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub layers: Vec<LayerDescriptorInfo>,
}

fn image_detail_blocking(data_dir: &Path, raw_ref: &str) -> Result<ImageDetail, AppError> {
    let (canonical, named) = lookup_named_image(data_dir, raw_ref)?;
    let store = ContentStore::new(data_dir.to_path_buf());
    let manifest_digest: Digest = named.manifest_digest.parse().map_err(|e: anyhow::Error| AppError::internal(format!("{e:#}")))?;
    let manifest = read_manifest(&store, &manifest_digest).map_err(AppError::from)?;
    let config_digest = manifest.config().digest().to_string();

    // `zip`, not an index-checked loop: `chain_ids[i]` corresponds to
    // `manifest.layers()[i]` by construction (`NamedImage`'s own doc
    // comment) — a length mismatch would mean `named-images.json` itself
    // was corrupted/hand-edited, in which case truncating to the shorter
    // of the two (rather than panicking the whole request) is the safer
    // degrade.
    let layers = manifest
        .layers()
        .iter()
        .zip(named.chain_ids.iter())
        .map(|(d, chain_id)| LayerDescriptorInfo {
            digest: d.digest().to_string(),
            media_type: d.media_type().to_string(),
            size: d.size(),
            chain_id: chain_id.clone(),
        })
        .collect();

    Ok(ImageDetail { reference: canonical, manifest_digest: named.manifest_digest, config_digest, layers })
}

/// `GET /images/:ref` — manifest + config digest + layer list, via a real
/// `ContentStore` blob read (module doc comment).
pub async fn get_image(
    State(state): State<Arc<AppState>>,
    PathParam(raw_ref): PathParam<String>,
) -> Result<Json<ImageDetail>, AppError> {
    let data_dir = state.data_dir.clone();
    let detail = tokio::task::spawn_blocking(move || image_detail_blocking(&data_dir, &raw_ref))
        .await
        .map_err(|e| AppError::internal(format!("images: get task panicked: {e}")))??;
    Ok(Json(detail))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LayersResponse {
    pub layers: Vec<LayerDescriptorInfo>,
}

/// `GET /images/:ref/layers` — the same layer list `GET /images/:ref`
/// returns, on its own.
pub async fn get_image_layers(
    State(state): State<Arc<AppState>>,
    PathParam(raw_ref): PathParam<String>,
) -> Result<Json<LayersResponse>, AppError> {
    let data_dir = state.data_dir.clone();
    let detail = tokio::task::spawn_blocking(move || image_detail_blocking(&data_dir, &raw_ref))
        .await
        .map_err(|e| AppError::internal(format!("images: layers task panicked: {e}")))??;
    Ok(Json(LayersResponse { layers: detail.layers }))
}

// ===========================================================================
// Step 4: DELETE /images/:ref
// ===========================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteImageResponse {
    pub reference: String,
    /// Digests that were ACTUALLY removed from the blob store (i.e.
    /// `remove_blob_if_unreferenced` returned `true` for them) — a digest
    /// still shared by another named image is ref-removed for THIS
    /// reference but intentionally absent from this list, since its blob
    /// genuinely still exists on disk afterward.
    pub blobs_removed: Vec<String>,
}

/// `DELETE /images/:ref` — `ContentStore::remove_ref` + `remove_blob_if_
/// unreferenced`, a direct passthrough (plan's own wording) for the
/// manifest, config, and every layer digest this reference pulled.
/// Extracted `LayerStore` diff directories are deliberately left alone —
/// out of scope for this task (a content-store-level delete, not a
/// snapshot/extracted-layer garbage collector).
pub async fn delete_image(
    State(state): State<Arc<AppState>>,
    PathParam(raw_ref): PathParam<String>,
) -> Result<Json<DeleteImageResponse>, AppError> {
    let data_dir = state.data_dir.clone();
    let response = tokio::task::spawn_blocking(move || delete_image_blocking(&data_dir, &raw_ref))
        .await
        .map_err(|e| AppError::internal(format!("images: delete task panicked: {e}")))??;
    Ok(Json(response))
}

fn delete_image_blocking(data_dir: &Path, raw_ref: &str) -> Result<DeleteImageResponse, AppError> {
    let (canonical, named) = lookup_named_image(data_dir, raw_ref)?;
    let store = ContentStore::new(data_dir.to_path_buf());
    let manifest_digest: Digest = named.manifest_digest.parse().map_err(|e: anyhow::Error| AppError::internal(format!("{e:#}")))?;
    let manifest = read_manifest(&store, &manifest_digest).map_err(AppError::from)?;
    let config_digest: Digest = manifest
        .config()
        .digest()
        .to_string()
        .parse()
        .map_err(|e: anyhow::Error| AppError::internal(format!("{e:#}")))?;
    let owner = sanitize_owner_id(&canonical);

    let mut all_digests = vec![manifest_digest, config_digest];
    for layer in manifest.layers() {
        let d: Digest = layer
            .digest()
            .to_string()
            .parse()
            .map_err(|e: anyhow::Error| AppError::internal(format!("{e:#}")))?;
        all_digests.push(d);
    }

    for digest in &all_digests {
        store.remove_ref(digest, &owner).map_err(AppError::from)?;
    }
    let mut blobs_removed = Vec::new();
    for digest in &all_digests {
        if store.remove_blob_if_unreferenced(digest).map_err(AppError::from)? {
            blobs_removed.push(digest.to_string());
        }
    }

    let _guard = named_images_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut images = read_named_images(data_dir).map_err(AppError::from)?;
    images.remove(&canonical);
    write_named_images(data_dir, &images).map_err(AppError::from)?;

    Ok(DeleteImageResponse { reference: canonical, blobs_removed })
}

// ===========================================================================
// Step 5: GET /images/dedup
// ===========================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct DedupResponse {
    /// Sum, over every named image, of that image's own layers'
    /// UNCOMPRESSED on-disk size — a real `fs::metadata` walk
    /// (`dir_size`) of that layer's already-extracted `LayerStore::
    /// diff_dir(chain_id)`, same technique `api::introspect::get_layers`
    /// (Task 19) uses for the identical "how big is this chain-id, for
    /// real" question. Deliberately double-counts a layer shared by two
    /// or more images — each image "logically" claims the full size of
    /// every layer it lists, whether or not that content happens to also
    /// be shared with another image.
    pub logical_bytes: u64,
    /// Sum, over every UNIQUE blob digest referenced by any named image
    /// (manifest, config, or layer — deduped by digest, computed once
    /// each, not once per image), of that blob's real, compressed,
    /// on-disk `ContentStore` file size. Since `ContentStore` is
    /// content-addressed, two images referencing the identical layer
    /// digest already share the exact same on-disk blob file — this is
    /// the real, physical storage cost, not an approximation.
    pub physical_bytes: u64,
    pub images: usize,
    pub unique_blobs: usize,
}

pub async fn get_dedup(State(state): State<Arc<AppState>>) -> Result<Json<DedupResponse>, AppError> {
    let data_dir = state.data_dir.clone();
    let response = tokio::task::spawn_blocking(move || dedup_blocking(&data_dir))
        .await
        .map_err(|e| AppError::internal(format!("images: dedup task panicked: {e}")))??;
    Ok(Json(response))
}

/// Resolves one `named-images.json` entry into the set of blob digests it
/// references plus its real extracted-content ("logical") byte size — or
/// an error describing why it couldn't be, so `dedup_blocking` can skip
/// just that one entry (same rationale/precedent as `resolve_image_summary`
/// above) instead of failing `GET /images/dedup` outright. Deliberately
/// returns everything-or-nothing for one entry (no partial digest set on a
/// mid-manifest failure): a half-collected entry would either under-count
/// `unique_blobs` or silently mix in a `logical_bytes` contribution from an
/// entry that otherwise got skipped, both worse than a clean skip.
fn resolve_dedup_entry(store: &ContentStore, layer_store: &LayerStore, named: &NamedImage) -> anyhow::Result<(Vec<Digest>, u64)> {
    let manifest_digest: Digest = named.manifest_digest.parse().context("parsing manifest digest")?;
    let manifest = read_manifest(store, &manifest_digest)?;
    let config_digest: Digest =
        manifest.config().digest().to_string().parse().context("parsing config digest")?;

    let mut digests = Vec::with_capacity(2 + manifest.layers().len());
    digests.push(manifest_digest);
    digests.push(config_digest);
    for layer in manifest.layers() {
        digests.push(layer.digest().to_string().parse().context("parsing layer digest")?);
    }

    let mut logical_bytes = 0u64;
    for chain_id in &named.chain_ids {
        logical_bytes += dir_size(&layer_store.diff_dir(chain_id))?;
    }

    Ok((digests, logical_bytes))
}

/// A single corrupted/stale `named-images.json` entry must not turn a `GET
/// /images/dedup` that would otherwise aggregate every OTHER image just
/// fine into a full `500` — mirrors `list_images_blocking`'s own identical
/// fix immediately above (see its doc comment for the precedent this
/// follows). `images` in the response reflects only the entries that were
/// actually resolvable and folded into the aggregate, not the raw count of
/// `named-images.json` entries (a bad entry contributes nothing to either
/// `logical_bytes`/`unique_blobs` or this count).
fn dedup_blocking(data_dir: &Path) -> Result<DedupResponse, AppError> {
    let images = read_named_images(data_dir).map_err(AppError::from)?;
    let store = ContentStore::new(data_dir.to_path_buf());
    let layer_store = LayerStore::new(data_dir.to_path_buf());

    let mut logical_bytes: u64 = 0;
    let mut unique_digests: HashSet<Digest> = HashSet::new();
    let mut resolved_images = 0usize;

    for (reference, named) in &images {
        match resolve_dedup_entry(&store, &layer_store, named) {
            Ok((digests, entry_logical_bytes)) => {
                unique_digests.extend(digests);
                logical_bytes += entry_logical_bytes;
                resolved_images += 1;
            }
            Err(e) => {
                tracing::warn!(
                    reference,
                    manifest_digest = %named.manifest_digest,
                    error = %e,
                    "GET /images/dedup: skipping named-images.json entry that could not be resolved"
                );
            }
        }
    }

    let mut physical_bytes: u64 = 0;
    for digest in &unique_digests {
        if let Ok(meta) = std::fs::metadata(store.blob_path(digest)) {
            physical_bytes += meta.len();
        }
    }

    Ok(DedupResponse { logical_bytes, physical_bytes, images: resolved_images, unique_blobs: unique_digests.len() })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::registry::Registry;

    fn test_app_state(data_dir: PathBuf, run_dir: PathBuf) -> Arc<AppState> {
        Arc::new(AppState {
            run_dir,
            data_dir,
            registry: Registry::default(),
            shim_path: PathBuf::new(),
            runtime_path: PathBuf::new(),
            stop_grace_period_s: 10,
            metrics_rx: tokio::sync::Mutex::new(tokio::sync::mpsc::channel(1).1),
            event_bus: events::new_bus(),
            last_status_map: crate::metrics::new_last_status_map(),
            network: kestreld::config::NetworkConfig::default(),
            seccomp_log: crate::api::introspect::SeccompLog::new(),
        })
    }

    async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        let value = if bytes.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&bytes).expect("parse JSON") };
        (status, value)
    }

    async fn delete_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder().method("DELETE").uri(uri).body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        let value = if bytes.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&bytes).expect("parse JSON") };
        (status, value)
    }

    async fn post_json(app: axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, Vec<u8>) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.expect("router oneshot");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
        (status, bytes.to_vec())
    }

    #[test]
    fn test_canonical_ref_string_defaults_untagged_to_latest() {
        let r = reference::parse("alpine").unwrap();
        assert_eq!(canonical_ref_string(&r), "docker.io/library/alpine:latest");
    }

    #[test]
    fn test_canonical_ref_string_is_stable_across_equivalent_spellings() {
        let a = reference::parse("alpine:latest").unwrap();
        let b = reference::parse("library/alpine:latest").unwrap();
        let c = reference::parse("docker.io/library/alpine:latest").unwrap();
        assert_eq!(canonical_ref_string(&a), canonical_ref_string(&b));
        assert_eq!(canonical_ref_string(&b), canonical_ref_string(&c));
    }

    #[test]
    fn test_sanitize_owner_id_strips_path_separators() {
        let sanitized = sanitize_owner_id("docker.io/library/alpine:latest");
        assert!(!sanitized.contains('/'), "sanitized owner id must not contain a path separator: {sanitized:?}");
        assert!(!sanitized.contains(':'));
    }

    #[test]
    fn test_named_images_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let mut images = NamedImages::new();
        images.insert(
            "docker.io/library/alpine:latest".to_string(),
            NamedImage { manifest_digest: format!("sha256:{}", "a".repeat(64)), chain_ids: vec!["sha256:c1".to_string()] },
        );
        write_named_images(tmp.path(), &images).unwrap();
        let read_back = read_named_images(tmp.path()).unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back["docker.io/library/alpine:latest"].chain_ids, vec!["sha256:c1".to_string()]);
    }

    #[test]
    fn test_read_named_images_missing_file_is_empty_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let images = read_named_images(tmp.path()).unwrap();
        assert!(images.is_empty());
    }

    #[tokio::test]
    async fn test_pull_image_endpoint_rejects_malformed_reference_with_400_before_any_network_io() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        // A `@digest` suffix that fails to parse as a real digest — caught
        // by `reference::parse` itself, synchronously, before this handler
        // ever spawns the background pull task or touches the network.
        let (status, _body) = post_json(app, "/images/pull", serde_json::json!({ "reference": "alpine@not-a-digest" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_image_unknown_reference_is_404() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        let (status, _) = get_json(app.clone(), "/images/does-not-exist:latest").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = get_json(app.clone(), "/images/does-not-exist:latest/layers").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = delete_json(app, "/images/does-not-exist:latest").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_and_dedup_are_empty_with_no_named_images() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        let (status, body) = get_json(app.clone(), "/images").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["images"].as_array().unwrap().len(), 0);

        let (status, body) = get_json(app, "/images/dedup").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["images"], 0);
        assert_eq!(body["logical_bytes"], 0);
        assert_eq!(body["physical_bytes"], 0);
        assert_eq!(body["unique_blobs"], 0);
    }

    /// The real proof `GET /images/dedup`'s literal route wins over `GET
    /// /images/:ref`'s dynamic one for the concrete path `/images/dedup`
    /// (both are two path segments; axum/matchit's documented static-over-
    /// dynamic priority is what's actually being exercised here) — the
    /// deterministic, no-network end of this task's own routing story.
    /// Combined with `test_list_and_dedup_are_empty_with_no_named_images`
    /// above, a `DedupResponse` (not a `404 image "dedup" not found`, which
    /// is what `get_image` would produce if it were wrongly matched
    /// instead) is the real, load-bearing assertion.
    #[tokio::test]
    async fn test_dedup_route_is_not_shadowed_by_the_dynamic_reference_route() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        let (status, body) = get_json(app, "/images/dedup").await;
        assert_eq!(status, StatusCode::OK, "expected DedupResponse, got: {body}");
        assert!(body.get("logical_bytes").is_some(), "response is not shaped like a DedupResponse: {body}");
    }

    /// End-to-end proof of `GET /images`, `GET /images/:ref`, `GET
    /// /images/:ref/layers`, `DELETE /images/:ref`, and `GET /images/dedup`
    /// against a real, on-disk (but hand-built, not actually pulled)
    /// `ContentStore`/`LayerStore`/`named-images.json` — deterministic and
    /// network-free, covering everything this task's endpoints do with
    /// data EXCEPT the pull itself (that's the real-network-gated test
    /// below, matching Phase 6's own `KESTREL_TEST_NETWORK=1` convention).
    #[tokio::test]
    async fn test_list_get_layers_delete_dedup_against_a_synthetic_named_image() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let layer_store = LayerStore::new(data_dir.path().to_path_buf());

        let layer1_bytes = b"layer-one-bytes".to_vec();
        let layer2_bytes = b"layer-two-bytes-a-bit-longer".to_vec();
        let layer1_digest = store.write_blob(None, Cursor::new(&layer1_bytes)).unwrap();
        let layer2_digest = store.write_blob(None, Cursor::new(&layer2_bytes)).unwrap();
        let config_digest = store.write_blob(None, Cursor::new(b"{}")).unwrap();

        let manifest_value = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.to_string(),
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer1_digest.to_string(),
                    "size": layer1_bytes.len(),
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer2_digest.to_string(),
                    "size": layer2_bytes.len(),
                },
            ],
        });
        let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
        let manifest_digest = store.write_blob(None, Cursor::new(&manifest_bytes)).unwrap();

        let chain_ids = vec!["sha256:synthchain1".to_string(), "sha256:synthchain2".to_string()];
        std::fs::create_dir_all(layer_store.diff_dir(&chain_ids[0])).unwrap();
        std::fs::write(layer_store.diff_dir(&chain_ids[0]).join("f1"), b"12345").unwrap(); // 5 bytes
        std::fs::create_dir_all(layer_store.diff_dir(&chain_ids[1])).unwrap();
        std::fs::write(layer_store.diff_dir(&chain_ids[1]).join("f2"), b"1234567890").unwrap(); // 10 bytes

        let reference = reference::parse("synthetic:latest").unwrap();
        let canonical = canonical_ref_string(&reference);
        let owner = sanitize_owner_id(&canonical);
        store.add_ref(&manifest_digest, &owner).unwrap();
        store.add_ref(&config_digest, &owner).unwrap();
        store.add_ref(&layer1_digest, &owner).unwrap();
        store.add_ref(&layer2_digest, &owner).unwrap();

        let mut images: NamedImages = HashMap::new();
        images.insert(canonical.clone(), NamedImage { manifest_digest: manifest_digest.to_string(), chain_ids: chain_ids.clone() });
        write_named_images(data_dir.path(), &images).unwrap();

        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        // ---- GET /images ----
        let (status, body) = get_json(app.clone(), "/images").await;
        assert_eq!(status, StatusCode::OK);
        let images_arr = body["images"].as_array().unwrap();
        assert_eq!(images_arr.len(), 1);
        assert_eq!(images_arr[0]["reference"], canonical);
        assert_eq!(images_arr[0]["layer_count"], 2);
        assert_eq!(images_arr[0]["size_bytes"], (layer1_bytes.len() + layer2_bytes.len()) as u64);

        // ---- GET /images/:ref (looked up via the SAME raw reference a
        // real client would have pulled with, not the canonical form —
        // proving `canonical_ref_string` normalization round-trips) ----
        let (status, body) = get_json(app.clone(), "/images/synthetic:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["reference"], canonical);
        assert_eq!(body["manifest_digest"], manifest_digest.to_string());
        assert_eq!(body["config_digest"], config_digest.to_string());
        let layers = body["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["chain_id"], chain_ids[0]);
        assert_eq!(layers[1]["chain_id"], chain_ids[1]);

        // ---- GET /images/:ref/layers ----
        let (status, body) = get_json(app.clone(), "/images/synthetic:latest/layers").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["layers"].as_array().unwrap().len(), 2);

        // ---- GET /images/dedup: logical double-counts nothing here (one
        // image only) — 5 + 10 = 15 bytes of real extracted content;
        // physical is the 4 real, distinct on-disk blob files
        // (manifest+config+2 layers). ----
        let (status, body) = get_json(app.clone(), "/images/dedup").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["images"], 1);
        assert_eq!(body["logical_bytes"], 15);
        assert_eq!(body["unique_blobs"], 4);
        assert!(body["physical_bytes"].as_u64().unwrap() > 0);

        // ---- DELETE /images/:ref: every blob genuinely unreferenced
        // afterward (this is the only owner of any of them) — real proof,
        // not just a 200. ----
        assert!(store.is_referenced(&manifest_digest));
        let (status, body) = delete_json(app.clone(), "/images/synthetic:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let removed = body["blobs_removed"].as_array().unwrap();
        assert_eq!(removed.len(), 4, "manifest + config + 2 layers should all have been removed: {body}");
        assert!(!store.is_referenced(&manifest_digest), "manifest must be unreferenced after delete");
        assert!(!store.has_blob(&manifest_digest), "manifest blob must actually be gone from disk");
        assert!(!store.has_blob(&layer1_digest));
        assert!(!store.has_blob(&layer2_digest));

        // ---- GET /images now empty again, GET /images/:ref now 404 ----
        let (status, body) = get_json(app.clone(), "/images").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["images"].as_array().unwrap().len(), 0);
        let (status, _) = get_json(app, "/images/synthetic:latest").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A layer shared by two named images must survive a `DELETE` of only
    /// one of them — `remove_blob_if_unreferenced` refusing to delete a
    /// still-referenced blob (the real property `ContentStore`'s own
    /// refcounting exists for), driven here through this module's actual
    /// `add_ref`/`remove_ref` wiring, not just `kestrel-image`'s own
    /// lower-level unit test of the same primitive.
    #[tokio::test]
    async fn test_delete_does_not_remove_a_layer_still_shared_by_another_image() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let layer_store = LayerStore::new(data_dir.path().to_path_buf());

        let shared_layer_bytes = b"shared-base-layer".to_vec();
        let shared_layer_digest = store.write_blob(None, Cursor::new(&shared_layer_bytes)).unwrap();

        let build_and_register = |suffix: &str, config_marker: &[u8]| {
            let config_digest = store.write_blob(None, Cursor::new(config_marker)).unwrap();
            let manifest_value = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest.to_string(), "size": 2 },
                "layers": [{
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": shared_layer_digest.to_string(),
                    "size": shared_layer_bytes.len(),
                }],
            });
            let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
            let manifest_digest = store.write_blob(None, Cursor::new(&manifest_bytes)).unwrap();

            let chain_id = format!("sha256:sharedchain-{suffix}");
            std::fs::create_dir_all(layer_store.diff_dir(&chain_id)).unwrap();
            std::fs::write(layer_store.diff_dir(&chain_id).join("f"), b"x").unwrap();

            let reference = reference::parse(&format!("shared-{suffix}:latest")).unwrap();
            let canonical = canonical_ref_string(&reference);
            let owner = sanitize_owner_id(&canonical);
            store.add_ref(&manifest_digest, &owner).unwrap();
            store.add_ref(&config_digest, &owner).unwrap();
            store.add_ref(&shared_layer_digest, &owner).unwrap();

            (canonical, manifest_digest, chain_id)
        };

        let (canonical_a, manifest_digest_a, chain_id_a) = build_and_register("a", b"config-a");
        let (canonical_b, manifest_digest_b, chain_id_b) = build_and_register("b", b"config-b");

        let mut images: NamedImages = HashMap::new();
        images.insert(canonical_a.clone(), NamedImage { manifest_digest: manifest_digest_a.to_string(), chain_ids: vec![chain_id_a] });
        images.insert(canonical_b.clone(), NamedImage { manifest_digest: manifest_digest_b.to_string(), chain_ids: vec![chain_id_b] });
        write_named_images(data_dir.path(), &images).unwrap();

        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        let (status, body) = delete_json(app.clone(), "/images/shared-a:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let removed: Vec<String> = body["blobs_removed"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(!removed.contains(&shared_layer_digest.to_string()), "shared layer must NOT be removed while image b still refs it: {removed:?}");
        assert!(store.has_blob(&shared_layer_digest), "shared layer blob must still be on disk");
        assert!(store.is_referenced(&shared_layer_digest), "shared layer must still show as referenced (by image b)");
        assert!(!store.has_blob(&manifest_digest_a), "image a's OWN manifest (not shared) must be gone");

        // Now delete image b too — the shared layer must finally go.
        let (status, _) = delete_json(app, "/images/shared-b:latest").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!store.is_referenced(&shared_layer_digest));
        assert!(!store.has_blob(&shared_layer_digest), "shared layer must be gone once BOTH images are deleted");
    }

    // -----------------------------------------------------------------
    // Adversarial-review regression tests: Bug 1 (`record_pulled_image`
    // wasn't transactional — a partial failure leaked `ContentStore` refs
    // with no `named-images.json` entry to ever clean them up via
    // `DELETE`) and Bug 2 (one corrupted/stale `named-images.json` entry
    // crashed `GET /images`/`GET /images/dedup` entirely instead of
    // degrading gracefully like `GET /system/namespaces` already does).
    // -----------------------------------------------------------------

    /// Writes the same shape of manifest+blobs `test_list_get_layers_
    /// delete_dedup_against_a_synthetic_named_image` above already
    /// establishes (two layers + a config), WITHOUT registering any refs
    /// or a `named-images.json` entry — the caller drives `record_pulled_
    /// image` itself so it can inject a failure partway through.
    fn write_synthetic_manifest_fixture(store: &ContentStore) -> (Digest, Vec<u8>, Digest, Digest, Digest) {
        let layer1_bytes = b"rollback-layer-one".to_vec();
        let layer2_bytes = b"rollback-layer-two-a-bit-longer".to_vec();
        let layer1_digest = store.write_blob(None, Cursor::new(&layer1_bytes)).unwrap();
        let layer2_digest = store.write_blob(None, Cursor::new(&layer2_bytes)).unwrap();
        let config_digest = store.write_blob(None, Cursor::new(b"{}")).unwrap();

        let manifest_value = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.to_string(),
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer1_digest.to_string(),
                    "size": layer1_bytes.len(),
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer2_digest.to_string(),
                    "size": layer2_bytes.len(),
                },
            ],
        });
        let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
        let manifest_digest = store.write_blob(None, Cursor::new(&manifest_bytes)).unwrap();

        (manifest_digest, manifest_bytes, config_digest, layer1_digest, layer2_digest)
    }

    /// Bug 1, failure mode A: a LATER `add_ref` call (the second layer's)
    /// fails after the manifest, config, and first layer were already
    /// successfully ref'd. Forced deterministically by pre-creating a
    /// plain FILE at the exact directory path `add_ref` would otherwise
    /// `create_dir_all` for that layer's digest (`content/refs/<hex>`),
    /// so `create_dir_all` fails with "not a directory" — no reliance on
    /// timing or environment. Before the fix, the manifest/config/layer1
    /// refs added before this point would have been left behind forever
    /// (a real disk leak: nothing named references them, so
    /// `remove_blob_if_unreferenced` would never fire for them either).
    #[tokio::test]
    async fn test_record_pulled_image_rolls_back_refs_when_a_later_add_ref_fails() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let (manifest_digest, manifest_bytes, config_digest, layer1_digest, layer2_digest) =
            write_synthetic_manifest_fixture(&store);

        // Sabotage: make `add_ref(&layer2_digest, ...)`'s own
        // `create_dir_all(content/refs/<layer2-hex>)` fail by occupying
        // that exact path with a plain file first.
        let poisoned_ref_dir = data_dir.path().join("content").join("refs").join(layer2_digest.hex());
        std::fs::create_dir_all(poisoned_ref_dir.parent().unwrap()).unwrap();
        std::fs::write(&poisoned_ref_dir, b"not a directory").unwrap();

        let reference = reference::parse("rollback-a-test:latest").unwrap();
        let canonical = canonical_ref_string(&reference);
        let chain_ids = vec!["sha256:rollbackchain1".to_string(), "sha256:rollbackchain2".to_string()];

        let result = record_pulled_image(data_dir.path(), &store, &canonical, &manifest_digest, &manifest_bytes, &chain_ids);
        assert!(result.is_err(), "record_pulled_image must fail when a later add_ref fails: {result:?}");

        // THE assertion this test exists for: every ref added BEFORE the
        // failure point must have been rolled back — zero refs
        // attributable to this call survive.
        assert!(!store.is_referenced(&manifest_digest), "manifest ref must have been rolled back");
        assert!(!store.is_referenced(&config_digest), "config ref must have been rolled back");
        assert!(!store.is_referenced(&layer1_digest), "layer1 ref must have been rolled back");
        assert!(!store.is_referenced(&layer2_digest), "layer2 was never successfully ref'd in the first place");

        // AND no `named-images.json` entry must exist for this reference
        // either — this call never got anywhere near that step.
        let images = read_named_images(data_dir.path()).unwrap();
        assert!(!images.contains_key(&canonical), "named-images.json must have no entry for a failed record_pulled_image call: {images:?}");
    }

    /// Bug 1, failure mode B: every `add_ref` call genuinely succeeds, but
    /// the TRAILING `write_named_images` step itself fails — forced by
    /// pre-occupying `named-images.json`'s own path with a directory, so
    /// `write_named_images`'s final `fs::rename(tmp, path)` fails (a file
    /// can't be renamed onto an existing directory). Before the fix, this
    /// was the worst-case leak: ALL of the manifest/config/layer1/layer2
    /// refs would have been left behind with literally no record of the
    /// pull having ever been attempted.
    #[tokio::test]
    async fn test_record_pulled_image_rolls_back_refs_when_write_named_images_fails() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let (manifest_digest, manifest_bytes, config_digest, layer1_digest, layer2_digest) =
            write_synthetic_manifest_fixture(&store);

        // Sabotage: occupy `named-images.json`'s own path with a
        // directory, so `write_named_images`'s final rename-into-place
        // fails.
        std::fs::create_dir_all(named_images_path(data_dir.path())).unwrap();

        let reference = reference::parse("rollback-b-test:latest").unwrap();
        let canonical = canonical_ref_string(&reference);
        let chain_ids = vec!["sha256:rollbackchain1".to_string(), "sha256:rollbackchain2".to_string()];

        let result = record_pulled_image(data_dir.path(), &store, &canonical, &manifest_digest, &manifest_bytes, &chain_ids);
        assert!(result.is_err(), "record_pulled_image must fail when write_named_images fails: {result:?}");

        // THE assertion this test exists for: ALL refs (every add_ref
        // genuinely succeeded before the write step failed) must have
        // been rolled back — none left dangling just because the JSON
        // write, not a ref call, was what actually failed.
        assert!(!store.is_referenced(&manifest_digest), "manifest ref must have been rolled back");
        assert!(!store.is_referenced(&config_digest), "config ref must have been rolled back");
        assert!(!store.is_referenced(&layer1_digest), "layer1 ref must have been rolled back");
        assert!(!store.is_referenced(&layer2_digest), "layer2 ref must have been rolled back");
    }

    /// Bug 2: one corrupted/stale `named-images.json` entry (here: a
    /// well-formed digest string that simply doesn't correspond to any
    /// real blob in `ContentStore` — e.g. the manifest blob it once
    /// pointed to has since been garbage-collected out from under a stale
    /// bookkeeping entry) must not turn `GET /images`/`GET /images/dedup`
    /// into a `500` for every other, perfectly good entry. Plants one good
    /// entry (a real, on-disk manifest+blobs, exactly like the synthetic
    /// fixture above) alongside one bad entry, and asserts both endpoints
    /// still return `200` and reflect ONLY the good entry.
    #[tokio::test]
    async fn test_list_and_dedup_skip_a_corrupted_named_images_entry_instead_of_failing_entirely() {
        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let layer_store = LayerStore::new(data_dir.path().to_path_buf());

        // ---- one GOOD entry: real manifest/config/layer blobs on disk,
        // real extracted chain-id content, properly ref'd. ----
        let layer_bytes = b"good-entry-layer-bytes".to_vec();
        let layer_digest = store.write_blob(None, Cursor::new(&layer_bytes)).unwrap();
        let config_digest = store.write_blob(None, Cursor::new(b"{}")).unwrap();
        let manifest_value = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest.to_string(), "size": 2 },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest.to_string(),
                "size": layer_bytes.len(),
            }],
        });
        let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
        let manifest_digest = store.write_blob(None, Cursor::new(&manifest_bytes)).unwrap();
        let good_chain_id = "sha256:goodentrychain".to_string();
        std::fs::create_dir_all(layer_store.diff_dir(&good_chain_id)).unwrap();
        std::fs::write(layer_store.diff_dir(&good_chain_id).join("f"), b"1234567890").unwrap(); // 10 bytes

        let good_reference = reference::parse("good-entry:latest").unwrap();
        let good_canonical = canonical_ref_string(&good_reference);
        let good_owner = sanitize_owner_id(&good_canonical);
        store.add_ref(&manifest_digest, &good_owner).unwrap();
        store.add_ref(&config_digest, &good_owner).unwrap();
        store.add_ref(&layer_digest, &good_owner).unwrap();

        // ---- one BAD entry: a well-formed digest that has no
        // corresponding blob anywhere in the content store (simulating a
        // stale/corrupted bookkeeping entry left over after, e.g., an
        // out-of-band blob loss). ----
        let bad_reference = reference::parse("bad-entry:latest").unwrap();
        let bad_canonical = canonical_ref_string(&bad_reference);
        let nonexistent_digest = format!("sha256:{}", "f".repeat(64));

        let mut images: NamedImages = HashMap::new();
        images.insert(good_canonical.clone(), NamedImage { manifest_digest: manifest_digest.to_string(), chain_ids: vec![good_chain_id] });
        images.insert(bad_canonical.clone(), NamedImage { manifest_digest: nonexistent_digest, chain_ids: vec!["sha256:nosuchchain".to_string()] });
        write_named_images(data_dir.path(), &images).unwrap();

        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let app = crate::build_router(state);

        // ---- GET /images: 200, only the good entry listed ----
        let (status, body) = get_json(app.clone(), "/images").await;
        assert_eq!(status, StatusCode::OK, "a corrupted entry must not turn this into a 500: {body}");
        let images_arr = body["images"].as_array().unwrap();
        assert_eq!(images_arr.len(), 1, "only the good entry should be listed: {body}");
        assert_eq!(images_arr[0]["reference"], good_canonical);

        // ---- GET /images/dedup: 200, aggregate reflects only the good
        // entry (1 image, 3 unique blobs: manifest+config+layer, 10
        // logical bytes from the one real extracted chain-id dir). ----
        let (status, body) = get_json(app.clone(), "/images/dedup").await;
        assert_eq!(status, StatusCode::OK, "a corrupted entry must not turn this into a 500 either: {body}");
        assert_eq!(body["images"], 1, "the aggregate image count must reflect only the resolvable entry: {body}");
        assert_eq!(body["unique_blobs"], 3, "the bad entry's phantom digest must not be counted: {body}");
        assert_eq!(body["logical_bytes"], 10, "only the good entry's real extracted content should be summed: {body}");

        // ---- the good entry's own individual lookup is completely
        // unaffected by its bad sibling ----
        let (status, body) = get_json(app, "/images/good-entry:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["manifest_digest"], manifest_digest.to_string());
    }

    // -----------------------------------------------------------------
    // Real-network test (Task 20 Step 6) — mirrors kestrel-image/tests/
    // pull_e2e.rs's own `KESTREL_TEST_NETWORK=1` gating EXACTLY, but
    // WITHOUT that test's additional `#[ignore = "requires root"]`
    // reasoning: `pull_image_with_client` itself needs no root privilege
    // at all (confirmed by kestrel-image/tests/pull.rs's own several
    // wiremock-backed pull tests, none of which are `#[ignore]`d — the
    // ONLY root-requiring parts of `pull_e2e.rs` are its OWN later mount/
    // pivot_root/exec steps, which this endpoint never performs; `POST
    // /images/pull` -> extraction only ever calls `apply_layer(...,
    // rootless=false)`, exactly like `bundle.rs`'s own already-unprivileged
    // production pull path). `#[ignore]` is still applied here (for the
    // same reason `pull_e2e.rs` documents at length: `make test-root`'s
    // own `--ignored` sweep would otherwise start making real HTTPS calls
    // to Docker Hub on every root-gated test run) — just with an accurate
    // reason string, and gated by the SAME env var, checked the SAME way.
    // -----------------------------------------------------------------

    /// Reads SSE `data: <json>` frames from `body` until a `"type":
    /// "Complete"` or `"type":"Error"` event is seen (or `timeout`
    /// elapses), returning every parsed event in arrival order.
    async fn collect_pull_progress(mut body: Body, timeout: std::time::Duration) -> Vec<serde_json::Value> {
        let mut collected = Vec::new();
        let mut acc = String::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for pull to reach a terminal SSE event; collected so far: {collected:?}");
            }
            let frame = tokio::time::timeout(remaining, body.frame())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for next SSE frame; collected so far: {collected:?}"))
                .expect("SSE body stream ended unexpectedly")
                .expect("reading SSE frame");
            if let Some(data) = frame.data_ref() {
                acc.push_str(&String::from_utf8_lossy(data));
            }
            while let Some(idx) = acc.find("\n\n") {
                let chunk: String = acc.drain(..idx + 2).collect();
                for line in chunk.lines() {
                    let Some(json_str) = line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")) else {
                        continue;
                    };
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str.trim()) else { continue };
                    let is_terminal = v["type"] == "Complete" || v["type"] == "Error";
                    collected.push(v);
                    if is_terminal {
                        return collected;
                    }
                }
            }
        }
    }

    /// The real Task 20 Step 6 test: pulls a real, small public image
    /// (`alpine:latest`, matching `pull_e2e.rs`'s own choice) through the
    /// real HTTP router's `POST /images/pull`, confirms the SSE progress
    /// events arrive in a sane order (starts with `ManifestFetched`, ends
    /// with `Complete`, at least one real layer event in between), then
    /// confirms `GET /images` lists it, `GET /images/:ref` and `.../layers`
    /// return real data, and `DELETE` removes it with `is_referenced`
    /// correctly reflecting zero refs afterward.
    #[tokio::test]
    #[ignore = "requires real network access to Docker Hub — set KESTREL_TEST_NETWORK=1 to run \
                (see kestrel-image/tests/pull_e2e.rs's own header comment for why #[ignore] alone \
                doesn't keep a test out of `make test-root`'s own `--ignored` sweep, and why this \
                test needs the SAME extra env-var gate even though — unlike that test — it needs no root)"]
    async fn test_pull_then_list_then_get_then_delete_real_alpine_image() {
        if std::env::var_os("KESTREL_TEST_NETWORK").is_none() {
            eprintln!(
                "skipping test_pull_then_list_then_get_then_delete_real_alpine_image: set \
                 KESTREL_TEST_NETWORK=1 to actually run it (this test makes real HTTPS calls to \
                 Docker Hub)"
            );
            return;
        }

        let data_dir = tempfile::tempdir().unwrap();
        let run_dir = tempfile::tempdir().unwrap();
        let state = test_app_state(data_dir.path().to_path_buf(), run_dir.path().to_path_buf());
        let event_bus = state.event_bus.clone();
        let mut event_sub = event_bus.subscribe();
        let app = crate::build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/images/pull")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&serde_json::json!({ "reference": "alpine:latest" })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(request).await.expect("POST /images/pull oneshot");
        assert_eq!(response.status(), StatusCode::OK, "POST /images/pull must return 200 (an SSE stream)");

        let events = collect_pull_progress(response.into_body(), std::time::Duration::from_secs(180)).await;
        assert!(events.len() >= 2, "expected at least a ManifestFetched and a terminal event, got: {events:?}");
        assert_eq!(events.first().unwrap()["type"], "ManifestFetched", "first SSE event should be ManifestFetched: {events:?}");
        let last = events.last().unwrap();
        assert_eq!(last["type"], "Complete", "pull must complete successfully: {events:?}");
        let chain_ids: Vec<String> =
            last["chain_ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(!chain_ids.is_empty(), "Complete event must carry real chain-ids");

        // ---- the real dual-publish: an `image.pull.done` event must ALSO
        // have landed on the event bus for this same pull, independent of
        // (and concurrently with) the SSE stream above. ----
        let bus_event = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match event_sub.recv().await {
                    Ok(Event::ImagePullDone { reference }) if reference == "alpine:latest" => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(bus_event, "expected an Event::ImagePullDone{{reference: \"alpine:latest\"}} on the event bus");

        // ---- GET /images lists it ----
        let (status, body) = get_json(app.clone(), "/images").await;
        assert_eq!(status, StatusCode::OK);
        let images_arr = body["images"].as_array().unwrap();
        let entry = images_arr
            .iter()
            .find(|v| v["reference"] == "docker.io/library/alpine:latest")
            .unwrap_or_else(|| panic!("pulled alpine:latest not found in GET /images: {body}"));
        assert!(entry["layer_count"].as_u64().unwrap() >= 1);
        let manifest_digest = entry["manifest_digest"].as_str().unwrap().to_string();

        // ---- GET /images/:ref, GET /images/:ref/layers: real data ----
        let (status, body) = get_json(app.clone(), "/images/alpine:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["manifest_digest"], manifest_digest);
        assert_eq!(body["layers"].as_array().unwrap().len(), chain_ids.len());

        let (status, body) = get_json(app.clone(), "/images/alpine:latest/layers").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["layers"].as_array().unwrap().len(), chain_ids.len());

        // ---- real is_referenced check before delete ----
        let store = ContentStore::new(data_dir.path().to_path_buf());
        let digest: Digest = manifest_digest.parse().unwrap();
        assert!(store.is_referenced(&digest), "freshly pulled manifest must be referenced");

        // ---- DELETE removes it; is_referenced correctly reflects zero refs ----
        let (status, body) = delete_json(app.clone(), "/images/alpine:latest").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(!body["blobs_removed"].as_array().unwrap().is_empty());
        assert!(!store.is_referenced(&digest), "manifest must be unreferenced after DELETE");

        let (status, _) = get_json(app, "/images/alpine:latest").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "deleted image must 404 afterward");
    }
}
