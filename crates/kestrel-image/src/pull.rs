//! Pull orchestration: resolve a manifest (or index), download layers with
//! bounded concurrency, decompress each while computing its diffID, then
//! walk the layers sequentially to build the chain-id sequence and extract
//! whatever isn't already present.
//!
//! # Two-phase design
//!
//! Downloading+hashing a layer is purely a function of that layer's own
//! compressed bytes — it does not depend on any other layer, so it's safe
//! (and worth it, over a real network) to run several of these concurrently.
//! Computing a layer's chain-id, by contrast, depends on the *previous*
//! layer's chain-id (see `kestrel_rootfs::snapshot::chain_id`), so that part
//! must stay strictly sequential. This module therefore splits the work:
//!
//! - **Phase A** (`download_and_hash_one`, driven via `buffer_unordered`):
//!   concurrently download each layer blob (deduped against the content
//!   store by digest) and decompress+hash it to get its diffID. Bounded to
//!   `DEFAULT_MAX_CONCURRENT_LAYERS` in flight at once. Results are written
//!   into a `Vec<Option<LayerDownload>>` indexed by the layer's original
//!   manifest position, since Phase B needs them back in order.
//! - **Phase B** (sequential): walk layers in original order, chaining
//!   chain-ids, skipping extraction (dedup) for layers whose diff directory
//!   is already fully populated, and extracting the rest.
//!
//! `LayerStart` events are emitted for all layers up front, before Phase A
//! begins, rather than exactly when each concurrent download starts: since
//! Phase A's per-layer futures run concurrently (not as separate spawned
//! tasks, but interleaved on the same task via `buffer_unordered`), there is
//! no single point that "owns" a unique `&mut` borrow of `on_progress` at
//! the moment each individual download kicks off without adding a channel
//! or `RefCell` layer of indirection. `LayerDownloaded` events, in contrast,
//! ARE emitted exactly as each Phase A future genuinely completes (via the
//! `while let Some(..) = downloads.next().await` loop below), so they can
//! and do arrive out of original layer order — that's the real concurrency
//! showing through, and is expected.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::stream::{self, StreamExt};
use kestrel_oci::image_spec::{ImageIndex, ImageManifest};
use kestrel_rootfs::snapshot::{chain_id, LayerStore};
use tokio::task::spawn_blocking;

use crate::apply::apply_layer;
use crate::digest::Digest;
use crate::manifest::{docker_platform_arch, is_index_media_type, select_platform};
use crate::reference::ImageReference;
use crate::registry::RegistryClient;
use crate::store::ContentStore;

#[derive(Debug, Clone)]
pub enum PullProgress {
    ManifestFetched { digest: Digest },
    LayerStart { digest: Digest, index: usize, total: usize },
    LayerDeduped { digest: Digest },
    LayerDownloaded { digest: Digest, bytes: u64 },
    LayerExtracted { digest: Digest, chain_id: String },
    Complete { chain_ids: Vec<String> },
}

/// Bound on how many layer blobs are downloaded+decompressed+hashed at
/// once in Phase A. CHECKLIST.md's "bounded-parallel layer download
/// (default 4)" requirement.
const DEFAULT_MAX_CONCURRENT_LAYERS: usize = 4;

/// Disambiguates concurrent staging paths (both `extract_layer`'s staging
/// directories AND `download_and_hash_one`'s staging blob files — they
/// share this one counter, not one each, since nothing requires them to be
/// numbered independently) the same way `store.rs`'s `TMP_COUNTER`
/// disambiguates concurrent blob temp files: the pid handles cross-process
/// collisions, this counter handles same-process ones (e.g. several Phase A
/// downloads genuinely racing via `buffer_unordered`, or two layers in
/// Phase B racing — which can't actually happen since Phase B is sequential
/// today, but costs nothing to make robust against a future change, and
/// mirrors the existing convention).
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Per-layer metadata read off the manifest, before any network I/O.
struct LayerMeta {
    /// The layer blob's digest as declared in the manifest — i.e. the
    /// digest of the (possibly compressed) bytes as transmitted, NOT the
    /// diffID. Used as this layer's stable identity across all
    /// `PullProgress` events.
    digest: Digest,
    media_type: String,
    size: u64,
}

/// Phase A's output for one layer.
struct LayerDownload {
    digest: Digest,
    diff_id: String,
    tar_path: PathBuf,
    size: u64,
}

/// Entry point used by real callers: builds its own `RegistryClient` and
/// pulls `reference` into `store`/`layer_store`, returning the bottom-to-top
/// chain-id sequence for `reference`'s layers.
pub async fn pull_image(
    reference: &ImageReference,
    store: &ContentStore,
    layer_store: &LayerStore,
    rootless: bool,
    on_progress: impl FnMut(PullProgress) + Send,
) -> Result<Vec<String>> {
    let client = Arc::new(RegistryClient::new()?);
    pull_image_with_client(client, reference, store, layer_store, rootless, on_progress).await
}

/// Same as `pull_image`, but takes an already-constructed `RegistryClient`
/// (wrapped in `Arc` so it can be cloned into each of Phase A's concurrent
/// download tasks — see `RegistryClient`'s own doc comment on why `&self`
/// plus an internal `RwLock` makes this safe without a client-wide `Mutex`
/// serializing everything). This is the hook this crate's own tests use to
/// point at a `wiremock` server via `RegistryClient::with_base_url`,
/// mirroring how `registry.rs`'s tests inject a base URL.
pub async fn pull_image_with_client(
    client: Arc<RegistryClient>,
    reference: &ImageReference,
    store: &ContentStore,
    layer_store: &LayerStore,
    rootless: bool,
    mut on_progress: impl FnMut(PullProgress) + Send,
) -> Result<Vec<String>> {
    let (manifest_bytes, manifest_digest, media_type) =
        client.fetch_manifest_bytes(reference).await.context("fetching manifest")?;
    on_progress(PullProgress::ManifestFetched { digest: manifest_digest });

    // Resolve a multi-platform index down to this platform's manifest if
    // necessary. `manifest_bytes`/`manifest` end up holding whichever bytes
    // were actually parsed into `manifest` — the per-platform manifest in
    // the index case, not the index itself — so the content store ends up
    // holding the manifest that corresponds to what was actually pulled.
    let (manifest_bytes, manifest): (Vec<u8>, ImageManifest) = if is_index_media_type(&media_type) {
        let index: ImageIndex = serde_json::from_slice(&manifest_bytes).context("parsing manifest as an index")?;
        let selected = select_platform(&index, "linux", docker_platform_arch(std::env::consts::ARCH), None)?;
        let selected_digest: Digest =
            selected.digest().to_string().parse().context("parsing selected manifest's digest")?;
        let (bytes, resolved_digest, _selected_media_type) = client
            .fetch_manifest_bytes(&ImageReference { digest: Some(selected_digest.clone()), ..reference.clone() })
            .await
            .context("fetching selected platform manifest")?;
        anyhow::ensure!(
            resolved_digest == selected_digest,
            "selected platform manifest digest mismatch: index said {selected_digest}, fetched bytes hash to {resolved_digest}"
        );
        let manifest: ImageManifest = serde_json::from_slice(&bytes).context("parsing selected platform manifest")?;
        (bytes, manifest)
    } else {
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes).context("parsing manifest")?;
        (manifest_bytes, manifest)
    };
    store.write_blob(None, std::io::Cursor::new(&manifest_bytes)).context("writing manifest blob to content store")?;

    let layer_meta: Vec<LayerMeta> = manifest
        .layers()
        .iter()
        .enumerate()
        .map(|(index, d)| {
            let digest: Digest =
                d.digest().to_string().parse().with_context(|| format!("parsing layer {index} digest"))?;
            Ok(LayerMeta { digest, media_type: d.media_type().to_string(), size: d.size() })
        })
        .collect::<Result<Vec<_>>>()?;
    let total = layer_meta.len();

    // --- Phase A: bounded-parallel download + decompress/hash ---
    // See this module's doc comment for why LayerStart is emitted up front
    // rather than exactly at each concurrent task's start.
    for (index, meta) in layer_meta.iter().enumerate() {
        on_progress(PullProgress::LayerStart { digest: meta.digest.clone(), index, total });
    }

    let mut phase_a_results: Vec<Option<LayerDownload>> = (0..total).map(|_| None).collect();
    {
        let mut downloads = stream::iter(layer_meta.iter().enumerate())
            .map(|(index, meta)| {
                let client = Arc::clone(&client);
                async move { download_and_hash_one(client, reference, store, index, meta).await }
            })
            .buffer_unordered(DEFAULT_MAX_CONCURRENT_LAYERS);

        while let Some(result) = downloads.next().await {
            let (index, dl) = result?;
            on_progress(PullProgress::LayerDownloaded { digest: dl.digest.clone(), bytes: dl.size });
            phase_a_results[index] = Some(dl);
        }
    }

    // --- Phase B: sequential chain-id bookkeeping + extraction ---
    let mut chain_ids: Vec<String> = Vec::with_capacity(total);
    let mut parent: Option<String> = None;
    for slot in phase_a_results.iter_mut() {
        let dl = slot.take().expect("Phase A must populate every index before Phase B reads it");
        let cid = chain_id(parent.as_deref(), &dl.diff_id);
        let diff_dir = layer_store.diff_dir(&cid);

        if dir_has_entries(&diff_dir) {
            on_progress(PullProgress::LayerDeduped { digest: dl.digest.clone() });
        } else {
            extract_layer(layer_store, &cid, &diff_dir, &dl.tar_path, rootless).await?;
            on_progress(PullProgress::LayerExtracted { digest: dl.digest.clone(), chain_id: cid.clone() });
        }

        // Idempotent bookkeeping (parent file + link-farm symlink) — cheap,
        // self-heals a missing symlink even on the dedup path, and never
        // disturbs `diff/`'s contents since `diff/` already exists by this
        // point either way.
        layer_store.ensure_layer(&cid, parent.as_deref())?;

        chain_ids.push(cid.clone());
        parent = Some(cid);
    }

    on_progress(PullProgress::Complete { chain_ids: chain_ids.clone() });
    Ok(chain_ids)
}

/// Downloads (if not already content-addressed in `store`) and
/// decompresses+hashes one layer. Independent of every other layer's
/// result — the property that makes running several of these concurrently
/// via `buffer_unordered` safe.
///
/// Downloads into a staging path first, NOT directly into
/// `store.blob_path(&meta.digest)` (the blob's final content-addressed
/// path) — the same idiom `extract_layer` uses for `diff_dir`, and for the
/// same reason. Phase A runs up to `DEFAULT_MAX_CONCURRENT_LAYERS` of these
/// futures concurrently via `buffer_unordered`, and `pull_image_with_client`
/// aborts the whole stream (via `result?`) the moment ANY one of them
/// returns an error — which drops every other still-in-flight download
/// future. If those futures were streaming straight into their blob's
/// final path, a drop mid-write would leave a truncated file sitting under
/// a name `ContentStore::has_blob` (a bare `is_file()` check) treats as a
/// complete, valid blob — silently corrupting the store. Downloading to a
/// staging path and only renaming into place AFTER `download_blob_verified`
/// returns `Ok` (i.e. after the digest has been fully verified) means a
/// cancelled download's partial bytes never become visible at
/// `store.blob_path(...)`: execution simply never reaches the rename.
async fn download_and_hash_one(
    client: Arc<RegistryClient>,
    reference: &ImageReference,
    store: &ContentStore,
    index: usize,
    meta: &LayerMeta,
) -> Result<(usize, LayerDownload)> {
    let blob_path = store.blob_path(&meta.digest);
    if !store.has_blob(&meta.digest) {
        if let Some(parent) = blob_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let unique = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staging_path =
            blob_path.with_file_name(format!(".staging-blob-{}-{}-{}", std::process::id(), unique, meta.digest.hex()));

        let download_result = client
            .download_blob_verified(reference, &meta.digest, &staging_path, None)
            .await
            .with_context(|| format!("downloading layer {index} ({})", meta.digest));

        if let Err(e) = download_result {
            let _ = fs::remove_file(&staging_path);
            return Err(e);
        }

        // Only now that the download has fully streamed and its digest has
        // been verified does the blob become visible at its final,
        // content-addressed path.
        fs::rename(&staging_path, &blob_path).with_context(|| {
            format!("renaming downloaded blob into place: {} -> {}", staging_path.display(), blob_path.display())
        })?;
    }

    let media_type = meta.media_type.clone();
    let blob_path_for_blocking = blob_path.clone();
    let (diff_id, tar_path) =
        spawn_blocking(move || decompress_and_hash(&blob_path_for_blocking, &media_type))
            .await
            .context("decompress-and-hash task panicked")??;

    Ok((index, LayerDownload { digest: meta.digest.clone(), diff_id, tar_path, size: meta.size }))
}

/// Extracts `tar_path` into a fresh staging directory sibling to `diff_dir`
/// and, only on success, atomically renames it into place as `diff_dir`.
///
/// This is the fix for `apply_layer`'s documented "no partial-application
/// marker" gap (see its doc comment in `apply.rs`, which explicitly flags
/// this as belonging to "Phase 6's content-store work"): extracting
/// directly into `diff_dir` (what a plain `LayerStore::ensure_layer` +
/// `apply_layer` call would do) means a mid-extraction failure leaves
/// `diff_dir` non-empty but incomplete, indistinguishable from a fully
/// applied layer by the `dir_has_entries` dedup check above it. By only
/// ever populating `diff_dir` via a single atomic rename-on-success (never
/// writing into it directly), `diff_dir`'s mere existence-with-contents
/// becomes a trustworthy "fully extracted" signal: it can never be caught
/// mid-write.
async fn extract_layer(
    layer_store: &LayerStore,
    cid: &str,
    diff_dir: &std::path::Path,
    tar_path: &std::path::Path,
    rootless: bool,
) -> Result<()> {
    let layer_dir = layer_store.layer_dir(cid);
    fs::create_dir_all(&layer_dir).with_context(|| format!("creating {}", layer_dir.display()))?;

    let unique = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging = layer_dir.join(format!(".staging-diff-{}-{}", std::process::id(), unique));
    fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;

    let tar_path_owned = tar_path.to_path_buf();
    let staging_for_blocking = staging.clone();
    let apply_result = spawn_blocking(move || -> Result<()> {
        let tar_file = fs::File::open(&tar_path_owned).with_context(|| format!("opening {}", tar_path_owned.display()))?;
        apply_layer(tar_file, &staging_for_blocking, rootless).map(|_stats| ())
    })
    .await
    .context("layer extraction task panicked")?;

    if let Err(e) = apply_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(e).with_context(|| format!("extracting layer into {}", staging.display()));
    }

    fs::rename(&staging, diff_dir)
        .with_context(|| format!("renaming {} to {}", staging.display(), diff_dir.display()))?;
    Ok(())
}

fn dir_has_entries(dir: &std::path::Path) -> bool {
    fs::read_dir(dir).map(|mut entries| entries.next().is_some()).unwrap_or(false)
}

/// The compression scheme implied by a layer's declared media type, per an
/// exact match against the known OCI and Docker-schema2 layer media type
/// strings — never a substring/`.contains()` guess. `oci_spec::image::
/// MediaType`'s own `impl From<&str>` (see the vendored source under
/// `~/.cargo/registry/src/.../oci-spec-0.10.0/src/image/mod.rs`) enumerates
/// the OCI ones exactly as matched below; the Docker-schema2 ones aren't in
/// that crate's enum at all (they'd fall through to its catch-all
/// `MediaType::Other`), so there's no single typed enum that covers this
/// function's full known set — hence matching directly on the media type
/// string here rather than threading a typed enum through the pipeline for
/// this. (Docker schema2 has no defined *uncompressed* layer media type to
/// confirm, so none is listed below — only the real, spec-documented gzip
/// ones.)
enum LayerCompression {
    Gzip,
    Zstd,
    None,
}

fn classify_layer_media_type(media_type: &str) -> Result<LayerCompression> {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip" => Ok(LayerCompression::Gzip),
        "application/vnd.oci.image.layer.v1.tar+zstd" | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd" => {
            Ok(LayerCompression::Zstd)
        }
        "application/vnd.oci.image.layer.v1.tar" | "application/vnd.oci.image.layer.nondistributable.v1.tar" => {
            Ok(LayerCompression::None)
        }
        other => anyhow::bail!("unsupported layer media type: {other}"),
    }
}

/// Decompresses `blob_path` (per `media_type`) into a sibling `.tar` file
/// while simultaneously hashing the decompressed bytes to get the layer's
/// diffID — one pass, not decompress-then-separately-hash.
fn decompress_and_hash(blob_path: &std::path::Path, media_type: &str) -> Result<(String, PathBuf)> {
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;

    let compression = classify_layer_media_type(media_type)?;

    let compressed = std::fs::File::open(blob_path).with_context(|| format!("opening {}", blob_path.display()))?;
    let out_path = blob_path.with_extension("tar");
    let out_file = std::fs::File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?;
    let mut writer = std::io::BufWriter::new(out_file);
    let mut hasher = Sha256::new();

    match compression {
        LayerCompression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(compressed);
            std::io::copy(&mut decoder, &mut TeeWriter { inner: &mut writer, hasher: &mut hasher })
                .context("decompressing gzip layer")?;
        }
        LayerCompression::Zstd => {
            let mut decoder = zstd::stream::Decoder::new(compressed).context("creating zstd decoder")?;
            std::io::copy(&mut decoder, &mut TeeWriter { inner: &mut writer, hasher: &mut hasher })
                .context("decompressing zstd layer")?;
        }
        LayerCompression::None => {
            let mut r = compressed;
            std::io::copy(&mut r, &mut TeeWriter { inner: &mut writer, hasher: &mut hasher })
                .context("copying uncompressed layer")?;
        }
    }
    writer.flush().context("flushing decompressed layer")?;

    let diff_id = format!("sha256:{:x}", hasher.finalize());
    Ok((diff_id, out_path))
}

/// A write-side tee: bytes written through `TeeWriter` land in `inner`
/// while simultaneously being fed into `hasher`, so decompression and
/// hashing happen in the same pass instead of two — the write-side
/// counterpart to `digest.rs`'s `VerifyingReader` (read-side tee).
struct TeeWriter<'a, W> {
    inner: W,
    hasher: &'a mut sha2::Sha256,
}

impl<'a, W: std::io::Write> std::io::Write for TeeWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest as _;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
