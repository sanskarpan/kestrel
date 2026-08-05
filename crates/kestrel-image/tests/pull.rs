use std::io::Write as _;
use std::time::{Duration, Instant};

use flate2::write::GzEncoder;
use flate2::Compression;
use kestrel_image::digest::Digest;
use kestrel_image::pull::{pull_image_with_client, PullProgress};
use kestrel_image::reference;
use kestrel_image::registry::RegistryClient;
use kestrel_image::store::ContentStore;
use kestrel_image::test_util::build_tar;
use kestrel_rootfs::snapshot::{chain_id, LayerStore};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A minimal, valid OCI image manifest referencing `layers`
/// (digest, size, media_type triples) plus a placeholder config descriptor
/// — `pull_image_with_client` never fetches the config blob, so it doesn't
/// need to resolve to anything real.
fn manifest_json(layers: &[(String, usize, &str)]) -> Vec<u8> {
    let layers: Vec<_> = layers
        .iter()
        .map(|(digest, size, media_type)| {
            serde_json::json!({ "mediaType": media_type, "digest": digest, "size": size })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{}", "0".repeat(64)),
            "size": 2
        },
        "layers": layers
    }))
    .unwrap()
}

async fn mount_manifest(server: &MockServer, repo_path: &str, tag: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/v2/{repo_path}/manifests/{tag}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json"),
        )
        .mount(server)
        .await;
}

async fn mount_blob(server: &MockServer, repo_path: &str, digest: &str, body: Vec<u8>, delay: Option<Duration>) {
    let mut template = ResponseTemplate::new(200).set_body_bytes(body);
    if let Some(d) = delay {
        template = template.set_delay(d);
    }
    Mock::given(method("GET"))
        .and(path(format!("/v2/{repo_path}/blobs/{digest}")))
        .respond_with(template)
        .mount(server)
        .await;
}

async fn mount_blob_404(server: &MockServer, repo_path: &str, digest: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v2/{repo_path}/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

const GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Test 1: a full pull against a mock registry serving a hand-built
/// single-layer manifest + config + gzip-compressed layer tarball.
#[tokio::test]
async fn test_pull_image_single_layer_chain_id_and_contents_match() {
    let server = MockServer::start().await;
    let repo_path = "myrepo/myimage";

    let tar_bytes = build_tar(&[("file.txt", b"hello")]);
    let compressed = gzip(&tar_bytes);
    let layer_digest = Digest::of_bytes(&compressed).to_string();

    mount_manifest(
        &server,
        repo_path,
        "latest",
        manifest_json(&[(layer_digest.clone(), compressed.len(), GZIP_MEDIA_TYPE)]),
    )
    .await;
    mount_blob(&server, repo_path, &layer_digest, compressed, None).await;

    let tmp = tempfile::tempdir().unwrap();
    let store = ContentStore::new(tmp.path().to_path_buf());
    let layer_store = LayerStore::new(tmp.path().to_path_buf());
    let client = Arc::new(RegistryClient::with_base_url(server.uri()).unwrap());
    let reference = reference::parse("myrepo/myimage:latest").unwrap();

    let mut events = Vec::new();
    let chain_ids = pull_image_with_client(client, &reference, &store, &layer_store, false, |e| events.push(e))
        .await
        .unwrap();

    // Independently computed expected chain-id: chain_id(None, diffID),
    // where diffID is the SHA-256 of the UNCOMPRESSED tar bytes (not the
    // gzip-compressed blob digest used to address the blob in the content
    // store — those are deliberately different digests of different byte
    // sequences).
    let expected_diff_id = Digest::of_bytes(&tar_bytes).to_string();
    let expected_chain_id = chain_id(None, &expected_diff_id);
    assert_eq!(chain_ids, vec![expected_chain_id.clone()]);

    let diff_dir = layer_store.diff_dir(&expected_chain_id);
    assert_eq!(std::fs::read(diff_dir.join("file.txt")).unwrap(), b"hello");

    // Progress events in a sensible order.
    assert!(matches!(events.first(), Some(PullProgress::ManifestFetched { .. })), "{events:?}");
    assert!(matches!(events.last(), Some(PullProgress::Complete { .. })), "{events:?}");
    let idx = |pred: &dyn Fn(&PullProgress) -> bool| events.iter().position(pred);
    let start = idx(&|e| matches!(e, PullProgress::LayerStart { .. })).expect("LayerStart missing");
    let downloaded = idx(&|e| matches!(e, PullProgress::LayerDownloaded { .. })).expect("LayerDownloaded missing");
    let extracted = idx(&|e| matches!(e, PullProgress::LayerExtracted { .. })).expect("LayerExtracted missing");
    assert!(start < downloaded, "LayerStart must precede LayerDownloaded: {events:?}");
    assert!(downloaded < extracted, "LayerDownloaded must precede LayerExtracted: {events:?}");
}

/// Test 2: the SAME base layer referenced from two different pulls (here,
/// two tags of the same repo, but what matters is that both manifests
/// reference a layer with identical content, hence identical diffID and
/// chain-id) must only be extracted once.
///
/// Proof strategy: `extract_layer` in `pull.rs` only ever populates a
/// layer's `diff/` directory via a whole-directory atomic rename from a
/// staging directory (never by writing into `diff/` directly) — see its
/// doc comment. That means if extraction were mistakenly re-run for an
/// already-extracted layer, the rename would REPLACE `diff/` wholesale,
/// discarding anything not present in the freshly-extracted staging dir.
/// So: write a sentinel file into `diff/` after the first pull (a file
/// that is deliberately NOT part of the layer's tar contents) and assert
/// it survives the second pull. A survives-or-not signal tied directly to
/// the actual dedup mechanism is more robust than e.g. asserting on
/// mtimes, which can be flaky at typical filesystem timestamp resolution.
#[tokio::test]
async fn test_pull_image_dedup_skips_reextraction_of_shared_layer() {
    let server = MockServer::start().await;
    let repo_path = "myrepo/myimage";

    let tar_bytes = build_tar(&[("shared.txt", b"shared layer contents")]);
    let compressed = gzip(&tar_bytes);
    let layer_digest = Digest::of_bytes(&compressed).to_string();

    let body = manifest_json(&[(layer_digest.clone(), compressed.len(), GZIP_MEDIA_TYPE)]);
    mount_manifest(&server, repo_path, "v1", body.clone()).await;
    mount_manifest(&server, repo_path, "v2", body).await;
    mount_blob(&server, repo_path, &layer_digest, compressed, None).await;

    let tmp = tempfile::tempdir().unwrap();
    let store = ContentStore::new(tmp.path().to_path_buf());
    let layer_store = LayerStore::new(tmp.path().to_path_buf());

    let expected_diff_id = Digest::of_bytes(&tar_bytes).to_string();
    let expected_chain_id = chain_id(None, &expected_diff_id);
    let diff_dir = layer_store.diff_dir(&expected_chain_id);

    // First pull: v1.
    let client1 = Arc::new(RegistryClient::with_base_url(server.uri()).unwrap());
    let reference1 = reference::parse("myrepo/myimage:v1").unwrap();
    let mut events1 = Vec::new();
    pull_image_with_client(client1, &reference1, &store, &layer_store, false, |e| events1.push(e))
        .await
        .unwrap();
    assert!(events1.iter().any(|e| matches!(e, PullProgress::LayerExtracted { .. })), "{events1:?}");
    assert_eq!(std::fs::read(diff_dir.join("shared.txt")).unwrap(), b"shared layer contents");

    // Plant a sentinel that pure re-extraction (via the rename-on-success
    // mechanism) would wipe out.
    std::fs::write(diff_dir.join("SENTINEL"), b"marker").unwrap();

    // Second pull: v2, same layer content -> same chain-id.
    let client2 = Arc::new(RegistryClient::with_base_url(server.uri()).unwrap());
    let reference2 = reference::parse("myrepo/myimage:v2").unwrap();
    let mut events2 = Vec::new();
    let chain_ids2 = pull_image_with_client(client2, &reference2, &store, &layer_store, false, |e| events2.push(e))
        .await
        .unwrap();

    assert_eq!(chain_ids2, vec![expected_chain_id]);
    assert!(events2.iter().any(|e| matches!(e, PullProgress::LayerDeduped { .. })), "{events2:?}");
    assert!(
        !events2.iter().any(|e| matches!(e, PullProgress::LayerExtracted { .. })),
        "must not re-extract a deduped layer: {events2:?}"
    );
    assert_eq!(
        std::fs::read(diff_dir.join("SENTINEL")).unwrap(),
        b"marker",
        "sentinel must survive — proves apply_layer/rename did not run a second time"
    );
}

/// Test 3: proves Phase A's bounded concurrency is real, not accidentally
/// sequential. Four distinct layers, each served with an artificial delay;
/// bounded to 4-way concurrency the whole pull should complete close to one
/// delay's worth of wall-clock time, not four.
#[tokio::test]
async fn test_pull_image_phase_a_downloads_are_genuinely_concurrent() {
    let server = MockServer::start().await;
    let repo_path = "myrepo/myimage";
    let delay = Duration::from_millis(80);
    let num_layers = 4;

    let mut layer_entries = Vec::new();
    for i in 0..num_layers {
        let tar_bytes = build_tar(&[(&format!("file{i}.txt"), format!("contents {i}").as_bytes())]);
        let compressed = gzip(&tar_bytes);
        let digest = Digest::of_bytes(&compressed).to_string();
        mount_blob(&server, repo_path, &digest, compressed.clone(), Some(delay)).await;
        layer_entries.push((digest, compressed.len(), GZIP_MEDIA_TYPE));
    }
    mount_manifest(&server, repo_path, "latest", manifest_json(&layer_entries)).await;

    let tmp = tempfile::tempdir().unwrap();
    let store = ContentStore::new(tmp.path().to_path_buf());
    let layer_store = LayerStore::new(tmp.path().to_path_buf());
    let client = Arc::new(RegistryClient::with_base_url(server.uri()).unwrap());
    let reference = reference::parse("myrepo/myimage:latest").unwrap();

    let started = Instant::now();
    let chain_ids = pull_image_with_client(client, &reference, &store, &layer_store, false, |_| {}).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(chain_ids.len(), num_layers);
    // Serial would be ~num_layers * delay (~320ms here). Bounded 4-way
    // concurrency should land close to one delay's worth plus overhead.
    // Generous tolerance (well under the serial figure) to avoid flakiness
    // on a loaded CI/VM host, while still being a REAL timing assertion.
    assert!(
        elapsed < Duration::from_millis(250),
        "pull of {num_layers} layers (each delayed {delay:?}) took {elapsed:?} — too close to the fully-serial \
         {:?}, bounded concurrency does not appear to be happening",
        delay * num_layers as u32
    );
}

/// Test 4: proves the fix for the "blob downloads bypass atomic-write
/// discipline" gap — `download_and_hash_one` must never stream straight
/// into `store.blob_path(&digest)` (the FINAL content-addressed path),
/// because Phase A's `buffer_unordered` aborts every other still-in-flight
/// download the instant any one layer errors (`pull_image_with_client`'s
/// `result?`), and a future dropped mid-write leaves whatever was already
/// written on disk. If that disk location were the final path,
/// `ContentStore::has_blob` (a bare `is_file()` check) would then mistake
/// the truncated leftovers for a complete, valid blob on a later pull.
///
/// Race construction, made reliable WITHOUT a fragile fixed delay: one
/// layer 404s immediately (never retried — only 5xx/429 are), while the
/// other ("victim") layers are each served a large (16 MiB) body with no
/// artificial delay at all. A 404 round-trips over loopback in well under a
/// millisecond; streaming 16 MiB inherently requires many more read/write
/// syscalls and thus measurably more wall-clock time. Since
/// `buffer_unordered` (bound to 4, same as the total layer count here)
/// starts all of these requests at essentially the same instant — this
/// module's own `test_pull_image_phase_a_downloads_are_genuinely_concurrent`
/// already establishes that Phase A's concurrency is real, not accidental —
/// the 404 reliably resolves first, `result?` bails, and every victim's
/// download future is dropped while genuinely still streaming its body.
/// The size gap (bytes vs. megabytes), not a hardcoded delay, is what makes
/// the ordering dependable across slower/loaded machines.
#[tokio::test]
async fn test_pull_image_cancelled_concurrent_download_never_corrupts_content_store() {
    let server = MockServer::start().await;
    let repo_path = "myrepo/myimage";

    const VICTIM_COUNT: usize = 3;
    const VICTIM_BODY_LEN: usize = 16 * 1024 * 1024; // 16 MiB — see doc comment above.

    let mut layer_entries = Vec::new();
    let mut victim_digests = Vec::new();
    for i in 0..VICTIM_COUNT {
        // Content doesn't need to be valid gzip: this layer's download is
        // meant to be cancelled before `pull_image_with_client` ever gets
        // to Phase B's decompression, so nothing ever tries to parse it.
        let body = vec![(i as u8).wrapping_add(1); VICTIM_BODY_LEN];
        let digest = Digest::of_bytes(&body).to_string();
        mount_blob(&server, repo_path, &digest, body, None).await;
        layer_entries.push((digest.clone(), VICTIM_BODY_LEN, GZIP_MEDIA_TYPE));
        victim_digests.push(digest);
    }

    let failing_digest = Digest::of_bytes(b"this blob is deliberately never served").to_string();
    mount_blob_404(&server, repo_path, &failing_digest).await;
    layer_entries.push((failing_digest, 1, GZIP_MEDIA_TYPE));

    mount_manifest(&server, repo_path, "latest", manifest_json(&layer_entries)).await;

    let tmp = tempfile::tempdir().unwrap();
    let store = ContentStore::new(tmp.path().to_path_buf());
    let layer_store = LayerStore::new(tmp.path().to_path_buf());
    let client = Arc::new(RegistryClient::with_base_url(server.uri()).unwrap());
    let reference = reference::parse("myrepo/myimage:latest").unwrap();

    let result = pull_image_with_client(client, &reference, &store, &layer_store, false, |_| {}).await;
    assert!(result.is_err(), "the pull must fail overall because one layer 404'd");

    // The property under test: every victim's blob is EITHER absent from
    // its final content-addressed path, OR (if it happened to fully
    // complete before cancellation reached it) fully intact — never a
    // truncated/partial file sitting under a name `has_blob` would trust.
    let mut at_least_one_absent = false;
    for digest_str in &victim_digests {
        let digest: Digest = digest_str.parse().unwrap();
        let blob_path = store.blob_path(&digest);
        if blob_path.is_file() {
            let bytes = std::fs::read(&blob_path).unwrap();
            assert_eq!(
                bytes.len(),
                VICTIM_BODY_LEN,
                "a blob visible at its final content-addressed path must never be a truncated/partial \
                 write — it must be fully present or not present at all (found {} of {} bytes at {})",
                bytes.len(),
                VICTIM_BODY_LEN,
                blob_path.display()
            );
            assert_eq!(
                Digest::of_bytes(&bytes).to_string(),
                *digest_str,
                "if a blob is present at its final path its bytes must actually match its digest"
            );
        } else {
            at_least_one_absent = true;
        }
    }
    assert!(
        at_least_one_absent,
        "expected at least one of the {VICTIM_COUNT} large concurrent downloads to genuinely still be \
         in flight (and thus get cancelled, never reaching its final path) when the 404'd layer aborted \
         the pull — if this fails, the race construction itself needs revisiting, not the fix"
    );
}
