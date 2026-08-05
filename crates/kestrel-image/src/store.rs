use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};

use crate::digest::{Digest, VerifyingReader};

/// Monotonic counter mixed into temp-file names alongside the pid, so two
/// `write_blob` calls racing within the SAME process (e.g. two threads, or
/// two `spawn_blocking` tasks that happen to overlap) never pick the same
/// `.tmp-*` name and clobber each other's bytes mid-write. `std::process::
/// id()` alone only disambiguates across processes.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The content-addressable blob store: `<root>/content/blobs/sha256/<digest>`.
/// Holds raw fetched bytes (manifests, configs, compressed layer
/// tarballs) — distinct from `kestrel_rootfs::snapshot::LayerStore`, which
/// holds EXTRACTED layer contents keyed by chain-id. Both live under the
/// same overall data root but are populated/read independently.
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: PathBuf) -> Self {
        ContentStore { root }
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("content/blobs")
    }

    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.blobs_dir().join(digest.store_relative_path())
    }

    pub fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_file()
    }

    /// Writes `reader`'s bytes into the store, verifying against
    /// `expected` if given (SPEC.md §10.2: reject a corrupt/malicious blob
    /// during the write, not after). Write-to-temp-then-rename for
    /// atomicity — a reader crashing mid-write, or a digest mismatch,
    /// leaves no partial blob visible at the final path; a concurrent
    /// reader of an already-complete blob is never exposed to a
    /// half-written file.
    pub fn write_blob(&self, expected: Option<&Digest>, mut reader: impl Read) -> Result<Digest> {
        let dir = self.blobs_dir().join("sha256");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        // `.tmp-<pid>-<counter>`: the pid disambiguates across processes,
        // the counter disambiguates concurrent writers within this same
        // process (see `TMP_COUNTER` doc comment above).
        let unique = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!(".tmp-{}-{}", std::process::id(), unique));
        let tmp_file = fs::File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        let mut verifying = VerifyingReader::new(&mut reader);
        let mut writer = std::io::BufWriter::new(tmp_file);

        let copy_result = std::io::copy(&mut verifying, &mut writer);
        let actual = verifying.finish();

        // Clean up the temp file on ANY failure path before propagating —
        // a write error or digest mismatch must never leave a stray
        // `.tmp-*` file behind for a later blob write to trip over.
        let cleanup_and_bail = |ctx: &str| -> Result<Digest> {
            let _ = fs::remove_file(&tmp_path);
            anyhow::bail!("{ctx}");
        };

        if let Err(e) = copy_result {
            return cleanup_and_bail(&format!("writing blob: {e}"));
        }
        if let Some(exp) = expected {
            if &actual != exp {
                return cleanup_and_bail(&format!("digest mismatch: expected {exp}, got {actual}"));
            }
        }

        let final_path = self.blob_path(&actual);
        fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("renaming {} to {}", tmp_path.display(), final_path.display()))?;
        Ok(actual)
    }

    /// Refcounting: `rmi` must never delete a blob another image still
    /// references. Refs are tracked as one file per (digest, owner)
    /// pair under `<root>/content/refs/<digest-hex>/<owner-id>` — an
    /// empty marker file, not a counter, so removing one owner's
    /// reference is a plain `remove_file`, immune to lost-update races
    /// a shared counter file would need extra locking to avoid.
    pub fn add_ref(&self, digest: &Digest, owner_id: &str) -> Result<()> {
        let dir = self.root.join("content/refs").join(digest.hex());
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::write(dir.join(owner_id), b"").with_context(|| format!("adding ref for {owner_id}"))
    }

    pub fn remove_ref(&self, digest: &Digest, owner_id: &str) -> Result<()> {
        let path = self.root.join("content/refs").join(digest.hex()).join(owner_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // already gone, fine
            Err(e) => Err(e).with_context(|| format!("removing ref {}", path.display())),
        }
    }

    pub fn is_referenced(&self, digest: &Digest) -> bool {
        let dir = self.root.join("content/refs").join(digest.hex());
        fs::read_dir(&dir).map(|mut d| d.next().is_some()).unwrap_or(false)
    }

    /// Deletes the blob if (and only if) nothing references it. Returns
    /// whether it was actually deleted.
    pub fn remove_blob_if_unreferenced(&self, digest: &Digest) -> Result<bool> {
        if self.is_referenced(digest) {
            return Ok(false);
        }
        let path = self.blob_path(digest);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// Writes a minimal `oci-layout` + `index.json` pair at the store
    /// root, per the OCI Image Layout spec — lets any OCI-compliant
    /// tool (not just kestrel) browse this store's images.
    pub fn write_oci_layout(&self, manifests: &[Digest]) -> Result<()> {
        fs::create_dir_all(&self.root).with_context(|| format!("creating {}", self.root.display()))?;
        let layout = serde_json::json!({ "imageLayoutVersion": "1.0.0" });
        fs::write(self.root.join("oci-layout"), serde_json::to_vec_pretty(&layout)?)
            .context("writing oci-layout")?;

        let manifest_entries: Vec<_> = manifests
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": d.to_string(),
                    "size": self.blob_path(d).metadata().map(|m| m.len()).unwrap_or(0),
                })
            })
            .collect();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": manifest_entries,
        });
        fs::write(self.root.join("index.json"), serde_json::to_vec_pretty(&index)?)
            .context("writing index.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_blob_then_read_back_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let data = b"hello content store";
        let digest = store.write_blob(None, std::io::Cursor::new(data)).unwrap();
        assert_eq!(digest, Digest::of_bytes(data));
        assert!(store.has_blob(&digest));
        let read_back = fs::read(store.blob_path(&digest)).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_write_blob_rejects_digest_mismatch_and_persists_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let wrong = Digest::of_bytes(b"something else entirely");
        let err = store.write_blob(Some(&wrong), std::io::Cursor::new(b"actual data")).unwrap_err();
        assert!(err.to_string().contains("digest mismatch"));
        assert!(!store.has_blob(&wrong));
        assert!(!store.has_blob(&Digest::of_bytes(b"actual data")), "no blob should be persisted under any digest on mismatch");
        // No stray temp files left behind.
        let entries: Vec<_> = fs::read_dir(tmp.path().join("content/blobs/sha256")).unwrap().collect();
        assert!(entries.is_empty(), "temp file must be cleaned up on digest mismatch");
    }

    #[test]
    fn test_write_blob_accepts_correct_expected_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let data = b"verified data";
        let expected = Digest::of_bytes(data);
        let actual = store.write_blob(Some(&expected), std::io::Cursor::new(data)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_refcounting_blocks_deletion_while_referenced() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let digest = store.write_blob(None, std::io::Cursor::new(b"shared layer")).unwrap();

        store.add_ref(&digest, "image-a").unwrap();
        store.add_ref(&digest, "image-b").unwrap();
        assert!(store.is_referenced(&digest));

        assert!(!store.remove_blob_if_unreferenced(&digest).unwrap(), "still referenced by image-b");
        assert!(store.has_blob(&digest));

        store.remove_ref(&digest, "image-a").unwrap();
        assert!(store.is_referenced(&digest), "image-b's ref must still hold");
        assert!(!store.remove_blob_if_unreferenced(&digest).unwrap());

        store.remove_ref(&digest, "image-b").unwrap();
        assert!(!store.is_referenced(&digest));
        assert!(store.remove_blob_if_unreferenced(&digest).unwrap());
        assert!(!store.has_blob(&digest));
    }

    #[test]
    fn test_write_oci_layout_produces_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let digest = store.write_blob(None, std::io::Cursor::new(b"a manifest")).unwrap();
        store.write_oci_layout(std::slice::from_ref(&digest)).unwrap();

        let layout: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join("oci-layout")).unwrap()).unwrap();
        assert_eq!(layout["imageLayoutVersion"], "1.0.0");

        let index: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join("index.json")).unwrap()).unwrap();
        assert_eq!(index["manifests"][0]["digest"], digest.to_string());
    }
}
