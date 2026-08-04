//! Chain-ID computation and the OverlayFS layer store — see
//! docs/superpowers/specs/2026-08-03-phase4-rootfs-design.md.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// `chainID(layer0) = diffID(layer0)`;
/// `chainID(layerN) = sha256(chainID(layerN-1) + " " + diffID(layerN))`.
/// Matches the OCI image-spec's chain-ID algorithm so kestrel's layer store
/// can be shared/compared with other implementations' digests in the future.
pub fn chain_id(parent_chain_id: Option<&str>, diff_id: &str) -> String {
    match parent_chain_id {
        None => diff_id.to_string(),
        Some(parent) => {
            let mut hasher = Sha256::new();
            hasher.update(parent.as_bytes());
            hasher.update(b" ");
            hasher.update(diff_id.as_bytes());
            format!("sha256:{:x}", hasher.finalize())
        }
    }
}

/// Owns `<root>/layers/` and `<root>/l/` — the content-addressed layer
/// diffs and the short-symlink farm that keeps overlay `lowerdir=` mount
/// option strings under the one-page (4096-byte) limit. See SPEC.md §6.3.
pub struct LayerStore {
    pub root: PathBuf,
}

impl LayerStore {
    pub fn new(root: PathBuf) -> Self {
        LayerStore { root }
    }

    pub fn layer_dir(&self, chain_id: &str) -> PathBuf {
        self.root.join("layers").join(sanitize_chain_id(chain_id))
    }

    pub fn diff_dir(&self, chain_id: &str) -> PathBuf {
        self.layer_dir(chain_id).join("diff")
    }

    fn link_farm_dir(&self) -> PathBuf {
        self.root.join("l")
    }

    /// Creates `layers/<chain-id>/{diff/,parent,link}` and the
    /// `l/<short> -> ../layers/<chain-id>/diff` symlink if they don't
    /// already exist. Returns the `diff/` directory, ready for
    /// `kestrel_image::apply::apply_layer` to extract into. Idempotent —
    /// safe to call again for a layer that's already present (e.g. shared
    /// by two images), which is the whole point of content-addressing by
    /// chain-id.
    pub fn ensure_layer(&self, chain_id: &str, parent: Option<&str>) -> Result<PathBuf> {
        let dir = self.layer_dir(chain_id);
        let diff = dir.join("diff");
        fs::create_dir_all(&diff)
            .with_context(|| format!("creating layer diff dir {}", diff.display()))?;
        if let Some(parent) = parent {
            let parent_file = dir.join("parent");
            if !parent_file.exists() {
                fs::write(&parent_file, parent)
                    .with_context(|| format!("writing {}", parent_file.display()))?;
            }
        }
        self.ensure_link(chain_id)?;
        Ok(diff)
    }

    /// Returns the short symlink name for `chain_id`, creating the
    /// `l/<short>` symlink (and persisting the name in `layers/<chain-id>/
    /// link`) on first use so it survives process restarts.
    pub fn ensure_link(&self, chain_id: &str) -> Result<String> {
        let dir = self.layer_dir(chain_id);
        let link_file = dir.join("link");
        if let Ok(existing) = fs::read_to_string(&link_file) {
            let existing = existing.trim().to_string();
            // Trust the cached short name only if its symlink entry is
            // actually still present in the farm — a `link` file surviving
            // a partial cleanup (or a restored `layers/` tree without its
            // `l/` farm) must not make us hand back a name that resolves to
            // nothing. Use symlink_metadata (lstat), not exists()/metadata
            // (stat): the symlink can legitimately be present-but-dangling
            // (its `diff/` target created separately by ensure_layer), and
            // exists() would follow the link and report a false negative.
            if !existing.is_empty()
                && self
                    .link_farm_dir()
                    .join(&existing)
                    .symlink_metadata()
                    .is_ok()
            {
                return Ok(existing);
            }
        }

        fs::create_dir_all(&dir)
            .with_context(|| format!("creating layer dir {}", dir.display()))?;

        let short = short_name(chain_id);
        let farm = self.link_farm_dir();
        fs::create_dir_all(&farm)
            .with_context(|| format!("creating link farm dir {}", farm.display()))?;
        let link_path = farm.join(&short);
        let target = PathBuf::from("..")
            .join("layers")
            .join(sanitize_chain_id(chain_id))
            .join("diff");
        if link_path.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(&target, &link_path).with_context(|| {
                format!("symlinking {} -> {}", link_path.display(), target.display())
            })?;
        }
        fs::write(&link_file, &short)
            .with_context(|| format!("writing {}", link_file.display()))?;
        Ok(short)
    }
}

/// Chain IDs are `sha256:<hex>` or, for test fixtures, arbitrary strings —
/// strip the `sha256:` prefix and reject path separators so a malformed or
/// adversarial diff-id/chain-id can never be used to escape `layers/`.
///
/// This mapping is not injective (e.g. `"a/b"` and `"a.b"` both sanitize to
/// `"a_b"`), which would be a collision risk for untrusted input. It's safe
/// here only because real chain-ids are always `sha256:<hex>` — already
/// alphanumeric and passed through unchanged; the substitution exists purely
/// as a defense-in-depth backstop against malformed/adversarial values, not
/// as a general-purpose encoding.
fn sanitize_chain_id(chain_id: &str) -> String {
    chain_id
        .strip_prefix("sha256:")
        .unwrap_or(chain_id)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn short_name(chain_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(chain_id.as_bytes());
    let digest = hasher.finalize();
    hex_prefix(&digest, 6) // 12 hex chars
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes.iter().take(n).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_of_first_layer_is_its_own_diff_id() {
        assert_eq!(chain_id(None, "sha256:aaaa"), "sha256:aaaa");
    }

    #[test]
    fn test_chain_id_chains_deterministically() {
        let l0 = chain_id(None, "sha256:aaaa");
        let l1 = chain_id(Some(&l0), "sha256:bbbb");
        let l1_again = chain_id(Some(&l0), "sha256:bbbb");
        assert_eq!(l1, l1_again, "chaining must be deterministic");
        assert_ne!(l1, l0, "chained id must differ from its parent");
        assert!(l1.starts_with("sha256:"));
    }

    #[test]
    fn test_chain_id_differs_when_diff_id_differs() {
        let l0 = chain_id(None, "sha256:aaaa");
        let a = chain_id(Some(&l0), "sha256:bbbb");
        let b = chain_id(Some(&l0), "sha256:cccc");
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod layer_store_tests {
    use super::*;

    #[test]
    fn test_ensure_layer_creates_diff_dir_and_link() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        let diff = store.ensure_layer("sha256:deadbeef", None).unwrap();
        assert!(diff.is_dir());
        assert!(diff.ends_with("diff"));

        let short = store.ensure_link("sha256:deadbeef").unwrap();
        let link = store.root.join("l").join(&short);
        assert!(link.exists(), "symlink {} should exist", link.display());
        let target = fs::read_link(&link).unwrap();
        assert!(target.to_str().unwrap().contains("deadbeef"));
    }

    #[test]
    fn test_ensure_layer_is_idempotent_and_link_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        let short1 = store.ensure_link("sha256:cafef00d").unwrap();
        let short2 = store.ensure_link("sha256:cafef00d").unwrap();
        assert_eq!(short1, short2, "link name must be stable across calls");
    }

    #[test]
    fn test_ensure_layer_writes_parent_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        store
            .ensure_layer("sha256:child", Some("sha256:parent"))
            .unwrap();
        let parent =
            fs::read_to_string(store.layer_dir("sha256:child").join("parent")).unwrap();
        assert_eq!(parent, "sha256:parent");
    }

    #[test]
    fn test_ensure_link_recreates_missing_symlink_and_keeps_same_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        store.ensure_layer("sha256:healme", None).unwrap();
        let short = store.ensure_link("sha256:healme").unwrap();
        let link = store.root.join("l").join(&short);
        assert!(link.exists(), "symlink should exist after ensure_layer");

        // Simulate partial cleanup: the farm entry is gone but the
        // `layers/<chain-id>/link` cache file is left behind.
        fs::remove_file(&link).unwrap();
        assert!(
            link.symlink_metadata().is_err(),
            "precondition: symlink must actually be gone"
        );

        let short_again = store.ensure_link("sha256:healme").unwrap();
        assert_eq!(short_again, short, "short name must remain stable");
        assert!(
            link.exists(),
            "ensure_link must self-heal the missing symlink"
        );
        let target = fs::read_link(&link).unwrap();
        assert!(target.to_str().unwrap().contains("healme"));
    }

    #[test]
    fn test_sanitize_chain_id_rejects_path_separators() {
        // Every non-alphanumeric byte (not just '/') is replaced, so a
        // chain-id of exactly "sha256:.." can never sanitize down to a
        // literal ".." path component and escape `layers/`.
        assert_eq!(sanitize_chain_id("sha256:../../etc"), "______etc");
        assert!(!sanitize_chain_id("sha256:../../etc").contains('/'));
        assert_ne!(sanitize_chain_id("sha256:.."), "..");
    }
}

/// Bottom-to-top list of `l/<short>` names (matching how OCI image
/// manifests order layers) plus the three per-container directories
/// `mount_overlay` (Task 4) needs.
pub struct Snapshot {
    /// Bare short names (e.g. `"a1b2c3d4e5f6"`), one per lower chain-id,
    /// bottom-to-top — *without* the `l/` prefix. `overlay::build_overlay_opts`
    /// is responsible for joining each with `l/` (via `format!("l/{l}")`)
    /// when building the `lowerdir=` mount option; don't prefix it here too.
    pub lower_links: Vec<String>,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub merged: PathBuf,
}

pub struct Snapshotter {
    pub data_dir: PathBuf,
    pub rootless: bool,
    pub metacopy: bool,
    pub redirect_dir: bool,
    store: LayerStore,
}

impl Snapshotter {
    pub fn new(data_dir: PathBuf, rootless: bool) -> Self {
        Snapshotter {
            store: LayerStore::new(data_dir.clone()),
            data_dir,
            rootless,
            metacopy: false,
            redirect_dir: false,
        }
    }

    /// Resolves `lower_chain_ids` (bottom-to-top) into their symlink-farm
    /// short names and creates this container's writable-layer
    /// directories. Does not mount anything — that's `overlay::mount_overlay`.
    /// Idempotent — safe to call again for the same `container_id` (e.g. on
    /// restart), since `create_dir_all` and `LayerStore::ensure_link` are
    /// both idempotent.
    pub fn prepare_snapshot(&self, container_id: &str, lower_chain_ids: &[String]) -> Result<Snapshot> {
        anyhow::ensure!(!container_id.is_empty(), "container_id must not be empty");
        anyhow::ensure!(
            container_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "container_id {container_id:?} must be [A-Za-z0-9_-] only"
        );

        let mut lower_links = Vec::with_capacity(lower_chain_ids.len());
        for chain_id in lower_chain_ids {
            lower_links.push(self.store.ensure_link(chain_id)?);
        }

        let base = self.data_dir.join("snapshots").join(container_id);
        let snap = Snapshot {
            lower_links,
            upper: base.join("upper"),
            work: base.join("work"),
            merged: base.join("merged"),
        };
        for dir in [&snap.upper, &snap.work, &snap.merged] {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(snap)
    }
}

#[cfg(test)]
mod snapshotter_tests {
    use super::*;

    #[test]
    fn test_prepare_snapshot_creates_upper_work_merged_and_resolves_links() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        store.ensure_layer("sha256:base", None).unwrap();
        store.ensure_layer("sha256:top", Some("sha256:base")).unwrap();
        // Capture the expected short names independently of prepare_snapshot
        // itself (ensure_link is idempotent, so calling it again here just
        // returns the same cached names) so the assertion below is a real
        // check of resolved identity and order, not just count.
        let expected_base = store.ensure_link("sha256:base").unwrap();
        let expected_top = store.ensure_link("sha256:top").unwrap();

        let snapshotter = Snapshotter::new(tmp.path().to_path_buf(), false);
        let snap = snapshotter
            .prepare_snapshot("container-1", &["sha256:base".into(), "sha256:top".into()])
            .unwrap();

        assert!(snap.upper.is_dir());
        assert!(snap.work.is_dir());
        assert!(snap.merged.is_dir());
        assert_eq!(
            snap.lower_links,
            vec![expected_base, expected_top],
            "bottom-to-top order must be preserved, not just the count"
        );
    }

    #[test]
    fn test_prepare_snapshot_rejects_empty_container_id() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshotter = Snapshotter::new(tmp.path().to_path_buf(), false);
        assert!(snapshotter.prepare_snapshot("", &["sha256:x".into()]).is_err());
    }

    #[test]
    fn test_prepare_snapshot_rejects_path_traversal_container_id() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshotter = Snapshotter::new(tmp.path().to_path_buf(), false);
        assert!(
            snapshotter
                .prepare_snapshot("../evil", &["sha256:x".into()])
                .is_err(),
            "container_id with '..' must be rejected"
        );
        assert!(
            snapshotter
                .prepare_snapshot("a/b", &["sha256:x".into()])
                .is_err(),
            "container_id with '/' must be rejected"
        );
    }
}
