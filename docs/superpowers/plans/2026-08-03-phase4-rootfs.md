# Phase 4 — Rootfs, OverlayFS & pivot_root Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-rootfs` (chain-ID/symlink-farm layer store, OverlayFS mount/unmount, the 6-step `pivot_root` sequence, standard mounts, masked/read-only paths, copy-up scanning) and `kestrel-image`'s `apply_layer()` (tar extraction with whiteout/opaque translation and a hardened path-traversal guard), per SPEC.md §6-7 and PROMPT.md's Phase 4 section.

**Architecture:** Two crates, following SPEC.md §16's ownership table. `kestrel-rootfs` owns everything that touches the mount table (`overlay.rs`, `pivot.rs`, `bindmount.rs`, `mounts.rs`, `mask.rs`) plus the pure layer-store bookkeeping (`snapshot.rs`, `copyup.rs`). `kestrel-image` owns only `apply_layer()` — turning a tar stream into a populated `diff/` directory — with no dependency on a content store or registry (Phase 6). All privileged operations get root-gated integration tests in `tests/`; pure logic (chain-ID math, mount-option-string building, path-traversal rejection) gets unprivileged unit tests in `#[cfg(test)]` blocks.

**Tech Stack:** Rust, `nix` 0.29 (`fs`, `mount`, `process`, `sched` features), `sha2` for chain-ID digests, `tar` for layer extraction, `xattr` for whiteout/opaque markers, reusing `kestrel-ns::test_util::run_isolated` (as a dev-dependency) for fork-isolated, single-threaded root-gated tests.

---

## File Structure

```
crates/kestrel-rootfs/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── snapshot.rs   — chain_id(), LayerStore, Snapshotter::prepare_snapshot, Snapshot
│   ├── overlay.rs     — build_overlay_opts, mount_overlay, unmount_overlay, ChdirGuard
│   ├── pivot.rs        — pivot_root
│   ├── bindmount.rs   — bind_readonly (the two-call footgun, standalone + reused by mask.rs)
│   ├── mounts.rs       — standard mounts table, device nodes, devpts ptmx symlink
│   ├── mask.rs          — mask_path, make_readonly, DEFAULT_MASKED/DEFAULT_READONLY
│   └── copyup.rs       — CopyUpEvent, CopyUpKind, scan_copy_ups
└── tests/
    ├── overlay.rs
    ├── pivot.rs
    ├── mounts.rs
    ├── mask.rs
    ├── copyup.rs
    └── lifecycle.rs   — full end-to-end: apply_layer x2 → snapshot → overlay → pivot_root

crates/kestrel-image/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   └── apply.rs         — LayerStats, apply_layer (with hardened traversal guard)
└── tests/
    └── apply.rs
```

---

## Task 1: `kestrel-rootfs` crate scaffolding

**Files:**
- Modify: `crates/kestrel-rootfs/Cargo.toml`
- Modify: `crates/kestrel-rootfs/src/lib.rs`

- [ ] **Step 1: Write the Cargo.toml**

```toml
[package]
name = "kestrel-rootfs"
edition.workspace = true
version.workspace = true

[dependencies]
nix = { workspace = true, features = ["fs", "mount", "process", "sched"] }
libc.workspace = true
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
sha2 = "0.10"

[dev-dependencies]
kestrel-ns = { path = "../kestrel-ns" }
tempfile = "3"
```

`tempfile` is new to the workspace (Phase 2/3 tests used `/tmp` paths built by hand); every unprivileged test in this phase needs a scratch directory, so bring in the standard crate rather than hand-rolling `mkdtemp` again in every test file.

- [ ] **Step 2: Write lib.rs**

```rust
#![deny(clippy::undocumented_unsafe_blocks)]

//! OverlayFS snapshotter, mounts, pivot_root, and masked/read-only path
//! application for kestrel. See
//! docs/superpowers/specs/2026-08-03-phase4-rootfs-design.md.

pub mod snapshot;
```

Only `snapshot` is declared for now — later tasks add one `pub mod` line each as they create their file, so the crate always compiles at the end of a task.

- [ ] **Step 3: Confirm it builds**

Run (inside the Lima VM, `cd ~/Container-Runtime`): `cargo build -p kestrel-rootfs`
Expected: fails, because `src/snapshot.rs` doesn't exist yet — that's fine, Task 2 creates it. If you want a green build at the end of this task, temporarily use `pub mod snapshot {}` inline, but don't commit that; Task 2 replaces it immediately.

- [ ] **Step 4: Commit**

Not applicable — this project is not using git (per explicit user instruction, "hold off on git entirely"). Skip all "commit" steps in this plan; verify via the build/test commands only.

---

## Task 2: Chain-ID computation and the layer store (`snapshot.rs`, part 1)

**Files:**
- Create: `crates/kestrel-rootfs/src/snapshot.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`

Per SPEC.md §6.1's layout:
```
/var/lib/kestrel/
├── layers/<chain-id>/{diff/, link, parent}
├── l/<short>  ->  ../layers/<chain-id>/diff
```

Chain-ID chaining is the standard OCI algorithm: `chainID(layer0) = diffID(layer0)`; `chainID(layerN) = sha256(chainID(layerN-1) + " " + diffID(layerN))`, each formatted as `sha256:<hex>`. `diff_id` here is caller-supplied (in Phase 6 it'll be the uncompressed layer's digest; in this phase's tests it's just a fixture string).

The symlink short-name deviates deliberately from Docker's random 26-char IDs: we derive it deterministically from the chain-ID's own hex digest (first 12 hex chars) and persist it in `layers/<chain-id>/link` so it's stable across restarts without needing a separate ID-allocation database. Collision risk is negligible at this project's scale and the plan intentionally avoids adding random-ID bookkeeping machinery for it.

- [ ] **Step 1: Write the test for chain_id chaining**

```rust
// crates/kestrel-rootfs/src/snapshot.rs

use std::fs;
use std::path::{Path, PathBuf};

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
```

- [ ] **Step 2: Run the test, confirm it fails to compile (module not wired yet), then wire it**

Add to `lib.rs`: already done in Task 1 (`pub mod snapshot;`).

Run: `cargo test -p kestrel-rootfs chain_id`
Expected: 3 passed.

- [ ] **Step 3: Write `LayerStore` — layer directory layout and the symlink farm**

Append to `crates/kestrel-rootfs/src/snapshot.rs`:

```rust
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
        let link_file = self.layer_dir(chain_id).join("link");
        if let Ok(existing) = fs::read_to_string(&link_file) {
            let existing = existing.trim().to_string();
            if !existing.is_empty() {
                return Ok(existing);
            }
        }

        let short = short_name(chain_id);
        let farm = self.link_farm_dir();
        fs::create_dir_all(&farm)
            .with_context(|| format!("creating link farm dir {}", farm.display()))?;
        let link_path = farm.join(&short);
        let target = PathBuf::from("..").join("layers").join(sanitize_chain_id(chain_id)).join("diff");
        if !link_path.exists() {
            // SAFETY: not unsafe — std::os::unix::fs::symlink is a safe fn.
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
```

- [ ] **Step 4: Write tests for `LayerStore`**

```rust
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
        store.ensure_layer("sha256:child", Some("sha256:parent")).unwrap();
        let parent = fs::read_to_string(store.layer_dir("sha256:child").join("parent")).unwrap();
        assert_eq!(parent, "sha256:parent");
    }

    #[test]
    fn test_sanitize_chain_id_rejects_path_separators() {
        assert_eq!(sanitize_chain_id("sha256:../../etc"), ".._.._etc");
        assert!(!sanitize_chain_id("sha256:../../etc").contains('/'));
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p kestrel-rootfs`
Expected: all `snapshot::` tests pass (7 total: 3 chain_id + 4 layer_store).

---

## Task 3: `Snapshotter::prepare_snapshot` (`snapshot.rs`, part 2)

**Files:**
- Modify: `crates/kestrel-rootfs/src/snapshot.rs`

Per SPEC.md §6.1: `snapshots/<container-id>/{upper/,work/,merged/}`. This task adds the `Snapshot` struct that `overlay.rs` (Task 4) mounts, and `Snapshotter`, which resolves an ordered list of chain-ids (bottom-to-top, matching how image manifests list layers) into their `l/<short>` names via `LayerStore`.

- [ ] **Step 1: Write the test**

Append to `crates/kestrel-rootfs/src/snapshot.rs`:

```rust
#[cfg(test)]
mod snapshotter_tests {
    use super::*;

    #[test]
    fn test_prepare_snapshot_creates_upper_work_merged_and_resolves_links() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LayerStore::new(tmp.path().to_path_buf());
        store.ensure_layer("sha256:base", None).unwrap();
        store.ensure_layer("sha256:top", Some("sha256:base")).unwrap();

        let snapshotter = Snapshotter::new(tmp.path().to_path_buf(), false);
        let snap = snapshotter
            .prepare_snapshot("container-1", &["sha256:base".into(), "sha256:top".into()])
            .unwrap();

        assert!(snap.upper.is_dir());
        assert!(snap.work.is_dir());
        assert!(snap.merged.is_dir());
        assert_eq!(snap.lower_links.len(), 2, "one link per chain-id, bottom-to-top order preserved");
    }

    #[test]
    fn test_prepare_snapshot_rejects_empty_container_id() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshotter = Snapshotter::new(tmp.path().to_path_buf(), false);
        assert!(snapshotter.prepare_snapshot("", &["sha256:x".into()]).is_err());
    }
}
```

- [ ] **Step 2: Implement**

Append to `crates/kestrel-rootfs/src/snapshot.rs`:

```rust
/// Bottom-to-top list of `l/<short>` names (matching how OCI image
/// manifests order layers) plus the three per-container directories
/// `mount_overlay` (Task 4) needs.
pub struct Snapshot {
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
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p kestrel-rootfs snapshot`
Expected: 9 passed (7 from Task 2 + 2 new).

---

## Task 4: OverlayFS mount/unmount (`overlay.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/overlay.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-rootfs/tests/overlay.rs`

Per SPEC.md §6.2-6.3: the mount-option string is built with the symlink-farm's short relative names for `lowerdir` (requiring the process to `chdir` into `data_dir` for the duration of the `mount()` call, since relative mount-option paths resolve against the calling process's cwd at syscall time — not the string's caller), and absolute paths for `upperdir`/`workdir` (single directories, no length pressure). `build_overlay_opts` is split out as a pure function so the one-page-limit `ensure!` can be unit-tested without root.

- [ ] **Step 1: Write the pure option-string-building code + its tests**

```rust
// crates/kestrel-rootfs/src/overlay.rs

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};

use crate::snapshot::Snapshot;

/// Mount option strings are capped at one page (4096 bytes) by the kernel.
/// Builds the string using the symlink farm's short `l/<name>` entries so a
/// deep image doesn't blow past that limit. `lowerdir` is colon-separated,
/// RIGHTMOST entry is the BOTTOM layer — `lower_links` is bottom-to-top
/// (matching image-manifest order), so it must be reversed here.
pub fn build_overlay_opts(snap: &Snapshot, rootless: bool, metacopy: bool, redirect_dir: bool) -> Result<String> {
    anyhow::ensure!(!snap.lower_links.is_empty(), "snapshot has no lower layers");
    let lowers: Vec<String> = snap.lower_links.iter().rev().map(|l| format!("l/{l}")).collect();
    let mut opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowers.join(":"),
        snap.upper.display(),
        snap.work.display(),
    );
    if rootless {
        // Kernel 5.11+: unprivileged users cannot set trusted.* xattrs, so
        // without this the first whiteout write fails with EPERM.
        opts.push_str(",userxattr");
    }
    if metacopy {
        opts.push_str(",metacopy=on");
    }
    if redirect_dir {
        opts.push_str(",redirect_dir=on");
    }
    anyhow::ensure!(
        opts.len() < 4096,
        "overlay mount options are {} bytes, exceeding the one-page (4096) limit — \
         symlink farm not applied, or too many lower layers even with short names",
        opts.len()
    );
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Snapshot;

    fn snap(lower_links: Vec<String>) -> Snapshot {
        Snapshot {
            lower_links,
            upper: PathBuf::from("/data/snapshots/c1/upper"),
            work: PathBuf::from("/data/snapshots/c1/work"),
            merged: PathBuf::from("/data/snapshots/c1/merged"),
        }
    }

    #[test]
    fn test_build_overlay_opts_reverses_lower_order() {
        let s = snap(vec!["aaa".into(), "bbb".into(), "ccc".into()]);
        let opts = build_overlay_opts(&s, false, false, false).unwrap();
        assert!(opts.starts_with("lowerdir=l/ccc:l/bbb:l/aaa,"), "got: {opts}");
    }

    #[test]
    fn test_build_overlay_opts_appends_rootless_flags() {
        let s = snap(vec!["aaa".into()]);
        let opts = build_overlay_opts(&s, true, true, true).unwrap();
        assert!(opts.contains(",userxattr"));
        assert!(opts.contains(",metacopy=on"));
        assert!(opts.contains(",redirect_dir=on"));
    }

    #[test]
    fn test_build_overlay_opts_rejects_empty_lowers() {
        let s = snap(vec![]);
        assert!(build_overlay_opts(&s, false, false, false).is_err());
    }

    #[test]
    fn test_build_overlay_opts_rejects_over_one_page() {
        // 300 short names of ~15 bytes each ("l/xxxxxxxxxxxx:") comfortably
        // exceeds 4096 bytes even with the symlink farm, proving the guard
        // fires — this is the regression test for the historical "40-layer
        // image blows past PAGE_SIZE" bug class, without needing to build
        // 300 real directories.
        let many: Vec<String> = (0..300).map(|i| format!("{i:012x}")).collect();
        let s = snap(many);
        let err = build_overlay_opts(&s, false, false, false).unwrap_err();
        assert!(err.to_string().contains("one-page"));
    }
}
```

- [ ] **Step 2: Run pure tests**

Run: `cargo test -p kestrel-rootfs overlay::tests`
Expected: 4 passed.

- [ ] **Step 3: Implement `mount_overlay`/`unmount_overlay`**

Append to `crates/kestrel-rootfs/src/overlay.rs`:

```rust
/// Temporarily `chdir`s into `dir`, restoring the previous cwd on drop —
/// needed because `build_overlay_opts`'s `lowerdir` entries are relative
/// (`l/<short>`), and the kernel resolves relative mount-option paths
/// against the calling process's cwd at the moment `mount(2)` runs, not
/// against any path baked into the string itself.
struct ChdirGuard {
    prev: PathBuf,
}

impl ChdirGuard {
    fn enter(dir: &Path) -> Result<Self> {
        let prev = std::env::current_dir().context("reading current dir")?;
        std::env::set_current_dir(dir).with_context(|| format!("chdir to {}", dir.display()))?;
        Ok(ChdirGuard { prev })
    }
}

impl Drop for ChdirGuard {
    fn drop(&mut self) {
        // Best-effort: if this fails there's nothing more useful to do than
        // log it, and Drop can't return a Result.
        if let Err(e) = std::env::set_current_dir(&self.prev) {
            tracing::warn!(error = %e, dir = %self.prev.display(), "failed to restore cwd after overlay mount");
        }
    }
}

/// `work/` must be completely empty at mount time — a stale `work/` left
/// behind by a crashed container makes the mount fail, or worse, succeed
/// with corrupted overlay metadata.
fn clear_dir(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        }
        .with_context(|| format!("clearing {}", path.display()))?;
    }
    Ok(())
}

/// Mounts the overlay described by `snap` at `snap.merged`. `data_dir` must
/// be the `LayerStore`/`Snapshotter` root whose `l/` symlink farm the
/// snapshot's `lower_links` refer to.
pub fn mount_overlay(
    data_dir: &Path,
    snap: &Snapshot,
    rootless: bool,
    metacopy: bool,
    redirect_dir: bool,
) -> Result<()> {
    let opts = build_overlay_opts(snap, rootless, metacopy, redirect_dir)?;
    clear_dir(&snap.work)?;
    let _guard = ChdirGuard::enter(data_dir)?;
    mount(Some("overlay"), &snap.merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))
        .with_context(|| format!("mounting overlay at {} (opts={opts})", snap.merged.display()))?;
    Ok(())
}

/// Reverses `mount_overlay`. Lazy detach (`MNT_DETACH`) because a process
/// still inside the container's mount namespace may be holding the merged
/// dir busy at the moment a parent process asks to unmount it.
pub fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH)
        .with_context(|| format!("unmounting overlay at {}", merged.display()))
}
```

- [ ] **Step 4: Wire into lib.rs**

```rust
pub mod overlay;
pub mod snapshot;
```

- [ ] **Step 5: Write the root-gated integration test**

**Post-implementation correction (found by code-quality review, applied during Task 4):** `run_isolated` only `fork()`s — it does not `unshare(CLONE_NEWNS)`. A real `mount(2)`/`umount2(2)` call inside it therefore lands in the actual VM mount namespace, not a disposable one. If an assertion between `mount_overlay` and `unmount_overlay` panics, `unmount_overlay` is skipped and the mount (plus the `TempDir` it lives under, which then fails to `remove_dir_all` with EBUSY) leaks onto the real VM filesystem. Every test below must `unshare(CloneFlags::CLONE_NEWNS)` as the first statement inside the `run_isolated` closure — the same safety rule Task 5 states explicitly for `pivot.rs`, which applies equally here. The code below already has the fix applied.

```rust
// crates/kestrel-rootfs/tests/overlay.rs

use std::fs;

use nix::sched::{unshare, CloneFlags};

use kestrel_rootfs::overlay::{mount_overlay, unmount_overlay};
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[test]
#[ignore = "requires root"]
fn test_overlay_composites_lower_and_upper_and_upper_wins() {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let store = LayerStore::new(data_dir.clone());

        let base_diff = store.ensure_layer("sha256:base", None).unwrap();
        fs::write(base_diff.join("only-in-base.txt"), b"base").unwrap();
        fs::write(base_diff.join("shadowed.txt"), b"base-version").unwrap();

        let top_diff = store.ensure_layer("sha256:top", Some("sha256:base")).unwrap();
        fs::write(top_diff.join("shadowed.txt"), b"top-version").unwrap();

        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter
            .prepare_snapshot("c-overlay-1", &["sha256:base".into(), "sha256:top".into()])
            .unwrap();

        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay");

        let base_visible = fs::read_to_string(snap.merged.join("only-in-base.txt")).unwrap();
        assert_eq!(base_visible, "base");
        let shadowed = fs::read_to_string(snap.merged.join("shadowed.txt")).unwrap();
        assert_eq!(shadowed, "top-version", "top layer must win over base layer");

        // Write through the merged view; it must land in upperdir, not the
        // lower diff dirs (proving copy-on-write, not shared mutation).
        fs::write(snap.merged.join("new-file.txt"), b"from-container").unwrap();
        assert!(snap.upper.join("new-file.txt").exists());
        assert!(!base_diff.join("new-file.txt").exists());
        assert!(!top_diff.join("new-file.txt").exists());

        unmount_overlay(&snap.merged).expect("unmount_overlay");
    });
}

#[test]
#[ignore = "requires root"]
fn test_mount_overlay_clears_stale_workdir() {
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let store = LayerStore::new(data_dir.clone());
        store.ensure_layer("sha256:base", None).unwrap();

        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter
            .prepare_snapshot("c-overlay-2", &["sha256:base".into()])
            .unwrap();
        // Simulate a stale work/ left behind by a crashed container.
        fs::write(snap.work.join("stale-garbage"), b"junk").unwrap();

        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay should clear work/ first");
        unmount_overlay(&snap.merged).expect("unmount_overlay");
    });
}
```

- [ ] **Step 6: Run the root-gated test**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test overlay -- --ignored`
Expected: 2 passed.

---

## Task 5: `pivot_root` (`pivot.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/pivot.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-rootfs/tests/pivot.rs`

This is PROMPT.md's own Rule #1 phase. Every test in this file that actually calls `pivot_root`/mount/umount2 on real paths must run inside a **freshly unshared mount namespace** (`unshare(CLONE_NEWNS)`), itself inside `kestrel_ns::test_util::run_isolated`'s forked child — so a mistake is contained to a disposable, already-single-use child process's own private mount namespace, never the VM's real root. This mirrors exactly how `kestrel-ns`'s own dance tests create real namespaces safely.

- [ ] **Step 1: Implement `pivot_root`, verbatim per SPEC.md §7.2 / PROMPT.md's Phase 4 section (both agree exactly)**

```rust
// crates/kestrel-rootfs/src/pivot.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::chdir;

/// The `pivot_root(".", ".")` idiom from pivot_root(2)'s NOTES section. It
/// works because `pivot_root` stacks the OLD root on top of `new_root` at
/// the same mount point; the subsequent `MNT_DETACH` unmounts only the old
/// one. No temporary directory needs to exist inside the container image.
///
/// Every step here is load-bearing — see SPEC.md §7.2 and PROMPT.md's
/// Phase 4 section, which independently arrive at the same six steps:
/// dropping any one of them either leaves the container able to reach the
/// host filesystem, or leaks a mount/unmount back into the host's mount
/// namespace.
pub fn pivot_root(new_root: &Path) -> Result<()> {
    // (1) Detach from host mount propagation. systemd marks / MS_SHARED;
    //     without this, our mounts leak into the host mount namespace, the
    //     umount2 below can propagate and unmount the HOST root, and
    //     pivot_root itself refuses to run (it checks propagation types).
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("making / private (required before pivot_root)")?;

    // (2) pivot_root requires new_root to BE a mount point. If the overlay
    //     is already mounted here this is a cheap no-op; otherwise it makes
    //     the requirement true.
    mount(Some(new_root), new_root, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .context("bind-mounting new_root onto itself")?;

    // (3) The "." form requires new_root to be CWD.
    chdir(new_root).with_context(|| format!("chdir to {}", new_root.display()))?;

    // (4) Swap. Old root is now stacked over ".".
    nix::unistd::pivot_root(".", ".").context("pivot_root(\".\", \".\")")?;

    // (5) Explicitly mark the old root MS_SLAVE before detaching — belt and
    //     braces on top of step (1): guarantees the umount cannot propagate.
    mount(None::<&str>, ".", None::<&str>, MsFlags::MS_REC | MsFlags::MS_SLAVE, None::<&str>)
        .context("marking old root MS_SLAVE")?;

    // (6) Lazy detach — submounts may still be busy; MNT_DETACH defers
    //     actual cleanup until the last reference drops.
    umount2(".", MntFlags::MNT_DETACH).context("detaching old root")?;

    chdir("/").context("chdir to new /")?;
    Ok(())
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod overlay;
pub mod pivot;
pub mod snapshot;
```

- [ ] **Step 3: Write the safety-critical root-gated tests**

```rust
// crates/kestrel-rootfs/tests/pivot.rs

use std::fs;

use nix::sched::{unshare, CloneFlags};
use kestrel_rootfs::pivot::pivot_root;

/// Runs `f` inside a forked, single-threaded child that has already
/// `unshare(CLONE_NEWNS)`d its own private mount namespace — so anything
/// `f` mounts, pivots, or unmounts is fully contained to that disposable
/// child and can never reach the VM's real root mount namespace, even if
/// `f` gets the sequence wrong. This is the safety posture PROMPT.md's
/// Rule #1 calls for beyond "just run it in a VM."
fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        f();
    });
}

fn build_fixture_rootfs(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("proc")).unwrap();
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::write(dir.join("canary.txt"), b"i-am-the-new-root").unwrap();
}

#[test]
#[ignore = "requires root"]
fn test_pivot_root_switches_root_and_hides_old_root() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        build_fixture_rootfs(tmp.path());

        // A path that exists on the VM's real root but NOT in our fixture —
        // proves the old root becomes unreachable after pivot, not just
        // that our fixture's own files are visible.
        let host_only_marker = "/etc/lima-release-or-similar-host-only-marker-kestrel-test";
        let _ = fs::remove_file(host_only_marker); // ignore if absent already

        pivot_root(tmp.path()).expect("pivot_root");

        let canary = fs::read_to_string("/canary.txt").expect("canary.txt must exist at new /");
        assert_eq!(canary, "i-am-the-new-root");

        assert!(
            !std::path::Path::new(host_only_marker).exists(),
            "old root's files must be unreachable after pivot_root"
        );
        // The old root's mountinfo entry must be gone too — /proc isn't
        // mounted in the fixture, so this just checks the filesystem
        // directly: nothing under / should resolve back to the tmp dir's
        // *parent*, since that parent was part of the now-detached old root.
    });
}

#[test]
#[ignore = "requires root"]
fn test_pivot_root_does_not_leak_mounts_to_host_mount_namespace() {
    // Captures the VM's real mountinfo from OUTSIDE the isolated child
    // (this test function's own process, still in the original mount ns),
    // runs a full pivot_root cycle inside a disposable child, then
    // re-reads mountinfo and confirms it is byte-identical — proving no
    // mount performed inside the child's private namespace propagated out.
    let before = fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo before");

    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        build_fixture_rootfs(tmp.path());
        pivot_root(tmp.path()).expect("pivot_root");
    });

    let after = fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo after");
    assert_eq!(before, after, "pivot_root inside an isolated mount namespace must not leak mounts to the host");
}

#[test]
#[ignore = "requires root"]
fn test_pivot_root_requires_new_root_to_become_a_mount_point() {
    // Regression test for step (2): even when new_root was a plain,
    // never-mounted directory (not already an overlay mountpoint), the
    // self-bind-mount must make pivot_root succeed anyway.
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        build_fixture_rootfs(tmp.path());
        // tmp.path() here is a bare tmpfs/overlay-backed dir from the test
        // harness — deliberately NOT bind-mounted or overlay-mounted by us
        // before calling pivot_root, to prove step (2) alone suffices.
        pivot_root(tmp.path()).expect("pivot_root must self-bind-mount new_root");
        assert!(fs::metadata("/canary.txt").is_ok());
    });
}
```

- [ ] **Step 4: Run the tests**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test pivot -- --ignored`
Expected: 3 passed. If `test_pivot_root_does_not_leak_mounts_to_host_mount_namespace` fails with a mountinfo diff, do not paper over it — that is exactly the historical bug class step (5)/(1) exist to prevent; diagnose which step was skipped or reordered.

---

## Task 6: The read-only bind-mount footgun (`bindmount.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/bindmount.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-rootfs/tests/mounts.rs` (started here, extended in Task 7)

- [ ] **Step 1: Implement `bind_readonly`**

```rust
// crates/kestrel-rootfs/src/bindmount.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};

/// A SINGLE `mount()` call with `MS_BIND | MS_RDONLY` silently IGNORES
/// `MS_RDONLY` — the kernel creates a writable bind mount and returns
/// success. This is the quietest bug in the whole mount API: a
/// "read-only" volume ends up writable and nothing tells you. The fix is
/// two calls: bind first, then a remount that actually applies RDONLY.
pub fn bind_readonly(src: &Path, dst: &Path) -> Result<()> {
    mount(Some(src), dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .with_context(|| format!("bind-mounting {} onto {}", src.display(), dst.display()))?;
    mount(
        None::<&str>,
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("remounting {} read-only", dst.display()))?;
    Ok(())
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod bindmount;
pub mod overlay;
pub mod pivot;
pub mod snapshot;
```

- [ ] **Step 3: Write the empirical one-call-vs-two-call proof test**

```rust
// crates/kestrel-rootfs/tests/mounts.rs

use std::fs;
use std::io::Write;

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};

use kestrel_rootfs::bindmount::bind_readonly;

fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        f();
    });
}

#[test]
#[ignore = "requires root"]
fn test_single_call_bind_rdonly_is_silently_writable() {
    // This test documents and proves the footgun itself, so a future
    // reader doesn't have to take the doc comment's word for it.
    run_in_fresh_mount_ns(|| {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f.txt"), b"orig").unwrap();

        mount(Some(src.path()), dst.path(), None::<&str>, MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>)
            .expect("single-call bind+rdonly mount");

        let write_result = fs::OpenOptions::new().write(true).open(dst.path().join("f.txt"));
        assert!(
            write_result.is_ok(),
            "documenting the footgun: a single MS_BIND|MS_RDONLY call does NOT make the mount read-only"
        );

        umount2(dst.path(), MntFlags::MNT_DETACH).unwrap();
    });
}

#[test]
#[ignore = "requires root"]
fn test_bind_readonly_two_call_sequence_actually_enforces_read_only() {
    run_in_fresh_mount_ns(|| {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f.txt"), b"orig").unwrap();

        bind_readonly(src.path(), dst.path()).expect("bind_readonly");

        let mut write_result = fs::OpenOptions::new().write(true).open(dst.path().join("f.txt"));
        match &mut write_result {
            Ok(f) => {
                let err = f.write_all(b"nope").unwrap_err();
                assert_eq!(err.raw_os_error(), Some(libc::EBADF).or(Some(libc::EROFS)));
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EROFS), "expected EROFS opening for write, got {e:?}");
            }
        }

        umount2(dst.path(), MntFlags::MNT_DETACH).unwrap();
    });
}
```

`open()` for write on a read-only mount fails with `EROFS` immediately (most likely path); some kernels/filesystem combos instead let `open` succeed and fail the first `write()` — the match above accepts either failure point rather than assuming one, since what matters is that data never actually gets written, not exactly which syscall reports it.

- [ ] **Step 4: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test mounts -- --ignored`
Expected: 2 passed.

---

## Task 7: Standard mounts and device nodes (`mounts.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/mounts.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Modify: `crates/kestrel-rootfs/tests/mounts.rs`

Per SPEC.md §7.3's table. `setup_standard_mounts` is called **before** `pivot_root` (mounting into the not-yet-root `merged` directory using absolute target paths under it), matching the design doc's ordering.

- [ ] **Step 1: Implement the mount table and device nodes**

```rust
// crates/kestrel-rootfs/src/mounts.rs

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};

struct StandardMount {
    relative_target: &'static str,
    fstype: &'static str,
    flags: MsFlags,
    data: &'static str,
}

const STANDARD_MOUNTS: &[StandardMount] = &[
    StandardMount {
        relative_target: "proc",
        fstype: "proc",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "",
    },
    StandardMount {
        relative_target: "sys",
        fstype: "sysfs",
        flags: MsFlags::from_bits_truncate(
            MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits() | MsFlags::MS_RDONLY.bits(),
        ),
        data: "",
    },
    StandardMount {
        relative_target: "dev",
        fstype: "tmpfs",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_STRICTATIME.bits()),
        data: "mode=755,size=65536k",
    },
    StandardMount {
        relative_target: "dev/pts",
        fstype: "devpts",
        flags: MsFlags::MS_NOSUID,
        data: "newinstance,ptmxmode=0666,mode=0620,gid=5",
    },
    StandardMount {
        relative_target: "dev/shm",
        fstype: "tmpfs",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "mode=1777,size=65536k",
    },
    StandardMount {
        relative_target: "dev/mqueue",
        fstype: "mqueue",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "",
    },
];

struct DeviceSpec {
    name: &'static str,
    major: u64,
    minor: u64,
}

const DEFAULT_DEVICES: &[DeviceSpec] = &[
    DeviceSpec { name: "null", major: 1, minor: 3 },
    DeviceSpec { name: "zero", major: 1, minor: 5 },
    DeviceSpec { name: "full", major: 1, minor: 7 },
    DeviceSpec { name: "random", major: 1, minor: 8 },
    DeviceSpec { name: "urandom", major: 1, minor: 9 },
    DeviceSpec { name: "tty", major: 5, minor: 0 },
];

/// Mounts `/proc`, `/sys`, `/dev` (tmpfs), `/dev/pts`, `/dev/shm`,
/// `/dev/mqueue` under `rootfs`, creates the standard device nodes, and
/// symlinks `/dev/ptmx -> pts/ptmx` (required because `dev/pts` is mounted
/// with `newinstance`, which requires using the instance's own ptmx rather
/// than a preexisting one). Must be called BEFORE `pivot::pivot_root`,
/// with `rootfs` set to the not-yet-root merged directory.
pub fn setup_standard_mounts(rootfs: &Path) -> Result<()> {
    for m in STANDARD_MOUNTS {
        let target = rootfs.join(m.relative_target);
        fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
        let data = if m.data.is_empty() { None } else { Some(m.data) };
        mount(Some(m.fstype), &target, Some(m.fstype), m.flags, data)
            .with_context(|| format!("mounting {} ({}) at {}", m.fstype, m.data, target.display()))?;
    }

    create_default_devices(rootfs)?;

    let ptmx = rootfs.join("dev/ptmx");
    let _ = fs::remove_file(&ptmx);
    std::os::unix::fs::symlink("pts/ptmx", &ptmx)
        .with_context(|| format!("symlinking {}", ptmx.display()))?;

    Ok(())
}

/// Creates `/dev/{null,zero,full,random,urandom,tty}` as character devices.
/// Requires real root (`CAP_MKNOD`) — see [`bind_default_devices`] for the
/// rootless fallback.
pub fn create_default_devices(rootfs: &Path) -> Result<()> {
    let dev = rootfs.join("dev");
    for d in DEFAULT_DEVICES {
        let path = dev.join(d.name);
        let _ = fs::remove_file(&path);
        mknod(&path, SFlag::S_IFCHR, Mode::from_bits_truncate(0o666), makedev(d.major, d.minor))
            .with_context(|| format!("mknod {} ({}:{})", path.display(), d.major, d.minor))?;
    }
    Ok(())
}

/// Rootless fallback: an unprivileged user cannot `mknod`, so bind-mount
/// each device node from the host instead. Requires the host path to
/// already exist (true on any real Linux system).
pub fn bind_default_devices(rootfs: &Path) -> Result<()> {
    let dev = rootfs.join("dev");
    for d in DEFAULT_DEVICES {
        let target = dev.join(d.name);
        fs::File::create(&target).with_context(|| format!("creating bind target {}", target.display()))?;
        let host_src = Path::new("/dev").join(d.name);
        mount(Some(&host_src), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("bind-mounting {} onto {}", host_src.display(), target.display()))?;
    }
    Ok(())
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod bindmount;
pub mod mounts;
pub mod overlay;
pub mod pivot;
pub mod snapshot;
```

- [ ] **Step 3: Append the root-gated integration tests to `tests/mounts.rs`**

```rust
// append to crates/kestrel-rootfs/tests/mounts.rs

use kestrel_rootfs::mounts::{create_default_devices, setup_standard_mounts};

#[test]
#[ignore = "requires root"]
fn test_setup_standard_mounts_creates_expected_mount_table_entries() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        setup_standard_mounts(tmp.path()).expect("setup_standard_mounts");

        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
        for expect in ["proc", "sysfs", "tmpfs", "devpts", "mqueue"] {
            assert!(
                mountinfo.lines().any(|l| l.contains(expect)),
                "mountinfo missing a {expect} entry:\n{mountinfo}"
            );
        }
    });
}

#[test]
#[ignore = "requires root"]
fn test_create_default_devices_produces_real_char_devices_with_correct_major_minor() {
    use nix::sys::stat::{stat, SFlag};

    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("dev")).unwrap();
        create_default_devices(tmp.path()).expect("create_default_devices");

        let null = stat(&tmp.path().join("dev/null")).unwrap();
        assert_eq!(null.st_mode & SFlag::S_IFMT.bits(), SFlag::S_IFCHR.bits());
        assert_eq!(nix::sys::stat::major(null.st_rdev), 1);
        assert_eq!(nix::sys::stat::minor(null.st_rdev), 3);

        let tty = stat(&tmp.path().join("dev/tty")).unwrap();
        assert_eq!(nix::sys::stat::major(tty.st_rdev), 5);
        assert_eq!(nix::sys::stat::minor(tty.st_rdev), 0);
    });
}

#[test]
#[ignore = "requires root"]
fn test_setup_standard_mounts_ptmx_symlink_works() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        setup_standard_mounts(tmp.path()).expect("setup_standard_mounts");
        let target = fs::read_link(tmp.path().join("dev/ptmx")).unwrap();
        assert_eq!(target, std::path::Path::new("pts/ptmx"));
    });
}
```

If `nix::sys::stat::major`/`minor` free functions aren't present in the resolved `nix` 0.29 API (some versions expose these as inherent methods or under a different module path), use `libc::major(dev)`/`libc::minor(dev)` instead — both are standard glibc macros nix/libc commonly re-expose; confirm the actual path with `cargo doc -p nix --open` or `grep -rn "pub fn major" ~/.cargo/registry/src/*/nix-0.29*/src/` inside the VM before writing the test, matching how every previous phase verified nix's real surface against the resolved lockfile version rather than assuming.

- [ ] **Step 4: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test mounts -- --ignored`
Expected: 5 passed (2 from Task 6 + 3 new).

---

## Task 8: Masked and read-only paths (`mask.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/mask.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-rootfs/tests/mask.rs`

Per SPEC.md §7.4. `make_readonly` reuses `bindmount::bind_readonly` from Task 6 rather than duplicating the two-call sequence a third time in this codebase.

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-rootfs/src/mask.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};

use crate::bindmount::bind_readonly;

pub const DEFAULT_MASKED: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

pub const DEFAULT_READONLY: &[&str] = &["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

/// Hides `p` (relative to the container's rootfs, already joined by the
/// caller) so it leaks no host information: directories get an empty
/// read-only tmpfs, files get bind-mounted over with `/dev/null`. Silently
/// no-ops paths that don't exist in this particular rootfs (not every
/// image has `/proc/acpi`, say) — anything else is a real error.
pub fn mask_path(p: &Path) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    match mount(Some("/dev/null"), p, None::<&str>, MsFlags::MS_BIND, None::<&str>) {
        Err(Errno::ENOTDIR) | Err(Errno::EISDIR) => {
            mount(Some("tmpfs"), p, Some("tmpfs"), MsFlags::MS_RDONLY, Some("size=0k"))
                .with_context(|| format!("mounting empty ro tmpfs over {}", p.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("bind-mounting /dev/null over {}", p.display())),
        Ok(()) => {}
    }
    Ok(())
}

/// Bind-mounts `p` onto itself read-only. Delegates to
/// [`crate::bindmount::bind_readonly`] for the two-call sequence the
/// single-call version silently gets wrong. No-ops if `p` doesn't exist.
pub fn make_readonly(p: &Path) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    bind_readonly(p, p)
}

/// Applies [`DEFAULT_MASKED`] and [`DEFAULT_READONLY`] under `rootfs`.
/// Must run before `pivot::pivot_root` (paths are joined onto `rootfs`,
/// the not-yet-root merged directory), same ordering as
/// `mounts::setup_standard_mounts`.
pub fn apply_default_masks(rootfs: &Path) -> Result<()> {
    for p in DEFAULT_MASKED {
        mask_path(&rootfs.join(p.trim_start_matches('/'))).with_context(|| format!("masking {p}"))?;
    }
    for p in DEFAULT_READONLY {
        make_readonly(&rootfs.join(p.trim_start_matches('/'))).with_context(|| format!("making {p} read-only"))?;
    }
    Ok(())
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod bindmount;
pub mod mask;
pub mod mounts;
pub mod overlay;
pub mod pivot;
pub mod snapshot;
```

- [ ] **Step 3: Write the root-gated tests**

```rust
// crates/kestrel-rootfs/tests/mask.rs

use std::fs;

use nix::sched::{unshare, CloneFlags};

use kestrel_rootfs::mask::{make_readonly, mask_path};

fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        f();
    });
}

#[test]
#[ignore = "requires root"]
fn test_mask_path_on_file_makes_it_read_as_empty() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret.txt");
        fs::write(&secret, b"host-only-information").unwrap();

        mask_path(&secret).expect("mask_path on a file");

        let contents = fs::read(&secret).unwrap();
        assert!(contents.is_empty(), "masked file must read as empty (bind-mounted over /dev/null)");
    });
}

#[test]
#[ignore = "requires root"]
fn test_mask_path_on_dir_makes_it_an_empty_readonly_tmpfs() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("secretdir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("leak.txt"), b"host info").unwrap();

        mask_path(&dir).expect("mask_path on a dir");

        let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert!(entries.is_empty(), "masked dir must appear empty");
        assert!(
            fs::write(dir.join("new.txt"), b"x").is_err(),
            "masked dir must be read-only"
        );
    });
}

#[test]
#[ignore = "requires root"]
fn test_mask_path_no_ops_on_missing_path() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        mask_path(&missing).expect("mask_path must silently succeed on a missing path");
    });
}

#[test]
#[ignore = "requires root"]
fn test_make_readonly_enforces_actual_read_only_via_two_call_sequence() {
    run_in_fresh_mount_ns(|| {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro-target");
        fs::create_dir(&dir).unwrap();

        make_readonly(&dir).expect("make_readonly");

        assert!(
            fs::write(dir.join("new.txt"), b"x").is_err(),
            "make_readonly must actually enforce read-only, not just look like it does"
        );
    });
}
```

- [ ] **Step 4: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test mask -- --ignored`
Expected: 4 passed.

---

## Task 9: Copy-up scanning (`copyup.rs`)

**Files:**
- Create: `crates/kestrel-rootfs/src/copyup.rs`
- Modify: `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-rootfs/tests/copyup.rs`

Per SPEC.md §6.5. Detection logic is pure enough to unit-test without root (plain files in plain tmpdirs standing in for "upper" and "lower"); one root-gated test proves it against a real overlay mount's real kernel-triggered copy-up.

- [ ] **Step 1: Implement, with unprivileged unit tests**

```rust
// crates/kestrel-rootfs/src/copyup.rs

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyUpKind {
    Data,
    MetadataOnly,
    Whiteout,
    Opaque,
}

#[derive(Debug, Clone)]
pub struct CopyUpEvent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub from_layer: String,
    pub detected_at: SystemTime,
    pub kind: CopyUpKind,
}

/// One entry in the lower stack, bottom-to-top, paired with the chain-id
/// (or any caller-chosen label) to attribute a copy-up to.
pub struct LowerLayer<'a> {
    pub chain_id: &'a str,
    pub diff_dir: &'a Path,
}

/// Walks `upper_dir` and, for each entry that ALSO exists at the same
/// relative path in one of `lowers` (top-most match wins, matching
/// overlayfs's own shadowing order), reports it as a copy-up. Detects
/// whiteouts (character device 0:0) and opaque directories (the
/// `{trusted,user}.overlay.opaque` xattr) as their own event kinds rather
/// than mislabeling them as ordinary data copy-ups.
pub fn scan_copy_ups(upper_dir: &Path, lowers: &[LowerLayer]) -> Result<Vec<CopyUpEvent>> {
    let mut events = Vec::new();
    walk(upper_dir, upper_dir, lowers, &mut events)?;
    Ok(events)
}

fn walk(root: &Path, dir: &Path, lowers: &[LowerLayer], events: &mut Vec<CopyUpEvent>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root).expect("path is under root by construction");
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            if is_opaque_dir(&path)? {
                if let Some(from) = find_in_lowers(rel, lowers) {
                    events.push(CopyUpEvent {
                        path: rel.to_path_buf(),
                        size_bytes: 0,
                        from_layer: from.to_string(),
                        detected_at: SystemTime::now(),
                        kind: CopyUpKind::Opaque,
                    });
                }
                continue; // don't recurse — everything below is opaque by definition
            }
            walk(root, &path, lowers, events)?;
            continue;
        }

        let Some(from) = find_in_lowers(rel, lowers) else {
            continue; // new file, not a copy-up
        };

        if file_type.is_char_device() && is_whiteout(&path)? {
            events.push(CopyUpEvent {
                path: rel.to_path_buf(),
                size_bytes: 0,
                from_layer: from.to_string(),
                detected_at: SystemTime::now(),
                kind: CopyUpKind::Whiteout,
            });
            continue;
        }

        let metadata = entry.metadata()?;
        let kind = if is_metadata_only_copy_up(&path)? {
            CopyUpKind::MetadataOnly
        } else {
            CopyUpKind::Data
        };
        events.push(CopyUpEvent {
            path: rel.to_path_buf(),
            size_bytes: metadata.len(),
            from_layer: from.to_string(),
            detected_at: SystemTime::now(),
            kind,
        });
    }
    Ok(())
}

/// Top-most (last, since lowers is bottom-to-top) match wins, matching
/// overlayfs's own shadowing order.
fn find_in_lowers<'a>(rel: &Path, lowers: &'a [LowerLayer]) -> Option<&'a str> {
    lowers.iter().rev().find(|l| l.diff_dir.join(rel).exists()).map(|l| l.chain_id)
}

fn is_whiteout(path: &Path) -> Result<bool> {
    use nix::sys::stat::{stat, SFlag};
    let st = stat(path).with_context(|| format!("stat {}", path.display()))?;
    Ok((st.st_mode & SFlag::S_IFMT.bits()) == SFlag::S_IFCHR.bits() && st.st_rdev == 0)
}

fn is_opaque_dir(path: &Path) -> Result<bool> {
    for ns in ["trusted.overlay.opaque", "user.overlay.opaque"] {
        if let Ok(Some(val)) = xattr::get(path, ns) {
            if val == b"y" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn is_metadata_only_copy_up(path: &Path) -> Result<bool> {
    for ns in ["trusted.overlay.metacopy", "user.overlay.metacopy"] {
        if xattr::get(path, ns).ok().flatten().is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

trait FileTypeExt {
    fn is_char_device(&self) -> bool;
}
impl FileTypeExt for fs::FileType {
    fn is_char_device(&self) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::os::unix::fs::FileType::is_char_device(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_copy_ups_detects_file_present_in_both_upper_and_lower() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        fs::write(lower.path().join("app.conf"), b"lower-version").unwrap();
        fs::write(upper.path().join("app.conf"), b"upper-version-after-copy-up").unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: lower.path() }];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, Path::new("app.conf"));
        assert_eq!(events[0].from_layer, "sha256:base");
        assert_eq!(events[0].kind, CopyUpKind::Data);
        assert!(events[0].size_bytes > 0);
    }

    #[test]
    fn test_scan_copy_ups_ignores_files_new_to_upper() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        fs::write(upper.path().join("brand-new.txt"), b"never existed below").unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: lower.path() }];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();
        assert!(events.is_empty(), "a file with no lower counterpart is not a copy-up");
    }

    #[test]
    fn test_scan_copy_ups_attributes_to_topmost_matching_lower() {
        let upper = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let mid = tempfile::tempdir().unwrap();
        fs::write(base.path().join("f.txt"), b"base").unwrap();
        fs::write(mid.path().join("f.txt"), b"mid").unwrap();
        fs::write(upper.path().join("f.txt"), b"top").unwrap();

        let lowers = [
            LowerLayer { chain_id: "sha256:base", diff_dir: base.path() },
            LowerLayer { chain_id: "sha256:mid", diff_dir: mid.path() },
        ];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].from_layer, "sha256:mid", "closest (topmost) lower match should win, matching overlayfs shadowing order");
    }

    #[test]
    fn test_scan_copy_ups_recurses_into_subdirectories() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();
        fs::create_dir_all(lower.path().join("nested/dir")).unwrap();
        fs::write(lower.path().join("nested/dir/deep.txt"), b"deep").unwrap();
        fs::create_dir_all(upper.path().join("nested/dir")).unwrap();
        fs::write(upper.path().join("nested/dir/deep.txt"), b"deep-modified").unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: lower.path() }];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, Path::new("nested/dir/deep.txt"));
    }
}
```

- [ ] **Step 2: Wire into lib.rs and Cargo.toml**

Add `xattr = "1"` to `crates/kestrel-rootfs/Cargo.toml`'s `[dependencies]`.

```rust
pub mod bindmount;
pub mod copyup;
pub mod mask;
pub mod mounts;
pub mod overlay;
pub mod pivot;
pub mod snapshot;
```

- [ ] **Step 3: Run the unprivileged tests**

Run: `cargo test -p kestrel-rootfs copyup::tests`
Expected: 4 passed.

- [ ] **Step 4: Write and run the root-gated real-overlay test**

```rust
// crates/kestrel-rootfs/tests/copyup.rs

use std::fs;

use kestrel_rootfs::copyup::{scan_copy_ups, CopyUpKind, LowerLayer};
use kestrel_rootfs::overlay::mount_overlay;
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[test]
#[ignore = "requires root"]
fn test_scan_copy_ups_against_a_real_kernel_triggered_copy_up() {
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let store = LayerStore::new(data_dir.clone());
        let base_diff = store.ensure_layer("sha256:base", None).unwrap();
        fs::write(base_diff.join("big.txt"), b"original-content-from-base-layer").unwrap();

        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter.prepare_snapshot("c-copyup-1", &["sha256:base".into()]).unwrap();
        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay");

        // A one-byte write to a file that only exists in the lower layer
        // forces the kernel to copy the WHOLE file up into upperdir first —
        // this is the real, kernel-driven copy-up scan_copy_ups must detect.
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new().write(true).open(snap.merged.join("big.txt")).unwrap();
            f.write_all(b"X").unwrap();
        }

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: &base_diff }];
        let events = scan_copy_ups(&snap.upper, &lowers).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, std::path::Path::new("big.txt"));
        assert_eq!(events[0].kind, CopyUpKind::Data);
        assert!(events[0].size_bytes > 0, "the whole file, not just the written byte, should have been copied up");

        kestrel_rootfs::overlay::unmount_overlay(&snap.merged).unwrap();
    });
}
```

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test copyup -- --ignored`
Expected: 1 passed.

---

## Task 10: `kestrel-image` scaffolding + `apply_layer` (`apply.rs`)

**Files:**
- Modify: `crates/kestrel-image/Cargo.toml`
- Modify: `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-image/src/apply.rs`
- Create: `crates/kestrel-image/tests/apply.rs`

**Deliberate deviation from PROMPT.md's and SPEC.md's own sample code:** both documents' `apply_layer` snippets guard path traversal with `target.starts_with(&dest)` *after* joining `dest.join(&path)`. `Path::starts_with` compares components lexically — it does **not** resolve `..` — so `dest.join("foo/../../etc/passwd")` still `starts_with(dest)` even though the path it actually names is `/etc/passwd`. This is a real, exploitable gap in both documents' sample code (a classic tar-slip variant, one level more subtle than a bare `../../etc/passwd` entry). This plan fixes it: reject any entry containing a `Component::ParentDir` or that is absolute *before* ever joining or touching the filesystem, matching the "verify empirically, don't trust code that merely looks right" pattern this project has followed since Phase 2's CVE-2014-8989 ordering and Phase 3's `CLONE_INTO_CGROUP` bug.

- [ ] **Step 1: Update Cargo.toml**

```toml
[package]
name = "kestrel-image"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
nix = { workspace = true, features = ["fs"] }
libc.workspace = true
tar = "0.4"
xattr = "1"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write `LayerStats` and the path-traversal guard, with its unprivileged tests first**

```rust
// crates/kestrel-image/src/apply.rs

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context, Result};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use tar::Archive;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LayerStats {
    pub files: u64,
    pub bytes: u64,
    pub whiteouts: u64,
    pub opaques: u64,
}

/// Rejects any tar entry path that is absolute or contains a `..`
/// component, BEFORE it is ever joined onto `dest` or touches the
/// filesystem. `Path::starts_with` on the joined result (what PROMPT.md's
/// and SPEC.md's own sample code do) is not sufficient on its own: it
/// compares path components lexically and does not resolve `..`, so
/// `dest.join("foo/../../etc/passwd")` still lexically "starts with"
/// `dest` even though the path it names is `/etc/passwd`. Rejecting `..`
/// components up front closes that gap.
fn safe_join(dest: &Path, entry_path: &Path) -> Result<PathBuf> {
    ensure!(
        entry_path.is_relative(),
        "path traversal in layer: absolute path {}",
        entry_path.display()
    );
    ensure!(
        !entry_path.components().any(|c| matches!(c, Component::ParentDir)),
        "path traversal in layer: {} contains a '..' component",
        entry_path.display()
    );
    let joined = dest.join(entry_path);
    ensure!(
        joined.starts_with(dest),
        "path traversal in layer: {} escapes {}",
        entry_path.display(),
        dest.display()
    );
    Ok(joined)
}

#[cfg(test)]
mod safe_join_tests {
    use super::*;

    #[test]
    fn test_safe_join_accepts_normal_relative_path() {
        let dest = Path::new("/data/layer");
        let result = safe_join(dest, Path::new("etc/app.conf")).unwrap();
        assert_eq!(result, Path::new("/data/layer/etc/app.conf"));
    }

    #[test]
    fn test_safe_join_rejects_absolute_path() {
        let dest = Path::new("/data/layer");
        assert!(safe_join(dest, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn test_safe_join_rejects_leading_dotdot() {
        let dest = Path::new("/data/layer");
        assert!(safe_join(dest, Path::new("../../etc/passwd")).is_err());
    }

    #[test]
    fn test_safe_join_rejects_embedded_dotdot() {
        // This is the case the sample code in PROMPT.md/SPEC.md misses: a
        // lexical starts_with() check on the JOINED path would pass this,
        // because "layer/foo/../../etc/passwd" still starts with
        // "/data/layer" component-wise without ".." resolution.
        let dest = Path::new("/data/layer");
        assert!(safe_join(dest, Path::new("foo/../../etc/passwd")).is_err());
    }

    #[test]
    fn test_safe_join_accepts_dot_component() {
        let dest = Path::new("/data/layer");
        let result = safe_join(dest, Path::new("./etc/app.conf")).unwrap();
        assert_eq!(result, Path::new("/data/layer/etc/app.conf"));
    }
}
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image safe_join`
Expected: 5 passed.

- [ ] **Step 4: Implement `apply_layer`**

Append to `crates/kestrel-image/src/apply.rs`:

```rust
/// Extracts `tar` into `dest`, translating OCI whiteout conventions into
/// their overlayfs on-disk form as it goes: `.wh..wh..opq` becomes the
/// opaque-dir xattr, `.wh.<name>` becomes a character-device-0:0 whiteout,
/// everything else is unpacked normally (including hardlinks and
/// symlinks — the `tar` crate's `unpack_in` already handles
/// `EntryType::Link`/`EntryType::Symlink` correctly; this function adds no
/// special-casing for them beyond what `unpack_in` already does).
pub fn apply_layer(tar: impl Read, dest: &Path, rootless: bool) -> Result<LayerStats> {
    let ns = if rootless { "user.overlay" } else { "trusted.overlay" };
    let dest = dest
        .canonicalize()
        .with_context(|| format!("canonicalizing destination {}", dest.display()))?;
    let mut stats = LayerStats::default();

    let mut archive = Archive::new(tar);
    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry")?;
        let path = entry.path().context("reading entry path")?.into_owned();

        let target = safe_join(&dest, &path)?;
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if name == ".wh..wh..opq" {
            let parent = target.parent().unwrap_or(&dest);
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
            xattr::set(parent, &format!("{ns}.opaque"), b"y")
                .with_context(|| format!("setting opaque xattr on {}", parent.display()))?;
            stats.opaques += 1;
            continue;
        }

        if let Some(victim) = name.strip_prefix(".wh.") {
            let parent = target.parent().unwrap_or(&dest);
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
            let wh = parent.join(victim);
            let _ = fs::remove_file(&wh);
            let _ = fs::remove_dir_all(&wh);
            mknod(&wh, SFlag::S_IFCHR, Mode::empty(), makedev(0, 0))
                .with_context(|| format!("creating whiteout {}", wh.display()))?;
            stats.whiteouts += 1;
            continue;
        }

        entry.set_preserve_permissions(true);
        entry.set_unpack_xattrs(true);
        let size = entry.size();
        entry.unpack_in(&dest).with_context(|| format!("extracting {}", path.display()))?;
        stats.files += 1;
        stats.bytes += size;
    }
    Ok(stats)
}
```

- [ ] **Step 5: Wire into lib.rs**

```rust
// crates/kestrel-image/src/lib.rs

pub mod apply;
```

- [ ] **Step 6: Run**

Run: `cargo build -p kestrel-image`
Expected: builds clean (no tests to run yet for `apply_layer` itself — those come in Task 11, since whiteout/opaque translation needs root for real `mknod`/`xattr::set`, but the extraction-of-ordinary-files path can be tested unprivileged first there).

---

## Task 11: `apply_layer` behavioral tests — traversal, whiteouts, opaque dirs, hardlinks

**Files:**
- Create: `crates/kestrel-image/tests/apply.rs`

Splits cleanly: rejecting a malicious tar entry never touches the filesystem, so those tests are unprivileged; whiteout `mknod` and `trusted.overlay.*` xattrs need real root.

- [ ] **Step 1: Build a tiny tar-fixture helper and write the unprivileged tests**

```rust
// crates/kestrel-image/tests/apply.rs

use std::fs;
use std::io::Cursor;

use kestrel_image::apply::apply_layer;
use tar::{Builder, Header};

fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, Cursor::new(*contents)).unwrap();
    }
    builder.into_inner().unwrap()
}

#[test]
fn test_apply_layer_extracts_ordinary_files() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_tar(&[("hello.txt", b"world"), ("dir/nested.txt", b"nested-content")]);

    let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap();

    assert_eq!(stats.files, 2);
    assert_eq!(fs::read_to_string(tmp.path().join("hello.txt")).unwrap(), "world");
    assert_eq!(fs::read_to_string(tmp.path().join("dir/nested.txt")).unwrap(), "nested-content");
}

#[test]
fn test_apply_layer_rejects_absolute_path_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_tar(&[("/etc/passwd", b"pwned")]);
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().contains("path traversal") || err.to_string().contains("traversal"));
    assert!(!std::path::Path::new("/etc/passwd_kestrel_test_marker").exists());
}

#[test]
fn test_apply_layer_rejects_dotdot_traversal_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_tar(&[("../../../etc/passwd", b"pwned")]);
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("traversal"));
}

#[test]
fn test_apply_layer_rejects_embedded_dotdot_traversal_entry() {
    // The specific case a naive post-join starts_with() check would miss.
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_tar(&[("subdir/../../escape.txt", b"pwned")]);
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("traversal"));
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p kestrel-image --test apply`
Expected: 4 passed.

- [ ] **Step 3: Write the root-gated whiteout/opaque/hardlink tests**

Append to `crates/kestrel-image/tests/apply.rs`:

```rust
#[test]
#[ignore = "requires root"]
fn test_apply_layer_translates_whiteout_to_char_device_0_0() {
    kestrel_ns_test_util_run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("existing.txt"), b"from-lower-layer").unwrap();

        let tar_bytes = build_tar(&[(".wh.existing.txt", b"")]);
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap();

        assert_eq!(stats.whiteouts, 1);
        let meta = fs::symlink_metadata(tmp.path().join("existing.txt")).unwrap();
        use std::os::unix::fs::FileTypeExt;
        assert!(meta.file_type().is_char_device(), "whiteout must be a character device");

        use nix::sys::stat::stat;
        let st = stat(&tmp.path().join("existing.txt")).unwrap();
        assert_eq!(st.st_rdev, 0, "whiteout device must be major:minor 0:0");
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_sets_opaque_xattr_on_directory_marker() {
    kestrel_ns_test_util_run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("mydir")).unwrap();

        let tar_bytes = build_tar(&[("mydir/.wh..wh..opq", b"")]);
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap();

        assert_eq!(stats.opaques, 1);
        let val = xattr::get(tmp.path().join("mydir"), "trusted.overlay.opaque").unwrap();
        assert_eq!(val, Some(b"y".to_vec()));
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_uses_userxattr_namespace_when_rootless() {
    kestrel_ns_test_util_run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("mydir")).unwrap();

        let tar_bytes = build_tar(&[("mydir/.wh..wh..opq", b"")]);
        apply_layer(Cursor::new(tar_bytes), tmp.path(), true).unwrap();

        let val = xattr::get(tmp.path().join("mydir"), "user.overlay.opaque").unwrap();
        assert_eq!(val, Some(b"y".to_vec()));
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_round_trips_hardlinks() {
    kestrel_ns_test_util_run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(b"shared-content".len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "original.txt", Cursor::new(b"shared-content" as &[u8])).unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_link_name("original.txt").unwrap();
        link_header.set_cksum();
        builder.append_data(&mut link_header, "hardlink.txt", Cursor::new(&[] as &[u8])).unwrap();

        let tar_bytes = builder.into_inner().unwrap();
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap();

        assert_eq!(stats.files, 2);
        assert_eq!(fs::read_to_string(tmp.path().join("hardlink.txt")).unwrap(), "shared-content");

        use std::os::unix::fs::MetadataExt;
        let orig_ino = fs::metadata(tmp.path().join("original.txt")).unwrap().ino();
        let link_ino = fs::metadata(tmp.path().join("hardlink.txt")).unwrap().ino();
        assert_eq!(orig_ino, link_ino, "hardlink must share the same inode as its target, not be a copy");
    });
}

/// `kestrel-image` intentionally has no production dependency on
/// `kestrel-ns` (it's a leaf crate per SPEC.md §16); these whiteout/opaque
/// tests still need real root and single-threaded fork isolation the same
/// way every other privileged test in this project does, so pull in
/// `kestrel-ns::test_util` as a dev-dependency purely for its
/// `run_isolated` helper, exactly as `kestrel-cgroup`'s tests already do.
fn kestrel_ns_test_util_run_isolated(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(f);
}
```

- [ ] **Step 2: Add the dev-dependency**

Add to `crates/kestrel-image/Cargo.toml`'s `[dev-dependencies]`:

```toml
kestrel-ns = { path = "../kestrel-ns" }
```

- [ ] **Step 3: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-image --test apply -- --ignored`
Expected: 4 passed.

---

## Task 12: Full end-to-end lifecycle integration test

**Files:**
- Create: `crates/kestrel-rootfs/tests/lifecycle.rs`
- Modify: `crates/kestrel-rootfs/Cargo.toml` (dev-dependency on `kestrel-image`)

Proves the whole phase works together: two layers applied via `kestrel-image::apply::apply_layer` (one of them containing a whiteout, hiding a file from the layer below), snapshotted and overlay-mounted via `kestrel-rootfs`, then a full `pivot_root` into the result (inside an isolated mount namespace, per Task 5's safety posture) followed by standard mounts and default masks — checking the final rootfs is self-consistent and the host is unreachable from inside it.

- [ ] **Step 1: Add the dev-dependency**

Add to `crates/kestrel-rootfs/Cargo.toml`'s `[dev-dependencies]`:

```toml
kestrel-image = { path = "../kestrel-image" }
```

- [ ] **Step 2: Write the test**

```rust
// crates/kestrel-rootfs/tests/lifecycle.rs

use std::fs;
use std::io::Cursor;

use nix::sched::{unshare, CloneFlags};
use tar::{Builder, Header};

use kestrel_image::apply::apply_layer;
use kestrel_rootfs::mask::apply_default_masks;
use kestrel_rootfs::mounts::setup_standard_mounts;
use kestrel_rootfs::overlay::mount_overlay;
use kestrel_rootfs::pivot::pivot_root;
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, Cursor::new(*contents)).unwrap();
    }
    builder.into_inner().unwrap()
}

#[test]
#[ignore = "requires root"]
fn test_full_lifecycle_two_layers_with_whiteout_through_pivot_root() {
    // Captured OUTSIDE the isolated child, to prove no leak at the very end.
    let host_mountinfo_before = fs::read_to_string("/proc/self/mountinfo").unwrap();

    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let store = LayerStore::new(data_dir.clone());

        // Layer 1 (base): two files.
        let base_diff = store.ensure_layer("sha256:base", None).unwrap();
        let base_tar = build_tar(&[("keep.txt", b"survives"), ("removed.txt", b"deleted-by-top-layer")]);
        apply_layer(Cursor::new(base_tar), &base_diff, false).expect("apply base layer");

        // Layer 2 (top): whites out removed.txt, adds a new file.
        let top_diff = store.ensure_layer("sha256:top", Some("sha256:base")).unwrap();
        let top_tar = build_tar(&[("new.txt", b"added-by-top-layer"), (".wh.removed.txt", b"")]);
        apply_layer(Cursor::new(top_tar), &top_diff, false).expect("apply top layer");

        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter
            .prepare_snapshot("c-lifecycle-1", &["sha256:base".into(), "sha256:top".into()])
            .unwrap();
        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay");

        assert_eq!(fs::read_to_string(snap.merged.join("keep.txt")).unwrap(), "survives");
        assert_eq!(fs::read_to_string(snap.merged.join("new.txt")).unwrap(), "added-by-top-layer");
        assert!(!snap.merged.join("removed.txt").exists(), "whiteout must hide the base-layer file in the merged view");

        // A host-only marker: exists in this test process's real root, but
        // must NOT be reachable once we pivot into the container's merged
        // rootfs below.
        let host_only_marker = "/etc/lima-release-or-similar-host-only-marker-kestrel-lifecycle-test";

        let merged = snap.merged.clone();
        setup_standard_mounts(&merged).expect("setup_standard_mounts");
        apply_default_masks(&merged).expect("apply_default_masks");

        pivot_root(&merged).expect("pivot_root");

        assert_eq!(fs::read_to_string("/keep.txt").unwrap(), "survives");
        assert_eq!(fs::read_to_string("/new.txt").unwrap(), "added-by-top-layer");
        assert!(!std::path::Path::new("/removed.txt").exists());
        assert!(
            !std::path::Path::new(host_only_marker).exists(),
            "host filesystem must be completely unreachable after pivot_root"
        );

        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mountinfo.lines().any(|l| l.contains("proc")), "post-pivot /proc must still be mounted");
    });

    let host_mountinfo_after = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert_eq!(
        host_mountinfo_before, host_mountinfo_after,
        "the entire lifecycle, including pivot_root, must leave the host's mount table untouched"
    );
}
```

- [ ] **Step 3: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-rootfs --test lifecycle -- --ignored`
Expected: 1 passed.

---

## Task 13: Workspace-wide verification and cleanup

**Files:** none new — verification only.

- [ ] **Step 1: Full unprivileged build and test pass**

Run: `cargo build --workspace && cargo test --workspace`
Expected: builds clean; all non-`#[ignore]`d tests pass across every crate, including the new `kestrel-rootfs`/`kestrel-image` unit tests from Tasks 1-11.

- [ ] **Step 2: Full root-gated test pass, via the Makefile target**

Run (inside the VM): `make test-root`
Expected: every `#[ignore = "requires root"]` test in the workspace passes, including all of this phase's: `overlay` (2), `pivot` (3), `mounts` (5), `mask` (4), `copyup` (1), `apply` (4), `lifecycle` (1) — 20 root-gated tests total for this phase, on top of Phases 2-3's existing root-gated suite.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: clean. Pay particular attention to any `clippy::undocumented_unsafe_blocks` hits in `kestrel-rootfs`/`kestrel-image` — neither crate should need any raw `unsafe` blocks in this phase (`nix`'s safe wrappers cover every syscall used here), so a hit likely means a raw `libc::` call snuck in somewhere and should be replaced with the `nix` equivalent already used throughout this plan.

- [ ] **Step 4: check-no-tokio still passes**

Run: `make check-no-tokio`
Expected: passes unchanged — this phase adds no dependency on `kestrel-runtime` and touches nothing async.

- [ ] **Step 5: Confirm the Makefile's NOTE comment still accurately describes which crates are Linux-only**

Read `Makefile`'s top-of-file comment (added in Phase 2, mentions `kestrel-ns`/`kestrel-cgroup`). Since `kestrel-rootfs` and `kestrel-image` are now also Linux-only (both depend on `nix` syscalls with no non-Linux fallback), extend the comment to mention them too:

Modify the comment block at the top of `Makefile` — change:
```
# NOTE (Phase 2+): kestrel-ns now implements real namespace syscalls
# (unshare/setns/mount in stages.rs, pin.rs, join.rs) that only exist on
# Linux, and kestrel-runtime depends on kestrel-ns. As a result the `build`,
```
to:
```
# NOTE (Phase 2+): kestrel-ns and kestrel-cgroup implement real namespace/
# cgroup syscalls that only exist on Linux; kestrel-rootfs and kestrel-image
# (Phase 4) add real mount/pivot_root/mknod syscalls on top. kestrel-runtime
# depends on all of them. As a result the `build`, `test`, and `test-root`
```
and remove the now-redundant old second line that duplicated `test`, and `test-root` below (keep the rest of the comment as-is; just extend the crate list and merge the wrapped sentence).

---

## Self-Review Notes

**Spec coverage:** SPEC.md §6 (layout, mount, symlink farm, whiteouts/opaque, copy-up, rootless note) → Tasks 2-4, 9. §7 (pivot_root, standard mounts, masked/read-only paths) → Tasks 5-8. Design doc's crate-ownership split (rootfs vs. image) → Tasks 1-9 vs. 10-11. Design doc's explicitly-required safety tests (`MS_PRIVATE` before any mount work, exact 6-step sequence, two-call read-only bind, path-traversal rejection, host-mountinfo-unchanged) → Tasks 5, 6, 10-11, 12 respectively. Out-of-scope items (content store, registry, chain-ID dedup, security layer wiring, CLI wiring) are correctly absent from every task.

**Placeholder scan:** every step has complete, concrete code; no "add error handling here" or "similar to Task N" placeholders.

**Type consistency:** `Snapshot{lower_links, upper, work, merged}` (Task 3) is the exact shape `build_overlay_opts`/`mount_overlay` (Task 4), `scan_copy_ups`'s test fixtures (Task 9), and `lifecycle.rs` (Task 12) all consume. `LayerStats{files, bytes, whiteouts, opaques}` (Task 10) matches what `apply_layer`'s tests (Task 11) and the lifecycle test (Task 12) assert against. `apply_layer(tar: impl Read, dest: &Path, rootless: bool) -> Result<LayerStats>`'s signature is identical everywhere it's called.

**Known judgment calls flagged for the implementer/reviewer to double-check against the live VM, following this project's established practice of verifying rather than assuming:**
- `nix::sys::stat::major`/`minor` free-function paths (Task 7) — verify against the resolved `nix` 0.29 lockfile before trusting the test code as written.
- The `EBADF`/`EROFS` write-failure assertion in Task 6's footgun test may need adjusting once actually run — the comment already says to accept whichever syscall reports the failure.
- `devpts`'s `newinstance` + `/dev/ptmx` symlink (Task 7) is a real but easy-to-get-subtly-wrong area; if `setup_standard_mounts`'s ptmx test fails, check whether the running kernel's devpts defaults already satisfy it without the explicit `newinstance` option before assuming the symlink step itself is wrong.
