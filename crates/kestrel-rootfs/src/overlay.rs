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
        let entry = entry.with_context(|| format!("reading entry in {}", dir.display()))?;
        let path = entry.path();
        if entry
            .file_type()
            .with_context(|| format!("reading entry in {}", dir.display()))?
            .is_dir()
        {
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
