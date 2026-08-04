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

/// Extracts `tar` into `dest`, translating OCI whiteout conventions into
/// their overlayfs on-disk form as it goes: `.wh..wh..opq` becomes the
/// opaque-dir xattr, `.wh.<name>` becomes a character-device-0:0 whiteout,
/// everything else is unpacked normally (including hardlinks and
/// symlinks — the `tar` crate's `unpack_in` already handles
/// `EntryType::Link`/`EntryType::Symlink` correctly; this function adds no
/// special-casing for them beyond what `unpack_in` already does).
///
/// # Preconditions
///
/// `dest` must already exist: this function calls `dest.canonicalize()`
/// immediately, which fails with a bare `os error 2` (`ENOENT`) on a
/// missing directory. Every current caller runs
/// `kestrel_rootfs::LayerStore::ensure_layer` first, which creates the
/// `diff/` directory before `apply_layer` is ever invoked — callers added
/// in the future must do the same (or otherwise create `dest`) before
/// calling this function.
///
/// # Known gap: no partial-application marker
///
/// If extraction fails partway through (for example, a whiteout's
/// `mknod` call fails), `dest` is left in a partially-applied state with
/// no on-disk marker distinguishing it from a fully-applied layer.
/// `LayerStore::ensure_layer`'s idempotency check currently only tests
/// whether the `diff/` directory *exists*, so a caller could later treat
/// a broken partial layer as already applied. This is a known,
/// deliberately deferred gap: a real fix (e.g. a completion sentinel
/// file, or extracting to a temp directory and renaming into place on
/// success) is an architectural decision that belongs with Phase 6's
/// content-store work, not this phase. It is documented here so it isn't
/// lost, not fixed here.
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
            xattr::set(parent, format!("{ns}.opaque"), b"y")
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
