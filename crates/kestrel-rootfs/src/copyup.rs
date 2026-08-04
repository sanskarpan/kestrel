// crates/kestrel-rootfs/src/copyup.rs
//
// Copy-up scanning per SPEC.md §6.5. Walks `upperdir` and, for each entry
// that also exists at the same relative path in one of the lower layers,
// reports it as a copy-up event. This surfaces the single biggest source of
// surprise disk usage and latency in containers: writing one byte to a 2 GB
// file in a lower layer copies all 2 GB up into upperdir.

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
        let entry = entry.with_context(|| format!("reading directory entry in {}", dir.display()))?;
        let path = entry.path();
        let rel = path.strip_prefix(root).expect("path is under root by construction");
        let file_type = entry.file_type().with_context(|| format!("reading file type of {}", path.display()))?;

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

        let metadata = entry.metadata().with_context(|| format!("reading metadata of {}", path.display()))?;
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
        std::os::unix::fs::FileTypeExt::is_char_device(self)
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

    #[test]
    fn test_scan_copy_ups_detects_opaque_directory() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        // Lower has a directory with a file in it; upper shadows that same
        // directory and marks it opaque, so overlayfs's real behavior would
        // hide everything below in the lower stack — recursion into it, and
        // reporting its (now-invisible) contents, would be wrong.
        fs::create_dir_all(lower.path().join("opaquedir")).unwrap();
        fs::write(lower.path().join("opaquedir/hidden-by-opaque.txt"), b"lower-only").unwrap();
        fs::create_dir_all(upper.path().join("opaquedir")).unwrap();
        xattr::set(upper.path().join("opaquedir"), "user.overlay.opaque", b"y").unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: lower.path() }];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, Path::new("opaquedir"));
        assert_eq!(events[0].kind, CopyUpKind::Opaque);
        assert_eq!(events[0].from_layer, "sha256:base");
    }

    #[test]
    fn test_scan_copy_ups_detects_metadata_only_copy_up() {
        let upper = tempfile::tempdir().unwrap();
        let lower = tempfile::tempdir().unwrap();

        fs::write(lower.path().join("metacopy.txt"), b"lower-content").unwrap();
        fs::write(upper.path().join("metacopy.txt"), b"lower-content").unwrap();
        xattr::set(upper.path().join("metacopy.txt"), "user.overlay.metacopy", b"y").unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: lower.path() }];
        let events = scan_copy_ups(upper.path(), &lowers).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, Path::new("metacopy.txt"));
        assert_eq!(events[0].kind, CopyUpKind::MetadataOnly);
    }
}
