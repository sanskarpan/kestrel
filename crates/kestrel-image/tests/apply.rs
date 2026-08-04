use std::fs;
use std::io::Cursor;

use kestrel_image::apply::apply_layer;
use kestrel_image::test_util::build_tar;
use tar::{Builder, Header};

/// Writes `path` directly into the header's raw old-header `name` field,
/// bypassing the `tar` crate's own `Header::set_path`/`Builder::append_data`
/// validation. As of `tar` 0.4.46, that validation unconditionally rejects
/// both absolute paths and any path containing a `..` component *at archive
/// build time* (`Builder::preserve_absolute` only relaxes the absolute-path
/// check, not the `..` check) -- so the traversal tests below could never
/// construct a malicious tar via the normal `append_data` API in the first
/// place (which is exactly what `kestrel_image::test_util::build_tar`
/// above uses, so it can't be reused here either). A real attacker crafting
/// a hostile layer tarball isn't going through this crate's safe builder
/// API either, so these tests write the raw bytes directly to reach
/// `apply_layer`'s own `safe_join` guard, which is what's actually under
/// test here. Deliberately kept local to this file, not promoted to
/// `test_util`: it exists only to build intentionally-malformed tars.
fn set_raw_path(header: &mut Header, path: &str) {
    let name = &mut header.as_old_mut().name;
    for b in name.iter_mut() {
        *b = 0;
    }
    let bytes = path.as_bytes();
    assert!(bytes.len() < name.len(), "test path too long for raw old-header name field");
    name[..bytes.len()].copy_from_slice(bytes);
}

/// Single-entry tar built via the raw-header path above, for the
/// traversal tests below only.
fn build_malicious_tar(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    set_raw_path(&mut header, path);
    header.set_cksum();
    builder.append(&header, Cursor::new(contents)).unwrap();
    builder.into_inner().unwrap()
}

#[test]
fn test_apply_layer_extracts_ordinary_files() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_tar(&[("hello.txt", b"world"), ("dir/nested.txt", b"nested-content")]);

    let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false)
        .expect("apply_layer should extract ordinary files");

    assert_eq!(stats.files, 2);
    assert_eq!(fs::read_to_string(tmp.path().join("hello.txt")).unwrap(), "world");
    assert_eq!(fs::read_to_string(tmp.path().join("dir/nested.txt")).unwrap(), "nested-content");
}

#[test]
fn test_apply_layer_rejects_absolute_path_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_malicious_tar("/etc/passwd", b"pwned");
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().contains("path traversal") || err.to_string().contains("traversal"));
    assert!(
        fs::read_dir(tmp.path()).unwrap().next().is_none(),
        "rejected entry must leave dest untouched"
    );
}

#[test]
fn test_apply_layer_rejects_dotdot_traversal_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_malicious_tar("../../../etc/passwd", b"pwned");
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("traversal"));
}

#[test]
fn test_apply_layer_rejects_embedded_dotdot_traversal_entry() {
    // The specific case a naive post-join starts_with() check would miss.
    let tmp = tempfile::tempdir().unwrap();
    let tar_bytes = build_malicious_tar("subdir/../../escape.txt", b"pwned");
    let err = apply_layer(Cursor::new(tar_bytes), tmp.path(), false).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("traversal"));
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_translates_whiteout_to_char_device_0_0() {
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("existing.txt"), b"from-lower-layer").unwrap();

        let tar_bytes = build_tar(&[(".wh.existing.txt", b"")]);
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false)
            .expect("apply_layer should translate whiteout to char device 0:0");

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
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("mydir")).unwrap();

        let tar_bytes = build_tar(&[("mydir/.wh..wh..opq", b"")]);
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false)
            .expect("apply_layer should set opaque xattr on directory marker");

        assert_eq!(stats.opaques, 1);
        let val = xattr::get(tmp.path().join("mydir"), "trusted.overlay.opaque").unwrap();
        assert_eq!(val, Some(b"y".to_vec()));
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_uses_userxattr_namespace_when_rootless() {
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("mydir")).unwrap();

        let tar_bytes = build_tar(&[("mydir/.wh..wh..opq", b"")]);
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), true)
            .expect("apply_layer should use user.overlay namespace when rootless");

        assert_eq!(stats.opaques, 1);
        let val = xattr::get(tmp.path().join("mydir"), "user.overlay.opaque").unwrap();
        assert_eq!(val, Some(b"y".to_vec()));
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_layer_round_trips_hardlinks() {
    kestrel_ns::test_util::run_isolated(|| {
        let tmp = tempfile::tempdir().unwrap();

        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(b"shared-content".len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "original.txt", Cursor::new(b"shared-content" as &[u8])).unwrap();

        let mut link_header = Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_link_name("original.txt").unwrap();
        link_header.set_cksum();
        builder.append_data(&mut link_header, "hardlink.txt", Cursor::new(&[] as &[u8])).unwrap();

        let tar_bytes = builder.into_inner().unwrap();
        let stats = apply_layer(Cursor::new(tar_bytes), tmp.path(), false)
            .expect("apply_layer should round-trip hardlinks");

        assert_eq!(stats.files, 2);
        assert_eq!(fs::read_to_string(tmp.path().join("hardlink.txt")).unwrap(), "shared-content");

        use std::os::unix::fs::MetadataExt;
        let orig_ino = fs::metadata(tmp.path().join("original.txt")).unwrap().ino();
        let link_ino = fs::metadata(tmp.path().join("hardlink.txt")).unwrap().ino();
        assert_eq!(orig_ino, link_ino, "hardlink must share the same inode as its target, not be a copy");
    });
}
