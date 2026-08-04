// crates/kestrel-rootfs/tests/overlay.rs

use std::fs;

use kestrel_rootfs::overlay::{mount_overlay, unmount_overlay};
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[path = "common/mod.rs"]
mod common;

#[test]
#[ignore = "requires root"]
fn test_overlay_composites_lower_and_upper_and_upper_wins() {
    common::run_in_fresh_mount_ns(|| {
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
    common::run_in_fresh_mount_ns(|| {
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
