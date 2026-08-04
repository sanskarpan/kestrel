// crates/kestrel-rootfs/tests/copyup.rs

use std::fs;

use kestrel_rootfs::copyup::{scan_copy_ups, CopyUpKind, LowerLayer};
use kestrel_rootfs::overlay::mount_overlay;
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[path = "common/mod.rs"]
mod common;

#[test]
#[ignore = "requires root"]
fn test_scan_copy_ups_against_a_real_kernel_triggered_copy_up() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
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

#[test]
#[ignore = "requires root"]
fn test_scan_copy_ups_detects_a_real_kernel_written_whiteout() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        let store = LayerStore::new(data_dir.clone());
        let base_diff = store.ensure_layer("sha256:base", None).unwrap();
        fs::write(base_diff.join("deleted-in-container.txt"), b"only-in-lower").unwrap();

        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter.prepare_snapshot("c-copyup-2", &["sha256:base".into()]).unwrap();
        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay");

        // Removing a file that only exists in a lower layer, through the
        // merged view, makes the kernel write a real whiteout (char device
        // 0:0) into upperdir at that path — this is what scan_copy_ups must
        // recognize as CopyUpKind::Whiteout rather than ordinary Data.
        fs::remove_file(snap.merged.join("deleted-in-container.txt")).unwrap();

        let lowers = [LowerLayer { chain_id: "sha256:base", diff_dir: &base_diff }];
        let events = scan_copy_ups(&snap.upper, &lowers).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, std::path::Path::new("deleted-in-container.txt"));
        assert_eq!(events[0].kind, CopyUpKind::Whiteout);

        kestrel_rootfs::overlay::unmount_overlay(&snap.merged).unwrap();
    });
}
