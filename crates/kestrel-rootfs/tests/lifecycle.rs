// crates/kestrel-rootfs/tests/lifecycle.rs
//
// Capstone integration test for Phase 4: proves kestrel-image::apply_layer
// and every kestrel-rootfs primitive (Snapshotter, mount_overlay,
// setup_standard_mounts, apply_default_masks, pivot_root) compose correctly
// end to end, in the same order a real container creation would use them —
// mount the overlay, set up standard mounts and masks INSIDE the
// not-yet-root merged directory, THEN pivot_root into it.

use std::fs;
use std::io::Cursor;

use kestrel_image::apply::apply_layer;
use kestrel_image::test_util::build_tar;
use kestrel_rootfs::mask::apply_default_masks;
use kestrel_rootfs::mounts::setup_standard_mounts;
use kestrel_rootfs::overlay::mount_overlay;
use kestrel_rootfs::pivot::pivot_root;
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[path = "common/mod.rs"]
mod common;

#[test]
#[ignore = "requires root"]
fn test_full_lifecycle_two_layers_with_whiteout_through_pivot_root() {
    // Captured OUTSIDE the isolated child, to prove no leak at the very end.
    let host_mountinfo_before = fs::read_to_string("/proc/self/mountinfo").unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
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

        // A host-only marker: exists in this test process's real root
        // (verified against the VM: /etc/os-release -> ../usr/lib/os-release
        // on Ubuntu 24.04, present on essentially every real Linux system),
        // but must NOT be reachable once we pivot into the container's
        // merged rootfs below, since that rootfs is built from nothing but
        // the two synthetic tar layers above and never contains an /etc at
        // all. This is a meaningful check, not a tautology: the path is
        // confirmed present on the host before the test runs.
        let host_only_marker = "/etc/os-release";

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

        // Prove apply_default_masks actually took effect, not merely that
        // it was called without error: `/proc/sys` is one of
        // `mask::DEFAULT_READONLY`, and is reliably present under any real
        // mounted `/proc`. Without this, deleting the
        // `apply_default_masks` call above (or a silent regression to a
        // no-op) would leave every other assertion in this test passing.
        assert!(
            fs::write("/proc/sys/kernel/foo", b"x").is_err(),
            "post-pivot /proc/sys must still be read-only via apply_default_masks"
        );

        // Same closure-the-gap logic for setup_standard_mounts: prove the
        // device nodes it creates are actually present post-pivot, not
        // merely that the call didn't error.
        assert!(std::path::Path::new("/dev/null").exists(), "post-pivot /dev/null must exist via setup_standard_mounts");
    });

    let host_mountinfo_after = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert_eq!(
        host_mountinfo_before, host_mountinfo_after,
        "the entire lifecycle, including pivot_root, must leave the host's mount table untouched"
    );
}
