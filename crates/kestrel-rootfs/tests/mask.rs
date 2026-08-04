// crates/kestrel-rootfs/tests/mask.rs

use std::fs;

#[path = "common/mod.rs"]
mod common;

use kestrel_rootfs::mask::{apply_default_masks, make_readonly, mask_path};

#[test]
#[ignore = "requires root"]
fn test_mask_path_on_file_makes_it_read_as_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = tmp.path().join("secret.txt");
    fs::write(&secret, b"host-only-information").unwrap();

    common::run_in_fresh_mount_ns(move || {
        mask_path(&secret).expect("mask_path on a file");

        let contents = fs::read(&secret).unwrap();
        assert!(contents.is_empty(), "masked file must read as empty (bind-mounted over /dev/null)");
    });
}

#[test]
#[ignore = "requires root"]
fn test_mask_path_on_dir_makes_it_an_empty_readonly_tmpfs() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("secretdir");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("leak.txt"), b"host info").unwrap();

    common::run_in_fresh_mount_ns(move || {
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
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");

    common::run_in_fresh_mount_ns(move || {
        mask_path(&missing).expect("mask_path must silently succeed on a missing path");
    });
}

#[test]
#[ignore = "requires root"]
fn test_make_readonly_enforces_actual_read_only_via_two_call_sequence() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("ro-target");
    fs::create_dir(&dir).unwrap();

    common::run_in_fresh_mount_ns(move || {
        make_readonly(&dir).expect("make_readonly");

        assert!(
            fs::write(dir.join("new.txt"), b"x").is_err(),
            "make_readonly must actually enforce read-only, not just look like it does"
        );
    });
}

#[test]
#[ignore = "requires root"]
fn test_make_readonly_no_ops_on_missing_path() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");

    common::run_in_fresh_mount_ns(move || {
        make_readonly(&missing).expect("make_readonly must silently succeed on a missing path");
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_default_masks_only_masks_paths_that_exist() {
    // Build a synthetic rootfs where only a couple of DEFAULT_MASKED /
    // DEFAULT_READONLY paths actually exist (proc/acpi, proc/sys) and the
    // rest are absent, mirroring a real image that doesn't ship the full
    // /proc or /sys tree. apply_default_masks must not error on the
    // missing ones, and must actually mask/read-only-ify the ones present.
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();
    fs::create_dir_all(rootfs.join("proc/acpi")).unwrap();
    fs::write(rootfs.join("proc/acpi/leak.txt"), b"host-acpi-info").unwrap();
    fs::create_dir_all(rootfs.join("proc/sys")).unwrap();

    common::run_in_fresh_mount_ns(move || {
        apply_default_masks(&rootfs)
            .expect("apply_default_masks must succeed even when most default paths are absent");

        let acpi_entries: Vec<_> = fs::read_dir(rootfs.join("proc/acpi")).unwrap().collect();
        assert!(acpi_entries.is_empty(), "proc/acpi must be masked to an empty view");

        assert!(
            fs::write(rootfs.join("proc/sys/new.txt"), b"x").is_err(),
            "proc/sys must be read-only after apply_default_masks"
        );
    });
}
