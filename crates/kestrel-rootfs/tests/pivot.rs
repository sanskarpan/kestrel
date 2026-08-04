// crates/kestrel-rootfs/tests/pivot.rs

use std::fs;

use kestrel_rootfs::pivot::pivot_root;

#[path = "common/mod.rs"]
mod common;

// `common::run_in_fresh_mount_ns` does an unshare(CLONE_NEWNS) followed by
// an MS_PRIVATE|MS_REC remount of `/`. `pivot_root`'s own step 1 already
// performs that remount itself, so here it's a harmless no-op — used
// anyway for consistency with the other root-gated test files rather than
// keeping a 4th divergent copy of this helper around.

fn build_fixture_rootfs(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("proc")).unwrap();
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::write(dir.join("canary.txt"), b"i-am-the-new-root").unwrap();
}

#[test]
#[ignore = "requires root"]
fn test_pivot_root_switches_root_and_hides_old_root() {
    // `tmp` is created and dropped in THIS (parent) process, which never
    // pivots or changes mount namespace — only the resolved path is moved
    // into the isolated child. That keeps `TempDir::drop`'s `remove_dir_all`
    // operating against a path that still resolves once the child (and its
    // private mount namespace) has exited, instead of silently no-op'ing
    // against a path that no longer exists under the pivoted root.
    let tmp = tempfile::tempdir().unwrap();
    build_fixture_rootfs(tmp.path());
    let new_root = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        // A path that genuinely exists on the VM's real root (verified
        // directly: `/etc/os-release` is present on essentially any real
        // Linux system, symlinked to ../usr/lib/os-release on this VM) but
        // NOT in our fixture (build_fixture_rootfs never creates an /etc at
        // all) — proves the old root becomes unreachable after pivot, not
        // just that our fixture's own files are visible. An earlier version
        // of this check used a placeholder path that never actually existed
        // on the host, making the assertion below trivially true regardless
        // of whether pivot_root worked; this was caught during Task 12 and
        // fixed here.
        let host_only_marker = "/etc/os-release";

        pivot_root(&new_root).expect("pivot_root");

        let canary = fs::read_to_string("/canary.txt").expect("canary.txt must exist at new /");
        assert_eq!(canary, "i-am-the-new-root");

        assert!(
            !std::path::Path::new(host_only_marker).exists(),
            "old root's files must be unreachable after pivot_root"
        );
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

    let tmp = tempfile::tempdir().unwrap();
    build_fixture_rootfs(tmp.path());
    let new_root = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        pivot_root(&new_root).expect("pivot_root");
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
    let tmp = tempfile::tempdir().unwrap();
    build_fixture_rootfs(tmp.path());
    let new_root = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        // new_root here is a bare tmpfs/overlay-backed dir from the test
        // harness — deliberately NOT bind-mounted or overlay-mounted by us
        // before calling pivot_root, to prove step (2) alone suffices.
        pivot_root(&new_root).expect("pivot_root must self-bind-mount new_root");
        assert!(fs::metadata("/canary.txt").is_ok());
    });
}

#[test]
#[ignore = "requires root"]
fn test_pivot_root_on_nonexistent_new_root_fails_cleanly() {
    // pivot_root must fail cleanly (not panic, not do anything undefined)
    // when new_root doesn't exist. Step (2)'s self-bind-mount is the first
    // operation that touches new_root, so it should fail with ENOENT before
    // chdir/pivot_root/umount2 ever run.
    common::run_in_fresh_mount_ns(|| {
        let nonexistent = std::path::Path::new("/this/path/does/not/exist/kestrel-pivot-test");
        let err = pivot_root(nonexistent).expect_err("pivot_root on a nonexistent path must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bind-mounting"),
            "expected error to come from step (2)'s bind-mount, got: {msg}"
        );
    });
}
