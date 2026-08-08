// crates/kestrel-rootfs/tests/mounts.rs

use std::fs;
use std::io::Write;

use nix::mount::{mount, umount2, MntFlags, MsFlags};

#[path = "common/mod.rs"]
mod common;

use kestrel_rootfs::bindmount::bind_readonly;
use kestrel_rootfs::mounts::{bind_default_devices, bind_mount_file, create_default_devices, setup_standard_mounts};

#[test]
#[ignore = "requires root"]
fn test_single_call_bind_rdonly_is_silently_writable() {
    // This test documents and proves the footgun itself, so a future
    // reader doesn't have to take the doc comment's word for it.
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    fs::write(src.path().join("f.txt"), b"orig").unwrap();
    let src_path = src.path().to_path_buf();
    let dst_path = dst.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        mount(Some(&src_path), &dst_path, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>)
            .expect("single-call bind+rdonly mount");

        let write_result = fs::OpenOptions::new().write(true).open(dst_path.join("f.txt"));
        assert!(
            write_result.is_ok(),
            "documenting the footgun: a single MS_BIND|MS_RDONLY call does NOT make the mount read-only"
        );

        umount2(&dst_path, MntFlags::MNT_DETACH).unwrap();
    });
}

#[test]
#[ignore = "requires root"]
fn test_bind_readonly_two_call_sequence_actually_enforces_read_only() {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    fs::write(src.path().join("f.txt"), b"orig").unwrap();
    let src_path = src.path().to_path_buf();
    let dst_path = dst.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        bind_readonly(&src_path, &dst_path).expect("bind_readonly");

        let mut write_result = fs::OpenOptions::new().write(true).open(dst_path.join("f.txt"));
        match &mut write_result {
            Ok(f) => {
                let err = f.write_all(b"nope").unwrap_err();
                assert!(
                    matches!(err.raw_os_error(), Some(libc::EBADF) | Some(libc::EROFS)),
                    "unexpected errno: {err:?}"
                );
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EROFS), "expected EROFS opening for write, got {e:?}");
            }
        }

        umount2(&dst_path, MntFlags::MNT_DETACH).unwrap();
    });
}

fn major_of(rdev: u64) -> u64 {
    nix::sys::stat::major(rdev)
}

fn minor_of(rdev: u64) -> u64 {
    nix::sys::stat::minor(rdev)
}

#[test]
#[ignore = "requires root"]
fn test_setup_standard_mounts_creates_expected_mount_table_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        setup_standard_mounts(&rootfs).expect("setup_standard_mounts");

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

    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        fs::create_dir_all(rootfs.join("dev")).unwrap();
        create_default_devices(&rootfs).expect("create_default_devices");

        let null = stat(&rootfs.join("dev/null")).unwrap();
        assert_eq!(null.st_mode & SFlag::S_IFMT.bits(), SFlag::S_IFCHR.bits());
        assert_eq!(major_of(null.st_rdev), 1);
        assert_eq!(minor_of(null.st_rdev), 3);

        let tty = stat(&rootfs.join("dev/tty")).unwrap();
        assert_eq!(major_of(tty.st_rdev), 5);
        assert_eq!(minor_of(tty.st_rdev), 0);
    });
}

#[test]
#[ignore = "requires root"]
fn test_bind_default_devices_bind_mounts_real_host_devices() {
    use nix::sys::stat::stat;

    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        fs::create_dir_all(rootfs.join("dev")).unwrap();
        bind_default_devices(&rootfs).expect("bind_default_devices");

        // Prove the bind actually happened — not just that a same-named
        // file exists — by confirming the container's dev/null resolves to
        // the exact same device as the host's real /dev/null (same
        // underlying char device AND same mount's st_dev), not merely a
        // file that happens to also be a character device.
        let host_null = stat("/dev/null").expect("stat host /dev/null");
        let container_null = stat(rootfs.join("dev/null").as_path()).expect("stat container dev/null");
        assert_eq!(
            container_null.st_rdev, host_null.st_rdev,
            "bind-mounted dev/null should report the same rdev (major/minor) as the host's /dev/null"
        );
        assert_eq!(
            container_null.st_dev, host_null.st_dev,
            "bind-mounted dev/null should live on the same underlying mount as the host's /dev/null"
        );

        let host_tty = stat("/dev/tty").expect("stat host /dev/tty");
        let container_tty = stat(rootfs.join("dev/tty").as_path()).expect("stat container dev/tty");
        assert_eq!(container_tty.st_rdev, host_tty.st_rdev);
        assert_eq!(container_tty.st_dev, host_tty.st_dev);
    });
}

#[test]
#[ignore = "requires root"]
fn test_setup_standard_mounts_ptmx_symlink_works() {
    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();

    common::run_in_fresh_mount_ns(move || {
        setup_standard_mounts(&rootfs).expect("setup_standard_mounts");
        let target = fs::read_link(rootfs.join("dev/ptmx")).unwrap();
        assert_eq!(target, std::path::Path::new("pts/ptmx"));
    });
}

#[test]
#[ignore = "requires root"]
fn test_bind_mount_file_is_a_real_bind_not_a_copy_and_unmounts_cleanly() {
    use nix::sys::stat::stat;

    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("source.txt");
    fs::write(&src_path, b"hello from source").unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let rootfs = tmp.path().to_path_buf();
    let relative_target = std::path::PathBuf::from("etc/resolv.conf");

    common::run_in_fresh_mount_ns(move || {
        bind_mount_file(&src_path, &rootfs, &relative_target).expect("bind_mount_file");

        let target_path = rootfs.join(&relative_target);

        // Prove it's a genuine bind mount (same underlying inode+device as
        // the source), not a copy.
        let src_stat = stat(&src_path).unwrap();
        let target_stat = stat(&target_path).unwrap();
        assert_eq!(target_stat.st_dev, src_stat.st_dev, "bind-mounted target should share the source's st_dev");
        assert_eq!(target_stat.st_ino, src_stat.st_ino, "bind-mounted target should share the source's inode");

        // Write through the target, read from the source: proves the bind
        // is live and read-write, not a one-shot copy.
        fs::write(&target_path, b"written through target").unwrap();
        let via_source = fs::read_to_string(&src_path).unwrap();
        assert_eq!(via_source, "written through target");

        // Write through the source, read from the target: the reverse
        // direction.
        fs::write(&src_path, b"written through source").unwrap();
        let via_target = fs::read_to_string(&target_path).unwrap();
        assert_eq!(via_target, "written through source");

        umount2(&target_path, MntFlags::MNT_DETACH).unwrap();

        // After unmount, the target reverts to the empty regular file that
        // bind_mount_file created as the mount point: different inode than
        // the source, and none of the content written through the bind
        // mount leaked into it. That's the "no host residue" proof — the
        // mount point is back to a plain, empty file, not still carrying
        // the source's data.
        let target_after = stat(&target_path).unwrap();
        assert_ne!(
            target_after.st_ino, src_stat.st_ino,
            "target should no longer share the source's inode after unmount"
        );
        let leftover = fs::read_to_string(&target_path).unwrap();
        assert!(
            leftover.is_empty(),
            "unmounted target should be the empty file bind_mount_file created, not leaking bind-mount content: got {leftover:?}"
        );
    });
}
