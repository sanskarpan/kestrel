// crates/kestrel-rootfs/src/mounts.rs

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};

struct StandardMount {
    relative_target: &'static str,
    fstype: &'static str,
    flags: MsFlags,
    data: &'static str,
}

const STANDARD_MOUNTS: &[StandardMount] = &[
    StandardMount {
        relative_target: "proc",
        fstype: "proc",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "",
    },
    StandardMount {
        relative_target: "sys",
        fstype: "sysfs",
        flags: MsFlags::from_bits_truncate(
            MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits() | MsFlags::MS_RDONLY.bits(),
        ),
        data: "",
    },
    StandardMount {
        relative_target: "dev",
        fstype: "tmpfs",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_STRICTATIME.bits()),
        data: "mode=755,size=65536k",
    },
    StandardMount {
        relative_target: "dev/pts",
        fstype: "devpts",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits()),
        data: "newinstance,ptmxmode=0666,mode=0620,gid=5",
    },
    StandardMount {
        relative_target: "dev/shm",
        fstype: "tmpfs",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "mode=1777,size=65536k",
    },
    StandardMount {
        relative_target: "dev/mqueue",
        fstype: "mqueue",
        flags: MsFlags::from_bits_truncate(MsFlags::MS_NOSUID.bits() | MsFlags::MS_NOEXEC.bits() | MsFlags::MS_NODEV.bits()),
        data: "",
    },
];

struct DeviceSpec {
    name: &'static str,
    major: u64,
    minor: u64,
}

const DEFAULT_DEVICES: &[DeviceSpec] = &[
    DeviceSpec { name: "null", major: 1, minor: 3 },
    DeviceSpec { name: "zero", major: 1, minor: 5 },
    DeviceSpec { name: "full", major: 1, minor: 7 },
    DeviceSpec { name: "random", major: 1, minor: 8 },
    DeviceSpec { name: "urandom", major: 1, minor: 9 },
    DeviceSpec { name: "tty", major: 5, minor: 0 },
];

/// Mounts `/proc`, `/sys`, `/dev` (tmpfs), `/dev/pts`, `/dev/shm`,
/// `/dev/mqueue` under `rootfs`, creates the standard device nodes, and
/// symlinks `/dev/ptmx -> pts/ptmx` (required because `dev/pts` is mounted
/// with `newinstance`, which requires using the instance's own ptmx rather
/// than a preexisting one). Must be called BEFORE `pivot::pivot_root`,
/// with `rootfs` set to the not-yet-root merged directory.
///
/// Precondition, same category as [`pivot::pivot_root`](crate::pivot::pivot_root)'s:
/// the caller must already be running inside its own unshared mount
/// namespace (`unshare(CLONE_NEWNS)`) with that namespace's mount tree
/// already made `MS_PRIVATE` (recursively) — unlike `pivot_root`, this
/// function does not perform that remount itself, so the caller must have
/// done it first. This function mounts real filesystems at real absolute
/// paths under `rootfs`; calling it against the host's actual mount
/// namespace, or before the private remount, would leak those mounts onto
/// the host.
pub fn setup_standard_mounts(rootfs: &Path) -> Result<()> {
    for m in STANDARD_MOUNTS {
        let target = rootfs.join(m.relative_target);
        fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
        let data = if m.data.is_empty() { None } else { Some(m.data) };
        mount(Some(m.fstype), &target, Some(m.fstype), m.flags, data)
            .with_context(|| format!("mounting {} ({}) at {}", m.fstype, m.data, target.display()))?;
    }

    create_default_devices(rootfs)?;

    let ptmx = rootfs.join("dev/ptmx");
    let _ = fs::remove_file(&ptmx);
    std::os::unix::fs::symlink("pts/ptmx", &ptmx)
        .with_context(|| format!("symlinking {} -> pts/ptmx", ptmx.display()))?;

    Ok(())
}

/// Creates `/dev/{null,zero,full,random,urandom,tty}` as character devices.
/// Requires real root (`CAP_MKNOD`) — see [`bind_default_devices`] for the
/// rootless fallback.
pub fn create_default_devices(rootfs: &Path) -> Result<()> {
    let dev = rootfs.join("dev");
    for d in DEFAULT_DEVICES {
        let path = dev.join(d.name);
        let _ = fs::remove_file(&path);
        mknod(&path, SFlag::S_IFCHR, Mode::from_bits_truncate(0o666), makedev(d.major, d.minor))
            .with_context(|| format!("mknod {} ({}:{})", path.display(), d.major, d.minor))?;
    }
    Ok(())
}

/// Rootless fallback: an unprivileged user cannot `mknod`, so bind-mount
/// each device node from the host instead. Requires the host path to
/// already exist (true on any real Linux system).
///
/// Same mount-namespace precondition as [`setup_standard_mounts`]: the
/// caller must already be inside its own unshared, `MS_PRIVATE` mount
/// namespace before calling this, or the bind mounts it performs will leak
/// onto the host instead of staying scoped to the container's `rootfs`.
pub fn bind_default_devices(rootfs: &Path) -> Result<()> {
    let dev = rootfs.join("dev");
    for d in DEFAULT_DEVICES {
        let target = dev.join(d.name);
        fs::File::create(&target).with_context(|| format!("creating bind target {}", target.display()))?;
        let host_src = Path::new("/dev").join(d.name);
        mount(Some(&host_src), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("bind-mounting {} onto {}", host_src.display(), target.display()))?;
    }
    Ok(())
}
