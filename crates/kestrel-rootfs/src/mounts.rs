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
        // `gid=0`, NOT the conventional `gid=5` ("tty") many other
        // runtimes default to. Root-caused (Phase 8 Task 16, via a real
        // `strace`d reproduction — `unshare -U -m --map-root-user --
        // mount -t devpts -o newinstance,...,gid=5 ...` reliably fails
        // `EINVAL`, while the identical call with `gid=0` succeeds):
        // when this mount's mount namespace is owned by a user namespace
        // (true for any container using a Linux user namespace, kestrel's
        // own included), the kernel's devpts driver must be able to
        // resolve the `gid=` option's value through that user namespace's
        // OWN `gid_map` — and there is no general guarantee a container's
        // gid mapping includes gid 5 specifically (kestrel's own
        // `NamespacePlan` only requires `gid_maps` be non-empty, not that
        // it cover any particular value; a bundle's `config.json` is free
        // to map only container gid 0, which is by far the common case
        // for "container runs as root"). `gid=0` is the one value this
        // call chain can actually guarantee resolves: `kestrel_ns::stages
        // ::stage1` already requires a real, non-empty `gid_maps` before
        // it will unshare a user namespace at all, and by OCI/kestrel
        // convention container gid 0 is what gets mapped for a
        // root-running container in the first place. The behavioral cost
        // is cosmetic only: pty slave device nodes end up group-owned by
        // 0 instead of 5, which does not affect this project's own use of
        // them (`ptmxmode=0666` already makes `/dev/ptmx` itself
        // world-accessible regardless of this option).
        data: "newinstance,ptmxmode=0666,mode=0620,gid=0",
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

    // `mknod(2)` for a character/block device special file is disallowed
    // by the kernel inside a mount namespace owned by a (non-init) user
    // namespace, REGARDLESS of the calling process's own capabilities
    // within that user namespace — root-caused (Phase 8 Task 16) via a
    // real, minimal reproduction (`unshare -U -m --map-root-user --
    // mount -t tmpfs tmpfs /some/dir && mknod /some/dir/null c 1 3`
    // reliably fails `EPERM` even though `capsh --print` shows `cap_mknod`
    // present in the bounding set): the check is against `CAP_MKNOD` in
    // the INIT user namespace specifically, not the container's own,
    // exactly the same class of restriction that motivated
    // [`bind_default_devices`] existing at all ("an unprivileged user
    // cannot `mknod`"). Since kestrel's own `NamespacePlan`/`stage1`
    // support a genuine Linux user namespace (this file's own
    // `stage_rootfs` in `kestrel-init` runs with one whenever the OCI
    // bundle's `linux.namespaces` includes `User`), "root inside a user
    // namespace" is a real, first-class case here, not just the
    // conventionally-rootless (non-root-on-host) case `bind_default_devices`'s
    // own doc comment was originally written for — so rather than
    // threading a separate "am I in a user namespace" signal through
    // `Bootstrap`/`MountPlan` (nothing here currently carries one, and
    // `MountPlan.rootless` is a distinct, independently-set flag that does
    // not reliably track this), this narrowly catches EXACTLY the `EPERM`
    // `mknod` produces and falls back to `bind_default_devices` — the same
    // "try the normal path, tolerate one specific, well-understood errno"
    // convention `kestrel-runtime`'s own `create.rs::pin_namespaces`
    // already established for its own EINVAL/Mount-pin case. A genuine,
    // different-cause failure (any errno other than `EPERM`) still
    // propagates normally. Safe to treat as complete replacement rather
    // than a partial-state merge: `create_default_devices` fails on its
    // very FIRST device (`null` is first in `DEFAULT_DEVICES`) before
    // creating anything else, so this fallback always starts from a clean
    // slate (no real device nodes for `bind_default_devices`'s own
    // `fs::File::create` calls to collide with).
    if let Err(e) = create_default_devices(rootfs) {
        if is_eperm(&e) {
            bind_default_devices(rootfs).context("mknod was disallowed (EPERM); falling back to bind-mounting host devices")?;
        } else {
            return Err(e);
        }
    }

    let ptmx = rootfs.join("dev/ptmx");
    let _ = fs::remove_file(&ptmx);
    std::os::unix::fs::symlink("pts/ptmx", &ptmx)
        .with_context(|| format!("symlinking {} -> pts/ptmx", ptmx.display()))?;

    Ok(())
}

/// Narrow errno check backing `setup_standard_mounts`'s
/// `create_default_devices` → `bind_default_devices` fallback (see that
/// call site's own doc comment for the full reasoning). Same
/// downcast-through-the-`anyhow`-chain convention as `kestrel-runtime`'s
/// `create.rs::is_known_mount_pin_einval`.
fn is_eperm(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<nix::errno::Errno>(), Some(nix::errno::Errno::EPERM))
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

/// Bind-mounts a single host file onto a path inside `rootfs` (already
/// mounted, pre-pivot). The target must exist as a regular file before the
/// bind-mount — same requirement `kestrel_ns::pin::pin_namespace` already
/// established for namespace pins, since bind-mount targets are not
/// auto-created by the kernel; this function creates the target itself
/// (including any missing parent directories) before mounting onto it.
/// Two real, independent needs motivate this: Phase 7's own
/// `/etc/hosts`/`/etc/hostname`/`/etc/resolv.conf` wiring (deferred to
/// "Phase 8's assembly concern" in that phase's own design doc) and this
/// phase's own exec-FIFO reachability across `pivot_root` (see the Phase 8
/// design doc §3).
///
/// Same mount-namespace precondition as [`setup_standard_mounts`]: the
/// caller must already be inside its own unshared, `MS_PRIVATE` mount
/// namespace before calling this, or the bind mount it performs will leak
/// onto the host instead of staying scoped to the container's `rootfs`.
pub fn bind_mount_file(source: &Path, rootfs: &Path, relative_target: &Path) -> Result<()> {
    // `relative_target` is, in practice, sometimes handed an ABSOLUTE
    // in-container path — `kestrel-init`'s own `Bootstrap.fifo_container_path`
    // ("/.kestrel/exec.fifo") is one real example: it is ALSO used
    // elsewhere, post-`pivot_root`, as a genuine absolute path passed
    // straight to `open()` (`kestrel_init::fifo::block_until_started`), so
    // it is legitimately absolute from that caller's point of view.
    // `Path::join` silently DISCARDS `rootfs` entirely when the joined
    // component is itself absolute (that's `Path::join`'s own documented
    // behavior) — root-caused (Phase 8 Task 16) via a real reproduction:
    // without this strip, the exec-FIFO bind-mount landed outside
    // `rootfs` entirely (on this pre-pivot process's still-host-rooted
    // "/"), so `kestrel-init` later found no FIFO at
    // `<merged>/.kestrel/exec.fifo` post-pivot and failed with plain
    // `ENOENT` trying to open it. Stripping a leading `/` first (same
    // `trim_start_matches('/')` idiom this project's own lifecycle test
    // helpers, e.g. `upper_path`, already use for exactly this reason)
    // makes this function correct for both relative and absolute inputs;
    // an already-relative `relative_target` (e.g. `"etc/resolv.conf"`) is
    // returned unchanged by `strip_prefix` failing and falling back via
    // `unwrap_or`.
    let stripped = relative_target.strip_prefix("/").unwrap_or(relative_target);
    let target = rootfs.join(stripped);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if !target.exists() {
        fs::File::create(&target).with_context(|| format!("creating bind-mount target {}", target.display()))?;
    }
    // Two-call MS_BIND then MS_BIND|MS_RDONLY footgun (this project's own
    // established lesson from Phase 4 — a single mount() call combining
    // MS_BIND with other flags silently ignores everything but MS_BIND)
    // does NOT apply here: this bind mount is read-write (the FIFO must be
    // writable-through for `start` to unblock it), so only the plain
    // MS_BIND call is needed, no second remount call.
    mount(Some(source), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
        .with_context(|| format!("bind-mounting {} onto {}", source.display(), target.display()))?;
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
