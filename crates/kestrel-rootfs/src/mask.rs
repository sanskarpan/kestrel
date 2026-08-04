// crates/kestrel-rootfs/src/mask.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};

use crate::bindmount::bind_readonly;

pub const DEFAULT_MASKED: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

pub const DEFAULT_READONLY: &[&str] = &["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

/// Hides `p` (relative to the container's rootfs, already joined by the
/// caller) so it leaks no host information: directories get an empty
/// read-only tmpfs, files get bind-mounted over with `/dev/null`. Silently
/// no-ops paths that don't exist in this particular rootfs (not every
/// image has `/proc/acpi`, say) — anything else is a real error.
pub fn mask_path(p: &Path) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    match mount(Some("/dev/null"), p, None::<&str>, MsFlags::MS_BIND, None::<&str>) {
        // ENOTDIR is the real, expected signal here: `p` is a directory but
        // the bind source (`/dev/null`, hardcoded above) is a file, so the
        // kernel refuses the file-onto-dir bind. EISDIR is included
        // defensively for symmetry — with the source hardcoded to
        // `/dev/null` (never a directory), there's no live kernel scenario
        // that should actually produce EISDIR for this specific
        // source/target combination; ENOTDIR alone is sufficient in
        // practice.
        Err(Errno::ENOTDIR) | Err(Errno::EISDIR) => {
            mount(Some("tmpfs"), p, Some("tmpfs"), MsFlags::MS_RDONLY, Some("size=0k"))
                .with_context(|| format!("mounting empty ro tmpfs over {}", p.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("bind-mounting /dev/null over {}", p.display())),
        Ok(()) => {}
    }
    Ok(())
}

/// Bind-mounts `p` onto itself read-only. Delegates to
/// [`crate::bindmount::bind_readonly`] for the two-call sequence the
/// single-call version silently gets wrong. No-ops if `p` doesn't exist.
pub fn make_readonly(p: &Path) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    bind_readonly(p, p)
}

/// Applies [`DEFAULT_MASKED`] and [`DEFAULT_READONLY`] under `rootfs`.
/// Must run before `pivot::pivot_root` (paths are joined onto `rootfs`,
/// the not-yet-root merged directory), same ordering as
/// `mounts::setup_standard_mounts`. Like `setup_standard_mounts`, this
/// assumes the caller is already inside an unshared, MS_PRIVATE-remounted
/// mount namespace — it does not perform that remount itself.
pub fn apply_default_masks(rootfs: &Path) -> Result<()> {
    for p in DEFAULT_MASKED {
        mask_path(&rootfs.join(p.trim_start_matches('/'))).with_context(|| format!("masking {p}"))?;
    }
    for p in DEFAULT_READONLY {
        make_readonly(&rootfs.join(p.trim_start_matches('/'))).with_context(|| format!("making {p} read-only"))?;
    }
    Ok(())
}
