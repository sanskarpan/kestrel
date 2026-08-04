// crates/kestrel-rootfs/src/pivot.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::chdir;

/// The `pivot_root(".", ".")` idiom from pivot_root(2)'s NOTES section. It
/// works because `pivot_root` stacks the OLD root on top of `new_root` at
/// the same mount point; the subsequent `MNT_DETACH` unmounts only the old
/// one. No temporary directory needs to exist inside the container image.
///
/// Every step here is load-bearing — see SPEC.md §7.2 and PROMPT.md's
/// Phase 4 section, which independently arrive at the same six steps:
/// dropping any one of them either leaves the container able to reach the
/// host filesystem, or leaks a mount/unmount back into the host's mount
/// namespace.
pub fn pivot_root(new_root: &Path) -> Result<()> {
    // (1) Detach from host mount propagation. systemd marks / MS_SHARED;
    //     without this, our mounts leak into the host mount namespace, the
    //     umount2 below can propagate and unmount the HOST root, and
    //     pivot_root itself refuses to run (it checks propagation types).
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("making / private (required before pivot_root)")?;

    // (2) pivot_root requires new_root to BE a mount point. If the overlay
    //     is already mounted here this is a cheap no-op; otherwise it makes
    //     the requirement true. Skip this and pivot_root(2) fails outright
    //     with EINVAL, since new_root would just be a plain directory on
    //     the same mount as its parent.
    mount(Some(new_root), new_root, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .context("bind-mounting new_root onto itself")?;

    // (3) The "." form requires new_root to be CWD. Skip this (or chdir
    //     somewhere else first) and the "." "." pivot_root call below
    //     either operates on the wrong path or fails outright, since both
    //     arguments are resolved relative to the calling process's CWD.
    chdir(new_root).with_context(|| format!("chdir to {}", new_root.display()))?;

    // (4) Swap. Old root is now stacked over ".".
    nix::unistd::pivot_root(".", ".").context("pivot_root(\".\", \".\")")?;

    // (5) Explicitly mark the old root MS_SLAVE before detaching — belt and
    //     braces on top of step (1): guarantees the umount cannot propagate.
    mount(None::<&str>, ".", None::<&str>, MsFlags::MS_REC | MsFlags::MS_SLAVE, None::<&str>)
        .context("marking old root MS_SLAVE")?;

    // (6) Lazy detach — submounts may still be busy; MNT_DETACH defers
    //     actual cleanup until the last reference drops.
    umount2(".", MntFlags::MNT_DETACH).context("detaching old root")?;

    chdir("/").context("chdir to new /")?;
    Ok(())
}
