// crates/kestrel-rootfs/src/bindmount.rs

use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};

/// A SINGLE `mount()` call with `MS_BIND | MS_RDONLY` silently IGNORES
/// `MS_RDONLY` — the kernel creates a writable bind mount and returns
/// success. This is the quietest bug in the whole mount API: a
/// "read-only" volume ends up writable and nothing tells you. The fix is
/// two calls: bind first, then a remount that actually applies RDONLY.
pub fn bind_readonly(src: &Path, dst: &Path) -> Result<()> {
    // (1) Plain recursive bind mount. `MS_REC` pulls in any mounts nested
    // under `src` (e.g. it's itself a tree with submounts) so they show up
    // under `dst` too. This call must happen FIRST and on its own: `dst`
    // only becomes a mount point as a side effect of this call succeeding,
    // and step (2) below requires `dst` to already BE a mount point —
    // `MS_REMOUNT` operates on an existing mount, it cannot create one.
    mount(Some(src), dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .with_context(|| format!("bind-mounting {} onto {}", src.display(), dst.display()))?;
    // (2) Remount to actually apply RDONLY. `MS_REMOUNT` must be combined
    // with `MS_BIND` (not issued alone) because without `MS_BIND` the
    // kernel would try to remount the underlying filesystem's real mount
    // point with new flags, rather than just this bind mount instance —
    // that would be both wrong (mutates state the bind mount doesn't own)
    // and typically fails outright for a non-superblock-owning caller.
    // `MS_REC` is needed here too, independently of step (1)'s `MS_REC`:
    // it propagates the RDONLY bit down to every submount that step (1)'s
    // recursive bind pulled in. Without it here, only the top-level `dst`
    // mount becomes read-only while the recursively-bound submounts
    // silently stay writable — the exact same "quiet footgun" shape as
    // the single-call bug this function exists to avoid, just one level
    // deeper.
    mount(
        None::<&str>,
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("remounting {} read-only", dst.display()))?;
    Ok(())
}
