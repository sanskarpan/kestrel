// crates/kestrel-ns/src/pin.rs
//
//! Namespace pinning: bind-mounting a namespace's `/proc/<pid>/ns/<ns>`
//! file onto a persistent path so it stays enterable (via `setns`) even
//! after every process that was inside it has exited. Requires
//! `CAP_SYS_ADMIN` in the host mount namespace — real root, not just an
//! unprivileged user namespace.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::Pid;

use crate::types::NsType;

/// Bind-mounts `/proc/<pid>/ns/<ns>` onto `target`, keeping the namespace
/// alive (and enterable via `setns` on `target`) even after `pid` exits.
pub fn pin_namespace(pid: Pid, ns: NsType, target: &Path) -> Result<()> {
    // The bind-mount target must already exist as a regular file.
    fs::File::create(target).with_context(|| format!("creating pin target {target:?}"))?;
    let src = format!("/proc/{pid}/ns/{}", ns.proc_name());
    if let Err(e) = mount(
        Some(src.as_str()),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    ) {
        // Don't leave a stray, unmounted file behind if the bind-mount
        // itself fails — best-effort, the original error is what matters.
        let _ = fs::remove_file(target);
        return Err(e).with_context(|| format!("bind-mounting {src} onto {target:?}"));
    }
    Ok(())
}

/// Reverses [`pin_namespace`]: lazily unmounts the pin and removes the
/// backing file.
pub fn unpin_namespace(target: &Path) -> Result<()> {
    umount2(target, MntFlags::MNT_DETACH).with_context(|| format!("unmounting pin {target:?}"))?;
    fs::remove_file(target).with_context(|| format!("removing pin file {target:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Doesn't need root: `File::create` fails on the missing parent
    /// directory before the privileged `mount()` call is ever reached.
    #[test]
    fn test_pin_namespace_fails_cleanly_when_parent_dir_missing() {
        let bogus = Path::new("/tmp/kestrel-ns-nonexistent-dir-xyz/uts");
        let err = pin_namespace(nix::unistd::getpid(), NsType::Uts, bogus).unwrap_err();
        assert!(
            err.to_string().contains("creating pin target"),
            "unexpected error: {err}"
        );
    }
}
