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
    fs::File::create(target).with_context(|| {
        format!(
            "syscall open(O_CREAT) target={target:?} for pin_namespace(pid={pid}, ns={ns:?}): failed while creating pin target; hint: check parent dir exists and is writable (mkdir -p {})",
            target.parent().unwrap_or(Path::new("/")).display()
        )
    })?;
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
        return Err(e).with_context(|| {
            format!(
                "syscall mount(MS_BIND) src={src} -> target={target:?} (pin_namespace pid={pid} ns={ns:?}): bind-mount failed; hint: requires CAP_SYS_ADMIN in host mount ns, src must exist (/proc/<pid>/ns/<type>), target must be a file"
            )
        });
    }
    Ok(())
}

/// Reverses [`pin_namespace`]: lazily unmounts the pin and removes the
/// backing file.
pub fn unpin_namespace(target: &Path) -> Result<()> {
    umount2(target, MntFlags::MNT_DETACH).with_context(|| {
        format!(
            "syscall umount2(MNT_DETACH) target={target:?}: failed to detach ns pin; hint: target may already be unmounted or not a mount point"
        )
    })?;
    fs::remove_file(target).with_context(|| {
        format!(
            "syscall unlink target={target:?}: failed to remove pin file after umount; hint: check permissions and that file still exists"
        )
    })?;
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
