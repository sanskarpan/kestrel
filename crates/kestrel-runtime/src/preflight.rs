#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version_with_suffix() {
        assert_eq!(parse_kernel_version("6.8.0-45-generic").unwrap(), (6, 8, 0));
    }

    #[test]
    fn test_parse_kernel_version_plain() {
        assert_eq!(parse_kernel_version("5.11.0").unwrap(), (5, 11, 0));
    }

    #[test]
    fn test_parse_kernel_version_rejects_garbage() {
        assert!(parse_kernel_version("not-a-version").is_err());
    }

    #[test]
    fn test_parse_kernel_version_missing_patch_defaults_to_zero() {
        assert_eq!(parse_kernel_version("5.11").unwrap(), (5, 11, 0));
    }
}

use anyhow::{bail, Context, Result};

#[derive(Debug, Default)]
pub struct EnvReport {
    pub controllers: Vec<String>,
    pub psi: bool,
    pub kernel: (u32, u32, u32),
    pub clone3: bool,
}

/// Parses a `uname -r`-style release string ("6.8.0-45-generic") into
/// (major, minor, patch), ignoring any distro suffix after the third
/// numeric component.
pub fn parse_kernel_version(release: &str) -> Result<(u32, u32, u32)> {
    let core = release.split('-').next().unwrap_or(release);
    let mut parts = core.split('.');
    let major = parts
        .next()
        .context("missing major version")?
        .parse()
        .context("major version not numeric")?;
    let minor = parts
        .next()
        .context("missing minor version")?
        .parse()
        .context("minor version not numeric")?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse()
        .context("patch version not numeric")?;
    Ok((major, minor, patch))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::statfs::statfs;
    use std::fs;
    use std::path::Path;

    pub fn check_environment() -> Result<EnvReport> {
        let mut r = EnvReport::default();

        // cgroup v2 unified. On v1/hybrid, everything in Phase 3 silently
        // misbehaves in ways that look like our bugs.
        let st = statfs("/sys/fs/cgroup").context("statfs /sys/fs/cgroup")?;
        if st.filesystem_type() != nix::sys::statfs::CGROUP2_SUPER_MAGIC {
            bail!(
                "cgroup v2 required. Boot with systemd.unified_cgroup_hierarchy=1 \
                 (or cgroup_no_v1=all) and reboot."
            );
        }
        r.controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .context("reading /sys/fs/cgroup/cgroup.controllers")?
            .split_whitespace()
            .map(String::from)
            .collect();

        // overlayfs
        if !fs::read_to_string("/proc/filesystems")
            .context("reading /proc/filesystems")?
            .contains("overlay")
        {
            bail!("overlayfs not available: modprobe overlay");
        }

        // PSI is a kernel config option; degrade gracefully rather than failing.
        r.psi = Path::new("/proc/pressure/cpu").exists();

        // 5.11 gives us userxattr overlay in a userns, which rootless needs.
        let uname = nix::sys::utsname::uname().context("uname()")?;
        r.kernel = parse_kernel_version(uname.release().to_string_lossy().as_ref())?;
        if r.kernel < (5, 11, 0) {
            tracing::warn!(
                kernel = ?r.kernel,
                "kernel < 5.11: rootless overlay will fall back to fuse-overlayfs"
            );
        }

        r.clone3 = probe_clone3();

        Ok(r)
    }

    /// clone3(2) with a null args pointer: ENOSYS means the syscall itself
    /// is unavailable; any other errno (typically EINVAL) means the kernel
    /// recognizes the syscall number and rejected the bogus arguments —
    /// i.e. clone3 exists.
    fn probe_clone3() -> bool {
        // SAFETY: passing a null pointer with size 0 is rejected by the
        // kernel's argument-size validation (`usize < CLONE_ARGS_SIZE_VER0`)
        // before the pointer is ever dereferenced or any process is
        // spawned, so this call can only fail cleanly (ENOSYS/EINVAL) —
        // it can never fault or create a stray process.
        let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null_mut::<u8>(), 0usize) };
        rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
    }
}

#[cfg(target_os = "linux")]
pub use linux::check_environment;

#[cfg(not(target_os = "linux"))]
pub fn check_environment() -> Result<EnvReport> {
    bail!(
        "kestrel-runtime preflight requires Linux (cgroup v2, overlayfs, /proc); \
         run this inside the Lima VM, not on the host."
    )
}

pub use kestrel_ns::threading::assert_single_threaded;
