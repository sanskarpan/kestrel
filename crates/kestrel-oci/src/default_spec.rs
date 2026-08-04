use crate::runtime::{
    LinuxBuilder, LinuxNamespace, Mount, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
};

/// The standard Linux namespace set used by `runc spec`'s default
/// (non-rootless) bundle: pid, network, ipc, uts, mount, and cgroup — no
/// user namespace.
///
/// Delegates to `oci_spec::runtime::get_default_namespaces()`, the same
/// helper `Linux::default()` uses internally, so this stays in sync with
/// upstream's reference shape instead of hand-duplicating it.
pub fn default_namespaces() -> Vec<LinuxNamespace> {
    oci_spec::runtime::get_default_namespaces()
}

/// The standard mount set used by `runc spec`'s default bundle: `/proc`,
/// `/dev`, `/dev/pts`, `/dev/shm`, `/dev/mqueue`, `/sys`, and
/// `/sys/fs/cgroup`, with their canonical options.
///
/// Delegates to `oci_spec::runtime::get_default_mounts()`, the same helper
/// `Spec::default()` uses internally, so this stays in sync with upstream's
/// reference shape (e.g. `/dev/pts`'s `gid=5` option) instead of
/// hand-duplicating it.
pub fn default_mounts() -> Vec<Mount> {
    oci_spec::runtime::get_default_mounts()
}

/// Matches `runc spec`'s default bundle shape: a non-rootless container
/// with the standard namespace/mount set and `sh` as the entrypoint.
pub fn default_spec() -> Spec {
    // Every `.build()` below is on a hardcoded, fully-specified value with no
    // external input, so a failure here would be a programmer error, not a
    // runtime condition to recover from — `.unwrap()` is acceptable (contrast
    // with validate.rs, which returns `Result` because it validates specs
    // that may come from untrusted/external sources).
    SpecBuilder::default()
        .version("1.0.2")
        .root(
            RootBuilder::default()
                .path("rootfs")
                .readonly(false)
                .build()
                .unwrap(),
        )
        .hostname("kestrel")
        .process(
            ProcessBuilder::default()
                .terminal(true)
                .args(vec!["sh".to_string()])
                .cwd("/")
                .env(vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "TERM=xterm".to_string(),
                ])
                .no_new_privileges(true)
                .build()
                .unwrap(),
        )
        .mounts(default_mounts())
        .linux(
            LinuxBuilder::default()
                .namespaces(default_namespaces())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::LinuxNamespaceType;
    use crate::validate::SpecExt;

    #[test]
    fn test_default_spec_is_valid() {
        assert!(default_spec().validate().is_ok());
    }

    #[test]
    fn test_default_spec_has_standard_namespaces() {
        let spec = default_spec();
        let types: Vec<_> = spec
            .linux()
            .as_ref()
            .unwrap()
            .namespaces()
            .clone()
            .unwrap()
            .into_iter()
            .map(|ns| ns.typ())
            .collect();
        for want in [
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Cgroup,
        ] {
            assert!(types.contains(&want), "missing namespace {want:?}");
        }
        assert!(
            !types.contains(&LinuxNamespaceType::User),
            "not rootless by default"
        );

        // Exact match: exactly these 6 namespaces, in this order — nothing
        // extra and nothing missing (upstream's `get_default_namespaces()`
        // order, which we rely on).
        assert_eq!(
            types,
            vec![
                LinuxNamespaceType::Pid,
                LinuxNamespaceType::Network,
                LinuxNamespaceType::Ipc,
                LinuxNamespaceType::Uts,
                LinuxNamespaceType::Mount,
                LinuxNamespaceType::Cgroup,
            ]
        );
    }

    #[test]
    fn test_default_spec_standard_mounts_present() {
        let spec = default_spec();
        let destinations: Vec<_> = spec
            .mounts()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.destination().clone())
            .collect();
        for want in [
            "/proc",
            "/dev",
            "/dev/pts",
            "/dev/shm",
            "/sys",
            "/sys/fs/cgroup",
        ] {
            assert!(
                destinations.iter().any(|d| d == std::path::Path::new(want)),
                "missing mount {want}"
            );
        }

        // Exact match: nothing extra (e.g. a stray duplicate mount) and
        // nothing missing — `validate()` doesn't inspect mounts at all, so
        // this is the only thing that would catch drift here.
        let expected: Vec<std::path::PathBuf> = [
            "/proc",
            "/dev",
            "/dev/pts",
            "/dev/shm",
            "/dev/mqueue",
            "/sys",
            "/sys/fs/cgroup",
        ]
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect();
        assert_eq!(destinations, expected);
    }
}
