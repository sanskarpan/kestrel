//! Translation of an OCI image's `Config` (Env/Cmd/Entrypoint/WorkingDir)
//! onto a base runtime `Spec`'s process.
//!
//! `User` and `ExposedPorts`/`Volumes` are intentionally **not** handled
//! here: `User` needs a later task's `/etc/passwd` resolution (which needs
//! a real rootfs, not available at this phase), and `ExposedPorts`/`Volumes`
//! feed the networking and mount layers built in much later phases.

use crate::image_spec::ImageConfiguration;
use crate::runtime::Spec;

/// Applies an image's Env/Cmd/Entrypoint/WorkingDir onto a base runtime
/// spec's process. Does not touch `User` (needs a later task's `/etc/passwd`
/// resolution against a real rootfs) or `ExposedPorts`/`Volumes` (consumed
/// by the networking/mount layers, not the process spec).
///
/// Per Docker/OCI image-spec semantics: `Cmd` is only used when
/// `Entrypoint` is absent; when both are present they concatenate
/// (`entrypoint + cmd`). For `Env`, real Docker/runc behavior is that the
/// image's value wins for any key also present in the base spec's env —
/// entries are deduped by `KEY=` prefix rather than blindly appended.
pub fn apply_image_config(mut spec: Spec, img: &ImageConfiguration) -> Spec {
    let Some(cfg) = img.config().as_ref() else {
        return spec;
    };

    let mut process = spec.process().clone().unwrap_or_default();

    if let Some(env) = cfg.env() {
        let mut merged = process.env().clone().unwrap_or_default();
        for entry in env {
            let key = entry.split('=').next().unwrap_or(entry);
            merged.retain(|existing| existing.split('=').next().unwrap_or(existing) != key);
            merged.push(entry.clone());
        }
        process.set_env(Some(merged));
    }

    let entrypoint = cfg.entrypoint().clone().unwrap_or_default();
    let cmd = cfg.cmd().clone().unwrap_or_default();
    let args: Vec<String> = if !entrypoint.is_empty() {
        entrypoint.into_iter().chain(cmd).collect()
    } else if !cmd.is_empty() {
        cmd
    } else {
        Vec::new()
    };
    if !args.is_empty() {
        process.set_args(Some(args));
    }

    if let Some(wd) = cfg.working_dir() {
        if !wd.is_empty() {
            process.set_cwd(wd.into());
        }
    }

    spec.set_process(Some(process));
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_spec::default_spec;
    use oci_spec::image::{ConfigBuilder, ImageConfigurationBuilder};

    fn image_config(cfg: oci_spec::image::Config) -> oci_spec::image::ImageConfiguration {
        ImageConfigurationBuilder::default()
            .architecture(oci_spec::image::Arch::Amd64)
            .os(oci_spec::image::Os::Linux)
            .config(cfg)
            .rootfs(
                oci_spec::image::RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(vec![])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn test_entrypoint_and_cmd_concatenate() {
        let cfg = ConfigBuilder::default()
            .entrypoint(vec!["/entry.sh".to_string()])
            .cmd(vec!["--flag".to_string()])
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        assert_eq!(
            spec.process().as_ref().unwrap().args().clone().unwrap(),
            vec!["/entry.sh".to_string(), "--flag".to_string()]
        );
    }

    #[test]
    fn test_cmd_only_used_when_entrypoint_absent() {
        let cfg = ConfigBuilder::default()
            .cmd(vec!["sh".to_string(), "-c".to_string()])
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        assert_eq!(
            spec.process().as_ref().unwrap().args().clone().unwrap(),
            vec!["sh".to_string(), "-c".to_string()]
        );
    }

    #[test]
    fn test_env_and_working_dir_applied() {
        let cfg = ConfigBuilder::default()
            .env(vec!["FOO=bar".to_string()])
            .working_dir("/app".to_string())
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        let process = spec.process().as_ref().unwrap();
        assert!(process
            .env()
            .clone()
            .unwrap()
            .contains(&"FOO=bar".to_string()));
        assert_eq!(process.cwd(), &std::path::PathBuf::from("/app"));
    }

    #[test]
    fn test_duplicate_env_key_image_value_wins() {
        let cfg = ConfigBuilder::default()
            .env(vec!["PATH=/custom/path".to_string()])
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        let env = spec.process().as_ref().unwrap().env().clone().unwrap();
        let path_entries: Vec<&String> = env
            .iter()
            .filter(|e| e.split('=').next() == Some("PATH"))
            .collect();
        assert_eq!(path_entries.len(), 1);
        assert_eq!(path_entries[0], "PATH=/custom/path");
    }

    #[test]
    fn test_empty_working_dir_does_not_change_cwd() {
        let cfg = ConfigBuilder::default()
            .working_dir("".to_string())
            .build()
            .unwrap();
        let before_cwd = default_spec().process().as_ref().unwrap().cwd().clone();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        assert_eq!(spec.process().as_ref().unwrap().cwd(), &before_cwd);
    }

    #[test]
    fn test_missing_config_is_a_noop() {
        let img = ImageConfigurationBuilder::default()
            .architecture(oci_spec::image::Arch::Amd64)
            .os(oci_spec::image::Os::Linux)
            .rootfs(
                oci_spec::image::RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(vec![])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let before = default_spec();
        let before_args = before.process().as_ref().unwrap().args().clone();
        let after = apply_image_config(before, &img);
        assert_eq!(
            after.process().as_ref().unwrap().args().clone(),
            before_args
        );
    }
}
