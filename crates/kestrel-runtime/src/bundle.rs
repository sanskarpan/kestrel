// crates/kestrel-runtime/src/bundle.rs

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::validate::SpecExt;

pub struct Bundle {
    pub path: PathBuf,
    pub spec: RawSpec,
}

pub fn load(bundle_path: &Path) -> Result<Bundle> {
    let config_path = bundle_path.join("config.json");
    let data = std::fs::read(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let spec: RawSpec = serde_json::from_slice(&data)
        .with_context(|| format!("parsing {}", config_path.display()))?;
    spec.spec.validate().context("validating config.json")?;
    Ok(Bundle {
        path: bundle_path.to_path_buf(),
        spec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::default_spec::default_spec;

    fn write_config(dir: &Path, spec: &kestrel_oci::runtime::Spec) {
        let raw = RawSpec {
            spec: spec.clone(),
            extra: serde_json::Map::new(),
        };
        let data = serde_json::to_vec_pretty(&raw).unwrap();
        std::fs::write(dir.join("config.json"), data).unwrap();
    }

    #[test]
    fn test_load_valid_bundle_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), &default_spec());

        let bundle = load(dir.path()).expect("valid bundle should load");
        assert_eq!(bundle.path, dir.path());
        assert_eq!(bundle.spec.spec.process().as_ref().unwrap().args().clone().unwrap(), vec!["sh".to_string()]);
    }

    #[test]
    fn test_load_rejects_invalid_spec_empty_process_args() {
        use kestrel_oci::runtime::ProcessBuilder;

        let dir = tempfile::tempdir().unwrap();
        let mut spec = default_spec();
        spec.set_process(Some(ProcessBuilder::default().args(vec![]).build().unwrap()));
        write_config(dir.path(), &spec);

        let result = load(dir.path());
        assert!(result.is_err(), "empty process.args should fail validation");
    }

    #[test]
    fn test_load_missing_config_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = load(dir.path());
        assert!(result.is_err(), "missing config.json should error");
    }
}
