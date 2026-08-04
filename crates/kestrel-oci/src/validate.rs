use std::collections::HashSet;

use thiserror::Error;

use crate::runtime::Spec;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("spec has no root, or root has an empty path")]
    MissingRoot,
    #[error("process.args must be non-empty")]
    EmptyProcessArgs,
    #[error("duplicate namespace type in linux.namespaces: {0:?}")]
    DuplicateNamespace(crate::runtime::LinuxNamespaceType),
    #[error("linux.namespaces requests a user namespace but uid_mappings/gid_mappings are missing or empty")]
    MissingIdMapCoverage,
}

pub trait SpecExt {
    fn validate(&self) -> Result<(), ValidationError>;
}

impl SpecExt for Spec {
    fn validate(&self) -> Result<(), ValidationError> {
        let root_ok = self
            .root()
            .as_ref()
            .map(|r| !r.path().as_os_str().is_empty())
            .unwrap_or(false);
        if !root_ok {
            return Err(ValidationError::MissingRoot);
        }

        let args_ok = self
            .process()
            .as_ref()
            .and_then(|p| p.args().clone())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if !args_ok {
            return Err(ValidationError::EmptyProcessArgs);
        }

        let Some(linux) = self.linux() else {
            return Ok(());
        };
        let namespaces = linux.namespaces().as_deref().unwrap_or(&[]);

        let mut seen = HashSet::new();
        for ns in namespaces {
            if !seen.insert(ns.typ()) {
                return Err(ValidationError::DuplicateNamespace(ns.typ()));
            }
        }

        let wants_userns = namespaces
            .iter()
            .any(|ns| ns.typ() == crate::runtime::LinuxNamespaceType::User);
        if wants_userns {
            let uid_ok = linux
                .uid_mappings()
                .as_ref()
                .map(|m| !m.is_empty())
                .unwrap_or(false);
            let gid_ok = linux
                .gid_mappings()
                .as_ref()
                .map(|m| !m.is_empty())
                .unwrap_or(false);
            if !uid_ok || !gid_ok {
                return Err(ValidationError::MissingIdMapCoverage);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceType, ProcessBuilder,
        RootBuilder, SpecBuilder,
    };

    fn minimal_valid_spec() -> Spec {
        SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build().unwrap())
            .process(
                ProcessBuilder::default()
                    .args(vec!["sh".into()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn test_valid_spec_passes() {
        assert!(minimal_valid_spec().validate().is_ok());
    }

    #[test]
    fn test_missing_root_rejected() {
        let mut s = minimal_valid_spec();
        s.set_root(None);
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_empty_process_args_rejected() {
        let mut s = minimal_valid_spec();
        s.set_process(Some(
            ProcessBuilder::default().args(vec![]).build().unwrap(),
        ));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_duplicate_namespace_rejected() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::Pid);
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns.clone(), ns])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_user_namespace_without_id_maps_rejected() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::User);
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_user_namespace_with_id_maps_accepted() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::User);
        let mapping = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(1u32)
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns])
            .uid_mappings(vec![mapping])
            .gid_mappings(vec![mapping])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_non_user_namespaces_without_id_maps_accepted() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::Pid);
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_user_namespace_with_only_uid_mapping_rejected() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::User);
        let mapping = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(1u32)
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns])
            .uid_mappings(vec![mapping])
            // gid_mappings deliberately omitted
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_err());
    }
}
