use anyhow::{bail, Result};
use kestrel_oci::image_spec::{Descriptor, ImageIndex};

/// The four media types a registry client must be prepared to receive
/// from a manifest fetch (CHECKLIST.md's explicit requirement) — the two
/// real content types (OCI and Docker v2 schema2) each have a
/// single-platform and a multi-platform (index/manifest-list) form.
pub const MANIFEST_ACCEPT_HEADER: &str = concat!(
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.oci.image.index.v1+json, ",
    "application/vnd.docker.distribution.manifest.v2+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json",
);

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

pub fn is_index_media_type(media_type: &str) -> bool {
    media_type == OCI_INDEX || media_type == DOCKER_MANIFEST_LIST
}

/// Selects the manifest `Descriptor` matching `(os, arch, variant)` from a
/// multi-platform index. `variant` matches only if the index entry
/// specifies one too (an entry with no variant matches any requested
/// variant, since most single-variant platforms — amd64, for instance —
/// never set one at all).
pub fn select_platform<'a>(
    index: &'a ImageIndex,
    os: &str,
    arch: &str,
    variant: Option<&str>,
) -> Result<&'a Descriptor> {
    for m in index.manifests() {
        let Some(p) = m.platform() else { continue };
        if p.os().to_string() != os {
            continue;
        }
        if p.architecture().to_string() != arch {
            continue;
        }
        let entry_variant = p.variant().as_deref();
        if let Some(want) = variant {
            if entry_variant.is_some() && entry_variant != Some(want) {
                continue;
            }
        }
        return Ok(m);
    }
    bail!("no manifest in index matches os={os} arch={arch} variant={variant:?}");
}

/// Maps Rust's own architecture spelling (`std::env::consts::ARCH`, e.g.
/// `"aarch64"`, `"x86_64"`) to the spelling OCI/Docker manifest-list
/// `platform.architecture` fields actually use (`"arm64"`, `"amd64"`) —
/// these differ for every architecture this project has been run on so
/// far. Found via Task 9's real end-to-end pull test: on the project's
/// aarch64 Lima VM, passing `std::env::consts::ARCH` (`"aarch64"`)
/// unmapped straight into [`select_platform`] made every real multi-arch
/// pull fail with "no manifest in index matches ... arch=aarch64", since
/// every real registry's index entries say `"arm64"`, never `"aarch64"`.
/// Falls back to the Rust spelling unchanged for anything not in this
/// list, rather than guessing.
pub fn docker_platform_arch(rust_arch: &str) -> &str {
    match rust_arch {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use kestrel_oci::image_spec::{Digest, DescriptorBuilder, ImageIndexBuilder, PlatformBuilder};

    use super::*;

    fn descriptor_for(os: &str, arch: &str, variant: Option<&str>, digest: &str) -> Descriptor {
        let mut pb = PlatformBuilder::default().os(os).architecture(arch);
        if let Some(v) = variant {
            pb = pb.variant(v);
        }
        let platform = pb.build().unwrap();
        DescriptorBuilder::default()
            .media_type("application/vnd.oci.image.manifest.v1+json")
            .digest(Digest::from_str(digest).unwrap())
            .size(1234_u64)
            .platform(platform)
            .build()
            .unwrap()
    }

    #[test]
    fn test_select_platform_matches_exact_os_arch() {
        let d_amd64 = descriptor_for("linux", "amd64", None, &format!("sha256:{}", "a".repeat(64)));
        let d_arm64 = descriptor_for("linux", "arm64", None, &format!("sha256:{}", "b".repeat(64)));
        let index = ImageIndexBuilder::default()
            .schema_version(2_u32)
            .manifests(vec![d_amd64.clone(), d_arm64.clone()])
            .build()
            .unwrap();

        let selected = select_platform(&index, "linux", "arm64", None).unwrap();
        assert_eq!(selected.digest(), d_arm64.digest());
    }

    #[test]
    fn test_select_platform_no_match_errors() {
        let d = descriptor_for("linux", "amd64", None, &format!("sha256:{}", "c".repeat(64)));
        let index = ImageIndexBuilder::default().schema_version(2_u32).manifests(vec![d]).build().unwrap();
        assert!(select_platform(&index, "windows", "amd64", None).is_err());
    }

    #[test]
    fn test_docker_platform_arch_maps_rust_names_to_oci_names() {
        assert_eq!(docker_platform_arch("aarch64"), "arm64");
        assert_eq!(docker_platform_arch("x86_64"), "amd64");
        assert_eq!(docker_platform_arch("riscv64"), "riscv64", "unmapped arches pass through unchanged");
    }

    #[test]
    fn test_is_index_media_type() {
        assert!(is_index_media_type(OCI_INDEX));
        assert!(is_index_media_type(DOCKER_MANIFEST_LIST));
        assert!(!is_index_media_type("application/vnd.oci.image.manifest.v1+json"));
    }
}
