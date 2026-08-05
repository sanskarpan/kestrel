use anyhow::{Context, Result};

use crate::digest::Digest;

/// A parsed `[registry/]name[:tag][@digest]` image reference, per
/// CHECKLIST.md's Phase 6 registry-client requirements. Defaults match
/// Docker's own conventions: no registry → `docker.io`, no repository
/// namespace → `library/`, no tag (and no digest) → `latest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<Digest>,
}

impl ImageReference {
    /// The registry HTTP API host to actually connect to — `docker.io`
    /// itself doesn't serve the registry API; `registry-1.docker.io` does.
    pub fn api_host(&self) -> &str {
        if self.registry == "docker.io" { "registry-1.docker.io" } else { &self.registry }
    }

    /// What to request from `/v2/<name>/manifests/<reference>` — prefers
    /// the digest (immutable, exact) over the tag when both are present.
    pub fn manifest_reference(&self) -> String {
        match &self.digest {
            Some(d) => d.to_string(),
            None => self.tag.clone().unwrap_or_else(|| "latest".to_string()),
        }
    }
}

pub fn parse(input: &str) -> Result<ImageReference> {
    // Split off an @digest suffix first — it's unambiguous (the only `@`
    // this grammar allows) and must not be confused with a `:tag`.
    let (before_digest, digest) = match input.split_once('@') {
        Some((rest, d)) => (rest, Some(d.parse::<Digest>().context("parsing @digest suffix")?)),
        None => (input, None),
    };

    // The remaining `[registry[:port]/]name[:tag]` grammar: a leading
    // component containing a `.` or `:` (before the first `/`) is a
    // registry host; otherwise the whole thing (minus an optional
    // trailing `:tag`) is the repository name under the default registry.
    let (registry, rest) = match before_digest.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => ("docker.io".to_string(), before_digest.to_string()),
    };

    // A `:tag` suffix on the repository portion — but a `:port` may
    // already have been consumed as part of `registry` above, so this
    // split only ever sees the repository+tag remainder.
    let (repo_part, tag) = match rest.rsplit_once(':') {
        Some((r, t)) if !t.contains('/') => (r.to_string(), Some(t.to_string())),
        _ => (rest, None),
    };

    // Docker's implicit `library/` namespace only applies to the default
    // registry's single-segment repository names (e.g. "alpine" →
    // "library/alpine"), not to custom registries or already-namespaced
    // names.
    let repository = if registry == "docker.io" && !repo_part.contains('/') {
        format!("library/{repo_part}")
    } else {
        repo_part
    };

    Ok(ImageReference { registry, repository, tag, digest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bare_name_defaults_to_docker_io_library_latest() {
        let r = parse("alpine").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, None);
        assert_eq!(r.manifest_reference(), "latest");
        assert_eq!(r.api_host(), "registry-1.docker.io");
    }

    #[test]
    fn test_name_with_tag() {
        let r = parse("alpine:3.19").unwrap();
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, Some("3.19".to_string()));
    }

    #[test]
    fn test_namespaced_name_on_docker_io_no_library_prefix() {
        let r = parse("someuser/someimage:v1").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "someuser/someimage");
        assert_eq!(r.tag, Some("v1".to_string()));
    }

    #[test]
    fn test_custom_registry_with_port() {
        let r = parse("myregistry.example.com:5000/foo/bar:latest").unwrap();
        assert_eq!(r.registry, "myregistry.example.com:5000");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag, Some("latest".to_string()));
        assert_eq!(r.api_host(), "myregistry.example.com:5000");
    }

    #[test]
    fn test_digest_reference() {
        let digest_hex = "e".repeat(64);
        let r = parse(&format!("alpine@sha256:{digest_hex}")).unwrap();
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, None);
        assert_eq!(r.manifest_reference(), format!("sha256:{digest_hex}"));
    }

    #[test]
    fn test_tag_and_digest_together_digest_wins_for_manifest_reference() {
        let digest_hex = "f".repeat(64);
        let r = parse(&format!("alpine:3.19@sha256:{digest_hex}")).unwrap();
        assert_eq!(r.tag, Some("3.19".to_string()));
        assert!(r.digest.is_some());
        assert_eq!(r.manifest_reference(), format!("sha256:{digest_hex}"), "digest must win over tag when both present");
    }

    #[test]
    fn test_localhost_registry_no_dot_needed() {
        let r = parse("localhost/foo:latest").unwrap();
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "foo");
    }
}
