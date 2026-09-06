# Phase 6 — Image Store & Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `kestrel-image` with a content-addressable blob store, OCI manifest/index handling, a real registry HTTP client (auth, manifest fetch, resumable bounded-parallel blob download), and streaming gzip/zstd decompression — per CHECKLIST.md's Phase 6 (24 tasks) and SPEC.md §10.

**Architecture:** All new code lives in `kestrel-image`, which gains a regular dependency on `kestrel-rootfs` (reusing its already-tested `chain_id`/`LayerStore` rather than duplicating them) and its own async stack (`tokio`+`reqwest`+`async-compression`), independent of `kestrel-runtime`'s single-threaded constraint (that rule is scoped to `kestrel-runtime` only). Every module is built and tested standalone before `pull.rs` composes them, matching this project's phase-by-phase assembly discipline.

**Tech Stack:** `tokio`, `reqwest` (stream feature), `async-compression` (tokio+gzip+zstd), `tokio-util` (`StreamReader`, bridges a `reqwest` byte stream into `AsyncBufRead`), `sha2` (already used identically in `kestrel-rootfs`), `wiremock` (dev-dep, local HTTP mock server for deterministic registry-protocol tests), `kestrel-oci::image_spec` (already-exported `Config`/`Descriptor`/`ImageConfiguration`/`ImageIndex`/`ImageManifest`), `kestrel-rootfs` (`chain_id`, `LayerStore`), `kestrel-image::apply` (Phase 4, `apply_layer` reused as-is).

---

## Real-API grounding this plan was written against

- `reqwest::Response::bytes_stream() -> impl Stream<Item = Result<Bytes>>` (needs the `stream` feature).
- `tokio_util::io::StreamReader::new(stream) -> StreamReader<S, B>`, which implements **both** `AsyncRead` and `AsyncBufRead` directly (confirmed via docs.rs) — this is the bridge from `reqwest`'s byte stream to what `async-compression`'s tokio decoders need, with no extra `BufReader` wrapper required.
- `async-compression`'s tokio decoders (`async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder}`) wrap an `AsyncBufRead` and themselves implement `AsyncRead`. **The exact module path (`tokio::bufread` vs `tokio::write` vs top-level) needs final confirmation against the resolved crate version** — docs.rs's rendering during plan-writing didn't expose the full module tree. Verify via `cargo doc -p async-compression --open` or the vendored source before trusting the import path literally; the overall approach (wrap `StreamReader` in a `{Gzip,Zstd}Decoder`, read decompressed bytes through it) is correct regardless of the exact path.
- `wiremock::MockServer::start().await`, `Mock::given(method("GET")).and(path("/v2/...")).respond_with(ResponseTemplate::new(200)...).mount(&server).await`, `server.uri()` for the base URL.
- `kestrel-rootfs::snapshot::{chain_id(parent: Option<&str>, diff_id: &str) -> String, LayerStore}` — already built, Phase 4.
- `kestrel-image::apply::apply_layer(tar: impl Read, dest: &Path, rootless: bool) -> Result<LayerStats>` — already built, Phase 4, synchronous.
- `kestrel-oci::image_spec::{Config, ConfigBuilder, Descriptor, ImageConfiguration, ImageConfigurationBuilder, ImageIndex, ImageManifest, RootFs, RootFsBuilder}` — already re-exported.
- The `kestrel-rootfs → kestrel-image` **dev**-dependency (Phase 4, for `tests/lifecycle.rs`) plus this phase's new `kestrel-image → kestrel-rootfs` **regular** dependency is not a cycle Cargo rejects (dev-deps are exempt) — the same pattern already proven working for `kestrel-ns`/`kestrel-cgroup` (Phase 3) and `kestrel-security`/`kestrel-init` (Phase 5). Confirm it builds; don't just assume.

---

## File Structure

```
crates/kestrel-image/
├── Cargo.toml                  — gains tokio/reqwest/async-compression/tokio-util/kestrel-rootfs; wiremock dev-dep
├── src/
│   ├── lib.rs
│   ├── apply.rs                 — unchanged (Phase 4)
│   ├── digest.rs                 — Digest newtype, streaming verify wrapper
│   ├── reference.rs               — image reference parsing, docker.io rewrite
│   ├── store.rs                    — content-addressable blob store
│   ├── auth.rs                      — WWW-Authenticate parsing, token fetch
│   ├── manifest.rs                   — platform selection, media-type compat
│   ├── registry.rs                    — HTTP client: manifest fetch, blob download+resume, retry
│   └── pull.rs                         — orchestration: bounded-parallel pull, decompress+hash, dedup, extract
└── tests/
    ├── apply.rs                — unchanged (Phase 4)
    ├── digest.rs
    ├── reference.rs
    ├── store.rs
    ├── registry.rs              — wiremock-backed protocol tests (auth, manifest, blob+resume, retry)
    ├── pull.rs                   — wiremock-backed full-pull-flow test
    └── pull_e2e.rs                — real, network-gated capstone (Docker Hub + mount/pivot/exec)
```

---

## Task 1: `kestrel-image` Cargo.toml — async stack, `kestrel-rootfs` dependency

**Files:**
- Modify: `crates/kestrel-image/Cargo.toml`

- [ ] **Step 1: Update Cargo.toml**

```toml
[package]
name = "kestrel-image"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
nix = { workspace = true, features = ["fs"] }
libc.workspace = true
tar = "0.4.45"
xattr = "1"
sha2 = "0.10"
kestrel-oci = { path = "../kestrel-oci" }
kestrel-rootfs = { path = "../kestrel-rootfs" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "fs", "time"] }
reqwest = { version = "0.12", features = ["stream", "json"], default-features = false, features = ["rustls-tls"] }
async-compression = { version = "0.4", features = ["tokio", "gzip", "zstd"] }
tokio-util = { version = "0.7", features = ["io"] }
futures-util = "0.3"
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tempfile = "3"
kestrel-ns = { path = "../kestrel-ns" }
wiremock = "0.6"
```

Note: `reqwest`'s `[features]` list above has a duplicate `features` key written out for clarity (`default-features = false` plus explicitly re-adding `rustls-tls` alongside `stream`/`json`) — Cargo.toml doesn't actually allow two `features = [...]` keys in one table; **merge them into one list**: `features = ["stream", "json", "rustls-tls"], default-features = false`. This is flagged here rather than silently fixed because it's exactly the kind of small-but-real mistake this plan's own review process should catch — implement it correctly (merged list), not as literally typo'd above. `rustls-tls` (not the default `default-tls`/OpenSSL) is chosen so the crate doesn't need a system OpenSSL dev package inside the Lima VM — confirm this reasoning by checking whether `libssl-dev` or similar was ever provisioned (per `.lima/kestrel.yaml`'s provisioning script from Phase 0/1) before trusting it's unnecessary; if OpenSSL already is available, plain `default-tls` is equally fine and simpler — verify rather than assume either way.

Before trusting these version pins, run `cargo add --dry-run` for each new dependency inside the VM to confirm what actually resolves (same discipline as every prior phase's Task 1) — the versions above are current-as-of-planning best guesses, not verified against a lockfile.

- [ ] **Step 2: Confirm it builds**

Run: `cargo build -p kestrel-image` inside the VM. This is a substantial dependency addition (first tokio/reqwest usage in the project) — if the build fails, diagnose the real cause (missing system TLS library, version conflict, wrong feature name) rather than working around it by downgrading scope.

## Context

Task 1 of 10. Establishes the crate's new async/networking dependency surface before any of the modules that use it exist.

## Your Job

1. Fix the Cargo.toml `features` duplication noted above before writing it.
2. Verify real resolvable versions for every new dependency.
3. Confirm `cargo build -p kestrel-image` succeeds (diagnosing, not routing around, any real failure).
4. Confirm `cargo build --workspace` still succeeds (the new `kestrel-rootfs` dependency edge is the first thing to verify doesn't create a real cycle problem, even though dev-deps are exempt — build it and see).
5. Report back — no git commands beyond what's needed to inspect files (no commits; this repo now has real git history from a separate tracking effort — do not commit, branch, or push anything as part of this plan's execution unless explicitly asked later).

---

## Task 2: `Digest` newtype and streaming verification

**Files:**
- Create: `crates/kestrel-image/src/digest.rs`
- Modify: `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-image/tests/digest.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/digest.rs

use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};

/// A content digest, `sha256:<64-hex>`. Only SHA-256 is supported — the
/// only algorithm the OCI distribution spec requires implementations to
/// support, and the only one this project's chain-ID/content-store design
/// ever produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    hex: String, // lowercase, 64 chars, no "sha256:" prefix
}

impl Digest {
    pub fn of_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Digest { hex: format!("{:x}", hasher.finalize()) }
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The path fragment this digest maps to under a content store's
    /// `blobs/sha256/` directory.
    pub fn store_relative_path(&self) -> String {
        format!("sha256/{}", self.hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let hex = s.strip_prefix("sha256:").context("digest must start with \"sha256:\"")?;
        bail_unless_valid_hex(hex)?;
        Ok(Digest { hex: hex.to_lowercase() })
    }
}

fn bail_unless_valid_hex(hex: &str) -> Result<()> {
    anyhow::ensure!(hex.len() == 64, "digest hex must be exactly 64 characters, got {}", hex.len());
    anyhow::ensure!(hex.chars().all(|c| c.is_ascii_hexdigit()), "digest hex must be all hex digits");
    Ok(())
}

/// Incrementally hashes bytes as they pass through, for verifying a
/// digest DURING a download rather than after it's fully buffered/written
/// — SPEC.md §10.2's explicit requirement, so a corrupt or malicious blob
/// is rejected before it's fully persisted. Wraps a plain `std::io::Read`;
/// the async registry client (Task 7) uses a parallel async-native
/// approach (hashing each chunk as it arrives from the byte stream) rather
/// than this synchronous wrapper, but both must agree on the same hashing
/// semantics — verified by Task 2's own tests and cross-checked against
/// Task 7's usage.
pub struct VerifyingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: std::io::Read> VerifyingReader<R> {
    pub fn new(inner: R) -> Self {
        VerifyingReader { inner, hasher: Sha256::new() }
    }

    /// Consumes the reader, returning the digest of everything read so far.
    /// Call only after fully reading `inner` (e.g. via `io::copy`).
    pub fn finish(self) -> Digest {
        Digest { hex: format!("{:x}", self.hasher.finalize()) }
    }
}

impl<R: std::io::Read> std::io::Read for VerifyingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_of_bytes_matches_known_sha256() {
        // echo -n "" | sha256sum
        let d = Digest::of_bytes(b"");
        assert_eq!(d.to_string(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_display_roundtrips_through_from_str() {
        let d = Digest::of_bytes(b"hello world");
        let s = d.to_string();
        let parsed: Digest = s.parse().unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn test_from_str_rejects_missing_prefix() {
        assert!("deadbeef".parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_rejects_wrong_length() {
        assert!("sha256:deadbeef".parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_rejects_non_hex() {
        let bad = format!("sha256:{}", "z".repeat(64));
        assert!(bad.parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_lowercases_hex() {
        let upper = format!("sha256:{}", "A".repeat(64));
        let d: Digest = upper.parse().unwrap();
        assert_eq!(d.hex(), "a".repeat(64));
    }

    #[test]
    fn test_verifying_reader_computes_correct_digest_while_passing_bytes_through() {
        let data = b"the quick brown fox";
        let mut vr = VerifyingReader::new(std::io::Cursor::new(data));
        let mut out = Vec::new();
        std::io::copy(&mut vr, &mut out).unwrap();
        assert_eq!(out, data, "reader must pass bytes through unchanged");
        assert_eq!(vr.finish(), Digest::of_bytes(data));
    }
}
```

Double-check `test_of_bytes_matches_known_sha256`'s expected hex against a real `sha256sum` of an empty input before trusting it verbatim — the well-known empty-string SHA-256 is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, but verify this yourself (`printf '' | sha256sum` inside the VM) rather than trusting a memorized constant, matching this project's "verify, don't assume" discipline even for widely-known values.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod digest;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image digest::` — expect 6 passed.

## Context

Task 2 of 10. Pure, unprivileged, no network/async needed here — `Digest` and `VerifyingReader` are plain synchronous types used by both the local content store (Task 4) and, via a parallel async-native pattern, the registry client (Task 7).

## Your Job

1. Verify the known-SHA-256 test value yourself before trusting it.
2. Implement exactly as specified.
3. Run tests, verify 6 pass.
4. Self-review, report back.

---

## Task 3: Image reference parsing

**Files:**
- Create: `crates/kestrel-image/src/reference.rs`
- Modify: `crates/kestrel-image/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/reference.rs

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
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod digest;
pub mod reference;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image reference::` — expect 7 passed.

## Context

Task 3 of 10. Pure parsing logic, no I/O. This grammar is a simplified version of Docker's real reference grammar (which is considerably more permissive/complex) — sufficient for CHECKLIST.md's stated requirement, not a full `distribution/reference` reimplementation.

## Your Job

Implement, run tests (7 expected), self-review the parsing logic against the 6 test cases' edge cases (especially the registry-vs-repository split heuristic), report back.

---

## Task 4: Content-addressable blob store

**Files:**
- Create: `crates/kestrel-image/src/store.rs`
- Modify: `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-image/tests/store.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/store.rs

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::digest::{Digest, VerifyingReader};

/// The content-addressable blob store: `<root>/content/blobs/sha256/<digest>`.
/// Holds raw fetched bytes (manifests, configs, compressed layer
/// tarballs) — distinct from `kestrel_rootfs::snapshot::LayerStore`, which
/// holds EXTRACTED layer contents keyed by chain-id. Both live under the
/// same overall data root but are populated/read independently.
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: PathBuf) -> Self {
        ContentStore { root }
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("content/blobs")
    }

    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.blobs_dir().join(digest.store_relative_path())
    }

    pub fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_file()
    }

    /// Writes `reader`'s bytes into the store, verifying against
    /// `expected` if given (SPEC.md §10.2: reject a corrupt/malicious blob
    /// during the write, not after). Write-to-temp-then-rename for
    /// atomicity — a reader crashing mid-write, or a digest mismatch,
    /// leaves no partial blob visible at the final path; a concurrent
    /// reader of an already-complete blob is never exposed to a
    /// half-written file.
    pub fn write_blob(&self, expected: Option<&Digest>, mut reader: impl Read) -> Result<Digest> {
        let dir = self.blobs_dir().join("sha256");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        let tmp_path = dir.join(format!(".tmp-{}", std::process::id()));
        let tmp_file = fs::File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        let mut verifying = VerifyingReader::new(&mut reader);
        let mut writer = std::io::BufWriter::new(tmp_file);

        let copy_result = std::io::copy(&mut verifying, &mut writer);
        let actual = verifying.finish();

        // Clean up the temp file on ANY failure path before propagating —
        // a write error or digest mismatch must never leave a stray
        // `.tmp-*` file behind for a later blob write to trip over.
        let cleanup_and_bail = |ctx: &str| -> Result<Digest> {
            let _ = fs::remove_file(&tmp_path);
            anyhow::bail!("{ctx}");
        };

        if let Err(e) = copy_result {
            return cleanup_and_bail(&format!("writing blob: {e}"));
        }
        if let Some(exp) = expected {
            if &actual != exp {
                return cleanup_and_bail(&format!("digest mismatch: expected {exp}, got {actual}"));
            }
        }

        let final_path = self.blob_path(&actual);
        fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("renaming {} to {}", tmp_path.display(), final_path.display()))?;
        Ok(actual)
    }

    /// Refcounting: `rmi` must never delete a blob another image still
    /// references. Refs are tracked as one file per (digest, owner)
    /// pair under `<root>/content/refs/<digest-hex>/<owner-id>` — an
    /// empty marker file, not a counter, so removing one owner's
    /// reference is a plain `remove_file`, immune to lost-update races
    /// a shared counter file would need extra locking to avoid.
    pub fn add_ref(&self, digest: &Digest, owner_id: &str) -> Result<()> {
        let dir = self.root.join("content/refs").join(digest.hex());
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::write(dir.join(owner_id), b"").with_context(|| format!("adding ref for {owner_id}"))
    }

    pub fn remove_ref(&self, digest: &Digest, owner_id: &str) -> Result<()> {
        let path = self.root.join("content/refs").join(digest.hex()).join(owner_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // already gone, fine
            Err(e) => Err(e).with_context(|| format!("removing ref {}", path.display())),
        }
    }

    pub fn is_referenced(&self, digest: &Digest) -> bool {
        let dir = self.root.join("content/refs").join(digest.hex());
        fs::read_dir(&dir).map(|mut d| d.next().is_some()).unwrap_or(false)
    }

    /// Deletes the blob if (and only if) nothing references it. Returns
    /// whether it was actually deleted.
    pub fn remove_blob_if_unreferenced(&self, digest: &Digest) -> Result<bool> {
        if self.is_referenced(digest) {
            return Ok(false);
        }
        let path = self.blob_path(digest);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// Writes a minimal `oci-layout` + `index.json` pair at the store
    /// root, per the OCI Image Layout spec — lets any OCI-compliant
    /// tool (not just kestrel) browse this store's images.
    pub fn write_oci_layout(&self, manifests: &[Digest]) -> Result<()> {
        fs::create_dir_all(&self.root).with_context(|| format!("creating {}", self.root.display()))?;
        let layout = serde_json::json!({ "imageLayoutVersion": "1.0.0" });
        fs::write(self.root.join("oci-layout"), serde_json::to_vec_pretty(&layout)?)
            .context("writing oci-layout")?;

        let manifest_entries: Vec<_> = manifests
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": d.to_string(),
                    "size": self.blob_path(d).metadata().map(|m| m.len()).unwrap_or(0),
                })
            })
            .collect();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": manifest_entries,
        });
        fs::write(self.root.join("index.json"), serde_json::to_vec_pretty(&index)?)
            .context("writing index.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_blob_then_read_back_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let data = b"hello content store";
        let digest = store.write_blob(None, std::io::Cursor::new(data)).unwrap();
        assert_eq!(digest, Digest::of_bytes(data));
        assert!(store.has_blob(&digest));
        let read_back = fs::read(store.blob_path(&digest)).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_write_blob_rejects_digest_mismatch_and_persists_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let wrong = Digest::of_bytes(b"something else entirely");
        let err = store.write_blob(Some(&wrong), std::io::Cursor::new(b"actual data")).unwrap_err();
        assert!(err.to_string().contains("digest mismatch"));
        assert!(!store.has_blob(&wrong));
        assert!(!store.has_blob(&Digest::of_bytes(b"actual data")), "no blob should be persisted under any digest on mismatch");
        // No stray temp files left behind.
        let entries: Vec<_> = fs::read_dir(tmp.path().join("content/blobs/sha256")).unwrap().collect();
        assert!(entries.is_empty(), "temp file must be cleaned up on digest mismatch");
    }

    #[test]
    fn test_write_blob_accepts_correct_expected_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let data = b"verified data";
        let expected = Digest::of_bytes(data);
        let actual = store.write_blob(Some(&expected), std::io::Cursor::new(data)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_refcounting_blocks_deletion_while_referenced() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let digest = store.write_blob(None, std::io::Cursor::new(b"shared layer")).unwrap();

        store.add_ref(&digest, "image-a").unwrap();
        store.add_ref(&digest, "image-b").unwrap();
        assert!(store.is_referenced(&digest));

        assert_eq!(store.remove_blob_if_unreferenced(&digest).unwrap(), false, "still referenced by image-b");
        assert!(store.has_blob(&digest));

        store.remove_ref(&digest, "image-a").unwrap();
        assert!(store.is_referenced(&digest), "image-b's ref must still hold");
        assert_eq!(store.remove_blob_if_unreferenced(&digest).unwrap(), false);

        store.remove_ref(&digest, "image-b").unwrap();
        assert!(!store.is_referenced(&digest));
        assert_eq!(store.remove_blob_if_unreferenced(&digest).unwrap(), true);
        assert!(!store.has_blob(&digest));
    }

    #[test]
    fn test_write_oci_layout_produces_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ContentStore::new(tmp.path().to_path_buf());
        let digest = store.write_blob(None, std::io::Cursor::new(b"a manifest")).unwrap();
        store.write_oci_layout(&[digest.clone()]).unwrap();

        let layout: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join("oci-layout")).unwrap()).unwrap();
        assert_eq!(layout["imageLayoutVersion"], "1.0.0");

        let index: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join("index.json")).unwrap()).unwrap();
        assert_eq!(index["manifests"][0]["digest"], digest.to_string());
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod digest;
pub mod reference;
pub mod store;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image store::` — expect 5 passed.

## Context

Task 4 of 10. Fully synchronous, no async needed — the blob store's own read/write API doesn't need to be async even though callers (Task 8's `pull.rs`) are; `write_blob` is called with the already-downloaded-and-verified-in-memory-or-temp-file bytes, or driven from a `spawn_blocking` context, matching how `apply_layer` is already handled.

## Your Job

Implement exactly as specified, run tests (5 expected), self-review the write-temp-then-rename atomicity and refcounting logic particularly carefully (this is the safety-critical piece of this task), report back.

---

## Task 5: `WWW-Authenticate` parsing and token fetch

**Files:**
- Create: `crates/kestrel-image/src/auth.rs`
- Modify: `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-image/tests/registry.rs` (started here, extended in Task 7)

- [ ] **Step 1: Implement the parser (pure, unprivileged)**

```rust
// crates/kestrel-image/src/auth.rs

use anyhow::{Context, Result};
use reqwest::header::HeaderMap;

/// A parsed `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
/// challenge, per the Docker Registry HTTP API V2 auth spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parses the `WWW-Authenticate` header from a 401 response. Only the
/// `Bearer` scheme is handled (what every major registry, including
/// Docker Hub, actually uses); `Basic` challenges are treated as "no
/// bearer challenge found" and the caller falls back accordingly.
pub fn parse_www_authenticate(headers: &HeaderMap) -> Result<Option<BearerChallenge>> {
    let Some(value) = headers.get(reqwest::header::WWW_AUTHENTICATE) else { return Ok(None) };
    let value = value.to_str().context("WWW-Authenticate header is not valid UTF-8")?;
    let Some(rest) = value.strip_prefix("Bearer ") else { return Ok(None) };

    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for pair in split_challenge_params(rest) {
        let Some((key, val)) = pair.split_once('=') else { continue };
        let val = val.trim_matches('"').to_string();
        match key {
            "realm" => realm = Some(val),
            "service" => service = Some(val),
            "scope" => scope = Some(val),
            _ => {}
        }
    }

    let realm = realm.context("Bearer challenge missing realm")?;
    Ok(Some(BearerChallenge { realm, service, scope }))
}

/// Splits `key="value with, commas",key2="value2"` on the commas that
/// separate PARAMETERS, not the ones that might appear inside a quoted
/// value — tracks quote state rather than a naive `split(',')`.
fn split_challenge_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

/// Fetches a bearer token from `challenge.realm`, with `service`/`scope`
/// query parameters if the challenge specified them. Anonymous (no
/// credentials) — CHECKLIST.md's 🟡 basic-auth item is out of scope for
/// this task's core flow but the `Client` parameter here is where it
/// would plug in later (`.basic_auth(user, Some(pass))` before `.send()`).
pub async fn fetch_token(client: &reqwest::Client, challenge: &BearerChallenge) -> Result<String> {
    let mut req = client.get(&challenge.realm);
    if let Some(service) = &challenge.service {
        req = req.query(&[("service", service)]);
    }
    if let Some(scope) = &challenge.scope {
        req = req.query(&[("scope", scope)]);
    }
    let resp = req.send().await.context("requesting auth token")?;
    let resp = resp.error_for_status().context("token endpoint returned an error status")?;
    let body: serde_json::Value = resp.json().await.context("parsing token response as JSON")?;
    // Registries use either "token" or "access_token" for the same thing.
    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .context("token response missing both \"token\" and \"access_token\" fields")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(reqwest::header::WWW_AUTHENTICATE, value.parse().unwrap());
        h
    }

    #[test]
    fn test_parse_full_bearer_challenge() {
        let h = headers_with(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#);
        let c = parse_www_authenticate(&h).unwrap().unwrap();
        assert_eq!(c.realm, "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:library/alpine:pull"));
    }

    #[test]
    fn test_parse_realm_only() {
        let h = headers_with(r#"Bearer realm="https://example.com/token""#);
        let c = parse_www_authenticate(&h).unwrap().unwrap();
        assert_eq!(c.realm, "https://example.com/token");
        assert_eq!(c.service, None);
    }

    #[test]
    fn test_parse_no_header_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(parse_www_authenticate(&h).unwrap(), None);
    }

    #[test]
    fn test_parse_basic_scheme_returns_none() {
        let h = headers_with(r#"Basic realm="something""#);
        assert_eq!(parse_www_authenticate(&h).unwrap(), None);
    }

    #[test]
    fn test_parse_missing_realm_is_an_error() {
        let h = headers_with(r#"Bearer service="registry.docker.io""#);
        assert!(parse_www_authenticate(&h).is_err());
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod auth;
pub mod digest;
pub mod reference;
pub mod store;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image auth::` — expect 5 passed.

- [ ] **Step 4: Write a `wiremock`-backed test for `fetch_token`**

```rust
// crates/kestrel-image/tests/registry.rs

use kestrel_image::auth::{fetch_token, BearerChallenge};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_fetch_token_sends_service_and_scope_and_parses_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .and(query_param("service", "registry.example.com"))
        .and(query_param("scope", "repository:foo:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "test-token-123" })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let challenge = BearerChallenge {
        realm: format!("{}/token", server.uri()),
        service: Some("registry.example.com".to_string()),
        scope: Some("repository:foo:pull".to_string()),
    };
    let token = fetch_token(&client, &challenge).await.unwrap();
    assert_eq!(token, "test-token-123");
}

#[tokio::test]
async fn test_fetch_token_accepts_access_token_field_too() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "access_token": "alt-field-token" })))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let challenge = BearerChallenge { realm: format!("{}/token", server.uri()), service: None, scope: None };
    let token = fetch_token(&client, &challenge).await.unwrap();
    assert_eq!(token, "alt-field-token");
}
```

Verify `wiremock`'s exact `matchers::query_param` signature and the `ResponseTemplate::set_body_json` method name against the resolved `wiremock` crate version before trusting this verbatim — this plan's grounding section flagged `wiremock` usage as verified only at a high level.

- [ ] **Step 5: Run**

Run: `cargo test -p kestrel-image --test registry` — expect 2 passed (no `--ignored`, no root needed; `wiremock` runs a real but purely local HTTP server on a random port).

## Context

Task 5 of 10. First task using `tokio`/`reqwest`/`wiremock` for real. `#[tokio::test]` needs the `macros` and `rt` (or `rt-multi-thread`) tokio features already added in Task 1.

## Your Job

Implement, run both the pure parser tests (5) and the wiremock-backed async tests (2), self-review the quote-aware comma-splitting logic specifically (a naive split would break on a scope value containing a comma, which real registry scopes can have for multi-resource pulls), report back.

---

## Task 6: Manifest and image-index handling

**Files:**
- Create: `crates/kestrel-image/src/manifest.rs`
- Modify: `crates/kestrel-image/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/manifest.rs

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

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::image_spec::{DescriptorBuilder, ImageIndexBuilder};
    use oci_spec::image::{Platform, PlatformBuilder};

    fn descriptor_for(os: &str, arch: &str, variant: Option<&str>, digest: &str) -> Descriptor {
        let mut pb = PlatformBuilder::default();
        pb.os(os).architecture(arch);
        if let Some(v) = variant {
            pb.variant(v);
        }
        let platform: Platform = pb.build().unwrap();
        DescriptorBuilder::default()
            .media_type("application/vnd.oci.image.manifest.v1+json")
            .digest(digest)
            .size(1234_i64)
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
    fn test_is_index_media_type() {
        assert!(is_index_media_type(OCI_INDEX));
        assert!(is_index_media_type(DOCKER_MANIFEST_LIST));
        assert!(!is_index_media_type("application/vnd.oci.image.manifest.v1+json"));
    }
}
```

Verify `oci_spec::image::Platform`/`PlatformBuilder`'s real field/builder-method names (`os`, `architecture`, `variant`) and whether `kestrel-oci::image_spec` already re-exports `Platform`/`PlatformBuilder` (add them to `crates/kestrel-oci/src/lib.rs`'s `image_spec` module if not — this project's established pattern this entire build has been that `kestrel-oci`'s re-export list needs a small addition in nearly every task that reaches for a new `oci_spec` type; check proactively rather than assuming it's covered) before trusting this test code verbatim.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod auth;
pub mod digest;
pub mod manifest;
pub mod reference;
pub mod store;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-image manifest::` — expect 3 passed.

## Context

Task 6 of 10. Pure logic, no network. Builds directly on `kestrel-oci::image_spec`'s existing re-exports.

## Your Job

Verify the `oci_spec::image::Platform` API and `kestrel-oci` re-export completeness first, implement, run tests (3 expected), report back.

---

## Task 7: Registry HTTP client — manifest fetch, blob download with resume, retry

**Files:**
- Create: `crates/kestrel-image/src/registry.rs`
- Modify: `crates/kestrel-image/src/lib.rs`
- Modify: `crates/kestrel-image/tests/registry.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/registry.rs

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::StatusCode;

use crate::auth::{fetch_token, parse_www_authenticate};
use crate::digest::Digest;
use crate::manifest::MANIFEST_ACCEPT_HEADER;
use crate::reference::ImageReference;

pub struct RegistryClient {
    http: reqwest::Client,
    token: Option<String>,
}

impl RegistryClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building HTTP client")?;
        Ok(RegistryClient { http, token: None })
    }

    fn manifest_url(reference: &ImageReference) -> String {
        format!("https://{}/v2/{}/manifests/{}", reference.api_host(), reference.repository, reference.manifest_reference())
    }

    fn blob_url(reference: &ImageReference, digest: &Digest) -> String {
        format!("https://{}/v2/{}/blobs/{}", reference.api_host(), reference.repository, digest)
    }

    /// Performs one request, and if it comes back 401 with a Bearer
    /// challenge, fetches a token and retries ONCE with it attached —
    /// covers both "never authenticated yet" and "token expired mid-pull".
    async fn get_with_auth(&mut self, url: &str, accept: Option<&str>) -> Result<reqwest::Response> {
        let send = |token: &Option<String>, accept: Option<&str>| {
            let mut req = self.http.get(url);
            if let Some(t) = token {
                req = req.bearer_auth(t);
            }
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            req
        };

        let resp = send(&self.token, accept).send().await.context("sending request")?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        let Some(challenge) = parse_www_authenticate(resp.headers())? else {
            return Ok(resp); // 401 with no bearer challenge — nothing more we can do
        };
        let token = fetch_token(&self.http, &challenge).await.context("fetching auth token")?;
        self.token = Some(token);
        send(&self.token, accept).send().await.context("retrying request with auth token")
    }

    /// Fetches a manifest (or index) as raw bytes plus its content digest
    /// (computed locally from the response body — registries also return
    /// a `Docker-Content-Digest` header, but computing it ourselves is
    /// what actually proves the bytes we received are what we think they
    /// are, matching this project's "verify, don't trust the transport"
    /// bias elsewhere).
    pub async fn fetch_manifest_bytes(&mut self, reference: &ImageReference) -> Result<(Vec<u8>, Digest, String)> {
        let url = Self::manifest_url(reference);
        let resp = self.get_with_auth(&url, Some(MANIFEST_ACCEPT_HEADER)).await?;
        let resp = resp.error_for_status().context("manifest fetch returned an error status")?;
        let media_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .to_string();
        let bytes = resp.bytes().await.context("reading manifest body")?;
        let digest = Digest::of_bytes(&bytes);
        Ok((bytes.to_vec(), digest, media_type))
    }

    /// Downloads a blob into `dest`, verifying its digest DURING the
    /// stream (hashing each chunk as it arrives, before it's written) —
    /// if `resume_from` is given, sends a `Range` header and appends
    /// rather than truncating, per CHECKLIST.md's resume requirement.
    /// On a digest mismatch, `dest` is truncated back to empty rather
    /// than left holding corrupt bytes under a name that looks complete.
    pub async fn download_blob_verified(
        &mut self,
        reference: &ImageReference,
        digest: &Digest,
        dest: &mut (impl tokio::io::AsyncWrite + Unpin),
        resume_from: Option<u64>,
    ) -> Result<()> {
        let url = Self::blob_url(reference, digest);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.http.get(&url);
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            if let Some(from) = resume_from {
                req = req.header(reqwest::header::RANGE, format!("bytes={from}-"));
            }
            let resp = req.send().await.context("sending blob request")?;

            if resp.status().is_server_error() || resp.status() == StatusCode::TOO_MANY_REQUESTS {
                if attempt >= 4 {
                    anyhow::bail!("blob download failed after {attempt} attempts: {}", resp.status());
                }
                let backoff = Duration::from_millis(200 * 2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
                continue;
            }
            let resp = resp.error_for_status().context("blob download returned an error status")?;

            use sha2::{Digest as _, Sha256};
            use tokio::io::AsyncWriteExt;
            let mut hasher = Sha256::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("reading blob chunk")?;
                hasher.update(&chunk);
                dest.write_all(&chunk).await.context("writing blob chunk")?;
            }
            let actual_hex = format!("{:x}", hasher.finalize());
            if actual_hex != digest.hex() {
                anyhow::bail!("blob digest mismatch: expected {digest}, got sha256:{actual_hex}");
            }
            return Ok(());
        }
    }
}
```

**Important caveat on the digest-verification-during-resume interaction**: the streaming hash above only covers bytes received in THIS call — if `resume_from` is set (a prior attempt already wrote some bytes to `dest`), the hash computed here is only of the *resumed portion*, not the whole blob, so the final `actual_hex != digest.hex()` check as written is WRONG for the resume case (it would compare a partial-content hash against the full-blob digest and always fail). Fix this before finalizing: either (a) don't verify per-chunk-hash against the full digest when resuming — instead re-verify by reading back and hashing the WHOLE assembled file from `dest`'s start after the download completes, or (b) track a running hasher that's seeded with the digest state from before the resume (not possible with `sha2`'s API, which doesn't support restoring hasher state from a partial digest) — meaning (a) is the only real option. Restructure `download_blob_verified` so that when `resume_from` is `Some`, the final verification step reads `dest` back from the beginning and hashes the whole thing, not just the newly-streamed chunk. Write a test proving this specifically (start a download, simulate a truncated first attempt, resume, verify the final full-file digest is checked correctly) — this is exactly the kind of subtly-wrong-under-a-specific-condition logic this project's review process exists to catch.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod auth;
pub mod digest;
pub mod manifest;
pub mod reference;
pub mod registry;
pub mod store;
```

- [ ] **Step 3: Append `wiremock`-backed tests to `tests/registry.rs`**

Cover: manifest fetch sends the correct `Accept` header and returns the right bytes/digest/media-type; a 401-then-token-then-retry flow succeeds; blob download computes the correct digest and rejects a mismatched one (serve deliberately wrong bytes from the mock, assert the error); a resumed download (mock a `Range` request, verify the `Range` header was actually sent, verify the resume-path digest fix from Step 1 works); a 503 response retried and eventually succeeding (mock the same endpoint to fail twice then succeed, assert exactly 3 requests were made and the client didn't give up early).

- [ ] **Step 4: Run**

Run: `cargo test -p kestrel-image --test registry` — expect the 2 tests from Task 5 plus at least 5 new ones (7+ total).

## Context

Task 7 of 10. The most complex task in this phase — real HTTP client logic with retry, resume, and auth-retry interacting. Budget real time for the resume/digest-verification fix flagged above; do not ship the naive version.

## Your Job

1. Fix the resume-verification bug identified in Step 1 before writing tests for it.
2. Implement the rest as specified.
3. Write and run the `wiremock` test suite, verify all pass.
4. Self-review the retry/backoff logic (does it actually cap at a bounded number of attempts? does a 4xx that ISN'T 401/429 correctly NOT retry, since retrying a permanent client error forever would be wrong?).
5. Report back.

---

## Task 8: Pull orchestration — bounded-parallel download, decompress-while-hash, dedup, extract

**Files:**
- Create: `crates/kestrel-image/src/pull.rs`
- Modify: `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-image/tests/pull.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-image/src/pull.rs

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use kestrel_oci::image_spec::ImageManifest;
use kestrel_rootfs::snapshot::{chain_id, LayerStore};
use tokio::sync::Semaphore;

use crate::digest::Digest;
use crate::reference::ImageReference;
use crate::registry::RegistryClient;
use crate::store::ContentStore;

#[derive(Debug, Clone)]
pub enum PullProgress {
    ManifestFetched { digest: Digest },
    LayerStart { digest: Digest, index: usize, total: usize },
    LayerDeduped { digest: Digest },
    LayerDownloaded { digest: Digest, bytes: u64 },
    LayerExtracted { digest: Digest, chain_id: String },
    Complete { chain_ids: Vec<String> },
}

const DEFAULT_MAX_CONCURRENT_LAYERS: usize = 4;

/// Pulls `reference` fully: manifest → config → every layer, deduped
/// against `store`'s already-fetched blobs AND `layer_store`'s
/// already-extracted chain-ids, extracting each new layer via
/// `apply_layer` (Phase 4, run via `spawn_blocking` so its synchronous
/// tar work never blocks an async worker thread). Returns the ordered
/// list of chain-ids (bottom-to-top) ready to hand to
/// `kestrel_rootfs::Snapshotter::prepare_snapshot`.
pub async fn pull_image(
    reference: &ImageReference,
    store: &ContentStore,
    layer_store: &LayerStore,
    rootless: bool,
    mut on_progress: impl FnMut(PullProgress) + Send,
) -> Result<Vec<String>> {
    let mut client = RegistryClient::new()?;

    let (manifest_bytes, manifest_digest, media_type) = client.fetch_manifest_bytes(reference).await?;
    on_progress(PullProgress::ManifestFetched { digest: manifest_digest.clone() });

    let manifest: ImageManifest = if crate::manifest::is_index_media_type(&media_type) {
        let index: kestrel_oci::image_spec::ImageIndex =
            serde_json::from_slice(&manifest_bytes).context("parsing manifest as an index")?;
        let selected = crate::manifest::select_platform(&index, "linux", std::env::consts::ARCH, None)?;
        let selected_digest: Digest = selected.digest().parse().context("parsing selected manifest's digest")?;
        let (bytes, _digest, _mt) = client.fetch_manifest_bytes(&ImageReference { digest: Some(selected_digest), ..reference.clone() }).await?;
        serde_json::from_slice(&bytes).context("parsing selected platform manifest")?
    } else {
        serde_json::from_slice(&manifest_bytes).context("parsing manifest")?
    };
    store.write_blob(None, std::io::Cursor::new(&manifest_bytes))?;

    let layers = manifest.layers();
    let total = layers.len();
    let semaphore = Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_LAYERS));

    let mut parent_chain: Option<String> = None;
    let mut chain_ids = Vec::with_capacity(total);

    // Sequential by design, NOT parallel-download-then-sequential-extract:
    // chain-id computation is inherently sequential (each layer's
    // chain-id depends on the previous one), and extraction order matters
    // for OverlayFS layering. The bounded-parallel requirement
    // (CHECKLIST.md) applies to the DOWNLOAD phase; this loop still
    // downloads each layer's blob with the semaphore limiting concurrent
    // in-flight requests, it just doesn't reorder extraction. A fuller
    // implementation could prefetch all layers in parallel into the
    // content store first, then extract sequentially from local disk —
    // left as a documented, deliberate simplification for this phase
    // rather than over-engineering the concurrency model on the first pass.
    for (i, layer_desc) in layers.iter().enumerate() {
        let _permit = semaphore.acquire().await.context("acquiring download semaphore")?;
        let layer_digest: Digest = layer_desc.digest().parse().context("parsing layer digest")?;
        on_progress(PullProgress::LayerStart { digest: layer_digest.clone(), index: i, total });

        if !store.has_blob(&layer_digest) {
            let mut buf = Vec::new();
            client.download_blob_verified(reference, &layer_digest, &mut buf, None).await?;
            store.write_blob(Some(&layer_digest), std::io::Cursor::new(&buf))?;
            on_progress(PullProgress::LayerDownloaded { digest: layer_digest.clone(), bytes: buf.len() as u64 });
        }

        // diffID = SHA-256 of the UNCOMPRESSED tar, per SPEC.md §10.1 —
        // decompress the just-stored blob while hashing it, entirely
        // separate from the (already-verified) compressed-blob digest.
        let blob_path = store.blob_path(&layer_digest);
        let media_type = layer_desc.media_type().to_string();
        let (diff_id, decompressed_path) = tokio::task::spawn_blocking({
            let blob_path = blob_path.clone();
            move || decompress_and_hash(&blob_path, &media_type)
        })
        .await
        .context("decompress_and_hash task panicked")??;

        let this_chain_id = chain_id(parent_chain.as_deref(), &diff_id);
        chain_ids.push(this_chain_id.clone());

        let diff_dir = layer_store.diff_dir(&this_chain_id);
        if diff_dir.is_dir() && diff_dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
            on_progress(PullProgress::LayerDeduped { digest: layer_digest.clone() });
        } else {
            let dest = layer_store.ensure_layer(&this_chain_id, parent_chain.as_deref())?;
            let rootless = rootless;
            tokio::task::spawn_blocking(move || {
                let f = std::fs::File::open(&decompressed_path).with_context(|| format!("opening {}", decompressed_path.display()))?;
                crate::apply::apply_layer(f, &dest, rootless)
            })
            .await
            .context("apply_layer task panicked")??;
            on_progress(PullProgress::LayerExtracted { digest: layer_digest, chain_id: this_chain_id.clone() });
        }

        parent_chain = Some(this_chain_id);
    }

    on_progress(PullProgress::Complete { chain_ids: chain_ids.clone() });
    Ok(chain_ids)
}

/// Decompresses `blob_path` (gzip or zstd, per `media_type`) into a
/// sibling temp file while computing the SHA-256 of the uncompressed
/// bytes, returning (diffID, path-to-decompressed-file). Synchronous —
/// called via `spawn_blocking` from the async pull loop above.
fn decompress_and_hash(blob_path: &std::path::Path, media_type: &str) -> Result<(String, PathBuf)> {
    use sha2::{Digest as _, Sha256};
    let compressed = std::fs::File::open(blob_path).with_context(|| format!("opening {}", blob_path.display()))?;
    let out_path = blob_path.with_extension("tar");
    let out_file = std::fs::File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?;
    let mut writer = std::io::BufWriter::new(out_file);
    let mut hasher = Sha256::new();

    if media_type.contains("gzip") {
        let mut decoder = flate2::read::GzDecoder::new(compressed);
        hash_and_copy(&mut decoder, &mut writer, &mut hasher)?;
    } else if media_type.contains("zstd") {
        let mut decoder = zstd::stream::Decoder::new(compressed).context("creating zstd decoder")?;
        hash_and_copy(&mut decoder, &mut writer, &mut hasher)?;
    } else {
        // Uncompressed tar (some registries/tools store layers this way).
        let mut r = compressed;
        hash_and_copy(&mut r, &mut writer, &mut hasher)?;
    }

    let diff_id = format!("sha256:{:x}", hasher.finalize());
    Ok((diff_id, out_path))
}

fn hash_and_copy(r: &mut impl std::io::Read, w: &mut impl std::io::Write, hasher: &mut impl std::io::Write) -> Result<()> {
    // Placeholder signature — `sha2::Sha256` doesn't implement
    // `std::io::Write` directly in a way that composes cleanly with a
    // generic `impl Write` hasher parameter here; this needs a real
    // `std::io::copy`-based implementation feeding the same bytes to both
    // `w` and a `Sha256::update` call (e.g. via a small `TeeWriter`
    // wrapper, similar in spirit to `digest.rs`'s own `VerifyingReader`
    // but for the write side). Verify the real approach against
    // `digest.rs`'s existing pattern and fix this signature/body before
    // treating this function as complete — flagged explicitly rather than
    // shipping code that doesn't actually compile.
    unimplemented!("implement via a tee-style writer, matching digest.rs's VerifyingReader pattern")
}
```

**This task has one deliberately unfinished function (`hash_and_copy`), flagged explicitly rather than silently wrong.** `Sha256` (from the `sha2` crate) implements `std::io::Write` itself via the `digest` crate ecosystem's blanket impls in some configurations, but relying on that without verifying is exactly the kind of unverified-API-usage this plan's grounding section already flagged as needing confirmation for `async-compression`. Fix `hash_and_copy` (and its call sites' types) using ONE of: (a) confirm `Sha256: std::io::Write` really holds for the resolved `sha2` version and simplify the signature to just take `&mut Sha256` directly, using `std::io::copy` with a small tee wrapper that writes to both `w` and the hasher, or (b) write a tiny local `struct TeeHasher<'a, W> { inner: W, hasher: &'a mut Sha256 }` implementing `Write` by writing to `inner` then `hasher.update()`-ing the same bytes, matching `digest.rs`'s `VerifyingReader` pattern exactly but for the write side instead of the read side. Do not leave `unimplemented!()` in the final code — this must be a real, compiling, tested implementation before the task is reported done.

Add `flate2 = "1"` and `zstd = "0.13"` to `Cargo.toml`'s `[dependencies]` (both are synchronous/blocking decompressors, used here specifically because `decompress_and_hash` runs inside `spawn_blocking`, not the async path — the async-compression streaming decoder from this plan's grounding section is an alternative that decompresses WHILE downloading rather than after; using it would mean restructuring this function to run inside the async download loop directly instead of as a separate post-download blocking step. Either approach satisfies CHECKLIST.md's requirement; this plan chose the simpler post-download blocking-decompression approach for Task 8, and the async-compression dependency added in Task 1 is available if a future revision wants the fully-streaming version instead — note this explicitly rather than silently dropping the unused dependency).

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod auth;
pub mod digest;
pub mod manifest;
pub mod pull;
pub mod reference;
pub mod registry;
pub mod store;
```

- [ ] **Step 3: Write `wiremock`-backed pull tests**

```rust
// crates/kestrel-image/tests/pull.rs
```

Cover: a full pull against a mock registry serving a hand-built single-layer manifest + config + gzip-compressed layer tarball, asserting the resulting chain-id matches an independently-computed expected value, the layer's contents actually land in `layer_store.diff_dir(...)`, and `on_progress` receives events in the expected order ending in `Complete`. A second test with the SAME base layer referenced from two different (mock) images, asserting the second pull's `LayerDeduped` event fires and `apply_layer` is not invoked twice (e.g. by checking a marker file `apply_layer` would have overwritten isn't touched the second time, or by timing/counting — pick whichever is more robust and non-flaky).

- [ ] **Step 4: Run**

Run: `cargo test -p kestrel-image --test pull` — expect 2+ passed.

## Context

Task 8 of 10. The orchestration layer tying every earlier task together. `hash_and_copy`'s fix is the one piece of real, non-trivial new logic in this task — everything else composes already-built pieces.

## Your Job

1. Fix `hash_and_copy` for real (per the note above) before anything else in this task can work.
2. Implement the rest, add `flate2`/`zstd` dependencies.
3. Write and run the pull tests, verify dedup genuinely isn't a no-op check (prove `apply_layer` really didn't run twice, not just that the test happened to pass).
4. Self-review: does the dedup check (`diff_dir.is_dir() && has entries`) have the same "empty vs missing vs populated" edge-case rigor `LayerStore::ensure_link`'s Phase 4 review required? Consider whether a partially-applied layer (Task 10 of Phase 4's plan flagged this exact "no completion marker" gap in `apply_layer` itself as a known, deliberately-deferred limitation) could cause this dedup check to wrongly treat a partial extraction as complete — if so, is that acceptable to inherit unchanged, or does this task need its own fix? Document your conclusion either way.
5. Report back.

---

## Task 9: Real end-to-end capstone test — pull, mount, pivot_root, exec

**Files:**
- Create: `crates/kestrel-image/tests/pull_e2e.rs`

- [ ] **Step 1: Write the test**

Root-gated AND network-gated (`#[ignore = "requires network and root"]`). Pulls a small, well-known public image (`docker.io/library/hello-world:latest` or `alpine:latest` — prefer whichever is smaller and more stable; `hello-world` is a few KB and rarely changes, making it a good choice for a repeatable test, but confirm it actually contains a `/bin/true`-equivalent or adjust to `alpine` if `hello-world`'s single binary doesn't fit the "run /bin/true" pattern CHECKLIST.md describes — verify the real image contents before committing to one, don't assume). Composes, for the first time in this project:

1. `pull_image()` (Task 8) against the real registry.
2. `kestrel_rootfs::Snapshotter::prepare_snapshot()` (Phase 4) with the returned chain-ids.
3. `kestrel_rootfs::overlay::mount_overlay()` (Phase 4).
4. `kestrel_rootfs::mounts::setup_standard_mounts()` + `kestrel_rootfs::mask::apply_default_masks()` (Phase 4).
5. `kestrel_rootfs::pivot::pivot_root()` (Phase 4).
6. `kestrel_init::exec::exec_into()` (Phase 5) running `/bin/true` (or whatever the real pulled image's shell/init binary is), inside a `run_isolated` + `unshare(CLONE_NEWNS)` + `MS_PRIVATE` mount-namespace-contained fork, per every established safety lesson from Phases 4-5.

Assert the exec'd process exits 0.

## Context

Task 9 of 10. This is the first test in the whole project composing Phases 4, 5, and 6 together — treat it with the same care Phase 4's and Phase 5's own lifecycle capstone tests received (parent-owns-any-tempdir, mount-namespace containment via the shared `kestrel-rootfs/tests/common` helper if reusable across crates, or a locally-duplicated equivalent if not).

## Your Job

1. Confirm the real chosen image's actual contents (what binary to exec) before writing the test, don't guess.
2. Write the test, applying every established safety/leak lesson from Phases 4/5 (mount-namespace isolation, parent-owns-tempdir, no dangling setuid/mount artifacts).
3. Run it (it needs both `sudo` AND real network — run manually, confirm it passes, note that it's excluded from `make test-root`'s normal sweep same as every other `#[ignore]`d test).
4. Self-review, report back.

---

## Task 10: Workspace-wide verification and cleanup

**Files:** none new — verification only.

- [ ] **Step 1:** `cargo build --workspace` — clean.
- [ ] **Step 2:** `cargo test --workspace` — all non-`#[ignore]`d tests pass.
- [ ] **Step 3:** `make test-root` — every root-gated (but not network-gated) test still passes; confirm the new network+root-gated `pull_e2e` test correctly does NOT run as part of this (it needs its own explicit `-- --ignored` invocation with network access, separate from the standard sweep).
- [ ] **Step 4:** `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] **Step 5:** `make check-no-tokio` — still passes (this phase adds tokio to `kestrel-image`, NOT `kestrel-runtime` — confirm the guard script still only checks `kestrel-runtime`'s dependency tree and correctly ignores `kestrel-image`'s new tokio dependency).
- [ ] **Step 6:** Grep for `todo!()`/`unimplemented!()` in `crates/kestrel-image` — zero matches expected (Task 8's `hash_and_copy` placeholder must have been resolved for real).
- [ ] **Step 7:** Sweep for leftover temp files/mounts after the full root-gated + (manually run) network-gated suite.
- [ ] **Step 8:** Extend the Makefile's NOTE comment to mention `kestrel-image` now also needs network access for its one `#[ignore]`d e2e test (informational — doesn't change what `make test`/`make test-root` actually run).

---

## Self-Review Notes

**Spec coverage:** CHECKLIST.md's Phase 6 items map to: content store/digest/refcounting/oci-layout → Tasks 2, 4. Manifest types/platform-selection/media-type-compat/chain_id → Task 6 (chain_id itself reused from Phase 4, not rebuilt). Registry client (auth/manifest-fetch/blob-resume/bounded-parallel/reference-parsing/docker.io-rewrite/retry-backoff) → Tasks 3, 5, 7, 8. Extraction (decompress-while-hashing/dedup/progress-events) → Task 8. All four required tests plus the 🟡 e2e → Tasks 2, 4, 8, 9.

**Placeholder scan:** two intentional, explicitly-flagged-and-must-be-resolved markers exist in this plan's initial code (Task 7's resume-digest-verification bug, Task 8's `hash_and_copy` stub) — both are real, load-bearing logic this plan couldn't fully resolve without live verification against resolved crate APIs, following the exact same "flag what's genuinely uncertain, don't guess" discipline Phase 5's plan used for `libseccomp`'s notify API (which the implementer then resolved for real, not left as a stub). Every task's final steps require zero remaining `todo!()`/`unimplemented!()`.

**Type consistency:** `pull_image`'s signature (`&ImageReference, &ContentStore, &LayerStore, bool, impl FnMut(PullProgress)`) is used consistently in Tasks 8-9. `RegistryClient::download_blob_verified`'s resume-fix (Task 7) must be reflected in how Task 8 calls it (currently calling with `resume_from: None` always — Task 8 doesn't itself implement resume-on-retry across pull attempts; that's a real, currently-unaddressed gap between "the primitive supports resume" and "the orchestration layer uses it," worth flagging to the implementer as a deliberate scope boundary: Task 7 builds the resume-capable primitive per CHECKLIST.md's own requirement, Task 8's orchestration doesn't yet have a retry-the-whole-pull-and-resume-partial-layers loop above it — that's reasonable for this phase's scope (a future daemon-level retry policy in `kestreld`, Phase 9, is the natural place for "resume an interrupted pull across process restarts") but should be stated explicitly, not silently absent.

**Known judgment calls flagged for the implementer/reviewer:**
- `async-compression`'s exact tokio-decoder module path (Task 1's grounding notes).
- `wiremock`'s exact matcher/response-builder method names (Tasks 5/7).
- `oci_spec::image::Platform`'s exact builder field names and whether `kestrel-oci` already re-exports it (Task 6).
- Task 8's choice of post-download blocking decompression over fully-streaming async-compression-based decompression — a real design simplification, stated explicitly rather than silently made.
- Task 9's exact test image choice depends on confirming real image contents first, not assumed.
