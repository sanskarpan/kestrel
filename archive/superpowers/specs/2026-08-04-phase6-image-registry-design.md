# Kestrel — Phase 6 (Image Store & Registry) Design

## Context

Phase 6 builds the parts of `kestrel-image` CHECKLIST.md's Phase 6 section
(24 tasks) and SPEC.md §10 describe but Phase 4 deliberately left out: the
content-addressable blob store, OCI manifest/index types, a real registry
HTTP client, and gzip/zstd layer decompression. This is the first genuinely
networked, asynchronous code in the project.

## 1. Crate ownership — resolving overlap with Phase 4

`chain_id()` and the layer store (`layers/<chain-id>/diff`) already exist,
are tested, and are in active use in `kestrel-rootfs::snapshot`
(`pub fn chain_id(parent_chain_id: Option<&str>, diff_id: &str) -> String`,
`pub struct LayerStore` with `ensure_layer`/`ensure_link`/`diff_dir`).
SPEC.md §16 assigns "chainID" to `kestrel-image`, but duplicating an
already-correct, already-tested chaining algorithm in a second crate would
be a real maintenance hazard (two implementations that must stay in sync
forever). Instead: `kestrel-image` gains a regular dependency on
`kestrel-rootfs` and reuses `chain_id`/`LayerStore` directly.

This does create a two-way relationship — `kestrel-rootfs` already has
`kestrel-image` as a **dev-dependency** (added in Phase 4 for
`tests/lifecycle.rs`'s use of `apply_layer`). A regular
`kestrel-image → kestrel-rootfs` edge plus a dev-only
`kestrel-rootfs → kestrel-image` edge is not a cycle Cargo rejects — dev-dependencies
are exempt from the cycle check, the exact same pattern already proven
working three times over (`kestrel-ns`/`kestrel-cgroup` in Phase 3,
`kestrel-security`/`kestrel-init` in Phase 5). Verify this still builds once
wired, per that established discipline, rather than assuming.

The content-addressable **blob store** this phase adds
(`content/blobs/sha256/<digest>`) is a genuinely new, separate concern from
`LayerStore`: it holds raw fetched bytes (manifests, configs, *compressed*
layer tarballs) keyed by digest, while `LayerStore` holds *extracted* layer
contents keyed by chain-id. Both live under the same data root
(`/var/lib/kestrel`, per SPEC.md §6.1) but are populated and read
differently.

## 2. New modules in `kestrel-image`

- `digest.rs` — `Digest` newtype (`sha256:<hex>`, parse/Display), a
  streaming-verification reader wrapper so a corrupt or malicious blob is
  rejected **during** download, not after it's fully written (SPEC.md
  §10.2's explicit requirement).
- `store.rs` — the blob content store: write-to-temp-then-rename
  atomicity, refcounting (`rmi` must never delete a blob another image
  still needs), `oci-layout` + `index.json` generation for local export.
- `reference.rs` — `[registry/]name[:tag][@digest]` parsing, defaulting to
  `docker.io/library/*:latest`, with the `docker.io` →
  `registry-1.docker.io` host rewrite.
- `auth.rs` — `WWW-Authenticate: Bearer realm=...,service=...,scope=...`
  parsing, token fetch with the correct scope, plus anonymous/basic
  fallback.
- `manifest.rs` — platform selection from an `ImageIndex` (os/arch/variant),
  Docker v2 schema2 ↔ OCI manifest media-type compatibility — built on
  `kestrel-oci::image_spec`'s existing `Config`/`Descriptor`/
  `ImageConfiguration`/`ImageIndex`/`ImageManifest` re-exports (already
  present from Phase 0/1, confirmed via `kestrel-oci/src/lib.rs`).
- `registry.rs` — the HTTP client: manifest fetch with the full
  four-media-type `Accept` header, blob download with `Range` resume
  support, retry with backoff on 429/5xx.
- `pull.rs` — orchestrates a full pull: resolve reference → fetch manifest
  (selecting a platform if it's an index) → fetch the config blob →
  bounded-parallel (`tokio::sync::Semaphore`, default 4) layer blob
  downloads → decompress-while-hashing each (computing the diffID from the
  *uncompressed* stream while the *compressed* bytes are simultaneously
  digest-verified against the manifest's declared digest) → skip extraction
  if the resulting chain-id's `LayerStore` entry already exists (dedup) →
  otherwise `apply_layer` (Phase 4, reused as-is) → a per-layer progress
  callback (`FnMut(PullProgress)`, not literal SSE — matching Phase 5's
  `notify.rs` precedent of building the mechanism here and leaving the
  transport to `kestreld`, Phase 9).

## 3. Async runtime — a first for this project, not a rule violation

PROMPT.md's Rule #2 ("`kestrel-runtime` must be single-threaded, no async
runtime") is scoped specifically to the `kestrel-runtime` crate — verified
by re-reading the rule's own wording, which never mentions other crates.
Registry pulling with bounded concurrency is a legitimately async-shaped
problem, so `kestrel-image` gets its own dependencies, independent of
`kestreld`'s (not-yet-built) async stack:

- `tokio` (`rt-multi-thread`, `macros`, `sync`, `fs`, `time` — verified via
  docs.rs which features gate what)
- `reqwest` (with the `stream` feature, for `Response::bytes_stream()`)
- `async-compression` (`tokio` + `gzip` + `zstd` features) for streaming
  decompression that never buffers a whole layer in memory
- `sha2` (already used identically in `kestrel-rootfs`, same version)

`apply_layer`'s synchronous tar extraction (Phase 4, unchanged) runs via
`tokio::task::spawn_blocking` from within the async pull pipeline, so it
never blocks an async worker thread for the duration of a potentially large
extraction.

## 4. Testing strategy

Continues this project's bias toward proving real behavior, split the same
way privileged-vs-unprivileged tests have been split since Phase 2:

- **Deterministic, no network**: content store write-temp-then-rename
  atomicity and refcounting, digest-mismatch-mid-stream rejection
  (`test_digest_mismatch_rejected`), chain-id known-value tests
  (`test_chain_id_known_values`, reusing `kestrel-rootfs::chain_id`),
  reference parsing (registry/tag/digest combinations, the docker.io
  rewrite), `WWW-Authenticate` header parsing, platform selection from a
  synthetic multi-platform index, `Accept` header construction.
- **Registry-protocol tests against a local mock server**: `wiremock` (a
  well-established, purpose-built crate for exactly this — mocking HTTP
  responses for client-side testing) as a dev-dependency, covering the
  auth-challenge → token-fetch → manifest-fetch → blob-download-with-Range-resume
  → 429/5xx-retry flow deterministically, without any real network
  dependency or flakiness.
- **One real, network-gated capstone test**
  (`#[ignore = "requires network"]`, matching CHECKLIST's own 🟡 tag on
  `test_pull_alpine_e2e`): confirmed the Lima VM can already reach
  `registry-1.docker.io` (a live `GET /v2/` returns the expected `401`
  auth challenge). This test pulls a real small image from Docker Hub,
  verifies content-addressed storage and layer dedup, then — the first time
  Phases 4, 5, and 6 compose together — actually `mount_overlay` →
  `pivot_root` → `kestrel_init::exec::exec_into`s `/bin/true` from the
  pulled rootfs and checks it exits 0, exactly matching CHECKLIST's "real
  pull, then run `/bin/true` from it." Not run by default (network tests
  are excluded from `make test`/`make test-root`'s normal sweep, same
  reasoning as every other `#[ignore]`d test in this project, plus Docker
  Hub's anonymous-pull rate limits make it unsuitable for repeated/CI runs).

## Out of scope for this increment

Wiring any of this into `kestreld`'s actual HTTP API or SSE event stream
(Phase 9). `kestrel-runtime`'s CLI-driven `pull`/`run` lifecycle commands
(Phase 8 assembly, same "Phases 2-6 each independently tested before
assembly" rule already applied to every prior phase). Registry push
(SPEC.md and CHECKLIST.md both scope this phase to pull only). Non-Docker-Hub
registry-specific auth quirks beyond the standard token-auth flow (ECR/GCR
session-token exchange, etc.) — the implementation targets the documented
Docker Registry HTTP API V2 spec generically, not any one vendor's
extensions.
