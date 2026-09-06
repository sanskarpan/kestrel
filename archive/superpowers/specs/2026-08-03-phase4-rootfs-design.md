# Kestrel — Phase 4 (Rootfs, OverlayFS & pivot_root) Design

## Context

Phase 4 builds the OverlayFS snapshotter, layer extraction, and the
`pivot_root` dance that turns a stack of image layers into a container's
actual root filesystem. PROMPT.md's own Phase 4 section and SPEC.md §6-7
already give this in full working-code detail — this document covers crate
ownership (there's a real ambiguity CHECKLIST.md's phase grouping doesn't
resolve), environment/safety posture, and testing strategy.

**This is PROMPT.md's own Rule #1 phase** ("A wrong `umount2` or
`pivot_root` can wedge the host filesystem... develop in a VM"). We're
already in the Lima VM for exactly this reason. If something does wedge the
VM's mount state, the recovery path is `limactl stop kestrel && limactl
start .lima/kestrel.yaml` (or worst case, delete and recreate the instance
from the already-cached disk image) — not something to be paralyzed by, but
worth stating explicitly so agents don't hesitate to test real mount/
pivot_root operations, which is the entire point of having this VM.

## 1. Crate ownership — resolving a real ambiguity

CHECKLIST.md groups "Snapshotter / Layer application / pivot_root /
Standard mounts / Copy-up tracing / Tests" under one "Phase 4" heading. But
SPEC.md §16's crate table assigns them to **two different crates**:

- `kestrel-rootfs` — "overlay snapshotter, mounts, pivot_root, masking"
- `kestrel-image` — "content store, registry, layer apply, chainID"

Following SPEC.md's crate ownership (the authoritative source) rather than
CHECKLIST.md's task grouping:

- **`kestrel-rootfs`** gets: chain-ID/symlink-farm layer-store layout,
  `mount_overlay`/`unmount_overlay`, `pivot_root`, standard mount setup
  (`/proc`, `/sys`, `/dev`, etc.), masked/read-only path application,
  copy-up scanning.
- **`kestrel-image`** gets: `apply_layer()` (tar extraction, whiteout/opaque
  translation, path-traversal guard, hardlink handling) — but **not** the
  content store, registry client, or digest-based dedup, which are Phase 6
  work and stay out of scope here. `apply_layer` in this phase takes a
  caller-supplied `Read` and destination path directly, with no dependency
  on a not-yet-built `ContentStore` abstraction.

This mirrors the Phase 2/Phase 3 pattern (kestrel-ns ↔ kestrel-cgroup) of a
single "checklist phase" spanning two crates when the underlying spec calls
for it.

## 2. Environment (verified against the live VM)

`overlay` is in `/proc/filesystems` (confirmed since Phase 0's preflight
check). `busybox` is available in the VM, useful for building minimal test
tar fixtures (a tiny synthetic "layer" tarball with a regular file, a
whiteout, and an opaque-dir marker) without needing to pull a real image
from a registry (Phase 6 territory).

Mount/pivot_root operations need real root — this phase's tests split the
same way Phases 2-3 did: pure logic (chain-ID computation, symlink-farm
naming, tar-entry-to-whiteout translation, mount-option-string building) is
unprivileged and unit-tested directly; anything that actually calls
`mount()`/`pivot_root()`/`umount2()` needs `#[ignore = "requires root"]` and
runs via `make test-root`.

## 3. Safety-critical invariants this phase must empirically prove, not just implement

Per PROMPT.md's own Code Standards and the `test_host_mountinfo_unchanged`
test CHECKLIST.md calls for:

- `MS_PRIVATE` on `/` **before any mount work**, or container mounts leak
  into the host (VM) mount namespace and outlive the container.
- The `pivot_root(".", ".")` idiom's exact 6-step sequence (private-ize →
  bind-mount new_root onto itself → chdir → pivot_root → slave the old root
  → lazy-detach) — every step is load-bearing per SPEC.md §7.2's comments;
  skipping the `MS_SLAVE` step before `umount2` is a real historical bug
  class (the detach can otherwise propagate to the host).
- Read-only bind mounts need **two** `mount()` calls — a single
  `MS_BIND|MS_RDONLY` call silently ignores `MS_RDONLY`. This exact
  footgun should get an explicit test proving the one-call version is
  writable and the two-call version isn't (matching how earlier phases
  proved CVE-2014-8989's ordering empirically rather than trusting the
  code review alone).
- Path traversal in tar extraction (`../../etc/passwd`, absolute paths) is
  a real CVE class (tar-slip) — needs an explicit rejection test, not just
  code that "looks like" it guards against it.

Given this project's track record so far (real, kernel-verified bugs found
in nearly every phase by actually running code rather than trusting review),
the plan for this phase should bias toward writing root-gated integration
tests that exercise real mount/pivot_root behavior wherever feasible, not
just unit tests of the surrounding pure logic.

## Out of scope for this increment

Content-addressable blob storage, registry client, image manifest/config
parsing, gzip/zstd decompression, chain-ID-based extraction dedup (all
Phase 6). Security layer (capabilities/seccomp — Phase 5, though Phase 5's
code runs *after* this phase's pivot_root in the real init sequence, this
phase doesn't need to wait for it). Wiring any of this into `kestrel-init`/
`kestrel-runtime`'s actual CLI (Phase 8).
