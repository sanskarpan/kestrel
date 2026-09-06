# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-09-06

Dependency refresh, no behavior changes except where noted:

- `nix` 0.29 → 0.30 with `AsFd`/`OwnedFd` migration across
  `kestrel-runtime`, `kestrel-shim`, `kestrel-init`, `kestrel-security`
  tests, and `kestreld` (two `from_raw_fd` dances removed entirely)
- `thiserror` 1 → 2, `toml` 0.8 → 1.1, `tokio-tungstenite` 0.29 → 0.30,
  `flate2` patch, `@types/node` 24 → 26, `typescript` 6 → 7,
  `@tanstack/react-table` 8 → 9, GitHub Actions checkout/setup-node v7
- DNS test port-allocation race fixed (`serve_socket` split)
- Fixes RUSTSEC-2026-0258 (`h2` update); documents `paste`/`lru`/
  `webpki-roots` decisions in `deny.toml`

## [0.1.0] — 2026-09-06

First tagged release. All 328 `CHECKLIST.md` tasks across Phases 0–14 complete
and verified in the Lima VM. Prebuilt Linux aarch64 binaries are attached to
the GitHub release (x86_64 follows; `cargo build --release` works anywhere):

- OCI spec types, validation, default spec generator (`kestrel-oci`)
- 8 Linux namespaces with three-stage fork/unshare dance (`kestrel-ns`)
- cgroups v2 manager, PSI, `clone_into_cgroup` (`kestrel-cgroup`)
- OverlayFS snapshotter, `pivot_root`, masked/RO paths (`kestrel-rootfs`)
- Capabilities, `no_new_privs`, seccomp incl. notify supervisor (`kestrel-security`)
- Image store + Docker Hub registry client (`kestrel-image`)
- Bridge/veth/IPAM/NAT/DNS networking (`kestrel-net`)
- Single-threaded runtime binary + static PID-1 init (`kestrel-runtime`, `kestrel-init`)
- `tokio`/`axum` daemon with lifecycle, metrics, events, introspection APIs (`kestreld`)
- `clap` CLI, `ratatui` TUI, React dashboard (D3/Recharts/xterm.js)
- 22-test privileged integration suite + OCI conformance validation

Requirements: Linux ≥ 5.11, cgroup v2 unified, root (or delegated userns).
