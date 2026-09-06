# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
