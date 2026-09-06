# Kestrel — Phase 0 + Phase 1 Bootstrap Design

## Context

`kestrel` is a from-scratch, Docker-class container runtime specified in exhaustive
detail in `PROMPT.md`, `SPEC.md`, and `CHECKLIST.md` at the repo root — those three
files are the project's master design and are not re-derived here. This document
scopes and pins down the decisions needed to start implementation: the dev
environment and the concrete shape of Phase 0 (bootstrap) and Phase 1 (OCI spec
types), the first two of fourteen phases (328 tasks total per `CHECKLIST.md`).

Everything past Phase 1 (namespaces, cgroups, rootfs, security, networking, the
runtime binary, daemon, CLI, TUI, web dashboard) is out of scope for this
increment and will get its own plan once Phase 0/1 land.

## Host constraint that shapes this phase

The host is macOS (arm64), with no Rust toolchain and no Linux VM tooling
installed yet. `nix`'s Linux-only syscalls (`unshare`, `setns`, `mount`,
`pivot_root`, ...) simply don't exist on macOS — crates that call them
(`kestrel-ns`, `kestrel-cgroup`, `kestrel-rootfs`, `kestrel-security`,
`kestrel-init`, and `kestrel-net`'s netlink calls) cannot compile on the host at
all, VM or no VM. That's expected, not a bug to work around.

Phase 0 and Phase 1 are the one part of the project that's actually
host-agnostic: workspace plumbing, the OCI spec type definitions, and
validation/translation logic touch no kernel APIs. They can be written,
compiled, and unit-tested directly on macOS. The one exception is Phase 0's
`preflight::check_environment()`, which reads `/proc` and `statfs`s
`/sys/fs/cgroup` — it will compile-check on macOS (guarded appropriately) but
can only be *run* inside Linux, i.e., inside the Lima VM.

## 1. Dev VM: Lima + Ubuntu 24.04

- `.lima/kestrel.yaml`: arm64 Ubuntu 24.04 guest, native `vz` virtualization
  backend (no QEMU emulation needed on Apple Silicon), cloud-init provisioning
  installs: `build-essential`, `pkg-config`, `libseccomp-dev`, `iproute2`,
  `iptables`, rustup (stable toolchain), and `bun`.
- Mounts the repo read-write into the guest at the same path, so edits made on
  the host are immediately visible in-VM — no rsync step.
- Port-forwards `7777` (daemon HTTP/SSE) and `5173` (Vite dev server) to
  localhost so the web dashboard is reachable from a host browser while the
  daemon runs in-VM.
- `make vm-up` / `make vm-ssh` / `make vm-provision` wrap `limactl start/shell`
  so the Makefile stays the single entry point regardless of which VM tool is
  behind it later.
- This VM is *not* exercised by Phase 0/1 work itself (nothing here needs a
  kernel), but stands up now so Phase 2 can start immediately after, and so
  Phase 0's preflight check has somewhere to actually run.

## 2. Workspace scaffold (Phase 0)

- `Cargo.toml` workspace with the 12 member crates from SPEC §16:
  `kestrel-oci`, `kestrel-ns`, `kestrel-cgroup`, `kestrel-rootfs`,
  `kestrel-security`, `kestrel-net`, `kestrel-image`, `kestrel-runtime`,
  `kestrel-init`, `kestreld`, `kestrel-cli`, `kestrel-tui`.
- Shared workspace deps: `nix`, `libc`, `rustix`, `anyhow`, `thiserror`,
  `serde`, `serde_json`, `tracing`, `tracing-subscriber`.
- Per-crate deps follow the SPEC §1 crate-selection table (e.g. `caps` +
  `libseccomp` only in `kestrel-security`; `tokio`/`axum` only in `kestreld`;
  `rtnetlink`/`netlink-packet-route` only in `kestrel-net`).
- **Enforced invariant**: `kestrel-runtime` must never depend on `tokio`
  (directly or transitively) or spawn threads. A `xtask`-style check (`cargo
  tree -p kestrel-runtime | grep tokio` wired into `make test`) fails the
  build if that ever creeps in, per PROMPT.md Rule #2.
- `kestrel-oci` pulls in the `oci-spec` crate and re-exports its types; this is
  also where Phase 1's local extensions live.
- `preflight.rs` in `kestrel-runtime`, matching PROMPT.md's sample: cgroup2
  magic check, overlay-in-`/proc/filesystems` check, PSI availability
  (degrades gracefully), kernel version parse, `clone3`/`CLONE_INTO_CGROUP`
  probe. `assert_single_threaded()` alongside it, reading `Threads:` from
  `/proc/self/status`.
- `tracing` initialized with a `container_id` span field convention every
  later crate is expected to thread through.
- Error model: `thiserror` enums per crate, `anyhow::Result` only at binary
  entry points (`kestrel-runtime`, `kestreld`, `kestrel-cli`, `kestrel-tui`).
- `Makefile` targets: `build`, `test`, `test-root`, `oci-conformance`,
  `web-dev`, `tui`, plus the `vm-*` targets above.
- `web/`: `bun create vite . --template react-ts`, the dependency set from
  PROMPT.md Phase 0 (`@tanstack/react-query`, `@tanstack/react-table`, `d3`,
  `recharts`, `@xterm/xterm` + fit addon, `zustand`, `clsx`, `lucide-react`,
  Tailwind + shadcn/ui init with the listed component set), `vite.config.ts`
  proxying `/v1` and `/events` to `localhost:7777`.

## 3. OCI spec types (Phase 1)

- `kestrel-oci` re-exports `oci-spec`'s Runtime and Image Spec types
  (`Spec`, `Process`, `Root`, `Mount`, `Linux`, `LinuxResources`,
  `LinuxNamespace`, `LinuxIdMapping`, `LinuxCapabilities`, `LinuxSeccomp`,
  `LinuxDevice`, `LinuxRlimit`, `Hooks` with all 5 phases + deprecated
  `prestart`) rather than hand-rolling them, per PROMPT.md Phase 0's
  `cargo add -p kestrel-runtime ... oci-spec`. `State`/`Status` is **not**
  part of this re-export — it's a kestrel-local hand-rolled type instead
  (see below), because kestrel's `Status` needs a `Paused` variant
  (`cgroup.freeze`-backed) that isn't part of the official OCI schema.
- Kestrel-specific additions on top of the re-exports:
  - `Spec::validate()` — root path present, non-empty process args, no
    duplicate namespace types, id-map coverage.
  - `State`/`Status` (SPEC.md §9.2) — kestrel-local, not an `oci-spec`
    re-export; adds a `Paused` status the official schema doesn't have.
  - Default spec generator (`kestrel spec`) matching `runc spec` output.
  - Image config → runtime spec translation. **Scoped to Env, Cmd,
    Entrypoint, WorkingDir only** — `User` and `ExposedPorts`/`Volumes` are
    deliberately deferred: `User` needs a real rootfs's `/etc/passwd` (not
    available until Phase 4's rootfs mounting), and `ExposedPorts`/`Volumes`
    feed the networking/mount layers built in Phase 7/Phase 4. Applying them
    here would be dead code with nothing to consume it yet — revisit once
    those phases land.
  - `User` resolution (numeric / `name` / `name:group` / `uid:gid`) resolved
    against the **container's** `/etc/passwd`, never the host's — the
    resolution logic itself is built now (Task 13), but wiring it into
    image-config translation is deferred per the point above.
- Tests: round-trip an official OCI example `config.json` through serde with
  no field loss (unknown-field preservation intact); `validate()` rejects the
  three invalid-spec cases above; user resolution against a synthetic
  `/etc/passwd` fixture.

## Out of scope for this increment

Namespaces, cgroups, rootfs/overlay, security, image registry, networking,
the runtime/init binaries' actual fork dance, the daemon, CLI, TUI, and web
dashboard — everything from Phase 2 onward. Those get their own
brainstorm-or-plan pass once this scaffold is in and buildable.

## Testing strategy for this increment

- `cargo build --workspace` and `cargo test -p kestrel-oci` run directly on
  the macOS host (no VM needed — nothing in Phase 0/1 touches Linux-only
  syscalls except `preflight.rs`, which is compiled but not exercised here).
- `preflight::check_environment()` is validated by running it inside the Lima
  VM once the VM is up, as a smoke test that Phase 0's environment guard
  correctly detects a real cgroup v2 + overlay Linux host.
- `web/`: `bun run build` as a smoke test that the Vite scaffold compiles.
