# Stretch Goals — Out of Scope with Design Notes

Phase 14 CHECKLIST marks three items as 🔵 stretch (intentionally not blocking
`1.0`): **CRIU checkpoint/restore**, **Wasm workloads**, and the **containerd
shim v2**. All three are stub-valued at `1.0` — the runtime, daemon, and CLI
compile, run containers end-to-end, and pass the conformance suite without any
of them. This document records *why* each is deferred and *what* would be
required to implement it, so a future contributor can pick one up without
re-reading the whole spec forest.

> **Status:** Design notes only. No new binaries, no `build.rs` probes, no
> extra `nix` features enabled for these paths. Any `#[cfg(...)]` stub is
> documented as `unimplemented!("stretch: ... see docs/STRETCH.md §N")` rather
> than a silent no-op.

---

## 1. CRIU checkpoint/restore

### What it would be

`kestrel checkpoint <id> --export /tmp/chkpt.tar` / `kestrel restore
--import /tmp/chkpt.tar --id <new-id>` — freeze a running container's
process tree, dump its memory, file-descriptor table, namespaces, and cgroup
state to disk, then recreate a bit-identical container from that dump.
Docker/Podman semantics: restore may land on the same host (live migration
needs extra plumbing; not assumed for `1.0`).

### Why it is out of scope

- **External dependency with a narrow kernel window.** CRIU (criu.org)
  requires a very recent kernel, `CONFIG_CHECKPOINT_RESTORE`, and a matching
  `criu` userspace binary whose RPC protocol drifts between releases. The
  runtime would need to `fork+exec criu dump/restore` (same isolation reason
  `kestreld` already `fork+exec`s `kestrel-runtime`) and stream its
  stdout/stderr plus the dump directory over the exec FIFO boundary. None of
  the Phase 0–9 kernel checks (`cgroup2`, `overlay`, `unprivileged_userns`)
  guarantee CRIU will actually work; a separate preflight probe
  (`criu check --extra`) would be needed.

- **Namespace-type coverage.** Lahat of the eight types (`kestrel-ns::NsType`)
  can be dumped, but Time ns offsets (`CLONE_NEWTIME`) and an already-pinned
  mount ns that was left unpinned on the Lima VM (see
  `crates/kestrel-runtime/src/create.rs:pin_namespaces`'s Mount/EINVAL
  fallback) both need special casing. The latter is why many runtimes gate
  CRIU behind `mount` namespace being fully pinned.

- **Rootfs + overlay interaction.** The dump must not capture the overlay's
  transient `workdir` state; the upperdir/merged view must be quiesced.
  `kestrel-runtime` would need to `cgroup.freeze` (already implemented in
  `kestrel-cgroup::control`) + sync the overlay before invoking CRIU, and the
  restore path would need to `prepare_snapshot` (via `kestrel-rootfs`) again
  from the same `lower_chain_ids` so the restored container re-attaches to an
  equivalent merged. The current `Snapshot`/`LayerStore` layout already stores
  `lower_chain_ids` (see `kestrel_rootfs::snapshot` and
  `kestreld::registry::layers.json`), so the *data* is there — the orchestration
  around it is not.

- **Daemon state coupling.** `kestreld`'s registry (`/run/kestrel/<id>/state.json`
  + `meta.json` + `layers.json`) plus `kestrel-shim`'s attach/seccomp sockets
  would need a pre-dump serialization step and a post-restore rehydration step.
  The shim is not currently checkpointable (it holds the attach PTY master);
  the simplest design is to kill the old shim and spawn a fresh one on restore,
  which callers must tolerate as a new `attach.sock`.

- **Conformance.** None of `oci-runtime-tools`'s validation suite exercises
  checkpoint/restore; it would be an extra, root-gated integration suite
  (`test_checkpoint_then_restore_memory_identical`) that must run single-threaded
  (`--test-threads=1`) because CRIU itself does global `ptrace` freezes.

### What it would need

1. `crates/kestrel-criu` — thin wrapper around `criu` RPC / CLI, feature-gated
   (`cfg(feature="criu")`), exposes `dump(id, dir, opts)` / `restore(dir, new_id)`
   that invoke `criu dump --tcp-established --ext-unix-sk --shell-job --images-dir <dir>`
   (flags depend on which namespaces are in the plan) and return the dump's
   `images/` metadata.

2. Runtime `checkpoint`/`restore` subcommands (`kestrel-runtime` is the only
   place that may touch `cgroup.freeze` + `criu dump`; the daemon must not
   link it). Same `fork+exec` rule as every other `kestreld → kestrel-runtime`
   path (`docs/superpowers/specs/2026-08-09-phase9-daemon-design.md` §2).

3. Bundle/manifest extension: store CRIU images as an additional content
   blob (or as a layer-adjacent tar) and record its digest in an annotation
   (`kestrel.criuImage`) so `kestreld` can `pull`/`push` it alongside the
   lower chain.

4. Daemon HTTP endpoints: `POST /containers/:id/checkpoint` and `POST
   /containers/restore`, both returning SSE progress (same framing as
   `POST /images/pull`), plus a CLI `kestrel checkpoint / restore`.

5. Integration tests + preflight: `kestrel-runtime --check-criu` probe, and a
   `#[ignore = "requires root + criu"]` e2e that dumps an idle `sleep 1000`
   container, restores it under a new id, and proves `state.json` pid changed
   but `/proc/<pid>/status` `VmRSS` and open-fd set are equivalent.

---

## 2. Wasm workloads via `wasmtime` as alternate entrypoint

### What it would be

An image whose config's `EntryPoint` is `["wasmtime", ...]` or whose OCI
`annotations["module.wasm.image/variant"]` marks a `.wasm` payload can be
run *without* a Linux process tree at all: `kestrel-init` (or a sibling
`kestrel-wasmtime` helper) loads the module via `wasmtime` and executes it
inside the already-prepared mount/cgroup/net namespaces, reusing the same
cgroup limits, seccomp profile, and network isolation. The WASI sandbox would
replace seccomp for pure WASI modules; mixed WASI+WASI-p2 modules would keep
the default seccomp notify path.

### Why it is out of scope

- **Entrypoint polymorphism.** Today `kestrel-init` ends in a single
  `execve(spec.process.args[0], spec.process.args)` — the kernel's own
  `ELF` loader is the whole abstraction. A Wasm entrypoint would need a
  pre-`execve` fork: one branch `execve`s a normal binary, the other `dlopen`s
  (or `fork+exec`s) a `wasmtime`-linked helper that `wasmtime::Module::from_file`
  + `Linker::instantiate` inside the same namespaces. The bootstrap path
  (`kestrel_oci::bootstrap::Bootstrap`) would need a `wasm_module_path`
  field alongside `process.args`, and `kestrel_oci::runtime::Process` would
  need a `wasi` annotation reader — neither exists today and both would ripple
  into the OCI conformance story.

- **Rootfs shape mismatch.** OCI image layers that carry a `.wasm` often have
  no valid Linux rootfs (no `/bin/sh`, no `/lib`). The current synthetic-layer
  trick in `kestrel_runtime::create::stage_bundle_rootfs_as_synthetic_layer`
  (deterministic `bundle-<id>` chain, then `Snapshotter::prepare_snapshot`)
  assumes a mountable directory tree. A WASI container would want a *data*
  directory (WASI preopens) rather than an overlay `merged` to `pivot_root`
  into — or it would want both, with `pivot_root` still happening but the
  WASI helper chrooting to a subdir of the merged. No decision here has been
  made; `wasm_runtime_spec` upstream is itself still draft.

- **Seccomp/cap model mismatch.** The default seccomp profile
  (`profiles/seccomp/default.json`, ~44 denied syscalls) assumes a real Linux
  binary making raw syscalls. A pure WASI module makes none of them; the
  seccomp filter would be either redundant (WASI already sandboxes) or actively
  harmful (WASI's `wasmtime` host syscalls for clock/getrandom may hit a
  default-deny rule). The capability sets (`kestrel-security::caps`) have the
  same mismatch: a WASI module has no Linux caps to drop.

- **Networking.** The bridge/veth + IPAM/NAT stack (`kestrel-net`) exposes a
  Linux `eth0` inside the netns. WASI Preview 2's `wasi:sockets` + component
  model would need a different NAT/DNAT story (WASI sockets are not raw
  `AF_INET` sockets in the container's netns; they are host-provided handles).
  There is no design yet for how `kestrel-net::attach_veth` + `ensure_bridge`
  would surface to a WASI module — the stretch design should probably expose
  them unchanged (the netns still exists) and let the WASI host decide, but
  that deliberately punts the hardest bit.

- **Tooling/USD.** `kestrel-cli` and `kestrel-tui` would need a `--wasm` flag
  and a different `exec`/`attach` story (there is no `setns` join into a PID 1
  that is not a Linux process). The daemon's `attach.sock` PTY bridge
  (`kestrel-shim::framing`) assumes byte streams over a Unix socket, which
  *does* map to WASI stdio, but the resize/tty path is meaningless for a WASI
  module that has no TTY.

### What it would need

1. `crates/kestrel-wasm` — `wasmtime` (or `wasmi`) host, WASI Preview 1+2
   preopen mapping from the container's `merged` into WASI dirs, fuel/metering
   wired to `cgroup` `cpu.max`/`memory.max`.

2. `kestrel-init` fork: `if spec.annotations.contains_key("module.wasm.image/variant") { exec_wasi() } else { exec_linux() }`, plus a static `kestrel-wasmtime` helper if the `wasmtime` crate cannot be statically linked into `kestrel-init`.

3. Spec/OCI changes: `kestrel-oci` extension for `wasi` config, and image-store
   support for `wasm` media types (`application/vnd.wasm.content.layer.v1+wasm`).

4. `kestreld`/`kestrel-cli` surface: `kestrel run --wasm <image>`, wasi
   contract for `attach`/`logs` (still stdout/stderr via `kestrel-shim`, but
   no PTY), and a seccomp/cap bypass for wasi-only containers.

5. Tests: `test_wasm_hello` (run a `hello.wasm` under the same cgroup/netns
   and assert exit 0 + bounded RSS), plus an interop test that a normal
   `alpine` and a `wasm` container can be on the same bridge.

---

## 3. containerd shim v2 (`io.containerd.kestrel.v2`)

### What it would be

A `containerd` shim v2 binary (`containerd-shim-kestrel-v2`) so a real
`containerd` (and therefore Kubernetes via the CRI) can drive `kestrel` as
its low-level runtime. The shim speaks the shim v2 TTRPC protocol
(`Create`, `Start`, `Delete`, `Exec`, `State`, `Pause`, `Resume`, `Kill`,
`Stats`, `Wait`, `Connect`) over a `containerd` vsock/Unix socket, and
delegates each call to `kestrel-runtime` (`create`/`start`/`kill`/`delete`/
`exec`/`state`) + `kestreld`'s cgroup/stats introspection endpoints — or,
more minimally, directly to the same syscalls (`kestrel-ns`, `kestrel-cgroup`,
`kestrel-rootfs`, `kestrel-security`) that `kestrel-runtime` already wraps.

### Why it is out of scope

- **Protocol surface.** Shim v2 is a long-lived, daemonized process per
  container (or per pod sandbox, depending on the CRI plugin mode). It must
  outlive `containerd` itself and re-attach to running containers after either
  side restarts. The current `kestrel-shim` (attach/seccomp supervisor) is a
  much simpler, per-container helper that `kestreld` owns; it does not implement
  the `shim::TaskService` protobuf/ttRPC service, the OCI `bundle` directory
  contract (`config.json` + `rootfs/` must be laid out exactly as
  `containerd`'s snapshotter expects), or the `containerd` event bus.

- **Snapshotter coupling.** `containerd`'s snapshotter already manages
  overlay layers; `kestrel`'s own `Snapshotter` + symlink farm (`kestrel-rootfs`)
  would become redundant or need to be made pluggable (the shim would mount
  the snapshotter-provided `rootfs` directly, rather than calling
  `Snapshotter::prepare_snapshot` from `kestrel-init`). Which side owns the
  `lowerdir` string would need a design doc of its own.

- **Cgroup manager.** `containerd` defaults to a `systemd` cgroup manager
  for Kubernetes; `kestrel-cgroup` implements only `cgroupfs` (parent dir +
  `subtree_control`) today. A real shim would need to support both, and the
  `Tasks`/`Stats` methods must return `containerd`-shaped protobuf, not the
  JSON that `GET /containers/:id/cgroup` and `/pressure` already return.

- **TTRPC/Protobuf toolchain.** The shim v2 spec is `protobuf` + `ttrpc`
  (or `connect` over a Unix socket, depending on `containerd` version). Pulling
  `prost` + `ttrpc` into the workspace (`kestrel-runtime` must stay single-threaded
  and `tokio`-free) would violate the `cargo deny` rule that forbids `tokio` in
  `kestrel-runtime`. The shim would necessarily be a separate crate that *does*
  use `tokio` (like `kestreld`), not something folded into `kestrel-runtime`
  itself — a workspace-level split that has not been prototyped.

- **Conformance of a different kind.** Passing `oci-runtime-tools` validates
  `kestrel-runtime`; a containerd shim needs the `cri-validation` and
  `ctr` conformance suites instead, which spin up a full `containerd` +
  `cni` stack. That test harness is operationally distinct from the Lima VM
  that `make test-root` already assumes.

### What it would need

1. `crates/kestrel-shim-v2` — new `tokio` binary, `prost` + `ttrpc` deps,
   implements `shimapi::TaskService` (generated from
   `github.com/containerd/containerd/api/types/task/task.proto`). Each method
   delegates to `kestrel-runtime` via `fork+exec` (preserving the single-thread
   rule) or to `kestrel-cgroup` / `kestrel-rootfs` directly for stats/mounts.

2. Bundle translation: `containerd`'s bundle (`config.json` + `rootfs/` +
   `mounts`) must be accepted verbatim; the shim's `Create` must *not*
   rewrite it into `kestreld`'s `kestrel.lowerChainIds` annotation path.
   `kestrel-init` would need a `containerd-bundle-mode` where it trusts the
   already-mounted rootfs rather than calling `prepare_snapshot`.

3. Daemon boundary: either `kestreld` becomes the shim's backend (shim is a
   thin TTRPC→HTTP translator to `kestreld`'s existing `/containers/*`
   endpoints), or the shim is standalone and `kestreld` remains for the
   `kestrel-cli`/`kestrel-tui`/web UX while Kubernetes bypasses it — the
   latter is simpler but duplicates cgroup/namespace bookkeeping.

4. Cgroup manager abstraction: `kestrel-cgroup`trait `CgroupDriver { create,
   destroy, add_process, stats }` with `CgroupFs` and `Systemd` impls;
   shim selects based on containerd's `linux.cgroup` spec.

5. CI: `containerd` + `containerd-shim-kestrel-v2` built inside the VM, then
   `ctr run --runtime io.containerd.kestrel.v2` e2e (plus a `crictl`/`kubelet`
   smoke), gated behind `make test-cri-required` (root + containerd installed).

---

## Non-goals that remain non-goals

These were already listed as out-of-scope in `docs/SECURITY.md` (threat
model table) and stay there: AppArmor/SELinux profiles, cosign/sigstore
image signing, encrypted layers, and a Kubernetes operator. Each would get
its own `docs/STRETCH-*.md` if promoted.

## How to propose a stretch implementation

1. Open a design doc under `docs/superpowers/specs/<date>-<stretch>-design.md`
   that answers: which host syscalls / kernel configs are assumed available,
   which existing crate is the natural owner, and what new CLI/HTTP surface
   appears.

2. Add the `Cargo.toml` feature gate (`criu` / `wasm` / `shim-v2`) and the
   new crate(s) under `crates/`, without adding `tokio` to `kestrel-runtime`
   or breaking `#![deny(clippy::undocumented_unsafe_blocks)]` / `cargo deny`.

3. Gate the conformance suite: every new e2e is `#[ignore = "requires ..."]`
   and runs only via `make test-root` with the extra host prereqs installed.

4. Update this file and `CHECKLIST.md` Phase 14 to point at the design doc and
   the new test make targets.
