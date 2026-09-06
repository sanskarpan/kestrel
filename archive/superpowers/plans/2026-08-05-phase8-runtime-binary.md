# Phase 8 — Runtime Binary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-runtime`'s nine lifecycle subcommands (`create`/`start`/`state`/`kill`/`delete`/`exec`/`ps`/`pause`/`resume`) and turn `kestrel-init` into the full static PID-1 binary, per CHECKLIST.md's Phase 8 (24 tasks) and the approved, twice-reviewed design (`docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md`).

**Architecture:** This is primarily assembly, not new-from-scratch work: `kestrel-ns::stages::run_stages` (Phase 2), `CgroupManager` (Phase 3, including its already-built `freeze`/`kill_all`), `kestrel-rootfs` (Phase 4), `kestrel-security` (Phase 5), and `kestrel-net` (Phase 7) are all reused as-is. New work: `kestrel-oci` gains a `Bootstrap` payload type and a `State.exit_code` field; `kestrel-runtime`'s `create` opens a dedicated two-phase sync socket, runs `createRuntime` hooks host-side, then hands off to `kestrel-init` via `execve`; `kestrel-init` does the rest of the container's own bootstrap (mounts → `createContainer` hooks → `pivot_root` → FIFO block → `startContainer` hooks → security → fork the entrypoint → reap it → write the exit code back to `state.json`).

**Tech Stack:** `clap` (CLI), `serde`/`serde_json` (Bootstrap/State), `nix` 0.29 (`signalfd`, `SigSet`, socketpair, `mkfifo`, `sethostname`), the already-vendored `kestrel-ns`/`kestrel-cgroup`/`kestrel-rootfs`/`kestrel-security`/`kestrel-net`/`kestrel-oci` crates.

---

## Real-API grounding this plan was written against

Verified directly against real, currently-resolved source (not guessed):

- **`run_stages`** (`crates/kestrel-ns/src/stages.rs`): `pub fn run_stages(plan: &NamespacePlan, cgroup_fd: Option<RawFd>, child_action: impl FnOnce() + 'static) -> Result<StageResult>` where `StageResult { init_pid: Pid, stage1_pid: Pid }`. `child_action` takes **zero parameters** — any data it needs must already be captured in the closure (fine, it's `'static`, so owned values — including an `OwnedFd`/`UnixDatagram` for the dedicated Phase-8 socket — can be moved in). When `cgroup_fd: Some(fd)` is passed, stage2 is placed in the cgroup atomically via `CLONE_INTO_CGROUP` *before* `child_action` ever runs — no manual join needed.
- **`NamespacePlan`** (`crates/kestrel-ns/src/types.rs`): `{ create: Vec<NsType>, uid_maps: Vec<IdMapping>, gid_maps: Vec<IdMapping> }`, with `.clone_flags()`, `.has_user_ns()`, `.has_pid_ns()`.
- **`CgroupManager`**: `freeze(&self, frozen: bool) -> Result<()>` (writes `cgroup.freeze`, polls `cgroup.events` for confirmation, 5s timeout) and `kill_all(&self) -> Result<()>` (writes `cgroup.kill` on 5.14+, falls back to iterate-and-`SIGKILL` on older kernels) — both **already exist and are already tested** in `crates/kestrel-cgroup/src/control.rs`. No new cgroup-layer code needed for `pause`/`resume`/`kill --all`.
- **`kestrel_ns::join::join_namespaces(pins: &BTreeMap<NsType, PathBuf>) -> Result<()>`** (`crates/kestrel-ns/src/join.rs`): joins every pinned namespace in `JOIN_ORDER` (Cgroup, Ipc, Uts, Net, Pid, Mount, Time, User). Confirmed: this does a flat `setns` loop with **no special-casing for PID** — `setns(fd, CLONE_NEWPID)` only affects the caller's subsequently-forked children, never the caller itself, so `exec_cmd.rs` MUST fork after calling this (§ Task 13).
- **`kestrel_init::exec::exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Infallible>`** (`crates/kestrel-init/src/exec.rs`, Phase 5): self-applies the full `kestrel_security::apply::apply_all` pipeline, then `execve`s. Never returns on success.
- **`oci_spec::runtime::Hook`** (vendored `oci-spec-0.10.0/src/runtime/hooks.rs`, read directly): `{ path: PathBuf, args: Option<Vec<String>>, env: Option<Vec<String>>, timeout: Option<i64> }` with getset accessors `.path()`, `.args()`, `.env()`, `.timeout()`. **The upstream crate's own doc comment confirms this plan's `createContainer`-before-`pivot_root` ordering independently of SPEC.md**: *"CreateContainer is a list of hooks to be run after the container has been created but but before `pivot_root` or any equivalent operation has been called."* `Hooks` (plural, the container struct with `create_runtime`/`create_container`/`start_container`/`poststart`/`poststop` fields) is already re-exported from `kestrel-oci::runtime`; `Hook` (singular) is **not** — Task 1 adds it.
- **`kestrel_oci::state::{State, Status}`** (`crates/kestrel-oci/src/state.rs`): currently `{ oci_version, id, status, pid, bundle, annotations }`, no `exit_code`, no atomic-write helper — Task 1 adds both.
- **`nix::sys::signalfd::{SignalFd, SfdFlags}`** (vendored `nix-0.29.0/src/sys/signalfd.rs`, read directly): `SignalFd::with_flags(mask: &SigSet, flags: SfdFlags) -> Result<SignalFd>`, `.read_signal(&self) -> Result<Option<siginfo>>` (blocks unless `SFD_NONBLOCK` was set; returns `Ok(None)` only in the nonblocking case on `EAGAIN`). `siginfo` is `libc::signalfd_siginfo`, whose `.ssi_signo` field is the raw signal number and `.ssi_pid`/`.ssi_status` carry `SIGCHLD`-specific data (not strictly needed — this plan `waitpid`s directly instead of trusting `ssi_status`, since `waitpid` is the authoritative source and multiple deaths can coalesce into one `signalfd` read as the module doc explicitly warns).
- **`kestrel_rootfs::mounts`** (`crates/kestrel-rootfs/src/mounts.rs`): currently has `setup_standard_mounts`, `create_default_devices`, `bind_default_devices` — no generic "bind-mount an arbitrary host file into the container" primitive yet. Task 2 adds one.
- **Not yet verified, flagged for the implementer**: `nix::unistd::{mkfifo, sethostname}`'s exact signatures (both are real, standard `nix` functions, but their precise argument types — e.g. whether `sethostname` takes `&str` vs `&OsStr` vs `impl NixPath` in this exact `nix` version — should be confirmed via `cargo doc -p nix --open` or the vendored source before writing Task 5's code verbatim, not assumed from a possibly-stale memory of the API). Time-namespace offset writing (`/proc/self/timens_offsets` or `/proc/<pid>/timens_offsets`) has no `nix` wrapper at all — this is a raw `/proc` file write with a specific line format (`<clockid> <offset-sec> <offset-nsec>` per line, per `man 7 time_namespaces`) that Task 5's implementer must verify against the real kernel doc / a working example before trusting any snippet in this plan. **Static linking**: whether `kestrel-init` (which depends on `kestrel-security`, which depends on the `libseccomp` C-library FFI crate) can genuinely be built for a musl target with full static linking is a real open question this plan does NOT resolve — Task 5 must verify this early (a throwaway `cargo build --target x86_64-unknown-linux-musl -p kestrel-init` or equivalent for whatever arch the Lima VM runs) before assuming the rest of the phase can proceed on a statically-linked `kestrel-init`. If musl+libseccomp genuinely doesn't work, the fallback (glibc static linking via `-C target-feature=+crt-static` on the default gnu target, which glibc supports for simple binaries but has known sharp edges around NSS/`getpwnam`-style calls — irrelevant here since `kestrel-init` doesn't do user/group name resolution) should be tried next; document whichever actually works.

## File Structure

```
crates/kestrel-oci/src/
├── bootstrap.rs              — Bootstrap payload type + socket send/recv (Task 1)
├── state.rs                  — MODIFIED: + exit_code field, + write_atomic (Task 1)
└── lib.rs                    — MODIFIED: + Hook re-export, + bootstrap module (Task 1)

crates/kestrel-rootfs/src/
└── mounts.rs                 — MODIFIED: + bind_mount_file (Task 2)

crates/kestrel-runtime/src/
├── bundle.rs                 — OCI bundle loading + validation (Task 3)
├── state.rs                  — state.json read + status-refresh wrapper (Task 3)
├── hooks.rs                  — poll-based (no-thread) hook execution (Task 4)
├── create.rs                 — `create` subcommand (Task 8)
├── start.rs                  — `start` subcommand (Task 9)
├── state_cmd.rs              — `state` subcommand (Task 10)
├── ps.rs                     — `ps` subcommand (Task 10)
├── kill.rs                   — `kill` subcommand (Task 11)
├── pause.rs / resume.rs      — `pause`/`resume` subcommands (Task 11)
├── delete.rs                 — `delete` subcommand, 7-step teardown (Task 12)
├── exec_cmd.rs                — `exec` subcommand (Task 13)
├── cli.rs                     — clap derive (Task 14)
├── main.rs                    — MODIFIED: wires cli.rs in (Task 14)
├── preflight.rs                — UNCHANGED (already exists)
└── lib.rs                      — MODIFIED: new module wiring

crates/kestrel-init/src/
├── bootstrap.rs                 — receives the Bootstrap payload (Task 5)
├── mounts.rs                     — rootfs/pivot/hostname/timens orchestration (Task 5)
├── fifo.rs                        — exec-FIFO block (Task 6)
├── reaper.rs                       — SIGCHLD reap loop (Task 6)
├── main.rs                          — MODIFIED: full PID-1 wiring (Task 7)
├── exec.rs                           — UNCHANGED (Phase 5)
├── pdeathsig.rs                       — UNCHANGED, unused by this phase's flow
└── lib.rs                              — MODIFIED: new module wiring

crates/kestrel-runtime/tests/
├── fixtures/lifecycle_fixture.rs        — synthetic static test binary (Task 15)
└── lifecycle.rs                          — the 5 required tests (Task 16)
```

---

## Task 1: `kestrel-oci` — `Hook` re-export, `State.exit_code`, `Bootstrap` payload

**Files:**
- Modify: `crates/kestrel-oci/src/lib.rs`
- Modify: `crates/kestrel-oci/src/state.rs`
- Create: `crates/kestrel-oci/src/bootstrap.rs`

- [ ] **Step 1: Add the `Hook` re-export**

```rust
// crates/kestrel-oci/src/lib.rs — add `Hook` to the existing runtime re-export list, alongside the already-present `Hooks`
pub mod runtime {
    pub use oci_spec::runtime::{
        // ... existing re-exports unchanged ...
        Hook,
        Hooks,
        // ... existing re-exports unchanged ...
    };
}
```

- [ ] **Step 2: Extend `State` with `exit_code`, add `write_atomic`**

```rust
// crates/kestrel-oci/src/state.rs — add to the existing State struct

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Not part of the official OCI state schema — same kind of
    /// kestrel-specific extension `Status::Paused` already is. `None`
    /// while the container hasn't stopped yet; `Some(code)` once
    /// kestrel-init's reaper has observed the entrypoint's real exit
    /// status and written it here (128+signum for a signal death, the
    /// raw exit code otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl State {
    /// Write-temp-then-rename, the same atomicity pattern every other
    /// piece of durable state in this project uses (kestrel-image's
    /// ContentStore, kestrel-net's Ipam, etc.). Lives here (not
    /// duplicated in both kestrel-runtime's and kestrel-init's own
    /// wrapper modules) because BOTH binaries need to write state.json
    /// atomically — kestrel-runtime during create/start/delete,
    /// kestrel-init once, when the entrypoint exits.
    pub fn write_atomic(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use anyhow::Context;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp_path = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self).context("serializing State")?;
        std::fs::write(&tmp_path, &data).with_context(|| format!("writing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path).with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;
        Ok(())
    }

    pub fn read(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))
    }
}
```

Update `state.rs`'s existing `test_state_round_trips_through_json` test to also construct a `State` with `exit_code: None` (must still compile) and add two new tests: `test_exit_code_round_trips_when_present` (a `State` with `exit_code: Some(42)`, JSON round-trip, assert equality) and `test_write_atomic_then_read_round_trips` (write to a tempdir path, read back, assert equality, and assert no `.tmp` file survives).

- [ ] **Step 3: `Bootstrap` payload type + socket transport**

```rust
// crates/kestrel-oci/src/bootstrap.rs
//
//! The payload `kestrel-runtime`'s `create` command sends to `kestrel-init`
//! across the `execve` boundary, over a dedicated Phase-8 socketpair — see
//! docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md §1.
//! Distinct from Phase 2's own internal id-map sync socket
//! (kestrel_ns::sync), which is a different, narrower protocol local to
//! the three-stage dance itself.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::runtime::{Hook, LinuxCapabilities, LinuxSeccomp, Process};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPlan {
    pub lower_chain_ids: Vec<String>,
    pub rootless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSet {
    pub create_container: Vec<HookSpec>,
    pub start_container: Vec<HookSpec>,
}

/// A plain-data mirror of `oci_spec::runtime::Hook` — `Hook` itself is
/// `Serialize`/`Deserialize` already (confirmed: it derives `Serialize,
/// Deserialize` in the vendored source), so this wrapper type is NOT
/// strictly necessary; `Vec<Hook>` could be used directly in `HookSet`
/// above. Kept as a thin alias-via-newtype only if the plan's Task 4
/// implementation finds a real reason `Hook`'s own (de)serialization
/// (e.g. its `camelCase` renaming, meant for config.json compatibility)
/// doesn't fit this internal-only payload — otherwise, SIMPLIFY: just use
/// `Vec<Hook>` directly and delete this `HookSpec` type. Flagged rather
/// than resolved here since it's a two-line simplification decision best
/// made with the real code in front of the implementer, not agonized
/// over in the plan.
pub type HookSpec = Hook;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub container_id: String,
    pub mount_plan: MountPlan,
    pub process: Process,
    pub capabilities: Option<LinuxCapabilities>,
    pub seccomp: Option<LinuxSeccomp>,
    pub hooks: HookSet,
    pub hostname: Option<String>,
    /// Raw lines for `/proc/self/timens_offsets`, already formatted —
    /// see this plan's Task 5 note on verifying the real format before
    /// trusting a specific string shape here.
    pub timens_offsets: Vec<String>,
    /// Host-side path to the exec FIFO (created by `create.rs` via
    /// `mkfifo`) — used by kestrel-init to know what to bind-mount, not
    /// what to open for reading (it opens `fifo_container_path` instead,
    /// post-pivot).
    pub fifo_host_path: PathBuf,
    pub fifo_container_path: PathBuf,
    /// Where kestrel-init should write exit_code/status once the
    /// entrypoint dies.
    pub state_json_path: PathBuf,
}

/// Sends `bootstrap` as a length-prefixed JSON message over `fd`. Called
/// by `create.rs`'s `child_action` closure — NOT by kestrel-init.
pub fn send_bootstrap(fd: RawFd, bootstrap: &Bootstrap) -> Result<()> {
    let json = serde_json::to_vec(bootstrap).context("serializing Bootstrap")?;
    let len = (json.len() as u32).to_be_bytes();
    // SAFETY-equivalent note for reviewers: this uses a raw fd via
    // std::os::unix::net::UnixDatagram::from_raw_fd's safe wrapper isn't
    // applicable here if `fd` isn't itself a datagram socket — verify
    // during implementation whether the Phase-8 dedicated socket is a
    // UnixDatagram (message-boundary-preserving, simpler) or a
  // UnixStream/plain socketpair (byte-stream, needs the length prefix
    // this function already writes defensively). Using UnixDatagram end
    // to end (matching Phase 2's own sync.rs convention, which already
    // uses UnixDatagram for its own socket) is the simpler, precedented
    // choice — if so, the length-prefix here is technically redundant
    // (datagrams preserve message boundaries) but harmless to keep for
    // uniformity with the stream case; confirm and simplify if desired
    // during implementation.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&len).context("writing bootstrap length prefix")?;
    file.write_all(&json).context("writing bootstrap payload")?;
    std::mem::forget(file); // don't close the fd — execve needs it to survive
    Ok(())
}

pub fn recv_bootstrap(fd: RawFd) -> Result<Bootstrap> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf).context("reading bootstrap length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut json_buf = vec![0u8; len];
    file.read_exact(&mut json_buf).context("reading bootstrap payload")?;
    std::mem::forget(file);
    serde_json::from_slice(&json_buf).context("parsing Bootstrap")
}
```

The `unsafe { std::fs::File::from_raw_fd(fd) }` / `std::mem::forget` pattern here is a deliberate choice to treat the fd as "borrowed, not owned" (the caller — `create.rs`'s closure, or `kestrel-init`'s `main`, both of which have their own ideas about when the fd should actually close) — **verify this reasoning holds** once Task 8/Task 5 actually write real call sites; if it turns out cleaner for `send_bootstrap`/`recv_bootstrap` to take an already-borrowed type (`BorrowedFd`) instead of a raw `RawFd` + manual `from_raw_fd`/`forget` dance, refactor to that — this plan's version prioritizes getting the ownership question flagged explicitly over guessing the cleanest final API shape.

- [ ] **Step 4: Wire into lib.rs, run tests**

```rust
pub mod bootstrap;
```

Add a `#[cfg(test)] mod tests` to `bootstrap.rs` covering: `send_bootstrap`/`recv_bootstrap` round-trip over a real `socketpair()` (via `nix::sys::socket::socketpair`, `AddressFamily::Unix`, `SockType::Datagram` or `Stream` — matching whatever Step 3's implementation settles on), asserting the received `Bootstrap` equals the sent one. Run: `cargo test -p kestrel-oci bootstrap::` and `cargo test -p kestrel-oci state::`.

## Context

Task 1 of 17. The shared-types foundation both `kestrel-runtime` and `kestrel-init` build on. No namespace/mount/security work here — pure data types and a socket transport, testable without root (a real `socketpair()` needs no privilege).

## Your Job

1. Add the `Hook` re-export.
2. Extend `State`, add `write_atomic`/`read`, update/add tests.
3. Implement `Bootstrap` and the send/recv functions, resolving the flagged ownership/socket-type questions for real (pick UnixDatagram vs UnixStream deliberately, simplify `HookSpec` away if `Hook` itself serializes fine standalone).
4. Write and run the round-trip test over a real socketpair.
5. Do NOT commit/branch/push. Report back with exactly what you decided for the flagged open questions and why.

---

## Task 2: `kestrel-rootfs` — generic bind-mount-a-file primitive

**Files:**
- Modify: `crates/kestrel-rootfs/src/mounts.rs`
- Modify: `crates/kestrel-rootfs/tests/mounts.rs` (or wherever this crate's existing root-gated mount tests live — check first)

- [ ] **Step 1: Implement**

```rust
// Addition to crates/kestrel-rootfs/src/mounts.rs

use std::path::Path;
use nix::mount::{mount, MsFlags};

/// Bind-mounts a single host file onto a path inside `rootfs` (already
/// mounted, pre-pivot). The target must exist as a regular file before
/// the bind-mount (same requirement `kestrel_ns::pin::pin_namespace`
/// already established for namespace pins — bind-mount targets are not
/// auto-created by the kernel). Two real, independent needs motivate
/// this: Phase 7's own `/etc/hosts`/`/etc/hostname`/`/etc/resolv.conf`
/// wiring (deferred to "Phase 8's assembly concern" in that phase's own
/// design doc) and this phase's own exec-FIFO reachability across
/// `pivot_root` (see the Phase 8 design doc §3).
pub fn bind_mount_file(source: &Path, rootfs: &Path, relative_target: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    let target = rootfs.join(relative_target);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if !target.exists() {
        std::fs::File::create(&target).with_context(|| format!("creating bind-mount target {}", target.display()))?;
    }
    // Two-call MS_BIND then MS_BIND|MS_RDONLY footgun (this project's own
    // established lesson from Phase 4 — a single mount() call combining
    // MS_BIND with other flags silently ignores everything but MS_BIND)
    // does NOT apply here: this bind mount is read-write (the FIFO must
    // be writable-through for `start` to unblock it), so only the plain
    // MS_BIND call is needed, no second remount call.
    mount(Some(source), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
        .with_context(|| format!("bind-mounting {} onto {}", source.display(), target.display()))?;
    Ok(())
}
```

- [ ] **Step 2: Test**

Add a root-gated test (following this crate's existing `tests/common/mod.rs` mount-namespace-isolation pattern, already established in Phase 4): bind-mount a tempfile onto a path inside a synthetic rootfs directory, write through the source, read from the target (or vice versa), confirm the same content is visible via both paths (proving it's a real bind mount, not a copy), then confirm unmounting the rootfs (or the test's namespace exiting) cleans it up with no host residue.

- [ ] **Step 3: Run**

`sudo -E cargo test -p kestrel-rootfs --test mounts -- --ignored` (or wherever the new test lives) inside the VM.

## Context

Task 2 of 17. Small, focused addition to an already-mature crate (Phase 4). Independent of Task 1.

## Your Job

Implement, test (root-gated, using this crate's existing isolation helper), confirm it passes with zero host residue. Do NOT commit/branch/push. Report back.

---

## Task 3: `kestrel-runtime` — `bundle.rs` + `state.rs`

**Files:**
- Modify: `crates/kestrel-runtime/Cargo.toml`
- Create: `crates/kestrel-runtime/src/bundle.rs`
- Create: `crates/kestrel-runtime/src/state.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Cargo.toml additions**

```toml
# add to crates/kestrel-runtime/Cargo.toml [dependencies]
kestrel-oci = { path = "../kestrel-oci" }
kestrel-rootfs = { path = "../kestrel-rootfs" }
kestrel-security = { path = "../kestrel-security" }
kestrel-cgroup = { path = "../kestrel-cgroup" }
kestrel-net = { path = "../kestrel-net" }
kestrel-init = { path = "../kestrel-init" }
clap = { version = "4", features = ["derive"] }
serde.workspace = true
serde_json.workspace = true
```

Verify real resolvable versions via `cargo add --dry-run` as every prior phase's Task 1 has. `kestrel-net`'s tokio dependency does NOT leak into `kestrel-runtime`'s own dependency tree just because it's a path dependency of `kestrel-runtime` — confirm `make check-no-tokio` still passes after this addition (it inspects `kestrel-runtime`'s OWN tree, which will now transitively include `kestrel-net` → `tokio` — **this is a real risk the design didn't fully address**: does `check-no-tokio-in-runtime.sh`'s `cargo tree -p kestrel-runtime --edges normal` walk transitively through `kestrel-net`'s own dependencies too? If `kestrel-runtime` depends on `kestrel-net` at all — needed for `delete.rs`'s network teardown per the design — tokio WILL appear somewhere in `kestrel-runtime`'s full dependency tree, which may violate Rule #2's spirit even if `kestrel-runtime`'s OWN code never touches an async runtime. Verify this exact question first, before proceeding with this task: does `kestrel-runtime` linking against `kestrel-net` (which is only ever called synchronously, e.g. via `tokio::runtime::Runtime::new()?.block_on(...)` at specific call sites, never spawning a persistent runtime) actually violate the single-threaded invariant, or is Rule #2 specifically about `kestrel-runtime` never RUNNING as multi-threaded (never itself calling `tokio::spawn`/holding a live multi-thread runtime), which a bounded `block_on` for one network-teardown call wouldn't violate? This needs a real decision, not an assumption — read PROMPT.md's Rule #2 wording exactly and either confirm bounded synchronous `block_on` calls are fine, or find an alternative (e.g. `kestreld`, not `kestrel-runtime`, owns all network teardown, and `kestrel-runtime`'s `delete` skips it — but CHECKLIST's `delete` bullet explicitly says "teardown net," so this needs resolving, not skipping).

- [ ] **Step 2: `bundle.rs`**

```rust
// crates/kestrel-runtime/src/bundle.rs

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::validate::SpecExt;

pub struct Bundle {
    pub path: PathBuf,
    pub spec: RawSpec,
}

pub fn load(bundle_path: &Path) -> Result<Bundle> {
    let config_path = bundle_path.join("config.json");
    let data = std::fs::read(&config_path).with_context(|| format!("reading {}", config_path.display()))?;
    let spec: RawSpec = serde_json::from_slice(&data).with_context(|| format!("parsing {}", config_path.display()))?;
    spec.spec.validate().context("validating config.json")?;
    Ok(Bundle { path: bundle_path.to_path_buf(), spec })
}
```

Verify `SpecExt::validate`'s exact error type (`ValidationError`, per the design doc's citation of `crates/kestrel-oci/src/validate.rs`) implements whatever's needed for `anyhow::Context` to work with it (it needs `std::error::Error + Send + Sync + 'static` — confirm `ValidationError`, a `thiserror`-derived enum per the design review's read of it, satisfies this; it should, `thiserror` types always do).

- [ ] **Step 3: `state.rs`**

```rust
// crates/kestrel-runtime/src/state.rs

use std::path::{Path, PathBuf};

use anyhow::Result;
use kestrel_oci::state::{State, Status};
use nix::sys::signal::kill;
use nix::unistd::Pid;

pub fn state_json_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join(id).join("state.json")
}

/// Reads state.json and refreshes `status` by checking whether `pid` is
/// still alive — `kill(pid, None)` (signal 0) is the standard
/// "does this pid exist and am I allowed to signal it" liveness probe,
/// doesn't actually send a signal. This alone can't distinguish
/// "still running" from "exited but not yet reaped by kestrel-init's own
/// reaper" in the split-second window between death and the reaper's
/// state.json write — acceptable imprecision for a status refresh (the
/// authoritative signal is state.json's own `exit_code` field once
/// populated, not this liveness check).
pub fn read_and_refresh(path: &Path) -> Result<State> {
    let mut state = State::read(path)?;
    if let Some(pid) = state.pid {
        let alive = kill(Pid::from_raw(pid), None).is_ok();
        if !alive && state.status != Status::Stopped {
            // Don't overwrite exit_code here — only kestrel-init's
            // reaper legitimately knows the real exit code; a
            // liveness-probe-only refresh that guesses "must be stopped"
            // without a real exit_code would be worse than leaving the
            // stale status, since a caller checking `exit_code.is_some()`
            // to decide "is the real result available yet" would be
            // misled. Leave status as-is if we can't confirm a real
            // reaper-written stop; only trust state.json's own
            // Status::Stopped once the reaper itself wrote it.
        }
    }
    Ok(state)
}
```

**Self-review flag for the implementer**: this `read_and_refresh` function's actual behavior is currently a no-op beyond the initial `State::read` (the `if !alive && ...` branch does nothing) — the design doc's requirement ("refreshing `status` by checking the pid") needs a real decision here: should a dead-but-not-yet-`Stopped`-per-state.json pid be reported as some intermediate status, or is "trust state.json's own Status field, only using the liveness check as a sanity/diagnostic signal" the right call given the exit-code mechanism (Task 7) is the actual source of truth? Resolve this for real during implementation, don't leave the dead branch empty without a decision — either implement a real status transition here or document explicitly why liveness-checking alone is intentionally not authoritative (given kestrel-init's reaper is the only source of truth for a REAL stop).

- [ ] **Step 4: Wire into lib.rs, tests**

```rust
pub mod bundle;
pub mod state;
```

Write unit tests for `bundle::load` (a real tempdir bundle with a minimal valid `config.json`, assert it loads; a bundle with an invalid spec — e.g. empty `process.args` — assert `validate()` catches it) and `state::state_json_path`. No root needed.

## Context

Task 3 of 17. Depends on Task 1 (`kestrel_oci::state`/`raw`/`validate`, already existing plus Task 1's `exit_code` addition). The Cargo.toml question about `kestrel-net`/tokio and Rule #2 is the most important thing to resolve correctly in this task — it affects every later task that touches `delete.rs`.

## Your Job

1. Resolve the `kestrel-net`/tokio/Rule-#2 question for real (read PROMPT.md's Rule #2 exact wording, make a reasoned call, document it).
2. Implement `bundle.rs`/`state.rs` as specified, resolving `read_and_refresh`'s flagged design gap for real.
3. Write and run tests.
4. Do NOT commit/branch/push. Report back, including your Rule #2 resolution and reasoning.

---

## Task 4: `kestrel-runtime` — `hooks.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/hooks.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-runtime/src/hooks.rs
//
//! Hook execution with a timeout, WITHOUT spawning any thread (Rule #2:
//! kestrel-runtime must not spawn threads, transitively — a
//! Command::spawn() child is a process, not a thread, so this is fine;
//! a naive timeout-via-watcher-thread would not be).

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kestrel_oci::runtime::Hook;

pub fn run_hooks(hooks: &[Hook], stdin_json: &[u8]) -> Result<()> {
    for hook in hooks {
        run_one_hook(hook, stdin_json)?;
    }
    Ok(())
}

fn run_one_hook(hook: &Hook, stdin_json: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut cmd = Command::new(hook.path());
    if let Some(args) = hook.args() {
        // Per Hook's own doc comment, `args` includes the binary name
        // itself (argv[0] convention) — the actual program to exec is
        // `hook.path()`; skip args[0] if present to avoid passing the
        // binary name twice as an argument, matching how execve's own
        // argv[0]-vs-path distinction works. Verify this reasoning
        // against a real hook invocation during implementation — some
        // OCI runtime implementations treat `args` as the FULL argv
        // (including [0]) passed verbatim to execve-style APIs, meaning
        // Command::new(hook.path()).args(&args[1..]) is correct, while
        // others might expect .args(&args[..]) with Command::new
        // supplying its own separate argv[0] — confirm against how
        // Command::args/arg0 interact before trusting this without
        // testing it against test_hooks_fire_in_order (Task 16).
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
    }
    if let Some(env) = hook.env() {
        cmd.env_clear();
        for kv in env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
    }
    cmd.stdin(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| format!("spawning hook {}", hook.path().display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_json);
    }

    let timeout = hook.timeout().map(|s| Duration::from_secs(s as u64)).unwrap_or(Duration::from_secs(30));
    wait_with_timeout(&mut child, timeout).with_context(|| format!("hook {} timed out or failed", hook.path().display()))
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("polling hook process")? {
            anyhow::ensure!(status.success(), "hook exited with {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("hook exceeded its timeout");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
```

`std::thread::sleep` inside `wait_with_timeout`'s poll loop does NOT spawn a new thread — it blocks the CALLING (single) thread, which is exactly what Rule #2 requires (the rule is about not creating additional OS threads, not about never sleeping). Confirm this reading is correct — it should be, but state it explicitly in your self-review since this is a place a careless reviewer could misflag.

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod hooks;
```

Write a test using two real, trivial hook scripts (e.g. `/bin/true` and `/bin/false`, or small fixture binaries) — one confirming a successful hook runs and returns `Ok`, one confirming a failing hook (`/bin/false`) returns `Err`, one confirming a hook that sleeps longer than its configured timeout gets killed and returns `Err` within roughly the timeout window (assert on elapsed wall-clock time being close to the timeout, not wildly longer — proving the poll loop actually enforces it rather than blocking forever on a hung `wait()`).

## Context

Task 4 of 17. Depends on Task 1's `Hook` re-export. No root needed — `/bin/true`/`/bin/false` and simple sleep commands don't need privilege.

## Your Job

Implement, resolve the `args[0]`-skipping question for real (test against real hook invocation semantics, don't just trust the plan's guess), write and run the 3 tests described, confirm the timeout test's timing assertion is real and not flaky. Do NOT commit/branch/push. Report back.

---

## Task 5: `kestrel-init` — `bootstrap.rs` + `mounts.rs` (rootfs, pivot, hostname, timens)

**Files:**
- Modify: `crates/kestrel-init/Cargo.toml`
- Create: `crates/kestrel-init/src/bootstrap.rs`
- Create: `crates/kestrel-init/src/mounts.rs`
- Modify: `crates/kestrel-init/src/lib.rs`

- [ ] **Step 1: Cargo.toml**

```toml
# add to crates/kestrel-init/Cargo.toml [dependencies]
kestrel-oci = { path = "../kestrel-oci" }
kestrel-rootfs = { path = "../kestrel-rootfs" }
serde_json.workspace = true
```

`kestrel-security` should already be a dependency (Phase 5, `exec.rs` uses `kestrel_security::apply::apply_all`) — confirm, don't re-add if present.

**Before writing any more code in this task, resolve the static-linking question empirically**: attempt building `kestrel-init` for a musl target inside the Lima VM (`rustup target add <arch>-unknown-linux-musl` if not already installed, then `cargo build --target <arch>-unknown-linux-musl -p kestrel-init`). If `libseccomp`'s build script (a `kestrel-security` transitive dependency) fails against musl, try the alternative (glibc + `-C target-feature=+crt-static`, via `.cargo/config.toml`'s `[target.<real-triple>] rustflags = ["-C", "target-feature=+crt-static"]` or an equivalent per-build flag). Document whichever approach actually works — this blocks nothing else in THIS task (mounts/pivot logic doesn't care about the final linking strategy), but must be resolved before Task 7's `main.rs` is considered done, since "is this genuinely a static binary" is one of CHECKLIST's own explicit requirements.

- [ ] **Step 2: `bootstrap.rs`**

```rust
// crates/kestrel-init/src/bootstrap.rs

use std::os::fd::RawFd;

use anyhow::Result;
use kestrel_oci::bootstrap::Bootstrap;

/// The well-known fd number `create.rs`'s child_action closure dup2's
/// the bootstrap socket onto before execve — a fixed number (rather than
/// discovering it via an env var) keeps kestrel-init's own startup dead
/// simple. Verify this exact number doesn't collide with anything
/// kestrel-init itself needs (stdin/stdout/stderr are 0/1/2; 3 is the
/// first free descriptor in a freshly-exec'd process barring anything
/// else explicitly inherited — confirm this assumption holds once Task 8
/// writes the real child_action code, adjust if it turns out something
/// else already occupies fd 3 in this process's real startup sequence).
pub const BOOTSTRAP_FD: RawFd = 3;

pub fn receive() -> Result<Bootstrap> {
    kestrel_oci::bootstrap::recv_bootstrap(BOOTSTRAP_FD)
}
```

- [ ] **Step 3: `mounts.rs`**

```rust
// crates/kestrel-init/src/mounts.rs

use anyhow::{Context, Result};
use kestrel_oci::bootstrap::Bootstrap;
use kestrel_rootfs::{mask, mounts, overlay, pivot, snapshot};

/// Stages the rootfs (overlay mount, standard mounts, masks, exec-FIFO
/// bind-mount) but does NOT pivot yet — the caller runs createContainer
/// hooks between this and `pivot`, per the design's resolved (pre-pivot)
/// hook ordering.
pub fn stage_rootfs(data_dir: &std::path::Path, bootstrap: &Bootstrap) -> Result<std::path::PathBuf> {
    let snapshotter = snapshot::Snapshotter::new(data_dir.to_path_buf(), bootstrap.mount_plan.rootless);
    let snap = snapshotter
        .prepare_snapshot(&bootstrap.container_id, &bootstrap.mount_plan.lower_chain_ids)
        .context("prepare_snapshot")?;
    overlay::mount_overlay(data_dir, &snap, bootstrap.mount_plan.rootless, false, false).context("mount_overlay")?;
    mounts::setup_standard_mounts(&snap.merged).context("setup_standard_mounts")?;
    mask::apply_default_masks(&snap.merged).context("apply_default_masks")?;
    mounts::bind_mount_file(&bootstrap.fifo_host_path, &snap.merged, &bootstrap.fifo_container_path)
        .context("bind-mounting exec fifo into the container")?;
    Ok(snap.merged)
}

pub fn pivot(merged: &std::path::Path) -> Result<()> {
    pivot::pivot_root(merged).context("pivot_root")
}

/// `sethostname`/timens-offset application. VERIFY the real `nix`
/// signature for `sethostname` before trusting this verbatim — this
/// plan's grounding section explicitly flagged this as unconfirmed.
pub fn apply_hostname_and_time(bootstrap: &Bootstrap) -> Result<()> {
    if let Some(hostname) = &bootstrap.hostname {
        nix::unistd::sethostname(hostname).context("sethostname")?;
    }
    if !bootstrap.timens_offsets.is_empty() {
        let content = bootstrap.timens_offsets.join("\n");
        std::fs::write("/proc/self/timens_offsets", content).context("writing /proc/self/timens_offsets")?;
    }
    Ok(())
}
```

Verify `snapshot::Snapshotter::prepare_snapshot`'s real signature (`crates/kestrel-rootfs/src/snapshot.rs`, Phase 4, already confirmed elsewhere in this project's history as `prepare_snapshot(&self, container_id: &str, lower_chain_ids: &[String]) -> Result<Snapshot>`) and `overlay::mount_overlay`'s real signature (`mount_overlay(data_dir: &Path, snap: &Snapshot, rootless: bool, metacopy: bool, redirect_dir: bool) -> Result<()>`) against the actual current source before trusting this verbatim — both should be unchanged since Phase 4, but confirm.

- [ ] **Step 4: Wire into lib.rs**

```rust
pub mod bootstrap;
pub mod mounts;
```

- [ ] **Step 5: Tests**

Write inline/integration tests reusing this crate's existing test-fixture patterns (Phase 5's `tests/fixtures/*.rs`) where feasible. Since `stage_rootfs`/`pivot` genuinely need root + real mount syscalls, defer FULL end-to-end testing of this module to Task 16's capstone suite — but write at least one focused root-gated test here for `apply_hostname_and_time` in isolation (inside a UTS-namespace-isolated test, verifying `sethostname` actually took effect via `uname()`), since that doesn't need the full rootfs machinery to test meaningfully.

## Context

Task 5 of 17. The core of kestrel-init's new rootfs-staging responsibility — pure orchestration over already-built Phase 4 primitives, plus two genuinely new small pieces (hostname, timens) this plan explicitly flags as needing real API verification. Depends on Task 1 (`Bootstrap` type) and Task 2 (`bind_mount_file`).

## Your Job

1. Resolve the static-linking question empirically FIRST, document the result.
2. Verify `sethostname`'s real signature and the timens_offsets file format against real kernel documentation/a working reference before trusting this plan's draft.
3. Verify `Snapshotter`/`mount_overlay`'s real current signatures.
4. Implement as specified (adjusting for any real API differences found).
5. Write and run the hostname test.
6. Do NOT commit/branch/push. Report back, including the static-linking resolution.

---

## Task 6: `kestrel-init` — `fifo.rs` + `reaper.rs`

**Files:**
- Create: `crates/kestrel-init/src/fifo.rs`
- Create: `crates/kestrel-init/src/reaper.rs`
- Modify: `crates/kestrel-init/src/lib.rs`

- [ ] **Step 1: `fifo.rs`**

```rust
// crates/kestrel-init/src/fifo.rs

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

/// Blocks until `kestrel start` opens the FIFO's host-side path for
/// writing (SPEC.md §9.1's own snippet, adapted to the container-
/// relative path this plan's bind-mount fix requires — see Task 5).
pub fn block_until_started(fifo_path: &Path) -> Result<()> {
    let mut f = OpenOptions::new().read(true).open(fifo_path).with_context(|| format!("opening {}", fifo_path.display()))?;
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).context("blocking read on exec fifo")?;
    Ok(())
}
```

- [ ] **Step 2: `reaper.rs`**

```rust
// crates/kestrel-init/src/reaper.rs
//
//! The SIGCHLD reap loop. Signal blocking + signalfd creation happen in
//! main.rs BEFORE the entrypoint is forked (see this plan's Task 7) —
//! this module only consumes an already-armed SignalFd, per the Phase 8
//! design doc's explicit resolution of SPEC.md §12's skeleton ordering.

use nix::sys::signal::{kill, Signal};
use nix::sys::signalfd::SignalFd;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Runs until `entrypoint` has exited AND been reaped, forwarding every
/// other received signal to it, reaping every other dead child
/// (orphans reparented to PID 1) along the way. Returns the entrypoint's
/// own exit code (raw exit code, or 128+signum if it died by signal).
pub fn run_init(entrypoint: Pid, sfd: &SignalFd) -> anyhow::Result<i32> {
    let mut entrypoint_exit: Option<i32> = None;

    loop {
        let siginfo = match sfd.read_signal()? {
            Some(si) => si,
            None => continue, // shouldn't happen on a blocking signalfd; defensive
        };
        let signo = siginfo.ssi_signo as i32;

        if signo == libc::SIGCHLD {
            // Loop: a single SIGCHLD delivery can represent MULTIPLE
            // child deaths (signals don't queue) — drain every
            // available exit with WNOHANG until none remain.
            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, code)) => {
                        if pid == entrypoint {
                            entrypoint_exit = Some(code);
                        }
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) => {
                        if pid == entrypoint {
                            entrypoint_exit = Some(128 + sig as i32);
                        }
                    }
                    Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
                    Ok(_) => continue, // Stopped/Continued etc. — not a death, keep draining
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(code) = entrypoint_exit {
                return Ok(code);
            }
        } else if let Ok(sig) = Signal::try_from(signo) {
            // Forward every other received signal to the entrypoint.
            let _ = kill(entrypoint, sig);
        }
    }
}
```

Verify `nix::sys::signalfd::siginfo`'s exact field name for the signal number (`ssi_signo`, per `libc::signalfd_siginfo`'s standard field naming — confirm against the real vendored `libc` crate's struct definition, not assumed) and `nix::sys::wait::WaitPidFlag`/`WaitStatus`'s exact variants against the real `nix` 0.29 source before trusting this verbatim.

- [ ] **Step 3: Wire into lib.rs, tests**

```rust
pub mod fifo;
pub mod reaper;
```

`fifo.rs`: a root-gated test isn't strictly needed (it's a thin wrapper around a well-understood blocking-open pattern) — a non-root test using a real FIFO created via `nix::unistd::mkfifo` in a tempdir, with a second thread... **wait, this project's binaries must not spawn threads (Rule #2 applies to `kestrel-runtime`, but does it apply to `kestrel-init` too? Check PROMPT.md's exact wording — Rule #2 is stated specifically about `kestrel-runtime`; `kestrel-init` is a different binary and this plan should confirm whether the same constraint applies to it or not, since `fifo.rs`'s own TEST (not the production code) might reasonably want a second thread or process to open the writer side concurrently with the blocking reader-side test call** — use a forked child process (not a thread) to open the writer side after a short delay, confirming the blocking read unblocks. This mirrors how this project already tests other blocking-open patterns (e.g. Phase 5's own FIFO-adjacent tests, if any exist — check `kestrel-init/tests/` for a precedent before inventing a new pattern).

`reaper.rs`: full testing deferred to Task 16's capstone (needs real fork/signal/wait machinery that's most meaningfully tested end-to-end, not in isolation) — but write at least one focused unit-level test here proving the `WNOHANG`-drain-loop logic in isolation is correct for the "one SIGCHLD covers multiple deaths" case specifically (fork several children that all exit near-simultaneously before the parent processes any signal, confirm the drain loop reaps all of them from a single `signalfd` read — this is directly testable without the full kestrel-init/bootstrap/mount machinery Task 16 needs).

## Context

Task 6 of 17. The reaper is the single most safety-critical piece of new logic in `kestrel-init` — get the `WNOHANG`-drain-loop and signal-forwarding right here, since Task 16's `test_zombie_reaping` (10,000 children) is the ultimate proof but this task's own focused test should catch a logic bug much earlier and cheaper.

## Your Job

1. Verify the real `nix`/`libc` field names and enum variants used in `reaper.rs`.
2. Resolve whether Rule #2 (no thread spawning) applies to `kestrel-init` specifically, or is `kestrel-runtime`-scoped only — check PROMPT.md directly.
3. Implement both modules as specified.
4. Write and run the fifo test (fork-based, not thread-based, regardless of the Rule #2 answer, unless you find a clear reason threads are fine here) and the focused multi-death-single-signal reaper test.
5. Do NOT commit/branch/push. Report back, including the Rule #2 scope finding.

---

## Task 7: `kestrel-init` — `main.rs` full PID-1 wiring

**Files:**
- Modify: `crates/kestrel-init/src/main.rs`
- Modify: `crates/kestrel-init/src/lib.rs` (if any new re-exports needed)

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-init/src/main.rs

fn main() -> anyhow::Result<()> {
    let bootstrap = kestrel_init::bootstrap::receive()?;

    let merged = kestrel_init::mounts::stage_rootfs(std::path::Path::new("/var/lib/kestrel"), &bootstrap)?;
    // (Verify the real data-dir path/convention against SPEC.md §6.1 —
    // this plan guesses "/var/lib/kestrel" from memory of earlier
    // phases' own conventions; confirm against the actual constant/config
    // this project already uses elsewhere, e.g. wherever kestrel-image's
    // ContentStore or kestrel-rootfs's Snapshotter got their own root
    // path in earlier phases' tests/production wiring, rather than
    // hardcoding a guessed literal here.)

    kestrel_runtime_shared_hooks_or_local_copy::run_hooks(&bootstrap.hooks.create_container, &state_json_bytes(&bootstrap)?)?;
    // (See self-review note below: hooks.rs currently lives in
    // kestrel-runtime, Task 4 — kestrel-init needs the SAME function.
    // Resolve where run_hooks actually lives before writing this call
    // for real; the plan's own design doc says "kestrel-init calls the
    // same function (linked in, not re-implemented)" — this means
    // hooks.rs's real location must be somewhere BOTH crates can depend
    // on, i.e. NOT kestrel-runtime (kestrel-init must not depend on
    // kestrel-runtime — that would be backwards, kestrel-runtime depends
    // on kestrel-init, not vice versa). Task 4's hooks.rs should
    // therefore actually live in a crate both depend on — most likely
    // kestrel-oci (matching this plan's own established pattern for
    // Bootstrap/State) or a small new shared crate. REVISIT TASK 4: move
    // hooks.rs's implementation to kestrel-oci (or confirm another
    // shared home) rather than kestrel-runtime, before this task can
    // compile for real. This is a real plan-level correction the
    // implementer must apply retroactively — flagged here explicitly
    // rather than silently duplicating hook-execution logic in both
    // binaries.)

    kestrel_init::mounts::pivot(&merged)?;
    kestrel_init::mounts::apply_hostname_and_time(&bootstrap)?;

    kestrel_init::fifo::block_until_started(&bootstrap.fifo_container_path)?;

    /* run_hooks(&bootstrap.hooks.start_container, ...)?; */

    // Block signals + arm the signalfd BEFORE forking the entrypoint —
    // see Task 6's reaper.rs doc comment and the Phase 8 design's
    // explicit resolution of this ordering.
    let mut mask = nix::sys::signal::SigSet::all();
    mask.remove(nix::sys::signal::Signal::SIGSEGV);
    mask.remove(nix::sys::signal::Signal::SIGBUS);
    mask.remove(nix::sys::signal::Signal::SIGILL);
    mask.remove(nix::sys::signal::Signal::SIGFPE);
    mask.thread_block()?;
    let sfd = nix::sys::signalfd::SignalFd::with_flags(&mask, nix::sys::signalfd::SfdFlags::SFD_CLOEXEC)?;

    let entrypoint_pid = match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { child } => child,
        nix::unistd::ForkResult::Child => {
            // apply_all (caps/no_new_privs/seccomp) + execve — all inside
            // exec_into, applied to THIS (soon-to-be-replaced) child
            // process, not PID 1 itself.
            let _: anyhow::Result<std::convert::Infallible> =
                kestrel_init::exec::exec_into(&bootstrap.process, bootstrap.seccomp.as_ref());
            std::process::exit(127); // only reached if exec_into itself returned Err
        }
    };

    let exit_code = kestrel_init::reaper::run_init(entrypoint_pid, &sfd)?;

    // Exit-code plumbing (Phase 8 design §2): write the final outcome to
    // state.json before PID 1 itself exits.
    let mut state = kestrel_oci::state::State::read(&bootstrap.state_json_path)?;
    state.status = kestrel_oci::state::Status::Stopped;
    state.exit_code = Some(exit_code);
    state.write_atomic(&bootstrap.state_json_path)?;

    std::process::exit(exit_code);
}

fn state_json_bytes(bootstrap: &kestrel_oci::bootstrap::Bootstrap) -> anyhow::Result<Vec<u8>> {
    // Hooks receive the container state as JSON on stdin per the OCI
    // spec — build a minimal State here from what Bootstrap already
    // carries (container_id, and whatever else State's schema needs;
    // `pid`/`status` at hook-execution time need real values, not
    // placeholders — resolve exactly what a createContainer/
    // startContainer hook should see on stdin during implementation,
    // this plan doesn't fully specify it).
    unimplemented!("resolve real hook-stdin State construction during implementation")
}
```

This task's draft has two explicitly-flagged, must-resolve-for-real gaps: (1) where `hooks.rs`'s `run_hooks` actually lives (move it out of `kestrel-runtime`, since `kestrel-init` cannot depend on `kestrel-runtime`), and (2) `state_json_bytes`'s real construction. **Do not ship either as a stub** — resolve both for real before this task is done.

- [ ] **Step 2: Retroactive fix to Task 4**

Move `hooks.rs` (built in Task 4) from `crates/kestrel-runtime/src/hooks.rs` to a shared location both `kestrel-runtime` and `kestrel-init` can depend on — `crates/kestrel-oci/src/hooks.rs` is the natural choice (matching this plan's own established "shared types/logic live in kestrel-oci" pattern for `Bootstrap`/`State`). Update both binaries' `Cargo.toml`/`lib.rs`/call sites accordingly. Re-run Task 4's own tests from their new location to confirm nothing broke in the move.

- [ ] **Step 3: Run**

Full build: `cargo build -p kestrel-init -p kestrel-runtime` (and whichever target Task 5 settled on for static linking). Confirm it compiles. Full end-to-end testing of this `main.rs` happens in Task 16 (needs `create.rs` from Task 8 to actually invoke it) — this task's own verification is "does it compile and does each individual piece it calls already have its own passing tests from Tasks 1-6."

## Context

Task 7 of 17. Ties together every piece Tasks 1, 2, 5, and 6 built. Depends on ALL of those. This task also requires a retroactive correction to Task 4 (moving `hooks.rs` out of `kestrel-runtime`) — if Task 4 was already implemented before this task starts, that move is real rework, not optional; if tasks are being executed in strict order, flag this dependency clearly so whoever does Task 4 is aware `hooks.rs`'s final home is `kestrel-oci`, not `kestrel-runtime`, and Task 4 should be implemented there directly the first time instead of moved later.

## Your Job

1. If Task 4 hasn't been done yet, tell whoever picks it up to build `hooks.rs` directly in `kestrel-oci`. If it HAS been done already, move it now.
2. Resolve `state_json_bytes`'s real construction.
3. Verify the real data-dir path convention (don't hardcode a guess).
4. Implement `main.rs` fully, no stubs remaining.
5. Confirm it builds (both binaries, and whatever the resolved static-linking target is).
6. Do NOT commit/branch/push. Report back.

---

## Task 8: `kestrel-runtime` — `create.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/create.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

The largest single module in this phase — implements the full two-phase hand-off protocol from the Phase 8 design doc §1: build the `NamespacePlan` and `Bootstrap` payload from the loaded `Bundle`, `mkfifo` the exec FIFO at the host path, create the dedicated socketpair, call `run_stages` with a `child_action` closure that blocks reading on its socket end before `execve`ing into `kestrel-init`, then (back in the host-side caller) run `createRuntime` hooks and send the `Bootstrap` payload (or an abort signal on hook failure), then write the initial `state.json`.

```rust
// crates/kestrel-runtime/src/create.rs

use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use kestrel_ns::stages::run_stages;
use kestrel_ns::types::NamespacePlan;
use kestrel_oci::bootstrap::Bootstrap;
use kestrel_oci::state::{State, Status};

use crate::bundle::Bundle;

pub fn create(id: &str, bundle: &Bundle, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let fifo_host_path = run_dir.join(id).join("exec.fifo");
    std::fs::create_dir_all(fifo_host_path.parent().unwrap())?;
    nix::unistd::mkfifo(&fifo_host_path, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .context("mkfifo")?;

    // Write the Creating-status state.json BEFORE run_stages, so a crash
    // partway through create still leaves diagnosable evidence.
    let initial_state = State {
        oci_version: "1.0.2".to_string(),
        id: id.to_string(),
        status: Status::Creating,
        pid: None,
        bundle: bundle.path.clone(),
        annotations: Default::default(),
        exit_code: None,
    };
    initial_state.write_atomic(&state_json_path)?;

    let plan = build_namespace_plan(bundle)?;
    let cgroup = kestrel_cgroup::manager::CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.create()?;

    // Dedicated Phase-8 socketpair — verify the real socketpair-creation
    // API against nix 0.29 (socketpair(AddressFamily::Unix, SockType::...,
    // None, SockFlag::empty()) returning (OwnedFd, OwnedFd), or whichever
    // exact shape this version's API has; kestrel-ns's own sync.rs is a
    // working precedent to follow for the exact call pattern, even though
    // this is a genuinely separate socket instance).
    let (host_end, init_end) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Datagram,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
    .context("creating bootstrap socketpair")?;

    let bootstrap = build_bootstrap(id, bundle, &fifo_host_path, &state_json_path)?;
    let init_end_raw = init_end.as_raw_fd();

    let child_action = move || {
        // Block reading — nothing sent yet means createRuntime hooks
        // haven't finished (or failed). This closure receives EOF/an
        // abort signal if hooks failed, or the real payload if they
        // succeeded — see the two branches below.
        match recv_go_ahead(init_end_raw) {
            Ok(true) => {
                // dup2 init_end onto the well-known BOOTSTRAP_FD kestrel-init expects.
                let _ = nix::unistd::dup2(init_end_raw, kestrel_init::bootstrap::BOOTSTRAP_FD);
                let kestrel_init_path = resolve_kestrel_init_path();
                let _ = nix::unistd::execv(&kestrel_init_path, &[kestrel_init_path.clone()]);
                std::process::exit(127); // only reached if execv itself failed
            }
            _ => std::process::exit(1), // createRuntime hooks failed or aborted; never exec
        }
    };

    let stage_result = run_stages(&plan, Some(cgroup.dir_fd()?), child_action)?;

    // Host side: run createRuntime hooks now, THEN send the go-ahead +
    // bootstrap payload (or signal failure).
    let hook_result = kestrel_oci::hooks::run_hooks(&bundle_create_runtime_hooks(bundle), &[]);
    match hook_result {
        Ok(()) => {
            send_go_ahead_and_bootstrap(host_end.as_raw_fd(), &bootstrap)?;
        }
        Err(e) => {
            // Close host_end without sending anything — child_action's
            // blocking read observes this as failure/EOF and exits
            // without execing. Surface the real hook error to the caller.
            drop(host_end);
            anyhow::bail!("createRuntime hooks failed: {e}");
        }
    }

    let mut state = State::read(&state_json_path)?;
    state.status = Status::Created;
    state.pid = Some(stage_result.init_pid.as_raw());
    state.write_atomic(&state_json_path)?;

    Ok(())
}

// The following are left as named-but-unimplemented stubs in this
// plan's draft — genuine implementation-time work, not because they're
// unimportant, but because their exact shape depends on decisions made
// in earlier tasks (Bundle's real field access patterns from Task 3,
// the exact NamespacePlan construction rules from Phase 2's own
// precedent) that are clearer to resolve with real code in hand than to
// guess at here:

fn build_namespace_plan(bundle: &Bundle) -> Result<NamespacePlan> {
    // Read bundle.spec.spec.linux().namespaces() (oci_spec's own
    // LinuxNamespace list) and translate into kestrel_ns::types::NsType
    // + IdMapping — this translation logic doesn't exist yet anywhere in
    // the codebase; implement it for real here, it's real, substantive
    // work, not a trivial pass-through.
    unimplemented!("translate bundle.spec's Linux namespaces + id mappings into a real NamespacePlan")
}

fn build_bootstrap(id: &str, bundle: &Bundle, fifo_host_path: &Path, state_json_path: &Path) -> Result<Bootstrap> {
    unimplemented!("construct the real Bootstrap payload from bundle.spec — process, capabilities, seccomp, hooks, hostname, timens_offsets, mount_plan (needs the resolved image layer chain-ids, which for a bundle-based create — not an image-pull based one — likely means bundle.spec.root().path() IS the already-extracted rootfs, meaning mount_plan/lower_chain_ids may not even apply the same way Phase 6's image-pull flow does — resolve during implementation whether `create` here supports BOTH a bare-bundle-with-pre-extracted-rootfs flow (the simpler, OCI-runtime-spec-standard case, and what the 5 required tests' synthetic rootfs likely needs) and a kestrel-image-chain-id-based flow, or just the former for this phase, deferring the image-integration path to kestreld's own Phase 9 assembly")
}

fn recv_go_ahead(fd: std::os::fd::RawFd) -> Result<bool> {
    unimplemented!("read a single byte/short message signaling go-ahead vs abort")
}

fn send_go_ahead_and_bootstrap(fd: std::os::fd::RawFd, bootstrap: &Bootstrap) -> Result<()> {
    unimplemented!("send the go-ahead signal, then kestrel_oci::bootstrap::send_bootstrap")
}

fn resolve_kestrel_init_path() -> std::ffi::CString {
    unimplemented!("resolve the real installed path to the kestrel-init binary")
}

fn bundle_create_runtime_hooks(bundle: &Bundle) -> Vec<kestrel_oci::runtime::Hook> {
    unimplemented!("extract bundle.spec.spec.hooks()'s create_runtime list")
}
```

**This task's draft is deliberately left with several named `unimplemented!()` stubs** — unlike every other task in this plan, `create.rs` is where enough genuinely-implementation-time decisions converge (the bundle-vs-image rootfs question, the exact NamespacePlan-from-Linux-namespaces translation, the go-ahead protocol's exact wire format) that writing fully-resolved code here would mean guessing at things the earlier tasks' real implementations should inform. **Every one of these `unimplemented!()` calls MUST be resolved with real, working code before this task is reported done** — this is not permission to ship stubs, it's an explicit acknowledgment that this task requires more implementation-time judgment than the others, flagged per this project's established "flag genuine uncertainty rather than guess" discipline, at a larger scale than usual given this module's size and centrality.

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod create;
```

Full testing deferred to Task 16 (this is the module Task 16's capstone tests exercise most directly) — but write whatever focused unit tests are feasible for the pure-logic pieces (`build_namespace_plan`'s translation logic, once implemented, is a good candidate for a non-root unit test against a few different `config.json` namespace-list shapes).

## Context

Task 8 of 17. The centerpiece of the whole phase. Depends on Tasks 1-7 (everything so far). Budget real implementation time here — this is not a mechanical task.

## Your Job

1. Resolve every flagged `unimplemented!()` with real, working code.
2. Resolve the bundle-vs-image-rootfs question explicitly (recommend: support the plain bundle-with-pre-extracted-rootfs case for this phase, matching what the OCI runtime spec itself assumes and what the 5 required tests need; explicitly note kestrel-image-chain-id-based creation as a Phase 9/`kestreld` integration concern if it doesn't fit cleanly here).
3. Implement the full module, no stubs remaining.
4. Write whatever focused unit tests are feasible now; note what's deferred to Task 16.
5. Do NOT commit/branch/push. Report back in detail, given this task's size — walk through each resolved design decision explicitly.

---

## Task 9: `kestrel-runtime` — `start.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/start.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-runtime/src/start.rs

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use kestrel_oci::state::{State, Status};

pub fn start(id: &str, run_dir: &Path) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = State::read(&state_json_path)?;
    anyhow::ensure!(state.status == Status::Created, "cannot start container {id}: status is {:?}, expected Created", state.status);

    let fifo_host_path = run_dir.join(id).join("exec.fifo");
    let mut fifo = std::fs::OpenOptions::new().write(true).open(&fifo_host_path).with_context(|| format!("opening {}", fifo_host_path.display()))?;
    fifo.write_all(&[0u8]).context("unblocking kestrel-init via exec fifo")?;

    state.status = Status::Running;
    state.write_atomic(&state_json_path)?;

    // poststart hooks — run AFTER the FIFO write above (per SPEC.md
    // §9.3's table: "after start returns"), using the same run_hooks
    // this project's Task 4/7 correction relocated to kestrel-oci.
    let bundle = crate::bundle::load(&state.bundle)?;
    kestrel_oci::hooks::run_hooks(&poststart_hooks(&bundle), &[])?;

    Ok(())
}

fn poststart_hooks(bundle: &crate::bundle::Bundle) -> Vec<kestrel_oci::runtime::Hook> {
    bundle.spec.spec.hooks().as_ref().and_then(|h| h.poststart().clone()).unwrap_or_default()
}
```

Verify `Hooks::poststart()`'s exact getter return type (`Option<Vec<Hook>>`, per the vendored source read during this plan's grounding) against the real `oci_spec::runtime::Hooks` struct before trusting the `.and_then(|h| h.poststart().clone())` chain verbatim.

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod start;
```

A focused test: write a `Created`-status `state.json` + a real FIFO, spawn a thread... **no — per this project's no-thread-spawning discipline (confirm scope per Task 6's Rule #2 finding), use a forked child** to block-read the FIFO the way `kestrel-init` would, call `start()` from the main test process, confirm the forked reader unblocks and `state.json` now shows `Running`.

## Context

Task 9 of 17. Small, focused, depends on Task 8 (needs a real `Created`-state container to start against for full testing, though the FIFO-write mechanics can be tested more narrowly as shown).

## Your Job

Implement, verify `Hooks::poststart()`'s real signature, write and run the focused test. Do NOT commit/branch/push. Report back.

---

## Task 10: `kestrel-runtime` — `state_cmd.rs` + `ps.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/state_cmd.rs`
- Create: `crates/kestrel-runtime/src/ps.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: `state_cmd.rs`**

```rust
// crates/kestrel-runtime/src/state_cmd.rs

use std::path::Path;

use anyhow::Result;
use kestrel_oci::state::State;

pub fn state(id: &str, run_dir: &Path) -> Result<State> {
    crate::state::read_and_refresh(&crate::state::state_json_path(run_dir, id))
}
```

- [ ] **Step 2: `ps.rs`**

```rust
// crates/kestrel-runtime/src/ps.rs

use std::path::Path;

use anyhow::Result;
use kestrel_oci::state::State;

/// Lists every container's state by scanning `<run_dir>/*/state.json`.
pub fn list(run_dir: &Path) -> Result<Vec<State>> {
    let mut states = Vec::new();
    if !run_dir.is_dir() {
        return Ok(states);
    }
    for entry in std::fs::read_dir(run_dir)? {
        let entry = entry?;
        let state_path = entry.path().join("state.json");
        if state_path.is_file() {
            if let Ok(state) = crate::state::read_and_refresh(&state_path) {
                states.push(state);
            }
            // A read/parse failure for one container's state.json
            // shouldn't fail the whole `ps` listing — skip it silently
            // here, but consider whether `ps` should surface a warning
            // per-skipped-entry during implementation (a reasonable
            // UX improvement, not a correctness requirement for this
            // phase's own tests).
        }
    }
    Ok(states)
}
```

- [ ] **Step 3: Wire into lib.rs, tests**

```rust
pub mod state_cmd;
pub mod ps;
```

Test `ps::list` against a tempdir with 2-3 hand-written `state.json` files (no real containers needed — this is pure filesystem scanning + parsing), confirming all are listed, and that a malformed one is skipped without failing the whole call.

## Context

Task 10 of 17. Thin, mostly-mechanical. Depends on Task 3's `state.rs`.

## Your Job

Implement, write and run the test. Do NOT commit/branch/push. Report back.

---

## Task 11: `kestrel-runtime` — `kill.rs` + `pause.rs` + `resume.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/kill.rs`
- Create: `crates/kestrel-runtime/src/pause.rs`
- Create: `crates/kestrel-runtime/src/resume.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-runtime/src/kill.rs

use std::path::Path;

use anyhow::{Context, Result};
use kestrel_cgroup::manager::CgroupManager;
use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;

pub fn kill(id: &str, run_dir: &Path, data_dir: &Path, signal: Signal, all: bool) -> Result<()> {
    if all {
        let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
        cgroup.kill_all().context("cgroup.kill")
    } else {
        let state = crate::state::read_and_refresh(&crate::state::state_json_path(run_dir, id))?;
        let pid = state.pid.context("container has no recorded pid")?;
        nix_kill(Pid::from_raw(pid), signal).context("kill")?;
        Ok(())
    }
}
```

```rust
// crates/kestrel-runtime/src/pause.rs

use std::path::Path;

use anyhow::Result;
use kestrel_cgroup::manager::CgroupManager;
use kestrel_oci::state::Status;

pub fn pause(id: &str, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.freeze(true)?;
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = kestrel_oci::state::State::read(&state_json_path)?;
    state.status = Status::Paused;
    state.write_atomic(&state_json_path)
}
```

```rust
// crates/kestrel-runtime/src/resume.rs

use std::path::Path;

use anyhow::Result;
use kestrel_cgroup::manager::CgroupManager;
use kestrel_oci::state::Status;

pub fn resume(id: &str, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.freeze(false)?;
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = kestrel_oci::state::State::read(&state_json_path)?;
    state.status = Status::Running;
    state.write_atomic(&state_json_path)
}
```

Verify `kill.rs`'s "signal by name or number" CHECKLIST requirement is satisfied at the CLI-parsing layer (Task 14, `clap`), not here — this module just takes an already-parsed `Signal`, string/number parsing is the CLI's job.

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod kill;
pub mod pause;
pub mod resume;
```

Root-gated tests: `pause`/`resume` against a real cgroup with a real long-running process inside it (confirm via `/proc/<pid>/status`'s `State:` field showing `D`/stopped-equivalent while frozen, running again after resume — or via the cgroup's own `cgroup.events` `frozen` field, already exposed through `CgroupManager::freeze`'s internal polling, so the external test can just trust `freeze()`'s own `Ok(())` return as sufficient proof, given it already polls for confirmation internally). `kill`: send a real signal to a real spawned process, confirm it dies.

## Context

Task 11 of 17. Thin orchestration over already-built `CgroupManager` methods (confirmed in Task 1's grounding to already exist). Depends on Task 3.

## Your Job

Implement, write and run root-gated tests. Do NOT commit/branch/push. Report back.

---

## Task 12: `kestrel-runtime` — `delete.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/delete.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

Following the Phase 8 design doc's explicit 7-step ordering: force-kill (if running and `--force`) → unmount overlay → destroy cgroup → unpin namespaces → network teardown → `poststop` hooks → remove the state/bundle-scratch directory last. Partial-failure policy: attempt every step, collect errors, report an aggregate at the end rather than aborting on the first failure.

```rust
// crates/kestrel-runtime/src/delete.rs

use std::path::Path;

use anyhow::Result;
use kestrel_oci::state::Status;

pub fn delete(id: &str, run_dir: &Path, data_dir: &Path, force: bool) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let state = kestrel_oci::state::State::read(&state_json_path)?;

    let mut errors: Vec<String> = Vec::new();

    if matches!(state.status, Status::Running | Status::Paused) {
        if force {
            if let Err(e) = crate::kill::kill(id, run_dir, data_dir, nix::sys::signal::Signal::SIGKILL, true) {
                errors.push(format!("force-kill: {e}"));
            }
            // Wait for the container to actually stop before proceeding
            // — tearing down mounts/cgroups/namespaces out from under a
            // still-dying process is exactly the kind of race this
            // project has avoided everywhere else (e.g. Phase 3's own
            // is_populated-before-destroy discipline). Poll state.json
            // for Status::Stopped (written by kestrel-init's reaper) up
            // to a reasonable deadline.
        } else {
            anyhow::bail!("cannot delete a running container {id} without --force");
        }
    }

    // (unmount overlay, destroy cgroup, unpin namespaces, network
    // teardown, poststop hooks — each wrapped the same
    // try-and-collect-errors way as force-kill above; implement each
    // for real using the real crate APIs, e.g.
    // kestrel_rootfs::overlay::unmount_overlay, CgroupManager::destroy,
    // kestrel_ns::pin::unpin_namespace per pinned NsType,
    // kestrel_net::bridge::teardown_bridge_network — resolve the exact
    // set of namespace pins/data needed to call each of these, which
    // depends on what create.rs (Task 8) actually recorded/pinned during
    // creation; this plan does not fully specify that record-keeping,
    // which is real implementation-time work: does state.json need to
    // grow more fields to remember, e.g., which namespaces were pinned
    // and where, or is this all re-derivable from a fixed, well-known
    // path convention like /run/kestrel/<id>/ns/<type> established
    // elsewhere in this project? Resolve for real, don't guess.)

    if let Some(parent) = state_json_path.parent() {
        if errors.is_empty() {
            let _ = std::fs::remove_dir_all(parent);
        }
        // If errors occurred, deliberately leave the directory (and
        // state.json) in place for diagnosis, per the "only erase
        // evidence once everything else succeeded" policy.
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("delete completed with errors: {}", errors.join("; "))
    }
}
```

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod delete;
```

Full end-to-end testing deferred to Task 16 (needs a real created/running container to delete). Write whatever focused tests are feasible now (e.g. the "cannot delete a running container without --force" error path, which needs only a hand-written `Running`-status `state.json`, no real container).

## Context

Task 12 of 17. The design doc flagged this as needing more attention than a one-line description — this task's draft reflects that, with several real implementation-time questions flagged rather than guessed (namespace-pin record-keeping specifically). Depends on Tasks 3, 8, 11.

## Your Job

1. Resolve the namespace-pin record-keeping question for real (check what Task 8's `create.rs` actually ends up doing/recording, and what convention — e.g. a fixed `/run/kestrel/<id>/ns/<type>` path — this project already established elsewhere for exactly this purpose).
2. Implement the full 7-step teardown, no stubs remaining.
3. Write the feasible-now test.
4. Do NOT commit/branch/push. Report back.

---

## Task 13: `kestrel-runtime` — `exec_cmd.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/exec_cmd.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

Per the Phase 8 design doc's resolution of the PID-namespace bug: `join_namespaces`, then fork, then the CHILD does `exec_into`, the PARENT `waitpid`s and propagates the exit code.

```rust
// crates/kestrel-runtime/src/exec_cmd.rs

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use kestrel_ns::join::join_namespaces;
use kestrel_oci::runtime::Process;

pub fn exec(id: &str, run_dir: &Path, process: &Process) -> Result<i32> {
    let ns_dir = run_dir.join(id).join("ns");
    let mut pins = BTreeMap::new();
    for ns_type in [
        kestrel_ns::types::NsType::Cgroup,
        kestrel_ns::types::NsType::Ipc,
        kestrel_ns::types::NsType::Uts,
        kestrel_ns::types::NsType::Net,
        kestrel_ns::types::NsType::Pid,
        kestrel_ns::types::NsType::Mount,
        kestrel_ns::types::NsType::Time,
        kestrel_ns::types::NsType::User,
    ] {
        let pin_path = ns_dir.join(ns_type.proc_name());
        if pin_path.exists() {
            pins.insert(ns_type, pin_path);
        }
    }

    join_namespaces(&pins).context("joining container namespaces")?;

    // setns(CLONE_NEWPID) only affects subsequently-forked children —
    // fork here so the exec'd process is genuinely born inside the
    // container's PID namespace, per this plan's grounding section.
    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { child } => {
            let status = nix::sys::wait::waitpid(child, None).context("waiting on exec'd child")?;
            Ok(exit_code_from_status(status))
        }
        nix::unistd::ForkResult::Child => {
            let _: anyhow::Result<std::convert::Infallible> = kestrel_init::exec::exec_into(process, None);
            std::process::exit(127);
        }
    }
}

fn exit_code_from_status(status: nix::sys::wait::WaitStatus) -> i32 {
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => code,
        nix::sys::wait::WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}
```

**Verify the namespace-pin path convention** (`run_dir.join(id).join("ns").join(ns_type.proc_name())`) against whatever Task 12 (`delete.rs`) and Task 8 (`create.rs`) actually settle on — this must be the SAME convention across all three tasks, or `exec` will silently fail to find pins that DO exist under a differently-shaped path. Resolve this as one shared constant/helper function (e.g. in `state.rs` alongside `state_json_path`) rather than each task independently guessing the same path shape.

- [ ] **Step 2: Wire into lib.rs, tests**

```rust
pub mod exec_cmd;
```

Full end-to-end testing deferred to Task 16 (needs a real running container with real pinned namespaces to exec into).

## Context

Task 13 of 17. Depends on Task 8/12's namespace-pin convention (must be unified across all three). Small in code size but implements a real, previously-identified correctness fix (the PID-namespace fork).

## Your Job

1. Confirm/establish the shared namespace-pin path convention (a single helper function, not three independent guesses).
2. Implement as specified.
3. Do NOT commit/branch/push. Report back, specifically confirming the pin-path convention is unified with Tasks 8/12.

---

## Task 14: `kestrel-runtime` — `cli.rs` + `main.rs`

**Files:**
- Create: `crates/kestrel-runtime/src/cli.rs`
- Modify: `crates/kestrel-runtime/src/main.rs`
- Modify: `crates/kestrel-runtime/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-runtime/src/cli.rs

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(long, default_value = "/run/kestrel")]
    pub run_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/kestrel")]
    pub data_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum Command {
    Create { id: String, #[arg(long)] bundle: PathBuf },
    Start { id: String },
    State { id: String },
    Kill { id: String, signal: String, #[arg(long)] all: bool },
    Delete { id: String, #[arg(long)] force: bool },
    Exec { id: String, command: Vec<String> },
    Ps,
    Pause { id: String },
    Resume { id: String },
}
```

Signal parsing ("by name or number", per CHECKLIST) belongs here: convert `signal: String` (e.g. `"KILL"`, `"SIGKILL"`, or `"9"`) into a real `nix::sys::signal::Signal` before calling `kill::kill`. Implement a small parser trying numeric parse first, then `Signal::from_str` (or a manual name-to-Signal match if `nix`'s `Signal` doesn't implement `FromStr` in this version — verify).

- [ ] **Step 2: `main.rs`**

```rust
// crates/kestrel-runtime/src/main.rs

use kestrel_runtime::cli::{Cli, Command};
use kestrel_runtime::preflight;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    preflight::assert_single_threaded()?;

    let cli = <Cli as clap::Parser>::parse();
    match cli.command {
        Command::Create { id, bundle } => {
            let b = kestrel_runtime::bundle::load(&bundle)?;
            kestrel_runtime::create::create(&id, &b, &cli.run_dir, &cli.data_dir)
        }
        Command::Start { id } => kestrel_runtime::start::start(&id, &cli.run_dir),
        Command::State { id } => {
            let state = kestrel_runtime::state_cmd::state(&id, &cli.run_dir)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(())
        }
        Command::Kill { id, signal, all } => {
            let sig = parse_signal(&signal)?;
            kestrel_runtime::kill::kill(&id, &cli.run_dir, &cli.data_dir, sig, all)
        }
        Command::Delete { id, force } => kestrel_runtime::delete::delete(&id, &cli.run_dir, &cli.data_dir, force),
        Command::Exec { id, command } => {
            let process = build_exec_process(&command)?;
            let code = kestrel_runtime::exec_cmd::exec(&id, &cli.run_dir, &process)?;
            std::process::exit(code);
        }
        Command::Ps => {
            for state in kestrel_runtime::ps::list(&cli.run_dir)? {
                println!("{}\t{:?}\t{:?}", state.id, state.status, state.pid);
            }
            Ok(())
        }
        Command::Pause { id } => kestrel_runtime::pause::pause(&id, &cli.run_dir, &cli.data_dir),
        Command::Resume { id } => kestrel_runtime::resume::resume(&id, &cli.run_dir, &cli.data_dir),
    }
}
```

`parse_signal`/`build_exec_process` are small, real functions to implement (not stubs) — `build_exec_process` constructs a minimal `oci_spec::runtime::Process` from the CLI's `command: Vec<String>` (args, inheriting the current environment or a minimal one, `cwd` defaulting to `/`).

- [ ] **Step 3: Wire lib.rs, run**

```rust
pub mod cli;
```

`cargo build -p kestrel-runtime`, confirm it compiles and `kestrel-runtime --help` shows all 9 subcommands.

## Context

Task 14 of 17. Ties every prior subcommand module together into a real, runnable binary. Depends on Tasks 3, 8-13.

## Your Job

Implement, verify `Signal`'s real `FromStr`/parsing situation in `nix` 0.29, confirm the binary builds and `--help` output looks right. Do NOT commit/branch/push. Report back.

---

## Task 15: Synthetic test fixture

**Files:**
- Create: `crates/kestrel-runtime/tests/fixtures/lifecycle_fixture.rs`
- Modify: `crates/kestrel-runtime/Cargo.toml` (`[[bin]]` target + `[dev-dependencies]`)

- [ ] **Step 1: Implement**

A single static binary, parameterized via argv, covering every required test's needs:

```rust
// crates/kestrel-runtime/tests/fixtures/lifecycle_fixture.rs
//
//! Reused across test_create_then_start / test_exit_code_propagates /
//! test_signal_exit_code / test_zombie_reaping / test_hooks_fire_in_order
//! via argv-selected behavior, matching this project's established
//! "one parameterized fixture, not N single-purpose ones" pattern
//! (Phase 5's kestrel-init/tests/fixtures/*.rs).

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("marker") => {
            // test_create_then_start: write a marker file (path from
            // argv[2]) proving this process actually ran its entrypoint
            // body, not just that the process exists.
            std::fs::write(&args[2], b"ran").unwrap();
        }
        Some("exit") => {
            let code: i32 = args[2].parse().unwrap();
            std::process::exit(code);
        }
        Some("sleep") => {
            let secs: u64 = args[2].parse().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        Some("spawn-abandon") => {
            let n: usize = args[2].parse().unwrap();
            for _ in 0..n {
                if unsafe { libc::fork() } == 0 {
                    // Double-fork-equivalent: exit immediately, orphaning
                    // this child to PID 1 for the parent (this fixture
                    // process) to never wait on — the parent moves on to
                    // spawn the next one without reaping, guaranteeing
                    // orphaning.
                    std::process::exit(0);
                }
            }
            // Deliberately never wait() on any of them.
            std::thread::sleep(std::time::Duration::from_secs(2)); // give the reaper time to observe them before this fixture itself exits
        }
        _ => {}
    }
}
```

Add the `[[bin]]` target to `Cargo.toml` and confirm it builds for whatever static-linking target Task 5 settled on (this fixture needs to run AS a container entrypoint, so it needs the same linking treatment `kestrel-init`'s own static-binary requirement implies — though technically the fixture itself doesn't need to survive a `pivot_root` the way `kestrel-init` does, since it's exec'd fresh by the ALREADY-pivoted `kestrel-init`; verify whether the fixture genuinely needs static linking or whether it can be a normal dynamically-linked test binary as long as its needed `.so`s are present inside the synthetic test rootfs — the latter is simpler if it works, don't assume static linking is required here just because it is for `kestrel-init` itself).

- [ ] **Step 2: Tar-builder test helper**

```rust
// Add to crates/kestrel-runtime/tests/common/mod.rs (new file)

/// Builds a minimal synthetic rootfs directory (not a tar — Task 16's
/// tests create real OCI bundles, which need an already-extracted
/// rootfs directory per Task 8's "plain bundle" resolution, not a
/// layered/tarball image) containing the fixture binary at a fixed path
/// (e.g. `/fixture`).
pub fn build_synthetic_rootfs(dest: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(dest).unwrap();
    let fixture_path = env!("CARGO_BIN_EXE_lifecycle_fixture");
    std::fs::copy(fixture_path, dest.join("fixture")).unwrap();
    std::fs::set_permissions(dest.join("fixture"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    dest.to_path_buf()
}
```

## Context

Task 15 of 17. Test infrastructure, not production code. Depends on Task 5's static-linking resolution (to know whether the fixture itself needs the same treatment).

## Your Job

Implement, confirm the fixture binary builds and each of its argv-selected behaviors works when run directly (not yet through the full container machinery — that's Task 16). Do NOT commit/branch/push. Report back.

---

## Task 16: The 5 required capstone tests

**Files:**
- Create: `crates/kestrel-runtime/tests/lifecycle.rs`

- [ ] **Step 1: Implement all 5 tests**

Per the Phase 8 design doc's testing section, using Task 15's fixture and rootfs builder, and a real, hand-written minimal `config.json` (via `kestrel_oci::runtime::SpecBuilder`/`default_spec`, already built) pointing `process.args` at `/fixture` with the appropriate argv for each scenario.

1. `test_create_then_start` — `create`, assert the marker file (via `fixture marker <path>` as the entrypoint args) does NOT exist yet; `start`; poll for the marker file to appear.
2. `test_exit_code_propagates` — entrypoint args `fixture exit 42`; `create` + `start`; poll `state` until `Status::Stopped`; assert `exit_code == Some(42)`.
3. `test_signal_exit_code` — entrypoint args `fixture sleep 30`; `create` + `start`; `kill` with `SIGKILL`; poll `state` until `Stopped`; assert `exit_code == Some(137)`.
4. `test_zombie_reaping` — entrypoint args `fixture spawn-abandon 10000`; `create` + `start` with a generously-set `pids.max` (per this plan's grounding note on resource limits); poll the cgroup's `pids.current` (via `kestrel-cgroup`'s existing stats reading) back down to a low baseline once the fixture itself exits; assert the achieved count and headroom explicitly rather than assuming 10,000 always succeeds cleanly.
5. `test_hooks_fire_in_order` — a `config.json` with all 5 hook types configured to append a phase-identifying line (via a tiny shell command or the fixture binary itself with a new `Some("hook-marker")` argv branch — add this to Task 15's fixture if needed) to a shared file; run the full `create`→`start`→(wait for exit)→`delete` lifecycle; assert the file's final content is in the exact expected order.

- [ ] **Step 2: Run**

`sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-runtime --test lifecycle -- --ignored --nocapture` inside the VM.

## Context

Task 16 of 17. The composing capstone for the whole phase — exercises `create.rs`, `start.rs`, `kill.rs`, `delete.rs`, `state_cmd.rs`, and the full `kestrel-init` PID-1 flow together for the first time. Depends on every prior task.

## Your Job

1. Implement all 5 tests with real, specific assertions.
2. Add the `hook-marker` argv branch to the fixture if needed.
3. Run the suite, debug real failures for real (this is where integration bugs between tasks will surface — expect real debugging work, not a quick pass).
4. Confirm zero residue in the VM's real state (mounts, cgroups, namespaces, network) after the suite runs.
5. Do NOT commit/branch/push. Report back in detail, including any cross-task integration bugs found and how you fixed them.

---

## Task 17: Workspace-wide verification and cleanup

**Files:** none new — verification only, plus Makefile note.

- [ ] **Step 1:** `cargo build --workspace` — clean.
- [ ] **Step 2:** `cargo test --workspace` — all non-ignored tests pass.
- [ ] **Step 3:** `make test-root` — every root-gated test passes, including the full `kestrel-runtime`/`kestrel-init` suites from this phase.
- [ ] **Step 4:** `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] **Step 5:** `make check-no-tokio` — re-verify given Task 3's flagged `kestrel-net`-dependency question; confirm the final resolution (whichever way Task 3 decided) is genuinely consistent with Rule #2's real requirement, not just "the script happens to pass."
- [ ] **Step 6:** Grep for `todo!()`/`unimplemented!()` in `crates/kestrel-runtime` and `crates/kestrel-init` — zero matches expected (every stub flagged in Tasks 7/8/12 must be resolved by now).
- [ ] **Step 7:** Sweep for leftover state after the full root-gated suite: mounts, cgroups, pinned namespaces, network state — all should be clean.
- [ ] **Step 8:** Update the Makefile's NOTE comment to document `kestrel-runtime`/`kestrel-init`'s new requirements (static-linking target for `kestrel-init`, per whatever Task 5 resolved) and confirm the single-threaded assertion (`preflight::assert_single_threaded`) genuinely fires correctly for the real CLI binary now that it has real subcommands doing real work (not just the preflight-only stub it was before this phase).

## Self-Review Notes

**Spec coverage:** CHECKLIST's 24 Phase 8 items map to: 9 clap subcommands → Tasks 8-14. Single-threaded assertion → already built, reused in Task 14. `create`'s full flow (bundle load, cgroup, three-stage dance, bootstrap-over-socket, state.json) → Task 8. Exec FIFO → Tasks 2 (bind-mount), 5 (fifo.rs), 8 (mkfifo). `createRuntime` hook timing → Task 8. `start`'s FIFO-unblock + poststart → Task 9. `state`'s pid-liveness refresh → Task 3/10. `kill` signal-by-name/number + `--all`/`cgroup.kill` → Tasks 11, 14. `delete`'s full teardown → Task 12. `exec`'s setns-in-order → Task 13. `pause`/`resume` via `cgroup.freeze` → Task 11. kestrel-init's full order (mounts→createContainer→pivot→hostname/timens→FIFO-block→startContainer→caps→seccomp→execve) → Tasks 5-7. Signal-blocking-before-fork, `signalfd` reaper, `WNOHANG` drain loop, signal forwarding, exit-code-or-128+signum → Task 6-7. All 5 required tests → Task 16.

**Placeholder scan:** this plan has MORE flagged `unimplemented!()`/deferred-decision points than any prior phase's plan — deliberately, given this is the largest, most integrative phase in the project and several genuine cross-task design decisions (namespace-pin path convention, bundle-vs-image rootfs scope, hooks.rs's shared-crate home, the go-ahead wire protocol's exact shape) are more soundly resolved with real code from earlier tasks in hand than guessed at plan-writing time. Every flagged item has explicit instructions that it MUST be resolved with real code before that task is done — none are permission to ship a stub.

**Type/signature consistency:** the namespace-pin path convention (`run_dir.join(id).join("ns").join(<name>)`) must be identical across Tasks 8, 12, and 13 — flagged explicitly in Task 13 as needing unification, not independent guessing. `Bootstrap`'s field set (Task 1) is consumed identically by Task 5 (kestrel-init) and produced by Task 8 (create.rs) — verify no field drift between when Task 1 defines it and when Task 8 actually constructs one. `hooks.rs`'s real crate location (kestrel-oci, per Task 7's retroactive correction to Task 4) must be applied BEFORE Task 4 is considered done if tasks are executed in order — flagged prominently in both tasks.

**Known judgment calls flagged for the implementer/reviewer:** the `kestrel-net`/tokio/Rule-#2 interaction (Task 3), static linking's real toolchain answer (Task 5), the bundle-vs-image-rootfs scope decision (Task 8), and whether Rule #2's no-thread-spawning constraint extends to `kestrel-init` (Task 6) are the four most consequential open questions this plan could not fully resolve without live verification — each is called out explicitly at its first relevant task rather than guessed.
