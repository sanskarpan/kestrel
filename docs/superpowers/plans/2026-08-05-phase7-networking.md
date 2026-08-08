# Phase 7 — Networking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-net` per CHECKLIST.md's Phase 7 (24 tasks) and SPEC.md §11: netns lifecycle, an `rtnetlink`-only bridge/veth data path, IPAM, iptables-based NAT, the four networking modes, `/etc/hosts`+friends generation, and an embedded DNS resolver — per the approved design doc (`docs/superpowers/specs/2026-08-05-phase7-networking-design.md`), incorporating its post-review fixes (posix_spawn-based netns creation instead of raw fork, two-chain NAT teardown, one-hop `container:<id>` resolution, `block_in_place` for `nsenter`).

**Architecture:** `kestrel-net` depends on `kestrel-ns` (namespace pin/join primitives, extended with one new generic `with_namespace` helper) and gets its own async stack (`tokio` + `rtnetlink`), independent of `kestrel-runtime`'s single-threaded constraint (Rule #2 scope, re-verified in Phase 6 and again here). Every module is built and unit/root-tested standalone; a final composing test suite proves the 5 CHECKLIST-required scenarios plus `host` mode and `container:<id>` mode end to end.

**Tech Stack:** `tokio`, `rtnetlink` (verified against the real, current crate source — see grounding below), `futures-util`, `ipnetwork` (the same subnet/address type `rtnetlink`'s own examples use), `serde`/`serde_json` (IPAM persistence), `nix`/`libc` (the `netns-helper` binary), `kestrel-ns` (namespace pin/join reuse).

---

## Real-API grounding this plan was written against

Fetched directly from `rust-netlink/rtnetlink`'s real source (GitHub, current `master`) — every snippet below is copied from real example/source files, not guessed:

- **Connection setup**: `let (connection, handle, _) = rtnetlink::new_connection().unwrap(); tokio::spawn(connection);` — the returned `connection` future must be polled (spawned) for the `handle` to ever get responses; this is a real, easy-to-miss requirement.
- **Bridge creation**: `handle.link().add(rtnetlink::LinkBridge::new("my-bridge").build()).execute().await?`
- **Veth creation**: `handle.link().add(rtnetlink::LinkVeth::new("veth1", "veth1-peer").build()).execute().await?` — both ends land in the caller's own netns; moving one end elsewhere is a separate `set()` call (below).
- **Finding a link by name**: `handle.link().get().match_name(name.to_string()).execute()` returns a stream; `use futures_util::stream::TryStreamExt; links.try_next().await?` yields `Option<LinkMessage>`, whose `.header.index` is the kernel ifindex needed by every other call.
- **Mutating an existing link** (up/down/mtu/rename/enslave/move-to-netns) — **does NOT chain directly off `handle.link().set(idx)`**, contrary to SPEC.md §11.2's pseudocode. The real pattern: build a `LinkMessage` via `rtnetlink::LinkUnspec::new_with_index(idx)` (a `LinkMessageBuilder<LinkUnspec>`), chain builder methods on THAT, then pass the finished message to `.set()`:
  ```rust
  handle.link().set(
      rtnetlink::LinkUnspec::new_with_index(idx)
          .up()                       // ip link set dev DEV up
          .controller(bridge_idx)     // ip link set NAME master CONTROLLER (enslave to bridge)
          .setns_by_fd(netns_raw_fd)  // move into another netns by fd (NOT setns_by_pid — pid reuse TOCTOU)
          .mtu(1500)
          .name("eth0")               // rename
          .build()
  ).execute().await?
  ```
  All of `.up()`, `.down()`, `.mtu(u32)`, `.name(impl Into<String>)`, `.address(Vec<u8>)` (sets MAC), `.setns_by_pid(u32)`, `.setns_by_fd(RawFd)`, `.controller(ctrl_index: u32)`, `.nocontroller()` are real, confirmed methods on `LinkMessageBuilder<LinkUnspec>` (`src/link/builder.rs`). Chain only the ones actually needed per call — a single `.set()` call can combine several (e.g. up + controller + mtu in one netlink message), which is preferable to multiple round-trips where the operations are independent.
- **Address assignment**: `handle.address().add(link_index, ip_addr, prefix_len).execute().await?` — takes a plain `std::net::IpAddr` + `u8` prefix length, not an `ipnetwork` type directly (`ip.ip()`/`ip.prefix()` from an `ipnetwork::IpNetwork` supply these).
- **Route addition**: `rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new().destination_prefix(dest_ip, prefix).gateway(gw_ip).build()`, then `handle.route().add(route).execute().await?`. For a default route, `destination_prefix` is `0.0.0.0/0` — confirm the builder accepts this (a default-route example wasn't directly fetched; verify during Task 5's implementation, it's a standard netlink route and should need no special-casing, but don't assume without a real compile+run check).
- **⚠️ Do NOT use `rtnetlink::NetworkNamespace::add`/`::del`** for netns creation, despite it existing in the crate (`src/ns.rs`) and looking convenient. Its real implementation calls `unsafe { fork() }` directly off whatever thread invokes it, with zero multi-threaded-process safety handling — exactly the hazard the design doc's Blocking Finding #1 identified and this plan's Task 3 works around via a `posix_spawn`-based helper subprocess instead. This is independent confirmation (from reading the crate's own source) that the design's fix was necessary, not overcautious.

## File Structure

```
crates/kestrel-net/
├── Cargo.toml                  — tokio/rtnetlink/futures-util/ipnetwork/serde/kestrel-ns deps
├── src/
│   ├── lib.rs
│   ├── bin/
│   │   └── netns-helper.rs      — tiny posix_spawn-friendly netns-creation helper (Task 3)
│   ├── netns.rs                  — create_netns/teardown_netns/nsenter (Task 3)
│   ├── bridge.rs                   — ensure_bridge/teardown_bridge_network (Task 4)
│   ├── veth.rs                       — veth pair, move-by-fd, enslave, in-netns setup, MAC (Task 5)
│   ├── ipam.rs                         — bitmap allocator + persistence (Task 6)
│   ├── nat.rs                            — iptables KESTREL-* chains (Task 7)
│   ├── modes.rs                            — NetworkConfig dispatch (Task 8)
│   ├── hosts.rs                              — /etc/hosts + friends generation (Task 8)
│   └── dns.rs                                  — minimal embedded resolver (Task 9)
└── tests/
    ├── ipam.rs                     — deterministic, no root (Task 6)
    ├── nat_args.rs                  — deterministic, no root (Task 7)
    ├── hosts.rs                      — deterministic, no root (Task 8)
    ├── netns.rs                        — root-gated (Task 3)
    ├── bridge.rs                        — root-gated (Task 4)
    ├── veth.rs                            — root-gated (Task 5)
    ├── dns.rs                               — root-gated (async, real UDP socket) (Task 9)
    └── lifecycle.rs                          — root-gated capstone: the 5 required
                                                  scenarios + host mode + container:<id> (Task 10)
```

Modifies (outside `kestrel-net`):
- `crates/kestrel-ns/src/join.rs` — adds `with_namespace` (Task 2).
- `Makefile` — top-of-file NOTE update (Task 11).

---

## Task 1: `kestrel-net` Cargo.toml

**Files:**
- Modify: `crates/kestrel-net/Cargo.toml`
- Modify: `crates/kestrel-net/src/lib.rs`

- [ ] **Step 1: Update Cargo.toml**

```toml
[package]
name = "kestrel-net"
edition.workspace = true
version.workspace = true

[[bin]]
name = "netns-helper"
path = "src/bin/netns-helper.rs"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
nix = { workspace = true, features = ["sched", "mount", "process", "fs"] }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
kestrel-ns = { path = "../kestrel-ns" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "process", "net", "sync", "time"] }
rtnetlink = "0.14"
futures-util = "0.3"
ipnetwork = "0.20"

[dev-dependencies]
tempfile = "3"
```

Before trusting these version pins, run `cargo add --dry-run <crate>` for each new dependency inside the VM to confirm what actually resolves — same discipline as every prior phase's Task 1. `rtnetlink = "0.14"` is a best guess at plan-writing time (the real API grounding above was fetched from the crate's `master` branch, not a specific tagged version) — pin whatever version actually resolves and re-confirm the grounding section's exact method signatures compile against it; if they've drifted, that's real, expected verification work, not a sign this plan is wrong.

- [ ] **Step 2: Create the binary target's placeholder and confirm the workspace builds**

```rust
// crates/kestrel-net/src/bin/netns-helper.rs
fn main() {
    unimplemented!("Task 3 implements this");
}
```

```rust
// crates/kestrel-net/src/lib.rs
//! kestrel-net — network namespace lifecycle, bridge/veth data path,
//! IPAM, NAT, and DNS for kestrel containers. See
//! docs/superpowers/specs/2026-08-05-phase7-networking-design.md.
```

- [ ] **Step 3: Confirm it builds**

Run inside the Lima VM: `cargo build -p kestrel-net` and `cargo build --workspace`. Both must succeed before Task 2 starts.

## Context

Task 1 of 11. Establishes `kestrel-net`'s dependency surface and its one binary target (`netns-helper`, a deliberate design choice from the reviewed design doc — see Task 3) before any real module exists.

## Your Job

1. Verify real resolvable dependency versions.
2. Add the `[[bin]]` target and its placeholder (a real binary target must exist and build from Task 1 onward, even though its logic isn't implemented until Task 3 — Cargo needs the target declared and a compiling `fn main` for the workspace build to stay green throughout).
3. Confirm both `cargo build -p kestrel-net` and `cargo build --workspace` succeed inside the VM.
4. Do NOT commit/branch/push. Report back.

---

## Task 2: `kestrel-ns::join::with_namespace` — the generic restore-on-exit primitive

**Files:**
- Modify: `crates/kestrel-ns/src/join.rs`
- Create: `crates/kestrel-ns/tests/with_namespace.rs`

- [ ] **Step 1: Implement**

```rust
// Addition to crates/kestrel-ns/src/join.rs

use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

/// Temporarily joins the namespace referenced by `fd`, runs `f`, then
/// restores the CALLING THREAD's original namespace before returning —
/// unlike [`join_namespaces`] (a one-way join used once at final
/// container exec), this is for code that needs to dip into another
/// namespace and come back, e.g. `kestrel-net`'s `nsenter` for
/// configuring an interface from inside a container's netns.
///
/// `setns` operates on the CALLING THREAD, not the whole process —
/// callers running under a multi-threaded async runtime MUST ensure this
/// runs on one pinned OS thread for its entire duration (e.g. via
/// `tokio::task::block_in_place`), since a raw `setns()` racing the
/// runtime's work-stealing scheduler would leave the wrong thread in the
/// wrong namespace. This function itself is runtime-agnostic — it uses
/// only synchronous syscalls — enforcing "stay on one thread" is the
/// caller's responsibility.
pub fn with_namespace<T>(ns: NsType, fd: BorrowedFd, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let self_path = Path::new("/proc/self/ns").join(ns.proc_name());
    let original = std::fs::File::open(&self_path)
        .with_context(|| format!("opening {} to remember the current namespace", self_path.display()))?;

    nix::sched::setns(fd, ns.clone_flag()).with_context(|| format!("setns into the target {ns:?} namespace"))?;

    // Guard ensures the restore happens even if `f` panics — `setns`ing
    // back to `original` on Drop, best-effort (a failure here is logged
    // via the returned Result's discard, not propagated, since Drop can't
    // return a Result; matches this crate's existing best-effort-cleanup
    // idiom elsewhere, e.g. pin.rs's `let _ = fs::remove_file(...)`).
    struct RestoreGuard {
        original: std::fs::File,
        ns: NsType,
    }
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            if let Err(e) = nix::sched::setns(self.original.as_fd(), self.ns.clone_flag()) {
                tracing::error!(error = %e, ns = ?self.ns, "failed to restore original namespace after with_namespace");
            }
        }
    }
    let _guard = RestoreGuard { original, ns };

    f()
}
```

Verify `NsType::proc_name()` (used by `pin.rs` already, per the design doc's citation) returns the right string (`"net"` for `NsType::Net`) — read `crates/kestrel-ns/src/types.rs` to confirm the exact method name and behavior before trusting this snippet verbatim; the design doc's grounding cites `ns.proc_name()` used identically in `pin.rs`, so this should already exist, but confirm rather than assume.

- [ ] **Step 2: Tests**

```rust
// crates/kestrel-ns/tests/with_namespace.rs
//
// Root-gated: setns requires CAP_SYS_ADMIN.

use std::os::fd::AsFd;

use kestrel_ns::join::with_namespace;
use kestrel_ns::types::NsType;

#[test]
#[ignore = "requires root"]
fn test_with_namespace_restores_original_namespace_after_closure() {
    kestrel_ns::test_util::run_isolated(|| {
        let original_ns_id = std::fs::read_link("/proc/self/ns/uts").unwrap();

        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUTS).expect("unshare a target UTS namespace");
        let target_ns_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_ne!(original_ns_id, target_ns_id, "unshare must have actually created a new namespace");

        // Re-open the CURRENT (target) namespace's own fd to join "into"
        // via with_namespace, then confirm we're restored to the
        // namespace we were in immediately before with_namespace was
        // called (i.e. `target_ns_id`, not `original_ns_id` — this test
        // deliberately calls with_namespace from INSIDE the just-unshared
        // namespace, joining back into itself via its own fd, to prove
        // the restore targets "whatever we were in when with_namespace
        // was called," not some other fixed reference point).
        let target_fd = std::fs::File::open("/proc/self/ns/uts").unwrap();

        with_namespace(NsType::Uts, target_fd.as_fd(), || {
            let inside_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
            assert_eq!(inside_id, target_ns_id, "must actually be in the target namespace inside the closure");
            Ok(())
        })
        .unwrap();

        let after_id = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_eq!(after_id, target_ns_id, "must be restored to the pre-call namespace after with_namespace returns");
    });
}

#[test]
#[ignore = "requires root"]
fn test_with_namespace_restores_even_when_closure_returns_err() {
    kestrel_ns::test_util::run_isolated(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUTS).expect("unshare");
        let ns_id_before = std::fs::read_link("/proc/self/ns/uts").unwrap();
        let target_fd = std::fs::File::open("/proc/self/ns/uts").unwrap();

        let result: anyhow::Result<()> = with_namespace(NsType::Uts, target_fd.as_fd(), || anyhow::bail!("deliberate failure"));
        assert!(result.is_err());

        let ns_id_after = std::fs::read_link("/proc/self/ns/uts").unwrap();
        assert_eq!(ns_id_before, ns_id_after, "restore must happen even when the closure returns Err, not just on success");
    });
}
```

Uses `NsType::Uts` (not `Net`) deliberately — this test belongs to `kestrel-ns`, which has no reason to know about networking specifically; UTS namespaces are simpler to unshare/verify in a test (`/proc/self/ns/uts` readlink target changing) and exercise exactly the same `setns`-restore mechanics `kestrel-net`'s `nsenter` will rely on for `NsType::Net`.

- [ ] **Step 3: Run**

Run inside the VM: `sudo -E cargo test -p kestrel-ns --test with_namespace -- --ignored` (or via `make test-root`, which sweeps all `#[ignore]`d tests workspace-wide). Confirm both tests pass.

## Context

Task 2 of 11. This is the one piece of this phase that lives OUTSIDE `kestrel-net` — a small, generically useful addition to the already-stable `kestrel-ns` crate (Phase 2/3), per the design doc's explicit reasoning for why "temporarily join and restore" belongs there rather than being duplicated inside `kestrel-net`. Nothing else in Phase 7 can proceed until this exists, since `kestrel-net`'s own `nsenter` (Task 3) is a thin wrapper around it.

## Your Job

1. Confirm `NsType::proc_name()`'s real signature/behavior in `crates/kestrel-ns/src/types.rs`.
2. Implement `with_namespace` exactly as specified, fixing any real API mismatch you find.
3. Write and run the two root-gated tests, confirm both pass.
4. Self-review: does the `Drop`-based restore genuinely fire on a panic unwinding through `f()`, not just a normal `Err` return? (Rust's `Drop` runs during unwinding by default unless the panic strategy is `abort` — confirm this crate's/workspace's panic strategy isn't set to `abort` in a way that would skip this, by checking the workspace `Cargo.toml`/`.cargo/config.toml` for a `panic = "abort"` profile setting.)
5. Do NOT commit/branch/push. Report back.

---

## Task 3: `netns.rs` — create/teardown/nsenter, via a `posix_spawn`-safe helper

**Files:**
- Create: `crates/kestrel-net/src/bin/netns-helper.rs` (replacing Task 1's placeholder)
- Create: `crates/kestrel-net/src/netns.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/netns.rs`

- [ ] **Step 1: The helper binary**

```rust
// crates/kestrel-net/src/bin/netns-helper.rs
//
//! A minimal, single-purpose helper: unshare CLONE_NEWNET, signal
//! readiness, then block until told to exit. Spawned via
//! `tokio::process::Command` (which uses posix_spawn on Linux) rather
//! than reached via a raw `fork()` from kestrel-net's own multi-threaded
//! process — see netns.rs's module doc for the full reasoning. Every
//! operation here is a plain, synchronous, async-signal-safe-adjacent
//! syscall; there is no allocation-heavy or lock-taking work between
//! process start and the unshare call.

use std::io::{Read, Write};

fn main() {
    if let Err(e) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET) {
        eprintln!("netns-helper: unshare(CLONE_NEWNET) failed: {e}");
        std::process::exit(1);
    }

    // Signal readiness: one byte on stdout. The parent reads this before
    // proceeding to open /proc/<this-pid>/ns/net for pinning — without
    // this handshake, the parent could race ahead and try to pin before
    // the unshare has actually happened.
    let mut stdout = std::io::stdout();
    if stdout.write_all(b"R").and_then(|_| stdout.flush()).is_err() {
        std::process::exit(1);
    }

    // Block until the parent closes stdin (EOF) or sends a byte — either
    // way, this process's only remaining job is to keep existing long
    // enough for the parent to pin the namespace via
    // /proc/<pid>/ns/net; once pinned, the namespace survives this
    // process's exit (the bind-mount pin is what keeps it alive, not
    // this process), so exiting here is always safe once the parent has
    // signaled it's done.
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read(&mut buf);
}
```

- [ ] **Step 2: `netns.rs`**

```rust
// crates/kestrel-net/src/netns.rs
//
//! Network namespace creation, pinning, teardown, and temporary joining.
//!
//! `create_netns` deliberately does NOT use a raw `fork()` (unlike
//! kestrel-ns's own `run_isolated`/three-stage-dance pattern, which is
//! only proven safe inside kestrel-runtime — a process Rule #2
//! *guarantees* is single-threaded). kestrel-net is explicitly
//! multi-threaded (tokio `rt-multi-thread`); forking one of its threads
//! would only duplicate that thread, silently leaving any lock another
//! thread held at that instant permanently "held" in the child, a real
//! deadlock hazard the moment the child's own bookkeeping touches
//! anything similar. Independent confirmation this isn't overcautious:
//! the `rtnetlink` crate's OWN `NetworkNamespace::add` does exactly this
//! unsafe raw-fork thing internally — deliberately not used here.
//!
//! Instead: spawn `netns-helper` (a separate, tiny, single-purpose
//! binary — see src/bin/netns-helper.rs) via `tokio::process::Command`,
//! which uses `posix_spawn` on Linux specifically to avoid this class of
//! multi-threaded-fork hazard. The helper unshares CLONE_NEWNET, signals
//! readiness, and blocks; the parent pins the namespace via the helper's
//! pid, then releases it.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::os::fd::{AsFd, BorrowedFd};

use anyhow::{bail, Context, Result};
use kestrel_ns::join::with_namespace;
use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::types::NsType;
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

fn pin_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join("netns").join(id)
}

/// Creates a new network namespace and pins it at
/// `<run_dir>/netns/<id>`. `run_dir` is normally `/run/kestrel`
/// (SPEC.md's state dir), passed explicitly rather than hardcoded so
/// tests can point it at a tempdir.
pub async fn create_netns(run_dir: &Path, id: &str) -> Result<PathBuf> {
    let target = pin_path(run_dir, id);
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| format!("creating {}", parent.display()))?;
    }

    let helper_path = std::env::current_exe()
        .context("resolving current_exe")?
        .parent()
        .context("current_exe has no parent dir")?
        .join("netns-helper");

    let mut child = Command::new(&helper_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", helper_path.display()))?;

    let pid = child.id().context("helper process has no pid (already exited?)")?;

    // Wait for the one-byte readiness signal before pinning — see
    // netns-helper.rs's own comment for why this handshake exists.
    let mut stdout = child.stdout.take().context("helper's stdout was not piped")?;
    let mut ready = [0u8; 1];
    stdout.read_exact(&mut ready).await.context("reading readiness byte from netns-helper")?;
    if ready[0] != b'R' {
        bail!("netns-helper sent unexpected readiness byte: {:?}", ready);
    }

    let pin_result = pin_namespace(Pid::from_raw(pid as i32), NsType::Net, &target);

    // Release the helper regardless of whether pinning succeeded — it's
    // done its job either way, and leaving it blocked on stdin forever
    // on a pin failure would leak a process.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.shutdown().await;
    }
    let _ = child.wait().await;

    pin_result.with_context(|| format!("pinning new netns for {id} at {}", target.display()))?;
    Ok(target)
}

/// Reverses [`create_netns`]: unmounts the pin and removes the file.
pub fn teardown_netns(run_dir: &Path, id: &str) -> Result<()> {
    let target = pin_path(run_dir, id);
    unpin_namespace(&target)
}

/// Temporarily enters the netns pinned at `pin_path`, runs `f`, restores
/// the caller's original netns on the way out. `f` and everything it
/// calls MUST be synchronous — this whole call must run on one pinned OS
/// thread (see `with_namespace`'s own doc comment), so callers on a
/// multi-threaded tokio runtime MUST wrap this in
/// `tokio::task::block_in_place` (or run it from a context already
/// guaranteed single-threaded, e.g. a test's `run_isolated` fork).
pub fn nsenter<T>(pin_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let file = std::fs::File::open(pin_path).with_context(|| format!("opening netns pin {}", pin_path.display()))?;
    with_namespace(NsType::Net, file.as_fd(), f)
}
```

Verify `kestrel_ns::pin::pin_namespace`'s exact signature (`pid: Pid, ns: NsType, target: &Path`) against the real current source (already read during design review — `crates/kestrel-ns/src/pin.rs`) before trusting this verbatim; it should be unchanged since Phase 2, but confirm.

- [ ] **Step 3: Wire into lib.rs**

```rust
pub mod netns;
```

- [ ] **Step 4: Tests**

```rust
// crates/kestrel-net/tests/netns.rs

use kestrel_net::netns::{create_netns, nsenter, teardown_netns};

#[tokio::test]
#[ignore = "requires root"]
async fn test_create_netns_produces_a_distinct_pinned_namespace() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = tmp.path();

    let host_ns = std::fs::read_link("/proc/self/ns/net").unwrap();
    let pin = create_netns(run_dir, "test1").await.unwrap();
    assert!(pin.is_file(), "pin file must exist");

    // The pinned namespace's real identity (via readlink on the pin
    // itself, which — being a bind-mount of a nsfs file — resolves the
    // same way /proc/<pid>/ns/net does) must differ from the host's.
    let pinned_ns = std::fs::read_link(&pin).unwrap();
    assert_ne!(host_ns, pinned_ns, "pinned netns must be a genuinely new namespace, not the host's");

    teardown_netns(run_dir, "test1").unwrap();
    assert!(!pin.exists(), "teardown must remove the pin file");
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_nsenter_runs_closure_inside_pinned_namespace_and_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = tmp.path();
    let pin = create_netns(run_dir, "test2").await.unwrap();
    let pinned_ns = std::fs::read_link(&pin).unwrap();
    let host_ns_before = std::fs::read_link("/proc/self/ns/net").unwrap();

    // nsenter's closure must run synchronously on one thread — wrap in
    // block_in_place per netns.rs's own documented contract, run inside
    // a #[tokio::test] (multi-threaded by default with the `macros` +
    // `rt-multi-thread` features).
    let observed = tokio::task::block_in_place(|| {
        nsenter(&pin, || Ok(std::fs::read_link("/proc/self/ns/net").unwrap()))
    })
    .unwrap();
    assert_eq!(observed, pinned_ns, "closure must observe the target namespace, not the host's");

    let host_ns_after = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_eq!(host_ns_before, host_ns_after, "nsenter must restore the original namespace afterward");

    teardown_netns(run_dir, "test2").unwrap();
}
```

Confirm bind-mounted nsfs pin files really do `readlink` to the same `net:[<inode>]`-style string `/proc/<pid>/ns/net` shows for the same namespace (this is standard nsfs behavior, but verify it empirically in the VM rather than assuming, since the whole first test's assertion depends on it).

- [ ] **Step 5: Run**

`make test-root` (or targeted `sudo -E cargo test -p kestrel-net --test netns -- --ignored`) inside the VM. Confirm both tests pass.

## Context

Task 3 of 11. The foundational module every other `kestrel-net` module builds on. Task 2's `with_namespace` must already exist. This is the task where the design doc's Blocking Finding #1 fix (no raw fork in a multi-threaded process) actually gets implemented, not just described.

## Your Job

1. Implement the `netns-helper` binary and `netns.rs` as specified.
2. Wire `pub mod netns;` into `lib.rs`.
3. Write and run the tests, confirm both pass.
4. Self-review: trace through what happens if `pin_namespace` FAILS (e.g. permission error) — does the helper process get cleanly released either way (confirm the `stdin.shutdown()`/`child.wait()` cleanup runs even on the pinning-failed path, not just the success path — re-read the `Step 2` code's control flow carefully, since a naive `?`-early-return before that cleanup would leak the helper)?
5. Do NOT commit/branch/push. Report back.

---

## Task 4: `bridge.rs` — `ensure_bridge` and the composed teardown entrypoint

**Files:**
- Create: `crates/kestrel-net/src/bridge.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/bridge.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-net/src/bridge.rs

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use ipnetwork::Ipv4Network;
use rtnetlink::{Handle, LinkBridge, LinkUnspec};

/// Finds a link's kernel ifindex by name, or `None` if it doesn't exist.
pub async fn find_link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await.with_context(|| format!("looking up link {name}"))? {
        Some(msg) => Ok(Some(msg.header.index)),
        None => Ok(None),
    }
}

/// Creates the bridge if it doesn't already exist, assigns it the
/// gateway address, and brings it up. Idempotent — safe to call on every
/// daemon start / container create.
pub async fn ensure_bridge(handle: &Handle, name: &str, gateway: Ipv4Addr, subnet: Ipv4Network) -> Result<u32> {
    let idx = match find_link_index(handle, name).await? {
        Some(idx) => idx,
        None => {
            handle.link().add(LinkBridge::new(name).build()).execute().await.with_context(|| format!("creating bridge {name}"))?;
            find_link_index(handle, name)
                .await?
                .with_context(|| format!("bridge {name} not found immediately after creating it"))?
        }
    };

    // Idempotent address assignment: adding the same address twice
    // returns EEXIST from the kernel, which is fine — check first rather
    // than relying on error-code-sniffing, since "does this link already
    // have this address" is a cheap, clear query.
    let already_has_gateway = handle
        .address()
        .get()
        .set_link_index_filter(idx)
        .execute()
        .try_filter(|addr| {
            let has_it = addr.header.family == rtnetlink::packet_route::AddressFamily::Inet
                && addr.attributes.iter().any(|a| matches!(a, rtnetlink::packet_route::address::AddressAttribute::Address(std::net::IpAddr::V4(ip)) if *ip == gateway));
            futures_util::future::ready(has_it)
        })
        .try_next()
        .await
        .context("checking existing bridge addresses")?
        .is_some();

    if !already_has_gateway {
        handle
            .address()
            .add(idx, std::net::IpAddr::V4(gateway), subnet.prefix())
            .execute()
            .await
            .with_context(|| format!("assigning gateway {gateway} to bridge {name}"))?;
    }

    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await
        .with_context(|| format!("bringing up bridge {name}"))?;

    Ok(idx)
}

/// Deletes the bridge link. Part of a full daemon-level network
/// teardown, NOT called per-container (the bridge is shared across every
/// bridge-mode container) — kept separate from
/// [`teardown_bridge_network`], which tears down one CONTAINER's
/// networking, not the shared bridge itself.
pub async fn delete_bridge(handle: &Handle, name: &str) -> Result<()> {
    if let Some(idx) = find_link_index(handle, name).await? {
        handle.link().del(idx).execute().await.with_context(|| format!("deleting bridge {name}"))?;
    }
    Ok(())
}

/// The composed, single-call teardown for ONE container's bridge-mode
/// networking — mirrors `attach_bridge`'s composed setup from the
/// opposite direction. Calls (in order) veth/link deletion, IPAM
/// release, NAT rule removal, and netns unpinning. The actual
/// implementation is filled in once Tasks 5-7 (veth, ipam, nat) exist —
/// this task establishes the function's signature and wires in what's
/// available so far (nothing yet); Task 8 completes its body once every
/// dependency module exists. Declared here (not deferred entirely to
/// Task 8) so the signature is locked in early and `bridge.rs` stays the
/// module that owns bridge-network lifecycle end to end, per the design
/// doc.
pub async fn teardown_bridge_network(_run_dir: &std::path::Path, _id: &str) -> Result<()> {
    // Completed in Task 8 once veth/ipam/nat modules exist.
    Ok(())
}
```

Verify `rtnetlink::packet_route::address::AddressAttribute` and `AddressFamily`'s exact real paths/variants (used in the "does this link already have this gateway" check) against the actual crate re-exports — the grounding section didn't fetch this specific type, so confirm it during implementation via `cargo doc -p rtnetlink --open` or the vendored source, and adjust the exact match pattern if the real enum shape differs.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod bridge;
```

- [ ] **Step 3: Tests**

```rust
// crates/kestrel-net/tests/bridge.rs

use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use kestrel_net::bridge::{delete_bridge, ensure_bridge, find_link_index};

#[tokio::test]
#[ignore = "requires root"]
async fn test_ensure_bridge_creates_assigns_and_brings_up() {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    let name = "kbr-test0";
    let gateway: Ipv4Addr = "172.30.0.1".parse().unwrap();
    let subnet: Ipv4Network = "172.30.0.0/24".parse().unwrap();

    let idx = ensure_bridge(&handle, name, gateway, subnet).await.unwrap();
    assert!(find_link_index(&handle, name).await.unwrap().is_some());

    // Idempotent: calling again must not error or duplicate anything.
    let idx2 = ensure_bridge(&handle, name, gateway, subnet).await.unwrap();
    assert_eq!(idx, idx2);

    delete_bridge(&handle, name).await.unwrap();
    assert!(find_link_index(&handle, name).await.unwrap().is_none());
}
```

Run this test's setup/teardown inside `kestrel_ns::test_util::run_isolated` with the mount/net-namespace-isolation preamble this project has used since Phase 4 (create a fresh, private netns for the WHOLE test via `unshare(CLONE_NEWNET)` first, so a real bridge creation/deletion never touches the VM's actual host network state) — write a small local `tests/common/mod.rs` for `kestrel-net` (a documented duplicate of the same pattern `kestrel-rootfs`/`kestrel-image` already use for their own namespace-isolation test helpers, adapted to `CLONE_NEWNET` instead of `CLONE_NEWNS`) rather than running this test directly against the VM's real network namespace.

- [ ] **Step 4: Run**

`sudo -E cargo test -p kestrel-net --test bridge -- --ignored` inside the VM.

## Context

Task 4 of 11. First task using `rtnetlink` for real network mutation. Depends on Task 1's dependency setup only (not Tasks 2/3) — bridges live in whatever netns the caller is already in, no `nsenter` needed for bridge management itself (only veth's in-netns half, Task 5, needs `nsenter`).

## Your Job

1. Verify the exact `AddressAttribute`/`AddressFamily` shape before trusting the idempotency-check snippet.
2. Implement as specified, write the `tests/common/mod.rs` netns-isolation helper for `kestrel-net` (CLONE_NEWNET-based, isolating the WHOLE test from the VM's real network state — this is different from `nsenter`'s per-container netns, it's test isolation for the test process itself).
3. Run tests, confirm they pass and leave no residue in the VM's real network namespace (check `ip link` before/after from OUTSIDE the test, i.e. from a plain VM shell, not from within the test's own isolated netns).
4. Do NOT commit/branch/push. Report back.

---

## Task 5: `veth.rs` — pair creation, move-by-fd, enslavement, in-netns setup, deterministic MAC

**Files:**
- Create: `crates/kestrel-net/src/veth.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/veth.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-net/src/veth.rs

use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use ipnetwork::Ipv4Network;
use rtnetlink::{Handle, LinkUnspec, LinkVeth, RouteMessageBuilder};

use crate::bridge::find_link_index;
use crate::netns::nsenter;

/// A deterministic MAC for `ip`, stable across restarts without needing
/// separate persisted state: a fixed locally-administered OUI (`02`, per
/// IEEE 802's locally-administered-address bit — never collides with a
/// real vendor-assigned MAC) followed by the IP's 4 octets. This gives
/// every container a unique, reproducible MAC as long as its IP is
/// unique (which IPAM already guarantees).
pub fn deterministic_mac(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

/// The full veth attach sequence: create the pair (both ends start in
/// the CALLER's netns), move the peer into the container's netns by fd,
/// enslave the host end to the bridge, bring it up; then, inside the
/// container's netns (via `nsenter`, wrapped in `block_in_place` since
/// this whole function runs under tokio), rename the peer to `eth0`,
/// assign its IP, set its deterministic MAC, bring it and `lo` up, and
/// add the default route via the bridge gateway.
pub async fn attach_veth(
    handle: &Handle,
    id: &str,
    netns_pin: &Path,
    bridge_idx: u32,
    ip: Ipv4Addr,
    subnet: Ipv4Network,
    gateway: Ipv4Addr,
) -> Result<()> {
    let host_if = format!("veth{}", &id[..id.len().min(8)]);
    let peer_if = format!("tmp-peer-{}", &id[..id.len().min(8)]);

    handle
        .link()
        .add(LinkVeth::new(&host_if, &peer_if).build())
        .execute()
        .await
        .with_context(|| format!("creating veth pair {host_if}/{peer_if}"))?;

    let peer_idx = find_link_index(handle, &peer_if)
        .await?
        .with_context(|| format!("veth peer {peer_if} not found immediately after creation"))?;

    // Open the netns pin file to get a real fd for setns_by_fd — NOT
    // setns_by_pid, per the design doc: a pid-based move is a real
    // TOCTOU hazard if the target's pid gets reused between namespace
    // creation and this call. The pin file itself IS the namespace
    // reference, immune to pid reuse entirely.
    let netns_file = std::fs::File::open(netns_pin).with_context(|| format!("opening netns pin {}", netns_pin.display()))?;

    handle
        .link()
        .set(LinkUnspec::new_with_index(peer_idx).setns_by_fd(netns_file.as_raw_fd()).build())
        .execute()
        .await
        .with_context(|| format!("moving {peer_if} into the container netns"))?;

    let host_idx = find_link_index(handle, &host_if)
        .await?
        .with_context(|| format!("host-side veth {host_if} not found"))?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(host_idx).controller(bridge_idx).mtu(1500).up().build())
        .execute()
        .await
        .with_context(|| format!("enslaving {host_if} to the bridge and bringing it up"))?;

    let mac = deterministic_mac(ip);
    let prefix = subnet.prefix();

    // Everything below runs INSIDE the container's netns. This whole
    // sync closure must stay on one OS thread — block_in_place per
    // netns.rs's documented contract.
    let netns_pin = netns_pin.to_path_buf();
    tokio::task::block_in_place(move || {
        nsenter(&netns_pin, || {
            // A fresh, blocking-friendly rtnetlink connection for use
            // INSIDE the target netns — reusing the outer `handle` here
            // would be wrong, since that handle's netlink socket was
            // opened in the CALLER's netns before nsenter ran; a socket
            // opened after nsenter operates against the namespace it was
            // opened in, which is exactly why this needs its own
            // connection rather than reusing `handle`. Uses a small,
            // local current-thread runtime rather than nested async,
            // since we're already inside block_in_place's synchronous
            // context — verify during implementation that constructing
            // and driving a throwaway `tokio::runtime::Builder::new_current_thread()`
            // runtime here is sound (it should be: block_in_place hands
            // this thread over for exactly this kind of blocking/nested
            // work), rather than assuming without checking.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building in-netns rtnetlink runtime")?;
            rt.block_on(async {
                let (connection, inner_handle, _) = rtnetlink::new_connection().context("opening netlink socket inside container netns")?;
                tokio::spawn(connection);

                inner_handle
                    .link()
                    .set(LinkUnspec::new_with_index(peer_idx).name("eth0").address(mac.to_vec()).build())
                    .execute()
                    .await
                    .context("renaming peer to eth0 and setting its MAC")?;

                inner_handle
                    .address()
                    .add(peer_idx, std::net::IpAddr::V4(ip), prefix)
                    .execute()
                    .await
                    .context("assigning container IP")?;

                inner_handle
                    .link()
                    .set(LinkUnspec::new_with_index(peer_idx).up().build())
                    .execute()
                    .await
                    .context("bringing up eth0")?;

                if let Some(lo_idx) = crate::bridge::find_link_index(&inner_handle, "lo").await? {
                    inner_handle.link().set(LinkUnspec::new_with_index(lo_idx).up().build()).execute().await.context("bringing up lo")?;
                }

                let default_route = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                    .gateway(gateway)
                    .build();
                inner_handle.route().add(default_route).execute().await.context("adding default route via bridge gateway")?;

                Ok::<(), anyhow::Error>(())
            })
        })
    })?;

    Ok(())
}
```

**Verify during implementation, don't assume**: (1) whether `RouteMessageBuilder::<Ipv4Addr>::destination_prefix(Ipv4Addr::UNSPECIFIED, 0)` is really the correct way to express a default route (`0.0.0.0/0`) with this crate's builder — the grounding section's fetched example used a specific destination/gateway pair, not a default route; confirm this compiles and produces the expected route via `ip route show` inside the test netns. (2) Whether constructing a fresh single-threaded tokio runtime from inside `block_in_place` (itself already running inside an outer multi-threaded runtime) is sound — this is a real, slightly unusual nesting pattern; if it turns out NOT to be sound (tokio may reject nested runtime construction in ways not obvious from the API alone), the fallback is to do the in-netns work via plain synchronous rtnetlink-equivalent raw netlink calls (no async needed for a handful of one-shot operations once already inside `nsenter`), or to keep the OUTER handle's underlying netlink socket fd and reopen the raw socket manually after `setns` — flag whichever approach you actually end up using clearly in your task report, since this is exactly the kind of thing this plan couldn't fully resolve without live verification.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod veth;
```

- [ ] **Step 3: Tests**

```rust
// crates/kestrel-net/tests/veth.rs

use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use kestrel_net::bridge::ensure_bridge;
use kestrel_net::netns::{create_netns, nsenter};
use kestrel_net::veth::{attach_veth, deterministic_mac};

#[test]
fn test_deterministic_mac_is_locally_administered_and_stable() {
    let ip: Ipv4Addr = "172.29.0.5".parse().unwrap();
    let mac1 = deterministic_mac(ip);
    let mac2 = deterministic_mac(ip);
    assert_eq!(mac1, mac2, "must be deterministic across calls");
    assert_eq!(mac1[0] & 0x02, 0x02, "must have the locally-administered bit set");
    assert_eq!(mac1[0] & 0x01, 0x00, "must NOT have the multicast bit set (a real unicast MAC)");
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_attach_veth_produces_working_container_networking() {
    // (Full test setup: create an isolating outer netns for the test
    // itself via this crate's tests/common/mod.rs helper from Task 4,
    // then inside it: ensure_bridge, create_netns for a fake container
    // id, attach_veth, then nsenter into the container netns and assert
    // `eth0` exists with the expected IP/MAC and a default route via the
    // gateway — via `ip addr show`/`ip route show`-equivalent rtnetlink
    // queries, not shelling out.)
}
```

Write the full test body during implementation (the plan intentionally leaves its exact assertions to the implementer, who will have a real, running `attach_veth` to introspect — write real assertions querying rtnetlink for the container-side interface's name/address/MAC/route, not a placeholder).

- [ ] **Step 4: Run**

`sudo -E cargo test -p kestrel-net --test veth -- --ignored` inside the VM.

## Context

Task 5 of 11. The most complex task in this phase — combines `rtnetlink`, `nsenter`'s block_in_place contract, and a genuinely uncertain nested-runtime question the plan flags explicitly rather than guessing. Depends on Tasks 3 (netns/nsenter) and 4 (bridge/find_link_index).

## Your Job

1. Resolve the two explicitly-flagged uncertainties (default-route construction, nested-runtime-inside-block_in_place soundness) for real — through actual compilation and testing, not assumption. If the nested-runtime approach doesn't work, implement the flagged fallback and explain why in your report.
2. Implement the rest as specified.
3. Write the full `tests/veth.rs` test body (not left as a stub) with real assertions.
4. Run tests, confirm they pass with zero residue in the VM's real network state.
5. Self-review: does `attach_veth` clean up the veth pair (or at least the host-side link) if it fails partway through (e.g. the netns move succeeds but the in-netns configuration fails)? A partially-attached veth is exactly the kind of leak `test_teardown_leaves_no_rules` (Task 10) needs to not exist. Document your conclusion.
6. Do NOT commit/branch/push. Report back.

---

## Task 6: `ipam.rs` — bitmap allocator with persistence

**Files:**
- Create: `crates/kestrel-net/src/ipam.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/ipam.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-net/src/ipam.rs
//
//! A bitmap allocator over an IPv4 subnet, persisted to disk. Network,
//! broadcast, and gateway addresses are reserved up front and never
//! handed out. Persistence uses the same write-temp-then-rename
//! atomicity `kestrel-image::store::ContentStore` established (Phase 6)
//! — not that type itself (a different crate, different concern), the
//! same PATTERN.

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
struct IpamState {
    /// Allocated address (as u32, host order via Ipv4Addr::into) -> owner id.
    allocated: HashMap<u32, String>,
}

pub struct Ipam {
    subnet: Ipv4Network,
    gateway: Ipv4Addr,
    state_path: PathBuf,
    state: IpamState,
}

impl Ipam {
    /// Loads persisted state from `state_path` if it exists, else starts
    /// empty. `gateway` is reserved automatically (in addition to the
    /// subnet's network/broadcast addresses) even on a fresh/empty
    /// state, so it's never handed out as a container address.
    pub fn load(subnet: Ipv4Network, gateway: Ipv4Addr, state_path: PathBuf) -> Result<Self> {
        let state = if state_path.is_file() {
            let data = fs::read(&state_path).with_context(|| format!("reading {}", state_path.display()))?;
            serde_json::from_slice(&data).with_context(|| format!("parsing {}", state_path.display()))?
        } else {
            IpamState::default()
        };
        Ok(Ipam { subnet, gateway, state_path, state })
    }

    fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        ip == self.subnet.network() || ip == self.subnet.broadcast() || ip == self.gateway
    }

    /// Allocates the lowest-numbered free address in the subnet for
    /// `owner_id`, persisting the change before returning it (so a crash
    /// immediately after allocation can't hand the same address out
    /// twice on restart).
    pub fn allocate(&mut self, owner_id: &str) -> Result<Ipv4Addr> {
        for ip in self.subnet.iter() {
            if self.is_reserved(ip) {
                continue;
            }
            let key: u32 = ip.into();
            if !self.state.allocated.contains_key(&key) {
                self.state.allocated.insert(key, owner_id.to_string());
                self.persist()?;
                return Ok(ip);
            }
        }
        bail!("no free addresses remaining in {}", self.subnet);
    }

    /// Releases `ip`. A no-op (not an error) if it wasn't allocated —
    /// matches this project's established "already gone is success"
    /// idiom for release/teardown operations (e.g. `store.rs`'s
    /// `remove_ref`).
    pub fn release(&mut self, ip: Ipv4Addr) -> Result<()> {
        let key: u32 = ip.into();
        self.state.allocated.remove(&key);
        self.persist()
    }

    /// Reconciles the persisted allocation set against `live_owner_ids`
    /// (container ids actually still running, as determined by the
    /// caller — kestrel-net has no visibility into container lifecycle
    /// itself), releasing anything whose owner isn't in that set. Called
    /// on daemon start to recover from a crash mid-lifecycle (an
    /// allocation whose owning container's delete never got to run
    /// `release`). Returns the addresses actually swept.
    pub fn sweep(&mut self, live_owner_ids: &std::collections::HashSet<String>) -> Result<Vec<Ipv4Addr>> {
        let stale: Vec<u32> = self
            .state
            .allocated
            .iter()
            .filter(|(_, owner)| !live_owner_ids.contains(*owner))
            .map(|(k, _)| *k)
            .collect();
        let mut released = Vec::with_capacity(stale.len());
        for key in stale {
            self.state.allocated.remove(&key);
            released.push(Ipv4Addr::from(key));
        }
        if !released.is_empty() {
            self.persist()?;
        }
        Ok(released)
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp_path = self.state_path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(&self.state).context("serializing IPAM state")?;
        fs::write(&tmp_path, &data).with_context(|| format!("writing {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &self.state_path).with_context(|| format!("renaming {} to {}", tmp_path.display(), self.state_path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(dir: &std::path::Path) -> Ipam {
        let subnet: Ipv4Network = "172.31.0.0/29".parse().unwrap(); // small: 8 addrs, easy to exhaust in tests
        let gateway: Ipv4Addr = "172.31.0.1".parse().unwrap();
        Ipam::load(subnet, gateway, dir.join("ipam.json")).unwrap()
    }

    #[test]
    fn test_allocate_skips_network_broadcast_and_gateway() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let a = ipam.allocate("c1").unwrap();
        assert_ne!(a, "172.31.0.0".parse::<Ipv4Addr>().unwrap(), "must not hand out the network address");
        assert_ne!(a, "172.31.0.1".parse::<Ipv4Addr>().unwrap(), "must not hand out the gateway");
        assert_ne!(a, "172.31.0.7".parse::<Ipv4Addr>().unwrap(), "must not hand out the broadcast address");
    }

    #[test]
    fn test_allocate_never_double_allocates() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let mut seen = std::collections::HashSet::new();
        // /29 has 8 addrs minus 3 reserved = 5 allocatable.
        for i in 0..5 {
            let ip = ipam.allocate(&format!("c{i}")).unwrap();
            assert!(seen.insert(ip), "allocate must never hand out the same address twice");
        }
        assert!(ipam.allocate("overflow").is_err(), "must error once the subnet is exhausted");
    }

    #[test]
    fn test_release_frees_address_for_reuse() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let ip = ipam.allocate("c1").unwrap();
        ipam.release(ip).unwrap();
        let ip2 = ipam.allocate("c2").unwrap();
        assert_eq!(ip, ip2, "a released address should become allocatable again");
    }

    #[test]
    fn test_state_persists_across_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ipam.json");
        let subnet: Ipv4Network = "172.31.0.0/29".parse().unwrap();
        let gateway: Ipv4Addr = "172.31.0.1".parse().unwrap();

        let ip = {
            let mut ipam = Ipam::load(subnet, gateway, path.clone()).unwrap();
            ipam.allocate("c1").unwrap()
        };

        let mut reloaded = Ipam::load(subnet, gateway, path).unwrap();
        // The same address must NOT be handed out again to a different
        // owner — proving state genuinely persisted, not just in-memory.
        let mut seen = std::collections::HashSet::new();
        seen.insert(ip);
        for i in 0..4 {
            let next = reloaded.allocate(&format!("d{i}")).unwrap();
            assert!(seen.insert(next), "reloaded state must remember the earlier allocation");
        }
    }

    #[test]
    fn test_sweep_releases_addresses_of_dead_owners_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ipam = fresh(tmp.path());
        let ip_alive = ipam.allocate("alive").unwrap();
        let ip_dead = ipam.allocate("dead").unwrap();

        let mut live = std::collections::HashSet::new();
        live.insert("alive".to_string());

        let released = ipam.sweep(&live).unwrap();
        assert_eq!(released, vec![ip_dead]);

        // The "alive" owner's address must still be allocated (not
        // re-handed-out to someone else).
        let mut seen = std::collections::HashSet::new();
        seen.insert(ip_alive);
        seen.insert(ip_dead); // now free again, expected to be reused
        for i in 0..3 {
            let next = ipam.allocate(&format!("new{i}")).unwrap();
            assert!(!seen.remove(&next) || next == ip_dead, "must not reallocate the still-live address");
        }
    }
}
```

Verify `Ipv4Network::iter()` (used by `allocate`) is real — `ipnetwork`'s `Ipv4Network` implements `IntoIterator`/has an `.iter()` yielding every address in the range including network/broadcast (which `is_reserved` then filters); confirm the exact method/trait name against the real crate docs before trusting this verbatim, and adjust if the iteration API differs (e.g. if it's only available via `IntoIterator for Ipv4Network` rather than a named `.iter()` method).

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod ipam;
```

- [ ] **Step 3: Run**

`cargo test -p kestrel-net ipam::` — expect 5 passed. No root needed, pure logic + tempdir.

## Context

Task 6 of 11. Pure, unprivileged, no networking syscalls at all — just allocation bookkeeping and file persistence. Independent of Tasks 2-5.

## Your Job

1. Verify `Ipv4Network`'s real iteration API.
2. Implement as specified, run the 5 tests, confirm they pass.
3. Self-review the persist-before-return ordering in `allocate` specifically (does a crash between "insert into the in-memory map" and "successfully persist" leave the in-memory allocation visible to a caller who then treats it as durable when it isn't? Trace through: `persist()` is called and its `Result` propagated via `?` BEFORE `allocate` returns `Ok(ip)` — so a persist failure correctly surfaces as an `Err` from `allocate` itself, not a silently-lost allocation. Confirm this is really how the code behaves, not just how it reads.)
4. Do NOT commit/branch/push. Report back.

---

## Task 7: `nat.rs` — iptables-based NAT via two KESTREL-owned chains

**Files:**
- Create: `crates/kestrel-net/src/nat.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/nat_args.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-net/src/nat.rs
//
//! NAT via `iptables`, invoked with argument VECTORS only (never a shell
//! string — no injection surface regardless of what values flow in,
//! though in practice every argument here is internally constructed from
//! IPAM/subnet data, never raw user input).
//!
//! Chain structure (see the design doc's "Chain structure fixes a real
//! teardown-correctness gap" section for the full reasoning): two
//! kestrel-owned custom chains, `KESTREL-POSTROUTING` and
//! `KESTREL-FORWARD`, each linked into its respective built-in chain by
//! exactly one jump rule. Every actual MASQUERADE/hairpin/DNAT/
//! FORWARD-accept rule lives inside these two custom chains, so teardown
//! is an exact flush+delete of two chains plus removal of two short,
//! fixed jump rules — never an argument-identical-matching problem.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use ipnetwork::Ipv4Network;

const POSTROUTING_CHAIN: &str = "KESTREL-POSTROUTING";
const FORWARD_CHAIN: &str = "KESTREL-FORWARD";

fn run_iptables(args: &[&str]) -> Result<std::process::Output> {
    Command::new("iptables").args(args).output().with_context(|| format!("running iptables {args:?}"))
}

fn rule_exists(check_args: &[&str]) -> Result<bool> {
    // `iptables -C` (check) exits 0 if the rule exists, 1 if it doesn't
    // — NOT the same as a real error (a malformed rule spec also exits
    // nonzero, but with a different, more verbose stderr; this function
    // treats any nonzero exit as "doesn't exist" for simplicity, which
    // is safe here because every rule spec this module builds is
    // internally fixed/well-formed).
    let output = Command::new("iptables").arg("-C").args(check_args).output().context("checking rule existence")?;
    Ok(output.status.success())
}

fn ensure_chain_exists(table: &str, chain: &str) -> Result<()> {
    let check = Command::new("iptables").args(["-t", table, "-L", chain, "-n"]).output().context("checking chain existence")?;
    if !check.status.success() {
        let out = run_iptables(&["-t", table, "-N", chain])?;
        ensure!(out.status.success(), "creating chain {chain} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

fn ensure_jump_exists(table: &str, from_chain: &str, to_chain: &str) -> Result<()> {
    let check_args = ["-t", table, from_chain, "-j", to_chain];
    if !rule_exists(&check_args)? {
        let out = run_iptables(&["-t", table, "-A", from_chain, "-j", to_chain])?;
        ensure!(out.status.success(), "linking {from_chain} -> {to_chain} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

/// Sets the two kernel forwarding sysctls this whole feature depends on.
/// `bridge-nf-call-iptables` only exists once `br_netfilter` is loaded —
/// fails loudly with a clear message rather than silently no-op-ing if
/// the path is missing, so a misconfigured host produces an obvious
/// error instead of NAT silently not working.
pub fn enable_forwarding_sysctls() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").context("writing net.ipv4.ip_forward=1")?;
    let br_path = "/proc/sys/net/bridge/bridge-nf-call-iptables";
    std::fs::write(br_path, b"1").with_context(|| {
        format!("writing {br_path}=1 — if this path doesn't exist, the br_netfilter kernel module needs to be loaded first (`modprobe br_netfilter`)")
    })?;
    Ok(())
}

/// Ensures the two KESTREL chains exist and are linked, and that
/// MASQUERADE (egress) is set up for `subnet` via `bridge_name`.
/// Idempotent.
pub fn ensure_masquerade(subnet: Ipv4Network, bridge_name: &str) -> Result<()> {
    ensure_chain_exists("nat", POSTROUTING_CHAIN)?;
    ensure_chain_exists("filter", FORWARD_CHAIN)?;
    ensure_jump_exists("nat", "POSTROUTING", POSTROUTING_CHAIN)?;
    ensure_jump_exists("filter", "FORWARD", FORWARD_CHAIN)?;

    let subnet_str = subnet.to_string();
    let masq_check = ["-t", "nat", POSTROUTING_CHAIN, "-s", &subnet_str, "!", "-o", bridge_name, "-j", "MASQUERADE"];
    if !rule_exists(&masq_check)? {
        let out = run_iptables(&["-t", "nat", "-A", POSTROUTING_CHAIN, "-s", &subnet_str, "!", "-o", bridge_name, "-j", "MASQUERADE"])?;
        ensure!(out.status.success(), "adding egress MASQUERADE failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    let fwd_in = ["-t", "filter", FORWARD_CHAIN, "-i", bridge_name, "!", "-o", bridge_name, "-j", "ACCEPT"];
    if !rule_exists(&fwd_in)? {
        run_iptables(&["-t", "filter", "-A", FORWARD_CHAIN, "-i", bridge_name, "!", "-o", bridge_name, "-j", "ACCEPT"])?;
    }
    let fwd_inter = ["-t", "filter", FORWARD_CHAIN, "-i", bridge_name, "-o", bridge_name, "-j", "ACCEPT"];
    if !rule_exists(&fwd_inter)? {
        run_iptables(&["-t", "filter", "-A", FORWARD_CHAIN, "-i", bridge_name, "-o", bridge_name, "-j", "ACCEPT"])?;
    }
    let fwd_est = ["-t", "filter", FORWARD_CHAIN, "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"];
    if !rule_exists(&fwd_est)? {
        run_iptables(&["-t", "filter", "-A", FORWARD_CHAIN, "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
    }

    Ok(())
}

/// DNAT for one published port: host `host_port` (tcp) -> `container_ip:container_port`,
/// plus the hairpin MASQUERADE rule so the container can reach its own
/// published port via the host/bridge address.
pub fn add_dnat(host_port: u16, container_ip: Ipv4Addr, container_port: u16) -> Result<()> {
    let dest = format!("{container_ip}:{container_port}");
    let host_port_s = host_port.to_string();
    let dnat_args = ["-t", "nat", POSTROUTING_CHAIN, "-p", "tcp", "--dport", &host_port_s, "-j", "DNAT", "--to-destination", &dest];
    if !rule_exists(&dnat_args)? {
        // DNAT rules belong logically with PREROUTING (external
        // traffic), but SPEC.md's own example DNATs from a custom chain
        // reached via PREROUTING in real Docker-equivalent setups;
        // verify during implementation whether this project's DNAT rule
        // should link from KESTREL-POSTROUTING (as drafted, for hairpin
        // NAT's sake — traffic FROM the host to a published port is
        // "postrouting" relative to the host's own loopback/bridge path)
        // or needs its own KESTREL-PREROUTING chain reached from
        // PREROUTING (for traffic arriving from a genuinely external
        // interface) — SPEC.md §11.3 doesn't fully disambiguate which
        // chain real inbound (non-hairpin) published-port traffic needs,
        // and this is exactly the kind of thing to verify against a real
        // `curl localhost:<port>`-from-outside-the-VM test (Task 10's
        // `test_published_port`) rather than assume. If a
        // KESTREL-PREROUTING chain turns out to be needed, add it
        // following the exact same pattern as the other two.
        let out = run_iptables(&["-t", "nat", "-A", POSTROUTING_CHAIN, "-p", "tcp", "--dport", &host_port_s, "-j", "DNAT", "--to-destination", &dest])?;
        ensure!(out.status.success(), "adding DNAT rule failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub fn remove_dnat(host_port: u16, container_ip: Ipv4Addr, container_port: u16) -> Result<()> {
    let dest = format!("{container_ip}:{container_port}");
    let host_port_s = host_port.to_string();
    let args = ["-t", "nat", "-D", POSTROUTING_CHAIN, "-p", "tcp", "--dport", &host_port_s, "-j", "DNAT", "--to-destination", &dest];
    let out = run_iptables(&args)?;
    // Deleting a rule that's already gone is fine (matches this
    // project's "already gone is success" release idiom) — iptables -D
    // on a missing rule exits nonzero, which this treats as a no-op
    // rather than an error.
    let _ = out;
    Ok(())
}

/// Full teardown for one container's NAT state (the DNAT rules for its
/// published ports — the shared MASQUERADE/FORWARD rules in the two
/// KESTREL chains stay, since other containers still need them; only a
/// full daemon-level `teardown_all` removes the chains themselves).
pub fn teardown_network_nat(_id: &str) -> Result<()> {
    // Per-container DNAT removal is the caller's responsibility (it
    // knows which ports THIS container published) via remove_dnat, one
    // call per port — this function exists as the named entrypoint
    // bridge.rs's teardown_bridge_network calls, completed in Task 8
    // once the caller-side port bookkeeping (which lives in modes.rs /
    // container metadata, not nat.rs) is available to iterate over.
    Ok(())
}

/// Full daemon-level teardown: flush and delete both KESTREL chains and
/// their jump-rule links. Only called on daemon shutdown / explicit
/// network reset, never per-container.
pub fn teardown_all(bridge_name: &str) -> Result<()> {
    let _ = bridge_name;
    for (table, chain, built_in) in [("nat", POSTROUTING_CHAIN, "POSTROUTING"), ("filter", FORWARD_CHAIN, "FORWARD")] {
        let _ = run_iptables(&["-t", table, "-D", built_in, "-j", chain]);
        let _ = run_iptables(&["-t", table, "-F", chain]);
        let _ = run_iptables(&["-t", table, "-X", chain]);
    }
    Ok(())
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod nat;
```

- [ ] **Step 3: Deterministic argument-construction tests**

```rust
// crates/kestrel-net/tests/nat_args.rs
//
// These test the ARGUMENT-BUILDING logic without invoking the real
// iptables binary (no root needed) — refactor nat.rs if needed so the
// argument-vector-construction pieces are separately testable pure
// functions, rather than baked inline into functions that immediately
// invoke Command. During implementation, extract e.g.
// `masquerade_rule_args(subnet, bridge_name) -> Vec<String>` and similar
// helpers that `ensure_masquerade`/`add_dnat` call, so tests can assert
// on the exact argument vectors built without needing root or a real
// iptables binary.
```

Write the real test bodies during implementation, after refactoring `nat.rs` as described in the comment above — the plan intentionally doesn't hand you exact argument-vector assertions here, because the right refactor (which functions get extracted as pure argument-builders) is an implementation-time judgment call the plan shouldn't pre-decide.

- [ ] **Step 4: Run**

`cargo test -p kestrel-net --test nat_args` (no root). Separately, note that `ensure_masquerade`/`add_dnat`/`teardown_all`'s actual iptables-invoking behavior is only exercised for real by Task 10's root-gated capstone suite — no isolated root-gated test for `nat.rs` alone is required by this task, since NAT rules are meaningless without a real bridge+subnet context Task 10 already provides.

## Context

Task 7 of 11. Independent of Tasks 2-5 (doesn't touch namespaces or rtnetlink at all — pure `Command` invocation). Depends only on Task 1's dependency setup. One real open question is flagged inline (`add_dnat`'s chain placement) rather than guessed — resolve it for real against `test_published_port` in Task 10, not here in isolation.

## Your Job

1. Implement as specified.
2. Refactor for testability as the Step 3 comment describes, then write real deterministic tests for the argument-construction logic.
3. Confirm the deterministic tests pass with zero root/iptables dependency.
4. Note (don't resolve yet) the `add_dnat` chain-placement question for Task 10's implementer to verify against a real published-port test.
5. Do NOT commit/branch/push. Report back.

---

## Task 8: `modes.rs` + `hosts.rs` — mode dispatch, `container:<id>` validation, `/etc/hosts` generation, completing `teardown_bridge_network`

**Files:**
- Create: `crates/kestrel-net/src/modes.rs`
- Create: `crates/kestrel-net/src/hosts.rs`
- Modify: `crates/kestrel-net/src/bridge.rs` (complete `teardown_bridge_network`)
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/hosts.rs`

- [ ] **Step 1: `modes.rs`**

```rust
// crates/kestrel-net/src/modes.rs

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Result};
use ipnetwork::Ipv4Network;

#[derive(Debug, Clone)]
pub enum NetworkConfig {
    Bridge { bridge_name: String, gateway: Ipv4Addr, subnet: Ipv4Network, published: Vec<(u16, u16)> },
    Host,
    None,
    Container(String),
}

/// A container's OWN recorded network mode — the minimal information
/// `resolve_container_mode` needs to enforce the one-hop-only rule from
/// the design doc. In this phase, callers (tests, later Phase 8 wiring)
/// supply this directly; a real "look up container X's mode" store is
/// Phase 8/9's daemon-state concern, out of scope here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeKind {
    Bridge,
    Host,
    None,
    Container,
}

/// Validates a `container:<id>` reference against the referenced
/// container's OWN mode, per the design doc's one-hop-only rule.
/// Returns the netns pin path to join if valid.
pub fn resolve_container_mode(run_dir: &Path, referenced_id: &str, referenced_mode: ModeKind) -> Result<std::path::PathBuf> {
    match referenced_mode {
        ModeKind::Bridge | ModeKind::None => Ok(run_dir.join("netns").join(referenced_id)),
        ModeKind::Host => bail!("cannot join network of container {referenced_id}: it has no network namespace (mode=host)"),
        ModeKind::Container => bail!(
            "cannot join network of container {referenced_id}: it is itself in container:<id> mode \
             (chained container-network references are not supported — reference the ultimate owner directly)"
        ),
    }
}
```

- [ ] **Step 2: `hosts.rs`**

```rust
// crates/kestrel-net/src/hosts.rs

use std::net::Ipv4Addr;

/// Generates `/etc/hosts` content: loopback entries, the container's own
/// hostname/IP, plus any extra caller-supplied entries.
pub fn generate_hosts(hostname: &str, container_ip: Option<Ipv4Addr>, extra: &[(Ipv4Addr, String)]) -> String {
    let mut out = String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some(ip) = container_ip {
        out.push_str(&format!("{ip}\t{hostname}\n"));
    }
    for (ip, name) in extra {
        out.push_str(&format!("{ip}\t{name}\n"));
    }
    out
}

pub fn generate_hostname(hostname: &str) -> String {
    format!("{hostname}\n")
}

/// `dns_ip` is the bridge gateway when the embedded resolver is active;
/// `None` means fall back to copying the host's real resolv.conf
/// (host/none modes) — the caller passes the already-read host content
/// in that case rather than this function re-reading `/etc/resolv.conf`
/// itself (keeping this function pure/testable).
pub fn generate_resolv_conf(dns_ip: Option<Ipv4Addr>, host_resolv_conf: &str) -> String {
    match dns_ip {
        Some(ip) => format!("nameserver {ip}\n"),
        None => host_resolv_conf.to_string(),
    }
}
```

- [ ] **Step 3: Tests**

```rust
// crates/kestrel-net/tests/hosts.rs

use std::net::Ipv4Addr;

use kestrel_net::hosts::{generate_hostname, generate_hosts, generate_resolv_conf};

#[test]
fn test_generate_hosts_includes_loopback_and_container_entry() {
    let ip: Ipv4Addr = "172.29.0.5".parse().unwrap();
    let out = generate_hosts("my-container", Some(ip), &[]);
    assert!(out.contains("127.0.0.1\tlocalhost"));
    assert!(out.contains("172.29.0.5\tmy-container"));
}

#[test]
fn test_generate_hosts_includes_extra_entries() {
    let extra_ip: Ipv4Addr = "172.29.0.9".parse().unwrap();
    let out = generate_hosts("c", None, &[(extra_ip, "sibling".to_string())]);
    assert!(out.contains("172.29.0.9\tsibling"));
}

#[test]
fn test_generate_hostname() {
    assert_eq!(generate_hostname("foo"), "foo\n");
}

#[test]
fn test_generate_resolv_conf_uses_embedded_dns_when_present() {
    let dns_ip: Ipv4Addr = "172.29.0.1".parse().unwrap();
    let out = generate_resolv_conf(Some(dns_ip), "nameserver 8.8.8.8\n");
    assert_eq!(out, "nameserver 172.29.0.1\n");
}

#[test]
fn test_generate_resolv_conf_falls_back_to_host_content() {
    let out = generate_resolv_conf(None, "nameserver 8.8.8.8\n");
    assert_eq!(out, "nameserver 8.8.8.8\n");
}
```

- [ ] **Step 4: Complete `bridge.rs`'s `teardown_bridge_network`**

```rust
// Replaces the Task 4 stub in crates/kestrel-net/src/bridge.rs

pub async fn teardown_bridge_network(
    handle: &rtnetlink::Handle,
    run_dir: &std::path::Path,
    id: &str,
    ipam: &mut crate::ipam::Ipam,
    container_ip: std::net::Ipv4Addr,
    published_ports: &[(u16, u16)],
) -> anyhow::Result<()> {
    // Host-side veth link deletion: deleting the host end also removes
    // the peer (a veth pair is one link with two ends — the kernel tears
    // down both together), so no separate in-netns deletion is needed.
    let host_if = format!("veth{}", &id[..id.len().min(8)]);
    if let Some(idx) = crate::bridge::find_link_index(handle, &host_if).await? {
        handle.link().del(idx).execute().await.with_context(|| format!("deleting {host_if}"))?;
    }

    for (host_port, container_port) in published_ports {
        crate::nat::remove_dnat(*host_port, container_ip, *container_port)?;
    }

    ipam.release(container_ip)?;
    crate::netns::teardown_netns(run_dir, id)?;
    Ok(())
}
```

Add `use anyhow::Context;` to `bridge.rs`'s imports if not already present.

- [ ] **Step 5: Wire into lib.rs**

```rust
pub mod modes;
pub mod hosts;
```

- [ ] **Step 6: Run**

`cargo test -p kestrel-net modes:: hosts::` and `cargo test -p kestrel-net --test hosts` — expect all passing, no root needed for any of this task's tests.

## Context

Task 8 of 11. Completes the composed teardown entrypoint Task 4 stubbed out, now that `ipam.rs` (Task 6) and `nat.rs` (Task 7) both exist. Implements the design doc's one-hop-only `container:<id>` validation rule as real, tested code (not just prose).

## Your Job

1. Implement `modes.rs`, `hosts.rs`, and the completed `teardown_bridge_network` exactly as specified.
2. Write and run the 5 `hosts.rs` tests plus reasonable inline tests for `resolve_container_mode`'s three branches (Bridge/None succeed with the expected path, Host errors, Container errors) — write these as inline `#[cfg(test)]` tests in `modes.rs` itself, following this crate's established pattern from `ipam.rs`.
3. Confirm everything compiles and passes with zero root dependency.
4. Do NOT commit/branch/push. Report back.

---

## Task 9: `dns.rs` — minimal embedded UDP resolver

**Files:**
- Create: `crates/kestrel-net/src/dns.rs`
- Modify: `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-net/tests/dns.rs`

- [ ] **Step 1: Implement**

A minimal, hand-rolled DNS message parser/writer for A-record queries only — deliberately not pulling in a full DNS crate, matching the design doc's "kept intentionally minimal" framing for this 🟡 item. The DNS wire format for a simple A-record query/response is well-documented (RFC 1035 §4) and small enough to hand-roll correctly, but **verify your parsing/serialization against a real query** (e.g. `dig`/`nslookup` from inside the VM against your running test server) rather than trusting a from-memory implementation of the header/question/answer section byte layout — get this wrong and every query silently fails or the resolver never responds, which is a real, easy-to-get-subtly-wrong parsing task.

```rust
// crates/kestrel-net/src/dns.rs
//
//! A minimal, best-effort DNS resolver for container-name lookups,
//! bound to the bridge gateway IP. Handles A-record queries only:
//! resolves a name against the IPAM allocation records passed in,
//! returns NXDOMAIN for anything unrecognized (or forwards upstream to
//! the host's real resolver if `upstream` is configured). No caching, no
//! recursion — deliberately minimal, matching this item's 🟡
//! (best-effort) status.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Name -> IP records this resolver answers from, kept in sync by
/// whatever owns IPAM allocation (kestrel-net doesn't itself own
/// container-name bookkeeping — that's a caller/daemon concern; this
/// type is just what dns::serve reads from).
pub type NameRecords = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

/// Runs the resolver until the socket errors or the process is killed —
/// intentionally has no built-in shutdown signal parameter; the caller
/// (whoever `tokio::spawn`s this, per the design doc's runtime-ownership
/// note) is responsible for aborting the resulting `JoinHandle` if a
/// clean shutdown is needed, rather than this function growing its own
/// signal-handling surface.
pub async fn serve(bind_ip: Ipv4Addr, records: NameRecords, upstream: Option<SocketAddr>) -> Result<()> {
    let socket = UdpSocket::bind((bind_ip, 53)).await?;
    let mut buf = [0u8; 512]; // DNS-over-UDP's classic (pre-EDNS0) size cap; sufficient for this resolver's minimal record set

    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        if let Some(response) = handle_query(&buf[..len], &records, upstream).await {
            let _ = socket.send_to(&response, from).await;
        }
    }
}

/// Parses a query, looks up (or forwards) an answer, builds a response.
/// Returns `None` if the query is too malformed to even parse a
/// transaction ID out of (nothing sensible to respond with in that
/// case).
async fn handle_query(query: &[u8], records: &NameRecords, upstream: Option<SocketAddr>) -> Option<Vec<u8>> {
    let parsed = parse_query(query)?;
    let ip = records.read().await.get(&parsed.name).copied();
    match ip {
        Some(ip) => Some(build_a_response(&parsed, ip)),
        None => match upstream {
            Some(_addr) => {
                // Forwarding: send `query` as-is to `_addr`, relay its
                // response back verbatim. Implement as a real UDP
                // round-trip during this task (a fresh short-lived
                // socket per forwarded query is fine for this minimal
                // resolver — no connection pooling needed). Flagged
                // as needing real implementation rather than sketched
                // further here, since exact timeout/retry behavior is
                // an implementation-time judgment call.
                None
            }
            None => Some(build_nxdomain_response(&parsed)),
        },
    }
}

struct ParsedQuery {
    id: u16,
    name: String,
    /// The raw question section bytes, needed verbatim to build a
    /// spec-compliant response (the question section is echoed back in
    /// the answer).
    question_bytes: Vec<u8>,
}

fn parse_query(query: &[u8]) -> Option<ParsedQuery> {
    // DNS header is 12 bytes: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2)
    // NSCOUNT(2) ARCOUNT(2).
    if query.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }

    // Question section starts at byte 12: a sequence of length-prefixed
    // labels terminated by a zero-length label, then QTYPE(2) QCLASS(2).
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        let label = query.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    let question_end = pos + 4; // QTYPE + QCLASS
    if query.len() < question_end {
        return None;
    }
    let question_bytes = query[12..question_end].to_vec();
    let name = labels.join(".");

    Some(ParsedQuery { id, name, question_bytes })
}

fn build_a_response(q: &ParsedQuery, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available, no error
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&q.question_bytes[..q.question_bytes.len() - 4]); // name labels (re-derive from q.question_bytes minus QTYPE/QCLASS is wrong if labels aren't re-extractable this way — see note below)
    // NOTE: this line is almost certainly wrong as drafted (it slices
    // question_bytes assuming the last 4 bytes are exactly QTYPE+QCLASS
    // and everything before is the name — actually correct given how
    // question_bytes was captured in parse_query, but re-verify this
    // indexing carefully against a real captured query byte-for-byte
    // during implementation rather than trusting this comment's own
    // reasoning).
    out.extend_from_slice(&q.question_bytes); // QTYPE + QCLASS repeated in the answer's fixed fields below is WRONG — replace with proper answer-section encoding: NAME (as a pointer 0xC0 0x0C back to the question's name), TYPE=A(1), CLASS=IN(1), TTL, RDLENGTH=4, RDATA=ip.octets(). Rewrite this whole function for real correctness during implementation; the sketch above is intentionally left rough to flag that this needs careful, verified-against-a-real-query implementation, not a copy-paste.
    out.extend_from_slice(&ip.octets());
    out
}

fn build_nxdomain_response(q: &ParsedQuery) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&[0x81, 0x83]); // flags: response, recursion available, NXDOMAIN (rcode 3)
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&q.question_bytes);
    out
}
```

**This task's `build_a_response` is deliberately left rough/flagged, not polished** — matching this plan's established discipline (Phase 6's Task 8 did the same for `hash_and_copy`) of flagging genuinely uncertain wire-format/API code rather than presenting unverified guesses as finished. The real fix: encode the answer section properly — `NAME` as a compressed pointer (`0xC0 0x0C`, pointing back to the question's name at offset 12) rather than repeating the label bytes, then `TYPE` (2 bytes, `0x0001` for A), `CLASS` (2 bytes, `0x0001` for IN), `TTL` (4 bytes, e.g. `60`), `RDLENGTH` (2 bytes, `0x0004`), `RDATA` (4 bytes, the IP octets) — and get this right by testing against a REAL `dig`/`nslookup` client, not just unit-testing your own parser against your own serializer (which could have symmetric bugs that cancel out and never get caught).

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod dns;
```

- [ ] **Step 3: Tests**

```rust
// crates/kestrel-net/tests/dns.rs
//
// Root-gated only because it binds port 53 (privileged) — bind to a
// high port instead for testing (serve() takes bind_ip only, not a
// fixed port 53 in a test-friendly variant, OR add a bind_port parameter
// — reconsider serve()'s signature during implementation to make it
// testable on an unprivileged port; the plan's Step 1 draft hardcodes
// port 53 for the production path, but the test suite needs a way
// around that without requiring root just to run a resolver unit test).
```

Write the real test bodies during implementation: start `serve()` on a test-friendly bind (loopback + high port), use a real UDP socket (or, ideally, the actual `dig`/`nslookup` binary via `std::process::Command` if present in the VM, since that's the strongest possible proof the wire format is genuinely correct — not just internally consistent) to query it for a known name, assert the returned IP matches, and a second query for an unknown name gets NXDOMAIN.

- [ ] **Step 4: Run**

`cargo test -p kestrel-net --test dns` inside the VM (root not required once `serve` supports a non-privileged test bind port).

## Context

Task 9 of 11. The one task in this phase with a real "hand-rolled wire-format parsing, verify against a real client" risk, flagged explicitly rather than shipped as an unverified guess. Independent of Tasks 2-8 except Task 1's dependency setup — `dns.rs` doesn't touch namespaces, rtnetlink, or iptables at all.

## Your Job

1. Make `serve()` testable on a non-privileged port (reconsider its signature).
2. Fix `build_a_response`'s answer-section encoding for real, verified correctness — implement the compressed-name-pointer format properly, don't ship the rough sketch above as-is.
3. Implement DNS forwarding (`handle_query`'s `Some(_addr)` branch) as a real UDP round-trip with a reasonable timeout.
4. Write and run tests, and additionally verify manually against a real `dig`/`nslookup` client inside the VM if available — report whether you did this and what you observed, since it's the strongest evidence the wire format is really correct.
5. Do NOT commit/branch/push. Report back.

---

## Task 10: Root-gated capstone test suite — the 5 required scenarios + host mode + `container:<id>`

**Files:**
- Create: `crates/kestrel-net/tests/common/mod.rs` (if not already created during Task 4)
- Create: `crates/kestrel-net/tests/lifecycle.rs`

- [ ] **Step 1: Implement**

Compose every module built in Tasks 1-9 into the CHECKLIST-required test scenarios, run inside `kestrel-net`'s own `tests/common/mod.rs` netns-isolation helper (Task 4) so none of this ever touches the VM's real network state:

1. `test_none_mode_only_lo` — `create_netns` + bring `lo` up inside it (no veth/bridge at all) + `nsenter` in and assert exactly one interface exists via `rtnetlink`'s link-list query.
2. `test_bridge_egress` — full `ensure_bridge` + `create_netns` + `attach_veth` + `ensure_masquerade` + `enable_forwarding_sysctls`, then from inside the container netns, a real TCP/ICMP reach to an external address (the VM already has real network access, confirmed during Phase 6's capstone test — reuse that same confidence; an HTTP HEAD request to a stable public host, or a raw ICMP ping if `nix`/permissions allow, whichever is more reliable to assert on in a test).
3. `test_inter_container` — two containers attached to the same bridge, one pings/connects to the other's bridge-assigned IP directly.
4. `test_published_port` — full `add_dnat` for one port, then a `curl`-equivalent (a real TCP connect + HTTP request, via `std::net::TcpStream` or similar, not shelling out) from the test's OWN (isolated, but NOT the container's) netns to `localhost:<hostport>`, reaching a listener running inside the container. **This is where Task 7's flagged `add_dnat` chain-placement question gets resolved for real** — if the drafted `KESTREL-POSTROUTING`-based DNAT doesn't actually work for this scenario, fix `nat.rs` here (adding a `KESTREL-PREROUTING` chain per Task 7's own flagged fallback) rather than working around it in the test.
5. `test_teardown_leaves_no_rules` — snapshot `ip link`/`ip addr` (via rtnetlink queries, not shelling out) and `iptables-save`-equivalent state (via `iptables -t nat -S`/`iptables -t filter -S` output, since there's no pure-Rust need to shell out for a one-time diagnostic read) before any setup, run a full bridge-mode container lifecycle (setup via every module above, then `teardown_bridge_network` + `nat::teardown_all`), snapshot again, assert byte-for-byte (or semantically, if ordering isn't guaranteed) identical.
6. `test_host_mode_shares_host_stack` — per the design doc's addition: assert a process under `Host` mode (i.e., explicitly skipping `create_netns` entirely) sees the same interface list as its own outer isolated-test netns (proving `Host` mode is a genuine, verified no-op at this layer, not just "recognized").
7. `test_container_mode_shares_netns` — the capstone: container A gets full bridge-mode setup; container B is set up via `resolve_container_mode`'s validated path into A's pinned netns (no new netns/veth of its own); a listener started "in A" (i.e., via `nsenter` into A's pin) is reachable from "B" (`nsenter` into the SAME pin, since B has no separate one) — proving shared-netns pod semantics actually work end to end, not just that resolution returns a path without erroring.
8. `test_container_mode_rejects_host_and_chained_references` — two quick negative-path tests: `resolve_container_mode` with `ModeKind::Host` and with `ModeKind::Container` both return `Err` (this doesn't need real networking, could be a plain unit test in `modes.rs` instead if not already covered by Task 8 — check before duplicating).

- [ ] **Step 2: Run**

`make test-root` (sweeps all `#[ignore]`d tests workspace-wide) or targeted `sudo -E cargo test -p kestrel-net --test lifecycle -- --ignored --nocapture` inside the VM. Confirm all scenarios pass.

## Context

Task 10 of 11. The composing capstone for the whole phase — every module from Tasks 2-9 gets exercised together for the first time. This is also where two explicitly-flagged open questions from earlier tasks (Task 5's nested-runtime-inside-block_in_place soundness, Task 7's DNAT chain placement) get their final real-world confirmation or fix.

## Your Job

1. Write all 8 scenarios (7 substantive + 1 possible-duplicate-check) with real, specific assertions — no scenario should merely check "no error," per this project's established "before/after diff, not just happy path" rigor.
2. Resolve Task 7's flagged DNAT chain-placement question for real via `test_published_port`; fix `nat.rs` if needed.
3. Run the full suite, confirm every scenario passes with zero residue in the VM's real (outer) network state.
4. Self-review: does `test_teardown_leaves_no_rules` actually prove what it claims, or could a subtle ordering difference in `iptables -S` output between two otherwise-identical states cause a false failure (or worse, a false pass if the diff logic is too loose)? Be specific about how you compared the before/after snapshots.
5. Do NOT commit/branch/push. Report back.

---

## Task 11: Workspace-wide verification and cleanup

**Files:** none new — verification only, plus the Makefile note.

- [ ] **Step 1:** `cargo build --workspace` — clean.
- [ ] **Step 2:** `cargo test --workspace` — all non-`#[ignore]`d tests pass (including `kestrel-ns`'s new `with_namespace` unit-testable pieces, if any exist outside the root-gated tests).
- [ ] **Step 3:** `make test-root` — every root-gated test passes, including every `kestrel-net` and the new `kestrel-ns` `with_namespace` test.
- [ ] **Step 4:** `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] **Step 5:** `make check-no-tokio` — still passes; confirm it correctly ignores `kestrel-net`'s new tokio dependency (same reasoning as Phase 6's equivalent check — re-verify, don't just assume the guard script's scope hasn't changed).
- [ ] **Step 6:** Grep for `todo!()`/`unimplemented!()` in `crates/kestrel-net` and `crates/kestrel-ns` — zero matches expected (Task 9's dns.rs answer-encoding placeholder and Task 1's `netns-helper` placeholder must both be fully resolved by now).
- [ ] **Step 7:** Sweep for leftover network state: run the full root-gated suite once more, then from a plain VM shell (not inside any test's isolated netns) check `ip link`, `ip addr`, `iptables -t nat -S`, `iptables -t filter -S` for any `kbr-test0`/`veth*`/`KESTREL-*`/test-created residue.
- [ ] **Step 8:** Update the Makefile's top-of-file NOTE comment to mention `kestrel-net` needs `iptables` present in the VM (already true — confirm via `which iptables` inside the VM rather than assuming) and that its root-gated tests manipulate real bridges/veths/iptables rules, fully isolated per-test via `unshare(CLONE_NEWNET)` (same reasoning already documented for the mount-namespace isolation pattern used since Phase 4).

## Self-Review Notes

**Spec coverage:** CHECKLIST's Phase 7 items map to: netns create/pin/teardown/nsenter → Tasks 2-3. Bridge/veth via rtnetlink, fd-based netns move, deterministic MAC → Tasks 4-5. IPAM bitmap/persist/reserve/release/sweep → Task 6. NAT sysctls/MASQUERADE/DNAT/hairpin/FORWARD/idempotent-add/complete-teardown → Task 7 (+ Task 10's real-world DNAT placement fix). Modes + `/etc/hosts`/hostname/resolv.conf → Task 8. Embedded DNS → Task 9. All 5 required tests + the two bonus scenarios (host mode, container:<id>) → Task 10. Rootless pasta/slirp4netns is the one CHECKLIST 🟡 item genuinely NOT covered by this plan — consistent with the design doc's explicit, reasoned deferral, not an oversight.

**Placeholder scan:** three intentional, explicitly-flagged-and-must-be-resolved markers exist in this plan's draft code — Task 5's nested-runtime-soundness question, Task 7's DNAT chain-placement question (resolved for real in Task 10), and Task 9's `build_a_response` answer-section encoding (must be fixed for real, verified against a real DNS client, not shipped as drafted) — the same "flag what's genuinely uncertain, verify for real during implementation" discipline every prior phase's plan has used for its hardest API-uncertainty spots.

**Type/signature consistency:** `create_netns(run_dir, id) -> Result<PathBuf>` (Task 3) is the signature `attach_veth` (Task 5), `resolve_container_mode` (Task 8), and the capstone tests (Task 10) all consume consistently. `Ipam::allocate/release/sweep` (Task 6) signatures match how `teardown_bridge_network` (Task 8) and the capstone tests use them. `nsenter`'s `block_in_place`-required contract (Task 3) is honored consistently everywhere it's called (Tasks 5, 10) — verify this explicitly during Task 10's self-review, since a missed `block_in_place` wrapper somewhere would be a subtle, hard-to-notice correctness bug rather than a compile error.
