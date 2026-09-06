# Kestrel Phase 2 (Namespaces) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-ns` — the three-stage fork/unshare dance creating all 8 Linux namespaces in the correct order, CVE-2014-8989-safe id-map writing, namespace pinning/joining for `kestrel exec`, and rootless subuid/subgid support — fully tested inside the Lima VM.

**Architecture:** A `run_isolated()` test helper forks each namespace-touching test into its own single-threaded child process (required because `unshare(CLONE_NEWUSER)` fails with `EINVAL` if the calling *process* is multithreaded, and `cargo test`'s harness is). `run_stages()`'s stage2 is parameterized by a `child_action: impl FnOnce() -> !` closure rather than hardcoding a not-yet-built exec pipeline, since Phase 4 (rootfs)/Phase 8 (runtime binary) don't exist yet — later phases pass a real closure, this phase's tests pass small inline closures that make assertions observable from the parent side.

**Tech Stack:** Rust, `nix` 0.29 (`process`, `sched`, `socket`, `mount`, `fs`, `user` features), `serde`/`serde_json` for the sync-socket wire format, `libc`, `thiserror`/`anyhow`.

**Environment:** All of this runs inside the Lima VM (`kestrel`, Ubuntu 24.04, kernel 6.8). From the host: `limactl shell kestrel -- bash -lc 'cd Container-Runtime && <command>'`. Inside the VM, `cargo`/`rustc` are at `~/.cargo/bin` (already on `PATH` via the login shell). Most tests run unprivileged (`cargo test -p kestrel-ns`); a subset needs real root (`sudo -E cargo test -p kestrel-ns -- --ignored`) — each task says which.

---

## File Structure

```
crates/kestrel-ns/
├── Cargo.toml                       # Task 1
└── src/
    ├── lib.rs                       # Task 1: module decls + re-exports; Task 2: test_util
    ├── threading.rs                 # Task 2: assert_single_threaded (moved from kestrel-runtime)
    ├── types.rs                     # Task 3: NsType; Task 4: IdMapping, NamespacePlan
    ├── sync.rs                      # Task 5: Sync enum + send/recv
    ├── idmap.rs                     # Task 6: write_id_maps, render_map
    ├── inode.rs                     # Task 7: read_ns_inode
    ├── stages.rs                    # Task 8: run_stages, stage0, stage1
    ├── pin.rs                       # Task 9: pin_namespace, unpin_namespace
    ├── join.rs                      # Task 10: join_namespaces
    └── rootless.rs                  # Task 11: subuid/subgid parsing
crates/kestrel-ns/tests/
├── dance.rs                         # Task 8: integration tests for run_stages
├── pin.rs                           # Task 9: integration tests (root-gated)
└── join.rs                          # Task 10: integration tests (root-gated)
crates/kestrel-runtime/
├── Cargo.toml                       # Task 2: += kestrel-ns dependency
└── src/preflight.rs                 # Task 2: re-export assert_single_threaded
Makefile                             # Task 12: real test-root target
```

---

## Task 1: Crate scaffolding + `run_isolated` test helper

**Files:**
- Modify: `crates/kestrel-ns/Cargo.toml`
- Modify: `crates/kestrel-ns/src/lib.rs`
- Create: `crates/kestrel-ns/src/types.rs`, `sync.rs`, `idmap.rs`, `inode.rs`, `stages.rs`, `pin.rs`, `join.rs`, `rootless.rs` (empty placeholders, filled by later tasks)

`kestrel-ns` currently exists as a Phase-0 stub (`Cargo.toml` with only `anyhow`/`thiserror`, `lib.rs` with a doc comment). This task wires the real dependencies and module tree.

- [ ] **Step 1: Update `Cargo.toml`**

```toml
[package]
name = "kestrel-ns"
edition.workspace = true
version.workspace = true

[dependencies]
nix = { workspace = true, features = ["process", "sched", "socket", "mount", "fs", "user"] }
libc.workspace = true
anyhow.workspace = true
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
```

If `cargo build -p kestrel-ns` reports a feature name doesn't exist in the installed `nix` 0.29 (feature names have shifted between nix releases in the past), check `cargo doc -p nix --no-deps` or `~/.cargo/registry/src/*/nix-0.29.*/Cargo.toml`'s `[features]` table and correct the list — preserve intent (fork/waitpid needs `process`, unshare/setns needs `sched`, socketpair needs `socket`, mount/umount2 needs `mount`).

- [ ] **Step 2: Update `lib.rs`**

```rust
//! Namespace creation, id-map writing, pinning, and setns ordering for
//! kestrel. See docs/superpowers/specs/2026-07-31-phase2-namespaces-design.md.

pub mod threading;
pub mod types;
pub mod sync;
pub mod idmap;
pub mod inode;
pub mod stages;
pub mod pin;
pub mod join;
pub mod rootless;

/// Fork-based test isolation. Not `#[cfg(test)]`-gated because
/// `tests/*.rs` integration test binaries compile against the crate's
/// normal public API, not its unit-test cfg — see Task 1 of
/// docs/superpowers/plans/2026-08-01-phase2-namespaces.md for why. Intended
/// for test code only; not part of the crate's operational surface.
pub mod test_util {
    use std::panic;

    /// Forks the calling process and runs `f` in the child. `unshare` with
    /// `CLONE_NEWUSER` fails with EINVAL if the calling PROCESS is
    /// multithreaded, and cargo test's harness always is (it spawns a
    /// thread per test) — forking guarantees the child starts with exactly
    /// one thread regardless of the parent's thread count, so anything that
    /// needs single-threadedness must run inside this closure, not directly
    /// in a `#[test]` fn. Panics in the parent if the child's exit code is
    /// nonzero; a panic inside `f` itself is caught, printed (via the
    /// default panic hook, before `catch_unwind` returns), and mapped to
    /// exit code 101 so it still fails the parent-side assertion.
    pub fn run_isolated<F: FnOnce() + panic::UnwindSafe>(f: F) {
        match unsafe { nix::unistd::fork() }.expect("fork failed") {
            nix::unistd::ForkResult::Child => {
                let result = panic::catch_unwind(f);
                let code = if result.is_ok() { 0 } else { 101 };
                unsafe { libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid failed");
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 0) => {}
                    other => panic!("isolated test child failed: {other:?}"),
                }
            }
        }
    }
}
```

- [ ] **Step 3: Create the 8 empty module files**

Each gets a one-line placeholder, e.g. `crates/kestrel-ns/src/types.rs`:
```rust
// filled in by Task 3
```
Same pattern for `sync.rs` ("Task 5"), `idmap.rs` ("Task 6"), `inode.rs` ("Task 7"), `stages.rs` ("Task 8"), `pin.rs` ("Task 9"), `join.rs` ("Task 10"), `rootless.rs` ("Task 11"). `threading.rs` is filled by Task 2 (next), so leave it as `// filled in by Task 2`.

- [ ] **Step 4: Verify it compiles**

Inside the VM: `cargo build -p kestrel-ns`. Expected: `Finished` (fails to compile until `threading.rs` exists — that's Task 2, immediately next; if executing tasks in order, don't block here, just confirm no *other* errors).

- [ ] **Step 5: Mark task complete**

No git (per this project's established convention — see Phase 0/1's plan for why).

---

## Task 2: Move `assert_single_threaded` to `kestrel-ns`

**Files:**
- Create content in: `crates/kestrel-ns/src/threading.rs`
- Modify: `crates/kestrel-runtime/Cargo.toml` (add `kestrel-ns` dependency)
- Modify: `crates/kestrel-runtime/src/preflight.rs` (replace the local impl with a re-export)

Phase 0 put `assert_single_threaded()` in `kestrel-runtime` because that was the only crate that existed with a real invariant to check. But the invariant belongs to `kestrel-ns` now — `run_stages()` needs to call it, and `kestrel-runtime` depends on `kestrel-ns` (not the other way around), so the canonical copy has to live in `kestrel-ns`. `kestrel-runtime`'s `preflight.rs` becomes a thin re-export so its existing call site (`preflight::assert_single_threaded()` in `main.rs`) keeps working unchanged.

- [ ] **Step 1: Write the failing tests in the new location**

```rust
// crates/kestrel-ns/src/threading.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_thread_count() {
        let status = "Name:\tfoo\nThreads:\t3\nVmSize:\t1024 kB\n";
        assert_eq!(parse_thread_count(status), 3);
    }

    #[test]
    fn test_parse_thread_count_missing_defaults_to_one() {
        assert_eq!(parse_thread_count("Name:\tfoo\n"), 1);
    }

    #[test]
    fn test_assert_single_threaded_passes_when_alone() {
        crate::test_util::run_isolated(|| {
            assert!(assert_single_threaded().is_ok());
        });
    }
}
```

(The third test is new relative to Phase 0's version — Phase 0 couldn't write it at all, since on macOS `/proc/self/status` doesn't exist and the function always errors. Inside the Linux VM it can actually verify the success path, via `run_isolated` since the ambient `cargo test` process itself is multithreaded.)

- [ ] **Step 2: Run to verify it fails**

`cargo test -p kestrel-ns threading::` — FAIL, `assert_single_threaded`/`parse_thread_count` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/threading.rs (above the tests module)

use anyhow::{ensure, Context, Result};

/// Rule 2, enforced (PROMPT.md). If this ever fires, someone added a
/// dependency that spawns threads and the userns syscalls are about to
/// start failing with EINVAL in a way that is very hard to trace back to
/// its cause. `unshare(CLONE_NEWUSER)`/the clone3-based namespace creation
/// in `stages.rs` require the calling PROCESS (not just the calling
/// thread) to be single-threaded.
pub fn assert_single_threaded() -> Result<()> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    let threads = parse_thread_count(&status);
    ensure!(
        threads == 1,
        "kestrel must be single-threaded (found {threads}). Some dependency \
         spawned a thread. setns(CLONE_NEWUSER) will fail."
    );
    Ok(())
}

fn parse_thread_count(status: &str) -> usize {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1)
}
```

- [ ] **Step 4: Update `kestrel-runtime` to depend on `kestrel-ns` and re-export**

`crates/kestrel-runtime/Cargo.toml` — add to `[dependencies]`:
```toml
kestrel-ns = { path = "../kestrel-ns" }
```

`crates/kestrel-runtime/src/preflight.rs` — remove the local `assert_single_threaded`/`parse_thread_count`/their tests, replace with:
```rust
pub use kestrel_ns::threading::assert_single_threaded;
```
Leave `check_environment()`, `EnvReport`, `parse_kernel_version`, and their tests untouched — only the single-threaded-assertion piece moves.

- [ ] **Step 5: Run tests, verify everything still passes**

`cargo test -p kestrel-ns threading::` — expect 3 passed.
`cargo test -p kestrel-runtime` — expect the preflight test count to drop by 2 (the two thread-count tests moved out) but everything else (kernel-version tests, `test_assert_single_threaded_passes_when_alone`-equivalent doesn't exist there anymore) still passes. Confirm the count: Phase 0 left `kestrel-runtime` at 6 tests; after removing 2 moved tests, expect 4.
`cargo run -p kestrel-runtime` — **inside the VM**, this should now behave differently than on macOS: `assert_single_threaded()` should actually succeed (real `/proc/self/status`, single-threaded process), and `check_environment()` should also succeed (real cgroup v2 + overlay). Confirm the full preflight now passes end-to-end for the first time, with a `tracing::info!` "preflight checks passed" line instead of the macOS `Error: reading /proc/self/status` this binary always printed before now.
`cargo build --workspace` — confirm still succeeds.

- [ ] **Step 6: Mark task complete**

---

## Task 3: `NsType`

**Files:**
- Create content in: `crates/kestrel-ns/src/types.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-ns/src/types.rs

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sched::CloneFlags;

    #[test]
    fn test_all_8_variants_have_distinct_flags() {
        let all = [
            NsType::Mount, NsType::Uts, NsType::Ipc, NsType::Pid,
            NsType::Net, NsType::User, NsType::Cgroup, NsType::Time,
        ];
        let flags: Vec<CloneFlags> = all.iter().map(|n| n.clone_flag()).collect();
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(flags[i], flags[j], "{:?} and {:?} share a flag", all[i], all[j]);
            }
        }
    }

    #[test]
    fn test_time_flag_matches_kernel_constant() {
        // CLONE_NEWTIME = 0x00000080, not exposed by nix's CloneFlags.
        assert_eq!(NsType::Time.clone_flag().bits(), 0x0000_0080);
    }

    #[test]
    fn test_proc_name_matches_proc_pid_ns_convention() {
        assert_eq!(NsType::Mount.proc_name(), "mnt");
        assert_eq!(NsType::Net.proc_name(), "net");
        assert_eq!(NsType::Cgroup.proc_name(), "cgroup");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns types::` — FAIL, `NsType` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/types.rs (above the tests module)

use nix::sched::CloneFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NsType {
    Mount,
    Uts,
    Ipc,
    Pid,
    Net,
    User,
    Cgroup,
    Time,
}

/// Not in `nix`'s `CloneFlags` (added to the kernel in 5.6, after nix's
/// flag table was defined for older constants).
const CLONE_NEWTIME: u64 = 0x0000_0080;

impl NsType {
    pub fn clone_flag(self) -> CloneFlags {
        match self {
            NsType::Mount => CloneFlags::CLONE_NEWNS,
            NsType::Uts => CloneFlags::CLONE_NEWUTS,
            NsType::Ipc => CloneFlags::CLONE_NEWIPC,
            NsType::Pid => CloneFlags::CLONE_NEWPID,
            NsType::Net => CloneFlags::CLONE_NEWNET,
            NsType::User => CloneFlags::CLONE_NEWUSER,
            NsType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
            NsType::Time => CloneFlags::from_bits_retain(CLONE_NEWTIME),
        }
    }

    /// Path component under `/proc/<pid>/ns/`.
    pub fn proc_name(self) -> &'static str {
        match self {
            NsType::Mount => "mnt",
            NsType::Uts => "uts",
            NsType::Ipc => "ipc",
            NsType::Pid => "pid",
            NsType::Net => "net",
            NsType::User => "user",
            NsType::Cgroup => "cgroup",
            NsType::Time => "time",
        }
    }
}
```

If `CloneFlags::from_bits_retain` doesn't exist in the installed `bitflags` version `nix` re-exports, check whether it's `from_bits_truncate` or a different constructor and adjust — preserve intent (construct a `CloneFlags` value carrying exactly bit `0x80`, tolerating that `nix`'s enum doesn't know its name).

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns types::` — expect 3 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 4: `IdMapping` + `NamespacePlan`

**Files:**
- Create content in: `crates/kestrel-ns/src/types.rs` (append)

- [ ] **Step 1: Write the failing tests** (append to the existing `mod tests` in `types.rs`)

```rust
    #[test]
    fn test_plan_clone_flags_unions_all_requested() {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Pid, NsType::Mount],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        let flags = plan.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNET));
    }

    #[test]
    fn test_plan_has_user_ns() {
        let with = NamespacePlan { create: vec![NsType::User], uid_maps: vec![], gid_maps: vec![] };
        let without = NamespacePlan { create: vec![NsType::Pid], uid_maps: vec![], gid_maps: vec![] };
        assert!(with.has_user_ns());
        assert!(!without.has_user_ns());
    }

    #[test]
    fn test_plan_has_pid_ns() {
        let with = NamespacePlan { create: vec![NsType::Pid], uid_maps: vec![], gid_maps: vec![] };
        let without = NamespacePlan { create: vec![NsType::User], uid_maps: vec![], gid_maps: vec![] };
        assert!(with.has_pid_ns());
        assert!(!without.has_pid_ns());
    }
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns types::` — FAIL, `NamespacePlan`/`IdMapping` not defined.

- [ ] **Step 3: Write the implementation** (append to `types.rs`, above the tests module)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct NamespacePlan {
    pub create: Vec<NsType>,
    pub uid_maps: Vec<IdMapping>,
    pub gid_maps: Vec<IdMapping>,
}

impl NamespacePlan {
    pub fn clone_flags(&self) -> CloneFlags {
        self.create.iter().fold(CloneFlags::empty(), |acc, ns| acc | ns.clone_flag())
    }

    pub fn has_user_ns(&self) -> bool {
        self.create.contains(&NsType::User)
    }

    pub fn has_pid_ns(&self) -> bool {
        self.create.contains(&NsType::Pid)
    }
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns types::` — expect 6 passed total (3 from Task 3 + 3 new).

- [ ] **Step 5: Mark task complete**

---

## Task 5: `Sync` protocol

**Files:**
- Create content in: `crates/kestrel-ns/src/sync.rs`

Frames go over an `AF_UNIX SOCK_SEQPACKET` socketpair, wrapped in `std::os::unix::net::UnixDatagram` (constructed `From<OwnedFd>`) so `send`/`recv`/`set_read_timeout` come for free instead of hand-rolling `poll()`-based timeout logic — `SOCK_SEQPACKET` preserves message boundaries at the `send`/`recv` syscall level regardless of which `std` wrapper type is used to call them, so this is a safe simplification, not a behavior change from a raw-syscall version.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-ns/src/sync.rs

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    fn pair() -> (UnixDatagram, UnixDatagram) {
        let (a, b) =
            socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
                .unwrap();
        (UnixDatagram::from(a), UnixDatagram::from(b))
    }

    #[test]
    fn test_round_trip_each_variant() {
        let (a, b) = pair();
        for msg in [
            Sync::RequestMaps,
            Sync::MapsDone,
            Sync::ReportPid(4242),
            Sync::Ready,
            Sync::Error("boom".to_string()),
        ] {
            send_sync(&a, &msg).unwrap();
            let got = recv_sync_timeout(&b, Duration::from_secs(1)).unwrap();
            assert_eq!(got, msg);
        }
    }

    #[test]
    fn test_recv_times_out_when_nothing_sent() {
        let (_a, b) = pair();
        let err = recv_sync_timeout(&b, Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("timed out"), "unexpected error: {err}");
    }
}
```

If `SockFlag::SOCK_CLOEXEC` doesn't exist in the installed `nix` (some versions call it `SockFlag::CLOEXEC` instead), correct the name — same intent either way, both close the socketpair's fds across `execve`.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns sync::` — FAIL, `Sync`/`send_sync`/`recv_sync_timeout` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/sync.rs (above the tests module)

use std::io;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sync {
    RequestMaps,
    MapsDone,
    ReportPid(i32),
    Ready,
    Error(String),
}

pub fn send_sync(sock: &UnixDatagram, msg: &Sync) -> Result<()> {
    let bytes = serde_json::to_vec(msg).context("serializing sync message")?;
    sock.send(&bytes).context("sending sync message")?;
    Ok(())
}

/// Every sync-socket read has a timeout — a wedged stage must fail loudly,
/// never block the caller forever.
pub fn recv_sync_timeout(sock: &UnixDatagram, timeout: Duration) -> Result<Sync> {
    sock.set_read_timeout(Some(timeout)).context("setting sync read timeout")?;
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            anyhow::anyhow!("sync recv timed out after {timeout:?}")
        }
        _ => anyhow::Error::from(e).context("receiving sync message"),
    })?;
    serde_json::from_slice(&buf[..n]).context("deserializing sync message")
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns sync::` — expect 2 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 6: `write_id_maps` (CVE-2014-8989 ordering)

**Files:**
- Create content in: `crates/kestrel-ns/src/idmap.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-ns/src/idmap.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::run_isolated;
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{getgid, getuid};
    use std::fs;

    #[test]
    fn test_render_map_formats_lines() {
        let maps = [
            IdMapping { container_id: 0, host_id: 1000, size: 1 },
            IdMapping { container_id: 1, host_id: 100000, size: 65536 },
        ];
        assert_eq!(render_map(&maps), "0 1000 1\n1 100000 65536");
    }

    #[test]
    fn test_render_map_empty() {
        assert_eq!(render_map(&[]), "");
    }

    #[test]
    fn test_setgroups_deny_required_before_gid_map() {
        // Proves the CVE-2014-8989 constraint empirically, in a real
        // unprivileged user namespace, so the ordering never gets "cleaned
        // up" by a future refactor. Must run in an isolated single-threaded
        // child (see test_util::run_isolated).
        run_isolated(|| {
            let uid = getuid();
            let gid = getgid();
            unshare(CloneFlags::CLONE_NEWUSER).expect("unshare(CLONE_NEWUSER)");
            let pid = nix::unistd::getpid();

            // Write uid_map directly (bypassing write_id_maps) so we can
            // attempt gid_map BEFORE setgroups=deny and observe the EPERM
            // this whole ordering exists to avoid.
            fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n")).unwrap();
            let err = fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))
                .expect_err("gid_map without setgroups=deny must fail");
            assert_eq!(err.raw_os_error(), Some(libc::EPERM));

            fs::write(format!("/proc/{pid}/setgroups"), "deny").unwrap();
            fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))
                .expect("gid_map after setgroups=deny must succeed");
        });
    }

    #[test]
    fn test_write_id_maps_end_to_end() {
        run_isolated(|| {
            let uid = getuid();
            let gid = getgid();
            unshare(CloneFlags::CLONE_NEWUSER).expect("unshare(CLONE_NEWUSER)");
            let pid = nix::unistd::getpid();

            write_id_maps(
                pid,
                &[IdMapping { container_id: 0, host_id: uid.as_raw(), size: 1 }],
                &[IdMapping { container_id: 0, host_id: gid.as_raw(), size: 1 }],
            )
            .expect("write_id_maps");

            let uid_map = fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
            assert!(uid_map.contains(&format!("0 {uid} 1")));
        });
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns idmap::` — FAIL, `render_map`/`write_id_maps`/`IdMapping` (last one's already defined in `types.rs` from Task 4) not resolvable — specifically `write_id_maps`/`render_map` missing.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/idmap.rs (above the tests module)

use std::fs;
use std::io;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::types::IdMapping;

pub fn write_id_maps(pid: Pid, uid_maps: &[IdMapping], gid_maps: &[IdMapping]) -> Result<()> {
    let base = format!("/proc/{pid}");

    // The kernel accepts exactly ONE write to uid_map/gid_map per
    // namespace — all lines must go in a single write() call.
    fs::write(format!("{base}/uid_map"), render_map(uid_maps))
        .with_context(|| format!("writing uid_map for pid {pid}"))?;

    // CVE-2014-8989: without denying setgroups first, an unprivileged
    // process writing gid_map gets EPERM. The reason is a real escape: a
    // user could map a group they belong to, then setgroups() to DROP it,
    // escaping a negative ACL (a file with `group foo: ---`). ENOENT on
    // kernels < 3.19 where the file does not exist.
    match fs::write(format!("{base}/setgroups"), "deny") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("denying setgroups"),
    }

    fs::write(format!("{base}/gid_map"), render_map(gid_maps))
        .with_context(|| format!("writing gid_map for pid {pid}"))?;
    Ok(())
}

pub fn render_map(maps: &[IdMapping]) -> String {
    maps.iter()
        .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
        .collect::<Vec<_>>()
        .join("\n")
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns idmap::` — expect 4 passed. These need real `unshare(CLONE_NEWUSER)` but not root (Ubuntu's `kernel.unprivileged_userns_clone` default) — should pass under plain `cargo test`, no `sudo` needed. If `test_setgroups_deny_required_before_gid_map` fails with an unexpected errno, run `cat /proc/sys/kernel/unprivileged_userns_clone` inside the VM to confirm it's `1`; if `0`, that's an environment issue to flag back, not a code bug.

- [ ] **Step 5: Mark task complete**

---

## Task 7: `read_ns_inode`

**Files:**
- Create content in: `crates/kestrel-ns/src/inode.rs`

Parses the `net:[4026531840]`-style symlink target under `/proc/<pid>/ns/<type>` into the bare inode number, used later to prove two namespaces are (or aren't) the same one.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-ns/src/inode.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NsType;
    use nix::unistd::getpid;

    #[test]
    fn test_read_own_mount_ns_inode() {
        // /proc/self/ns/mnt always exists and always parses.
        let inode = read_ns_inode(getpid(), NsType::Mount).unwrap();
        assert!(inode > 0);
    }

    #[test]
    fn test_parse_ns_link_target() {
        assert_eq!(parse_ns_link_target("net:[4026531840]").unwrap(), 4026531840);
        assert_eq!(parse_ns_link_target("mnt:[4026531841]").unwrap(), 4026531841);
    }

    #[test]
    fn test_parse_ns_link_target_rejects_garbage() {
        assert!(parse_ns_link_target("not-a-ns-link").is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns inode::` — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/inode.rs (above the tests module)

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::types::NsType;

/// Reads the inode number a namespace symlink points at, e.g.
/// `/proc/1234/ns/net` -> `net:[4026531840]` -> `4026531840`.
pub fn read_ns_inode(pid: Pid, ns: NsType) -> Result<u64> {
    let path = format!("/proc/{pid}/ns/{}", ns.proc_name());
    let target = std::fs::read_link(&path).with_context(|| format!("reading link {path}"))?;
    let target = target.to_string_lossy();
    parse_ns_link_target(&target).with_context(|| format!("parsing ns link target {target:?}"))
}

fn parse_ns_link_target(target: &str) -> Result<u64> {
    let inner = target
        .split_once('[')
        .and_then(|(_, rest)| rest.strip_suffix(']'))
        .context("expected `type:[inode]` format")?;
    inner.parse().context("inode component is not numeric")
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns inode::` — expect 3 passed, no root/unshare needed (reads the test process's own, real namespaces).

- [ ] **Step 5: Mark task complete**

---

## Task 8: The three-stage dance

**Files:**
- Create content in: `crates/kestrel-ns/src/stages.rs`
- Create: `crates/kestrel-ns/tests/dance.rs`

This is PROMPT.md's "hardest 200 lines in the project," translated close to verbatim, with one deliberate change: stage2 is parameterized by `child_action: impl FnOnce() -> !` instead of a hardcoded `stage2_never_returns()` placeholder, since Phase 4 (rootfs)/Phase 5 (security)/Phase 8 (runtime binary wiring) — what a real container's PID 1 actually *does* — don't exist yet. Because `child_action` is a normal in-memory closure and every stage is reached purely by `fork()` (which copies the whole address space, no cross-process serialization involved), passing it through stage0 → stage1 → stage2 needs no special handling.

- [ ] **Step 1: Write the failing tests** — as an integration test file, since this exercises the crate's full public surface end-to-end.

`crates/kestrel-ns/tests/dance.rs`:

```rust
use std::time::Duration;

use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};

#[test]
fn test_uts_isolation() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts, NsType::Mount],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };
        let host_hostname = nix::unistd::gethostname().unwrap();

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            nix::unistd::sethostname("kestrel-test").expect("sethostname");
            // Park until killed by the parent test — this closure's whole
            // job is to hold the namespace open long enough for the parent
            // to inspect it via /proc, standing in for the real container
            // entrypoint later phases will supply.
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        })
        .expect("run_stages");

        // Host's own hostname must be unaffected by the child's sethostname.
        assert_eq!(nix::unistd::gethostname().unwrap(), host_hostname);

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).unwrap();
    });
}

#[test]
fn test_pid_isolation() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Pid, NsType::Mount],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            // Inside the new PID namespace, this process must see itself
            // as PID 1. Write the observation somewhere the parent can
            // read it back rather than asserting here (an assertion
            // failure inside this closure is caught by run_stages'
            // caller's own isolation, not visible to the outer test
            // process directly) — /proc/self mapping to "1" is exactly
            // what proves isolation, so read it and exit with a code that
            // encodes the result.
            let self_pid = std::fs::read_link("/proc/self")
                .ok()
                .and_then(|p| p.to_str().map(String::from));
            let code = if self_pid.as_deref() == Some("1") { 0 } else { 1 };
            unsafe { libc::_exit(code) };
        })
        .expect("run_stages");

        let status = nix::sys::wait::waitpid(result.init_pid, None).unwrap();
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Exited(result.init_pid, 0),
            "PID 1 inside the new namespace did not see itself as PID 1"
        );
    });
}

#[test]
fn test_userns_maps_uid_0_inside_maps_to_invoking_uid_outside() {
    run_isolated(|| {
        let outside_uid = nix::unistd::getuid().as_raw();
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Mount],
            uid_maps: vec![IdMapping { container_id: 0, host_id: outside_uid, size: 1 }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            let inside_uid = nix::unistd::getuid().as_raw();
            unsafe { libc::_exit(if inside_uid == 0 { 0 } else { 1 }) };
        })
        .expect("run_stages");

        let status = nix::sys::wait::waitpid(result.init_pid, None).unwrap();
        assert_eq!(status, nix::sys::wait::WaitStatus::Exited(result.init_pid, 0));

        // From the host's perspective, that same process's uid_map should
        // show container-uid 0 mapped to our real invoking uid.
        let uid_map =
            std::fs::read_to_string(format!("/proc/{}/uid_map", result.init_pid)).unwrap_or_default();
        // (best-effort — the child may have already exited and reaped by
        // the time we read this; the waitpid above already proved the
        // in-namespace uid was 0, which is the actual invariant under test)
        let _ = uid_map;
    });
}
```

`test_userns_maps_uid_0_inside_maps_to_invoking_uid_outside`'s exit-code check is the real assertion; the trailing `uid_map` read is best-effort color, not required to pass — note this in a comment as shown, don't remove the exit-code check.

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns --test dance` — FAIL, `kestrel_ns::stages::run_stages` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/stages.rs

use std::os::fd::RawFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, setresgid, setresuid, ForkResult, Gid, Pid, Uid};

use crate::idmap::write_id_maps;
use crate::sync::{recv_sync_timeout, send_sync, Sync};
use crate::threading::assert_single_threaded;
use crate::types::NamespacePlan;

pub struct StageResult {
    pub init_pid: Pid,
    pub stage1_pid: Pid,
}

pub fn run_stages(
    plan: &NamespacePlan,
    cgroup_fd: Option<RawFd>,
    child_action: impl FnOnce() -> ! + 'static,
) -> Result<StageResult> {
    assert_single_threaded()?;

    let (a, b) = socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
        .context("creating sync socketpair")?;
    let parent_sock = UnixDatagram::from(a);
    let child_sock = UnixDatagram::from(b);

    // Everything EXCEPT CLONE_NEWPID. PID ns is unshared in stage1, because
    // the caller of unshare(CLONE_NEWPID) stays in the old namespace — only
    // its subsequent children land in the new one.
    let mut flags = plan.clone_flags();
    flags.remove(CloneFlags::CLONE_NEWPID);

    match unsafe { fork() }.context("fork (stage1)")? {
        ForkResult::Child => {
            drop(parent_sock);
            // Any error here must be REPORTED over the socket, not just
            // exited on, or the parent hangs forever on the sync read with
            // no diagnosis.
            if let Err(e) = stage1(&child_sock, flags, plan, cgroup_fd, child_action) {
                let _ = send_sync(&child_sock, &Sync::Error(format!("{e:#}")));
            }
            unsafe { libc::_exit(1) };
        }
        ForkResult::Parent { child: stage1_pid } => {
            drop(child_sock);
            stage0(&parent_sock, stage1_pid, plan)
                .map(|init_pid| StageResult { init_pid, stage1_pid })
        }
    }
}

// ─────────────────────────── STAGE 0 (runtime, host namespaces) ───────────
fn stage0(sock: &UnixDatagram, stage1_pid: Pid, plan: &NamespacePlan) -> Result<Pid> {
    match recv_sync_timeout(sock, Duration::from_secs(10))? {
        Sync::RequestMaps => {}
        Sync::Error(e) => bail!("stage1 failed before maps: {e}"),
        other => bail!("unexpected sync from stage1: {other:?}"),
    }

    if plan.has_user_ns() {
        write_id_maps(stage1_pid, &plan.uid_maps, &plan.gid_maps)?;
    }
    send_sync(sock, &Sync::MapsDone)?;

    let init_pid = match recv_sync_timeout(sock, Duration::from_secs(30))? {
        Sync::ReportPid(p) => Pid::from_raw(p),
        Sync::Error(e) => bail!("stage1 failed after maps: {e}"),
        other => bail!("expected ReportPid, got {other:?}"),
    };

    // Stage1 exits immediately after reporting; reap it so it does not
    // linger as a zombie in the runtime's process table.
    let _ = waitpid(stage1_pid, None);
    Ok(init_pid)
}

// ─────────── STAGE 1 (all namespaces except PID; still has old PID) ───────
fn stage1(
    sock: &UnixDatagram,
    flags: CloneFlags,
    plan: &NamespacePlan,
    cgroup_fd: Option<RawFd>,
    child_action: impl FnOnce() -> ! + 'static,
) -> Result<()> {
    // Create the user namespace FIRST and alone. Combining it with the
    // others in one unshare() works, but separating makes the ordering
    // explicit and the failure modes far easier to read.
    if plan.has_user_ns() {
        unshare(CloneFlags::CLONE_NEWUSER).context("unshare(CLONE_NEWUSER)")?;
        send_sync(sock, &Sync::RequestMaps)?;
        match recv_sync_timeout(sock, Duration::from_secs(10))? {
            Sync::MapsDone => {}
            other => bail!("expected MapsDone, got {other:?}"),
        }
        // We are mapped to 0 inside the userns but our euid is still the
        // old value. setresuid makes us actually root in here, which the
        // remaining unshares require.
        setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
            .context("setresuid(0,0,0)")?;
        setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))
            .context("setresgid(0,0,0)")?;
    }

    // Everything else, minus user (already done) and pid (handled next).
    let rest = flags - CloneFlags::CLONE_NEWUSER;
    if !rest.is_empty() {
        unshare(rest).with_context(|| format!("unshare({rest:?})"))?;
    }

    // Does NOT move us. Our next child becomes PID 1 of the new namespace.
    if plan.has_pid_ns() {
        unshare(CloneFlags::CLONE_NEWPID).context("unshare(CLONE_NEWPID)")?;
    }

    let init_pid = match cgroup_fd {
        // clone3 + CLONE_INTO_CGROUP would place the child atomically —
        // not exercised this phase (Phase 3 doesn't exist yet to supply a
        // real fd); when it does, this branch's job is to call the same
        // raw-syscall helper Phase 3's cgroup manager will define.
        Some(_fd) => bail!("CLONE_INTO_CGROUP not implemented until Phase 3 supplies a cgroup fd"),
        None => match unsafe { fork() }.context("fork (stage2)")? {
            ForkResult::Child => {
                // STAGE 2 — we are PID 1. Never returns.
                child_action()
            }
            ForkResult::Parent { child } => child,
        },
    };

    send_sync(sock, &Sync::ReportPid(init_pid.as_raw()))?;

    // Stage1 must exit so PID 1 is reparented and the process tree is clean.
    unsafe { libc::_exit(0) };
}
```

## API drift note

`nix::unistd::fork()` is `unsafe fn`, matches PROMPT.md's usage. `Uid`/`Gid`/`Pid` are re-exported from `nix::unistd` directly in 0.29 (not a separate `nix::unistd::user` submodule) — if `cargo build` disagrees, check `cargo doc -p nix --no-deps` for their real location and fix the `use` line, same intent. `UnixDatagram::from(OwnedFd)` relies on std's `From<OwnedFd> for UnixDatagram` impl; if that specific conversion doesn't exist, use `use std::os::fd::FromRawFd; unsafe { UnixDatagram::from_raw_fd(fd.into_raw_fd()) }` instead — same effect, slightly less safe-by-construction.

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns --test dance` — expect 3 passed. None of these need root (Ubuntu's unprivileged userns default covers everything exercised here — no networking, no pinning).

- [ ] **Step 5: Mark task complete**

---

## Task 9: Namespace pinning (root-gated)

**Files:**
- Create content in: `crates/kestrel-ns/src/pin.rs`
- Create: `crates/kestrel-ns/tests/pin.rs`

Bind-mounting onto `/run/kestrel/...` needs `CAP_SYS_ADMIN` in the *host* mount namespace — real root, not just an unprivileged user namespace. These tests are `#[ignore]`d and run via `sudo -E cargo test -p kestrel-ns -- --ignored`.

- [ ] **Step 1: Write the failing tests**

`crates/kestrel-ns/tests/pin.rs`:

```rust
use std::time::Duration;

use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::stages::run_stages;
use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};

#[test]
#[ignore = "requires root"]
fn test_pin_survives_pid1_exit() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts, NsType::Mount],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };

        let result = run_stages(&plan, None, || {
            std::thread::sleep(Duration::from_secs(2));
            unsafe { libc::_exit(0) };
        })
        .expect("run_stages");

        let tmp = tempfile_dir();
        let target = tmp.join("uts");
        pin_namespace(result.init_pid, NsType::Uts, &target).expect("pin_namespace");

        // Wait for PID 1 to exit on its own.
        nix::sys::wait::waitpid(result.init_pid, None).unwrap();

        // The pin must still be enterable after PID 1 is gone.
        let f = std::fs::File::open(&target).expect("pinned ns file still openable");
        drop(f);

        unpin_namespace(&target).expect("unpin_namespace");
        assert!(!target.exists(), "unpin must remove the pin file");

        std::fs::remove_dir_all(&tmp).ok();
    });
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kestrel-ns-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
```

- [ ] **Step 2: Run to verify it fails.** `sudo -E cargo test -p kestrel-ns --test pin -- --ignored` — FAIL, `pin_namespace`/`unpin_namespace` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/pin.rs

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::Pid;

use crate::types::NsType;

/// Bind-mounts `/proc/<pid>/ns/<ns>` onto `target`, keeping the namespace
/// alive (and enterable via `setns` on `target`) even after `pid` exits.
pub fn pin_namespace(pid: Pid, ns: NsType, target: &Path) -> Result<()> {
    // The bind-mount target must already exist as a regular file.
    fs::File::create(target).with_context(|| format!("creating pin target {target:?}"))?;
    let src = format!("/proc/{pid}/ns/{}", ns.proc_name());
    mount(Some(src.as_str()), target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
        .with_context(|| format!("bind-mounting {src} onto {target:?}"))?;
    Ok(())
}

pub fn unpin_namespace(target: &Path) -> Result<()> {
    umount2(target, MntFlags::MNT_DETACH)
        .with_context(|| format!("unmounting pin {target:?}"))?;
    fs::remove_file(target).with_context(|| format!("removing pin file {target:?}"))?;
    Ok(())
}
```

- [ ] **Step 4: Run to verify it passes.** `sudo -E cargo test -p kestrel-ns --test pin -- --ignored` — expect 1 passed. Confirm the test genuinely needed root — run it without `sudo` first (still with `--ignored`, since `#[ignore]` only means "skip by default," not "skip without root") and confirm it fails with a permission error, then confirm `sudo -E` passes, so the `#[ignore]` gate is doing real work, not just decorative.

- [ ] **Step 5: Mark task complete**

---

## Task 10: `join_namespaces` (root-gated)

**Files:**
- Create content in: `crates/kestrel-ns/src/join.rs`
- Create: `crates/kestrel-ns/tests/join.rs`

User namespace LAST, because entering it drops the capabilities needed to enter the others (this ordering bug is what produces runc issue #4390's exact error).

- [ ] **Step 1: Write the failing tests**

`crates/kestrel-ns/tests/join.rs`:

```rust
use std::collections::BTreeMap;
use std::time::Duration;

use kestrel_ns::join::join_namespaces;
use kestrel_ns::pin::pin_namespace;
use kestrel_ns::stages::run_stages;
use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};
use nix::sched::CloneFlags;

fn pin_all(init_pid: nix::unistd::Pid, dir: &std::path::Path) -> BTreeMap<NsType, std::path::PathBuf> {
    let mut pins = BTreeMap::new();
    for ns in [NsType::User, NsType::Uts, NsType::Mount] {
        let target = dir.join(ns.proc_name());
        pin_namespace(init_pid, ns, &target).expect("pin");
        pins.insert(ns, target);
    }
    pins
}

#[test]
#[ignore = "requires root"]
fn test_join_order_matters() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts, NsType::Mount],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };
        let result = run_stages(&plan, None, || loop {
            std::thread::sleep(Duration::from_secs(3600));
        })
        .expect("run_stages");

        let dir = std::env::temp_dir().join(format!("kestrel-join-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pins = pin_all(result.init_pid, &dir);

        // User-namespace-first: join user, then try net (not even in our
        // pin set on purpose — use mount instead, which still requires a
        // capability the userns join has just dropped) — expect failure.
        let user_first_fails = {
            let f = std::fs::File::open(&pins[&NsType::User]).unwrap();
            let user_join_ok = nix::sched::setns(&f, CloneFlags::CLONE_NEWUSER).is_ok();
            let mount_join_ok = std::fs::File::open(&pins[&NsType::Mount])
                .ok()
                .map(|f| nix::sched::setns(&f, CloneFlags::CLONE_NEWNS).is_ok())
                .unwrap_or(false);
            user_join_ok && !mount_join_ok
        };
        assert!(user_first_fails, "joining user-namespace first should break the subsequent join");

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).ok();
        std::fs::remove_dir_all(&dir).ok();
    });
}

#[test]
#[ignore = "requires root"]
fn test_join_namespaces_canonical_order_succeeds() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts, NsType::Mount],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };
        let result = run_stages(&plan, None, || loop {
            std::thread::sleep(Duration::from_secs(3600));
        })
        .expect("run_stages");

        let dir = std::env::temp_dir().join(format!("kestrel-join-test-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pins = pin_all(result.init_pid, &dir);

        // A second isolated fork so this join attempt doesn't corrupt the
        // caller's own namespaces for the rest of the test process.
        run_isolated(|| {
            join_namespaces(&pins).expect("canonical-order join must succeed");
        });

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).ok();
        std::fs::remove_dir_all(&dir).ok();
    });
}
```

- [ ] **Step 2: Run to verify it fails.** `sudo -E cargo test -p kestrel-ns --test join -- --ignored` — FAIL, `join_namespaces` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/join.rs

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::types::NsType;

/// User namespace LAST. Entering a user namespace drops the capabilities
/// you need to enter the others, so joining user-first makes every
/// subsequent setns() fail with EPERM. This ordering bug produces the
/// exact error in runc issue #4390.
pub fn join_namespaces(pins: &BTreeMap<NsType, PathBuf>) -> Result<()> {
    const ORDER: &[NsType] = &[
        NsType::Cgroup,
        NsType::Ipc,
        NsType::Uts,
        NsType::Net,
        NsType::Pid,
        NsType::Mount,
        NsType::Time,
        NsType::User,
    ];
    for ns in ORDER {
        let Some(path) = pins.get(ns) else { continue };
        let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        nix::sched::setns(&f, ns.clone_flag())
            .with_context(|| format!("setns into {ns:?}"))?;
    }
    Ok(())
}
```

- [ ] **Step 4: Run to verify it passes.** `sudo -E cargo test -p kestrel-ns --test join -- --ignored` — expect 2 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 11: Rootless — `/etc/subuid`/`/etc/subgid` parsing

**Files:**
- Create content in: `crates/kestrel-ns/src/rootless.rs`

Pure parsing, no root/unshare needed — this is the 🟡-priority half of Phase 2. Format is `name:start:count` per line (e.g. `sanskar:100000:65536`), matching `/etc/subuid`'s real format.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-ns/src/rootless.rs

#[cfg(test)]
mod tests {
    use super::*;

    const SUBUID: &str = "\
sanskar:100000:65536
root:231072:65536
";

    #[test]
    fn test_parse_subuid_finds_matching_user() {
        let range = parse_subid_range(SUBUID, "sanskar").unwrap();
        assert_eq!(range, SubIdRange { start: 100000, count: 65536 });
    }

    #[test]
    fn test_parse_subuid_unknown_user_rejected() {
        assert!(parse_subid_range(SUBUID, "ghost").is_err());
    }

    #[test]
    fn test_parse_subuid_malformed_line_skipped_not_fatal() {
        let with_garbage = "not-a-valid-line\nsanskar:100000:65536\n";
        let range = parse_subid_range(with_garbage, "sanskar").unwrap();
        assert_eq!(range, SubIdRange { start: 100000, count: 65536 });
    }

    #[test]
    fn test_build_single_range_id_mapping() {
        let range = SubIdRange { start: 100000, count: 65536 };
        let maps = range.to_id_mappings();
        assert_eq!(
            maps,
            vec![crate::types::IdMapping { container_id: 0, host_id: 100000, size: 65536 }]
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-ns rootless::` — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-ns/src/rootless.rs (above the tests module)

use anyhow::{Context, Result};

use crate::types::IdMapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubIdRange {
    pub start: u32,
    pub count: u32,
}

impl SubIdRange {
    /// A single contiguous range maps container ids [0, count) onto
    /// host ids [start, start+count).
    pub fn to_id_mappings(self) -> Vec<IdMapping> {
        vec![IdMapping { container_id: 0, host_id: self.start, size: self.count }]
    }
}

/// Parses `/etc/subuid`/`/etc/subgid`-format content (`name:start:count`
/// per line) for the given username. Malformed lines are skipped, not
/// fatal — a single bad line elsewhere in the file shouldn't block a
/// lookup that would otherwise succeed.
pub fn parse_subid_range(contents: &str, username: &str) -> Result<SubIdRange> {
    contents
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.splitn(3, ':');
            let name = parts.next()?;
            if name != username {
                return None;
            }
            let start = parts.next()?.parse().ok()?;
            let count = parts.next()?.parse().ok()?;
            Some(SubIdRange { start, count })
        })
        .with_context(|| format!("no subuid/subgid entry for {username:?}"))
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-ns rootless::` — expect 4 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 12: Wire `make test-root`, full-suite verification

**Files:**
- Modify: `Makefile`

Phase 0 left `test-root` as a stub that always fails with an explanatory message. Now that Phase 2 has real `--ignored` tests, point it at the real invocation.

- [ ] **Step 1: Update the `test-root` target**

```makefile
test-root:
	sudo -E $$(command -v cargo || echo "$$HOME/.cargo/bin/cargo") test --workspace -- --ignored
```

(`sudo -E` preserves the invoking user's environment, notably `PATH`/`CARGO_HOME`, so the cargo installed via rustup for the normal user is still what runs under sudo — `sudo cargo` alone would usually fail with "command not found" since root's `PATH` doesn't include `~/.cargo/bin`. The `$$(command -v cargo || ...)` fallback covers both "cargo is on PATH already" and "it isn't" without hardcoding a path that might not match every environment.)

- [ ] **Step 2: Run the full suite, both halves, inside the VM**

```
make test
make test-root
```
Expected: `make test` — tokio guard OK, all non-`--ignored` tests across the workspace pass (this now includes `kestrel-ns`'s Task 3–8/11 tests, ~20+ tests, plus everything from Phase 0/1). `make test-root` — the `--ignored` tests from Task 9/10 pass (2 tests).

- [ ] **Step 3: Full workspace build + web build sanity check (still works, nothing regressed)**

`cargo build --workspace` inside the VM. Then, back on the macOS host (not the VM): `cargo build --workspace` again — confirm the crates that compile on macOS (`kestrel-oci`, and now also `kestrel-runtime` up to the point where it needs `kestrel-ns`) — **note:** `kestrel-runtime` now depends on `kestrel-ns`, and `kestrel-ns` uses `nix::mount`/`nix::sched` functions that don't exist on macOS (`unshare`, `setns`, `mount` — Linux-only, same category as Phase 0's `preflight.rs` Linux-gating). Confirm whether `kestrel-ns` needs the same `#[cfg(target_os = "linux")]` treatment Phase 0 gave `preflight.rs` to keep `cargo build --workspace` green on the host — if `cargo build --workspace` on macOS now fails because of this, that's a real regression from this phase's design intent (Phase 0/1 were explicitly kept host-agnostic) and needs a fix: gate `kestrel-ns`'s Linux-only modules (`stages.rs`, `pin.rs`, `join.rs`, parts of `idmap.rs`) behind `#[cfg(target_os = "linux")]` the same way, so the crate still compiles (with a reduced surface) on macOS. Do this if the build fails; if `nix`'s own feature-gating already makes this a non-issue (some `nix` functions simply don't exist as symbols outside Linux, causing the same category of compile error Phase 0 already solved once), apply the same pattern used in `kestrel-runtime/src/preflight.rs`.

- [ ] **Step 4: Mark task complete**

---

## Self-Review Notes

- **Spec coverage:** CHECKLIST.md Phase 2's "Core" bullets map to Tasks 1/3/4/6 (`NsType`, `CLONE_NEWTIME`, `NamespacePlan`, `unshare` usage inline in `stages.rs`, `pin_namespace`/`unpin_namespace`/`read_ns_inode` — Tasks 7/9); "ID maps" bullets map to Tasks 4/6; "three-stage dance" bullets map to Task 8; "Tests" bullets map across Tasks 6/8/9/10 (each gating test lives next to the code it gates, per TDD, rather than being batched at the end).
- **Known deviation from PROMPT.md, and why:** `run_stages()` takes a `child_action` closure instead of calling a hardcoded `stage2_never_returns()`. This is necessary, not optional — Phase 4/5/8 (what a real PID 1 actually does) don't exist yet, and PROMPT.md's own comment ("STAGE 2 — we are PID 1. Never returns.") is describing a placeholder for code that later phases supply. Later phases pass a real closure; this phase's tests pass small ones.
- **Root requirement is real and unavoidable, not a testing-shortcut smell:** namespace pinning (Task 9) and cross-process joining (Task 10) both need `CAP_SYS_ADMIN` in the host mount namespace for the bind-mount calls involved — this is why CHECKLIST.md's own Makefile design has a separate `test-root` target requiring `sudo`, matching Task 12.
