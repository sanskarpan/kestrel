# Kestrel — Phase 2 (Namespaces) Design

## Context

Phase 2 builds `kestrel-ns`: the three-stage fork/unshare dance that creates
all 8 Linux namespaces correctly ordered, writes uid/gid maps with the
CVE-2014-8989-safe ordering, and pins/joins namespaces for `kestrel exec`.
PROMPT.md's own "Phase 2 — Namespaces: the three-stage dance" section and
SPEC.md §4 already give this in full, working-code detail — this document
does not re-derive that design, it pins down the two things that section
doesn't cover: how this actually gets *tested* given real syscall
constraints, and how it fits into what's built so far.

This is scoped as **all of Phase 2** (28 checklist tasks) per the earlier
decision. Environment: the Lima VM (`kestrel`, Ubuntu 24.04, kernel 6.8,
cgroup v2, overlay, passwordless sudo) is now up and provisioned — this is
the first phase that actually needs it, since every syscall involved
(`unshare`, `clone`/`clone3`, `setns`, `mount` for pinning) doesn't exist on
macOS.

## 1. Crate structure (`crates/kestrel-ns`)

Per SPEC §16 ("namespaces, id maps, pinning, setns ordering") and the
existing crate stub from Phase 0:

- `src/lib.rs` — re-exports the public surface
- `src/types.rs` — `NsType` (8-variant enum, `clone_flag()`/`proc_name()`),
  `IdMapping`, `NamespacePlan`
- `src/idmap.rs` — `write_id_maps()` (the CVE-2014-8989 ordering),
  `render_map()`
- `src/sync.rs` — the `Sync` protocol enum (`RequestMaps`, `MapsDone`,
  `ReportPid`, `Ready`, `Error(String)`) and the socketpair send/recv
  helpers with timeouts
- `src/stages.rs` — `run_stages()` and the stage0/stage1/stage2 functions
- `src/pin.rs` — `pin_namespace()`, `unpin_namespace()`, `read_ns_inode()`
- `src/join.rs` — `join_namespaces()` (the fixed 8-namespace order, user
  last)
- `src/rootless.rs` — `/etc/subuid`/`/etc/subgid` parsing,
  `newuidmap`/`newgidmap` fallback (🟡 important, not blocking — included
  since scope is "all of Phase 2," but lands after the 🔴 core items)

`Cargo.toml` gains the crate-specific deps this phase actually needs:
`nix` with `sched`, `mount`, `process`, `fs`, `signal`, `socket`, `net`
features enabled (workspace `nix` currently has no features turned on
beyond what `kestrel-runtime` needs); `serde`/`serde_json` for the `Sync`
enum (it's sent over the socketpair as a length-prefixed JSON frame, the
simplest correct thing here — bincode would also work but adds a dep for no
real benefit at this message volume).

`kestrel-runtime` gains a dependency on `kestrel-ns` (it's the caller of
`run_stages()`), but Phase 8 (the actual runtime binary wiring `create`/
`start`/etc. subcommands) is still out of scope — this phase only needs
`kestrel-ns` to compile and pass its own tests standalone. No changes to
`kestrel-runtime`'s `main.rs`.

## 2. `CLONE_INTO_CGROUP` is stubbed, not implemented, this phase

`run_stages()`'s signature takes `cgroup_fd: Option<RawFd>` per PROMPT.md.
Phase 3 (cgroups v2) doesn't exist yet, so every caller in this phase's
tests passes `None`, which exercises the `fork()` fallback path (stage1
forks a child normally; PID 1 is *not* placed in a cgroup atomically). The
`clone3`-based `Some(fd)` branch is written now (it's pure syscall glue with
no cgroup-subsystem dependency) but has no test coverage until Phase 3
supplies a real cgroup fd — that's expected, not a gap to close here.

## 3. The core testing problem: `unshare(CLONE_NEWUSER)` requires a
   single-threaded **process**, and `cargo test`'s harness isn't one

This is the one thing in Phase 2 that isn't just "translate PROMPT.md's
pseudocode" — it determines how every test in this phase has to be shaped.

`unshare(2)`/`clone(2)` with `CLONE_NEWUSER` fail with `EINVAL` if the
calling **process** is multithreaded — not just the calling thread. Rust's
default test harness (`cargo test`) runs the whole test binary as one
process and spawns a real OS thread per test (even under
`--test-threads=1`, which only serializes *execution*, not thread
*creation* — the process still ends up multithreaded over the run). So no
`#[test]` function can call `unshare(CLONE_NEWUSER)` (or anything in
`run_stages()`, which starts with `assert_single_threaded()`) directly and
expect it to work — it'll intermittently or consistently fail with `EINVAL`
depending on test ordering/parallelism, for reasons that have nothing to do
with the code under test.

**Resolution, matching what PROMPT.md's own `test_setgroups_deny_required`
sample already implies with its `spawn_userns_child()` helper:** every test
that needs a genuinely single-threaded process forks *itself* into an
isolated child first. `fork()` guarantees the child starts with exactly one
thread regardless of how many threads the parent (test harness) process
had — so the child is always eligible to call `unshare(CLONE_NEWUSER)`
correctly. A small shared test helper does this once:

```rust
// crates/kestrel-ns/tests/common/mod.rs (or a #[cfg(test)] module in the crate)
pub fn run_isolated<F: FnOnce() -> i32>(f: F) -> i32 {
    match unsafe { nix::unistd::fork() }.expect("fork") {
        nix::unistd::ForkResult::Child => {
            let code = f();
            unsafe { libc::_exit(code) };
        }
        nix::unistd::ForkResult::Parent { child } => {
            match nix::sys::wait::waitpid(child, None).expect("waitpid") {
                nix::sys::wait::WaitStatus::Exited(_, code) => code,
                other => panic!("child did not exit cleanly: {other:?}"),
            }
        }
    }
}
```

Every test that exercises `unshare`/`run_stages`/`join_namespaces`/pinning
wraps its actual assertions in `run_isolated(|| { ... ; 0 })` and asserts on
the returned exit code (nonzero = the closure should signal failure via a
distinct exit code, since panics don't cross the fork boundary usefully —
`std::panic::catch_unwind` inside the child, mapping a caught panic to exit
code 101, is the concrete mechanism). This is the single load-bearing
pattern this phase's plan needs to get right; everything else follows
PROMPT.md's given code directly.

## 4. Root vs. non-root test split

Not every Phase 2 test needs host root — this determines what runs under
plain `cargo test` (in the VM, as the provisioned non-root user) vs. what
needs `sudo -E cargo test -- --ignored`:

- **No root needed** (Ubuntu enables `kernel.unprivileged_userns_clone` by
  default): `unshare(CLONE_NEWUSER)` itself, the full three-stage dance for
  namespace types that don't need host privilege (`user`, `mount`, `uts`,
  `ipc`, `pid`, `cgroup`, `time` — all creatable by an unprivileged process
  once it holds a user namespace), `write_id_maps()` and the
  CVE-2014-8989 ordering test, `join_namespaces()`'s ordering test (via
  `setns` on pins created by an unprivileged run).
- **Needs real host root** (`#[ignore = "requires root"]`, run via
  `make test-root` → `sudo -E cargo test --workspace -- --ignored`):
  `CLONE_NEWNET` (creating/naming network interfaces needs `CAP_NET_ADMIN`
  in the *host* namespace the veth end lives in — not applicable until
  Phase 7, but the plan flag is set now since `NsType::Net` is one of the
  8), `pin_namespace()`/`unpin_namespace()` (bind-mounting onto
  `/run/kestrel/...` needs `CAP_SYS_ADMIN` in the host mount namespace),
  and `test_pin_survives_pid1_exit` (needs a real pin).

## 5. Sync protocol wire format

PROMPT.md's `Sync` enum is `Serialize + Deserialize` already (matches the
existing Phase 0 convention of deriving these liberally). Frames over the
`AF_UNIX SOCK_SEQPACKET` socketpair are whole `serde_json`-encoded messages
per `send()`/`recv()` call — `SOCK_SEQPACKET` preserves message boundaries,
so no length-prefixing is needed (a plain `SOCK_STREAM` would need one).
Every `recv` goes through `recv_sync_timeout()` with a duration argument
(10s for pre-map sync, 30s for post-map/PID-report, matching PROMPT.md's own
values) using `poll()` before `recv()` so a wedged stage fails loudly
instead of hanging the test suite (or, later, the real runtime) forever.

## 6. Testing strategy summary

- `cargo test -p kestrel-ns` (no root, runs on every `make test`): `NsType`
  flag/name mapping, `render_map()` formatting, `write_id_maps()`'s
  CVE-2014-8989 ordering (via `run_isolated`, unprivileged userns is
  sufficient), the full three-stage dance end-to-end for a non-net
  namespace set (via `run_isolated`), `join_namespaces()` ordering
  (user-first fails, canonical order succeeds).
- `sudo -E cargo test -p kestrel-ns -- --ignored` (root, run manually via
  `make test-root` inside the VM — not part of `make test`, matching
  Phase 0's own `test-root` Makefile target stub): namespace pinning,
  `test_single_threaded` under real runtime-like conditions, and anything
  touching `/run/kestrel`.
- Every test that forks (`run_isolated`) must reap its child unconditionally
  (even on the assertion-failure path) — a leaked zombie or orphaned
  namespace-holding process would otherwise accumulate across test runs
  inside the VM. `run_isolated` handles this by always `waitpid`-ing in the
  parent regardless of what the child returned.

## Out of scope for this increment

Phase 3 (cgroups — `CLONE_INTO_CGROUP`'s real fd), Phase 4 (rootfs/overlay/
pivot_root — stage2's actual container setup beyond becoming PID 1), Phase 5
(security), and wiring any of this into `kestrel-runtime`'s CLI (Phase 8).
Phase 2 produces a standalone, fully-tested `kestrel-ns` library; nothing
calls it yet outside its own test suite.
