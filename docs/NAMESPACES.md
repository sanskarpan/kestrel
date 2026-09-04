# docs/NAMESPACES.md — Linux Namespaces in Kestrel

All 8 namespaces, creation ordering, the three-stage dance, pinning, and `setns` join order.

## The 8 Types

| # | Type | Flag | Proc name | Isolates | Since |
|---|------|------|-----------|----------|-------|
| 1 | Mount | `CLONE_NEWNS` | `mnt` | mount table | 2.4.19 |
| 2 | UTS | `CLONE_NEWUTS` | `uts` | hostname, domainname | 2.6.19 |
| 3 | IPC | `CLONE_NEWIPC` | `ipc` | SysV IPC, POSIX mqueues | 2.6.19 |
| 4 | PID | `CLONE_NEWPID` | `pid` | PID number space (PID 1) | 2.6.24 |
| 5 | Network | `CLONE_NEWNET` | `net` | interfaces, routes, iptables, sockets | 2.6.29 |
| 6 | User | `CLONE_NEWUSER` | `user` | UID/GID, capabilities, keys | 3.8 |
| 7 | Cgroup | `CLONE_NEWCGROUP` | `cgroup` | cgroup root view | 4.6 |
| 8 | Time | `CLONE_NEWTIME` | `time` | `CLOCK_MONOTONIC`/`BOOTTIME` offsets | 5.6 |

`CLONE_NEWTIME = 0x80` is not in `nix`; `kestrel-ns::types::NsType` defines it manually.

```rust
// crates/kestrel-ns/src/types.rs
pub enum NsType { Mount, Uts, Ipc, Pid, Net, User, Cgroup, Time }
impl NsType {
    pub fn clone_flag(self) -> CloneFlags { /* … */ }
    pub fn proc_name(self) -> &'static str { /* "mnt"/"uts"/… */ }
}
```

---

## Why Ordering Matters

Three constraints conflict:

1. **User ns must be first** (unprivileged): inside a new userns you hold a full cap set, which is what makes the remaining `unshare`s possible without real root.
2. **uid/gid maps must be written from *outside*** the new userns (needs `CAP_SETUID` in the parent ns). One `write()` per map, `setgroups=deny` before `gid_map` (CVE-2014-8989).
3. **`unshare(CLONE_NEWPID)` does not move the caller.** It only affects children. The next `fork()` produces PID 1; the caller stays in the old PID ns.

Solution: a three-stage fork dance (cf. `runc` `nsexec.c`, but pure Rust — possible because `kestrel-runtime` is single-threaded).

---

## The Three-Stage Dance

```
STAGE 0  kestrel-runtime (parent, host PID ns)
  │
  ├─ socketpair(AF_UNIX, SOCK_SEQPACKET)  ← sync channel
  │
  ├─ clone/unshare  CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS
  │                | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME
  │                └─ NOT CLONE_NEWPID  (see constraint 3)
  │       │
  │       ▼
  │   STAGE 1  child (all ns except PID)
  │     │
  │     ├─ send  RequestMaps  ─────────►  STAGE 0
  │     │                                 ├─ write /proc/<child>/uid_map
  │     │                                 ├─ write /proc/<child>/setgroups = "deny"
  │     │                                 ├─ write /proc/<child>/gid_map   (single write, all lines)
  │     │                                 └─ send  MapsDone  ─────────► STAGE 1
  │     │
  │     ├─ setresuid(0,0,0) / setresgid(0,0,0)  ← now root inside userns
  │     ├─ unshare(CLONE_NEWPID)                ← affects children only
  │     ├─ fork() ──► STAGE 2  (grandchild, becomes PID 1)
  │     │               │
  │     │               ├─ join cgroup (or CLONE_INTO_CGROUP via clone3)
  │     │               ├─ mount("/", MS_REC|MS_PRIVATE)  ← detach from host propagation
  │     │               ├─ overlay mount → pivot_root(".", ".") → umount old root
  │     │               ├─ sethostname, time offsets, createContainer hooks
  │     │               ├─ block on exec.fifo  ← create ≠ start
  │     │               ├─ startContainer hooks → caps → no_new_privs → seccomp → execve
  │     │               └─ signalfd reaper loop (SIGCHLD → waitpid(-1, WNOHANG) loop)
  │     │
  │     ├─ send ReportPid(grandchild_pid) ──► STAGE 0
  │     └─ _exit(0)   ← dies; PID 1 reparented to host init
  │
  ├─ recv grandchild PID
  ├─ write state.json atomically (temp+rename), pin ns, create exec.fifo
  └─ exit (create) / wait (run)
```

**Sync protocol** (`kestrel-ns::sync`): `RequestMaps | MapsDone | ReportPid(i32) | Ready | Error(String)`, every stage writes errors to the socket, every read has a timeout — a wedged stage fails instead of hanging.

**ASCII timing** (what `--verbose` traces):

```
[0.000] STAGE0 clone  userns+mnt+uts+ipc+net+cgroup+time
[0.002] STAGE1 RequestMaps
[0.003] STAGE0 write uid_map/gid_map
[0.004] STAGE1 setresuid → unshare(NEWPID) → fork
[0.005] STAGE2 PID1: private mounts → overlay → pivot_root
[0.020] STAGE2 block on exec.fifo (created)
[0.021] STAGE0 ReportPid(12345) → state.json
```

---

## Pinning & Joining

Namespaces die with the last task *unless* pinned. For `kestrel exec` the runtime bind-mounts `/proc/<pid>/ns/<type>` → `/run/kestrel/<id>/ns/<type>` (`kestrel-ns::pin`):

```rust
pub fn pin_namespace(pid: Pid, ns: NsType, target: &Path) -> Result<()> {
    File::create(target)?;
    mount(Some(format!("/proc/{pid}/ns/{}", ns.proc_name())), target, None::<&str>, MS_BIND, None::<&str>)?;
    Ok(())
}
pub fn unpin_namespace(target: &Path) -> Result<()> {
    umount2(target, MNT_DETACH)?; fs::remove_file(target)?;
    Ok(())
}
```

**Join order matters.** Entering the user ns drops caps needed for the others, so it is *last*:

```
Cgroup → Ipc → Uts → Net → Pid → Mount → Time → User   (kestrel-ns::join::ORDER)
```

`test_join_order` proves the reverse fails.

## Network Namespace Isolation in Tests

`kestrel-net`'s integration tests never touch the host. `tests/common/mod.rs::run_in_isolated_netns` does:

```
tokio::spawn_blocking → fork (now single-threaded) → unshare(CLONE_NEWNET) → build multi_thread runtime AFTER unshare → rt.block_on(test_body)
```

Runtime is built *after* `unshare` so every worker thread inherits the new netns at `clone()` time. `block_in_place` is required inside `attach_veth`'s `nsenter` — hence the outer runtime must be `multi_thread` (see that file's flavor note).

Netns pinning for containers (`kestrel-net::netns::create_netns`) avoids raw `fork` entirely — it spawns `netns-helper` via `tokio::process::Command` (which uses `posix_spawn`) and pins ` /proc/<helper>/ns/net`.

## Threading Invariant

`kestrel-runtime` asserts `Threads: 1` at startup (`kestrel-ns::threading::assert_single_threaded`). The daemon (`kestreld`) is multi-threaded but `fork+exec`s the runtime — never links it.

## Further Reading

* `crates/kestrel-ns/src/{types,idmap,pin,join,stages,sync,threading}.rs`
* `docs/superpowers/specs/2026-07-31-phase2-namespaces-design.md`
* SPEC §4, CHECKLIST Phase 2
