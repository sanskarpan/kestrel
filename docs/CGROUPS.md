# docs/CGROUPS.md — cgroups v2 in Kestrel

Unified hierarchy, controller enabling, no-internal-process rule, PSI, and `clone3`.

## Layout & Detection

```
// single unified mount
/sys/fs/cgroup/
  cgroup.controllers          "cpuset cpu io memory hugetlb pids"
  cgroup.subtree_control      "+cpu +memory +pids"   ← what CHILDREN may use
  cgroup.procs
  cpu.pressure  memory.pressure  io.pressure
  kestrel/
    cgroup.subtree_control    "+cpu +memory +pids +io"
    <id>/
      cgroup.procs  cgroup.threads  cgroup.freeze  cgroup.kill
      cgroup.events             "populated 0/1"
      cpu.max  cpu.weight  cpu.stat  cpu.pressure
      memory.max  memory.high  memory.low  memory.min  memory.swap.max
      memory.current  memory.peak  memory.events  memory.stat
      io.max  io.weight  io.stat  io.pressure
      pids.max  pids.current
      cpuset.cpus  cpuset.mems
```

`CgroupManager::new` verifies v2 by `statfs` magic `CGROUP2_SUPER_MAGIC` and refuses v1/hybrid with `systemd.unified_cgroup_hierarchy=1`.

```
                    ┌─────────────────┐
                    │ /sys/fs/cgroup  │  root (no processes except PID 1)
                    └────────┬────────┘
                             │ subtree_control: +cpu +memory +pids
                    ┌────────▼────────┐
                    │    kestrel/     │  intermediate (no processes — Rule 2)
                    └────────┬────────┘
                             │ subtree_control: +cpu +memory +pids +io …
              ┌──────────────┼──────────────┐
     ┌────────▼───┐   ┌──────▼─────┐  ┌────▼─────┐
     │  <id-a>    │   │  <id-b>    │  │  <id-c>  │  leaves (containers live here)
     │ cgroup.procs│   │ cgroup.procs│  │ cgroup.procs│
     └────────────┘   └────────────┘  └──────────┘
```

## Two Structural Rules

**Rule 1 — top-down enabling.** A controller's interface files appear in a cgroup only if the *parent* listed it in `cgroup.subtree_control`. Enabling in children does not enable in self.

```rust
fn enable_controllers_in_parents(&self) -> Result<()> {
    // walk root → parent, writing "+cpu +memory +io +pids" at each level
    // stop BEFORE the leaf — never enable in the leaf itself
}
```

**Rule 2 — no internal processes.** A cgroup with `subtree_control` set may not contain processes (except root). Containers always get a leaf. `test_no_internal_processes` asserts that `write(cgroup.procs)` fails when `subtree_control` is set.

## Controller Reference

| OCI field | File | Format | Notes |
|-----------|------|--------|-------|
| `cpu.quota`/`period` | `cpu.max` | `"<quota> <period>"` or `"max <period>"` | `-1`/`0` → `"max"` |
| `cpu.shares` | `cpu.weight` | `1..10000` | `1 + (s-2)*9999/262142` (v1→v2) |
| `cpu.cpus`/`mems` | `cpuset.cpus`/`mems` | list/range | |
| `memory.limit` | `memory.max` | bytes or `"max"` | hard limit |
| `memory.reservation` | `memory.high` | bytes | throttle, not kill |
| `memory.swap` | `memory.swap.max` | bytes | v2 swap is *separate* (not mem+swap) |
| `pids.limit` | `pids.max` | int or `"max"` | `fork` returns `EAGAIN` |
| `blockIO.*` | `io.max` `io.weight` | `rbps/wbps/riops/wiops` per device | |
| `hugepageLimits` | `hugetlb.<size>.max` | bytes | if controller present |

Helper `fmt_limit(limit)` maps `0`/`-1`/`"max"` → `"max"`.

## Freezer, Kill, Populated

* **Freeze:** `cgroup.freeze = 1` → poll `cgroup.events` for `frozen 1`.
* **Kill:** `cgroup.kill = 1` (5.14+), fallback iterates `cgroup.procs`.
* **Populated:** `cgroup.events` `populated 0|1`.

## Stats & OOM

```rust
pub fn stats(&self) -> Result<CgroupStats>   // cpu.stat, memory.current/peak/stat, io.stat, pids.current
pub fn oom_events(&self) -> Result<u64>       // memory.events → oom_kill (authoritative, not exit 137)
```

The daemon polls `memory.events` at 1 Hz; `oom_kill` increment → `OomKilled` event.

## PSI — Pressure Stall Information

The most useful signal v2 added (Docker does not surface; Kestrel does).

```
$ cat /sys/fs/cgroup/kestrel/<id>/memory.pressure
some avg10=12.43 avg60=8.91 avg300=3.02 total=8213445
full avg10=4.11  avg60=2.30 avg300=0.88 total=2011923
```

* `some` — at least one task stalled.
* `full` — *every* runnable task stalled (pure lost work).
* `cpu` has no `full` on older kernels.

```rust
pub struct PsiLine { avg10, avg60, avg300, total_us }
pub struct Psi { some: PsiLine, full: Option<PsiLine> }
```

**Interpretation guide:**

| Signal | Meaning | Action |
|--------|---------|--------|
| `memory.some` rising | reclaim/thrashing | raise `memory.high` or add memory |
| `memory.full` > 0 | all tasks blocked on memory | OOM imminent |
| `cpu.some` high | throttling (`cpu.max` too tight) | raise quota or `cpu.weight` |
| `io.some`/`full` high | device contention | adjust `io.max`/`weight` |

**Threshold triggers** (event-driven, not poll): `write "some <stall_us> <window_us>"` → `poll(POLLPRI)`. Gracefully degraded when `CONFIG_PSI=n`.

## clone3 — No Window Without Limits

Classic `fork` → `write(cgroup.procs)` races: child runs briefly outside the cgroup. `clone3` with `CLONE_INTO_CGROUP` is atomic.

```rust
#[repr(C)] struct CloneArgs { flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup }
const CLONE_INTO_CGROUP: u64 = 0x2000_0000_0000;
unsafe fn clone_into_cgroup(flags: u64, cgroup_fd: RawFd) -> Result<Pid> {
    let mut args = CloneArgs { flags: flags|CLONE_INTO_CGROUP, exit_signal: SIGCHLD as u64, cgroup: cgroup_fd as u64, ..zeroed() };
    let rc = syscall(SYS_clone3, &mut args, size_of::<CloneArgs>());
    ...
}
```

Falls back to `fork` + `cgroup.procs` on `ENOSYS`. `test_clone_into_cgroup_no_window` asserts a memory bomb on first instruction still OOM-kills.

## Further Reading

* `crates/kestrel-cgroup/src/lib.rs`
* `docs/superpowers/specs/2026-08-01-phase3-cgroups-design.md`
* SPEC §5, CHECKLIST Phase 3
