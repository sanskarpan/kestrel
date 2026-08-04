# Kestrel — Phase 3 (cgroups v2) Design

## Context

Phase 3 builds `kestrel-cgroup`: the cgroup v2 manager (top-down controller
enabling, resource limits, freezer, atomic kill), PSI parsing, OOM
detection, and the `clone3`/`CLONE_INTO_CGROUP` glue that finally lets
Phase 2's `run_stages()` place a container's PID 1 into its cgroup
atomically instead of always taking the `fork()` fallback path (`cgroup_fd:
None`) it's been limited to since Task 8. PROMPT.md's "Phase 3 — cgroups
v2" section and SPEC.md §5 already give this in full code detail — this
document covers what those don't: environment specifics for this VM and
the same kind of root/non-root test split Phase 2 needed.

## 1. Environment check (done against the live VM)

`/sys/fs/cgroup` is cgroup2, unified, with `cpuset cpu io memory hugetlb
pids rdma misc` all available and `cpuset cpu io memory pids` already
enabled in the root's `subtree_control` (systemd's own doing). Creating
`/sys/fs/cgroup/kestrel/` requires root (`mkdir` fails unprivileged,
succeeds via `sudo`) — expected, matches CHECKLIST's assumption that
cgroup management is a privileged operation. No delegation setup is needed
beyond that for this dev VM (we're not running as a systemd-managed
service with `Delegate=yes`, we're root directly).

## 2. Crate structure (`crates/kestrel-cgroup`)

Per SPEC §16 and §5.2's `CgroupManager` sketch:

- `src/lib.rs` — re-exports
- `src/manager.rs` — `CgroupManager { root, path, delegated }`,
  `create()`/`destroy()`, `enable_controllers_in_parents()`,
  `add_process()`
- `src/resources.rs` — `apply()` translating `LinuxResources` (from
  `kestrel-oci`) into the controller writes: `cpu.max`/`cpu.weight`
  (with the v1-shares→v2-weight conversion), `cpuset.cpus`/`mems`,
  `memory.max`/`.high`/`.low`/`.min`/`.swap.max`, `pids.max`,
  `io.max`/`.weight`, `hugetlb.*.max` when present
- `src/control.rs` — `freeze()`, `kill_all()`, `is_populated()`
- `src/stats.rs` — `stats()` parsing `cpu.stat`, `memory.current/peak/stat`,
  `io.stat`, `pids.current`; `oom_kill_count()` from `memory.events`
  (authoritative — **not** exit code 137)
- `src/psi.rs` — `Psi`/`PsiLine` parser for `cpu.pressure`/
  `memory.pressure`/`io.pressure`, plus the `poll(POLLPRI)`-based trigger
  watcher
- `src/clone3.rs` — `CloneArgs` repr(C), `CLONE_INTO_CGROUP`,
  `clone_into_cgroup()` — this is what Phase 2's `stages.rs` `Some(_fd) =>
  bail!(...)` branch has been waiting for

`kestrel-ns`'s `stages.rs` gets a small, targeted change: the
`cgroup_fd: Option<RawFd>` branch that currently always `bail!`s gets
wired to actually call `kestrel_cgroup::clone3::clone_into_cgroup()`. This
means `kestrel-ns` gains a dependency on `kestrel-cgroup` — worth calling
out since it reverses the layering a reader might assume (cgroup depends on
ns, not the other way around) but matches PROMPT.md's own sketch (`stages.rs`
takes a `cgroup_fd` parameter and calls a clone3 helper directly).

## 3. Root vs. non-root test split (same pattern as Phase 2)

- **No root needed**: PSI parsing (pure string parsing against captured
  fixtures), `shares_to_weight()`/`fmt_limit()` unit conversions, stats
  parsing against fixture strings, `CgroupManager` path-construction logic.
- **Needs real root** (`#[ignore]`, run via `make test-root`): creating
  real cgroups under `/sys/fs/cgroup/kestrel/<id>`, writing real limits and
  observing kernel enforcement (`test_memory_limit_ooms`,
  `test_cpu_throttle`, `test_pids_limit`, `test_freeze_thaw`,
  `test_no_internal_processes`), and `clone_into_cgroup()`'s integration
  with `kestrel-ns::stages::run_stages`.

## 4. Known risk to watch for, given Phase 2's history

Phase 2 surfaced two real, non-obvious environment limits in this VM
(mount-namespace nsfs binding, root's capability-ownership rule). Phase 3's
cgroup writes and `clone3` usage are a different syscall surface, but the
same posture applies: verify claims empirically against the real VM rather
than assuming PROMPT.md's sketch works unmodified, and if something doesn't
work, diagnose before working around it — don't paper over a real gap.

## Out of scope for this increment

Wiring `kestrel-cgroup` into `kestrel-runtime`'s actual CLI (`create`/
`start`/etc. subcommands) is Phase 8. `nftables`/network cgroup
integration is Phase 7. This phase produces a standalone, tested
`kestrel-cgroup` library plus the one targeted `stages.rs` change enabling
real `CLONE_INTO_CGROUP` usage.
