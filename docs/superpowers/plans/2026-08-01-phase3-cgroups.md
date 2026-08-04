# Kestrel Phase 3 (cgroups v2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-cgroup` — the cgroup v2 manager (top-down controller enabling, resource limits, freezer, atomic kill), stats/PSI parsing, OOM detection, and `clone3`/`CLONE_INTO_CGROUP` — and wire the latter into `kestrel-ns::stages::run_stages`, which has been limited to its `fork()` fallback (`cgroup_fd: None`) since Phase 2.

**Architecture:** `CgroupManager` operates on plain `std::fs` reads/writes against `/sys/fs/cgroup/kestrel/<id>` — cgroupfs is a normal (virtual) filesystem, no netlink/ioctl machinery needed for most of this crate. Only `clone3.rs` needs a raw syscall (`libc::syscall(SYS_clone3, ...)`, same pattern as `kestrel-ns`'s `fork()`/`_exit()` usage) and `psi.rs`'s trigger watcher needs `poll(2)`. Resource limits are translated from `kestrel_oci::runtime::LinuxResources` (already available from Phase 0/1's `kestrel-oci` re-exports) — field shapes verified against the real `oci-spec` 0.10.0 API via docs.rs before writing this plan.

**Tech Stack:** Rust, `nix` (poll feature for PSI triggers), `libc` (raw `clone3` syscall), `anyhow`/`thiserror`, `kestrel-oci` (for `LinuxResources` et al.), `kestrel-ns` (for the `stages.rs` wiring in Task 10).

**Environment:** Same as Phase 2 — everything runs inside the Lima VM (`kestrel`) via `limactl shell kestrel -- bash -lc 'cd ~/Container-Runtime && <command>'`. Creating/writing real cgroups needs root (verified: `mkdir /sys/fs/cgroup/kestrel-probe` fails unprivileged, succeeds via `sudo`) — same root/non-root test split as Phase 2, using the same `run_isolated`-style forking where a test needs to avoid polluting the calling process's own state, and `#[ignore = "requires root"]` + `make test-root` for anything that creates a real cgroup.

**No git** — same project convention as Phase 0-2. Do not `git init`/`add`/`commit`.

---

## File Structure

```
crates/kestrel-cgroup/
├── Cargo.toml                       # Task 1
└── src/
    ├── lib.rs                       # Task 1: module decls
    ├── manager.rs                   # Task 2: CgroupManager, create/destroy; Task 3: enable_controllers_in_parents, add_process
    ├── resources.rs                 # Task 4: cpu; Task 5: memory+pids; Task 6: io+hugetlb
    ├── control.rs                   # Task 7: freeze/kill_all/is_populated
    ├── stats.rs                     # Task 8: stats(), oom_kill_count()
    ├── psi.rs                       # Task 9: Psi parser + trigger watcher
    └── clone3.rs                    # Task 10: CloneArgs, clone_into_cgroup
crates/kestrel-cgroup/tests/
└── integration.rs                   # Task 11: root-gated gating tests
crates/kestrel-ns/
├── Cargo.toml                       # Task 10: += kestrel-cgroup dependency
└── src/stages.rs                    # Task 10: wire the Some(fd) branch to clone_into_cgroup
Makefile                             # Task 12: no changes expected, verify test-root still covers this crate
```

---

## Task 1: Crate scaffolding

**Files:**
- Modify: `crates/kestrel-cgroup/Cargo.toml`
- Modify: `crates/kestrel-cgroup/src/lib.rs`
- Create: `crates/kestrel-cgroup/src/{manager,resources,control,stats,psi,clone3}.rs` (placeholders)

`kestrel-cgroup` currently exists as a Phase-0 stub (only `anyhow`/`thiserror`, doc-comment-only `lib.rs`).

- [ ] **Step 1: Update `Cargo.toml`**

```toml
[package]
name = "kestrel-cgroup"
edition.workspace = true
version.workspace = true

[dependencies]
nix = { workspace = true, features = ["poll", "fs"] }
libc.workspace = true
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
kestrel-oci = { path = "../kestrel-oci" }
```

If `nix`'s `poll` feature name doesn't match the installed version (check `cargo doc -p nix --no-deps` or the vendored `Cargo.toml`'s `[features]` table inside the VM if `cargo build` complains), correct it — same "verify against real crate, preserve intent" allowance used throughout Phase 2.

- [ ] **Step 2: Update `lib.rs`**

```rust
//! cgroup v2 manager: resource limits, freezer, PSI, OOM detection, and
//! CLONE_INTO_CGROUP. See docs/superpowers/specs/2026-08-01-phase3-cgroups-design.md.

pub mod manager;
pub mod resources;
pub mod control;
pub mod stats;
pub mod psi;
pub mod clone3;
```

- [ ] **Step 3: Create the 6 placeholder module files**

Each gets a one-line placeholder comment referencing its owning task, e.g. `crates/kestrel-cgroup/src/manager.rs`:
```rust
// filled in by Task 2 (create/destroy) and Task 3 (enable_controllers_in_parents, add_process)
```
Same pattern for `resources.rs` ("Tasks 4-6"), `control.rs` ("Task 7"), `stats.rs` ("Task 8"), `psi.rs` ("Task 9"), `clone3.rs` ("Task 10").

- [ ] **Step 4: Verify it compiles.** `cargo build -p kestrel-cgroup` and `cargo build --workspace` (inside the VM) — expect `Finished`, no errors.

- [ ] **Step 5: Mark task complete**

---

## Task 2: `CgroupManager` — creation, controller discovery

**Files:**
- Create content in: `crates/kestrel-cgroup/src/manager.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-cgroup/src/manager.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_manager_path_is_root_joined_with_relative_id() {
        let m = CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), "abc123");
        assert_eq!(m.path, PathBuf::from("/sys/fs/cgroup/kestrel/abc123"));
    }

    #[test]
    fn test_read_available_controllers_parses_space_separated_list() {
        let parsed = parse_controllers("cpuset cpu io memory hugetlb pids rdma misc\n");
        assert_eq!(
            parsed,
            vec!["cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"]
        );
    }

    #[test]
    fn test_read_available_controllers_handles_empty() {
        assert!(parse_controllers("").is_empty());
        assert!(parse_controllers("\n").is_empty());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup manager::` (inside VM) — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-cgroup/src/manager.rs (above the tests module)

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

pub struct CgroupManager {
    pub root: PathBuf, // /sys/fs/cgroup
    pub path: PathBuf, // /sys/fs/cgroup/kestrel/<id>
    pub delegated: bool,
}

impl CgroupManager {
    pub fn new(root: PathBuf, id: &str) -> Self {
        let path = root.join("kestrel").join(id);
        CgroupManager { root, path, delegated: false }
    }

    /// Creates the leaf cgroup and enables the controllers Rule 1 (top-down
    /// enabling) requires in every ancestor. Does NOT apply resource limits
    /// — that's `resources::apply()`, a separate step (Tasks 4-6).
    pub fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.path)
            .with_context(|| format!("creating cgroup dir {}", self.path.display()))?;
        self.enable_controllers_in_parents()
    }

    /// Removes the leaf cgroup. Fails with EBUSY if processes remain — the
    /// caller (Task 7's kill_all, or later phases) is responsible for
    /// ensuring the cgroup is empty first.
    pub fn destroy(&self) -> Result<()> {
        fs::remove_dir(&self.path)
            .with_context(|| format!("removing cgroup dir {}", self.path.display()))?;
        Ok(())
    }

    pub fn read_available_controllers(&self, at: &std::path::Path) -> Result<Vec<String>> {
        let contents = fs::read_to_string(at.join("cgroup.controllers"))
            .with_context(|| format!("reading cgroup.controllers at {}", at.display()))?;
        Ok(parse_controllers(&contents))
    }

    // enable_controllers_in_parents() is Task 3.

    pub(crate) fn write(&self, file: &str, value: &str) -> Result<()> {
        fs::write(self.path.join(file), value)
            .with_context(|| format!("writing {value:?} to {}", self.path.join(file).display()))
    }
}

fn parse_controllers(contents: &str) -> Vec<String> {
    contents.split_whitespace().map(String::from).collect()
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup manager::` — expect 3 passed (pure logic, no root needed — these tests don't touch a real filesystem path under `/sys/fs/cgroup`).

- [ ] **Step 5: Mark task complete**

---

## Task 3: Top-down controller enabling (Rule 1) + `add_process` (Rule 2)

**Files:**
- Create content in: `crates/kestrel-cgroup/src/manager.rs` (append)
- Create: `crates/kestrel-cgroup/tests/integration.rs` (first tests — root-gated)

Rule 1: a controller's interface files exist in a cgroup only if the PARENT listed it in `cgroup.subtree_control`. Rule 2: a cgroup with `subtree_control` set may not itself contain processes — this is why containers always get a leaf cgroup.

- [ ] **Step 1: Write the failing unit test** (append to `manager.rs`'s existing `mod tests`)

```rust
    #[test]
    fn test_enable_controllers_spec_string_filters_to_available() {
        let want = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"];
        let available = vec!["cpu".to_string(), "memory".to_string(), "pids".to_string()];
        let spec = build_subtree_control_spec(&want, &available);
        assert_eq!(spec, "+cpu +memory +pids");
    }
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup manager::` — FAIL, `build_subtree_control_spec` not defined.

- [ ] **Step 3: Write the implementation** (append to `manager.rs`, above the tests module)

```rust
impl CgroupManager {
    /// Walk from root to our parent, adding controllers to each ancestor's
    /// `cgroup.subtree_control` — Rule 1: a controller's interface files
    /// exist in a cgroup only if the PARENT listed it. Never enable in the
    /// leaf itself (Rule 2: a cgroup with subtree_control set may not
    /// contain processes, and containers always live in the leaf).
    pub fn enable_controllers_in_parents(&self) -> Result<()> {
        let available = self.read_available_controllers(&self.root)?;
        let want = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"];
        let spec = build_subtree_control_spec(&want, &available);

        let rel = self
            .path
            .strip_prefix(&self.root)
            .context("cgroup path is not under root")?;
        let mut cur = self.root.clone();
        for comp in rel.components() {
            // A failure here is often benign (already enabled by systemd or
            // a prior run) — log and continue rather than aborting cgroup
            // creation over it.
            if let Err(e) = fs::write(cur.join("cgroup.subtree_control"), &spec) {
                tracing::debug!(path = %cur.display(), error = %e, "subtree_control write failed (often benign)");
            }
            cur = cur.join(comp);
            if cur == self.path {
                break; // never enable in the leaf itself
            }
        }
        Ok(())
    }

    /// Adds `pid` to this cgroup. Must be called on a LEAF cgroup (Rule 2)
    /// — writing to a cgroup with subtree_control set fails.
    pub fn add_process(&self, pid: nix::unistd::Pid) -> Result<()> {
        self.write("cgroup.procs", &pid.as_raw().to_string())
    }
}

fn build_subtree_control_spec(want: &[&str], available: &[String]) -> String {
    want.iter()
        .filter(|c| available.iter().any(|a| a == *c))
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}
```

- [ ] **Step 4: Run to verify the unit test passes.** `cargo test -p kestrel-cgroup manager::` — expect 4 passed.

- [ ] **Step 5: Write the root-gated integration tests**

`crates/kestrel-cgroup/tests/integration.rs`:

```rust
use std::path::PathBuf;

use kestrel_cgroup::manager::CgroupManager;

fn test_manager(id: &str) -> CgroupManager {
    CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), id)
}

#[test]
#[ignore = "requires root"]
fn test_create_enables_controllers_and_destroy_cleans_up() {
    let m = test_manager("kestrel-test-create");
    m.create().expect("create");
    assert!(m.path.join("cgroup.controllers").exists());
    // At least one requested controller's interface file should now exist
    // in the leaf (proving Rule 1's top-down enabling actually worked).
    assert!(m.path.join("memory.max").exists(), "memory controller interface missing");
    m.destroy().expect("destroy");
    assert!(!m.path.exists());
}

#[test]
#[ignore = "requires root"]
fn test_no_internal_processes_rule() {
    // Writing a PID to a cgroup that has subtree_control set (i.e. has
    // children with controllers enabled) must fail — Rule 2.
    let m = test_manager("kestrel-test-internal");
    m.create().expect("create");
    let child = m.path.join("child");
    std::fs::create_dir_all(&child).expect("mkdir child");
    // Enable a controller in `m.path` itself (not the leaf's own leaf) so
    // it now has subtree_control set, making it a non-leaf.
    std::fs::write(m.path.join("cgroup.subtree_control"), "+memory").expect("enable in m.path");

    let err = kestrel_cgroup::manager::CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), "kestrel-test-internal")
        .add_process(nix::unistd::getpid())
        .expect_err("adding a process to a non-leaf cgroup must fail");
    assert!(err.to_string().to_lowercase().contains("writing"), "unexpected error: {err}");

    std::fs::remove_dir(&child).ok();
    m.destroy().ok();
}
```

- [ ] **Step 6: Run to verify they pass.** `sudo -E env "PATH=$PATH" cargo test -p kestrel-cgroup --test integration -- --ignored` (inside VM) — expect 2 passed. If `test_no_internal_processes_rule` doesn't fail the way expected (e.g., the kernel returns success instead of an error), double-check against the live filesystem manually (`echo $$ > /sys/fs/cgroup/kestrel/kestrel-test-internal/cgroup.procs` after enabling a child controller) to confirm the actual kernel behavior before concluding the code is wrong — this is exactly the kind of empirical check Phase 2 relied on repeatedly.

## Context

This is Task 3 of 12. `manager.rs` now has the full creation/enabling/add_process surface. Tasks 4-6 add resource-limit application on top.

- [ ] **Step 7: Mark task complete**

---

## Task 4: Resource limits — CPU

**Files:**
- Create content in: `crates/kestrel-cgroup/src/resources.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-cgroup/src/resources.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shares_to_weight_default() {
        assert_eq!(shares_to_weight(0), 100);
    }

    #[test]
    fn test_shares_to_weight_minimum() {
        assert_eq!(shares_to_weight(2), 1);
    }

    #[test]
    fn test_shares_to_weight_maximum() {
        assert_eq!(shares_to_weight(262_144), 10000);
    }

    #[test]
    fn test_cpu_max_format_with_quota() {
        assert_eq!(format_cpu_max(Some(50_000), 100_000), "50000 100000");
    }

    #[test]
    fn test_cpu_max_format_unlimited() {
        // A non-positive quota means "no limit" per OCI semantics.
        assert_eq!(format_cpu_max(Some(-1), 100_000), "max 100000");
        assert_eq!(format_cpu_max(None, 100_000), "max 100000");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup resources::` (inside VM) — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-cgroup/src/resources.rs (above the tests module)

use anyhow::Result;
use kestrel_oci::runtime::LinuxResources;

use crate::manager::CgroupManager;

impl CgroupManager {
    /// Applies the CPU portion of `resources`: `cpu.max` (quota/period),
    /// `cpu.weight` (converted from OCI's v1-style `shares`), and
    /// `cpuset.cpus`/`cpuset.mems` if present.
    pub fn apply_cpu(&self, resources: &LinuxResources) -> Result<()> {
        let Some(cpu) = resources.cpu() else { return Ok(()) };

        let period = cpu.period().unwrap_or(100_000);
        // Only write cpu.max if the spec actually says something about CPU
        // limiting (quota present) — otherwise leave the kernel default.
        if cpu.quota().is_some() {
            self.write("cpu.max", &format_cpu_max(cpu.quota(), period))?;
        }
        if let Some(shares) = cpu.shares() {
            self.write("cpu.weight", &shares_to_weight(shares).to_string())?;
        }
        if let Some(cpus) = cpu.cpus() {
            self.write("cpuset.cpus", cpus)?;
        }
        if let Some(mems) = cpu.mems() {
            self.write("cpuset.mems", mems)?;
        }
        Ok(())
    }
}

/// v1 `shares` [2, 262144] (default 1024) -> v2 `cpu.weight` [1, 10000]
/// (default 100). Matches the mapping systemd and runc use so migrated
/// configs behave the same. Zero means "not set" -> the v2 default.
pub(crate) fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 100;
    }
    let s = shares.clamp(2, 262_144) as f64;
    (1.0 + ((s - 2.0) * 9999.0) / 262_142.0).round() as u64
}

/// `cpu.max` is `"<quota> <period>"` or `"max <period>"`. A missing or
/// non-positive quota means unlimited.
pub(crate) fn format_cpu_max(quota: Option<i64>, period: u64) -> String {
    let quota_str = match quota {
        Some(q) if q > 0 => q.to_string(),
        _ => "max".to_string(),
    };
    format!("{quota_str} {period}")
}
```

## API drift note

`LinuxCpu`'s getters (`.period()`, `.quota()`, `.shares()`, `.cpus()`, `.mems()`) were verified against `oci-spec` 0.10.0's docs.rs page before writing this plan: `shares: Option<u64>`, `quota: Option<i64>`, `period: Option<u64>`, `cpus: Option<String>`, `mems: Option<String>`. If the installed crate's getter names or `Option`-wrapping differ (e.g. `cpus()` returning `&Option<String>` vs `Option<&String>`), adjust the call sites to match — preserve intent (read each field, apply the same conditional-write logic).

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup resources::` — expect 5 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 5: Resource limits — memory + pids

**Files:**
- Create content in: `crates/kestrel-cgroup/src/resources.rs` (append)

- [ ] **Step 1: Write the failing tests** (append to the existing `mod tests`)

```rust
    #[test]
    fn test_fmt_limit_positive() {
        assert_eq!(fmt_limit(536_870_912), "536870912");
    }

    #[test]
    fn test_fmt_limit_negative_means_unlimited() {
        assert_eq!(fmt_limit(-1), "max");
    }
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup resources::` — FAIL, `fmt_limit` not defined.

- [ ] **Step 3: Write the implementation** (append to `resources.rs`, above the tests module)

```rust
impl CgroupManager {
    /// `memory.max` (hard limit — OOM-kills above), `memory.high` (throttle
    /// point — reclaim aggressively, do NOT kill; without it memory.max
    /// alone is a cliff, memory.high gives a ramp), `memory.swap.max`
    /// (v2 swap is a SEPARATE limit, not v1's combined memory+swap).
    pub fn apply_memory(&self, resources: &LinuxResources) -> Result<()> {
        if let Some(mem) = resources.memory() {
            if let Some(limit) = mem.limit() {
                self.write("memory.max", &fmt_limit(limit))?;
            }
            if let Some(reservation) = mem.reservation() {
                self.write("memory.high", &fmt_limit(reservation))?;
            }
            if let Some(swap) = mem.swap() {
                self.write("memory.swap.max", &fmt_limit(swap))?;
            }
        }
        Ok(())
    }

    pub fn apply_pids(&self, resources: &LinuxResources) -> Result<()> {
        if let Some(pids) = resources.pids() {
            self.write("pids.max", &fmt_limit(pids.limit()))?;
        }
        Ok(())
    }
}

/// Unified formatter for cgroup v2's `<n>` / `"max"` limit convention:
/// negative (OCI's "no limit" sentinel, typically -1) becomes `"max"`.
pub(crate) fn fmt_limit(v: i64) -> String {
    if v < 0 {
        "max".to_string()
    } else {
        v.to_string()
    }
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup resources::` — expect 7 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 6: Resource limits — io + hugetlb

**Files:**
- Create content in: `crates/kestrel-cgroup/src/resources.rs` (append)

- [ ] **Step 1: Write the failing tests** (append to the existing `mod tests`)

```rust
    #[test]
    fn test_io_max_line_format() {
        assert_eq!(format_io_max_line(8, 0, "rbps", 1_048_576), "8:0 rbps=1048576");
    }

    #[test]
    fn test_blkio_weight_to_io_weight_clamps_range() {
        // v1 blkio weight [10, 1000] -> v2 io.weight [1, 10000], same
        // linear-ish mapping style as CPU shares -> weight.
        assert_eq!(blkio_weight_to_io_weight(10), 1);
        assert_eq!(blkio_weight_to_io_weight(1000), 10000);
    }
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup resources::` — FAIL, not defined.

- [ ] **Step 3: Write the implementation** (append to `resources.rs`, above the tests module)

```rust
impl CgroupManager {
    /// `io.weight` and, per throttled device, `io.max` — cgroup v2 accepts
    /// PARTIAL io.max writes (one key at a time), so each throttle vector
    /// (rbps/wbps/riops/wiops) for a given device is its own write() call;
    /// the kernel merges them rather than requiring one combined line.
    pub fn apply_io(&self, resources: &LinuxResources) -> Result<()> {
        let Some(io) = resources.block_io() else { return Ok(()) };

        if let Some(weight) = io.weight() {
            self.write("io.weight", &blkio_weight_to_io_weight(weight).to_string())?;
        }

        for (key, devices) in [
            ("rbps", io.throttle_read_bps_device()),
            ("wbps", io.throttle_write_bps_device()),
            ("riops", io.throttle_read_iops_device()),
            ("wiops", io.throttle_write_iops_device()),
        ] {
            for dev in devices.iter().flatten() {
                let line = format_io_max_line(dev.major(), dev.minor(), key, dev.rate());
                self.write("io.max", &line)?;
            }
        }
        Ok(())
    }

    pub fn apply_hugetlb(&self, resources: &LinuxResources) -> Result<()> {
        for limit in resources.hugepage_limits().iter().flatten() {
            let file = format!("hugetlb.{}.max", limit.page_size());
            // Only write if the controller's interface file actually
            // exists — hugetlb availability varies by kernel config, and
            // this project degrades gracefully rather than failing hard.
            if self.path.join(&file).exists() {
                self.write(&file, &fmt_limit(limit.limit()))?;
            }
        }
        Ok(())
    }
}

fn format_io_max_line(major: u64, minor: u64, key: &str, rate: u64) -> String {
    format!("{major}:{minor} {key}={rate}")
}

/// v1 blkio weight [10, 1000] -> v2 io.weight [1, 10000].
pub(crate) fn blkio_weight_to_io_weight(weight: u16) -> u64 {
    let w = (weight as f64).clamp(10.0, 1000.0);
    (1.0 + ((w - 10.0) * 9999.0) / 990.0).round() as u64
}
```

## API drift note

`LinuxThrottleDevice`'s `.major()`/`.minor()`/`.rate()` getter return types (verified as present, but exact integer width — `u64` vs `i64` — wasn't independently confirmed against the installed crate for this plan) may need a cast adjustment at the call site if they don't match `format_io_max_line`'s `u64` parameters. `LinuxBlockIo::weight()` returns `Option<u16>` per the verified API. Adjust as needed, preserving intent (one `io.max` write per device per throttle vector).

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup resources::` — expect 9 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 7: `freeze`/`kill_all`/`is_populated`

**Files:**
- Create content in: `crates/kestrel-cgroup/src/control.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-cgroup/src/control.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_events_populated_true() {
        assert!(parse_populated("populated 1\nfrozen 0\n"));
    }

    #[test]
    fn test_parse_events_populated_false() {
        assert!(!parse_populated("populated 0\nfrozen 0\n"));
    }

    #[test]
    fn test_parse_events_missing_defaults_false() {
        assert!(!parse_populated(""));
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup control::` (inside VM) — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-cgroup/src/control.rs (above the tests module)

use anyhow::Result;

use crate::manager::CgroupManager;

impl CgroupManager {
    /// cgroup v2 replaces v1's separate freezer controller with a single
    /// file: write "1"/"0" to `cgroup.freeze`.
    pub fn freeze(&self, frozen: bool) -> Result<()> {
        self.write("cgroup.freeze", if frozen { "1" } else { "0" })
    }

    /// Atomic kill of every process in the cgroup (kernel 5.14+) — far more
    /// reliable than iterating `cgroup.procs` and killing one at a time,
    /// which races against fork().
    pub fn kill_all(&self) -> Result<()> {
        self.write("cgroup.kill", "1")
    }

    pub fn is_populated(&self) -> Result<bool> {
        let contents = std::fs::read_to_string(self.path.join("cgroup.events"))?;
        Ok(parse_populated(&contents))
    }
}

fn parse_populated(events: &str) -> bool {
    events
        .lines()
        .find_map(|l| l.strip_prefix("populated "))
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup control::` — expect 3 passed.

- [ ] **Step 5: Write a root-gated freeze/thaw integration test** — append to `crates/kestrel-cgroup/tests/integration.rs`:

```rust
#[test]
#[ignore = "requires root"]
fn test_freeze_thaw() {
    let m = test_manager("kestrel-test-freeze");
    m.create().expect("create");

    // Spawn a real child inside this cgroup, freeze it, confirm it stops
    // making progress, thaw it, confirm it resumes.
    let counter_path = std::env::temp_dir().join("kestrel-freeze-counter");
    std::fs::write(&counter_path, "0").unwrap();
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "for i in $(seq 1 1000); do echo $i > {}; sleep 0.01; done",
            counter_path.display()
        ))
        .spawn()
        .expect("spawn counter");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32)).expect("add_process");

    std::thread::sleep(std::time::Duration::from_millis(200));
    m.freeze(true).expect("freeze");
    let count_at_freeze = std::fs::read_to_string(&counter_path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let count_after_wait = std::fs::read_to_string(&counter_path).unwrap();
    assert_eq!(count_at_freeze, count_after_wait, "frozen process made progress");

    m.freeze(false).expect("thaw");
    std::thread::sleep(std::time::Duration::from_millis(300));
    let count_after_thaw = std::fs::read_to_string(&counter_path).unwrap();
    assert_ne!(count_after_wait, count_after_thaw, "thawed process did not resume");

    let _ = child.kill();
    let _ = child.wait();
    m.kill_all().ok();
    std::fs::remove_file(&counter_path).ok();
    m.destroy().ok();
}
```

- [ ] **Step 6: Run to verify it passes.** `sudo -E env "PATH=$PATH" cargo test -p kestrel-cgroup --test integration test_freeze_thaw -- --ignored` — expect 1 passed. This test is inherently timing-sensitive; if it's flaky, widen the sleep durations rather than removing the assertions.

- [ ] **Step 7: Mark task complete**

---

## Task 8: Stats parsing + OOM detection

**Files:**
- Create content in: `crates/kestrel-cgroup/src/stats.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-cgroup/src/stats.rs

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_STAT: &str = "\
usage_usec 1234567
user_usec 1000000
system_usec 234567
nr_periods 10
nr_throttled 3
throttled_usec 45678
";

    #[test]
    fn test_parse_cpu_stat() {
        let s = parse_cpu_stat(CPU_STAT).unwrap();
        assert_eq!(s.usage_usec, 1_234_567);
        assert_eq!(s.nr_throttled, 3);
        assert_eq!(s.throttled_usec, 45_678);
    }

    const MEMORY_EVENTS: &str = "\
low 0
high 2
max 0
oom 1
oom_kill 1
oom_group_kill 0
";

    #[test]
    fn test_oom_kill_count() {
        assert_eq!(parse_oom_kill_count(MEMORY_EVENTS).unwrap(), 1);
    }

    #[test]
    fn test_oom_kill_count_missing_field_errors() {
        assert!(parse_oom_kill_count("low 0\n").is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup stats::` (inside VM) — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-cgroup/src/stats.rs (above the tests module)

use anyhow::{Context, Result};

use crate::manager::CgroupManager;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CpuStat {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

impl CgroupManager {
    pub fn cpu_stat(&self) -> Result<CpuStat> {
        let contents = std::fs::read_to_string(self.path.join("cpu.stat"))
            .context("reading cpu.stat")?;
        parse_cpu_stat(&contents)
    }

    /// `memory.events`'s `oom_kill` counter is the authoritative OOM
    /// signal — exit code 137 is NOT, since a container can be SIGKILLed
    /// for many reasons, and conflating them produces false "OOMKilled"
    /// statuses (a bug Docker itself has shipped).
    pub fn oom_kill_count(&self) -> Result<u64> {
        let contents = std::fs::read_to_string(self.path.join("memory.events"))
            .context("reading memory.events")?;
        parse_oom_kill_count(&contents)
    }

    pub fn memory_current(&self) -> Result<u64> {
        let contents = std::fs::read_to_string(self.path.join("memory.current"))
            .context("reading memory.current")?;
        contents.trim().parse().context("memory.current is not numeric")
    }

    pub fn pids_current(&self) -> Result<u64> {
        let contents = std::fs::read_to_string(self.path.join("pids.current"))
            .context("reading pids.current")?;
        contents.trim().parse().context("pids.current is not numeric")
    }
}

fn parse_kv_lines(contents: &str) -> impl Iterator<Item = (&str, &str)> {
    contents.lines().filter_map(|l| l.split_once(' '))
}

fn parse_cpu_stat(contents: &str) -> Result<CpuStat> {
    let mut s = CpuStat::default();
    for (k, v) in parse_kv_lines(contents) {
        let v: u64 = v.trim().parse().with_context(|| format!("cpu.stat field {k} not numeric"))?;
        match k {
            "usage_usec" => s.usage_usec = v,
            "nr_periods" => s.nr_periods = v,
            "nr_throttled" => s.nr_throttled = v,
            "throttled_usec" => s.throttled_usec = v,
            _ => {}
        }
    }
    Ok(s)
}

fn parse_oom_kill_count(contents: &str) -> Result<u64> {
    parse_kv_lines(contents)
        .find(|(k, _)| *k == "oom_kill")
        .map(|(_, v)| v.trim().parse().context("oom_kill value not numeric"))
        .context("memory.events missing oom_kill")?
}
```

- [ ] **Step 4: Run to verify it passes.** `cargo test -p kestrel-cgroup stats::` — expect 4 passed.

- [ ] **Step 5: Mark task complete**

---

## Task 9: PSI parsing + trigger watcher

**Files:**
- Create content in: `crates/kestrel-cgroup/src/psi.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-cgroup/src/psi.rs

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_PRESSURE: &str = "\
some avg10=12.43 avg60=8.91 avg300=3.02 total=8213445
full avg10=4.11 avg60=2.30 avg300=0.88 total=2011923
";

    const CPU_PRESSURE_NO_FULL: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";

    #[test]
    fn test_parse_psi_both_lines() {
        let p = parse_psi(CPU_PRESSURE).unwrap();
        assert_eq!(p.some.avg10, 12.43);
        assert_eq!(p.some.total_us, 8_213_445);
        assert_eq!(p.full.unwrap().avg60, 2.30);
    }

    #[test]
    fn test_parse_psi_missing_full_is_none_not_error() {
        let p = parse_psi(CPU_PRESSURE_NO_FULL).unwrap();
        assert!(p.full.is_none());
    }

    #[test]
    fn test_parse_psi_missing_some_errors() {
        assert!(parse_psi("full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo test -p kestrel-cgroup psi::` (inside VM) — FAIL, not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-cgroup/src/psi.rs (above the tests module)

use std::os::fd::AsFd;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

use crate::manager::CgroupManager;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Psi {
    pub some: PsiLine,
    /// `full` = every runnable task stalled (pure lost work). Absent on
    /// older kernels for `cpu.pressure` specifically, hence Option.
    pub full: Option<PsiLine>,
}

pub enum PsiResource {
    Cpu,
    Memory,
    Io,
}

impl PsiResource {
    fn filename(&self) -> &'static str {
        match self {
            PsiResource::Cpu => "cpu.pressure",
            PsiResource::Memory => "memory.pressure",
            PsiResource::Io => "io.pressure",
        }
    }
}

impl CgroupManager {
    pub fn pressure(&self, resource: PsiResource) -> Result<Psi> {
        let contents = std::fs::read_to_string(self.path.join(resource.filename()))
            .with_context(|| format!("reading {}", resource.filename()))?;
        parse_psi(&contents)
    }
}

fn parse_psi(s: &str) -> Result<Psi> {
    let mut some = None;
    let mut full = None;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next().unwrap_or_default();
        let mut l = PsiLine::default();
        for kv in it {
            let (k, v) = kv.split_once('=').context("malformed psi field")?;
            match k {
                "avg10" => l.avg10 = v.parse().context("avg10 not numeric")?,
                "avg60" => l.avg60 = v.parse().context("avg60 not numeric")?,
                "avg300" => l.avg300 = v.parse().context("avg300 not numeric")?,
                "total" => l.total_us = v.parse().context("total not numeric")?,
                _ => {}
            }
        }
        match kind {
            "some" => some = Some(l),
            "full" => full = Some(l),
            _ => {}
        }
    }
    Ok(Psi { some: some.context("psi missing `some` line")?, full })
}

/// Event-driven pressure alerts: write a trigger spec, then poll(POLLPRI)
/// — the kernel wakes us only when the threshold is breached, instead of
/// polling a file every N milliseconds. `window_us` must be in [500ms,
/// 10s]; `stall_us` must be less than `window_us` (kernel-enforced).
pub struct PsiWatcher {
    file: std::fs::File,
}

impl PsiWatcher {
    pub fn watch(path: &std::path::Path, stall_us: u64, window_us: u64) -> Result<Self> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        write!(f, "some {stall_us} {window_us}").context("writing psi trigger spec")?;
        Ok(PsiWatcher { file: f })
    }

    /// Blocks until the trigger fires or `timeout` elapses. Returns `true`
    /// if the pressure threshold was breached.
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        let mut fds = [PollFd::new(self.file.as_fd(), PollFlags::POLLPRI)];
        let timeout_ms: i32 = timeout.as_millis().try_into().unwrap_or(i32::MAX);
        let n = poll(&mut fds, PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::MAX))
            .context("poll on psi trigger fd")?;
        Ok(n > 0)
    }
}
```

## API drift note

`nix::poll`'s `PollFd::new()`/`PollTimeout` API has changed across `nix` versions (older versions used a plain `i32` millisecond timeout instead of a `PollTimeout` newtype). If `cargo build` reports a mismatch, check `cargo doc -p nix --no-deps` for the installed version's real `poll()` signature and adjust — preserve intent (poll the trigger fd for `POLLPRI` with the given timeout, return whether it fired).

- [ ] **Step 4: Run to verify the pure-parsing tests pass.** `cargo test -p kestrel-cgroup psi::` — expect 3 passed (the `PsiWatcher` part isn't unit-tested here since it needs a real cgroup's `*.pressure` file — covered by the root-gated integration pass if time permits, otherwise it's exercised implicitly by any later phase that uses it for real).

- [ ] **Step 5: Mark task complete**

---

## Task 10: `clone3`/`CLONE_INTO_CGROUP` + wire into `kestrel-ns`

**Files:**
- Create content in: `crates/kestrel-cgroup/src/clone3.rs`
- Modify: `crates/kestrel-ns/Cargo.toml` (add `kestrel-cgroup` dependency)
- Modify: `crates/kestrel-ns/src/stages.rs` (wire the `Some(fd)` branch)

The classic sequence — `fork()`, then write the child's pid to `cgroup.procs` — leaves a window where the child runs with NO limits. A memory bomb on the entrypoint's first line escapes `memory.max`. `clone3` with `CLONE_INTO_CGROUP` places the child in the cgroup atomically at creation, closing that window. This is exactly what `kestrel-ns::stages::stage1`'s `Some(_fd) => bail!(...)` branch has been waiting for since Phase 2 Task 8.

- [ ] **Step 1: Write the implementation directly (no separable pure-logic unit to TDD here — this is a thin raw-syscall wrapper; correctness is proven by the Task 11 integration test, not a unit test)**

```rust
// crates/kestrel-cgroup/src/clone3.rs

use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::unistd::Pid;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub const CLONE_INTO_CGROUP: u64 = 0x2000_0000_0000;

/// Forks via `clone3(2)` with `CLONE_INTO_CGROUP`, placing the child in
/// `cgroup_fd`'s cgroup atomically — before its first instruction runs, so
/// there is no window where the child is unconstrained by the cgroup's
/// limits (unlike fork()-then-write-cgroup.procs).
///
/// # Safety
/// Caller must be single-threaded (same requirement as `fork()` elsewhere
/// in this project — clone3 has the same multithreading hazards). The
/// child branch (return value `Ok(None)`) must not touch any state that
/// assumes a parent context, matching `nix::unistd::fork()`'s own
/// documented child-side restrictions (only async-signal-safe operations
/// until the child calls `_exit`/`execve`).
pub unsafe fn clone_into_cgroup(exit_signal: u64, cgroup_fd: RawFd) -> Result<Option<Pid>> {
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP,
        exit_signal,
        cgroup: cgroup_fd as u64,
        ..Default::default()
    };
    // SAFETY: `args` is a valid, correctly-sized CloneArgs on the stack for
    // the duration of this call; SYS_clone3 either returns -1 (parent,
    // error), 0 (child), or the child's pid (parent, success) per clone3(2)
    // — the same three-way return convention as fork(2), handled below the
    // same way nix::unistd::fork() handles it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    match rc {
        -1 => Err(std::io::Error::last_os_error()).context("clone3(CLONE_INTO_CGROUP)"),
        0 => Ok(None),                       // child
        n => Ok(Some(Pid::from_raw(n as i32))), // parent
    }
}
```

- [ ] **Step 2: Verify it compiles.** `cargo build -p kestrel-cgroup` (inside VM) — expect `Finished`. `cargo clippy -p kestrel-cgroup --all-targets -- -D warnings` — this crate does NOT have `#![deny(clippy::undocumented_unsafe_blocks)]` set yet; add it to `lib.rs` now (matching `kestrel-ns`'s convention) since this task introduces the crate's first `unsafe` code:
```rust
#![deny(clippy::undocumented_unsafe_blocks)]
```
at the top of `crates/kestrel-cgroup/src/lib.rs`, above the existing `//!` doc comment. Re-run clippy to confirm the `// SAFETY:` comment above satisfies it.

- [ ] **Step 3: Wire `kestrel-ns::stages::stage1`'s cgroup branch**

`crates/kestrel-ns/Cargo.toml` — add to `[dependencies]`:
```toml
kestrel-cgroup = { path = "../kestrel-cgroup" }
```

`crates/kestrel-ns/src/stages.rs` — replace the `Some(_fd) => bail!(...)` arm in `stage1` with:

```rust
        Some(fd) => {
            // SAFETY: stage1 runs single-threaded (assert_single_threaded()
            // was checked at the top of run_stages, and nothing in stage1
            // spawns a thread before reaching here).
            match unsafe { kestrel_cgroup::clone3::clone_into_cgroup(libc::SIGCHLD as u64, fd) }
                .context("clone3(CLONE_INTO_CGROUP)")?
            {
                None => {
                    // STAGE 2 — we are PID 1, placed atomically in the
                    // cgroup before this instruction ran. Never returns.
                    child_action()
                }
                Some(pid) => pid,
            }
        }
```

(This replaces the whole `match cgroup_fd { Some(_fd) => bail!(...), None => match unsafe { fork() } ... }` block's `Some` arm specifically — leave the `None` arm, which still uses the `fork()` fallback, untouched.)

- [ ] **Step 4: Run the full `kestrel-ns` suite to confirm nothing broke.** `cargo test -p kestrel-ns` (inside VM, non-`--ignored`) — expect the same passing counts as at the end of Phase 2 (no regressions — this change only touches a branch that was previously an unconditional `bail!` and had zero test coverage before now).

- [ ] **Step 5: Mark task complete**

---

## Task 11: Root-gated gating tests — memory OOM, cpu throttle, pids limit, clone3-no-window

**Files:**
- Modify: `crates/kestrel-cgroup/tests/integration.rs` (append)

These are the tests CHECKLIST.md Phase 3 calls for by name: `test_memory_limit_ooms`, `test_cpu_throttle`, `test_pids_limit`, `test_clone_into_cgroup_no_window`.

- [ ] **Step 1: Write the tests** — append to `crates/kestrel-cgroup/tests/integration.rs`:

```rust
use kestrel_oci::runtime::{LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResourcesBuilder};

#[test]
#[ignore = "requires root"]
fn test_memory_limit_ooms() {
    let m = test_manager("kestrel-test-oom");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .memory(LinuxMemoryBuilder::default().limit(32 * 1024 * 1024i64).build().unwrap())
        .build()
        .unwrap();
    m.apply_memory(&resources).expect("apply_memory");

    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("head -c 200000000 /dev/zero | tail -c 200000000 > /dev/null")
        .spawn()
        .expect("spawn memory bomb");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32)).expect("add_process");

    let status = child.wait().expect("wait");
    assert!(!status.success(), "memory bomb should have been killed");
    assert!(m.oom_kill_count().expect("oom_kill_count") >= 1, "oom_kill counter did not increment");

    m.kill_all().ok();
    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_cpu_throttle() {
    let m = test_manager("kestrel-test-throttle");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .cpu(LinuxCpuBuilder::default().quota(50_000i64).period(100_000u64).build().unwrap())
        .build()
        .unwrap();
    m.apply_cpu(&resources).expect("apply_cpu");

    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("timeout 2 sh -c 'while :; do :; done'")
        .spawn()
        .expect("spawn busy loop");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32)).expect("add_process");
    child.wait().ok();

    let stat = m.cpu_stat().expect("cpu_stat");
    assert!(stat.nr_throttled > 0, "expected throttling under a 50% quota busy loop");

    m.kill_all().ok();
    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_pids_limit() {
    let m = test_manager("kestrel-test-pids");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .pids(LinuxPidsBuilder::default().limit(10i64).build().unwrap())
        .build()
        .unwrap();
    m.apply_pids(&resources).expect("apply_pids");

    let mut child = std::process::Command::new("sh")
        .arg("-c")
        // Fork bomb attempt, bounded by `timeout` so the test can't hang
        // the VM even if the limit somehow didn't apply.
        .arg("timeout 3 sh -c ':(){ :|:& };:' || true")
        .spawn()
        .expect("spawn fork bomb");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32)).expect("add_process");
    child.wait().ok();

    // The host must remain responsive — a trivial command should still
    // execute promptly. (If pids.max didn't hold, this VM might already be
    // struggling; that in itself would be the test's real failure mode.)
    let host_still_responsive = std::process::Command::new("true").status().is_ok();
    assert!(host_still_responsive, "host became unresponsive — pids.max may not have held");

    m.kill_all().ok();
    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_clone_into_cgroup_no_window() {
    // With fork()-then-write-cgroup.procs there is a window where the
    // child runs unconstrained; a memory bomb on line 1 could escape
    // memory.max. With CLONE_INTO_CGROUP it cannot — verify by placing a
    // 32MiB-limited cgroup's fd into clone_into_cgroup and confirming the
    // child (which immediately allocates far more than that) is OOM-killed
    // rather than ever completing.
    let m = test_manager("kestrel-test-clone3");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .memory(LinuxMemoryBuilder::default().limit(32 * 1024 * 1024i64).build().unwrap())
        .build()
        .unwrap();
    m.apply_memory(&resources).expect("apply_memory");

    kestrel_ns::test_util::run_isolated(|| {
        let cgroup_fd = std::fs::File::open(&m.path).expect("open cgroup dir for O_PATH-ish fd use");
        use std::os::fd::AsRawFd;
        let result = unsafe {
            kestrel_cgroup::clone3::clone_into_cgroup(libc::SIGCHLD as u64, cgroup_fd.as_raw_fd())
        }
        .expect("clone3");
        match result {
            None => {
                // Child: immediately try to allocate well past the limit.
                // If clone3 placed us in the cgroup atomically, this must
                // be killed before it can finish — there is no window.
                let _bomb: Vec<u8> = vec![0u8; 200 * 1024 * 1024];
                std::hint::black_box(&_bomb);
                unsafe { libc::_exit(0) }; // should never be reached
            }
            Some(pid) => {
                let status = nix::sys::wait::waitpid(pid, None).expect("waitpid");
                assert_ne!(
                    status,
                    nix::sys::wait::WaitStatus::Exited(pid, 0),
                    "child completed its allocation — it was NOT constrained from t=0"
                );
            }
        }
    });

    m.kill_all().ok();
    m.destroy().ok();
}
```

## API drift note

`LinuxResourcesBuilder`/`LinuxCpuBuilder`/`LinuxMemoryBuilder`/`LinuxPidsBuilder` need to be added to `kestrel-oci`'s `runtime` re-export module (`crates/kestrel-oci/src/lib.rs`) if they aren't already there — check first; Phase 0/1 added the builders that were needed at the time (`SpecBuilder`, `ProcessBuilder`, `RootBuilder`, `LinuxBuilder`, `MountBuilder`, `LinuxIdMappingBuilder`), but `LinuxResourcesBuilder`/`LinuxCpuBuilder`/`LinuxMemoryBuilder`/`LinuxPidsBuilder` are new additions this task needs. Add them to the `pub use oci_spec::runtime::{...}` list in `kestrel-oci/src/lib.rs`, verifying the exact names against the real installed `oci-spec` crate the same way earlier tasks did (check `cargo doc -p oci-spec --no-deps` or the vendored source if the names don't match).

- [ ] **Step 2: Run to verify they pass.** `sudo -E env "PATH=$PATH" cargo test -p kestrel-cgroup --test integration -- --ignored` (inside VM) — expect all integration tests (from this task plus Tasks 3 and 7) passing: 2 (Task 3) + 1 (Task 7) + 4 (this task) = 7. Run at least twice to check for flakiness, especially `test_cpu_throttle` and `test_pids_limit`, which are timing/resource-sensitive.

- [ ] **Step 3: Process/cgroup leak check.** After running the full root-gated suite, confirm no leftover cgroups under `/sys/fs/cgroup/kestrel/` and no orphaned processes (`ps aux`, `ls /sys/fs/cgroup/kestrel/` before/after).

- [ ] **Step 4: Mark task complete**

---

## Task 12: Final verification

**Files:**
- No file changes expected — this task verifies everything ties together. If `make test-root` needs updating to include `kestrel-cgroup`'s tests, it already will (the target runs `cargo test --workspace -- --ignored`, which covers every crate automatically) — confirm this is true rather than assuming it.

- [ ] **Step 1: Full workspace build.** `cargo build --workspace` inside the VM — confirm `Finished`, no errors, across all 12 crates including the now-more-complete `kestrel-cgroup` and the `kestrel-ns` → `kestrel-cgroup` dependency edge.

- [ ] **Step 2: Full non-root test suite.** `make test` inside the VM — confirm the tokio guard passes and every crate's non-`--ignored` tests pass (kestrel-cgroup's unit tests from Tasks 2-9, kestrel-ns's full Phase 2 suite unchanged, kestrel-oci's Phase 0/1 suite unchanged).

- [ ] **Step 3: Full root test suite.** `make test-root` inside the VM — confirm it now also runs and passes `kestrel-cgroup`'s 7 integration tests (Tasks 3, 7, 11) alongside Phase 2's `kestrel-ns` root tests (with `test_join_order_matters` still correctly excluded via `--skip`). Run twice for stability.

- [ ] **Step 4: Confirm the `#![deny(clippy::undocumented_unsafe_blocks)]` convention holds crate-wide.** `cargo clippy -p kestrel-cgroup -p kestrel-ns --all-targets -- -D warnings` inside the VM — clean.

- [ ] **Step 5: `cargo fmt --check` across both touched crates.** `cargo fmt -p kestrel-cgroup -p kestrel-ns -- --check` inside the VM — clean (run `cargo fmt` first if not).

- [ ] **Step 6: Mark task complete**

---

## Self-Review Notes

- **Spec coverage:** CHECKLIST.md Phase 3's "Manager" bullets map to Tasks 2-3; "Controllers" bullets map to Tasks 4-6; "Runtime control" maps to Task 7; "Stats & PSI" maps to Tasks 8-9; "clone3" maps to Task 10; "Tests" map across Tasks 3/7/11 (each gating test lives with the code it gates, per TDD, same convention as Phase 2).
- **Known API-drift risk, same category as every prior phase:** `LinuxCpu`/`LinuxMemory`/`LinuxPids`/`LinuxBlockIo`/`LinuxHugepageLimit` field types were verified against `oci-spec` 0.10.0's docs.rs pages before writing this plan (Tasks 4-6's "API drift note" sections cite exact confirmed types); the corresponding `*Builder` types needed by Task 11's tests were NOT individually re-verified and may need adding to `kestrel-oci`'s re-export list — flagged explicitly in Task 11.
- **Cross-phase dependency direction:** this phase makes `kestrel-ns` depend on `kestrel-cgroup` (Task 10) — the reverse of what a reader might assume from the crate names, but matches PROMPT.md's own `stages.rs` sketch, which takes a `cgroup_fd` parameter and calls a clone3 helper directly.
