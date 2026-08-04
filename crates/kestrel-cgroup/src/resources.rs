// filled in by Tasks 4-6 (CPU, memory + pids, io + hugetlb resource limits)

use anyhow::Result;
use kestrel_oci::runtime::LinuxResources;

use crate::manager::CgroupManager;

impl CgroupManager {
    /// Applies the CPU portion of `resources`: `cpu.max` (quota/period),
    /// `cpu.weight` (converted from OCI's v1-style `shares`), and
    /// `cpuset.cpus`/`cpuset.mems` if present.
    pub fn apply_cpu(&self, resources: &LinuxResources) -> Result<()> {
        let Some(cpu) = resources.cpu() else {
            return Ok(());
        };

        let period = cpu.period().unwrap_or(100_000);
        // Only write cpu.max if the spec actually says something about CPU
        // limiting (quota present) — otherwise leave the kernel default.
        // A `period` with no `quota` is harmless to skip: cgroup v2 only
        // enforces `period` in combination with a numeric quota, never on
        // its own (quota absent/"max" means unconstrained regardless).
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
            let limit = pids.limit();
            // `LinuxPids::limit` is a required (non-`Option`) `i64` in
            // oci-spec, marked `#[serde(default)]` — upstream's own doc
            // comment on the field says "Default is 'no limit'". That means
            // an OCI spec with an empty/default `"pids": {}` block
            // deserializes `limit` as `0`, indistinguishable at this point
            // from someone genuinely writing `"limit": 0`. Since
            // `fmt_limit(0)` is `"0"` (only negative values map to `"max"`),
            // writing it unconditionally would set `pids.max = 0` and block
            // ALL process/thread creation in the container, including its
            // own entrypoint. Treat 0 as "not set" and skip the write,
            // matching upstream's documented default semantics.
            if limit != 0 {
                self.write("pids.max", &fmt_limit(limit))?;
            }
        }
        Ok(())
    }

    /// `io.weight` and, per throttled device, `io.max` — cgroup v2 accepts
    /// PARTIAL io.max writes (one key at a time), so each throttle vector
    /// (rbps/wbps/riops/wiops) for a given device is its own write() call;
    /// the kernel merges them rather than requiring one combined line.
    pub fn apply_io(&self, resources: &LinuxResources) -> Result<()> {
        let Some(io) = resources.block_io() else {
            return Ok(());
        };

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

    /// `hugetlb.<pagesize>.max` per entry in `hugepageLimits`.
    ///
    /// Unlike `LinuxPids::limit` (Task 5), `LinuxHugepageLimit::limit` is
    /// NOT given the same "treat 0 as unset" guard, even though it has the
    /// identical shape (non-`Option` `i64`, `#[serde(default)]`, so a
    /// hugepage entry missing `limit` in JSON also deserializes to `0`).
    /// The reasons this isn't the same footgun:
    ///   1. Zero live processes is never a coherent real limit (a container
    ///      always needs at least its entrypoint), so for pids, 0 could only
    ///      mean "field omitted". Zero hugepage reservations, by contrast,
    ///      is a completely coherent and plausible *explicit* request ("this
    ///      container may not use hugepages of this size at all") — so 0 is
    ///      genuinely ambiguous between "unset" and "deliberately denied",
    ///      and unlike pids there's no safe default interpretation to prefer.
    ///   2. The blast radius is scoped: `pids.max=0` prevents ANY process
    ///      from ever running in the cgroup, including the container's own
    ///      entrypoint — a hard failure. `hugetlb.<size>.max=0` only denies
    ///      allocations of that one specific hugepage size; most workloads
    ///      never touch hugepages, so this doesn't brick the container the
    ///      way the pids case did.
    ///
    /// So we pass `limit()` straight through `fmt_limit` unguarded.
    ///
    /// NOTE: this is NOT because `pageSize` is a required field — it isn't.
    /// `LinuxHugepageLimit::page_size` is `#[serde(default)]` too (defaults
    /// to `""`), so a degenerate `{}` entry deserializes with `page_size =
    /// ""` and `limit = 0`, the same shape as the pids footgun. It's
    /// harmless *today* only by accident: `hugetlb..max` (empty page size)
    /// is never a real interface file, so the `self.path.join(&file).exists()`
    /// guard below filters that specific degenerate case out before any
    /// write happens — not because the input is structurally impossible.
    /// Latent risk this leaves on the table: a future spec generator that
    /// emits a legitimate page-size-only entry (e.g. `{"pageSize": "2MB"}`
    /// with `limit` implicitly defaulted to `0` rather than explicitly set)
    /// would hit a real file (`hugetlb.2MB.max` exists) and this code would
    /// silently write `hugetlb.2MB.max=0` — denying that page size, with no
    /// way to tell it apart from a genuine `"limit": 0`. Revisit this guard
    /// if that generator pattern ever becomes real.
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

fn format_io_max_line(major: i64, minor: i64, key: &str, rate: u64) -> String {
    format!("{major}:{minor} {key}={rate}")
}

/// v1 blkio weight [10, 1000] -> v2 io.weight [1, 10000]. Uses integer
/// truncating division (not float + round) to match runc/systemd's real
/// mapping — Task 4's `shares_to_weight` originally used f64 + `.round()`
/// and was found to disagree with the integer formula for about half of all
/// inputs (e.g. the very common default-shares case), with the disagreement
/// invisible at the [min, max] boundaries where both approaches happen to
/// agree. Using integer division here from the start avoids repeating that
/// bug in the analogous io.weight conversion.
pub(crate) fn blkio_weight_to_io_weight(weight: u16) -> u64 {
    let w = (weight as u64).clamp(10, 1000);
    1 + ((w - 10) * 9999) / 990
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

/// v1 `shares` [2, 262144] (default 1024) -> v2 `cpu.weight` [1, 10000]
/// (default 100). Matches the mapping systemd and runc use so migrated
/// configs behave the same. Zero means "not set" -> the v2 default.
pub(crate) fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 100;
    }
    let s = shares.clamp(2, 262_144);
    1 + ((s - 2) * 9999) / 262_142
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

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::runtime::{LinuxPidsBuilder, LinuxResourcesBuilder};

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
    fn test_shares_to_weight_matches_runc_for_default_shares() {
        // The OCI/v1 default (1024) is the case where float-rounding and
        // integer-truncation previously disagreed (39 vs 40) — pin the
        // correct (integer-truncating, runc/systemd-matching) value.
        assert_eq!(shares_to_weight(1024), 39);
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

    #[test]
    fn test_fmt_limit_positive() {
        assert_eq!(fmt_limit(536_870_912), "536870912");
    }

    #[test]
    fn test_fmt_limit_negative_means_unlimited() {
        assert_eq!(fmt_limit(-1), "max");
    }

    /// Builds a `CgroupManager` rooted in a fresh temp directory and creates
    /// its leaf dir, so `self.write()` (plain `fs::write`) works without
    /// root or a real cgroupfs — this crate's other tests that touch real
    /// `/sys/fs/cgroup` are `#[ignore = "requires root"]` integration tests;
    /// this one only needs an ordinary writable directory.
    fn test_manager(name: &str) -> CgroupManager {
        let unique = format!(
            "{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        );
        let root = std::env::temp_dir().join(unique);
        let m = CgroupManager::new(root, "leaf").expect("valid cgroup id");
        std::fs::create_dir_all(&m.path).expect("create fake leaf dir");
        m
    }

    #[test]
    fn test_apply_pids_treats_zero_as_unset_not_a_real_limit() {
        // LinuxPids::limit defaults to 0 via #[serde(default)] when a spec
        // has an empty "pids": {} block (oci-spec's own doc comment on the
        // field says "Default is 'no limit'"). Writing pids.max=0 would
        // block ALL process creation in the container, which is never the
        // intent of an omitted/empty pids limit — so apply_pids must skip
        // the write entirely rather than relying on fmt_limit (which has no
        // special-casing for 0: fmt_limit(0) == "0", confirmed below).
        assert_eq!(fmt_limit(0), "0");

        let m = test_manager("pids-zero");
        let pids = LinuxPidsBuilder::default().limit(0i64).build().unwrap();
        let resources = LinuxResourcesBuilder::default().pids(pids).build().unwrap();
        m.apply_pids(&resources)
            .expect("apply_pids should not error");
        assert!(
            !m.path.join("pids.max").exists(),
            "apply_pids must not write pids.max when limit == 0 (would block all process creation)"
        );
        std::fs::remove_dir_all(m.root).ok();
    }

    #[test]
    fn test_apply_pids_writes_real_nonzero_limit() {
        // Control case for the test above: prove apply_pids does write a
        // genuine limit, so the zero-case assertion isn't vacuously true
        // because of some unrelated write failure.
        let m = test_manager("pids-nonzero");
        let pids = LinuxPidsBuilder::default().limit(64i64).build().unwrap();
        let resources = LinuxResourcesBuilder::default().pids(pids).build().unwrap();
        m.apply_pids(&resources)
            .expect("apply_pids should not error");
        let written = std::fs::read_to_string(m.path.join("pids.max")).expect("pids.max written");
        assert_eq!(written, "64");
        std::fs::remove_dir_all(m.root).ok();
    }

    #[test]
    fn test_io_max_line_format() {
        assert_eq!(
            format_io_max_line(8, 0, "rbps", 1_048_576),
            "8:0 rbps=1048576"
        );
    }

    #[test]
    fn test_blkio_weight_to_io_weight_clamps_range() {
        // v1 blkio weight [10, 1000] -> v2 io.weight [1, 10000], same
        // linear-ish mapping style as CPU shares -> weight.
        assert_eq!(blkio_weight_to_io_weight(10), 1);
        assert_eq!(blkio_weight_to_io_weight(1000), 10000);
    }
}
