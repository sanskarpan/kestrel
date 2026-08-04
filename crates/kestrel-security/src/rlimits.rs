// crates/kestrel-security/src/rlimits.rs

use anyhow::{Context, Result};
use kestrel_oci::runtime::{PosixRlimit, PosixRlimitType};
use nix::sys::resource::{setrlimit, Resource};

/// `oci_spec`'s 16 `PosixRlimitType` variants map 1:1 onto `nix`'s
/// `Resource::RLIMIT_*` — verified by reading both enums directly (not
/// assumed). Kept as an explicit `match` (not a derive/macro) so a future
/// kernel/spec addition to either side fails to compile here instead of
/// silently mismapping.
fn translate_rlimit_type(t: PosixRlimitType) -> Resource {
    match t {
        PosixRlimitType::RlimitCpu => Resource::RLIMIT_CPU,
        PosixRlimitType::RlimitFsize => Resource::RLIMIT_FSIZE,
        PosixRlimitType::RlimitData => Resource::RLIMIT_DATA,
        PosixRlimitType::RlimitStack => Resource::RLIMIT_STACK,
        PosixRlimitType::RlimitCore => Resource::RLIMIT_CORE,
        PosixRlimitType::RlimitRss => Resource::RLIMIT_RSS,
        PosixRlimitType::RlimitNproc => Resource::RLIMIT_NPROC,
        PosixRlimitType::RlimitNofile => Resource::RLIMIT_NOFILE,
        PosixRlimitType::RlimitMemlock => Resource::RLIMIT_MEMLOCK,
        PosixRlimitType::RlimitAs => Resource::RLIMIT_AS,
        PosixRlimitType::RlimitLocks => Resource::RLIMIT_LOCKS,
        PosixRlimitType::RlimitSigpending => Resource::RLIMIT_SIGPENDING,
        PosixRlimitType::RlimitMsgqueue => Resource::RLIMIT_MSGQUEUE,
        PosixRlimitType::RlimitNice => Resource::RLIMIT_NICE,
        PosixRlimitType::RlimitRtprio => Resource::RLIMIT_RTPRIO,
        PosixRlimitType::RlimitRttime => Resource::RLIMIT_RTTIME,
    }
}

/// Applies every rlimit in `limits` to the current process. Must run
/// BEFORE the uid drop in `apply_all` — some limits cannot be raised once
/// privileges are dropped (CAP_SYS_RESOURCE is needed to raise a hard
/// limit, and that capability may itself be dropped by the bounding-set
/// step that runs after this one).
pub fn apply_rlimits(limits: Option<&[PosixRlimit]>) -> Result<()> {
    let Some(limits) = limits else { return Ok(()) };
    for rl in limits {
        let resource = translate_rlimit_type(rl.typ());
        setrlimit(resource, rl.soft(), rl.hard())
            .with_context(|| format!("setrlimit({:?}, soft={}, hard={})", rl.typ(), rl.soft(), rl.hard()))?;
    }
    Ok(())
}

/// Writes `/proc/self/oom_score_adj`. Range is -1000 (never killed first)
/// to 1000 (killed first); lowering below a value previously set by a
/// CAP_SYS_RESOURCE-holding process requires that same capability, but
/// setting your own to anything from your current value or higher never
/// needs privilege.
pub fn set_oom_score_adj(score: i32) -> Result<()> {
    anyhow::ensure!((-1000..=1000).contains(&score), "oom_score_adj {score} out of range [-1000, 1000]");
    std::fs::write("/proc/self/oom_score_adj", score.to_string())
        .with_context(|| format!("writing oom_score_adj={score}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_rlimit_type_covers_every_variant() {
        // Exhaustive match above already guarantees compile-time coverage;
        // this test just confirms a couple of the mappings are the
        // expected, non-transposed ones (a translation bug that swapped
        // e.g. RLIMIT_CPU and RLIMIT_NPROC would still compile).
        assert_eq!(translate_rlimit_type(PosixRlimitType::RlimitNofile), Resource::RLIMIT_NOFILE);
        assert_eq!(translate_rlimit_type(PosixRlimitType::RlimitCpu), Resource::RLIMIT_CPU);
    }
}
