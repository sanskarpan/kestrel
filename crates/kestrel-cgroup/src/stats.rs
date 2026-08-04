use anyhow::{Context, Result};

use crate::manager::CgroupManager;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CpuStat {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

impl CgroupManager {
    pub fn cpu_stat(&self) -> Result<CpuStat> {
        let contents = std::fs::read_to_string(self.path.join("cpu.stat")).with_context(|| {
            format!(
                "reading cpu.stat at {}",
                self.path.join("cpu.stat").display()
            )
        })?;
        parse_cpu_stat(&contents)
    }

    /// `memory.events`'s `oom_kill` counter is the authoritative OOM
    /// signal — exit code 137 is NOT, since a container can be SIGKILLed
    /// for many reasons, and conflating them produces false "OOMKilled"
    /// statuses (a bug Docker itself has shipped).
    pub fn oom_kill_count(&self) -> Result<u64> {
        let contents =
            std::fs::read_to_string(self.path.join("memory.events")).with_context(|| {
                format!(
                    "reading memory.events at {}",
                    self.path.join("memory.events").display()
                )
            })?;
        parse_oom_kill_count(&contents)
    }

    pub fn memory_current(&self) -> Result<u64> {
        let contents =
            std::fs::read_to_string(self.path.join("memory.current")).with_context(|| {
                format!(
                    "reading memory.current at {}",
                    self.path.join("memory.current").display()
                )
            })?;
        parse_u64_content(&contents)
    }

    pub fn pids_current(&self) -> Result<u64> {
        let contents =
            std::fs::read_to_string(self.path.join("pids.current")).with_context(|| {
                format!(
                    "reading pids.current at {}",
                    self.path.join("pids.current").display()
                )
            })?;
        parse_u64_content(&contents)
    }
}

fn parse_kv_lines(contents: &str) -> impl Iterator<Item = (&str, &str)> {
    contents.lines().filter_map(|l| l.split_once(' '))
}

fn parse_u64_content(contents: &str) -> Result<u64> {
    contents
        .trim()
        .parse()
        .with_context(|| format!("value {:?} is not numeric", contents.trim()))
}

/// Tolerant field-by-field parse: a single malformed numeric field is
/// skipped (and logged) rather than aborting the whole read, matching the
/// crate's established tolerance conventions (`parse_populated`/
/// `parse_frozen` in control.rs default safely; `kill_all_fallback`'s pid
/// parsing skips bad lines via `.ok()`). One bad field — e.g. a kernel
/// that adds an unexpected format — shouldn't lose the other three.
fn parse_cpu_stat(contents: &str) -> Result<CpuStat> {
    let mut s = CpuStat::default();
    for (k, v) in parse_kv_lines(contents) {
        let Some(parsed) = v.trim().parse::<u64>().ok() else {
            tracing::warn!(
                field = k,
                value = v,
                "cpu.stat field is not numeric, skipping"
            );
            continue;
        };
        match k {
            "usage_usec" => s.usage_usec = parsed,
            "nr_periods" => s.nr_periods = parsed,
            "nr_throttled" => s.nr_throttled = parsed,
            "throttled_usec" => s.throttled_usec = parsed,
            _ => {}
        }
    }
    Ok(s)
}

fn parse_oom_kill_count(contents: &str) -> Result<u64> {
    parse_kv_lines(contents)
        .find(|(k, _)| *k == "oom_kill")
        .map(|(_, v)| {
            v.trim()
                .parse()
                .with_context(|| format!("memory.events oom_kill value {v:?} is not numeric"))
        })
        .context("memory.events missing oom_kill field")?
}

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

    #[test]
    fn test_parse_u64_content() {
        assert_eq!(parse_u64_content("12345\n").unwrap(), 12345);
    }

    #[test]
    fn test_parse_u64_content_rejects_non_numeric() {
        assert!(parse_u64_content("not-a-number\n").is_err());
    }

    #[test]
    fn test_parse_u64_content_rejects_negative() {
        // memory.current/pids.current are always non-negative in real
        // cgroupfs output; a stray negative sign should be rejected by
        // the u64 parse, not silently misread.
        assert!(parse_u64_content("-5\n").is_err());
    }
}
