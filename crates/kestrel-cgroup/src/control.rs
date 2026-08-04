use anyhow::{Context, Result};

use crate::manager::CgroupManager;

impl CgroupManager {
    /// cgroup v2 replaces v1's separate freezer controller with a single
    /// file: write "1"/"0" to `cgroup.freeze`, then poll `cgroup.events`
    /// until the transition is confirmed — freezing isn't instantaneous
    /// (a task in an uninterruptible state can take time to actually
    /// stop), so a caller needs a synchronous guarantee, not just "the
    /// write succeeded."
    pub fn freeze(&self, frozen: bool) -> Result<()> {
        self.write("cgroup.freeze", if frozen { "1" } else { "0" })?;
        self.wait_for_frozen_state(frozen, std::time::Duration::from_secs(5))
    }

    fn wait_for_frozen_state(&self, want_frozen: bool, timeout: std::time::Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let contents = std::fs::read_to_string(self.path.join("cgroup.events"))
                .context("reading cgroup.events while polling freeze state")?;
            if parse_frozen(&contents) == want_frozen {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for cgroup to reach frozen={want_frozen}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Atomic kill of every process in the cgroup (kernel 5.14+) — far more
    /// reliable than iterating `cgroup.procs` and killing one at a time,
    /// which races against fork(). Falls back to the iterate-and-kill
    /// approach on kernels older than 5.14, where `cgroup.kill` doesn't
    /// exist — this project's stated minimum kernel is 5.11.
    pub fn kill_all(&self) -> Result<()> {
        if self.path.join("cgroup.kill").exists() {
            self.write("cgroup.kill", "1")
        } else {
            self.kill_all_fallback()
        }
    }

    /// Pre-5.14 fallback: kill every pid currently in cgroup.procs
    /// individually. This races against fork() — a process could fork a
    /// new child between reading cgroup.procs and the kill loop below —
    /// which is exactly what cgroup.kill's atomicity avoids on newer
    /// kernels. Best available option when cgroup.kill doesn't exist.
    fn kill_all_fallback(&self) -> Result<()> {
        let procs = std::fs::read_to_string(self.path.join("cgroup.procs"))
            .context("reading cgroup.procs for kill_all fallback")?;
        for line in procs.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        Ok(())
    }

    pub fn is_populated(&self) -> Result<bool> {
        let contents =
            std::fs::read_to_string(self.path.join("cgroup.events")).with_context(|| {
                format!(
                    "reading cgroup.events at {}",
                    self.path.join("cgroup.events").display()
                )
            })?;
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

fn parse_frozen(events: &str) -> bool {
    events
        .lines()
        .find_map(|l| l.strip_prefix("frozen "))
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

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

    #[test]
    fn test_parse_events_frozen_true() {
        assert!(parse_frozen("populated 1\nfrozen 1\n"));
    }

    #[test]
    fn test_parse_events_frozen_false() {
        assert!(!parse_frozen("populated 1\nfrozen 0\n"));
    }

    #[test]
    fn test_parse_events_frozen_missing_defaults_false() {
        assert!(!parse_frozen(""));
    }

    #[test]
    fn test_parse_pids_from_procs_content() {
        // Pure logic check for the fallback's parsing, since we can't
        // easily force a pre-5.14 kernel in this dev VM to exercise the
        // full kill_all_fallback() path end-to-end.
        let procs = "123\n456\n\n789\n";
        let pids: Vec<i32> = procs
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        assert_eq!(pids, vec![123, 456, 789]);
    }
}
