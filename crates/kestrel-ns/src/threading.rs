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
