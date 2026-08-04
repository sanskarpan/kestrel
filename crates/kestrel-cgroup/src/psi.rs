//! PSI (Pressure Stall Information) parsing and event-driven trigger
//! watching. See cgroups(7) and Documentation/accounting/psi.rst.

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
    Ok(Psi {
        some: some.context("psi missing `some` line")?,
        full,
    })
}

/// Event-driven pressure alerts: write a trigger spec, then poll(POLLPRI)
/// — the kernel wakes us only when the threshold is breached, instead of
/// polling a file every N milliseconds. `window_us` must be in [500ms,
/// 10s]; `stall_us` must be less than `window_us` (kernel-enforced).
#[derive(Debug)]
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
        // The kernel's PSI-trigger sysfs handler requires the entire
        // "some <stall_us> <window_us>" spec in a single write(2) call and
        // rejects partial writes with EINVAL, so this must NOT be a
        // `write!` macro call (which issues one write(2) per fragment).
        //
        // Note: an EINVAL here can also mean stall_us/window_us violate the
        // kernel's constraints (window_us must be in [500_000, 10_000_000],
        // stall_us must be < window_us), not just a write-atomicity issue —
        // if debugging an EINVAL from this line, check both.
        let spec = format!("some {stall_us} {window_us}");
        f.write_all(spec.as_bytes())
            .context("writing psi trigger spec")?;
        Ok(PsiWatcher { file: f })
    }

    /// Blocks until the trigger fires or `timeout` elapses. Returns `true`
    /// only if the fd actually reported a genuine `POLLPRI` pressure event.
    ///
    /// `POLLERR`/`POLLHUP`/`POLLNVAL` are always reported by the kernel
    /// regardless of the requested event mask (see poll(2)), so a bare
    /// `n > 0` check would false-positive on e.g. the underlying cgroup
    /// being removed out from under the open fd. That case needs its own
    /// check, not just "did we see POLLPRI": when a PSI trigger's cgroup is
    /// torn down, `psi_trigger_poll()` in the kernel deliberately reports
    /// `EPOLLPRI` *together with* `EPOLLERR` on the now-dangling trigger, as
    /// its way of unblocking waiters — so `revents` can contain both bits
    /// at once and `.contains(POLLPRI)` alone is not sufficient to
    /// distinguish "real pressure event" from "trigger destroyed". Treat
    /// any POLLERR/POLLHUP/POLLNVAL as an error condition that takes
    /// precedence over a POLLPRI bit riding along with it.
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        let mut fds = [PollFd::new(self.file.as_fd(), PollFlags::POLLPRI)];
        poll(
            &mut fds,
            PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX),
        )
        .context("poll on psi trigger fd")?;
        let revents = fds[0].revents().unwrap_or(PollFlags::empty());
        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            anyhow::bail!(
                "psi trigger fd reported an error condition (POLLERR/POLLHUP/POLLNVAL, revents={revents:?}) — the underlying cgroup or pressure file was likely removed"
            );
        }
        Ok(revents.contains(PollFlags::POLLPRI))
    }
}

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
