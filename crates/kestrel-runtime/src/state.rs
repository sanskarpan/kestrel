// crates/kestrel-runtime/src/state.rs

use std::path::{Path, PathBuf};

use anyhow::Result;
use kestrel_oci::state::{State, Status};
use nix::sys::signal::kill;
use nix::unistd::Pid;

pub fn state_json_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join(id).join("state.json")
}

/// Reads state.json and cross-checks `status` against whether `pid` is
/// still alive (`kill(pid, None)`, signal 0 — the standard liveness
/// probe, doesn't actually send a signal).
///
/// # Design decision: liveness-checking is diagnostic only, never authoritative
///
/// This function deliberately does NOT synthesize a new `Status` (e.g. an
/// "exited but not yet reaped" variant) when the pid is dead but
/// `state.json` still says something other than `Stopped`. Two reasons:
///
/// 1. There is a real, unavoidable race: kestrel-init's own reaper (built
///    in a later Phase 8 task) is the only process that can observe the
///    entrypoint's actual exit status (via `waitpid`) and is the sole
///    writer of `Status::Stopped` + `exit_code` into state.json. Between
///    the moment the pid dies and the moment the reaper's `write_atomic`
///    call lands, `kill(pid, None)` will report "dead" while state.json
///    still says e.g. `Running`. That window is bounded but nonzero, and
///    a `read_and_refresh` caller has no way to distinguish "the reaper
///    just hasn't run yet" from "something is wrong" using the liveness
///    check alone.
/// 2. `Status` is part of the OCI runtime-spec `state` command's output
///    schema (plus kestrel's own `Paused` extension) and is meant to
///    reflect what kestrel's own lifecycle machinery (create/start/kill/
///    delete, the reaper) has *decided* and durably recorded — not a
///    best-effort guess derived from a liveness probe that can't see
///    `exit_code`. Overwriting it here with a synthesized status would
///    make state.json lie about who the actual source of truth is and
///    could race the reaper's own write.
///
/// So: `state.json`'s own `status` field (and `exit_code` once the reaper
/// populates it) remains authoritative and is never mutated by this
/// function. The liveness check is still useful — it's surfaced both as a
/// `tracing::warn!` (for the trace log) AND as `RefreshedState::stale`
/// (for callers, e.g. `state_cmd`/`ps`, that surface `status` directly to
/// a human and need a way to say "this might be out of date" instead of
/// silently passing through a possibly-dead-but-unreaped status — see
/// `RefreshedState::stale_note`).
pub fn read_and_refresh(path: &Path) -> Result<RefreshedState> {
    let state = State::read(path)?;
    let mut stale = false;
    if let Some(pid) = state.pid {
        let alive = kill(Pid::from_raw(pid), None).is_ok();
        if !alive && state.status != Status::Stopped {
            stale = true;
            tracing::warn!(
                id = %state.id,
                pid,
                status = ?state.status,
                "pid is not alive but state.json status is not Stopped yet; \
                 trusting state.json as authoritative (kestrel-init's reaper \
                 has not written the terminal status/exit_code yet, or has \
                 not been reaped) — this is a diagnostic signal, not a status \
                 override",
            );
        }
    }
    Ok(RefreshedState { state, stale })
}

/// Return value of [`read_and_refresh`]: the on-disk `State` plus whether
/// the pid-liveness probe disagreed with it at read time.
///
/// This exists so the "pid is dead but status isn't `Stopped` yet"
/// condition documented on `read_and_refresh` isn't ONLY visible in the
/// trace log. A CLI caller that reads `.state` without checking `.stale`
/// would otherwise print e.g. "Running" for a container whose process has
/// already exited, with no indication anything is off — the only signal
/// being a `tracing::warn!` a user is unlikely to see during normal CLI
/// usage. Callers that surface `status` to a human (`state_cmd`, `ps`)
/// should check `.stale` and say something (see `stale_note`) rather than
/// passing the status through silently.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshedState {
    pub state: State,
    /// `true` when `state.pid` was no longer alive but `state.status` was
    /// not yet `Stopped` at read time.
    pub stale: bool,
}

impl RefreshedState {
    /// A short, human-readable note for callers that print `state.status`
    /// to a human (CLI stdout/stderr) — `None` when `stale` is `false`,
    /// i.e. nothing worth saying.
    pub fn stale_note(&self) -> Option<String> {
        if !self.stale {
            return None;
        }
        Some(format!(
            "container {} status is reported as {:?} but its process (pid {}) \
             is no longer running; this status may be stale until \
             kestrel-init's reaper catches up and records the real exit \
             status",
            self.state.id,
            self.state.status,
            self.state.pid.unwrap_or(-1),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_json_path_joins_run_dir_id_and_filename() {
        let run_dir = Path::new("/run/kestrel");
        let path = state_json_path(run_dir, "abc123");
        assert_eq!(path, PathBuf::from("/run/kestrel/abc123/state.json"));
    }

    #[test]
    fn test_state_json_path_is_scoped_per_id() {
        let run_dir = Path::new("/run/kestrel");
        let a = state_json_path(run_dir, "container-a");
        let b = state_json_path(run_dir, "container-b");
        assert_ne!(a, b);
    }

    fn temp_state_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-runtime-state-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    #[test]
    fn test_read_and_refresh_returns_state_unchanged_when_pid_alive() {
        let path = temp_state_path();
        let s = State {
            oci_version: "1.0.2".into(),
            id: "abc123".into(),
            status: Status::Running,
            // Our own pid is guaranteed alive for the duration of this test.
            pid: Some(std::process::id() as i32),
            bundle: "/var/lib/kestrel/bundles/abc123".into(),
            annotations: Default::default(),
            exit_code: None,
        };
        s.write_atomic(&path).unwrap();

        let refreshed = read_and_refresh(&path).unwrap();
        assert_eq!(refreshed.state, s);
        assert!(!refreshed.stale, "pid is alive, should not be flagged stale");
        assert!(refreshed.stale_note().is_none());
    }

    #[test]
    fn test_read_and_refresh_trusts_status_when_pid_is_dead_but_not_stopped() {
        // A pid that (barring an extraordinarily unlucky reuse) does not
        // correspond to a live process, to exercise the "dead pid, status
        // not yet Stopped" diagnostic branch. The important assertion is
        // that read_and_refresh does NOT synthesize/overwrite the status
        // (see the design-decision doc comment on read_and_refresh) — it
        // stays exactly what was on disk, deferring to kestrel-init's
        // reaper as the sole authority on the terminal status.
        let path = temp_state_path();
        let s = State {
            oci_version: "1.0.2".into(),
            id: "def456".into(),
            status: Status::Running,
            pid: Some(i32::MAX - 1),
            bundle: "/var/lib/kestrel/bundles/def456".into(),
            annotations: Default::default(),
            exit_code: None,
        };
        s.write_atomic(&path).unwrap();

        let refreshed = read_and_refresh(&path).unwrap();
        assert_eq!(refreshed.state.status, Status::Running);
        assert_eq!(refreshed.state, s);
        assert!(
            refreshed.stale,
            "dead pid + non-Stopped status should be flagged stale"
        );
        let note = refreshed.stale_note().expect("expected a stale note");
        assert!(note.contains("def456"));
        assert!(note.contains("stale"));
    }
}
