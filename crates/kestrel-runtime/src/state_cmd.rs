// crates/kestrel-runtime/src/state_cmd.rs
//
//! `state` — the OCI runtime-spec `state` subcommand: reads and returns a
//! single container's `state.json` (liveness-refreshed via
//! `crate::state::read_and_refresh`).
//!
//! ## Stale-status visibility (resolving Task 3 review's carried-forward note)
//!
//! `read_and_refresh` deliberately never overwrites `state.json`'s
//! `status` field itself (see its own doc comment — only kestrel-init's
//! reaper can know the real exit code), but it DOES tell us, via
//! `RefreshedState::stale`, when the pid-liveness probe disagreed with
//! that status. If `state()` just returned `refreshed.state` and dropped
//! that signal on the floor, a caller/user running `kestrel state <id>`
//! could see `"status": "running"` for a container whose process has
//! already exited, with literally no way to know that from the CLI
//! output — only a `tracing::warn!` line in the trace log, which normal
//! CLI usage doesn't surface at all (no `RUST_LOG` set, log go to
//! wherever `tracing_subscriber` is configured to write, not to the
//! terminal a human is looking at).
//!
//! The fix here: `state()` still returns the OCI-spec-shaped `State`
//! unchanged on stdout/JSON (so it doesn't invent new fields in an
//! output format other tooling parses), but prints a one-line warning to
//! stderr whenever `RefreshedState::stale` is true. This is cheap, keeps
//! the machine-readable output spec-compliant, and makes the disagreement
//! visible in completely ordinary CLI usage (a human watching a terminal
//! sees stdout AND stderr) instead of requiring a trace log a user isn't
//! looking at.

use std::path::Path;

use anyhow::Result;
use kestrel_oci::state::State;

pub fn state(id: &str, run_dir: &Path) -> Result<State> {
    let refreshed = crate::state::read_and_refresh(&crate::state::state_json_path(run_dir, id))?;
    if let Some(note) = refreshed.stale_note() {
        eprintln!("kestrel: warning: {note}");
    }
    Ok(refreshed.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::state::Status;
    use std::path::PathBuf;

    #[test]
    fn test_state_returns_state_for_existing_container() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        let id = "abc123";
        let s = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Created,
            pid: None,
            bundle: PathBuf::from("/var/lib/kestrel/bundles/abc123"),
            annotations: Default::default(),
            exit_code: None,
        };
        s.write_atomic(&crate::state::state_json_path(&run_dir, id))
            .unwrap();

        let result = state(id, &run_dir).unwrap();
        assert_eq!(result, s);
    }

    #[test]
    fn test_state_errors_for_missing_container() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        let result = state("does-not-exist", &run_dir);
        assert!(result.is_err());
    }
}
