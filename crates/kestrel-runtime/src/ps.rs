// crates/kestrel-runtime/src/ps.rs
//
//! `ps` — lists every container's state by scanning `<run_dir>/*/state.json`.
//!
//! Same stale-status visibility concern as `state_cmd.rs` applies here
//! (see that module's doc comment): each entry goes through
//! `crate::state::read_and_refresh`, and a stderr note is printed for any
//! entry whose liveness probe disagreed with its stored status, so a
//! `kestrel ps` listing doesn't silently show a dead container as
//! `"running"` with zero visible indication anything might be stale.

use std::path::Path;

use anyhow::Result;
use kestrel_oci::state::State;

/// Lists every container's state by scanning `<run_dir>/*/state.json`.
///
/// A malformed/unreadable `state.json` for one container is skipped
/// (logged, not propagated) rather than failing the whole listing — one
/// corrupt entry shouldn't hide every other container from `ps`.
pub fn list(run_dir: &Path) -> Result<Vec<State>> {
    let mut states = Vec::new();
    if !run_dir.is_dir() {
        return Ok(states);
    }
    for entry in std::fs::read_dir(run_dir)? {
        let entry = entry?;
        let state_path = entry.path().join("state.json");
        if state_path.is_file() {
            match crate::state::read_and_refresh(&state_path) {
                Ok(refreshed) => {
                    if let Some(note) = refreshed.stale_note() {
                        eprintln!("kestrel: warning: {note}");
                    }
                    states.push(refreshed.state);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %state_path.display(),
                        error = %e,
                        "skipping unreadable/malformed state.json in ps listing",
                    );
                }
            }
        }
    }
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::state::Status;
    use std::path::PathBuf;

    fn write_state(run_dir: &Path, id: &str, status: Status) {
        let s = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status,
            pid: None,
            bundle: PathBuf::from(format!("/var/lib/kestrel/bundles/{id}")),
            annotations: Default::default(),
            exit_code: None,
        };
        s.write_atomic(&crate::state::state_json_path(run_dir, id))
            .unwrap();
    }

    #[test]
    fn test_list_returns_empty_vec_for_missing_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("does-not-exist");
        let states = list(&run_dir).unwrap();
        assert!(states.is_empty());
    }

    #[test]
    fn test_list_finds_all_containers() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        write_state(&run_dir, "container-a", Status::Created);
        write_state(&run_dir, "container-b", Status::Running);
        write_state(&run_dir, "container-c", Status::Stopped);

        let mut states = list(&run_dir).unwrap();
        states.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(states.len(), 3);
        assert_eq!(states[0].id, "container-a");
        assert_eq!(states[0].status, Status::Created);
        assert_eq!(states[1].id, "container-b");
        assert_eq!(states[1].status, Status::Running);
        assert_eq!(states[2].id, "container-c");
        assert_eq!(states[2].status, Status::Stopped);
    }

    #[test]
    fn test_list_skips_malformed_state_json_without_failing() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        write_state(&run_dir, "good-a", Status::Created);
        write_state(&run_dir, "good-b", Status::Running);

        // Hand-corrupt a third container's state.json.
        let bad_dir = run_dir.join("bad-container");
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(bad_dir.join("state.json"), b"{ not valid json").unwrap();

        let mut states = list(&run_dir).unwrap();
        states.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(
            states.len(),
            2,
            "malformed entry should be skipped, not fail the whole call"
        );
        assert_eq!(states[0].id, "good-a");
        assert_eq!(states[1].id, "good-b");
    }

    #[test]
    fn test_list_ignores_entries_without_state_json() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        write_state(&run_dir, "container-a", Status::Created);
        // A stray directory with no state.json at all (e.g. leftover
        // scratch dir) should just be ignored, not error.
        std::fs::create_dir_all(run_dir.join("not-a-container")).unwrap();

        let states = list(&run_dir).unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].id, "container-a");
    }
}
