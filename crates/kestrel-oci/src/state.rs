use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
    /// Not part of the official OCI runtime-spec state schema — kestrel's
    /// extension for `cgroup.freeze`-backed pause/resume (SPEC.md §9.1).
    Paused,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    /// In the RUNTIME's pid namespace, not the container's. Before the
    /// container's entrypoint is forked (`Status::Creating`/`Created`),
    /// this is `kestrel-init`'s own pid — the only live process
    /// representing the container at that point, blocked on the exec
    /// FIFO. Once the entrypoint exists, this is updated to the
    /// entrypoint's own real (host-namespace) pid, so `kill.rs`'s
    /// non-`--all` path (which signals this field directly) reaches the
    /// actual workload rather than `kestrel-init`/PID 1 itself.
    ///
    /// That update is performed by `kestrel-runtime`'s own `start.rs`
    /// (host-side), NOT by `kestrel-init` — a deliberate correction (Phase
    /// 8 Task 16): `kestrel-init` runs AS PID 1 of a freshly unshared pid
    /// namespace and has no way to learn a host-relative pid for anything,
    /// including its own children — a raw `fork()` return value inside
    /// `kestrel-init` is only ever meaningful within the container's OWN
    /// pid namespace (commonly a tiny number like `2`), and writing that
    /// here would corrupt this field with a value that generally collides
    /// with a real, unrelated, always-alive process on the host (pid 2 is
    /// commonly `kthreadd`). Only the runtime side can correctly resolve
    /// this, since it already knows kestrel-init's own real, host-relative
    /// pid (recorded here at `Created` time, from `create()`'s
    /// `run_stages` return value) and can read
    /// `/proc/<that pid>/task/.../children` from its OWN (host) namespace
    /// to find the entrypoint's host-relative pid once it exists — see
    /// `start.rs`'s own doc comment for the mechanism.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Not part of the official OCI state schema — same kind of
    /// kestrel-specific extension `Status::Paused` already is. `None`
    /// while the container hasn't stopped yet; `Some(code)` once
    /// kestrel-init's reaper has observed the entrypoint's real exit
    /// status and written it here (128+signum for a signal death, the
    /// raw exit code otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl State {
    /// Write-temp-then-rename, the same atomicity pattern every other
    /// piece of durable state in this project uses (kestrel-image's
    /// ContentStore, kestrel-net's Ipam, etc.). Lives here (not
    /// duplicated in both kestrel-runtime's and kestrel-init's own
    /// wrapper modules) because BOTH binaries need to write state.json
    /// atomically — kestrel-runtime during create/start/delete,
    /// kestrel-init once, when the entrypoint exits.
    pub fn write_atomic(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use anyhow::Context;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp_path = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self).context("serializing State")?;
        std::fs::write(&tmp_path, &data)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;
        Ok(())
    }

    pub fn read(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_round_trips_through_json() {
        let s = State {
            oci_version: "1.0.2".into(),
            id: "abc123".into(),
            status: Status::Running,
            pid: Some(4242),
            bundle: "/var/lib/kestrel/bundles/abc123".into(),
            annotations: Default::default(),
            exit_code: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"ociVersion\":\"1.0.2\""));
        assert!(json.contains("\"status\":\"running\""));
        assert!(!json.contains("exitCode") && !json.contains("exit_code"));
        let back: State = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn test_status_paused_is_not_part_of_oci_schema_but_serializes() {
        let json = serde_json::to_string(&Status::Paused).unwrap();
        assert_eq!(json, "\"paused\"");
        let back: Status = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Status::Paused);
    }

    #[test]
    fn test_exit_code_round_trips_when_present() {
        let s = State {
            oci_version: "1.0.2".into(),
            id: "abc123".into(),
            status: Status::Stopped,
            pid: Some(4242),
            bundle: "/var/lib/kestrel/bundles/abc123".into(),
            annotations: Default::default(),
            exit_code: Some(42),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"exit_code\":42"));
        let back: State = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn test_write_atomic_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-oci-state-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let s = State {
            oci_version: "1.0.2".into(),
            id: "abc123".into(),
            status: Status::Running,
            pid: Some(4242),
            bundle: "/var/lib/kestrel/bundles/abc123".into(),
            annotations: Default::default(),
            exit_code: None,
        };
        s.write_atomic(&path).unwrap();

        let back = State::read(&path).unwrap();
        assert_eq!(back, s);

        let tmp_path = path.with_extension("tmp");
        assert!(
            !tmp_path.exists(),
            "temp file should not survive write_atomic"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
