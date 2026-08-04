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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    /// In the RUNTIME's pid namespace, not the container's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
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
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"ociVersion\":\"1.0.2\""));
        assert!(json.contains("\"status\":\"running\""));
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
}
