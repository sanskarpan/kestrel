use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("invalid cgroup id {0:?}: must be non-empty and contain only [A-Za-z0-9_.-], no path separators or '..'")]
    InvalidId(String),
}

pub struct CgroupManager {
    pub root: PathBuf, // /sys/fs/cgroup
    pub path: PathBuf, // /sys/fs/cgroup/kestrel/<id>
    pub delegated: bool,
}

impl CgroupManager {
    pub fn new(root: PathBuf, id: &str) -> Result<Self, CgroupError> {
        let valid = !id.is_empty()
            && id != "."
            && id != ".."
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
        if !valid {
            return Err(CgroupError::InvalidId(id.to_string()));
        }
        let path = root.join("kestrel").join(id);
        Ok(CgroupManager {
            root,
            path,
            delegated: false,
        })
    }

    /// Creates the leaf cgroup and enables the controllers Rule 1 (top-down
    /// enabling) requires in every ancestor. Does NOT apply resource limits
    /// — that's the individual `apply_cpu`/`apply_memory`/`apply_pids`/
    /// `apply_io`/`apply_hugetlb` methods in `resources.rs`, called
    /// separately by whichever ones a given `LinuxResources` needs.
    pub fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.path)
            .with_context(|| format!("creating cgroup dir {}", self.path.display()))?;
        self.enable_controllers_in_parents()
    }

    /// Removes the leaf cgroup. Retries on EBUSY for up to ~1s — a cgroup
    /// whose processes just received a kill signal isn't empty
    /// instantaneously; the kernel needs a moment to actually reap them.
    pub fn destroy(&self) -> Result<()> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("removing cgroup dir {}", self.path.display()));
                }
            }
        }
    }

    pub fn read_available_controllers(&self, at: &std::path::Path) -> Result<Vec<String>> {
        let contents = fs::read_to_string(at.join("cgroup.controllers"))
            .with_context(|| format!("reading cgroup.controllers at {}", at.display()))?;
        Ok(parse_controllers(&contents))
    }

    pub(crate) fn write(&self, file: &str, value: &str) -> Result<()> {
        fs::write(self.path.join(file), value)
            .with_context(|| format!("writing {value:?} to {}", self.path.join(file).display()))
    }
}

fn parse_controllers(contents: &str) -> Vec<String> {
    contents.split_whitespace().map(String::from).collect()
}

impl CgroupManager {
    /// Walk from root to our parent, adding controllers to each ancestor's
    /// `cgroup.subtree_control` — Rule 1: a controller's interface files
    /// exist in a cgroup only if the PARENT listed it. Never enable in the
    /// leaf itself (Rule 2: a cgroup with subtree_control set may not
    /// contain processes, and containers always live in the leaf).
    pub fn enable_controllers_in_parents(&self) -> Result<()> {
        let available = self.read_available_controllers(&self.root)?;
        let want = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"];
        let spec = build_subtree_control_spec(&want, &available);

        let rel = self
            .path
            .strip_prefix(&self.root)
            .context("cgroup path is not under root")?;
        let mut cur = self.root.clone();
        for comp in rel.components() {
            if let Err(e) = fs::write(cur.join("cgroup.subtree_control"), &spec) {
                if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                    return Err(e).with_context(|| {
                        format!(
                            "enabling controllers in {} (permission denied)",
                            cur.display()
                        )
                    });
                }
                tracing::warn!(path = %cur.display(), error = %e, "subtree_control write failed (often benign — already enabled)");
            }
            cur = cur.join(comp);
            if cur == self.path {
                break; // never enable in the leaf itself
            }
        }
        Ok(())
    }

    /// Adds `pid` to this cgroup. Must be called on a LEAF cgroup (Rule 2)
    /// — writing to a cgroup with subtree_control set fails.
    pub fn add_process(&self, pid: nix::unistd::Pid) -> Result<()> {
        self.write("cgroup.procs", &pid.as_raw().to_string()).context(
            "failed to add process — if this cgroup has subtree_control set, Rule 2 (no internal processes) forbids adding processes to it",
        )
    }
}

fn build_subtree_control_spec(want: &[&str], available: &[String]) -> String {
    want.iter()
        .filter(|c| available.iter().any(|a| a == *c))
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_manager_path_is_root_joined_with_relative_id() {
        let m = CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), "abc123").unwrap();
        assert_eq!(m.path, PathBuf::from("/sys/fs/cgroup/kestrel/abc123"));
    }

    #[test]
    fn test_new_rejects_path_traversal_id() {
        assert!(CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), "../../etc").is_err());
    }

    #[test]
    fn test_new_rejects_empty_id() {
        assert!(CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), "").is_err());
    }

    #[test]
    fn test_read_available_controllers_parses_space_separated_list() {
        let parsed = parse_controllers("cpuset cpu io memory hugetlb pids rdma misc\n");
        assert_eq!(
            parsed,
            vec!["cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc"]
        );
    }

    #[test]
    fn test_read_available_controllers_handles_empty() {
        assert!(parse_controllers("").is_empty());
        assert!(parse_controllers("\n").is_empty());
    }

    #[test]
    fn test_enable_controllers_spec_string_filters_to_available() {
        let want = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"];
        let available = vec!["cpu".to_string(), "memory".to_string(), "pids".to_string()];
        let spec = build_subtree_control_spec(&want, &available);
        assert_eq!(spec, "+cpu +memory +pids");
    }
}
