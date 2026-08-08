// crates/kestrel-runtime/src/kill.rs
//
//! `kill` — send a signal to a container's entrypoint, either directly (via
//! the pid recorded in `state.json`) or to every process in the
//! container's cgroup (`--all`, mirroring `runc kill --all`: the
//! entrypoint may have already forked children that don't share its pid,
//! and a single `kill(entrypoint_pid)` wouldn't reach them).

use std::path::Path;

use anyhow::{Context, Result};
use kestrel_cgroup::manager::CgroupManager;
use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;

pub fn kill(id: &str, run_dir: &Path, data_dir: &Path, signal: Signal, all: bool) -> Result<()> {
    if all {
        let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
        cgroup.kill_all().context("cgroup.kill")
    } else {
        let refreshed =
            crate::state::read_and_refresh(&crate::state::state_json_path(run_dir, id))?;
        let pid = refreshed
            .state
            .pid
            .context("container has no recorded pid")?;
        nix_kill(Pid::from_raw(pid), signal).context("kill")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn test_kill_sends_signal_to_pid_recorded_in_state_json() {
        let run_dir = tempfile::tempdir().unwrap();
        let id = "kill-pid-test";
        let mut child = Command::new("sleep").arg("30").spawn().expect("spawn sleep");
        let pid = child.id() as i32;

        let state = kestrel_oci::state::State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: kestrel_oci::state::Status::Running,
            pid: Some(pid),
            bundle: PathBuf::from("/var/lib/kestrel/bundles/kill-pid-test"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        // Unused by the non-`all` path, but the signature requires it.
        let data_dir = tempfile::tempdir().unwrap();
        kill(id, run_dir.path(), data_dir.path(), Signal::SIGKILL, false).expect("kill");

        let status = child.wait().expect("wait");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(Signal::SIGKILL as i32),
                "child should have died from the SIGKILL kill() sent, got {status:?}"
            );
        }
    }

    #[test]
    fn test_kill_errors_when_state_has_no_recorded_pid() {
        let run_dir = tempfile::tempdir().unwrap();
        let id = "kill-no-pid-test";
        let state = kestrel_oci::state::State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: kestrel_oci::state::Status::Created,
            pid: None,
            bundle: PathBuf::from("/var/lib/kestrel/bundles/kill-no-pid-test"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let err = kill(id, run_dir.path(), data_dir.path(), Signal::SIGTERM, false)
            .expect_err("kill should fail without a recorded pid");
        assert!(format!("{err:#}").contains("no recorded pid"));
    }

    // ---- root-gated: the `--all` path goes through a real cgroup ----
    //
    // Same "mount a second cgroup2 view at <data_dir>/cgroups" technique
    // `create_hook_failure_no_hang.rs` and `kestrel-cgroup/tests/
    // integration.rs` already use — cgroup2 has exactly one hierarchy, so
    // any mount of it reaches the same tree.

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg(&self.0).status();
        }
    }

    struct CgroupGuard(CgroupManager);
    impl Drop for CgroupGuard {
        fn drop(&mut self) {
            let _ = self.0.kill_all();
            let _ = self.0.destroy();
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn test_kill_all_kills_every_process_in_cgroup() {
        let data_dir = tempfile::tempdir().unwrap();
        let cgroups_mount = data_dir.path().join("cgroups");
        std::fs::create_dir_all(&cgroups_mount).unwrap();
        let mount_status = Command::new("mount")
            .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
            .status()
            .expect("spawning mount(8)");
        assert!(
            mount_status.success(),
            "mounting a second cgroup2 view at {} failed — this test must run as root",
            cgroups_mount.display()
        );
        let _mount_guard = MountGuard(cgroups_mount.clone());

        let id = format!("kill-all-test-{}", std::process::id());
        let cgroup = CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id");
        cgroup.create().expect("create cgroup");
        let _cgroup_guard =
            CgroupGuard(CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id"));

        // Spawn several independent processes into the same cgroup — the
        // point of `cgroup.kill` (and its fallback) is that it kills every
        // process in the cgroup atomically, not just "a" process. A
        // single-child test can't distinguish that from `kill(one_pid)`,
        // so use enough children that a targeted-pid kill would visibly
        // leave survivors.
        let mut children: Vec<std::process::Child> = (0..3)
            .map(|_| Command::new("sleep").arg("30").spawn().expect("spawn sleep"))
            .collect();
        for child in &children {
            cgroup
                .add_process(nix::unistd::Pid::from_raw(child.id() as i32))
                .expect("add_process");
        }
        std::thread::sleep(Duration::from_millis(100));

        // `run_dir` is unused by the `all` path — `kill()` never touches
        // state.json when killing the whole cgroup.
        let run_dir = tempfile::tempdir().unwrap();
        kill(&id, run_dir.path(), data_dir.path(), Signal::SIGKILL, true).expect("kill --all");

        for child in &mut children {
            let status = child.wait().expect("wait");
            assert!(
                !status.success(),
                "every process in the cgroup should have been killed via cgroup.kill, \
                 not just some — pid {} exited cleanly: {status:?}",
                child.id()
            );
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(
                    status.signal(),
                    Some(Signal::SIGKILL as i32),
                    "pid {} should have died from SIGKILL via cgroup.kill, got {status:?}",
                    child.id()
                );
            }
        }
    }
}
