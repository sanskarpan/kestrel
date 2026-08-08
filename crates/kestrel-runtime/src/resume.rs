// crates/kestrel-runtime/src/resume.rs
//
//! `resume` — thaw a paused container's cgroup (`cgroup.freeze`) and
//! record `Status::Running` in `state.json`. `CgroupManager::freeze(false)`
//! blocks until `cgroup.events` confirms the thaw, so by the time this
//! returns `Ok(())` the container is really running again, not just
//! requested to resume.

use std::path::Path;

use anyhow::Result;
use kestrel_cgroup::manager::CgroupManager;
use kestrel_oci::state::Status;

pub fn resume(id: &str, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.freeze(false)?;
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = kestrel_oci::state::State::read(&state_json_path)?;
    state.status = Status::Running;
    state.write_atomic(&state_json_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::state::State;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    // Same real-cgroup2-mount technique as `pause.rs`'s tests and
    // `kestrel-cgroup/tests/integration.rs`'s `test_freeze_thaw`.
    // `freeze()` itself already blocks on `cgroup.events` until the
    // kernel confirms the transition, so this test just needs to prove
    // `resume()` wires that confirmed thaw up to a real process AND to
    // `state.json`.

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg(&self.0).status();
        }
    }

    struct CgroupGuard(CgroupManager);
    impl Drop for CgroupGuard {
        fn drop(&mut self) {
            let _ = self.0.freeze(false);
            let _ = self.0.kill_all();
            let _ = self.0.destroy();
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn test_resume_thaws_process_and_records_status_running() {
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

        let id = format!("resume-test-{}", std::process::id());
        let cgroup = CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id");
        cgroup.create().expect("create cgroup");
        let _cgroup_guard =
            CgroupGuard(CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id"));

        let run_dir = tempfile::tempdir().unwrap();
        let state_json_path = crate::state::state_json_path(run_dir.path(), &id);
        let initial = State {
            oci_version: "1.0.2".into(),
            id: id.clone(),
            status: Status::Paused,
            pid: None,
            bundle: PathBuf::from("/var/lib/kestrel/bundles/resume-test"),
            annotations: Default::default(),
            exit_code: None,
        };
        initial.write_atomic(&state_json_path).unwrap();

        let counter_path =
            std::env::temp_dir().join(format!("kestrel-resume-counter-{}", std::process::id()));
        std::fs::write(&counter_path, "0").unwrap();
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "for i in $(seq 1 1000); do echo $i > {}; sleep 0.01; done",
                counter_path.display()
            ))
            .spawn()
            .expect("spawn counter");
        cgroup
            .add_process(nix::unistd::Pid::from_raw(child.id() as i32))
            .expect("add_process");
        std::thread::sleep(Duration::from_millis(200));

        // Freeze directly (not via `pause()`) so this test isolates
        // `resume()` under test rather than depending on `pause()` too.
        cgroup.freeze(true).expect("freeze");
        let count_at_freeze = std::fs::read_to_string(&counter_path).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let count_after_wait = std::fs::read_to_string(&counter_path).unwrap();
        assert_eq!(
            count_at_freeze, count_after_wait,
            "frozen process made progress before resume() was even called"
        );

        resume(&id, run_dir.path(), data_dir.path()).expect("resume");

        std::thread::sleep(Duration::from_millis(150));
        let count_after_resume = std::fs::read_to_string(&counter_path).unwrap();
        assert_ne!(
            count_after_wait, count_after_resume,
            "thawed process did not resume"
        );

        let recorded = State::read(&state_json_path).expect("read state.json");
        assert_eq!(recorded.status, Status::Running);

        let _ = child.kill();
        let _ = child.wait();
        std::fs::remove_file(&counter_path).ok();
    }
}
