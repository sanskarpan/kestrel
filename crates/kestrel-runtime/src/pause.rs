// crates/kestrel-runtime/src/pause.rs
//
//! `pause` — freeze every process in a container's cgroup
//! (`cgroup.freeze`) and record `Status::Paused` in `state.json`.
//! `CgroupManager::freeze(true)` blocks until `cgroup.events` confirms the
//! transition, so by the time this returns `Ok(())` the freeze is real,
//! not just requested.

use std::path::Path;

use anyhow::Result;
use kestrel_cgroup::manager::CgroupManager;
use kestrel_oci::state::Status;

pub fn pause(id: &str, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let cgroup = CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.freeze(true)?;
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let mut state = kestrel_oci::state::State::read(&state_json_path)?;
    state.status = Status::Paused;
    state.write_atomic(&state_json_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::state::State;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    // Same "mount a second cgroup2 view at <data_dir>/cgroups" technique as
    // `create_hook_failure_no_hang.rs` / `kestrel-cgroup/tests/
    // integration.rs`'s own `test_freeze_thaw` — cgroup2 has exactly one
    // hierarchy, so any mount of it reaches the same tree. `freeze()`
    // itself already blocks on `cgroup.events` until the kernel confirms
    // the transition (Task 1's grounding), so this test just needs to
    // prove `pause()` wires that confirmed freeze up to a real process
    // AND to `state.json`.

    struct MountGuard(PathBuf);
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg(&self.0).status();
        }
    }

    struct CgroupGuard(CgroupManager);
    impl Drop for CgroupGuard {
        fn drop(&mut self) {
            // Thaw first: a cgroup can still be frozen if the test body
            // panicked before its own explicit thaw-and-cleanup ran, and
            // kill_all()/destroy() should not be left fighting a frozen
            // cgroup.
            let _ = self.0.freeze(false);
            let _ = self.0.kill_all();
            let _ = self.0.destroy();
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn test_pause_freezes_process_and_records_status_paused() {
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

        let id = format!("pause-test-{}", std::process::id());
        let cgroup = CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id");
        cgroup.create().expect("create cgroup");
        let _cgroup_guard =
            CgroupGuard(CgroupManager::new(cgroups_mount.clone(), &id).expect("valid cgroup id"));

        let run_dir = tempfile::tempdir().unwrap();
        let state_json_path = crate::state::state_json_path(run_dir.path(), &id);
        let initial = State {
            oci_version: "1.0.2".into(),
            id: id.clone(),
            status: Status::Running,
            pid: None,
            bundle: PathBuf::from("/var/lib/kestrel/bundles/pause-test"),
            annotations: Default::default(),
            exit_code: None,
        };
        initial.write_atomic(&state_json_path).unwrap();

        let counter_path =
            std::env::temp_dir().join(format!("kestrel-pause-counter-{}", std::process::id()));
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

        pause(&id, run_dir.path(), data_dir.path()).expect("pause");

        let count_at_pause = std::fs::read_to_string(&counter_path).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let count_after_wait = std::fs::read_to_string(&counter_path).unwrap();
        assert_eq!(
            count_at_pause, count_after_wait,
            "frozen process made progress"
        );

        let recorded = State::read(&state_json_path).expect("read state.json");
        assert_eq!(recorded.status, Status::Paused);

        // Cleanup: thaw before the guard's kill_all()/destroy() run.
        cgroup.freeze(false).ok();
        let _ = child.kill();
        let _ = child.wait();
        std::fs::remove_file(&counter_path).ok();
    }
}
