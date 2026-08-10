use std::time::Duration;

use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::stages::run_stages;
use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};

#[test]
#[ignore = "requires root"]
fn test_pin_survives_pid1_exit() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Uts, NsType::Mount],
            join: vec![],
            uid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getuid().as_raw(),
                size: 1,
            }],
            gid_maps: vec![IdMapping {
                container_id: 0,
                host_id: nix::unistd::getgid().as_raw(),
                size: 1,
            }],
        };

        let result = run_stages(&plan, None, || {
            std::thread::sleep(Duration::from_secs(2));
            unsafe { libc::_exit(0) };
        })
        .expect("run_stages");

        let tmp = tempfile_dir();
        let target = tmp.join("uts");
        pin_namespace(result.init_pid, NsType::Uts, &target).expect("pin_namespace");

        // Wait for PID 1 to exit on its own.
        nix::sys::wait::waitpid(result.init_pid, None).unwrap();

        // The pin must still be enterable after PID 1 is gone.
        let f = std::fs::File::open(&target).expect("pinned ns file still openable");
        drop(f);

        unpin_namespace(&target).expect("unpin_namespace");
        assert!(!target.exists(), "unpin must remove the pin file");

        std::fs::remove_dir_all(&tmp).ok();
    });
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kestrel-ns-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
