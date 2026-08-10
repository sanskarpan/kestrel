use std::path::PathBuf;

use kestrel_cgroup::manager::CgroupManager;

fn test_manager(id: &str) -> CgroupManager {
    CgroupManager::new(PathBuf::from("/sys/fs/cgroup"), id).expect("valid cgroup id")
}

#[test]
#[ignore = "requires root"]
fn test_create_enables_controllers_and_destroy_cleans_up() {
    let m = test_manager("kestrel-test-create");
    m.create().expect("create");
    assert!(m.path.join("cgroup.controllers").exists());
    // At least one requested controller's interface file should now exist
    // in the leaf (proving Rule 1's top-down enabling actually worked).
    assert!(
        m.path.join("memory.max").exists(),
        "memory controller interface missing"
    );
    let subtree_control = std::fs::read_to_string(m.path.join("cgroup.subtree_control")).unwrap();
    assert!(
        subtree_control.trim().is_empty(),
        "leaf's own subtree_control should not be enabled"
    );
    m.destroy().expect("destroy");
    assert!(!m.path.exists());
}

#[test]
#[ignore = "requires root"]
fn test_no_internal_processes_rule() {
    // Writing a PID to a cgroup that has subtree_control set (i.e. has
    // children with controllers enabled) must fail — Rule 2.
    let m = test_manager("kestrel-test-internal");
    m.create().expect("create");
    // This child dir is illustrative/for realism only (mirrors what a real
    // delegated hierarchy looks like) — it is not load-bearing: the kernel
    // check that rejects `add_process` below keys off `m.path`'s own
    // `cgroup.subtree_control` contents, not off whether a child dir exists.
    let child = m.path.join("child");
    std::fs::create_dir_all(&child).expect("mkdir child");
    // Enable a controller in `m.path` itself (not the leaf's own leaf) so
    // it now has subtree_control set, making it a non-leaf.
    std::fs::write(m.path.join("cgroup.subtree_control"), "+memory").expect("enable in m.path");

    let err = test_manager("kestrel-test-internal")
        .add_process(nix::unistd::getpid())
        .expect_err("adding a process to a non-leaf cgroup must fail");
    let io_err = err.downcast_ref::<std::io::Error>();
    assert_eq!(
        io_err.and_then(|e| e.raw_os_error()),
        Some(libc::EBUSY),
        "expected EBUSY (Rule 2 violation), got: {err}"
    );

    std::fs::remove_dir(&child).ok();
    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_freeze_thaw() {
    let m = test_manager("kestrel-test-freeze");
    m.create().expect("create");

    // Spawn a real child inside this cgroup, freeze it, confirm it stops
    // making progress, thaw it, confirm it resumes.
    let counter_path = std::env::temp_dir().join("kestrel-freeze-counter");
    std::fs::write(&counter_path, "0").unwrap();
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "for i in $(seq 1 1000); do echo $i > {}; sleep 0.01; done",
            counter_path.display()
        ))
        .spawn()
        .expect("spawn counter");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32))
        .expect("add_process");

    std::thread::sleep(std::time::Duration::from_millis(200));

    // freeze() now blocks until cgroup.events confirms frozen=1, so we no
    // longer need a blind sleep for the transition itself — just a short
    // verification window to confirm the process really stays paused
    // rather than drifting.
    m.freeze(true).expect("freeze");
    let count_at_freeze = std::fs::read_to_string(&counter_path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let count_after_wait = std::fs::read_to_string(&counter_path).unwrap();
    assert_eq!(
        count_at_freeze, count_after_wait,
        "frozen process made progress"
    );

    // thaw() is likewise confirmed synchronously, but the process still
    // needs a moment to actually execute a loop iteration afterward —
    // "frozen state cleared" and "made progress" are different things.
    m.freeze(false).expect("thaw");
    std::thread::sleep(std::time::Duration::from_millis(150));
    let count_after_thaw = std::fs::read_to_string(&counter_path).unwrap();
    assert_ne!(
        count_after_wait, count_after_thaw,
        "thawed process did not resume"
    );

    let _ = child.kill();
    let _ = child.wait();
    m.kill_all().ok();
    std::fs::remove_file(&counter_path).ok();
    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_psi_watcher_watch_succeeds_against_real_pressure_file() {
    let m = test_manager("kestrel-test-psi");
    m.create().expect("create");
    let watcher = kestrel_cgroup::psi::PsiWatcher::watch(
        &m.path.join("cpu.pressure"),
        50_000,    // stall_us
        1_000_000, // window_us (1s, within the kernel's [500ms, 10s] requirement)
    );
    assert!(
        watcher.is_ok(),
        "PsiWatcher::watch should succeed against a real cgroup pressure file: {watcher:?}"
    );

    let watcher = watcher.unwrap();
    let fired = watcher.wait(std::time::Duration::from_millis(200));
    assert!(
        !fired.unwrap(),
        "no real pressure event occurred — wait() should report false, not time out into a phantom true"
    );

    m.destroy().ok();
}

#[test]
#[ignore = "requires root"]
fn test_psi_watcher_wait_does_not_false_positive_on_cgroup_removal() {
    let m = test_manager("kestrel-test-psi-removal");
    m.create().expect("create");
    let watcher =
        kestrel_cgroup::psi::PsiWatcher::watch(&m.path.join("cpu.pressure"), 50_000, 1_000_000)
            .expect("watch");
    m.destroy().expect("destroy while watcher fd still open");
    let fired = watcher.wait(std::time::Duration::from_millis(200));
    // The exact right behavior here (Ok(false) vs an Err) depends on what
    // POLLERR/POLLHUP actually signals once the underlying file is gone —
    // but it must NOT be Ok(true) (a phantom pressure event). In practice
    // this is an Err: the kernel reports POLLPRI *together with* POLLERR
    // when a PSI trigger's cgroup is torn down, and wait() treats that
    // combination as an error rather than a genuine pressure event.
    assert!(
        !fired.unwrap_or(false),
        "destroying the cgroup must not report as a real pressure event"
    );
}

use kestrel_oci::runtime::{
    LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResourcesBuilder,
};

#[test]
#[ignore = "requires root"]
fn test_memory_limit_ooms() {
    let m = test_manager("kestrel-test-oom");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .memory(
            LinuxMemoryBuilder::default()
                .limit(32 * 1024 * 1024i64)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    m.apply_memory(&resources).expect("apply_memory");

    // NOTE: the originally-planned `sh -c "head|tail" ` pipeline + a
    // parent-side `add_process()` call was verified BY HAND to be racy in a
    // way that made the test meaningless: a shell pipeline forks its `head`
    // and `tail` stages essentially the instant the shell starts running,
    // which routinely wins the race against the parent's `add_process()`
    // syscall — `/proc/<pid>/cgroup` for `head`/`tail` showed them still in
    // the PARENT cgroup, never the leaf, so `memory.max` never applied to
    // them at all (`memory.events` stayed all-zero, no OOM, exit 0). Fork
    // the test process itself instead and have the child place ITSELF into
    // the cgroup before allocating anything — no separate process, no
    // window, no race.
    match unsafe { nix::unistd::fork() }.expect("fork") {
        nix::unistd::ForkResult::Child => {
            std::fs::write(m.path.join("cgroup.procs"), std::process::id().to_string())
                .expect("child self-placement into cgroup.procs");
            // Grow in 1MiB steps, writing a non-zero byte pattern.
            // `vec![0u8; N]` specifically must NOT be used here: Rust's
            // `Vec::from_elem` specializes the all-zero case to
            // `alloc_zeroed` (calloc-equivalent), whose pages are backed by
            // the kernel's shared read-only zero page until actually
            // written — meaning a huge all-zero vec can be "allocated"
            // without ever faulting in real, distinct physical pages, so
            // `memory.current` never rises and no OOM fires. This was
            // confirmed to be the exact failure mode of
            // `test_clone_into_cgroup_no_window`'s original `vec![0u8; N]`
            // below (child exited 0, having "allocated" 200MiB that never
            // became real RSS). Explicitly writing a non-zero pattern
            // forces every page to be faulted in for real.
            let mut v: Vec<u8> = Vec::new();
            for _ in 0..220 {
                v.extend(std::iter::repeat_n(0xABu8, 1024 * 1024));
                std::hint::black_box(&v);
            }
            unsafe { libc::_exit(0) }; // should be OOM-killed before reaching here
        }
        nix::unistd::ForkResult::Parent { child } => {
            let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
            eprintln!("test_memory_limit_ooms: child wait status = {status:?}");

            m.kill_all().ok();
            let oom_kills = m.oom_kill_count().expect("oom_kill_count");
            eprintln!("test_memory_limit_ooms: observed oom_kill_count = {oom_kills}");
            m.destroy().ok();

            assert!(
                !matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                "memory bomb should have been killed, got {status:?}"
            );
            assert!(oom_kills >= 1, "oom_kill counter did not increment");
        }
    }
}

#[test]
#[ignore = "requires root"]
fn test_cpu_throttle() {
    let m = test_manager("kestrel-test-throttle");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .cpu(
            LinuxCpuBuilder::default()
                .quota(50_000i64)
                .period(100_000u64)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    m.apply_cpu(&resources).expect("apply_cpu");

    // NOTE: the originally-planned `timeout 2 sh -c 'while :; do :; done'`
    // (an outer shell running `timeout`, which itself forks the inner shell
    // that runs the busy loop) was verified BY HAND to hit the exact same
    // escape-the-cgroup race as `test_memory_limit_ooms` above: `timeout`
    // forks its child before the parent-side `add_process()` call lands,
    // so the actual busy loop ran in the PARENT cgroup the whole time
    // (`/proc/<pid>/cgroup` confirmed it) while our leaf's `cpu.stat`
    // stayed nearly idle (observed: nr_periods=2, nr_throttled=0,
    // usage_usec=145, despite `ps` showing the loop at ~97% CPU). Spawning
    // a single `sh -c 'while :; do :; done'` directly — no `timeout`, no
    // nested shell — avoids any further fork/exec after the one exec()
    // `Command::spawn()` already waits for, so there's no window for the
    // workload to end up in the wrong cgroup; duration is bounded from the
    // Rust side instead of via `timeout`.
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("while :; do :; done")
        .spawn()
        .expect("spawn busy loop");
    m.add_process(nix::unistd::Pid::from_raw(child.id() as i32))
        .expect("add_process");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = child.kill();
    let _ = child.wait();

    let stat = m.cpu_stat().expect("cpu_stat");
    eprintln!(
        "test_cpu_throttle: observed cpu.stat = {:?} (nr_periods={}, nr_throttled={}, throttled_usec={}, usage_usec={})",
        stat, stat.nr_periods, stat.nr_throttled, stat.throttled_usec, stat.usage_usec
    );

    m.kill_all().ok();
    m.destroy().ok();

    assert!(
        stat.nr_throttled > 0,
        "expected throttling under a 50% quota busy loop"
    );
}

#[test]
#[ignore = "requires root"]
fn test_pids_limit() {
    let m = test_manager("kestrel-test-pids");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .pids(LinuxPidsBuilder::default().limit(10i64).build().unwrap())
        .build()
        .unwrap();
    m.apply_pids(&resources).expect("apply_pids");

    // NOTE: the originally-planned `timeout 3 sh -c ':(){ :|:& };:' || true`
    // has three real problems, all found by actually running it:
    //   1. `sh` on this system is dash, which rejects `:` as a function
    //      name ("Bad function name") — the fork bomb never even started.
    //   2. Even with a shell that accepts it, wrapping the workload in
    //      `timeout` + a nested shell reproduces the same escape-the-cgroup
    //      race documented on `test_memory_limit_ooms`/`test_cpu_throttle`
    //      above.
    //   3. The assertion ("a trivial `true` command still runs") is true
    //      regardless of whether pids.max held — it never actually
    //      verified the limit did anything, and an uncontrolled exponential
    //      fork bomb is real risk to the shared VM regardless.
    // Instead: fork the test process itself, self-place into the cgroup
    // (no race — see test_memory_limit_ooms), then attempt a bounded,
    // strictly LINEAR (never exponential) number of further forks — well
    // past the limit of 10 — and report back exactly how many succeeded.
    // Every forked grandchild blocks forever so the cgroup stays populated
    // above the limit for the whole attempt; `m.kill_all()` (cgroup.kill)
    // atomically reaps the entire subtree afterward regardless of process
    // ancestry.
    const ATTEMPTS: u32 = 40;
    let successes: u32 = match unsafe { nix::unistd::fork() }.expect("fork") {
        nix::unistd::ForkResult::Child => {
            std::fs::write(m.path.join("cgroup.procs"), std::process::id().to_string())
                .expect("child self-placement into cgroup.procs");
            let mut successes = 0u32;
            for _ in 0..ATTEMPTS {
                match unsafe { nix::unistd::fork() } {
                    Ok(nix::unistd::ForkResult::Child) => loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    },
                    Ok(nix::unistd::ForkResult::Parent { .. }) => successes += 1,
                    Err(_) => {} // expected once pids.max denies further forks
                }
            }
            unsafe { libc::_exit(successes.min(255) as i32) };
        }
        nix::unistd::ForkResult::Parent { child } => {
            let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
            match status {
                nix::sys::wait::WaitStatus::Exited(_, code) => code as u32,
                other => panic!("pids-limit test child ended unexpectedly: {other:?}"),
            }
        }
    };

    eprintln!(
        "test_pids_limit: {successes} of {ATTEMPTS} fork() attempts succeeded before pids.max (limit=10) started denying further forks"
    );

    m.kill_all().ok();
    m.destroy().ok();

    // `successes < ATTEMPTS` alone only proves "not unlimited" — a real
    // enforced cap of, say, 35 instead of the configured 10 would also
    // satisfy it. Pin the assertion to the actual configured value: the
    // self-placed test process occupies 1 of the 10 slots itself, so
    // exactly 9 further forks should succeed before pids.max starts
    // denying.
    assert_eq!(
        successes, 9,
        "expected exactly 9 successful forks (pids.max=10 minus the 1 slot the test process itself occupies), got {successes} — the configured limit may not have taken effect as expected"
    );
}

#[test]
#[ignore = "requires root"]
fn test_io_stat_reports_real_write_activity() {
    let m = test_manager("kestrel-test-io-stat");
    m.create().expect("create");

    // Same self-placement-before-work pattern as test_memory_limit_ooms/
    // test_cpu_throttle/test_pids_limit above, for the same reason: any
    // separately-forked child (e.g. via Command::spawn + a later
    // add_process()) races the exec and can end up doing its I/O in the
    // parent cgroup instead of the leaf, making `io.stat` never reflect it.
    let out_path = std::env::temp_dir().join("kestrel-io-stat-test.out");
    let out_path_child = out_path.clone();
    match unsafe { nix::unistd::fork() }.expect("fork") {
        nix::unistd::ForkResult::Child => {
            std::fs::write(m.path.join("cgroup.procs"), std::process::id().to_string())
                .expect("child self-placement into cgroup.procs");
            // Write a few MiB with real fsync so the kernel actually issues
            // block I/O attributed to this cgroup, not just a page-cache
            // write that might stay buffered.
            use std::io::Write;
            let mut f = std::fs::File::create(&out_path_child).expect("create out file");
            let buf = vec![0xABu8; 1024 * 1024];
            for _ in 0..4 {
                f.write_all(&buf).expect("write");
            }
            f.sync_all().expect("fsync");
            unsafe { libc::_exit(0) };
        }
        nix::unistd::ForkResult::Parent { child } => {
            let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
            assert_eq!(
                status,
                nix::sys::wait::WaitStatus::Exited(child, 0),
                "io-generating child did not exit cleanly: {status:?}"
            );
        }
    }

    let stats = m.io_stat().expect("io_stat");
    eprintln!("test_io_stat_reports_real_write_activity: observed io.stat = {stats:?}");

    m.kill_all().ok();
    m.destroy().ok();
    let _ = std::fs::remove_file(&out_path);

    assert!(
        stats.iter().any(|d| d.wbytes > 0),
        "expected at least one device to show nonzero wbytes after real writes, got {stats:?}"
    );
}

#[test]
#[ignore = "requires root"]
fn test_clone_into_cgroup_no_window() {
    // With fork()-then-write-cgroup.procs there is a window where the
    // child runs unconstrained; a memory bomb on line 1 could escape
    // memory.max. With CLONE_INTO_CGROUP it cannot — verify by placing a
    // 32MiB-limited cgroup's fd into clone_into_cgroup and confirming the
    // child (which immediately allocates far more than that) is OOM-killed
    // rather than ever completing.
    let m = test_manager("kestrel-test-clone3");
    m.create().expect("create");
    let resources = LinuxResourcesBuilder::default()
        .memory(
            LinuxMemoryBuilder::default()
                .limit(32 * 1024 * 1024i64)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    m.apply_memory(&resources).expect("apply_memory");

    // The assertion below needs to run cleanup (`m.kill_all()`/
    // `m.destroy()`) even if it fails — otherwise a failing assertion
    // panics straight out of `run_isolated` (which itself panics in the
    // parent branch on a nonzero child exit code) and skips cleanup
    // entirely, leaking the cgroup. Wrap in `catch_unwind` so cleanup is
    // unconditional, then resume the panic afterward — same pattern
    // `test_memory_limit_ooms`/`test_cpu_throttle`/`test_pids_limit` use by
    // running cleanup before their final `assert!`.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kestrel_ns::test_util::run_isolated(|| {
            let cgroup_fd =
                std::fs::File::open(&m.path).expect("open cgroup dir for O_PATH-ish fd use");
            use std::os::fd::AsRawFd;
            let clone_result = unsafe {
                kestrel_cgroup::clone3::clone_into_cgroup(
                    libc::SIGCHLD as u64,
                    cgroup_fd.as_raw_fd(),
                )
            }
            .expect("clone3");
            match clone_result {
                None => {
                    // Child: immediately try to allocate well past the limit.
                    // If clone3 placed us in the cgroup atomically, this must
                    // be killed before it can finish — there is no window.
                    //
                    // MUST be a non-zero fill value, not `vec![0u8; N]`: this
                    // was verified by hand to be the actual cause of this
                    // test's first failure (child exited 0, having "allocated"
                    // 200MiB that never became real RSS). Rust's
                    // `Vec::from_elem` specializes the all-zero case to
                    // `alloc_zeroed`, whose pages are backed by the kernel's
                    // shared read-only zero page until actually written to —
                    // so an all-zero vec can be "allocated" without the kernel
                    // ever needing to fault in real, distinct physical pages,
                    // and `memory.current` never rises. A non-zero fill value
                    // forces `Vec::from_elem`'s generic memset path, which
                    // genuinely writes every byte.
                    let _bomb: Vec<u8> = vec![0xABu8; 200 * 1024 * 1024];
                    std::hint::black_box(&_bomb);
                    unsafe { libc::_exit(0) }; // should never be reached
                }
                Some(pid) => {
                    let status = nix::sys::wait::waitpid(pid, None).expect("waitpid");
                    assert_ne!(
                        status,
                        nix::sys::wait::WaitStatus::Exited(pid, 0),
                        "child completed its allocation — it was NOT constrained from t=0"
                    );
                    // A nonzero-exit/signal death alone isn't proof of OOM —
                    // it could just as well be a crash from a bad
                    // `CloneArgs` layout/alignment bug in the low-level
                    // clone3 call, which would satisfy the assertion above
                    // just as well as a genuine OOM-kill. Pin down the
                    // actual mechanism, same as test_memory_limit_ooms does.
                    assert!(
                        m.oom_kill_count().expect("oom_kill_count") >= 1,
                        "child died but not via OOM-kill — clone3 placement may not have worked as expected"
                    );
                }
            }
        });
    }));

    m.kill_all().ok();
    m.destroy().ok();

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
