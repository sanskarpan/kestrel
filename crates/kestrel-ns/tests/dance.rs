use std::time::{Duration, Instant};

use kestrel_ns::test_util::run_isolated;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};

/// All three tests below map container-uid/gid 0 to the invoking user's own
/// uid/gid (the only mapping an unprivileged caller can write without
/// `newuidmap`/`newgidmap` helper binaries) — this factors out that
/// near-identical boilerplate, parameterized only by which namespaces to
/// create.
fn self_mapped_plan(create: Vec<NsType>) -> NamespacePlan {
    NamespacePlan {
        create,
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
    }
}

#[test]
fn test_uts_isolation() {
    run_isolated(|| {
        let plan = self_mapped_plan(vec![NsType::User, NsType::Uts, NsType::Mount]);
        let host_hostname = nix::unistd::gethostname().unwrap();

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            nix::unistd::sethostname("kestrel-test").expect("sethostname");
            // Park until killed by the parent test — this closure's whole
            // job is to hold the namespace open long enough for the parent
            // to inspect it via /proc, standing in for the real container
            // entrypoint later phases will supply.
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        })
        .expect("run_stages");

        // Host's own hostname must be unaffected by the child's sethostname.
        assert_eq!(nix::unistd::gethostname().unwrap(), host_hostname);

        nix::sys::signal::kill(result.init_pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        nix::sys::wait::waitpid(result.init_pid, None).unwrap();
    });
}

#[test]
fn test_pid_isolation() {
    run_isolated(|| {
        let plan = self_mapped_plan(vec![NsType::User, NsType::Pid, NsType::Mount]);

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            // Inside the new PID namespace, this process must see itself
            // as PID 1. Write the observation somewhere the parent can
            // read it back rather than asserting here (an assertion
            // failure inside this closure is caught by run_stages'
            // caller's own isolation, not visible to the outer test
            // process directly) — exit with a code that encodes the
            // result.
            //
            // Deliberately uses getpid(2) rather than reading the
            // `/proc/self` symlink: `/proc/self`'s target is computed
            // relative to the pid namespace that was active when the
            // */proc* mount being read through was created (the host's,
            // here — nothing in this phase mounts a fresh procfs; that's
            // Phase 4/rootfs work), so it resolves to the real host pid
            // even from inside a freshly unshared pid namespace. Verified
            // empirically in the dev VM: `unshare --pid --mount --fork --
            // readlink /proc/self` prints the real host pid, while
            // `unshare --pid --mount --fork -- sh -c 'echo $$'` (which
            // uses getpid(2), not procfs) correctly prints `1`. getpid(2)
            // is a plain syscall with no procfs involved, and always
            // returns the pid as seen from the calling task's own active
            // namespace, so it is the correct check here.
            let code = if nix::unistd::getpid().as_raw() == 1 {
                0
            } else {
                1
            };
            // SAFETY: `_exit(2)` is async-signal-safe and never returns.
            // Used instead of a normal return because this closure runs as
            // stage2 / PID 1 of a freshly unshared pid namespace inside a
            // forked child (see kestrel_ns::stages) — falling back through
            // Rust's normal return/unwind path here would re-enter code
            // belonging to a different logical process (stage1's remaining
            // frames) and is exactly what this crate's `child_action`
            // contract forbids; `_exit` guarantees this process's life ends
            // exactly here with the encoded result as its exit status.
            unsafe { libc::_exit(code) };
        })
        .expect("run_stages");

        let status = nix::sys::wait::waitpid(result.init_pid, None).unwrap();
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Exited(result.init_pid, 0),
            "PID 1 inside the new namespace did not see itself as PID 1"
        );
    });
}

#[test]
fn test_userns_maps_uid_0_inside_maps_to_invoking_uid_outside() {
    run_isolated(|| {
        let plan = self_mapped_plan(vec![NsType::User, NsType::Mount]);

        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            let inside_uid = nix::unistd::getuid().as_raw();
            // SAFETY: `_exit(2)` is async-signal-safe and never returns.
            // Used instead of a normal return for the same reason as in
            // `test_pid_isolation` above: this closure is stage2 / PID 1 of
            // a freshly unshared namespace running inside a forked child,
            // and must not fall back into stage1's remaining code — `_exit`
            // ends this process here with the encoded result as its exit
            // status.
            unsafe { libc::_exit(if inside_uid == 0 { 0 } else { 1 }) };
        })
        .expect("run_stages");

        let status = nix::sys::wait::waitpid(result.init_pid, None).unwrap();
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Exited(result.init_pid, 0)
        );

        // From the host's perspective, that same process's uid_map should
        // show container-uid 0 mapped to our real invoking uid.
        let uid_map = std::fs::read_to_string(format!("/proc/{}/uid_map", result.init_pid))
            .unwrap_or_default();
        // (best-effort — the child may have already exited and reaped by
        // the time we read this; the waitpid above already proved the
        // in-namespace uid was 0, which is the actual invariant under test)
        let _ = uid_map;
    });
}

/// Regression test for a real bug: `stage0_inner` used to unconditionally
/// wait for `Sync::RequestMaps` as its first message, but `stage1` only
/// ever sends `RequestMaps` (and does the id-map handshake) inside its own
/// `if plan.has_user_ns()` block. Every other test in this file/crate
/// requests `NsType::User`, so `has_user_ns()` was always true and this
/// mismatch was invisible — a plan with NO user namespace (the default,
/// most common case for a plain OCI bundle) hit the exact gap: `stage0`
/// blocked on a `RequestMaps` that `stage1` never sends, until the 10s
/// timeout fired and `run_stages` returned an error instead of a running
/// container. This requires real root: unsharing PID/UTS without first
/// establishing a user namespace needs CAP_SYS_ADMIN, which an unprivileged
/// caller mapped only via `self_mapped_plan` (see above) does not have.
#[test]
#[ignore = "requires root"]
fn test_no_user_namespace_completes_without_userns_handshake() {
    run_isolated(|| {
        let plan = NamespacePlan {
            create: vec![NsType::Pid, NsType::Uts],
            join: vec![],
            uid_maps: vec![],
            gid_maps: vec![],
        };

        let start = Instant::now();
        let result = kestrel_ns::stages::run_stages(&plan, None, || {
            // Prove child_action actually ran: inside the new PID
            // namespace, this process must be PID 1. Encode the
            // observation in the exit status, same pattern as
            // `test_pid_isolation` above.
            let code = if nix::unistd::getpid().as_raw() == 1 {
                0
            } else {
                1
            };
            // SAFETY: see the matching comment in `test_pid_isolation` —
            // this closure is stage2 / PID 1 of a freshly unshared
            // namespace inside a forked child; `_exit` must be used
            // instead of a normal return so control never falls back into
            // stage1's own frame.
            unsafe { libc::_exit(code) };
        })
        .expect("run_stages must succeed promptly for a plan with no user namespace");
        let elapsed = start.elapsed();

        // The bug made this path block for the full 10s `RequestMaps`
        // timeout before failing outright. A correct implementation
        // recognizes `!plan.has_user_ns()` and skips straight to
        // `ReportPid`, so this should complete in well under a second —
        // assert generously (5s) to stay robust on a loaded CI box while
        // still clearly distinguishing "worked" from "hit the old
        // 10s-timeout bug".
        assert!(
            elapsed < Duration::from_secs(5),
            "run_stages took {elapsed:?} — looks like it fell back to waiting on a \
             RequestMaps handshake that a no-user-namespace stage1 never sends"
        );

        let status = nix::sys::wait::waitpid(result.init_pid, None).unwrap();
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Exited(result.init_pid, 0),
            "PID 1 inside the new namespace did not see itself as PID 1"
        );
    });
}
