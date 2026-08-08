// crates/kestrel-runtime/tests/delete_teardown.rs
//
//! Root-gated end-to-end coverage for `delete.rs`: a real `create()` then
//! `delete()` sequence, proving the cgroup, namespace pins, and on-disk
//! state directory are genuinely cleaned up — not just that `delete()`
//! returns `Ok(())`.
//!
//! Reuses the same test infrastructure `create_pins_namespaces.rs` /
//! `create_hook_failure_no_hang.rs` already established: the
//! `fixture-stub-init` sibling-binary trick (`install_stub_kestrel_init`)
//! and the "mount a second cgroup2 view at `data_dir/cgroups`" technique.
//! Each test file in this crate duplicates this small helper set rather
//! than sharing a module — matching this crate's own established
//! convention (`create_pins_namespaces.rs` and
//! `create_hook_failure_no_hang.rs` each already do this independently).
//!
//! ## Why these tests never call `start()`
//!
//! The fixture `kestrel-init` stand-in (`tests/fixtures/stub_init.rs`)
//! just blocks forever — it never mounts a real overlay, never runs a
//! reaper, and never writes anything back to `state.json`. So after
//! `create()` returns, `state.json` genuinely says `Status::Created` (not
//! `Running` — nothing in this test's setup ever calls `start`, and
//! nothing here needs to).
//!
//! `delete.rs`'s step 1 now checks REAL pid liveness (`kill(pid, None)`),
//! not the `status` label (see `delete.rs`'s own doc comment for why) — so
//! a `Created`-status container's blocked-forever stub process is exactly
//! the case that matters here: `test_create_then_delete_cleans_up_cgroup_pins_and_state_dir`
//! kills+reaps it before calling `delete(force=false)`, exercising the
//! "process already dead" teardown path; `test_create_then_delete_force_kills_live_created_container`
//! leaves it genuinely alive and calls `delete()` both without and with
//! `--force`, proving the reject-without-force and force-kill-with-force
//! paths both work correctly for a `Created` container end-to-end.
//! `delete.rs`'s own unit tests separately cover the same logic against
//! Running/Paused/Stopped/no-pid states without needing this heavier
//! end-to-end rig.

use std::path::{Path, PathBuf};
use std::process::Command;

use kestrel_oci::default_spec::default_spec;
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType};
use kestrel_oci::state::{State, Status};
use kestrel_ns::types::NsType;
use kestrel_runtime::bundle::Bundle;

struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// Kills (SIGKILL) and reaps the spawned stub-init process on drop,
/// best-effort — it blocks forever, so without this a panic before
/// `delete()` runs (which itself force-kills nothing here, since status
/// stays `Created`) would leak a root-owned process. Only used as a
/// belt-and-suspenders fallback: the happy path's own `delete()` call
/// doesn't kill this process either (status is `Created`, not
/// `Running`), so this guard is what actually reaps it in EVERY path,
/// including the success path.
struct ProcessGuard(nix::unistd::Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

/// Same as `create_pins_namespaces.rs`'s helper of the same name:
/// installs `fixture-stub-init` as a sibling of this test binary, named
/// literally `kestrel-init`, matching `create.rs`'s
/// `resolve_kestrel_init_path` sibling-binary convention.
fn install_stub_kestrel_init() -> PathBuf {
    let stub = PathBuf::from(env!("CARGO_BIN_EXE_fixture-stub-init"));
    let current_exe = std::env::current_exe().expect("current_exe");
    let sibling_dir = current_exe
        .parent()
        .expect("current_exe has a parent directory")
        .to_path_buf();
    let target = sibling_dir.join("kestrel-init");
    let tmp = sibling_dir.join(format!(".kestrel-init.tmp.{}", nix::unistd::getpid()));
    std::fs::copy(&stub, &tmp).expect("copy fixture-stub-init to tmp");
    std::fs::rename(&tmp, &target).expect("rename tmp into place as sibling kestrel-init");
    target
}

/// `default_namespaces()` (Pid, Network, Ipc, Uts, Mount, Cgroup) minus
/// `Mount`, plus User — same routing-around as `create_pins_namespaces.rs`:
/// this Lima VM cannot bind-mount Mount namespaces at all (real,
/// documented `EINVAL` limitation — see `kestrel-ns/tests/join.rs`), and
/// `create.rs`'s all-or-nothing pinning policy means a plan containing
/// `Mount` never reaches `Status::Created` here. A User namespace is
/// needed to route around a separate, pre-existing `stage0_inner`
/// mismatch documented in `create_hook_failure_no_hang.rs`.
fn namespaces_without_mount_plus_user() -> Vec<LinuxNamespace> {
    use kestrel_oci::default_spec::default_namespaces;
    let mut namespaces: Vec<LinuxNamespace> = default_namespaces()
        .into_iter()
        .filter(|ns| ns.typ() != LinuxNamespaceType::Mount)
        .collect();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()
            .expect("build user namespace"),
    );
    namespaces
}

/// Builds the in-memory `Bundle` `create()` takes AND writes a real
/// `config.json` to `bundle_dir` — unlike `create_pins_namespaces.rs`'s
/// helper of the same name (which only needs the in-memory `Bundle`,
/// since `create()` itself never re-reads `config.json` from disk), this
/// test's `delete()` call reloads the bundle via `kestrel_runtime::bundle::
/// load(&state.bundle)` (to re-derive the namespace plan and find
/// `poststop` hooks), which genuinely reads `config.json` off disk — so a
/// real file has to be there for that reload to succeed.
fn bundle_with_namespaces(bundle_dir: &Path, namespaces: Vec<LinuxNamespace>) -> Bundle {
    std::fs::create_dir_all(bundle_dir.join("rootfs")).expect("mkdir rootfs");

    let mut spec = default_spec();
    let uid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0u32)
        .host_id(nix::unistd::getuid().as_raw())
        .size(1u32)
        .build()
        .expect("build uid mapping");
    let gid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0u32)
        .host_id(nix::unistd::getgid().as_raw())
        .size(1u32)
        .build()
        .expect("build gid mapping");
    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .build()
        .expect("build linux section");
    spec.set_linux(Some(linux));

    let raw = RawSpec {
        spec: spec.clone(),
        extra: serde_json::Map::new(),
    };
    let data = serde_json::to_vec_pretty(&raw).expect("serialize config.json");
    std::fs::write(bundle_dir.join("config.json"), data).expect("write config.json");

    Bundle {
        path: bundle_dir.to_path_buf(),
        spec: raw,
    }
}

/// Real cgroup2 mount at `data_dir/cgroups`, same technique used
/// throughout this crate's root-gated tests.
fn setup_dirs(id: &str) -> (tempfile::TempDir, tempfile::TempDir, MountGuard) {
    let data_dir = tempfile::tempdir().expect("data_dir tempdir");
    let cgroups_mount = data_dir.path().join("cgroups");
    std::fs::create_dir_all(&cgroups_mount).expect("mkdir cgroups mountpoint");
    let mount_status = Command::new("mount")
        .args(["-t", "cgroup2", "none", cgroups_mount.to_str().unwrap()])
        .status()
        .expect("spawning mount(8)");
    assert!(
        mount_status.success(),
        "mounting a second cgroup2 view at {} failed — this test must run as root",
        cgroups_mount.display()
    );
    let mount_guard = MountGuard(cgroups_mount.clone());

    let run_dir = tempfile::tempdir().expect("run_dir tempdir");
    let _ = id;
    (run_dir, data_dir, mount_guard)
}

#[test]
#[ignore = "requires root"]
fn test_create_then_delete_cleans_up_cgroup_pins_and_state_dir() {
    // `run_stages` (deep inside `create()`) requires a single-threaded
    // calling process — cargo test's harness never is. Same isolation
    // pattern as every other root-gated test in this crate.
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let bundle = bundle_with_namespaces(bundle_dir.path(), namespaces_without_mount_plus_user());

        let id = format!("delete-e2e-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard) = setup_dirs(&id);

        // ---- create() a real container ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(
            result.is_ok(),
            "create() should succeed (no createRuntime hooks, no Mount namespace in this \
             environment): {:?}",
            result.err()
        );

        let state_json_path = run_dir.path().join(&id).join("state.json");
        let created_state = State::read(&state_json_path).expect("read state.json after create");
        assert_eq!(created_state.status, Status::Created);
        let container_pid = nix::unistd::Pid::from_raw(
            created_state.pid.expect("state.json must carry a pid after create()"),
        );
        // Guard the blocked-forever stub process — belt and suspenders in
        // case an assertion below panics before the explicit kill+reap
        // just below runs.
        let process_guard = ProcessGuard(container_pid);

        // This test exercises the realistic "process already exited (or
        // was killed externally) before delete() runs" precondition —
        // e.g. the entrypoint already died on its own — with
        // `force=false`. delete()'s step 1 now checks REAL pid liveness
        // (`kill(pid, None)`, not the `status` label — see delete.rs's
        // own doc comment), so with the process already dead here it
        // correctly finds nothing to kill and proceeds straight to
        // teardown. (A genuinely-alive Created container is covered
        // separately below, by `test_create_then_delete_force_kills_live_created_container`,
        // which proves delete() force-kills it instead of either bailing
        // incorrectly or silently ignoring it.)
        nix::sys::signal::kill(container_pid, nix::sys::signal::Signal::SIGKILL)
            .expect("kill stub container process");
        nix::sys::wait::waitpid(container_pid, None).expect("reap stub container process");

        // ---- preconditions: prove the things delete() is supposed to
        // tear down are genuinely present first, so the post-delete
        // assertions mean something ----
        let cgroup_path = data_dir.path().join("cgroups").join("kestrel").join(&id);
        assert!(cgroup_path.exists(), "cgroup should exist after create()");

        let ns_dir = run_dir.path().join(&id).join("ns");
        let pinned_types = [
            NsType::Pid,
            NsType::Net,
            NsType::Ipc,
            NsType::Uts,
            NsType::Cgroup,
            NsType::User,
        ];
        for ns in pinned_types {
            assert!(
                ns_dir.join(ns.proc_name()).exists(),
                "expected a pin file for {ns:?} before delete()"
            );
        }

        // ---- the real call under test ----
        // The container's process was killed and reaped just above, so
        // delete()'s pid-liveness check finds nothing alive and proceeds
        // straight to teardown with force=false.
        let delete_result =
            kestrel_runtime::delete::delete(&id, run_dir.path(), data_dir.path(), false);
        assert!(
            delete_result.is_ok(),
            "delete() should succeed with no partial failures: {:?}",
            delete_result.err()
        );

        // ---- proof: cgroup destroyed ----
        assert!(
            !cgroup_path.exists(),
            "cgroup directory {} should have been destroyed by delete()",
            cgroup_path.display()
        );

        // ---- proof: every namespace pin unmounted and removed ----
        for ns in pinned_types {
            let pin_path = ns_dir.join(ns.proc_name());
            assert!(
                !pin_path.exists(),
                "pin file for {ns:?} at {} should have been unpinned by delete()",
                pin_path.display()
            );
        }

        // ---- proof: the state directory itself is gone (step 7 ran) ----
        let state_dir = run_dir.path().join(&id);
        assert!(
            !state_dir.exists(),
            "state directory {} should have been removed by delete()'s final step",
            state_dir.display()
        );

        // ---- cleanup ----
        drop(process_guard);
        drop(mount_guard);
    });
}

/// The gap this task fixes: a `Status::Created` container has a real, live
/// process (`kestrel-init` blocks on the exec FIFO before forking the
/// entrypoint — see `delete.rs`'s own doc comment), which is the normal,
/// spec-mandated "created but never started" state, not a rare edge case.
/// `delete()`'s step 1 must (a) bail without `--force` here exactly as it
/// would for a Running/Paused container, since it now checks real pid
/// liveness rather than trusting the `status` label, and (b) with
/// `--force`, force-kill the live process and tear down every step (cgroup,
/// namespace pins, state directory) successfully — rather than skipping
/// the kill (as the pre-fix status-only check did) and cascading into an
/// `EBUSY` cgroup-destroy failure that leaves everything behind.
#[test]
#[ignore = "requires root"]
fn test_create_then_delete_force_kills_live_created_container() {
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let bundle = bundle_with_namespaces(bundle_dir.path(), namespaces_without_mount_plus_user());

        let id = format!("delete-force-live-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard) = setup_dirs(&id);

        // ---- create() a real container ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(result.is_ok(), "create() should succeed: {:?}", result.err());

        let state_json_path = run_dir.path().join(&id).join("state.json");
        let created_state = State::read(&state_json_path).expect("read state.json after create");
        assert_eq!(created_state.status, Status::Created);
        let container_pid = nix::unistd::Pid::from_raw(
            created_state.pid.expect("state.json must carry a pid after create()"),
        );
        // Belt-and-suspenders: if an assertion below panics before
        // delete(force=true) actually kills it, this still reaps it.
        let process_guard = ProcessGuard(container_pid);

        // The fixture's stub kestrel-init blocks forever — the process is
        // genuinely alive right now, confirmed directly via the same
        // liveness probe delete() itself uses (signal 0).
        assert!(
            nix::sys::signal::kill(container_pid, None).is_ok(),
            "container process (pid {container_pid}) should be genuinely alive before delete()"
        );

        let cgroup_path = data_dir.path().join("cgroups").join("kestrel").join(&id);
        let ns_dir = run_dir.path().join(&id).join("ns");
        let pinned_types = [
            NsType::Pid,
            NsType::Net,
            NsType::Ipc,
            NsType::Uts,
            NsType::Cgroup,
            NsType::User,
        ];

        // ---- (a) without --force: must bail, and must NOT tear anything
        // down (status is Created, but the process is genuinely alive) ----
        let no_force_result =
            kestrel_runtime::delete::delete(&id, run_dir.path(), data_dir.path(), false);
        let err = no_force_result.expect_err(
            "delete() without --force must reject a Created container whose process is \
             genuinely still alive, exactly as it would for Running/Paused",
        );
        assert!(
            format!("{err:#}").contains("without --force"),
            "unexpected error: {err:#}"
        );
        assert!(
            nix::sys::signal::kill(container_pid, None).is_ok(),
            "process must still be alive after a rejected no-force delete() attempt"
        );
        assert!(
            cgroup_path.exists(),
            "cgroup must be untouched after a rejected no-force delete() attempt"
        );
        for ns in pinned_types {
            assert!(
                ns_dir.join(ns.proc_name()).exists(),
                "pin file for {ns:?} must be untouched after a rejected no-force delete() attempt"
            );
        }

        // ---- (b) with --force: must force-kill the live process and
        // successfully tear down every step ----
        let force_result =
            kestrel_runtime::delete::delete(&id, run_dir.path(), data_dir.path(), true);
        assert!(
            force_result.is_ok(),
            "delete(--force) on a Created container with a genuinely live process should \
             succeed: {:?}",
            force_result.err()
        );

        // ---- proof: the process is actually dead now ----
        // waitpid it explicitly first (it's this test process's direct
        // child) so the liveness probe below isn't looking at a zombie —
        // ProcessGuard's own kill+waitpid on drop would otherwise race
        // this assertion.
        let _ = nix::sys::wait::waitpid(container_pid, None);
        assert!(
            nix::sys::signal::kill(container_pid, None).is_err(),
            "container process (pid {container_pid}) should have been force-killed by delete()"
        );

        // ---- proof: cgroup destroyed ----
        assert!(
            !cgroup_path.exists(),
            "cgroup directory {} should have been destroyed by delete(--force)",
            cgroup_path.display()
        );

        // ---- proof: every namespace pin unmounted and removed ----
        for ns in pinned_types {
            let pin_path = ns_dir.join(ns.proc_name());
            assert!(
                !pin_path.exists(),
                "pin file for {ns:?} at {} should have been unpinned by delete(--force)",
                pin_path.display()
            );
        }

        // ---- proof: the state directory itself is gone (step 7 ran) ----
        let state_dir = run_dir.path().join(&id);
        assert!(
            !state_dir.exists(),
            "state directory {} should have been removed by delete(--force)'s final step",
            state_dir.display()
        );

        // ---- cleanup ----
        drop(process_guard);
        drop(mount_guard);
    });
}
