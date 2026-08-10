// crates/kestrel-runtime/tests/create_applies_resource_limits.rs
//
//! Root-gated regression test for the resource-application gap found
//! during Phase 9 Task 13's review: `create()` created a cgroup for every
//! container but never read the bundle's `linux.resources` back out and
//! applied it — `apply_cpu`/`apply_memory`/`apply_pids`/`apply_io` (all
//! real, already-implemented in `kestrel_cgroup::resources`) were never
//! called anywhere in `kestrel-runtime`'s lifecycle code. Every resource
//! limit configured in a bundle's `config.json` — including `kestreld`'s
//! own `POST /containers` `memory_bytes`/`pids_limit` fields — was
//! silently non-functional.
//!
//! This test proves the fix the most direct way available: build a bundle
//! whose `linux.resources` configures a real, non-default `memory.max` and
//! `pids.max`, call the real `create()`, and read `memory.max`/`pids.max`
//! back out of the REAL cgroupfs path immediately afterward — no OOM
//! trigger, no busy loop, no timing-sensitive kernel event needed. If the
//! gap were still present, both files would read back the cgroup-v2
//! default `"max"` sentinel instead of the configured values.
//!
//! Same plumbing/pattern as `create_pins_namespaces.rs`: a second, private
//! cgroup2 mount under a temp `data_dir` (so this doesn't disturb the
//! Lima VM's real cgroup hierarchy), a stub `kestrel-init` installed as a
//! sibling binary (so `child_action`'s `execv` succeeds and `run_stages`
//! returns a real, live pid), and guards that kill/reap the spawned
//! process and unmount/destroy the cgroup on the way out.

use std::path::{Path, PathBuf};
use std::process::Command;

use kestrel_oci::default_spec::{default_namespaces, default_spec};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxMemoryBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder,
};
use kestrel_oci::state::{State, Status};
use kestrel_runtime::bundle::Bundle;

struct MountGuard(PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

struct CgroupGuard(kestrel_cgroup::manager::CgroupManager);
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let _ = self.0.destroy();
    }
}

/// Kills (SIGKILL) and reaps the spawned container process on drop,
/// best-effort — same convention as `create_pins_namespaces.rs`'s own
/// `ProcessGuard`: the stub init blocks forever, so without this a panic
/// mid-test leaks a root-owned, forever-blocking process.
struct ProcessGuard(nix::unistd::Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

/// Installs `fixture-stub-init` as a sibling of THIS test binary, named
/// literally `kestrel-init` — identical to `create_pins_namespaces.rs`'s
/// own `install_stub_kestrel_init` (see that file for the full rationale
/// on the copy-to-tmp-then-rename technique and why it's never removed
/// afterward).
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
/// Mount, plus a User namespace — the exact same proven-working namespace
/// set `create_pins_namespaces.rs`'s `namespaces_without_mount_plus_user()`
/// uses, for the same reasons: this Lima VM cannot bind-mount ANY mount
/// namespace (a real, independently-verified `EINVAL` environment
/// limitation — see that file's module doc comment), and a plan containing
/// a User namespace requires `stage0_inner` to receive the
/// `Sync::RequestMaps` message stage1 only sends when one is present. This
/// test is about resource-limit application, not namespace plumbing, so it
/// deliberately reuses this exact known-good combination rather than
/// inventing an untested one (e.g. an empty namespace list).
fn namespaces_without_mount_plus_user() -> Vec<LinuxNamespace> {
    let mut namespaces = default_namespaces();
    namespaces.retain(|ns| ns.typ() != LinuxNamespaceType::Mount);
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::User)
            .build()
            .expect("build user namespace"),
    );
    namespaces
}

/// Builds a minimal-but-real `Bundle` with the proven-working namespace set
/// above (plus a trivial identity uid/gid map, required since it includes
/// `NsType::User`) and the given `LinuxResources` block.
fn bundle_with_resources(bundle_dir: &Path, resources: kestrel_oci::runtime::LinuxResources) -> Bundle {
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
        .namespaces(namespaces_without_mount_plus_user())
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .resources(resources)
        .build()
        .expect("build linux section");
    spec.set_linux(Some(linux));

    Bundle {
        path: bundle_dir.to_path_buf(),
        spec: RawSpec {
            spec,
            extra: serde_json::Map::new(),
        },
    }
}

/// Unpins every namespace `create()` actually bind-mounts under
/// `run_dir/<id>/ns/*` for this file's tests — the exact set
/// `namespaces_without_mount_plus_user()` requests (everything but Mount,
/// which cannot be bind-mounted in this environment; see that function's
/// doc comment).
///
/// Same order/technique as `create_pins_namespaces.rs`'s own cleanup
/// (call `unpin_namespace` on every real pin path before dropping the
/// cgroup/mount guards) and `kestreld/src/main.rs`'s root-gated tests —
/// both already establish this as the correct pattern. Without this step,
/// the pin files stay busy (bind-mounted) and `TempDir::drop`'s internal
/// `remove_dir_all` silently fails to remove them, leaking both the nsfs
/// bind mounts and the tempdir itself on every root-gated run of these
/// two tests.
fn unpin_test_namespaces(run_dir: &Path, id: &str) {
    let ns_dir = run_dir.join(id).join("ns");
    let ns_types = [
        kestrel_ns::types::NsType::Pid,
        kestrel_ns::types::NsType::Net,
        kestrel_ns::types::NsType::Ipc,
        kestrel_ns::types::NsType::Uts,
        kestrel_ns::types::NsType::Cgroup,
        kestrel_ns::types::NsType::User,
    ];
    for ns in ns_types {
        let _ = kestrel_ns::pin::unpin_namespace(&ns_dir.join(ns.proc_name()));
    }
}

/// Same shared-plumbing setup as `create_pins_namespaces.rs`'s own
/// `setup_dirs`: a real, private cgroup2 mount at `data_dir/cgroups`, a
/// fresh `run_dir`, and a destroy-on-drop cgroup guard for `id`.
fn setup_dirs(id: &str) -> (tempfile::TempDir, tempfile::TempDir, MountGuard, CgroupGuard) {
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
    let cgroup_guard = CgroupGuard(
        kestrel_cgroup::manager::CgroupManager::new(data_dir.path().join("cgroups"), id)
            .expect("valid cgroup id"),
    );

    (run_dir, data_dir, mount_guard, cgroup_guard)
}

#[test]
#[ignore = "requires root"]
fn test_create_applies_configured_memory_and_pids_limits_to_the_real_cgroup() {
    // `run_stages` (deep inside `create()`) requires a single-threaded
    // calling process — cargo test's harness never is. Same isolation
    // pattern as `create_pins_namespaces.rs`/`create_hook_failure_no_hang.rs`.
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        const MEMORY_LIMIT_BYTES: i64 = 33 * 1024 * 1024; // 33 MiB — arbitrary, non-default
        const PIDS_LIMIT: i64 = 17; // arbitrary, non-default

        let resources = LinuxResourcesBuilder::default()
            .memory(
                LinuxMemoryBuilder::default()
                    .limit(MEMORY_LIMIT_BYTES)
                    .build()
                    .expect("build LinuxMemory"),
            )
            .pids(
                LinuxPidsBuilder::default()
                    .limit(PIDS_LIMIT)
                    .build()
                    .expect("build LinuxPids"),
            )
            .build()
            .expect("build LinuxResources");

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        let bundle = bundle_with_resources(bundle_dir.path(), resources);

        let id = format!("resources-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard, cgroup_guard) = setup_dirs(&id);

        // ---- the real call under test ----
        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(
            result.is_ok(),
            "create() should succeed (no namespaces, no createRuntime hooks configured): {:?}",
            result.err()
        );

        // ---- state.json must report Created + a real pid: create()
        // genuinely completed and the stub process genuinely exists ----
        let state_path = run_dir.path().join(&id).join("state.json");
        let state = State::read(&state_path).expect("read state.json");
        assert_eq!(state.status, Status::Created);
        let target_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        let process_guard = ProcessGuard(target_pid);

        // ---- the real proof: read memory.max/pids.max straight out of the
        // real cgroupfs path and confirm they match the CONFIGURED values,
        // not the cgroup-v2 "max" (unconstrained) default. This is checked
        // against the exact same `CgroupManager::path` the running
        // container's process was cloned into (`cgroup_guard.0.path`), so
        // there is no ambiguity about which cgroup is being inspected. ----
        let memory_max = std::fs::read_to_string(cgroup_guard.0.path.join("memory.max"))
            .expect("reading memory.max")
            .trim()
            .to_string();
        let pids_max = std::fs::read_to_string(cgroup_guard.0.path.join("pids.max"))
            .expect("reading pids.max")
            .trim()
            .to_string();

        assert_eq!(
            memory_max,
            MEMORY_LIMIT_BYTES.to_string(),
            "memory.max should reflect the bundle's configured linux.resources.memory.limit \
             ({MEMORY_LIMIT_BYTES}), not the cgroup-v2 default of \"max\" — got {memory_max:?}. \
             This is the exact production gap: create() must apply configured resource limits \
             to the cgroup, not just create it."
        );
        assert_eq!(
            pids_max,
            PIDS_LIMIT.to_string(),
            "pids.max should reflect the bundle's configured linux.resources.pids.limit \
             ({PIDS_LIMIT}), not the cgroup-v2 default of \"max\" — got {pids_max:?}."
        );

        // ---- also confirm the limits were ALREADY in effect before the
        // process existed, not applied racily after: the process is placed
        // into the cgroup via CLONE_INTO_CGROUP during create() itself, so
        // by the time create() returns (i.e. by the time we read these
        // files above) the limits and the process's membership are already
        // both established — there is no separate "apply now" step to race
        // against. The stub process being alive AND the limits already
        // matching, observed together right after create() returns, is
        // exactly the guarantee this fix provides. ----
        assert!(
            nix::sys::signal::kill(target_pid, None).is_ok(),
            "the container's real process should still be alive at this point"
        );

        // ---- cleanup: kill+reap the container process, unpin every
        // namespace create() bind-mounted under run_dir/<id>/ns/*, then
        // tear down the cgroup/mount/tempdir guards ----
        drop(process_guard);
        unpin_test_namespaces(run_dir.path(), &id);
        drop(cgroup_guard);
        drop(mount_guard);
    });
}

#[test]
#[ignore = "requires root"]
fn test_create_with_no_resources_leaves_defaults_unconstrained() {
    // Regression guard for the "no regression for the common case"
    // requirement: a bundle with NO `linux.resources` block at all must
    // behave identically to before this fix — memory.max/pids.max stay at
    // the cgroup-v2 default "max" (unconstrained), proving
    // `apply_resource_limits`'s early return for an absent resources block
    // really is a no-op and doesn't, say, accidentally write a zero limit.
    kestrel_ns::test_util::run_isolated(|| {
        install_stub_kestrel_init();

        let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
        std::fs::create_dir_all(bundle_dir.path().join("rootfs")).expect("mkdir rootfs");
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
            .namespaces(namespaces_without_mount_plus_user())
            .uid_mappings(vec![uid_mapping])
            .gid_mappings(vec![gid_mapping])
            .build()
            .expect("build linux section with no resources");
        spec.set_linux(Some(linux));
        let bundle = Bundle {
            path: bundle_dir.path().to_path_buf(),
            spec: RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        };

        let id = format!("no-resources-{}", nix::unistd::getpid().as_raw());
        let (run_dir, data_dir, mount_guard, cgroup_guard) = setup_dirs(&id);

        let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
        assert!(result.is_ok(), "create() should succeed: {:?}", result.err());

        let state_path = run_dir.path().join(&id).join("state.json");
        let state = State::read(&state_path).expect("read state.json");
        let target_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
        let process_guard = ProcessGuard(target_pid);

        let memory_max = std::fs::read_to_string(cgroup_guard.0.path.join("memory.max"))
            .expect("reading memory.max")
            .trim()
            .to_string();
        let pids_max = std::fs::read_to_string(cgroup_guard.0.path.join("pids.max"))
            .expect("reading pids.max")
            .trim()
            .to_string();

        assert_eq!(
            memory_max, "max",
            "no linux.resources configured — memory.max must stay at the cgroup-v2 default"
        );
        assert_eq!(
            pids_max, "max",
            "no linux.resources configured — pids.max must stay at the cgroup-v2 default"
        );

        drop(process_guard);
        unpin_test_namespaces(run_dir.path(), &id);
        drop(cgroup_guard);
        drop(mount_guard);
    });
}
