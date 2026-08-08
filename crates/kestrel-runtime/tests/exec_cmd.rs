// crates/kestrel-runtime/tests/exec_cmd.rs
//
//! Root-gated end-to-end coverage for `exec_cmd.rs`: a real `create()`
//! followed by a real `exec_cmd::exec()` call, proving (a) the exec'd
//! process genuinely runs INSIDE the container's already-pinned
//! namespaces — not just that `exec()` returns success — and (b) its
//! real exit status (both a plain exit code and a signal death) actually
//! propagates back out of `exec_cmd::exec()`'s own return value.
//!
//! Reuses the same test infrastructure `create_pins_namespaces.rs` /
//! `delete_teardown.rs` already established: the `fixture-stub-init`
//! sibling-binary trick (`install_stub_kestrel_init`), the "mount a
//! second cgroup2 view at `data_dir/cgroups`" technique, and
//! `Drop`-based guards for unconditional cleanup even on a panicking
//! assertion. Each test file in this crate duplicates this small helper
//! set rather than sharing a module — see `delete_teardown.rs`'s own doc
//! comment for why.
//!
//! ## How genuine namespace-joining is proven, given the fork/exec split
//!
//! `exec_cmd.rs`'s own module doc comment documents a real kernel
//! behavior: `setns(fd, CLONE_NEWPID)` does NOT move the CALLING process
//! into the target PID namespace, only its future children — which is
//! exactly why `exec()` itself `fork`s AFTER joining, and has the CHILD
//! (not the joiner) do the final `exec_into`. `create_pins_namespaces.rs`'s
//! own setns test already deliberately excludes `NsType::Pid` from its
//! direct-identity check for precisely this reason: it setns's and checks
//! the JOINING process's own `/proc/self/ns/pid`, which never changes.
//!
//! This test does NOT make that mistake. It doesn't check the identity of
//! whatever process happens to call `join_namespaces` — it checks the
//! identity of the process that `exec_cmd::exec()` actually execs, which
//! is a process FORKED AFTER the join. A process's PID-namespace
//! membership is fixed at the moment it's created (`pid_namespaces(7)`),
//! and a child forked after its parent's `setns(CLONE_NEWPID)` is created
//! IN that newly joined namespace — so unlike the joiner itself, this
//! forked-then-exec'd process's own `/proc/self/ns/pid` DOES genuinely
//! reflect the container's PID namespace. Checking it here is the
//! non-naive, load-bearing version of the same proof
//! `create_pins_namespaces.rs` correctly declined to attempt on the
//! joiner directly.
//!
//! Concretely: the exec'd process (`fixture-exec-probe`, see
//! `tests/fixtures/exec_probe.rs`) stats its own `/proc/self/ns/*` for
//! every type the test container has pinned (including `pid`) and writes
//! the `(dev, ino)` pairs to a file — the only channel available once
//! `execve` has replaced its image and it's no longer a distinct,
//! queryable process from the test's point of view. The test compares
//! that report against the container's own pin-file identities
//! (`stat`ed directly, same technique `create_pins_namespaces.rs` uses).
//!
//! `exec_cmd::exec()` itself is always invoked from inside a nested
//! `kestrel_ns::test_util::run_isolated` — required both because
//! `join_namespaces`'s `setns` calls need a single-threaded caller
//! (cargo test's harness never is; same requirement `create()`'s
//! `run_stages` has) and because joining a namespace (especially a User
//! namespace) is a ONE-WAY mutation of the calling process — doing it in
//! a disposable forked child keeps the outer test process's own
//! namespaces untouched for its subsequent cleanup (unpinning, cgroup
//! destroy, etc).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use kestrel_oci::default_spec::{default_namespaces, default_spec};
use kestrel_oci::raw::RawSpec;
use kestrel_oci::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType,
    Process, ProcessBuilder,
};
use kestrel_oci::state::{State, Status};
use kestrel_ns::types::NsType;
use kestrel_runtime::bundle::Bundle;

/// The namespace types every test container below pins: `default_namespaces()`
/// (Pid, Network, Ipc, Uts, Mount, Cgroup) minus Mount (this Lima VM can't
/// bind-mount Mount namespaces at all — see `create_pins_namespaces.rs`'s
/// module doc comment), plus User (routes around the pre-existing
/// `stage0_inner`/`plan.has_user_ns()` mismatch documented in
/// `create_hook_failure_no_hang.rs`). Kept in one place so the container's
/// plan, the pin-identity collection, and `fixture-exec-probe`'s own
/// hardcoded `NS_PROC_NAMES` list all agree on the same six types.
const PINNED_TYPES: [NsType; 6] = [
    NsType::Ipc,
    NsType::Uts,
    NsType::Net,
    NsType::Cgroup,
    NsType::User,
    NsType::Pid,
];

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
/// best-effort — the stub init the tests exec into blocks forever, so
/// without this the process leaks (root-owned, blocking forever) any time
/// a test panics before reaching manual cleanup. Same pattern as
/// `create_pins_namespaces.rs`/`delete_teardown.rs`.
struct ProcessGuard(nix::unistd::Pid);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(self.0, None);
    }
}

/// Same as `create_pins_namespaces.rs`'s helper of the same name: installs
/// `fixture-stub-init` as a sibling of this test binary, named literally
/// `kestrel-init`, matching `create.rs`'s `resolve_kestrel_init_path`
/// sibling-binary convention.
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

fn stat_ns_identity(path: &Path) -> (u64, u64) {
    let st = nix::sys::stat::stat(path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
    (st.st_dev, st.st_ino)
}

fn namespaces_without_mount_plus_user() -> Vec<LinuxNamespace> {
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

/// Same as `create_pins_namespaces.rs`'s helper of the same name: a
/// minimal-but-real `Bundle` with the given namespace list plus a trivial
/// identity uid/gid map, no hooks.
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

    Bundle {
        path: bundle_dir.to_path_buf(),
        spec: RawSpec {
            spec,
            extra: serde_json::Map::new(),
        },
    }
}

/// Real cgroup2 mount at `data_dir/cgroups`, same technique used
/// throughout this crate's root-gated tests.
fn setup_dirs() -> (tempfile::TempDir, tempfile::TempDir, MountGuard) {
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
    (run_dir, data_dir, mount_guard)
}

/// A real, `Created` container plus every guard needed to tear it down
/// (cgroup, second cgroup2 mount, blocked-forever stub process) and the
/// pin identities `exec_cmd::exec()`'s target process is expected to
/// match. `Drop` unpins every namespace pin file BEFORE the other guards
/// run (in particular before `_run_dir`'s `TempDir::drop` removes the
/// directory the pins live under) — `create_pins_namespaces.rs` does this
/// same unpin explicitly inline; bundling it into `Drop` here just lets
/// every test function below share one setup path without duplicating
/// that cleanup step three times.
struct ContainerFixture {
    id: String,
    run_dir_path: PathBuf,
    /// (dev, ino) identity of each pinned namespace's REAL target, i.e.
    /// what `stat`ing the pin file itself under `run_dir_path` reports.
    pins: BTreeMap<NsType, (u64, u64)>,
    _process_guard: ProcessGuard,
    _cgroup_guard: CgroupGuard,
    _mount_guard: MountGuard,
    _run_dir: tempfile::TempDir,
    _data_dir: tempfile::TempDir,
}

impl Drop for ContainerFixture {
    fn drop(&mut self) {
        let ns_dir = self.run_dir_path.join(&self.id).join("ns");
        for ns in PINNED_TYPES {
            let pin_path = ns_dir.join(ns.proc_name());
            let _ = kestrel_ns::pin::unpin_namespace(&pin_path);
        }
    }
}

/// Installs the stub `kestrel-init`, builds a bundle, mounts a scratch
/// cgroup2 view, and calls the real `create()` — proving along the way
/// that every namespace type this test cares about was genuinely pinned
/// (mirroring `create_pins_namespaces.rs`'s own step 1) before handing
/// back a `ContainerFixture` ready for `exec_cmd::exec()` calls against
/// it. Must be called from inside `kestrel_ns::test_util::run_isolated`
/// (single-threaded requirement of `create()`'s own `run_stages`).
fn setup_running_container(id_prefix: &str) -> ContainerFixture {
    install_stub_kestrel_init();

    let bundle_dir = tempfile::tempdir().expect("bundle tempdir");
    let bundle = bundle_with_namespaces(bundle_dir.path(), namespaces_without_mount_plus_user());

    let id = format!("{id_prefix}-{}", nix::unistd::getpid().as_raw());
    let (run_dir, data_dir, mount_guard) = setup_dirs();

    let result = kestrel_runtime::create::create(&id, &bundle, run_dir.path(), data_dir.path());
    assert!(
        result.is_ok(),
        "create() should succeed (no createRuntime hooks, no Mount namespace in this \
         environment): {:?}",
        result.err()
    );

    let state_path = run_dir.path().join(&id).join("state.json");
    let state = State::read(&state_path).expect("read state.json");
    assert_eq!(state.status, Status::Created);
    let target_pid = nix::unistd::Pid::from_raw(state.pid.expect("state.json must carry a pid"));
    let process_guard = ProcessGuard(target_pid);

    let cgroup_guard = CgroupGuard(
        kestrel_cgroup::manager::CgroupManager::new(data_dir.path().join("cgroups"), &id)
            .expect("valid cgroup id (must match the one create() itself derived)"),
    );

    let ns_dir = run_dir.path().join(&id).join("ns");
    let mut pins = BTreeMap::new();
    for ns in PINNED_TYPES {
        let pin_path = ns_dir.join(ns.proc_name());
        assert!(
            pin_path.exists(),
            "expected a pin file for {ns:?} at {} after create()",
            pin_path.display()
        );
        pins.insert(ns, stat_ns_identity(&pin_path));
    }

    ContainerFixture {
        id,
        run_dir_path: run_dir.path().to_path_buf(),
        pins,
        _process_guard: process_guard,
        _cgroup_guard: cgroup_guard,
        _mount_guard: mount_guard,
        _run_dir: run_dir,
        _data_dir: data_dir,
    }
}

/// Builds the `Process` spec `exec_cmd::exec()` execs: `fixture-exec-probe`
/// (see `tests/fixtures/exec_probe.rs`), with its behavior steered purely
/// via env vars so one fixture binary covers every test below.
fn exec_probe_process(ns_output: &Path, exit_code: Option<i32>, signal: Option<&str>) -> Process {
    let fixture = PathBuf::from(env!("CARGO_BIN_EXE_fixture-exec-probe"));
    let mut env = vec![format!("KESTREL_TEST_NS_OUTPUT={}", ns_output.display())];
    if let Some(code) = exit_code {
        env.push(format!("KESTREL_TEST_EXIT_CODE={code}"));
    }
    if let Some(sig) = signal {
        env.push(format!("KESTREL_TEST_SIGNAL={sig}"));
    }
    ProcessBuilder::default()
        .args(vec![fixture.to_string_lossy().into_owned()])
        .cwd(PathBuf::from("/"))
        .env(env)
        .build()
        .expect("build fixture-exec-probe process spec")
}

/// Parses one `<proc_name> <dev> <ino>` line from `fixture-exec-probe`'s
/// report back into an `(NsType, (dev, ino))` pair.
fn parse_ns_report_line(line: &str) -> (NsType, (u64, u64)) {
    let mut parts = line.split_whitespace();
    let name = parts.next().unwrap_or_else(|| panic!("empty ns report line"));
    let dev: u64 = parts
        .next()
        .unwrap_or_else(|| panic!("missing dev field in line {line:?}"))
        .parse()
        .expect("dev field is a u64");
    let ino: u64 = parts
        .next()
        .unwrap_or_else(|| panic!("missing ino field in line {line:?}"))
        .parse()
        .expect("ino field is a u64");
    let ns = PINNED_TYPES
        .into_iter()
        .find(|ns| ns.proc_name() == name)
        .unwrap_or_else(|| panic!("unrecognized ns proc_name {name:?} in report line {line:?}"));
    (ns, (dev, ino))
}

#[test]
#[ignore = "requires root"]
fn test_exec_joins_every_real_namespace_and_propagates_zero_exit() {
    // `create()`'s own `run_stages` requires a single-threaded calling
    // process — cargo test's harness never is. Same isolation pattern as
    // every other root-gated test in this crate.
    kestrel_ns::test_util::run_isolated(|| {
        let fixture = setup_running_container("exec-ns");

        let ns_output_dir = tempfile::tempdir().expect("ns-report output tempdir");
        let ns_output_path = ns_output_dir.path().join("ns_report.txt");
        let process = exec_probe_process(&ns_output_path, None, None);

        // ---- the real call under test, isolated in a disposable forked
        // child: `join_namespaces` inside `exec_cmd::exec` is a one-way
        // mutation of whatever process calls it, and `exec_cmd::exec`
        // itself needs a single-threaded caller to `fork` safely ----
        let id = fixture.id.clone();
        let run_dir_path = fixture.run_dir_path.clone();
        kestrel_ns::test_util::run_isolated(move || {
            let exit_code = kestrel_runtime::exec_cmd::exec(&id, &run_dir_path, &process)
                .expect("exec_cmd::exec should succeed against a real, just-created container");
            assert_eq!(
                exit_code, 0,
                "fixture-exec-probe with no exit-code override should exit 0, matching \
                 exec_cmd::exec's exit_code_from_status for a clean exit"
            );
        });

        // ---- the real proof: the exec'd process's OWN namespace
        // identities (reported to a file, since by the time we get here
        // it's long gone as a distinct process) match the container's
        // pins for every one of the six types, INCLUDING Pid — valid
        // here specifically because this is the forked-then-exec'd
        // process, not the joiner itself (see this file's module doc
        // comment) ----
        let report =
            std::fs::read_to_string(&ns_output_path).expect("read ns report written by exec'd process");
        let mut seen = HashSet::new();
        for line in report.lines() {
            let (ns, identity) = parse_ns_report_line(line);
            assert_eq!(
                identity, fixture.pins[&ns],
                "exec'd process's own {ns:?} namespace (dev={}, ino={}) does not match the \
                 container's pin (dev={}, ino={}) — exec_cmd::exec did not genuinely join it",
                identity.0, identity.1, fixture.pins[&ns].0, fixture.pins[&ns].1
            );
            assert!(seen.insert(ns), "duplicate {ns:?} line in ns report: {report}");
        }
        assert_eq!(
            seen.len(),
            PINNED_TYPES.len(),
            "expected a report line for every one of the container's {} pinned namespace \
             types, got: {report:?}",
            PINNED_TYPES.len()
        );

        drop(fixture);
    });
}

#[test]
#[ignore = "requires root"]
fn test_exec_propagates_nonzero_exit_code() {
    kestrel_ns::test_util::run_isolated(|| {
        let fixture = setup_running_container("exec-exit");

        let ns_output_dir = tempfile::tempdir().expect("ns-report output tempdir");
        let ns_output_path = ns_output_dir.path().join("ns_report.txt");
        let process = exec_probe_process(&ns_output_path, Some(42), None);

        let id = fixture.id.clone();
        let run_dir_path = fixture.run_dir_path.clone();
        kestrel_ns::test_util::run_isolated(move || {
            let exit_code = kestrel_runtime::exec_cmd::exec(&id, &run_dir_path, &process)
                .expect("exec_cmd::exec should succeed");
            assert_eq!(
                exit_code, 42,
                "exec_cmd::exec must propagate the exec'd process's real plain exit code, not \
                 just report success/failure"
            );
        });

        drop(fixture);
    });
}

#[test]
#[ignore = "requires root"]
fn test_exec_propagates_signal_exit_code() {
    kestrel_ns::test_util::run_isolated(|| {
        let fixture = setup_running_container("exec-sig");

        let ns_output_dir = tempfile::tempdir().expect("ns-report output tempdir");
        let ns_output_path = ns_output_dir.path().join("ns_report.txt");
        let process = exec_probe_process(&ns_output_path, None, Some("KILL"));

        let id = fixture.id.clone();
        let run_dir_path = fixture.run_dir_path.clone();
        kestrel_ns::test_util::run_isolated(move || {
            let exit_code = kestrel_runtime::exec_cmd::exec(&id, &run_dir_path, &process)
                .expect("exec_cmd::exec should succeed even when the exec'd process dies by signal");
            assert_eq!(
                exit_code,
                128 + 9,
                "a SIGKILL death must map to 128+signum (137), matching exec_cmd.rs's own \
                 exit_code_from_status convention"
            );
        });

        drop(fixture);
    });
}
