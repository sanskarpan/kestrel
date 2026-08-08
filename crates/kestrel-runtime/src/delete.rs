// crates/kestrel-runtime/src/delete.rs
//
//! `delete` — the 7-step teardown command. Per the Phase 8 design doc's
//! explicit ordering (docs/superpowers/specs/2026-08-05-phase8-runtime-
//! binary-design.md §2, "`delete.rs` deserves explicit ordering"):
//!
//! 1. force-kill (if the recorded pid is genuinely still alive and
//!    `--force`), then wait for the container to actually stop
//! 2. unmount the overlay
//! 3. destroy the cgroup
//! 4. unpin namespaces
//! 5. network teardown — explicitly SKIPPED here, see the module-level
//!    note below
//! 6. run `poststop` hooks
//! 7. remove the state/bundle-scratch directories, last, only on full
//!    success
//!
//! **Partial-failure policy**: every step is attempted regardless of
//! whether an earlier step failed; each step's error is collected into
//! `errors` rather than aborting the function early (e.g. a namespace-
//! unpin failure must never prevent the cgroup from also being cleaned
//! up). The aggregate is reported as a single `Err` at the end. Step 7
//! (removing on-disk evidence) only runs if every earlier step succeeded
//! — a partial failure leaves the state directory and snapshot scratch
//! directory in place so the failure can be diagnosed and `delete`
//! retried, rather than erasing the evidence a retry or a human would
//! need.
//!
//! ## Step 5 — why network teardown is not called here
//!
//! `kestrel-runtime` cannot depend on `kestrel-net` at all: Rule #2 ("no
//! tokio transitively", resolved in Task 3) means `kestrel-runtime` must
//! stay free of `kestrel-net`'s dependency tree. Real network teardown
//! for a bridge-mode container therefore cannot be a direct function call
//! from this module. Per SPEC.md §9.3's hook table (`poststop` fires
//! "after delete — network teardown"), this is intentionally left to
//! `poststop` hooks (step 6, which — like `createRuntime` in `create.rs`
//! — is exactly where CNI-style plugins are meant to run, host-side, with
//! full access to whatever network state needs tearing down) or to a
//! `kestreld` (Phase 9)-level concern that orchestrates `kestrel-net`
//! directly. This is a deliberate scope boundary, not an oversight — see
//! Task 12's own brief for the explicit instruction to document rather
//! than silently omit this step.
//!
//! ## Step 1 — why this checks pid liveness, not `status`
//!
//! A container in `Status::Created` has a real, live process:
//! `kestrel-init`'s `main.rs` blocks on the exec FIFO
//! (`block_until_started`) *before* forking the entrypoint, and nothing
//! transitions `status` to `Running` until `kestrel start` is called
//! separately. "Created but never started" is a normal, spec-mandated
//! intermediate state (e.g. an orchestrator creates a container, decides
//! not to start it, and wants to delete it) — not a rare edge case. Gating
//! the force-kill step on `matches!(state.status, Running | Paused)` alone
//! would silently skip it for a `Created` container with a live process,
//! which then makes step 3 (`CgroupManager::destroy`) fail with `EBUSY`
//! (the process is still a cgroup member), which in turn skips step 7
//! (directory removal) — `delete()` on a created-but-not-started container
//! would reliably fail and leave everything behind.
//!
//! So step 1 checks the ACTUAL thing that matters — is there a live
//! process to deal with — via `kill(pid, None)` (signal 0, the standard
//! liveness probe, sends nothing), not the `status` label. This covers
//! `Created` (and any other status) uniformly, is more robust than
//! enumerating specific `Status` variants, and still bails without
//! `--force` whenever the process is genuinely alive, regardless of what
//! `status` says. A dead pid (the common `Stopped`-before-delete case, or
//! a `Creating` container whose `create()` errored before recording a pid
//! at all) naturally takes the "nothing to kill" path with no special
//! casing needed.
//!
//! This liveness check has the same known, accepted imprecision
//! `crate::state::read_and_refresh` already documents: `kill(pid, None)`
//! cannot fully rule out the pid having been reused by an unrelated
//! process since the container's process actually exited. This module
//! doesn't attempt to solve pid-reuse detection either — it's consistent
//! with how the rest of this codebase already treats that limitation.
//!
//! ## Re-deriving which namespaces to unpin
//!
//! `create.rs`'s `pin_namespaces` pins every `NsType` in the container's
//! `NamespacePlan` (built from the bundle's `config.json` at create time)
//! onto `run_dir/<id>/ns/<type.proc_name()>` — see `create.rs`'s own doc
//! comments, SPEC.md §4.4. `delete` must unpin from those EXACT SAME
//! paths. Rather than guessing which types were pinned purely from which
//! files happen to exist under `ns/` (a stray or unrelated file there
//! would be misread as "this was a pinned namespace"), this module
//! reloads the bundle from `state.bundle` and calls the same
//! `build_namespace_plan` `create.rs` used, so the *set of candidate
//! types* comes from the real, authoritative source (the container's own
//! recorded config), not from filesystem inference alone.
//!
//! Within that candidate set, this module still checks whether each
//! type's pin file actually exists before attempting to unpin it — this
//! is the "already gone is fine" idiom this project uses everywhere else
//! for teardown (`kestrel_ns::pin::unpin_namespace`'s own callers,
//! `kestrel-net`'s `nat::remove_dnat`/`teardown_all`, `kestrel-image`'s
//! `store.rs::remove_ref`). It matters concretely for `NsType::Mount` in
//! this Lima VM: `crates/kestrel-ns/tests/join.rs` and
//! `tests/create_pins_namespaces.rs` both document a real, pre-existing
//! environment limitation where bind-mounting a Mount namespace via nsfs
//! fails with `EINVAL` — not a kestrel bug. Under `create.rs`'s current
//! all-or-nothing pinning policy this means a bundle whose plan includes
//! `Mount` never successfully reaches `Status::Created` at all in this
//! environment (the whole `create()` call fails and rolls back), so in
//! practice every genuinely-`Created` container's `ns/` directory already
//! has every planned type's pin file present. The existence check here is
//! deliberately defensive anyway: it's the same "don't trust a single
//! invariant elsewhere in the codebase to always hold" posture this
//! project takes generally, and it means `delete` degrades gracefully
//! (skips, doesn't error) rather than hard-failing if that invariant ever
//! changes (e.g. a future best-effort pinning policy, or a container
//! whose bundle `config.json` was edited between create and delete).
//!
//! If the bundle can no longer be reloaded at delete time (its
//! `config.json` was removed, the bundle directory was cleaned up, etc.)
//! — a real possibility, since nothing pins a bundle directory's lifetime
//! to its container's — this module falls back to checking all 8
//! `NsType` variants against `ns/`'s actual file contents. This is
//! explicitly the last-resort, "guessing from file existence alone" path
//! the task brief calls out as inferior to the config-driven approach;
//! it exists only so `delete` still makes a best effort at cleaning up
//! pins rather than leaving them all behind just because the bundle is
//! gone.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kestrel_cgroup::manager::CgroupManager;
use kestrel_ns::types::NsType;
use kestrel_oci::runtime::Hook;
use kestrel_oci::state::{State, Status};

use crate::bundle::Bundle;

/// Every `NsType` variant — the last-resort fallback candidate set used
/// when the bundle can no longer be reloaded at delete time. See this
/// module's doc comment.
const ALL_NS_TYPES: [NsType; 8] = [
    NsType::Mount,
    NsType::Cgroup,
    NsType::Uts,
    NsType::Ipc,
    NsType::User,
    NsType::Pid,
    NsType::Net,
    NsType::Time,
];

/// How long to wait, after a `--force` cgroup-wide kill, for
/// `kestrel-init`'s reaper to record `Status::Stopped` before giving up
/// and proceeding with the rest of teardown anyway. See
/// `wait_for_stopped`'s own doc comment for why this is explicitly
/// best-effort, not a hard requirement.
const FORCE_KILL_STOP_TIMEOUT: Duration = Duration::from_secs(5);

pub fn delete(id: &str, run_dir: &Path, data_dir: &Path, force: bool) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let state = State::read(&state_json_path)?;

    let mut errors: Vec<String> = Vec::new();

    // ---- Step 1: force-kill, if the recorded pid is genuinely still
    // alive — see this module's doc comment ("why this checks pid
    // liveness, not status") for why this is a `kill(pid, None)` liveness
    // probe rather than `matches!(state.status, Running | Paused)`. ----
    let process_alive = state
        .pid
        .is_some_and(|pid| nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok());
    if process_alive {
        if force {
            if let Err(e) =
                crate::kill::kill(id, run_dir, data_dir, nix::sys::signal::Signal::SIGKILL, true)
            {
                errors.push(format!("force-kill: {e:#}"));
            }
            // Wait for the container to actually stop before proceeding —
            // poll state.json for Status::Stopped (written by
            // kestrel-init's reaper) up to a reasonable deadline. See
            // wait_for_stopped's doc comment: this is a best-effort
            // settling window, not something `delete` can treat as an
            // error on timeout.
            wait_for_stopped(&state_json_path, FORCE_KILL_STOP_TIMEOUT);
        } else {
            anyhow::bail!(
                "cannot delete container {id} without --force: its process (pid {}) is still alive",
                state.pid.expect("process_alive implies state.pid is Some")
            );
        }
    }

    // ---- Step 2: unmount the overlay ----
    // The merged mountpoint's path is fully deterministic from data_dir +
    // id (kestrel-init's own `stage_rootfs` computes the identical path
    // via `Snapshotter::prepare_snapshot(container_id, ...)` ->
    // `data_dir/snapshots/<id>/merged`, per SPEC.md §6.1) — no need to
    // have persisted the Bootstrap payload anywhere to recover it here.
    let merged = data_dir.join("snapshots").join(id).join("merged");
    if let Err(e) = unmount_overlay_tolerant(&merged) {
        errors.push(format!("unmount overlay at {}: {e:#}", merged.display()));
    }

    // ---- Step 3: destroy the cgroup ----
    match CgroupManager::new(data_dir.join("cgroups"), id) {
        Ok(cgroup) => {
            if let Err(e) = destroy_cgroup_tolerant(&cgroup) {
                errors.push(format!("destroy cgroup: {e:#}"));
            }
        }
        Err(e) => errors.push(format!("constructing cgroup manager: {e}")),
    }

    // ---- Steps 4 & 6 both need the bundle reloaded: namespace plan
    // re-derivation (4) and poststop hooks (6) ----
    let bundle = match crate::bundle::load(&state.bundle) {
        Ok(b) => Some(b),
        Err(e) => {
            errors.push(format!(
                "reloading bundle {} for namespace/hook teardown: {e:#}",
                state.bundle.display()
            ));
            None
        }
    };

    // ---- Step 4: unpin namespaces ----
    let ns_dir = run_dir.join(id).join("ns");
    let candidate_types: Vec<NsType> = match &bundle {
        Some(b) => match crate::create::build_namespace_plan(b) {
            Ok(plan) => plan.create,
            Err(e) => {
                errors.push(format!("re-deriving namespace plan for unpinning: {e:#}"));
                ALL_NS_TYPES.to_vec()
            }
        },
        None => ALL_NS_TYPES.to_vec(),
    };
    for err in unpin_namespaces(&ns_dir, &candidate_types) {
        errors.push(err);
    }

    // ---- Step 5: network teardown — deliberately skipped, see this
    // module's doc comment for why. ----

    // ---- Step 6: poststop hooks ----
    if let Some(b) = &bundle {
        if let Err(e) = kestrel_oci::hooks::run_hooks(&bundle_poststop_hooks(b), &[]) {
            errors.push(format!("poststop hooks: {e:#}"));
        }
    }
    // If the bundle couldn't be reloaded, its poststop hooks are already
    // recorded as an error above (bundle-load failure) — no separate
    // error is added here to avoid double-reporting the same root cause.

    // ---- Step 7: remove the state/bundle-scratch directories, LAST, and
    // only if every earlier step succeeded — leave evidence in place on
    // partial failure. ----
    if errors.is_empty() {
        let state_dir = run_dir.join(id);
        if let Err(e) = remove_dir_all_tolerant(&state_dir) {
            errors.push(format!("removing state directory {}: {e:#}", state_dir.display()));
        }
        let snapshot_dir = data_dir.join("snapshots").join(id);
        if let Err(e) = remove_dir_all_tolerant(&snapshot_dir) {
            errors.push(format!(
                "removing snapshot scratch directory {}: {e:#}",
                snapshot_dir.display()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("delete completed with errors: {}", errors.join("; "))
    }
}

/// Unpins every type in `candidate_types` whose pin file actually exists
/// under `ns_dir`, skipping (not erroring on) any that don't — the
/// "already gone is fine" idiom, see this module's doc comment. Returns
/// one formatted error string per type that DID have a pin file but
/// failed to unpin.
fn unpin_namespaces(ns_dir: &Path, candidate_types: &[NsType]) -> Vec<String> {
    let mut errors = Vec::new();
    for &ns_type in candidate_types {
        let target = ns_dir.join(ns_type.proc_name());
        // symlink_metadata (lstat), not exists()/metadata (stat): the pin
        // target is a bind-mounted regular file, never a symlink, but
        // lstat is still the right call here — it doesn't follow
        // anything and reports the literal path's own presence, matching
        // `LayerStore::ensure_link`'s established convention elsewhere in
        // this codebase for "does this exact path exist" checks.
        if target.symlink_metadata().is_err() {
            // Never pinned — either this type isn't one create.rs's
            // pin_namespaces actually reached (e.g. NsType::Mount on this
            // Lima VM), or this container never got far enough to pin
            // anything at all. Not an error.
            continue;
        }
        if let Err(e) = kestrel_ns::pin::unpin_namespace(&target) {
            errors.push(format!("unpin {ns_type:?} at {}: {e:#}", target.display()));
        }
    }
    errors
}

/// `kestrel_rootfs::overlay::unmount_overlay`, tolerant of "there was
/// nothing mounted there to begin with" — `ENOENT` (the merged directory
/// itself was never created, e.g. this container's `kestrel-init` never
/// reached `stage_rootfs`) and `EINVAL` (the directory exists but isn't a
/// mountpoint) are both treated as success, matching the "already gone is
/// fine" idiom this module uses throughout. Any other error is real and
/// propagates.
fn unmount_overlay_tolerant(merged: &Path) -> Result<()> {
    match kestrel_rootfs::overlay::unmount_overlay(merged) {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_ignorable_unmount_error(&e) {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

fn is_ignorable_unmount_error(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<nix::errno::Errno>(),
        Some(nix::errno::Errno::ENOENT) | Some(nix::errno::Errno::EINVAL)
    )
}

/// `CgroupManager::destroy`, tolerant of "the cgroup directory is already
/// gone" (e.g. a previous `delete` attempt already destroyed it, or it
/// was never created).
fn destroy_cgroup_tolerant(cgroup: &CgroupManager) -> Result<()> {
    match cgroup.destroy() {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_ignorable_not_found_error(&e) {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

fn is_ignorable_not_found_error(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<std::io::Error>().map(|io| io.kind()),
        Some(std::io::ErrorKind::NotFound)
    )
}

/// `fs::remove_dir_all`, tolerant of the directory already being gone.
fn remove_dir_all_tolerant(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", dir.display())),
    }
}

/// Polls `state_json_path` for `Status::Stopped`, up to `timeout`.
///
/// # Why this is best-effort, not a hard requirement
///
/// The force-kill step above calls `kill(..., all=true)`, which goes
/// through `CgroupManager::kill_all` — an atomic `SIGKILL` of *every*
/// process in the container's cgroup (`crates/kestrel-cgroup/src/
/// control.rs`'s `kill_all`/`cgroup.kill`), including `kestrel-init`
/// itself (the container's PID 1 and the sole writer of
/// `Status::Stopped` + `exit_code`, per the exit-code plumbing described
/// in the Phase 8 design doc §2). `SIGKILL` cannot be caught, so when
/// `kestrel-init` is killed alongside the entrypoint it has no
/// opportunity to run its reaper's final `state.json` write — meaning
/// this poll can legitimately spin for the full `timeout` and never
/// observe `Status::Stopped` at all after a `--force` delete. That is
/// expected, not a bug: the point of this wait is to give a genuinely
/// still-alive `kestrel-init` (e.g. one whose entrypoint died from the
/// kill but which is still running its own reaper loop for a brief
/// moment before exiting on its own) a chance to settle and write final
/// state before the rest of teardown proceeds, not to guarantee that
/// write happens. Every later step (overlay unmount, cgroup destroy) is
/// itself tolerant of "already torn down" / "nothing there", so
/// proceeding after a timeout is safe.
fn wait_for_stopped(state_json_path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = State::read(state_json_path) {
            if s.status == Status::Stopped {
                return;
            }
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `poststop` hooks, extracted from the bundle spec — same pattern as
/// `create.rs`'s `bundle_create_runtime_hooks`.
fn bundle_poststop_hooks(bundle: &Bundle) -> Vec<Hook> {
    bundle
        .spec
        .spec
        .hooks()
        .as_ref()
        .and_then(|h| h.poststop().clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_delete_rejects_running_container_without_force() {
        let run_dir = tempfile::tempdir().unwrap();
        let id = "running-no-force";
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Running,
            // Step 1 now checks REAL pid liveness (`kill(pid, None)`), not
            // just the `status` label — so this must be a pid the test
            // process can actually signal-probe successfully. Its own pid
            // is guaranteed alive for the duration of the test, same idiom
            // `state.rs`'s `read_and_refresh` liveness tests already use.
            // A hardcoded pid like `1` would report EPERM (not "alive")
            // when this test isn't running as root, defeating the check.
            pid: Some(std::process::id() as i32),
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let err = delete(id, run_dir.path(), data_dir.path(), false)
            .expect_err("deleting a container with a live process without --force must fail");
        assert!(
            format!("{err:#}").contains("without --force"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_delete_rejects_paused_container_without_force() {
        let run_dir = tempfile::tempdir().unwrap();
        let id = "paused-no-force";
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Paused,
            // See the comment in the Running variant of this test above:
            // must be a genuinely live, self-signalable pid now that step
            // 1 checks real liveness rather than the `status` label.
            pid: Some(std::process::id() as i32),
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let err = delete(id, run_dir.path(), data_dir.path(), false)
            .expect_err("deleting a container with a live process without --force must fail");
        assert!(
            format!("{err:#}").contains("without --force"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_delete_rejects_created_container_with_live_process_without_force() {
        // The bug this fix closes: a container in `Status::Created` has a
        // real, live process (kestrel-init blocks on the exec FIFO before
        // forking the entrypoint — see this module's doc comment). Step 1
        // must bail without --force here too, exactly as it would for
        // Running/Paused, since it's now gated on actual pid liveness, not
        // the status label.
        let run_dir = tempfile::tempdir().unwrap();
        let id = "created-live-no-force";
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Created,
            pid: Some(std::process::id() as i32),
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let err = delete(id, run_dir.path(), data_dir.path(), false).expect_err(
            "deleting a Created container with a genuinely live process without --force must fail",
        );
        assert!(
            format!("{err:#}").contains("without --force"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_delete_proceeds_when_status_says_stopped_but_would_also_proceed_for_dead_pid() {
        // The common, expected pre-delete case: Status::Stopped with a
        // pid that is no longer alive. The liveness check must naturally
        // skip the kill step (kill(pid, None) fails) and let delete()
        // proceed into teardown rather than bailing — proving step 1
        // isn't accidentally gated in a way that blocks the normal case.
        // Uses an out-of-range-ish pid (i32::MAX - 1) that, barring an
        // extraordinarily unlucky reuse, cannot correspond to a live
        // process — same idiom as `state.rs`'s own dead-pid test.
        let run_dir = tempfile::tempdir().unwrap();
        let id = "stopped-dead-pid";
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Stopped,
            pid: Some(i32::MAX - 1),
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: Some(0),
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        // No --force needed: the process is dead, so step 1 must not
        // bail. The call still ends in an aggregate Err because the
        // nonexistent bundle can't be reloaded (steps 4/6) — the point
        // here is exclusively that the error does NOT mention
        // "without --force", proving step 1 itself was skipped cleanly.
        let err = delete(id, run_dir.path(), data_dir.path(), false)
            .expect_err("nonexistent bundle means later steps still fail, but not step 1");
        assert!(
            !format!("{err:#}").contains("without --force"),
            "step 1 should have been skipped for a dead pid, unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_delete_proceeds_when_pid_is_none() {
        // A Creating-status container whose create() errored before ever
        // recording a pid: state.pid is None, so there's nothing to
        // liveness-check or kill — step 1 must handle this gracefully
        // (no panic, no spurious bail) and let delete() proceed.
        let run_dir = tempfile::tempdir().unwrap();
        let id = "creating-no-pid";
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Creating,
            pid: None,
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir.path(), id))
            .unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let err = delete(id, run_dir.path(), data_dir.path(), false)
            .expect_err("nonexistent bundle means later steps still fail, but not step 1");
        assert!(
            !format!("{err:#}").contains("without --force"),
            "step 1 should have been skipped when pid is None, unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_unpin_namespaces_skips_types_with_no_pin_file() {
        // No root/privilege needed: this never calls the real
        // pin_namespace/unpin_namespace privileged mount syscalls — every
        // candidate type's pin file is simply absent, so the loop's
        // `symlink_metadata` check short-circuits before ever reaching
        // `kestrel_ns::pin::unpin_namespace`.
        let ns_dir = tempfile::tempdir().unwrap();
        let errors = unpin_namespaces(ns_dir.path(), &ALL_NS_TYPES);
        assert!(
            errors.is_empty(),
            "no pin files exist; every type should be silently skipped, got: {errors:?}"
        );
    }

    #[test]
    fn test_unpin_namespaces_reports_a_real_failure_but_still_processes_every_type() {
        // A stray file that isn't a real bind-mounted namespace pin: the
        // `symlink_metadata` check passes (the file exists), so
        // `unpin_namespace` is genuinely attempted and fails (umount2 on
        // a plain file that was never bind-mounted returns EINVAL, or the
        // call isn't even privileged enough to try — either way, an
        // error). The point of this test is that ONE type failing must
        // not stop the loop from still checking every other type (all of
        // which are legitimately absent here).
        let ns_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ns_dir.path()).unwrap();
        std::fs::write(ns_dir.path().join(NsType::Uts.proc_name()), b"not a real pin").unwrap();

        let errors = unpin_namespaces(ns_dir.path(), &ALL_NS_TYPES);
        assert_eq!(
            errors.len(),
            1,
            "exactly one type (Uts) had a pin file present at all, got: {errors:?}"
        );
        assert!(errors[0].contains("Uts"), "unexpected error content: {errors:?}");
    }

    #[test]
    fn test_is_ignorable_unmount_error_accepts_enoent_and_einval_only() {
        assert!(is_ignorable_unmount_error(&anyhow::Error::new(
            nix::errno::Errno::ENOENT
        )));
        assert!(is_ignorable_unmount_error(&anyhow::Error::new(
            nix::errno::Errno::EINVAL
        )));
        assert!(!is_ignorable_unmount_error(&anyhow::Error::new(
            nix::errno::Errno::EPERM
        )));
        assert!(!is_ignorable_unmount_error(&anyhow::anyhow!("some unrelated error")));
    }

    #[test]
    fn test_is_ignorable_not_found_error_accepts_only_notfound_io_errors() {
        assert!(is_ignorable_not_found_error(&anyhow::Error::new(
            std::io::Error::from(std::io::ErrorKind::NotFound)
        )));
        assert!(!is_ignorable_not_found_error(&anyhow::Error::new(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        )));
        assert!(!is_ignorable_not_found_error(&anyhow::anyhow!("some unrelated error")));
    }

    #[test]
    fn test_remove_dir_all_tolerant_is_ok_when_already_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        remove_dir_all_tolerant(&missing).expect("missing directory should be tolerated");
    }

    #[test]
    fn test_remove_dir_all_tolerant_removes_a_real_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("real");
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("nested").join("file"), b"x").unwrap();
        remove_dir_all_tolerant(&dir).expect("removing a real directory should succeed");
        assert!(!dir.exists());
    }

    #[test]
    fn test_bundle_poststop_hooks_defaults_to_empty() {
        let bundle = Bundle {
            path: PathBuf::from("/nonexistent/bundle"),
            spec: kestrel_oci::raw::RawSpec {
                spec: kestrel_oci::default_spec::default_spec(),
                extra: serde_json::Map::new(),
            },
        };
        assert!(bundle_poststop_hooks(&bundle).is_empty());
    }
}
