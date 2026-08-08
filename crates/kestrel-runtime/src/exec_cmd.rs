// crates/kestrel-runtime/src/exec_cmd.rs
//
//! `exec` — runs an additional process inside an already-`Created`/
//! `Running` container's namespaces. See docs/superpowers/specs/
//! 2026-08-05-phase8-runtime-binary-design.md §1's resolution of a real
//! PID-namespace bug:
//!
//! `setns(fd, CLONE_NEWPID)` does NOT move the CALLING process into the
//! target PID namespace — per `pid_namespaces(7)`, it only changes which
//! namespace the caller's *subsequently forked children* are born into;
//! the caller's own `/proc/self/ns/pid` is unaffected (this is exactly
//! what `create_pins_namespaces.rs`'s own setns test already documents
//! and deliberately excludes `NsType::Pid` from its direct-identity
//! check). So this module cannot simply `join_namespaces` then `execve`
//! in place — it must `join_namespaces` (setns into every OTHER pinned
//! namespace too, which DO take effect on the calling process
//! immediately), THEN `fork`, with the CHILD (born after the join, hence
//! genuinely inside the container's PID namespace) doing the final
//! `exec_into`, and the PARENT `waitpid`-ing on it and propagating its
//! exit code as this function's own return value.
//!
//! ## Why existence-checking, not a re-derived `NamespacePlan`
//!
//! `create.rs`/`delete.rs` both re-derive the container's exact
//! `NamespacePlan` from the bundle (`build_namespace_plan`) before
//! pinning/unpinning, because those two operations need to know
//! authoritatively which types were SUPPOSED to be pinned (pinning is
//! all-or-nothing; unpinning needs to tell "never pinned" apart from
//! "pinned then failed to unpin"). `exec` has neither concern — it only
//! needs to `setns` into whatever pins genuinely exist right now, so a
//! namespace that was planned but never successfully pinned (in this
//! Lima VM, that's always `NsType::Mount` — see `create.rs`'s
//! `pin_namespaces` doc comment) is simply absent from `pins` and
//! `join_namespaces` skips it, exactly as it would for any other type
//! this container's plan never requested at all. Checking existence of
//! all 8 possible `NsType`s directly against the fixed `ns/<proc_name>`
//! paths is therefore the right approach here, not a shortcut standing
//! in for the "real" one.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use kestrel_ns::join::join_namespaces;
use kestrel_oci::runtime::Process;
use kestrel_oci::state::{State, Status};

/// Joins every pinned namespace of container `id` under `run_dir`, then
/// forks and execs `process` inside them, waiting for it to finish and
/// returning its exit code (128+signal for a fatal-signal exit, matching
/// the conventional shell/`runc exec` encoding).
///
/// `process` is executed with the FULL Phase 5 security pipeline
/// (`kestrel_init::exec::exec_into` -> `kestrel_security::apply::apply_all`)
/// applied to it, exactly as the container's own entrypoint is — no
/// separate, weaker code path for `exec`ed processes.
///
/// # Existence/liveness check
///
/// Before touching any namespace pin, this reads `state.json` via
/// `State::read`, which naturally errors (file-not-found) for an `id` that
/// was never created or was already `delete`d — see `start.rs`'s identical
/// `State::read` idiom for the established "does this container exist"
/// check in this crate. Without this, a typo'd or stale `id` would walk
/// straight into the loop below, find that none of the 8 `NsType` pin
/// files exist under a nonexistent `run_dir/<id>/ns`, end up with an EMPTY
/// `pins` map, and `join_namespaces(&pins)` on an empty map is a silent
/// no-op success — meaning `process` would then be forked/exec'd in
/// whatever namespaces the CALLING process (i.e. the host / this CLI
/// invocation itself) already happens to be in, with no error at all. That
/// was a real, live-confirmed bug.
///
/// `status` is further required to be `Created` or `Running` — OCI's own
/// `exec` semantics (and this crate's own root-gated exec tests, which
/// exec against a container immediately after `create()`, i.e. while it is
/// still `Created`) allow both. `Stopped` is rejected because there's
/// nothing left to join into. `Paused` is rejected too: its namespaces
/// still exist, but its cgroup is frozen (`pause.rs`/`cgroup.freeze`), so a
/// process joined into it and then forked would simply hang rather than
/// run — exec-ing into a frozen container isn't useful and a container
/// must be `resume`d first.
pub fn exec(id: &str, run_dir: &Path, process: &Process) -> Result<i32> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let state = State::read(&state_json_path)
        .with_context(|| format!("container {id} not found"))?;
    anyhow::ensure!(
        matches!(state.status, Status::Created | Status::Running),
        "cannot exec into container {id}: status is {:?}, expected Created or Running",
        state.status
    );

    let ns_dir = run_dir.join(id).join("ns");
    let mut pins = BTreeMap::new();
    for ns_type in [
        kestrel_ns::types::NsType::Cgroup,
        kestrel_ns::types::NsType::Ipc,
        kestrel_ns::types::NsType::Uts,
        kestrel_ns::types::NsType::Net,
        kestrel_ns::types::NsType::Pid,
        kestrel_ns::types::NsType::Mount,
        kestrel_ns::types::NsType::Time,
        kestrel_ns::types::NsType::User,
    ] {
        let pin_path = ns_dir.join(ns_type.proc_name());
        if pin_path.exists() {
            pins.insert(ns_type, pin_path);
        }
    }

    // Defense-in-depth: even with the state.json check above, a
    // known-Created/Running container's `ns/` directory could in principle
    // have been cleaned up out-of-band (e.g. manual interference, a bug
    // elsewhere). An empty `pins` map is itself the exact symptom of the
    // original bug (nothing to join, `join_namespaces` silently no-ops) —
    // fail loudly instead of falling through to a no-op join.
    anyhow::ensure!(
        !pins.is_empty(),
        "no pinned namespaces found for container {id} under {}; refusing to exec into the \
         caller's own namespaces",
        ns_dir.display()
    );

    join_namespaces(&pins).context("joining container namespaces")?;

    // SAFETY: this process is a single-threaded CLI invocation of
    // `kestrel exec` (the same "cargo test's harness is multi-threaded,
    // production binaries are not" distinction `preflight::
    // assert_single_threaded` exists to enforce elsewhere in this crate —
    // the root-gated integration test below routes this call through
    // `kestrel_ns::test_util::run_isolated` for exactly that reason). The
    // child branch below only calls `waitpid`-safe/async-signal-safe-ish
    // library code (`kestrel_init::exec::exec_into`, which itself either
    // `execve`s — replacing the process image entirely — or returns an
    // error handled via a plain `std::process::exit`) before terminating;
    // no other non-async-signal-safe work happens between `fork` and that
    // exit/exec.
    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { child } => {
            let status = nix::sys::wait::waitpid(child, None).context("waiting on exec'd child")?;
            Ok(exit_code_from_status(status))
        }
        nix::unistd::ForkResult::Child => {
            let _: anyhow::Result<std::convert::Infallible> = kestrel_init::exec::exec_into(process, None);
            // Only reached if exec_into itself failed (e.g. the target
            // program doesn't exist, or the security pipeline rejected
            // it) — never on success, since a successful execve replaces
            // this process image and never returns here at all. 127
            // matches the conventional shell "command not found /
            // couldn't exec" exit code.
            std::process::exit(127);
        }
    }
}

fn exit_code_from_status(status: nix::sys::wait::WaitStatus) -> i32 {
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => code,
        nix::sys::wait::WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::runtime::ProcessBuilder;
    use std::path::PathBuf;

    fn dummy_process() -> Process {
        ProcessBuilder::default()
            .args(vec!["true".to_string()])
            .cwd("/")
            .build()
            .expect("build dummy process")
    }

    fn write_state(run_dir: &Path, id: &str, status: Status) {
        let state = State {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status,
            pid: None,
            bundle: PathBuf::from("/nonexistent/bundle"),
            annotations: Default::default(),
            exit_code: None,
        };
        state
            .write_atomic(&crate::state::state_json_path(run_dir, id))
            .unwrap();
    }

    // None of these tests reach `join_namespaces`/`fork` — every case below
    // is rejected by the existence/status/pins checks before that point, so
    // no root privilege or namespace setup is required.

    #[test]
    fn test_exec_errors_when_container_does_not_exist() {
        let run_dir = tempfile::tempdir().unwrap();
        let err = exec("definitely-does-not-exist", run_dir.path(), &dummy_process())
            .expect_err("exec against a never-created id must fail, not silently no-op");
        assert!(
            format!("{err:#}").contains("not found"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_exec_rejects_stopped_container() {
        let run_dir = tempfile::tempdir().unwrap();
        write_state(run_dir.path(), "stopped-id", Status::Stopped);
        let err = exec("stopped-id", run_dir.path(), &dummy_process())
            .expect_err("exec against a Stopped container must fail");
        assert!(
            format!("{err:#}").contains("Stopped"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_exec_rejects_paused_container() {
        let run_dir = tempfile::tempdir().unwrap();
        write_state(run_dir.path(), "paused-id", Status::Paused);
        let err = exec("paused-id", run_dir.path(), &dummy_process())
            .expect_err("exec against a Paused container must fail (frozen cgroup would hang)");
        assert!(
            format!("{err:#}").contains("Paused"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn test_exec_rejects_empty_pins_even_for_created_status() {
        // Defense-in-depth: state.json says Created (passes the status
        // gate) but the ns/ directory has no pin files at all — the exact
        // symptom of the original bug. Must still fail loudly rather than
        // silently join zero namespaces.
        let run_dir = tempfile::tempdir().unwrap();
        write_state(run_dir.path(), "no-pins-id", Status::Created);
        let err = exec("no-pins-id", run_dir.path(), &dummy_process())
            .expect_err("exec with no pinned namespaces must fail, not silently no-op");
        assert!(
            format!("{err:#}").contains("no pinned namespaces"),
            "unexpected error: {err:#}"
        );
    }
}
