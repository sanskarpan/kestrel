// crates/kestrel-ns/src/join.rs
//
//! Joining an existing set of pinned namespaces via `setns(2)`.

use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::types::NsType;

/// The one join order that is safe regardless of which subset of namespaces
/// is present: user namespace LAST. Public so other code (debugging/CLI
/// tooling) can introspect the canonical order without duplicating it.
pub const JOIN_ORDER: &[NsType] = &[
    NsType::Cgroup,
    NsType::Ipc,
    NsType::Uts,
    NsType::Net,
    NsType::Pid,
    NsType::Mount,
    NsType::Time,
    NsType::User,
];

/// Joins every pinned namespace in `pins`, in `JOIN_ORDER`. Namespace types
/// absent from `pins` are silently skipped — the caller is responsible for
/// ensuring the pin set is complete if that matters.
///
/// Entering a user namespace drops the capabilities you need to enter the
/// others, so joining user-first makes every subsequent `setns()` fail with
/// `EPERM`. This ordering bug produces the exact error in runc issue #4390.
pub fn join_namespaces(pins: &BTreeMap<NsType, PathBuf>) -> Result<()> {
    for ns in JOIN_ORDER {
        let Some(path) = pins.get(ns) else { continue };
        let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        nix::sched::setns(&f, ns.clone_flag())
            .with_context(|| format!("setns into {ns:?} via {}", path.display()))?;
    }
    Ok(())
}

/// Temporarily joins the namespace referenced by `fd`, runs `f`, then
/// restores the CALLING THREAD's original namespace before returning —
/// unlike [`join_namespaces`] (a one-way join used once at final
/// container exec), this is for code that needs to dip into another
/// namespace and come back, e.g. `kestrel-net`'s `nsenter` for
/// configuring an interface from inside a container's netns.
///
/// `setns` operates on the CALLING THREAD, not the whole process —
/// callers running under a multi-threaded async runtime MUST ensure this
/// runs on one pinned OS thread for its entire duration (e.g. via
/// `tokio::task::block_in_place`), since a raw `setns()` racing the
/// runtime's work-stealing scheduler would leave the wrong thread in the
/// wrong namespace. This function itself is runtime-agnostic — it uses
/// only synchronous syscalls — enforcing "stay on one thread" is the
/// caller's responsibility.
///
/// The original namespace is read from `/proc/thread-self/ns/<type>`,
/// not `/proc/self/ns/<type>`: `/proc/self` resolves to the process's
/// thread-group leader rather than the calling thread, so on a thread
/// that has previously diverged from the leader's namespace (e.g. a
/// reused tokio worker thread), `/proc/self` would capture the wrong
/// "original" to restore. `/proc/thread-self` always resolves to the
/// calling thread and is correct in both cases.
pub fn with_namespace<T>(ns: NsType, fd: BorrowedFd, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let self_path = Path::new("/proc/thread-self/ns").join(ns.proc_name());
    let original = std::fs::File::open(&self_path).with_context(|| {
        format!(
            "opening {} to remember the current namespace",
            self_path.display()
        )
    })?;

    nix::sched::setns(fd, ns.clone_flag())
        .with_context(|| format!("setns into the target {ns:?} namespace"))?;

    // Guard ensures the restore happens even if `f` panics — `setns`ing
    // back to `original` on Drop, best-effort (a failure here is logged
    // via `tracing::error!` rather than propagated, since Drop can't
    // return a Result; matches this crate's existing best-effort-cleanup
    // idiom elsewhere, e.g. pin.rs's `let _ = fs::remove_file(...)`).
    struct RestoreGuard {
        original: std::fs::File,
        ns: NsType,
    }
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            if let Err(e) = nix::sched::setns(self.original.as_fd(), self.ns.clone_flag()) {
                tracing::error!(error = %e, ns = ?self.ns, "failed to restore original namespace after with_namespace");
            }
        }
    }
    let _guard = RestoreGuard { original, ns };

    f()
}
