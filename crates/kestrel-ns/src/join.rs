// crates/kestrel-ns/src/join.rs
//
//! Joining an existing set of pinned namespaces via `setns(2)`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

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
