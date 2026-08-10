// crates/kestreld/src/runtime_cli.rs
//
//! Thin subprocess-invocation helper shared by every lifecycle endpoint
//! (start/stop/kill/pause/unpause/delete, Task 9): shells out to the real
//! `kestrel-runtime` binary rather than linking it as a library — matching
//! `lib.rs`'s own "`kestreld` never links `kestrel-runtime`" rule, the same
//! reason `api::containers::spawn_shim_and_create` (Task 8) already
//! fork+execs it instead of calling `kestrel_runtime::create::create`
//! directly.
//!
//! Binary resolution deliberately reuses `crate::resolve_sibling_binary`
//! (`main.rs`, Task 8) rather than re-deriving a second, possibly-
//! inconsistent sibling-binary lookup here — that helper is already the
//! one, real convention this crate uses to locate `kestrel-shim`/
//! `kestrel-runtime` (mirroring `kestrel_runtime::create::
//! resolve_kestrel_init_path`'s own sibling-of-`current_exe()` technique),
//! and `AppState::runtime_path`/`shim_path` are themselves just cached
//! results of calling it once at startup. A plain `Command::new("kestrel-
//! runtime")` PATH lookup would silently contradict that convention, so
//! this file never does that.

use std::path::Path;

use anyhow::Context;

/// Invokes `kestrel-runtime --run-dir <run_dir> --data-dir <data_dir>
/// <args...>` and waits for it to exit, treating a non-zero exit status as
/// a real error (the global `--run-dir`/`--data-dir` flags MUST precede
/// the subcommand token, per `kestrel-runtime`'s real `Cli` struct,
/// `crates/kestrel-runtime/src/cli.rs:18-26` — `args` is only ever the
/// subcommand and ITS OWN flags, e.g. `["kill", id, signal]`, never the
/// global flags).
pub async fn run_kestrel_runtime(run_dir: &Path, data_dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let bin = crate::resolve_sibling_binary("kestrel-runtime")
        .context("locating kestrel-runtime binary for a lifecycle operation")?;
    let status = tokio::process::Command::new(&bin)
        .arg("--run-dir")
        .arg(run_dir)
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .status()
        .await
        .with_context(|| format!("spawning {} {args:?}", bin.display()))?;
    anyhow::ensure!(status.success(), "kestrel-runtime {args:?} failed: {status}");
    Ok(())
}
