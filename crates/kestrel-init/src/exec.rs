// crates/kestrel-init/src/exec.rs

use std::convert::Infallible;
use std::ffi::CString;

use anyhow::{Context, Result};
use kestrel_oci::runtime::{LinuxSeccomp, Process};
use nix::unistd::execve;

/// Applies the full Phase 5 security pipeline to the CURRENT process, then
/// execve()s into `process.args()`. Never returns on success (the process
/// image is replaced) — the `Result<Infallible>` return type makes that
/// contract checkable by the compiler at every call site, matching the
/// convention `Ok(x): Infallible` establishes elsewhere in Rust's std for
/// "this either diverges or errors."
pub fn exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Infallible> {
    std::env::set_current_dir(process.cwd())
        .with_context(|| format!("chdir to {}", process.cwd().display()))?;

    // apply_all runs BEFORE the chdir above is questioned further — cwd
    // itself needs no special privilege, so its exact position relative to
    // apply_all's five steps doesn't matter; done first here simply
    // because a failed chdir should abort before we've dropped anything.
    kestrel_security::apply::apply_all(process, seccomp).context("apply_all")?;

    let args = process
        .args()
        .as_deref()
        .filter(|a| !a.is_empty())
        .context("process.args must specify at least the program to exec")?;
    let program = CString::new(args[0].as_str()).context("program path contains a NUL byte")?;
    let argv: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("an argument contains a NUL byte")?;
    let envp: Vec<CString> = process
        .env()
        .iter()
        .flatten()
        .map(|e| CString::new(e.as_str()))
        .collect::<Result<_, _>>()
        .context("an env entry contains a NUL byte")?;

    // nix::unistd::execve's return type is `Result<Infallible, Errno>` —
    // it genuinely cannot construct `Ok` (a successful exec replaces this
    // process image and never returns to this stack frame at all), so
    // `.with_context()` propagating straight through to this function's
    // own `Result<Infallible>` return type is correct as-is, with no
    // `expect_err` unwrapping dance needed.
    execve(&program, &argv, &envp)
        .with_context(|| format!("execve({:?}, {:?})", program, argv))
}
