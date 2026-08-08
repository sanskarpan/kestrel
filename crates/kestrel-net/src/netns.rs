// crates/kestrel-net/src/netns.rs
//
//! Network namespace creation, pinning, teardown, and temporary joining.
//!
//! `create_netns` deliberately does NOT use a raw `fork()` (unlike
//! kestrel-ns's own `run_isolated`/three-stage-dance pattern, which is
//! only proven safe inside kestrel-runtime — a process Rule #2
//! *guarantees* is single-threaded). kestrel-net is explicitly
//! multi-threaded (tokio `rt-multi-thread`); forking one of its threads
//! would only duplicate that thread, silently leaving any lock another
//! thread held at that instant permanently "held" in the child, a real
//! deadlock hazard the moment the child's own bookkeeping touches
//! anything similar. Independent confirmation this isn't overcautious:
//! the `rtnetlink` crate's OWN `NetworkNamespace::add` does exactly this
//! unsafe raw-fork thing internally — deliberately not used here.
//!
//! Instead: spawn `netns-helper` (a separate, tiny, single-purpose
//! binary — see src/bin/netns-helper.rs) via `tokio::process::Command`,
//! which uses `posix_spawn` on Linux specifically to avoid this class of
//! multi-threaded-fork hazard. The helper unshares CLONE_NEWNET, signals
//! readiness, and blocks; the parent pins the namespace via the helper's
//! pid, then releases it.

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use kestrel_ns::join::with_namespace;
use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::types::NsType;
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Name of the helper binary built by this crate's `[[bin]]` target.
const HELPER_BIN_NAME: &str = "netns-helper";

/// Cargo sets this env var to the absolute path of the `netns-helper`
/// binary — but ONLY as the ambient process environment for test/bench
/// binaries built by `cargo test`/`cargo bench` (confirmed empirically:
/// it's a genuine runtime env var inherited by the whole test process,
/// not merely a compile-time `env!` value, so plain library code can
/// read it via `std::env::var` with no `env!` needed in this file). It
/// is never set for a production `kestreld` invocation, so it's checked
/// first and then ignored if absent.
const CARGO_BIN_ENV_VAR: &str = "CARGO_BIN_EXE_netns-helper";

/// Resolves the path to the `netns-helper` binary.
///
/// In a `cargo test`/`cargo bench` context, `current_exe()` for the
/// *test* binary resolves to `target/debug/deps/<test>-<hash>`, whose
/// parent is `target/debug/deps/` — NOT `target/debug/`, where
/// `netns-helper` actually gets built. So the naive
/// `current_exe().parent().join("netns-helper")` fails to find it in
/// tests. Resolution order:
///
/// 1. `CARGO_BIN_EXE_netns-helper` (test/bench context only).
/// 2. Sibling of `current_exe()` (the expected production layout: e.g.
///    `kestreld` and `netns-helper` installed/built into the same
///    directory).
/// 3. Parent-of-parent of `current_exe()` (covers running a compiled
///    test binary directly, outside `cargo test`, from `target/debug/deps/`).
fn resolve_helper_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var(CARGO_BIN_ENV_VAR) {
        return Ok(PathBuf::from(p));
    }

    let current_exe = std::env::current_exe().context("resolving current_exe")?;
    let exe_dir = current_exe
        .parent()
        .context("current_exe has no parent dir")?;

    let sibling = exe_dir.join(HELPER_BIN_NAME);
    if sibling.is_file() {
        return Ok(sibling);
    }

    if let Some(grandparent) = exe_dir.parent() {
        let candidate = grandparent.join(HELPER_BIN_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    bail!(
        "could not locate {HELPER_BIN_NAME} binary near {} (checked {} and its parent dir)",
        current_exe.display(),
        exe_dir.display()
    )
}

fn pin_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join("netns").join(id)
}

/// Creates a new network namespace and pins it at
/// `<run_dir>/netns/<id>`. `run_dir` is normally `/run/kestrel`
/// (SPEC.md's state dir), passed explicitly rather than hardcoded so
/// tests can point it at a tempdir.
pub async fn create_netns(run_dir: &Path, id: &str) -> Result<PathBuf> {
    let target = pin_path(run_dir, id);
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let helper_path = resolve_helper_path()?;

    let mut child = Command::new(&helper_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", helper_path.display()))?;

    let pid = child
        .id()
        .context("helper process has no pid (already exited?)")?;

    // Wait for the one-byte readiness signal before pinning — see
    // netns-helper.rs's own comment for why this handshake exists.
    let mut stdout = child.stdout.take().context("helper's stdout was not piped")?;
    let mut ready = [0u8; 1];
    stdout
        .read_exact(&mut ready)
        .await
        .context("reading readiness byte from netns-helper")?;
    if ready[0] != b'R' {
        bail!("netns-helper sent unexpected readiness byte: {:?}", ready);
    }

    let pin_result = pin_namespace(Pid::from_raw(pid as i32), NsType::Net, &target);

    // Release the helper regardless of whether pinning succeeded — it's
    // done its job either way, and leaving it blocked on stdin forever
    // on a pin failure would leak a process.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.shutdown().await;
    }
    let _ = child.wait().await;

    pin_result
        .with_context(|| format!("pinning new netns for {id} at {}", target.display()))?;
    Ok(target)
}

/// Reverses [`create_netns`]: unmounts the pin and removes the file.
pub fn teardown_netns(run_dir: &Path, id: &str) -> Result<()> {
    let target = pin_path(run_dir, id);
    unpin_namespace(&target)
}

/// Temporarily enters the netns pinned at `pin_path`, runs `f`, restores
/// the caller's original netns on the way out. `f` and everything it
/// calls MUST be synchronous — this whole call must run on one pinned OS
/// thread (see `with_namespace`'s own doc comment), so callers on a
/// multi-threaded tokio runtime MUST wrap this in
/// `tokio::task::block_in_place` (or run it from a context already
/// guaranteed single-threaded, e.g. a test's `run_isolated` fork).
pub fn nsenter<T>(pin_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let file = std::fs::File::open(pin_path)
        .with_context(|| format!("opening netns pin {}", pin_path.display()))?;
    with_namespace(NsType::Net, file.as_fd(), f)
}
