// crates/kestrel-init/src/pdeathsig.rs

use anyhow::{Context, Result};
use nix::sys::signal::Signal;

/// Sets PR_SET_PDEATHSIG(sig) on the calling process — if the parent
/// (kestrel-runtime) dies, the kernel delivers `sig` to this process
/// automatically, so kestrel-init never becomes an orphan supervising a
/// container with no one left to report its exit status to. Must be set
/// early (before any privilege-dropping steps that might affect signal
/// delivery permissions) and is re-armed to the caller's real parent at
/// the moment of the call — if the parent has ALREADY died by the time
/// this runs, the signal fires essentially immediately rather than never.
pub fn set_parent_death_signal(sig: Signal) -> Result<()> {
    nix::sys::prctl::set_pdeathsig(Some(sig)).context("prctl(PR_SET_PDEATHSIG)")
}
