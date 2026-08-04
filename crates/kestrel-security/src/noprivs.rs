// crates/kestrel-security/src/noprivs.rs

use anyhow::{Context, Result};

/// Sets PR_SET_NO_NEW_PRIVS on the calling thread. IRREVERSIBLE for the
/// lifetime of the process (and everything it execve()s). Must run before
/// seccomp installation (an unprivileged process may only load a seccomp
/// filter once this is set), and permanently prevents setuid/setcap
/// binaries execve()'d afterward from elevating.
pub fn set_no_new_privs() -> Result<()> {
    nix::sys::prctl::set_no_new_privs().context("prctl(PR_SET_NO_NEW_PRIVS, 1)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_no_new_privs_is_observable_afterward() {
        kestrel_ns::test_util::run_isolated(|| {
            assert!(!nix::sys::prctl::get_no_new_privs().unwrap(), "should start unset in a fresh process");
            set_no_new_privs().expect("set_no_new_privs");
            assert!(nix::sys::prctl::get_no_new_privs().unwrap(), "must be observably set afterward");
        });
    }
}
