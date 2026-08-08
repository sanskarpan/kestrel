// crates/kestrel-init/src/bootstrap.rs

use std::os::fd::RawFd;

use anyhow::Result;
use kestrel_oci::bootstrap::Bootstrap;

/// The well-known fd number `create.rs`'s child_action closure dup2's
/// the bootstrap socket onto before execve — a fixed number (rather than
/// discovering it via an env var) keeps kestrel-init's own startup dead
/// simple. Verify this exact number doesn't collide with anything
/// kestrel-init itself needs (stdin/stdout/stderr are 0/1/2; 3 is the
/// first free descriptor in a freshly-exec'd process barring anything
/// else explicitly inherited — confirm this assumption holds once Task 8
/// writes the real child_action code, adjust if it turns out something
/// else already occupies fd 3 in this process's real startup sequence).
pub const BOOTSTRAP_FD: RawFd = 3;

/// Reads the `Bootstrap` payload `create.rs` already wrote to
/// `BOOTSTRAP_FD` before `execve`'ing into this binary — see
/// `kestrel_oci::bootstrap`'s module doc comment for why that's a
/// `SOCK_STREAM` socketpair (length-prefixed framing) rather than the
/// `kestrel_ns::sync` datagram pattern. `recv_bootstrap`'s real current
/// signature (`fn recv_bootstrap(fd: RawFd) -> Result<Bootstrap>`) takes
/// the raw fd directly, matching what's called here.
pub fn receive() -> Result<Bootstrap> {
    kestrel_oci::bootstrap::recv_bootstrap(BOOTSTRAP_FD)
}
