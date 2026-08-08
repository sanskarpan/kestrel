// crates/kestrel-net/src/bin/netns-helper.rs
//
//! A minimal, single-purpose helper: unshare CLONE_NEWNET, signal
//! readiness, then block until told to exit. Spawned via
//! `tokio::process::Command` (which uses posix_spawn on Linux) rather
//! than reached via a raw `fork()` from kestrel-net's own multi-threaded
//! process — see netns.rs's module doc for the full reasoning. Every
//! operation here is a plain, synchronous, async-signal-safe-adjacent
//! syscall; there is no allocation-heavy or lock-taking work between
//! process start and the unshare call.

use std::io::{Read, Write};

fn main() {
    if let Err(e) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET) {
        eprintln!("netns-helper: unshare(CLONE_NEWNET) failed: {e}");
        std::process::exit(1);
    }

    // Signal readiness: one byte on stdout. The parent reads this before
    // proceeding to open /proc/<this-pid>/ns/net for pinning — without
    // this handshake, the parent could race ahead and try to pin before
    // the unshare has actually happened.
    let mut stdout = std::io::stdout();
    if stdout.write_all(b"R").and_then(|_| stdout.flush()).is_err() {
        std::process::exit(1);
    }

    // Block until the parent closes stdin (EOF) or sends a byte — either
    // way, this process's only remaining job is to keep existing long
    // enough for the parent to pin the namespace via
    // /proc/<pid>/ns/net; once pinned, the namespace survives this
    // process's exit (the bind-mount pin is what keeps it alive, not
    // this process), so exiting here is always safe once the parent has
    // signaled it's done.
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read(&mut buf);
}
