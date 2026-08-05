// crates/kestrel-image/tests/common/mod.rs
//
// Shared test helper for kestrel-image's root-gated integration tests.
// Named `common/mod.rs` (rather than `common.rs`) on purpose: that's the
// Rust-recognized convention for a module shared across multiple test
// binaries in `tests/` without cargo treating it as its own test binary.
//
// This is a deliberate, documented DUPLICATE of
// `crates/kestrel-rootfs/tests/common/mod.rs`'s helper of the same name —
// this test lives in a different crate (kestrel-image, not kestrel-rootfs),
// and cargo test binaries can't share `tests/` helpers across a crate
// boundary. This project's established convention (see kestrel-security's
// own doc-comment duplication of Phase 2/4's deny_personality_profile, and
// kestrel-init's own copy of the seccomp-deny construction) is deliberate,
// documented duplication across crate boundaries rather than an awkward
// cross-crate test-helper dependency — so this comment is kept in sync with
// the original rather than factored out.

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};

/// Runs `f` inside a forked, single-threaded child (via
/// `kestrel_ns::test_util::run_isolated`) that has `unshare(CLONE_NEWNS)`d
/// its own private mount namespace AND had `/` recursively remounted
/// `MS_PRIVATE`.
///
/// Both steps are required. `unshare(CLONE_NEWNS)` alone does NOT isolate:
/// the new namespace starts as a copy of the caller's mount tree, and by
/// default those mounts are MS_SHARED, so anything mounted "inside" it
/// propagates straight back into the real host/VM mount namespace. The
/// `MS_PRIVATE | MS_REC` remount below severs that propagation so
/// mounts/unmounts performed by `f` stay confined to this namespace and
/// vanish for free when the forked child exits — even if `f` panics before
/// any explicit cleanup/unmount is reached.
///
/// See `crates/kestrel-rootfs/tests/common/mod.rs`'s identical helper for
/// the full history of this bug class (Task 7/Task 4 of Phase 4's plan).
pub fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>)
            .expect("remount / as MS_PRIVATE|MS_REC");
        f();
    });
}
