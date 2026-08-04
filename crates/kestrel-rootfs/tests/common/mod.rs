// crates/kestrel-rootfs/tests/common/mod.rs
//
// Shared test helper for kestrel-rootfs's root-gated integration tests.
// Named `common/mod.rs` (rather than `common.rs`) on purpose: that's the
// Rust-recognized convention for a module shared across multiple test
// binaries in `tests/` without cargo treating it as its own test binary
// (which would otherwise print a spurious "running 0 tests" and, worse,
// attempt to execute it standalone).

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
/// This exact bug (isolation via `unshare` alone, without the remount) was
/// found and fixed in Task 7 (`tests/mounts.rs`) and retroactively in Task
/// 4 (`tests/overlay.rs`). It previously existed as three near-identical
/// copies across `tests/mounts.rs`, `tests/mask.rs`, and (in split form, as
/// `run_isolated` + `make_mount_ns_private`) `tests/overlay.rs`; it is
/// consolidated here so this safety-critical comment has exactly one place
/// to go stale, instead of three.
pub fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>)
            .expect("remount / as MS_PRIVATE|MS_REC");
        f();
    });
}
