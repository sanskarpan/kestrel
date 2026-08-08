// crates/kestrel-net/tests/common/mod.rs
//
// Shared test helper for kestrel-net's root-gated integration tests.
// Named `common/mod.rs` (rather than `common.rs`) on purpose: that's the
// Rust-recognized convention for a module shared across multiple test
// binaries in `tests/` without cargo treating it as its own test binary.

use std::future::Future;

use nix::sched::{unshare, CloneFlags};

/// Runs `f` — an async closure — inside a forked, single-threaded child
/// process (via `kestrel_ns::test_util::run_isolated`) that has
/// `unshare(CLONE_NEWNET)`d its own private, empty network namespace
/// before `f` ever starts.
///
/// This is DIFFERENT from `kestrel_net::netns::nsenter`: `nsenter` joins
/// an already-created, PINNED namespace (production code, used once a
/// container's netns exists on disk under `/run/kestrel/netns/<id>`).
/// This helper instead isolates the TEST PROCESS itself in a fresh,
/// throwaway, unpinned namespace, purely so that this crate's real
/// `rtnetlink` mutations (bridge/veth/address add-and-delete) never
/// touch the VM's actual host network state while under test —
/// analogous to how `kestrel-rootfs`/`kestrel-image`'s own
/// `tests/common/mod.rs` helpers isolate their mount-namespace-mutating
/// tests via `unshare(CLONE_NEWNS)` + a private remount.
///
/// ## Reconciling fork-before-unshare with an async test body
///
/// `kestrel_ns::test_util::run_isolated`'s contract requires a
/// synchronous `FnOnce()` closure, forked while the *calling* process
/// (cargo test's own harness, which spawns a thread per test) is still
/// multi-threaded — forking resets the CHILD down to exactly one thread
/// regardless of the parent's thread count at the moment of the call, so
/// `unshare` is always safe there. But this crate's actual work
/// (`rtnetlink`'s `Handle`) is async. The sequencing used here to
/// reconcile the two:
///
/// 1. `tokio::task::spawn_blocking` moves the whole fork+unshare+run
///    dance onto one of the test runtime's blocking-pool threads, so the
///    calling `#[tokio::test]` task can simply `.await` a `JoinHandle`
///    instead of blocking its own executor thread on `waitpid`.
/// 2. Inside that blocking closure, `kestrel_ns::test_util::run_isolated`
///    forks. The child is, at that instant, guaranteed single-threaded
///    (see its own doc comment), so...
/// 3. ...`unshare(CLONE_NEWNET)` runs first, safely, before anything else
///    in the child.
/// 4. Only THEN is a brand new Tokio runtime built — deliberately built
///    AFTER the unshare, not before: any worker/reactor thread Tokio
///    spun up would inherit whatever netns was active AT THAT THREAD'S
///    OWN CREATION time, so building (or reusing) a runtime before the
///    unshare risks a thread that never picked up the new namespace and
///    silently leaks mutations into the real one. Building it AFTER the
///    unshare is what keeps "exactly one namespace, established once,
///    for every thread this process will ever have" airtight — this
///    holds regardless of runtime flavor, since new OS threads (however
///    many the runtime spins up) inherit their creating thread's
///    namespaces at `clone()` time, and the creating thread here has
///    already unshared.
///
///    **Flavor note (revised from Task 4):** originally built as
///    `current_thread`, on the reasoning that never spinning up extra OS
///    threads is the simplest way to keep the above invariant airtight.
///    Task 5 found a real conflict with that: `kestrel_net::veth::attach_veth`
///    internally uses `tokio::task::block_in_place` (required by
///    `nsenter`'s single-thread-for-the-duration contract) — and
///    `block_in_place` unconditionally panics when called from inside a
///    `current_thread` runtime (confirmed directly from tokio 1.53.1's
///    own source, `runtime/scheduler/multi_thread/worker.rs`: a
///    `current_thread` context hits the "can call blocking only when
///    running on the multi-threaded runtime" panic branch). So this now
///    builds a `multi_thread` runtime instead. This does not weaken the
///    isolation guarantee above: every worker thread the multi-thread
///    runtime spawns is created via `Builder::build()`, which — per
///    point 4 — always runs after the `unshare` in this function, so
///    every such thread still inherits the correct (already-isolated)
///    netns at the moment it's spawned.
/// 5. `rt.block_on(f())` runs the actual async test body on that runtime.
///
/// `f` takes no captured state from the caller in this crate's tests
/// (everything it needs — bridge name, gateway, subnet — is constructed
/// inside the closure), which is what lets it satisfy `Send + 'static`
/// for `spawn_blocking` for free.
pub async fn run_in_isolated_netns<F, Fut>(f: F)
where
    F: FnOnce() -> Fut + Send + std::panic::UnwindSafe + 'static,
    Fut: Future<Output = ()>,
{
    tokio::task::spawn_blocking(move || {
        kestrel_ns::test_util::run_isolated(move || {
            unshare(CloneFlags::CLONE_NEWNET).expect("unshare(CLONE_NEWNET)");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("building isolated-netns tokio runtime");
            rt.block_on(f());
        });
    })
    .await
    .expect("isolated-netns child task panicked or was cancelled");
}
