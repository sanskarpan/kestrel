// crates/kestrel-net/tests/netns.rs

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use kestrel_net::netns::{create_netns, nsenter, teardown_netns};

/// A namespace's identity, for comparison purposes. `readlink` on a
/// namespace file (e.g. `/proc/<pid>/ns/net`) normally yields a
/// `net:[<inode>]`-style string, but that does NOT hold for a
/// *bind-mounted pin* of one: once bind-mounted, the pin is a plain
/// regular file (mode `-r--r--r--`) rather than a magic symlink, so
/// `readlink()` on it fails with `EINVAL` (confirmed empirically against
/// this VM's kernel — the plan's assumption that readlink would work
/// verbatim on the pin does not hold). What DOES hold, confirmed the
/// same way: `stat()`/`fs::metadata()` on the pin reports the exact same
/// `(dev, ino)` pair as `stat()` on the original (dereferenced)
/// `/proc/<pid>/ns/net` — nsfs entries carry a stable identity through
/// that pair regardless of whether they're reached via `/proc` or via a
/// bind-mount elsewhere. So identity here is compared via `(dev, ino)`,
/// not via `readlink`.
fn ns_identity(path: &Path) -> (u64, u64) {
    let meta = std::fs::metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// The CALLING THREAD's own current network namespace.
///
/// Deliberately reads `/proc/thread-self/ns/net`, NOT `/proc/self/ns/net`
/// — confirmed empirically (via a failing assertion during development)
/// that `/proc/self` resolves to the thread-GROUP-leader's (main
/// thread's) namespace regardless of which OS thread performs the read,
/// while `setns(2)` — which is what `nsenter`/`with_namespace` actually
/// call — changes only the CALLING thread's namespace. Since
/// `tokio::task::block_in_place`'s closure runs on a worker OS thread
/// that is essentially never the process's main thread, checking
/// `/proc/self/ns/net` from inside that closure silently observes the
/// unaffected main thread instead of the thread that was actually
/// `setns`'d — `/proc/thread-self` is the per-thread-correct magic
/// symlink for exactly this case.
fn current_thread_ns_identity() -> (u64, u64) {
    ns_identity(Path::new("/proc/thread-self/ns/net"))
}

#[tokio::test]
#[ignore = "requires root"]
async fn test_create_netns_produces_a_distinct_pinned_namespace() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = tmp.path();

    let host_ns = current_thread_ns_identity();
    let pin = create_netns(run_dir, "test1").await.unwrap();
    assert!(pin.is_file(), "pin file must exist");

    let pinned_ns = ns_identity(&pin);
    assert_ne!(host_ns, pinned_ns, "pinned netns must be a genuinely new namespace, not the host's");

    teardown_netns(run_dir, "test1").unwrap();
    assert!(!pin.exists(), "teardown must remove the pin file");
}

// `block_in_place` (used below) panics unless the runtime is explicitly
// the multi-threaded flavor — `#[tokio::test]` alone defaults to the
// single-threaded `current_thread` runtime regardless of which tokio
// features are enabled on the crate (confirmed empirically: the plan's
// assumption that `#[tokio::test]` is "multi-threaded by default with
// the macros + rt-multi-thread features" does not hold; the flavor must
// be requested explicitly).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root"]
async fn test_nsenter_runs_closure_inside_pinned_namespace_and_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = tmp.path();
    let pin = create_netns(run_dir, "test2").await.unwrap();
    let pinned_ns = ns_identity(&pin);
    let host_ns_before = current_thread_ns_identity();

    // nsenter's closure must run synchronously on one thread — wrap in
    // block_in_place per netns.rs's own documented contract, run inside
    // a #[tokio::test(flavor = "multi_thread")].
    let observed = tokio::task::block_in_place(|| nsenter(&pin, || Ok(current_thread_ns_identity())))
        .unwrap();
    assert_eq!(observed, pinned_ns, "closure must observe the target namespace, not the host's");

    let host_ns_after = current_thread_ns_identity();
    assert_eq!(host_ns_before, host_ns_after, "nsenter must restore the original namespace afterward");

    teardown_netns(run_dir, "test2").unwrap();
}
