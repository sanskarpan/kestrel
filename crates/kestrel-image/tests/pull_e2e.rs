// crates/kestrel-image/tests/pull_e2e.rs
//
// Task 9's capstone: the first test in this whole project that composes
// Phase 6 (image pull) end to end with Phase 4 (rootfs/overlay/pivot_root)
// and Phase 5 (security/exec). Pulls a REAL small public image from Docker
// Hub, builds an OverlayFS snapshot from its actual layers, pivot_roots
// into it, and exec's a real binary from inside it via
// `kestrel_init::exec::exec_into`, asserting it exits 0.
//
// Doubly gated, on top of each other:
//   - `#[ignore]`, like every other root-gated test in this project — kept
//     out of a plain `cargo test`.
//   - The `KESTREL_TEST_NETWORK=1` opt-in env var, checked at the top of
//     the test function itself. `#[ignore]` alone is NOT enough here: this
//     project's `test-root` Makefile target runs
//     `cargo test --workspace -- --ignored --skip test_join_order_matters`
//     — i.e. it deliberately re-includes every `#[ignore]`d test in the
//     whole workspace (that's how kestrel-rootfs's and kestrel-security's
//     own root-gated capstones get exercised there). Nothing in that sweep
//     distinguishes "needs root" from "needs root AND the real internet",
//     and grepping the codebase turned up no existing convention for a
//     network-gated test (nothing else in this project hits a real
//     network) — so without a second, independent gate, `make test-root`
//     would silently start making real HTTPS calls to Docker Hub on every
//     invocation. This env var is Task 9's proposal for that convention;
//     `make test-root` itself is intentionally left unchanged (it still
//     passes `--ignored` workspace-wide) since this test's own early-return
//     below is what keeps it inert there, not a Makefile-level exclusion.
//
// Run explicitly (inside the Lima VM, which is required for this whole
// crate — see the Makefile's own top-of-file note):
//
//   limactl shell kestrel -- bash -lc 'cd /home/sanskar.guest/Container-Runtime && \
//     sudo -E KESTREL_TEST_NETWORK=1 $(command -v cargo || echo "$HOME/.cargo/bin/cargo") \
//     test -p kestrel-image --test pull_e2e -- --ignored --nocapture'

use std::path::PathBuf;

use kestrel_image::pull::pull_image;
use kestrel_image::reference;
use kestrel_image::store::ContentStore;
use kestrel_init::exec::exec_into;
use kestrel_oci::runtime::ProcessBuilder;
use kestrel_rootfs::mask::apply_default_masks;
use kestrel_rootfs::mounts::setup_standard_mounts;
use kestrel_rootfs::overlay::mount_overlay;
use kestrel_rootfs::pivot::pivot_root;
use kestrel_rootfs::snapshot::{LayerStore, Snapshotter};

#[path = "common/mod.rs"]
mod common;

/// `alpine:latest` — a few MB, single layer, busybox-based. Manually
/// verified (see Task 9's report) that its merged rootfs contains a real,
/// executable `/bin/true` — a busybox multi-call symlink whose target
/// (`bin/busybox`) is itself present in the same layer, not a shell
/// builtin or something that only resolves once a shell is already
/// running.
const IMAGE_REF: &str = "alpine:latest";
const EXEC_TARGET_ABS: &str = "/bin/true";
const EXEC_TARGET_REL: &str = "bin/true";

#[test]
#[ignore = "requires root and real network access to Docker Hub"]
fn test_pull_mount_pivot_exec_real_alpine_true() {
    if std::env::var_os("KESTREL_TEST_NETWORK").is_none() {
        eprintln!(
            "skipping test_pull_mount_pivot_exec_real_alpine_true: set KESTREL_TEST_NETWORK=1 to \
             actually run it (this test makes real HTTPS calls to Docker Hub — see this file's header \
             comment for why #[ignore] alone doesn't keep it out of `make test-root`'s `--ignored` sweep)"
        );
        return;
    }

    // `tmp` (the TempDir guard) is created HERE, in the real, un-forked
    // test process, and deliberately never moved into the closure below —
    // only plain-data clones of the path it resolves to are. Mirrors the
    // "parent owns the tempdir" discipline documented in
    // kestrel-init/tests/exec_via_kestrel_init.rs and
    // kestrel-security/tests/rlimits.rs: `exec_into`'s success path
    // replaces the forked child's process image entirely, so a `TempDir`
    // guard created inside that child would never run its `Drop`. Keeping
    // it out here means normal `TempDir::drop` cleanup runs when this
    // function returns, regardless of what happens inside the fork below
    // (including a panic partway through mount/pivot).
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_path_buf();

    let store = ContentStore::new(data_dir.clone());
    let layer_store = LayerStore::new(data_dir.clone());
    let reference = reference::parse(IMAGE_REF).expect("parse image reference");

    // Real network I/O: a plain async HTTP client, no root or namespace
    // tricks needed, so this happens entirely OUTSIDE run_isolated's fork
    // below — same "do the non-privileged, non-fork-sensitive work first"
    // shape as tests/exec_via_kestrel_init.rs's tempdir setup. The tokio
    // runtime driving it is explicitly shut down (not just left to drop at
    // scope-end) before the next statement's fork(): fork() only
    // duplicates the calling thread, and nothing in the forked child below
    // ever touches tokio, but tearing the runtime down first removes that
    // whole hazard class rather than relying on "the child never touches
    // it anyway".
    let chain_ids = {
        let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
        let result = rt.block_on(pull_image(&reference, &store, &layer_store, false, |_progress| {}));
        rt.shutdown_background();
        result.expect("pull_image against real Docker Hub")
    };
    assert!(!chain_ids.is_empty(), "pull must yield at least one chain-id");

    common::run_in_fresh_mount_ns(move || {
        let snapshotter = Snapshotter::new(data_dir.clone(), false);
        let snap = snapshotter.prepare_snapshot("c-pull-e2e", &chain_ids).expect("prepare_snapshot");
        mount_overlay(&data_dir, &snap, false, false, false).expect("mount_overlay");

        // Confirm the real exec target actually exists in the real,
        // pulled-and-extracted image BEFORE pivoting into it or trying to
        // exec it — this assertion fails loudly and points straight at
        // "the image doesn't have this binary at this path" instead of
        // producing an opaque post-pivot execve ENOENT buried inside
        // apply_all's error chain.
        let target_in_merged = snap.merged.join(EXEC_TARGET_REL);
        assert!(
            target_in_merged.is_file(),
            "{} must exist as a (possibly symlinked) regular file in the merged rootfs",
            target_in_merged.display()
        );

        let merged = snap.merged.clone();
        setup_standard_mounts(&merged).expect("setup_standard_mounts");
        apply_default_masks(&merged).expect("apply_default_masks");
        pivot_root(&merged).expect("pivot_root");

        let process = ProcessBuilder::default()
            .args(vec![EXEC_TARGET_ABS.to_string()])
            .cwd(PathBuf::from("/"))
            .build()
            .expect("build Process spec");

        // exec_into replaces THIS (already-forked, disposable) process's
        // image entirely with the real alpine /bin/true — its exit code IS
        // this whole test's result, observed by run_isolated's own waitpid
        // back in the real, un-forked parent process. Never returns on
        // success.
        let _ = exec_into(&process, None, None);
        unreachable!("exec_into only returns on failure");
    });

    // `tmp` drops here, in the real parent process — removing the content
    // store, layer store, and snapshot directories regardless of what
    // happened inside the forked child above. Any overlay/proc/sys/dev
    // mounts performed inside that child were confined to its own private,
    // unshared mount namespace (see common::run_in_fresh_mount_ns) and were
    // torn down for free by the kernel the moment that child process
    // exited — this parent process never entered that namespace, so there
    // is nothing left to unmount here.
}
