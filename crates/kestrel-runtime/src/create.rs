// crates/kestrel-runtime/src/create.rs
//
//! `create` — the largest subcommand in this phase: builds the
//! `NamespacePlan` and `Bootstrap` payload from the loaded `Bundle`,
//! `mkfifo`s the exec FIFO at its host path, creates the dedicated
//! Phase-8 bootstrap socketpair, calls `run_stages` with a `child_action`
//! that blocks reading a go-ahead byte before `execve`ing into
//! `kestrel-init`, then (host-side, after `run_stages` returns) runs
//! `createRuntime` hooks and sends the go-ahead + `Bootstrap` payload (or
//! aborts by closing its socket end on hook failure), then writes the
//! `Created` state.json. See
//! docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md §1.
//!
//! ## Bundle rootfs handling (resolved design decision)
//!
//! `kestrel_init::mounts::stage_rootfs` (Task 5) unconditionally goes
//! through `Snapshotter::prepare_snapshot` + `mount_overlay` — kestrel's
//! whole rootfs mechanism is overlay/chain-id based, even for a plain OCI
//! bundle `create` (not just a kestrel-image pull). So a bundle's
//! `root.path()` directory is treated as a single synthetic layer: this
//! module computes a deterministic-per-container synthetic chain-id
//! (`bundle-<id>`, no content hashing — this is a one-off local creation,
//! not a dedup-sensitive pull), materializes it via
//! `LayerStore::ensure_layer`, and copies the bundle rootfs contents into
//! that layer's diff directory. `kestrel-init` then mounts it as the
//! (single) lower layer of an otherwise-ordinary overlay, same as any
//! image-pull-based container.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use kestrel_ns::pin::{pin_namespace, unpin_namespace};
use kestrel_ns::stages::run_stages;
use kestrel_ns::types::{IdMapping, NamespacePlan, NsType};
use kestrel_oci::bootstrap::{Bootstrap, HookSet, MountPlan};
use kestrel_oci::runtime::{Hook, LinuxNamespaceType, LinuxSeccomp, LinuxSeccompAction};
use kestrel_oci::state::{State, Status};

use crate::bundle::Bundle;

/// Fixed in-container path the exec FIFO is bind-mounted to by
/// `kestrel-init` (see Task 5's `mounts::stage_rootfs`) — `kestrel-init`
/// opens this path, post-`pivot_root`, to block until `start` unblocks it.
/// `create.rs`/`start.rs` themselves always operate on the HOST path
/// (`run_dir/<id>/exec.fifo`); this constant only ever travels inside the
/// `Bootstrap` payload for `kestrel-init`'s benefit.
const FIFO_CONTAINER_PATH: &str = "/.kestrel/exec.fifo";

pub fn create(id: &str, bundle: &Bundle, run_dir: &Path, data_dir: &Path) -> Result<()> {
    let state_json_path = crate::state::state_json_path(run_dir, id);
    let fifo_host_path = run_dir.join(id).join("exec.fifo");
    std::fs::create_dir_all(fifo_host_path.parent().unwrap()).with_context(|| {
        format!(
            "creating {}",
            fifo_host_path.parent().unwrap().display()
        )
    })?;
    nix::unistd::mkfifo(&fifo_host_path, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .context("mkfifo")?;

    // Write the Creating-status state.json BEFORE run_stages, so a crash
    // partway through create still leaves diagnosable evidence.
    let initial_state = State {
        oci_version: "1.0.2".to_string(),
        id: id.to_string(),
        status: Status::Creating,
        pid: None,
        bundle: bundle.path.clone(),
        annotations: Default::default(),
        exit_code: None,
    };
    initial_state.write_atomic(&state_json_path)?;

    let mount_plan = stage_bundle_rootfs_as_synthetic_layer(id, bundle, data_dir)?;

    let plan = build_namespace_plan(bundle)?;
    let cgroup = kestrel_cgroup::manager::CgroupManager::new(data_dir.join("cgroups"), id)?;
    cgroup.create()?;
    apply_resource_limits(&cgroup, bundle)?;

    // `run_stages`' `CLONE_INTO_CGROUP` fast path needs an open fd on the
    // cgroup's own directory (not a "dir_fd()" method — `CgroupManager`
    // has no such accessor; `crates/kestrel-cgroup/tests/integration.rs`'s
    // own `test_clone_into_cgroup_no_window` establishes the real pattern
    // this follows: a plain `File::open` on the cgroup path). Must stay
    // alive (not dropped) until after `run_stages` returns, since its
    // raw fd is what stage1 passes to `clone3(CLONE_INTO_CGROUP)`
    // internally — dropping it early would close the fd out from under
    // that call.
    let cgroup_dir = std::fs::File::open(&cgroup.path)
        .with_context(|| format!("opening cgroup dir {} for CLONE_INTO_CGROUP", cgroup.path.display()))?;

    // Dedicated Phase-8 socketpair — SOCK_STREAM, not SOCK_DGRAM/SEQPACKET.
    // `kestrel_oci::bootstrap`'s own module doc comment (and its
    // `send_bootstrap`/`recv_bootstrap` length-prefixed `read_exact`
    // framing) requires real byte-stream semantics: `Bootstrap`'s
    // serialized size is unbounded (embeds `Process`/`LinuxCapabilities`/
    // `LinuxSeccomp`/hook lists), so a single-recv-per-datagram socket
    // would desynchronize the length-prefix framing. No `SOCK_CLOEXEC` at
    // creation time: `init_end` must stay inheritable across
    // `child_action`'s later `execve` into kestrel-init.
    let (host_end, init_end) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
    .context("creating bootstrap socketpair")?;

    // `host_end` specifically (NOT `init_end`) gets `FD_CLOEXEC` set right
    // away. This is defense-in-depth for the SUCCESS path only: it stops
    // `host_end`'s fd from leaking (unused) across `child_action`'s
    // `execve` into `kestrel-init`.
    //
    // It does NOT, on its own, fix the hook-FAILURE hang below. `run_stages`
    // forks stage1/stage2 (which becomes `child_action`) well before
    // `execve` ever runs, and that forked child inherits its own live copy
    // of `host_end` at fork time regardless of CLOEXEC — CLOEXEC only
    // closes a fd *at exec*, and `child_action`'s blocking
    // `recv_go_ahead(init_end_raw)` read happens BEFORE any exec. So on the
    // hook-failure path (`drop(host_end)` below, no exec ever happens in
    // that child), the child's inherited copy would otherwise keep
    // `host_end`'s write side alive from the kernel's point of view even
    // after the PARENT drops its own copy, and the child's `read()` would
    // never observe EOF. The actual fix for that is the explicit
    // `nix::unistd::close(host_end_raw)` as the first action inside
    // `child_action`, below — CLOEXEC here is purely belt-and-suspenders
    // fd hygiene for the already-working success path.
    nix::fcntl::fcntl(
        host_end.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .context("setting FD_CLOEXEC on host_end")?;

    let bootstrap = build_bootstrap(id, bundle, mount_plan, &fifo_host_path, &state_json_path, run_dir)?;
    let init_end_raw = init_end.as_raw_fd();
    let host_end_raw = host_end.as_raw_fd();

    let child_action = move || {
        // Close OUR OWN inherited copy of host_end FIRST, before anything
        // else. `run_stages` forks this process (twice — stage1, then
        // stage2/this closure) before the host ever runs createRuntime
        // hooks, so this process ends up holding a live copy of host_end's
        // fd that it never touches or needs. If we don't close it, that
        // copy alone keeps the socket's write side referenced from the
        // kernel's perspective even after the PARENT (host) later
        // `drop`s/closes its own `host_end` on a hook-failure abort — each
        // process has its own fd table, so closing OUR copy here has no
        // effect on the parent's copy, but it DOES mean we stop holding a
        // reference to the write end ourselves. Once that's done, the
        // parent's own eventual close/drop of host_end is the LAST
        // reference, and `recv_go_ahead`'s blocking `read()` on `init_end`
        // (a different, unaffected fd — our own socket end) correctly
        // observes EOF instead of hanging forever. Must happen before
        // `recv_go_ahead` is called, not merely before the (possible)
        // later `execve` — CLOEXEC alone would only take effect at exec
        // time, which is too late (recv_go_ahead's blocking read happens
        // first).
        let _ = nix::unistd::close(host_end_raw);

        // Block reading — nothing sent yet means createRuntime hooks
        // haven't finished (or failed). This closure receives EOF/an
        // abort signal if hooks failed, or the real go-ahead + payload if
        // they succeeded — see the two branches below.
        match recv_go_ahead(init_end_raw) {
            Ok(true) => {
                // dup2 init_end onto the well-known BOOTSTRAP_FD kestrel-init expects.
                let _ = nix::unistd::dup2(init_end_raw, kestrel_init::bootstrap::BOOTSTRAP_FD);
                if let Ok(kestrel_init_path) = resolve_kestrel_init_path() {
                    let _ = nix::unistd::execv(
                        &kestrel_init_path,
                        std::slice::from_ref(&kestrel_init_path),
                    );
                }
                std::process::exit(127); // only reached if resolve/execv itself failed
            }
            _ => std::process::exit(1), // createRuntime hooks failed or aborted; never exec
        }
    };

    let stage_result = run_stages(&plan, Some(cgroup_dir.as_raw_fd()), child_action)?;
    drop(cgroup_dir);

    // Host side: run createRuntime hooks now, THEN send the go-ahead +
    // bootstrap payload (or signal failure).
    let hook_result = kestrel_oci::hooks::run_hooks(&bundle_create_runtime_hooks(bundle), &[]);
    match hook_result {
        Ok(()) => {
            send_go_ahead_and_bootstrap(host_end.as_raw_fd(), &bootstrap)?;
        }
        Err(e) => {
            // Close host_end without sending anything — child_action's
            // blocking read observes this as EOF and exits without
            // execing. Surface the real hook error to the caller.
            drop(host_end);
            anyhow::bail!("createRuntime hooks failed: {e}");
        }
    }

    // Pin every namespace this container created onto a stable path under
    // `run_dir/<id>/ns/<type>`, per SPEC.md §4.4. Deliberately placed here
    // — after `run_stages` has returned a real, live `init_pid` AND after
    // createRuntime hooks have succeeded (i.e. the container has genuinely
    // started, not aborted) — rather than immediately after `run_stages`
    // returns. Pinning an about-to-be-aborted container's namespaces would
    // create pin files with nothing meaningful depending on them, since a
    // hook-failure abort never lets the container run at all.
    pin_namespaces(run_dir, id, &plan, stage_result.init_pid)?;

    let mut state = State::read(&state_json_path)?;
    state.status = Status::Created;
    state.pid = Some(stage_result.init_pid.as_raw());
    state.write_atomic(&state_json_path)?;

    Ok(())
}

/// Gap-fix (found during Phase 9 Task 13's review): applies the bundle's
/// `linux.resources` (CPU shares/quota/cpuset, memory limit/reservation/
/// swap, pids limit, IO weight/throttle, hugetlb) — if present — to the
/// leaf cgroup `create()` just made, via the real, already-implemented
/// `kestrel_cgroup::resources::{apply_cpu,apply_memory,apply_pids,apply_io,
/// apply_hugetlb}` methods. Before this fix, `create()` created the cgroup
/// and enabled controllers but never read `linux.resources` back out of
/// the bundle at all — every resource limit configured in a bundle's
/// `config.json` (including `kestreld`'s own `POST /containers`
/// `memory_bytes`/`pids_limit` fields, which `kestreld::bundle` correctly
/// writes into `config.json`) was silently non-functional.
///
/// # Ordering: called here, BEFORE the container's process joins the
/// cgroup
///
/// This runs right after `cgroup.create()` and well before `run_stages`
/// (below) clones the container's `kestrel-init` process into the cgroup
/// via the `CLONE_INTO_CGROUP` fast path. cgroup v2 accepts writes to
/// `memory.max`/`cpu.max`/`pids.max`/etc. against an empty leaf cgroup with
/// zero processes in it — there is no rule requiring a cgroup to be
/// non-empty before its controller files can be configured. Applying limits
/// to the still-empty cgroup means they are already in effect the INSTANT
/// the process is cloned into it: no window, however small, where the
/// container's init process (or anything it execs into) runs unconstrained.
/// The alternative ordering — clone the process in first, apply limits
/// after — would leave exactly that window open for no benefit.
///
/// # No-op for the common case
///
/// A bundle with no `linux.resources` block at all short-circuits via the
/// `let-else` below. A `linux.resources` block whose sub-fields
/// (`cpu`/`memory`/`pids`/`blockIO`/`hugepageLimits`) are all absent is
/// likewise a no-op: every one of `apply_cpu`/`apply_memory`/`apply_pids`/
/// `apply_io`/`apply_hugetlb` already treats an absent sub-field as
/// "nothing to configure, write nothing" (see each function's own doc
/// comment in `kestrel_cgroup::resources`) — this function does not need to
/// (and does not) duplicate that presence-checking itself. So a container
/// that requests no resource limits behaves identically to before this fix.
fn apply_resource_limits(cgroup: &kestrel_cgroup::manager::CgroupManager, bundle: &Bundle) -> Result<()> {
    let Some(resources) = bundle
        .spec
        .spec
        .linux()
        .as_ref()
        .and_then(|l| l.resources().as_ref())
    else {
        return Ok(());
    };

    cgroup
        .apply_cpu(resources)
        .context("applying cpu resource limits to the container's cgroup")?;
    cgroup
        .apply_memory(resources)
        .context("applying memory resource limits to the container's cgroup")?;
    cgroup
        .apply_pids(resources)
        .context("applying pids resource limit to the container's cgroup")?;
    cgroup
        .apply_io(resources)
        .context("applying io resource limits to the container's cgroup")?;
    cgroup
        .apply_hugetlb(resources)
        .context("applying hugetlb resource limits to the container's cgroup")?;
    Ok(())
}

/// Annotation key `kestreld` writes into a bundle's `config.json` before
/// calling `create()` for a container built from already-pulled,
/// content-addressed image layers (Phase 9's whole reason for existing —
/// see docs/superpowers/specs/2026-08-09-phase9-daemon-design.md §4b).
/// Its value is a comma-joined, bottom-to-top list of layer chain-ids that
/// already exist in the `LayerStore` rooted at `data_dir`.
const LOWER_CHAIN_IDS_ANNOTATION: &str = "kestrel.lowerChainIds";

/// Resolution #1: a bundle's `root.path()` directory becomes a single
/// synthetic overlay layer, keyed by a deterministic-per-container
/// (not content-hashed) chain-id. Returns the `MountPlan` `kestrel-init`
/// needs to mount it.
///
/// Gap-fill (Phase 9 Task 3): checked FIRST, before any of the above, is
/// a fast path for bundles `kestreld` materializes directly from
/// already-pulled layers. `Snapshotter::prepare_snapshot` (called later,
/// inside `kestrel-init`, from `MountPlan.lower_chain_ids`) already
/// accepts an arbitrary multi-entry chain-id list with no length
/// restriction — the only real gap was HERE: this function unconditionally
/// treated the bundle as exactly one new synthetic layer via a full
/// recursive copy, with no way to say "reuse these chain-ids as-is". When
/// the `kestrel.lowerChainIds` annotation is present, this returns
/// immediately with a `MountPlan` built directly from it — no
/// `LayerStore::ensure_layer`, no copy, and critically, no read of
/// `bundle.path.join(root.path())` at all (that whole path, including the
/// `root()` lookup itself, is only reached in the fallback below), so a
/// `kestreld`-materialized bundle need not even have a `rootfs/` directory
/// on disk.
fn stage_bundle_rootfs_as_synthetic_layer(
    id: &str,
    bundle: &Bundle,
    data_dir: &Path,
) -> Result<MountPlan> {
    // `Spec::annotations()` -> `&Option<HashMap<String, String>>`
    // (confirmed against the vendored oci-spec-0.10.0 source: `Spec`
    // carries `#[getset(get = "pub")]`, and its `annotations` field is
    // `Option<HashMap<String, String>>`). This value survives
    // `bundle::load` completely unfiltered — `RawSpec`'s
    // `#[serde(flatten)] spec: Spec` (crates/kestrel-oci/src/raw.rs)
    // deserializes it like any other real `Spec` field, no special-casing
    // needed.
    if let Some(annotations) = bundle.spec.spec.annotations() {
        if let Some(csv) = annotations.get(LOWER_CHAIN_IDS_ANNOTATION) {
            // Checked on `csv` itself, BEFORE splitting: `str::split`
            // always yields at least one element for any input (including
            // `""`, which splits to `[""]`), so a post-split
            // `!lower_chain_ids.is_empty()` check could never actually
            // trigger — this is the check that does.
            anyhow::ensure!(
                !csv.trim().is_empty(),
                "{LOWER_CHAIN_IDS_ANNOTATION} annotation is present but empty"
            );
            let lower_chain_ids: Vec<String> = csv.split(',').map(str::to_string).collect();
            return Ok(MountPlan {
                lower_chain_ids,
                // Hardcoded `false`, matching the fallback synthetic-layer
                // branch below exactly — no regression either way versus
                // today's behavior. `kestreld` (this phase) has no
                // rootless story yet (see design doc §14, "out of scope
                // for this phase"), so this is deliberately NOT wired to
                // the annotation any further here; whoever adds rootless
                // support later will need a second annotation (or to
                // extend this one) to drive this field for real.
                rootless: false,
            });
        }
    }

    let root = bundle
        .spec
        .spec
        .root()
        .as_ref()
        .context("bundle config.json has no root (validate() should have caught this)")?;
    let bundle_rootfs = bundle.path.join(root.path());

    let synthetic_chain_id = format!("bundle-{id}");
    let layer_store = kestrel_rootfs::snapshot::LayerStore::new(data_dir.to_path_buf());
    let diff_dir = layer_store
        .ensure_layer(&synthetic_chain_id, None)
        .context("ensure_layer for bundle rootfs")?;

    copy_dir_recursive(&bundle_rootfs, &diff_dir).with_context(|| {
        format!(
            "copying bundle rootfs {} into layer diff {}",
            bundle_rootfs.display(),
            diff_dir.display()
        )
    })?;

    Ok(MountPlan {
        lower_chain_ids: vec![synthetic_chain_id],
        rootless: false,
    })
}

/// Plain recursive copy (directories, regular files, symlinks) — no
/// precedent in this codebase for shelling out to `cp -a` (checked
/// `kestrel-rootfs`'s `copyup.rs`/`bindmount.rs` and the rest of the
/// workspace), so this is a small hand-rolled walk instead. Special files
/// (device nodes, fifos, sockets) inside a bundle rootfs are rare and are
/// deliberately skipped rather than mis-copied as regular files — a real
/// device node would need `mknod`, not `fs::copy`.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry.with_context(|| format!("reading directory entry in {}", src.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type of {}", entry.path().display()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_symlink() {
            let target = std::fs::read_link(&src_path)
                .with_context(|| format!("reading symlink {}", src_path.display()))?;
            std::os::unix::fs::symlink(&target, &dst_path)
                .with_context(|| format!("creating symlink {}", dst_path.display()))?;
        } else if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path)
                .with_context(|| format!("creating directory {}", dst_path.display()))?;
            copy_dir_recursive(&src_path, &dst_path)?;
            let meta = std::fs::symlink_metadata(&src_path)
                .with_context(|| format!("reading metadata of {}", src_path.display()))?;
            std::fs::set_permissions(&dst_path, meta.permissions())
                .with_context(|| format!("setting permissions on {}", dst_path.display()))?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)
                .with_context(|| format!("copying {} to {}", src_path.display(), dst_path.display()))?;
        }
        // else: device/fifo/socket — skipped, see doc comment above.
    }
    Ok(())
}

/// Resolution #2: translate `bundle.spec.spec.linux()`'s namespaces +
/// id mappings into a real `NamespacePlan`. Namespaces with a non-`None`
/// `.path()` (join-an-existing-namespace, e.g. a `container:<id>`- or
/// bridge-mode-netns-equivalent case) are routed into `plan.join` rather
/// than `plan.create` — `kestrel_ns::stages::stage1` performs the actual
/// `setns()` for each of those (gap-fill, Phase 9 Task 4; see
/// `docs/superpowers/specs/2026-08-09-phase9-daemon-design.md` §4a for the
/// full rationale, including why the join must happen before any
/// `unshare()`, in particular before `CLONE_NEWUSER`).
pub(crate) fn build_namespace_plan(bundle: &Bundle) -> Result<NamespacePlan> {
    let mut create = Vec::new();
    let mut join = Vec::new();
    let mut uid_maps = Vec::new();
    let mut gid_maps = Vec::new();

    if let Some(linux) = bundle.spec.spec.linux() {
        if let Some(namespaces) = linux.namespaces() {
            for ns in namespaces {
                if let Some(path) = ns.path() {
                    join.push((map_ns_type(ns.typ()), path.clone()));
                    continue;
                }
                create.push(map_ns_type(ns.typ()));
            }
        }
        if let Some(uids) = linux.uid_mappings() {
            uid_maps = uids.iter().map(map_id_mapping).collect();
        }
        if let Some(gids) = linux.gid_mappings() {
            gid_maps = gids.iter().map(map_id_mapping).collect();
        }
    }

    Ok(NamespacePlan {
        create,
        join,
        uid_maps,
        gid_maps,
    })
}

/// Pins every namespace `plan.create` lists onto its stable, well-known
/// path — `run_dir/<id>/ns/<type.proc_name()>` — by bind-mounting
/// `/proc/<init_pid>/ns/<type>` there (`kestrel_ns::pin::pin_namespace`).
/// This is exactly SPEC.md §4.4's convention, and is what gives
/// `kestrel exec` a stable `setns` target and `kestrel delete` a real
/// handle to unmount/tear down, even after `kestrel-init` (the process
/// that originally created these namespaces) eventually exits.
///
/// `init_pid` must already be a real, live pid whose `/proc/<pid>/ns/*`
/// entries are the container's actual namespaces — i.e. this must only be
/// called after `run_stages` has returned successfully.
///
/// An empty `plan.create` (e.g. a namespace-less test spec) is a no-op:
/// no `ns/` directory is even created, since there is nothing to pin.
///
/// # Error handling: all-or-nothing, not best-effort — with ONE narrow,
/// environment-specific exception
///
/// If pinning namespace type N succeeds but type N+1 fails partway
/// through the loop, every namespace already pinned earlier in *this
/// call* is unpinned again before returning the error. A partially-pinned
/// container is worse than an unpinned one: later code (`exec`, `delete`)
/// has no way to distinguish "this namespace type was never in the
/// plan" from "it was in the plan but pinning silently failed", so it
/// would only discover the gap when it specifically tries to use the one
/// missing type — a confusing, delayed failure instead of a clear,
/// immediate `create()` error. Failing `create()` outright here (this
/// function's `Err` propagates straight out of `create()` via `?`) is
/// deliberate: a missing pin is a real functionality gap for two
/// not-yet-built features that depend on it, not something to silently
/// tolerate.
///
/// **The one exception**: a pin failure for `NsType::Mount` specifically,
/// where the underlying error is `EINVAL`, is tolerated — logged via
/// `tracing::warn!` and skipped, WITHOUT rolling back or failing the rest
/// of the call. This is not a general "pinning is optional" policy; it
/// exists solely because of a real, independently-verified, non-kestrel
/// limitation of this project's dev Lima VM (Ubuntu 24.04, kernel 6.8.0,
/// aarch64/vz): `mount(2)` with `MS_BIND` on `/proc/<pid>/ns/mnt` ALWAYS
/// fails with `EINVAL` in this VM, while the identical bind-mount
/// operation succeeds for every other namespace type of the same
/// process, and CREATING a fresh Mount namespace (`run_stages`/`clone`/
/// `unshare`) works completely fine — only the later, separate PINNING
/// step fails. See `crates/kestrel-ns/tests/join.rs`'s top-of-file
/// comment for the independent verification (`crates/kestrel-ns/tests/pin.rs`
/// exercises Mount-namespace creation via `run_stages` but never attempts
/// to pin it, so it doesn't itself corroborate the EINVAL signature — the
/// corroboration lives in `join.rs` and this crate's own
/// `create_pins_namespaces.rs`). On a real target Linux host (i.e. anywhere outside this
/// dev VM), Mount pinning is expected to succeed normally like every
/// other type, and this fallback path is expected to simply never
/// trigger.
///
/// The check is narrowed to `EINVAL` specifically (not "any error for
/// `NsType::Mount`") on purpose: a genuine, different-cause Mount pin
/// failure (e.g. a real permissions problem, or the pin target's parent
/// directory being missing) must still trigger the full rollback-and-fail
/// behavior like any other namespace type — only the exact, known
/// EINVAL-on-Mount signature this VM produces is tolerated.
///
/// The practical consequence of hitting this fallback: `kestrel exec`
/// cannot join this container's actual mount namespace/rootfs view in
/// this environment. `exec_cmd.rs` already handles this gracefully — a
/// namespace that was planned but never successfully pinned (for any
/// reason) is simply absent from `pins`, and `join_namespaces` skips it.
fn pin_namespaces(run_dir: &Path, id: &str, plan: &NamespacePlan, init_pid: nix::unistd::Pid) -> Result<()> {
    if plan.create.is_empty() {
        return Ok(());
    }

    let ns_dir = run_dir.join(id).join("ns");
    std::fs::create_dir_all(&ns_dir).with_context(|| format!("creating {}", ns_dir.display()))?;

    let mut pinned_so_far: Vec<PathBuf> = Vec::new();
    for &ns_type in &plan.create {
        let target = ns_dir.join(ns_type.proc_name());
        if let Err(e) = pin_namespace(init_pid, ns_type, &target) {
            if ns_type == NsType::Mount && is_known_mount_pin_einval(&e) {
                // See this function's doc comment ("The one exception").
                // Not rolled back, not fatal: nothing was actually pinned
                // for this type (pin_namespace already cleaned up its own
                // stray target file on failure), so there is nothing to
                // undo, and the rest of the loop proceeds normally.
                tracing::warn!(
                    error = %e,
                    container_id = id,
                    "pinning the Mount namespace failed with EINVAL, matching this dev Lima \
                     VM's known, independently-verified bind-mount-on-mnt-namespace \
                     limitation (see crates/kestrel-ns/tests/join.rs's top-of-file comment) \
                     rather than a genuine bug; tolerating \
                     this one pin failure instead of failing create() outright. Consequence: \
                     `kestrel exec` will not be able to join this container's actual mount \
                     namespace/rootfs view in this environment. On a real target Linux host \
                     this fallback is not expected to trigger."
                );
                continue;
            }
            // Roll back everything this call already pinned, so a failure
            // here never leaves a partially-pinned container behind (see
            // this function's doc comment for why that matters).
            for already_pinned in &pinned_so_far {
                if let Err(unpin_err) = unpin_namespace(already_pinned) {
                    tracing::error!(
                        error = %unpin_err,
                        path = %already_pinned.display(),
                        "failed to roll back a previously-pinned namespace after a later \
                         pin_namespace call failed; this pin file may be left behind"
                    );
                }
            }
            return Err(e).with_context(|| {
                format!(
                    "pinning {ns_type:?} namespace for container {id} failed ({} \
                     previously-pinned namespace(s) in this call were rolled back)",
                    pinned_so_far.len()
                )
            });
        }
        pinned_so_far.push(target);
    }

    Ok(())
}

/// Narrow, deliberately-scoped check for the ONE tolerated failure mode
/// described in [`pin_namespaces`]'s doc comment: does `e`'s error chain
/// contain the specific `EINVAL` errno this dev Lima VM's Mount-namespace
/// bind-mount limitation always produces? Matches `delete.rs`'s own
/// `is_ignorable_unmount_error`/`is_ignorable_not_found_error` convention
/// of downcasting through an `anyhow::Context`-wrapped error chain to the
/// real underlying `nix::errno::Errno` rather than string-matching the
/// formatted message.
fn is_known_mount_pin_einval(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<nix::errno::Errno>(), Some(nix::errno::Errno::EINVAL))
}

/// All 8 `LinuxNamespaceType` variants map onto `NsType`, one name
/// difference: oci_spec's `Network` <-> kestrel_ns's `Net`.
fn map_ns_type(typ: LinuxNamespaceType) -> NsType {
    match typ {
        LinuxNamespaceType::Mount => NsType::Mount,
        LinuxNamespaceType::Cgroup => NsType::Cgroup,
        LinuxNamespaceType::Uts => NsType::Uts,
        LinuxNamespaceType::Ipc => NsType::Ipc,
        LinuxNamespaceType::User => NsType::User,
        LinuxNamespaceType::Pid => NsType::Pid,
        LinuxNamespaceType::Network => NsType::Net,
        LinuxNamespaceType::Time => NsType::Time,
    }
}

fn map_id_mapping(m: &kestrel_oci::runtime::LinuxIdMapping) -> IdMapping {
    IdMapping {
        container_id: m.container_id(),
        host_id: m.host_id(),
        size: m.size(),
    }
}

/// Resolution #3: construct the `Bootstrap` payload from the loaded
/// bundle + the resolved `MountPlan`. `capabilities` lives on
/// `Process` in the real `oci_spec` schema, NOT on `Linux` — the
/// dispatch's own draft cited `.linux().and_then(|l| l.capabilities())`,
/// which does not exist on the real vendored `Linux` struct (confirmed:
/// `Linux` has no `capabilities` field at all); `LinuxCapabilities` is a
/// `Process` field (`process.capabilities() -> &Option<LinuxCapabilities>`)
/// per the real vendored source. Corrected here.
fn build_bootstrap(
    id: &str,
    bundle: &Bundle,
    mount_plan: MountPlan,
    fifo_host_path: &Path,
    state_json_path: &Path,
    run_dir: &Path,
) -> Result<Bootstrap> {
    let spec = &bundle.spec.spec;

    let process = spec
        .process()
        .clone()
        .context("bundle config.json has no process (validate() should have caught this)")?;
    let capabilities = process.capabilities().clone();
    let seccomp = spec.linux().as_ref().and_then(|l| l.seccomp().clone());
    let hostname = spec.hostname().clone();

    let hooks = spec.hooks().as_ref();
    let create_container = hooks
        .and_then(|h| h.create_container().clone())
        .unwrap_or_default();
    let start_container = hooks
        .and_then(|h| h.start_container().clone())
        .unwrap_or_default();

    // Phase 9 Task 16: only set when the profile genuinely uses
    // `SCMP_ACT_NOTIFY` somewhere — mirrors `kestrel_security::seccomp::
    // install_seccomp`'s own `uses_notify` check exactly (default action OR
    // any per-syscall rule action), duplicated here (not imported) because
    // this check needs no `libseccomp` translation at all, just the raw
    // `kestrel_oci::runtime::LinuxSeccompAction` values already on hand.
    // `<run_dir>/<id>/seccomp.sock` matches `kestrel-shim`'s own listener
    // path (design doc §7) exactly — `kestrel-shim` binds it unconditionally
    // right after `create` succeeds, well before `start` (a separate, later
    // call) ever triggers this fd-send, so there's no ordering race.
    let seccomp_notify_sink = seccomp
        .as_ref()
        .filter(|s| uses_seccomp_notify(s))
        .map(|_| run_dir.join(id).join("seccomp.sock"));

    Ok(Bootstrap {
        container_id: id.to_string(),
        mount_plan,
        process,
        capabilities,
        seccomp,
        hooks: HookSet {
            create_container,
            start_container,
        },
        hostname,
        // This phase's config.json-driven bundles don't carry an explicit
        // time-namespace-offsets source anywhere in oci_spec's `Spec` —
        // it's a narrower OCI feature (`/proc/[pid]/timens_offsets`, set
        // out-of-band by a runtime that wants a container's clocks to
        // read differently from the host's), and no real, populated
        // source for it exists in this bundle-loading path. Empty Vec
        // (no offsets applied) is the honest, defensible default rather
        // than inventing a fake source.
        timens_offsets: Vec::new(),
        fifo_host_path: fifo_host_path.to_path_buf(),
        fifo_container_path: PathBuf::from(FIFO_CONTAINER_PATH),
        state_json_path: state_json_path.to_path_buf(),
        seccomp_notify_sink,
    })
}

/// Whether `profile` uses `SCMP_ACT_NOTIFY` anywhere — either as the
/// filter's default action or on any individual syscall rule. Mirrors
/// `kestrel_security::seccomp::install_seccomp`'s own `uses_notify`
/// computation exactly (that function's own doc comment: "Returns
/// `Some(fd)` if the profile uses SCMP_ACT_NOTIFY anywhere"), so
/// `seccomp_notify_sink` is set here if and only if `install_seccomp`
/// (called later, inside the container, by `kestrel-init`'s `exec_into`)
/// will actually return `Some(fd)` for this same profile.
fn uses_seccomp_notify(profile: &LinuxSeccomp) -> bool {
    matches!(profile.default_action(), LinuxSeccompAction::ScmpActNotify)
        || profile
            .syscalls()
            .iter()
            .flatten()
            .any(|rule| matches!(rule.action(), LinuxSeccompAction::ScmpActNotify))
}

/// Resolution #4: the go-ahead is a trivial 1-byte protocol over the SAME
/// `SOCK_STREAM` socket, sent/received BEFORE the `Bootstrap` payload
/// itself. Reads exactly 1 byte, blocking; `Ok(0)` (EOF — the host
/// closed its end without writing, i.e. `createRuntime` hooks failed) is
/// distinguished from a real error, per `std::io::Read::read`'s contract
/// (unlike `read_exact`, which can't tell "peer closed cleanly before any
/// byte arrived" apart from "short read due to a real I/O error" on its
/// own).
fn recv_go_ahead(fd: RawFd) -> Result<bool> {
    // SAFETY-equivalent note (matching `kestrel_oci::bootstrap`'s own
    // established pattern): this fd is "borrowed, not owned" — it must
    // stay open for the later `dup2`/`execv` in `child_action`, so the
    // `File` wrapper's own `Drop` (a real `close(2)`) must never run.
    // `mem::forget` is how that's expressed without a `BorrowedFd`.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = [0u8; 1];
    let n = file.read(&mut buf).context("reading go-ahead byte");
    std::mem::forget(file);
    let n = n?;
    if n == 0 {
        // Clean EOF: create.rs aborted (createRuntime hooks failed) and
        // closed its end without writing anything.
        return Ok(false);
    }
    Ok(buf[0] == 0x01)
}

fn send_go_ahead_and_bootstrap(fd: RawFd, bootstrap: &Bootstrap) -> Result<()> {
    use std::io::Write;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = file.write_all(&[0x01]).context("writing go-ahead byte");
    std::mem::forget(file);
    result?;
    kestrel_oci::bootstrap::send_bootstrap(fd, bootstrap)
}

/// Resolution #5: `kestrel-runtime`'s own currently-running binary path,
/// sibling-binary convention (matching Phase 6's `kestrel-net`/
/// `netns-helper` pairing — installed binaries live next to each other).
fn resolve_kestrel_init_path() -> Result<CString> {
    let current_exe = std::env::current_exe().context("resolving current_exe")?;
    let parent = current_exe
        .parent()
        .with_context(|| format!("{} has no parent directory", current_exe.display()))?;
    let path = parent.join("kestrel-init");
    let path_str = path
        .to_str()
        .with_context(|| format!("kestrel-init path {} is not valid UTF-8", path.display()))?;
    CString::new(path_str)
        .with_context(|| format!("kestrel-init path {path_str:?} contains a NUL byte"))
}

/// Resolution #6: `createRuntime` hooks, extracted from the bundle spec.
fn bundle_create_runtime_hooks(bundle: &Bundle) -> Vec<Hook> {
    bundle
        .spec
        .spec
        .hooks()
        .as_ref()
        .and_then(|h| h.create_runtime().clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::raw::RawSpec;
    use kestrel_oci::runtime::{
        LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
        ProcessBuilder, RootBuilder, SpecBuilder,
    };

    fn bundle_with_spec(spec: kestrel_oci::runtime::Spec) -> Bundle {
        Bundle {
            path: PathBuf::from("/nonexistent/bundle"),
            spec: RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        }
    }

    fn minimal_spec() -> kestrel_oci::runtime::Spec {
        SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build().unwrap())
            .process(ProcessBuilder::default().args(vec!["sh".into()]).build().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn test_build_namespace_plan_with_no_linux_section_is_empty() {
        // `SpecBuilder::default()`'s unset `linux` field is NOT `None` —
        // it falls back to `Spec::default()`'s own value, which is
        // `Some(Linux::default())` carrying oci_spec's own 6 default
        // namespaces (Pid/Network/Ipc/Uts/Mount/Cgroup, no User/Time).
        // Verified empirically against the real vendored builder before
        // writing this test: a *bundle-provided* `config.json` genuinely
        // omitting `linux` entirely is exercised via `set_linux(None)`
        // explicitly, matching the same pattern `validate.rs`'s own
        // tests use (`s.set_root(None)`) — the builder's own default
        // fallback is a separate, already-covered case (see
        // `test_build_namespace_plan_translates_all_namespace_types` and
        // friends, which all start from an explicit `LinuxBuilder`).
        let mut spec = minimal_spec();
        spec.set_linux(None);
        let bundle = bundle_with_spec(spec);
        let plan = build_namespace_plan(&bundle).unwrap();
        assert!(plan.create.is_empty());
        assert!(plan.uid_maps.is_empty());
        assert!(plan.gid_maps.is_empty());
    }

    #[test]
    fn test_build_namespace_plan_translates_all_namespace_types() {
        let mut spec = minimal_spec();

        let ns_types = [
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Cgroup,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::User,
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Time,
        ];
        let namespaces: Vec<_> = ns_types
            .iter()
            .map(|t| LinuxNamespaceBuilder::default().typ(*t).build().unwrap())
            .collect();

        let uid_mapping = LinuxIdMappingBuilder::default()
            .host_id(1000u32)
            .container_id(0u32)
            .size(1u32)
            .build()
            .unwrap();
        let gid_mapping = LinuxIdMappingBuilder::default()
            .host_id(2000u32)
            .container_id(0u32)
            .size(1u32)
            .build()
            .unwrap();

        let linux = LinuxBuilder::default()
            .namespaces(namespaces)
            .uid_mappings(vec![uid_mapping])
            .gid_mappings(vec![gid_mapping])
            .build()
            .unwrap();
        spec.set_linux(Some(linux));

        let bundle = bundle_with_spec(spec);
        let plan = build_namespace_plan(&bundle).unwrap();

        assert_eq!(
            plan.create,
            vec![
                NsType::Mount,
                NsType::Cgroup,
                NsType::Uts,
                NsType::Ipc,
                NsType::User,
                NsType::Pid,
                NsType::Net,
                NsType::Time,
            ]
        );
        assert_eq!(
            plan.uid_maps,
            vec![IdMapping {
                container_id: 0,
                host_id: 1000,
                size: 1
            }]
        );
        assert_eq!(
            plan.gid_maps,
            vec![IdMapping {
                container_id: 0,
                host_id: 2000,
                size: 1
            }]
        );
    }

    #[test]
    fn test_build_namespace_plan_routes_join_path_namespaces_into_plan_join() {
        let mut spec = minimal_spec();

        let fresh_pid_ns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Pid)
            .build()
            .unwrap();
        let joined_net_ns = LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Network)
            .path("/var/run/netns/existing")
            .build()
            .unwrap();

        let linux = LinuxBuilder::default()
            .namespaces(vec![fresh_pid_ns, joined_net_ns])
            .build()
            .unwrap();
        spec.set_linux(Some(linux));

        let bundle = bundle_with_spec(spec);
        let plan = build_namespace_plan(&bundle).unwrap();

        // The namespace WITHOUT a `path` (create fresh) goes into
        // `plan.create`; the one WITH a `path` (join an existing
        // namespace) is routed into `plan.join` instead of being
        // silently dropped — see this function's own doc comment.
        assert_eq!(plan.create, vec![NsType::Pid]);
        assert_eq!(
            plan.join,
            vec![(NsType::Net, PathBuf::from("/var/run/netns/existing"))]
        );
    }

    #[test]
    fn test_build_namespace_plan_preserves_namespace_order() {
        let mut spec = minimal_spec();
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()
                .unwrap(),
        ];
        let linux = LinuxBuilder::default().namespaces(namespaces).build().unwrap();
        spec.set_linux(Some(linux));

        let bundle = bundle_with_spec(spec);
        let plan = build_namespace_plan(&bundle).unwrap();

        assert_eq!(plan.create, vec![NsType::Uts, NsType::Mount, NsType::Ipc]);
    }

    #[test]
    fn test_bundle_create_runtime_hooks_extracts_and_defaults_to_empty() {
        let bundle = bundle_with_spec(minimal_spec());
        assert!(bundle_create_runtime_hooks(&bundle).is_empty());
    }

    #[test]
    fn test_stage_bundle_rootfs_fast_path_uses_annotation_without_touching_bundle_path() {
        let mut spec = minimal_spec();
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(
            LOWER_CHAIN_IDS_ANNOTATION.to_string(),
            "sha256:aaa,sha256:bbb".to_string(),
        );
        spec.set_annotations(Some(annotations));

        // `path` deliberately points at a directory that does not exist at
        // all — the real proof that the fast path never reads
        // `bundle.path.join(root.path())`: if it did, this would fail with
        // an I/O error instead of returning `Ok`.
        let bundle = Bundle {
            path: PathBuf::from("/nonexistent/bundle-for-fast-path-unit-test"),
            spec: RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        };
        let data_dir = tempfile::tempdir().unwrap();

        let plan = stage_bundle_rootfs_as_synthetic_layer("fast-path-id", &bundle, data_dir.path())
            .expect("fast path must succeed without ever touching bundle.path");

        assert_eq!(
            plan.lower_chain_ids,
            vec!["sha256:aaa".to_string(), "sha256:bbb".to_string()]
        );
        assert!(
            !plan.rootless,
            "rootless is deliberately hardcoded false, matching the fallback branch"
        );
    }

    #[test]
    fn test_stage_bundle_rootfs_fast_path_rejects_empty_annotation() {
        let mut spec = minimal_spec();
        let mut annotations = std::collections::HashMap::new();
        annotations.insert(LOWER_CHAIN_IDS_ANNOTATION.to_string(), "".to_string());
        spec.set_annotations(Some(annotations));
        let bundle = bundle_with_spec(spec);
        let data_dir = tempfile::tempdir().unwrap();

        let err = stage_bundle_rootfs_as_synthetic_layer("id", &bundle, data_dir.path())
            .expect_err("an empty annotation value must be rejected, not silently treated as zero layers");
        assert!(
            format!("{err:#}").contains("annotation is present but empty"),
            "unexpected error message: {err:#}"
        );
    }

    #[test]
    fn test_stage_bundle_rootfs_falls_back_to_synthetic_copy_without_annotation() {
        let bundle_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(bundle_dir.path().join("rootfs")).unwrap();
        std::fs::write(bundle_dir.path().join("rootfs").join("marker"), b"hi").unwrap();

        // No annotations set at all — must take the pre-existing
        // synthetic-single-layer copy path exactly as before this task.
        let spec = minimal_spec();
        let bundle = Bundle {
            path: bundle_dir.path().to_path_buf(),
            spec: RawSpec {
                spec,
                extra: serde_json::Map::new(),
            },
        };
        let data_dir = tempfile::tempdir().unwrap();

        let plan = stage_bundle_rootfs_as_synthetic_layer("fallback-id", &bundle, data_dir.path())
            .expect("fallback synthetic-layer path must still work");

        assert_eq!(plan.lower_chain_ids, vec!["bundle-fallback-id".to_string()]);
        assert!(!plan.rootless);
        // `LayerStore::diff_dir` (not a hand-built path): the on-disk
        // directory name is `sanitize_chain_id`-sanitized (e.g. `-` ->
        // `_`), a private implementation detail of `kestrel_rootfs` that
        // this test must not re-derive by hand.
        let copied = kestrel_rootfs::snapshot::LayerStore::new(data_dir.path().to_path_buf())
            .diff_dir("bundle-fallback-id")
            .join("marker");
        assert!(
            copied.exists(),
            "fallback path must still copy the bundle rootfs into the layer diff dir"
        );
    }

    #[test]
    fn test_is_known_mount_pin_einval_accepts_only_einval() {
        // Same convention as `delete.rs`'s `is_ignorable_unmount_error`/
        // `is_ignorable_not_found_error` tests: prove the downcast
        // correctly narrows to EINVAL specifically, both through a plain
        // `anyhow::Error::new(Errno)` and through the SAME
        // `.with_context()`-wrapped shape `pin_namespace` itself actually
        // produces (context.rs's `Context` combinator, not a raw Errno),
        // so this doesn't silently regress if that wrapping ever changes.
        assert!(is_known_mount_pin_einval(&anyhow::Error::new(
            nix::errno::Errno::EINVAL
        )));
        assert!(!is_known_mount_pin_einval(&anyhow::Error::new(
            nix::errno::Errno::EPERM
        )));
        assert!(!is_known_mount_pin_einval(&anyhow::anyhow!(
            "some unrelated error"
        )));

        let wrapped: Result<()> =
            Err(nix::errno::Errno::EINVAL).context("bind-mounting /proc/1/ns/mnt onto /tmp/x");
        assert!(is_known_mount_pin_einval(&wrapped.unwrap_err()));

        let wrapped_other: Result<()> =
            Err(nix::errno::Errno::EACCES).context("bind-mounting /proc/1/ns/mnt onto /tmp/x");
        assert!(!is_known_mount_pin_einval(&wrapped_other.unwrap_err()));
    }

    #[test]
    #[ignore = "requires root"]
    fn test_pin_namespaces_rolls_back_on_a_genuine_non_mount_failure() {
        // Fault injection deliberately UNRELATED to the Mount/EINVAL
        // tolerance added to `pin_namespaces`: a directory is pre-created
        // at the `Net` pin's target path, so `pin_namespace`'s own
        // `fs::File::create(target)` step fails (a directory can't be
        // opened as a plain file) before `mount(2)` is ever reached — a
        // real, deterministic, environment-independent failure with
        // nothing to do with the Lima-VM Mount/EINVAL quirk. This proves
        // the ordinary all-or-nothing rollback-and-fail behavior is
        // completely untouched by the new Mount-specific exception: `Pid`
        // pins successfully first (needs real CAP_SYS_ADMIN, hence
        // root-gated), `Net` then fails for an unrelated reason, `Pid`'s
        // pin must be rolled back, and `Ipc` must never be attempted.
        let run_dir = tempfile::tempdir().unwrap();
        let id = "rollback-non-mount";
        let ns_dir = run_dir.path().join(id).join("ns");
        std::fs::create_dir_all(ns_dir.join(NsType::Net.proc_name()))
            .expect("pre-create a directory at Net's pin target to force a non-Mount failure");

        let plan = NamespacePlan {
            create: vec![NsType::Pid, NsType::Net, NsType::Ipc],
            join: Vec::new(),
            uid_maps: Vec::new(),
            gid_maps: Vec::new(),
        };

        let err = pin_namespaces(run_dir.path(), id, &plan, nix::unistd::getpid()).expect_err(
            "a pre-existing directory at the Net pin target must still fail, not be tolerated",
        );
        let msg = format!("{err:#}");
        assert!(msg.contains("Net"), "expected the failure to be about Net, got: {msg}");
        assert!(msg.contains("rolled back"), "expected the rollback message, got: {msg}");
        assert!(
            msg.contains("1 previously-pinned"),
            "expected exactly Pid's pin to have been rolled back, got: {msg}"
        );

        assert!(
            !ns_dir.join(NsType::Pid.proc_name()).exists(),
            "Pid's pin should have been rolled back after Net's unrelated failure"
        );
        assert!(
            !ns_dir.join(NsType::Ipc.proc_name()).exists(),
            "Ipc should never have been attempted after Net failed"
        );
    }

    #[test]
    fn test_pin_namespaces_with_empty_plan_is_a_no_op() {
        // No root/privilege needed: an empty `create` list must return
        // `Ok(())` without ever touching the filesystem (no `ns/`
        // directory, no bind-mount attempt) — the real, privileged
        // pinning path (`kestrel_ns::pin::pin_namespace`) is exercised
        // only by the root-gated integration test.
        let run_dir = tempfile::tempdir().unwrap();
        let plan = NamespacePlan::default();
        pin_namespaces(run_dir.path(), "empty-plan-container", &plan, nix::unistd::getpid())
            .expect("empty plan must not error");
        assert!(
            !run_dir.path().join("empty-plan-container").join("ns").exists(),
            "an empty namespace plan should not even create the ns/ directory"
        );
    }
}
