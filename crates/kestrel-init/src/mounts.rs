// crates/kestrel-init/src/mounts.rs

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kestrel_oci::bootstrap::Bootstrap;
use kestrel_rootfs::{mask, mounts, overlay, pivot, snapshot};

/// Stages the rootfs (overlay mount, standard mounts, masks, exec-FIFO
/// bind-mount) but does NOT pivot yet — the caller runs `createContainer`
/// hooks between this and [`pivot`], per the design's resolved (pre-pivot)
/// hook ordering (SPEC.md §9.3's hook table, confirmed authoritative over
/// CHECKLIST's terser paraphrase — see
/// docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md §1).
///
/// ## Why this makes `/` `MS_PRIVATE` (recursively) first
///
/// `kestrel_ns::stages::stage1` calls `unshare(CLONE_NEWNS)` (as part of
/// the plan's combined `unshare(rest)`) to give this process its own mount
/// namespace, but `unshare(CLONE_NEWNS)` on its own does NOT change that
/// new namespace's mount *propagation* type — every mount in it starts out
/// still peer-sharing (`MS_SHARED`) with the namespace it was cloned from
/// (the host's, typically shared by systemd), exactly like `pivot_root`'s
/// own step (1) doc comment already explains for the *later* pivot. Every
/// function this call chain goes on to invoke — `overlay::mount_overlay`,
/// `mounts::setup_standard_mounts`, `mask::apply_default_masks`,
/// `mounts::bind_mount_file` below — documents the same precondition
/// ("the caller must already be running inside its own unshared mount
/// namespace with that namespace's mount tree already made `MS_PRIVATE`
/// (recursively)") but deliberately does not perform the remount itself,
/// so it must happen exactly once, here, before any of them run.
///
/// Without this remount, every mount `stage_rootfs` performs below (the
/// overlay itself, `/proc`, `/sys`, the `/dev` tmpfs and its children)
/// would propagate straight back out into the HOST's real mount
/// namespace — a genuine host-contamination bug independent of any
/// container-specific failure, and exactly the hazard `pivot_root`'s own
/// step (1) already guards against for the mounts it touches later.
///
/// NOTE, so a future reader doesn't repeat this investigation: this
/// `MS_PRIVATE` remount was originally added (Phase 8 Task 16) suspecting
/// it was ALSO the fix for a real, independently-hit `devpts` `newinstance`
/// `EINVAL` failure at `<merged>/dev/pts` — it is not. That `EINVAL` was
/// root-caused (via a real, `strace`d, minimal reproduction:
/// `unshare -U -m --map-root-user -- mount -t devpts -o newinstance,...,
/// gid=5 ...`) to a completely different cause: `setup_standard_mounts`'s
/// `dev/pts` entry hardcoded the conventional `gid=5` ("tty") devpts
/// option, but the mount namespace here is owned by a freshly created USER
/// namespace whose `gid_map` — built from the OCI bundle's own
/// `linux.gidMappings` — usually maps only container gid 0, not 5;
/// devpts's `gid=` option must resolve through that mapping, and an
/// unmapped gid makes the whole mount call fail `EINVAL`. The real fix is
/// `kestrel-rootfs::mounts::STANDARD_MOUNTS`'s `dev/pts` entry now using
/// `gid=0` (guaranteed mapped) instead of `gid=5` — see that entry's own
/// doc comment for the full explanation. This `MS_PRIVATE` remount is kept
/// anyway because the host-mount-leak hazard above is real on its own
/// merits, matching every downstream function's already-documented
/// precondition — just not, in the end, why `devpts` was failing.
pub fn stage_rootfs(data_dir: &Path, bootstrap: &Bootstrap) -> Result<PathBuf> {
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("making / private (required before any staging mount, and again before pivot_root)")?;

    let snapshotter = snapshot::Snapshotter::new(data_dir.to_path_buf(), bootstrap.mount_plan.rootless);
    let snap = snapshotter
        .prepare_snapshot(&bootstrap.container_id, &bootstrap.mount_plan.lower_chain_ids)
        .context("prepare_snapshot")?;
    overlay::mount_overlay(data_dir, &snap, bootstrap.mount_plan.rootless, false, false).context("mount_overlay")?;
    mounts::setup_standard_mounts(&snap.merged).context("setup_standard_mounts")?;
    mask::apply_default_masks(&snap.merged).context("apply_default_masks")?;
    mounts::bind_mount_file(&bootstrap.fifo_host_path, &snap.merged, &bootstrap.fifo_container_path)
        .context("bind-mounting exec fifo into the container")?;
    Ok(snap.merged)
}

/// Swaps `/` to `merged`, detaching the old root. Must run AFTER
/// `createContainer` hooks have had a chance to touch the staged rootfs,
/// and BEFORE `apply_hostname_and_time` (sethostname/timens are UTS/time
/// namespace operations, unaffected by the pivot itself, but this
/// module's own call order in `main.rs`'s eventual wiring — Task 7 —
/// follows the design doc's `pivot_root` → `sethostname` → timens
/// sequencing).
pub fn pivot(merged: &Path) -> Result<()> {
    pivot::pivot_root(merged).context("pivot_root")
}

/// `sethostname(2)` and `/proc/self/timens_offsets` application.
///
/// `nix::unistd::sethostname`'s real signature (confirmed against the
/// vendored nix 0.29.0 source, `src/unistd.rs`) is
/// `sethostname<S: AsRef<OsStr>>(name: S) -> Result<()>` — `&String`
/// satisfies `AsRef<OsStr>` via the standard blanket
/// `impl<T: AsRef<U>> AsRef<U> for &T`, so passing `hostname` (a
/// `&String` here) directly works with no extra conversion. Gated behind
/// nix's `hostname` cargo feature (added to this crate's `Cargo.toml`).
///
/// `/proc/self/timens_offsets`'s real format, verified against `man 7
/// time_namespaces` (not assumed from this plan's own draft, which
/// described the clock-id field as numeric-only — the real kernel doc
/// says the opposite: the clock-id is normally the STRING `monotonic` or
/// `boottime`, with numeric ids (`1`/`7`) accepted only "for
/// compatibility" and symbolic names "preferred"). `Bootstrap` already
/// carries each line pre-formatted (`kestrel-runtime`'s `create.rs`,
/// Task 8, is responsible for producing the `<clock-id> <offset-secs>
/// <offset-nanosecs>` lines) — this function's only job is joining them
/// with newlines, INCLUDING a trailing newline, since the kernel doc
/// describes writes as "newline-terminated records". The file must be
/// written before any other process is created in this time namespace
/// (writes fail with EACCES afterward) — true here by construction,
/// since `kestrel-init` is itself the first and only process in the
/// container's time namespace at this point in the startup sequence.
pub fn apply_hostname_and_time(bootstrap: &Bootstrap) -> Result<()> {
    if let Some(hostname) = &bootstrap.hostname {
        nix::unistd::sethostname(hostname).context("sethostname")?;
    }
    if !bootstrap.timens_offsets.is_empty() {
        let mut content = bootstrap.timens_offsets.join("\n");
        content.push('\n');
        std::fs::write("/proc/self/timens_offsets", content).context("writing /proc/self/timens_offsets")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_oci::bootstrap::{HookSet, MountPlan};
    use kestrel_oci::runtime::Process;
    use nix::sched::{unshare, CloneFlags};

    fn sample_bootstrap(hostname: Option<&str>) -> Bootstrap {
        Bootstrap {
            container_id: "c1".into(),
            mount_plan: MountPlan { lower_chain_ids: vec![], rootless: false },
            process: Process::default(),
            capabilities: None,
            seccomp: None,
            hooks: HookSet { create_container: vec![], start_container: vec![] },
            hostname: hostname.map(String::from),
            timens_offsets: vec![],
            fifo_host_path: "/run/kestrel/c1/exec.fifo".into(),
            fifo_container_path: "/exec.fifo".into(),
            state_json_path: "/run/kestrel/c1/state.json".into(),
            seccomp_notify_sink: None,
        }
    }

    /// Root-gated: `unshare(CLONE_NEWUTS)` requires `CAP_SYS_ADMIN`.
    /// `apply_hostname_and_time` doesn't need the full rootfs machinery to
    /// test meaningfully — this isolates just the `sethostname` half in
    /// its own UTS namespace (so the test never touches the real host
    /// hostname) and confirms it actually took effect via `uname()`,
    /// exactly what this task's plan asks for. `run_isolated` (from
    /// `kestrel_ns::test_util`, already a dev-dependency) forks first so
    /// the single-threadedness `unshare(CLONE_NEWUSER)`-style namespace
    /// calls generally require is guaranteed regardless of how many
    /// threads cargo test's own harness has running.
    #[test]
    #[ignore = "requires root"]
    fn test_apply_hostname_and_time_sets_hostname_in_isolated_uts_ns() {
        kestrel_ns::test_util::run_isolated(|| {
            unshare(CloneFlags::CLONE_NEWUTS).expect("unshare(CLONE_NEWUTS)");

            let bootstrap = sample_bootstrap(Some("kestrel-test-host"));
            apply_hostname_and_time(&bootstrap).expect("apply_hostname_and_time");

            let uts = nix::sys::utsname::uname().expect("uname");
            assert_eq!(
                uts.nodename().to_str().expect("nodename is valid utf8"),
                "kestrel-test-host",
                "sethostname must actually take effect, observed via uname()"
            );
        });
    }

    #[test]
    #[ignore = "requires root"]
    fn test_apply_hostname_and_time_is_noop_without_hostname_or_timens() {
        kestrel_ns::test_util::run_isolated(|| {
            unshare(CloneFlags::CLONE_NEWUTS).expect("unshare(CLONE_NEWUTS)");

            let before = nix::sys::utsname::uname().expect("uname");
            let bootstrap = sample_bootstrap(None);
            apply_hostname_and_time(&bootstrap).expect("apply_hostname_and_time");
            let after = nix::sys::utsname::uname().expect("uname");

            assert_eq!(
                before.nodename(),
                after.nodename(),
                "hostname must be left untouched when Bootstrap.hostname is None"
            );
        });
    }
}
