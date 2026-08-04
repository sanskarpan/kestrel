// crates/kestrel-security/tests/caps.rs
//
// Root-gated: real capability-set mutation via apply_capabilities(), then a
// real mount(2) syscall to prove CAP_SYS_ADMIN was actually removed from
// the bounding/effective sets (not just "believed" removed by inspecting
// /proc/self/status).
//
// MOUNT-NAMESPACE SAFETY (read before touching this file):
//
// `/tmp` in the dev VM is NOT its own mountpoint. `findmnt -T /tmp` and
// `/proc/self/mountinfo` both show it resolves to the root ext4 filesystem
// (`/dev/vda1` on `/`, mounted `rw,relatime,discard,errors=remount-ro,
// commit=30` — there is no separate `/tmp` line at all).
//
// This was checked BEFORE assuming "MS_REMOUNT on an existing mount is a
// no-op on the mount table" was safe to rely on, per the task's explicit
// instruction to verify rather than assume. The plan's own risk analysis
// (a bare `MS_REMOUNT`/no-data call resetting the target mount's flags —
// e.g. stripping `discard`/`commit=30`/`errors=remount-ro` from a real
// ext4 superblock) is real in principle, but empirically it never gets the
// chance to happen here: `mount(2)`'s `MS_REMOUNT` requires its target
// path to be an EXISTING mountpoint's root (i.e. `path.dentry ==
// path.mnt->mnt_root`); a plain subdirectory of a larger mount (which is
// exactly what `/tmp` is on this VM) fails at path resolution with EINVAL
// before the kernel ever touches that mount's flags — confirmed by running
// the unguarded version of these tests first: `apply_capabilities(None)`
// followed by the raw `MS_REMOUNT` on `/tmp` returned `EINVAL`, not
// success, and `/proc/self/mountinfo`'s root-fs line was byte-for-byte
// identical before and after (see task report for the diff).
//
// So the tests need a real, disposable mountpoint to remount — not the
// host's ambiguous `/tmp`. `run_in_fresh_mount_ns` below creates one
// safely: fork (`kestrel_ns::test_util::run_isolated`) + unshare
// (`CLONE_NEWNS`) + recursive `MS_PRIVATE` remount of `/` (so nothing
// propagates back to the VM's real mount table — the same discipline
// `kestrel-rootfs/tests/common/mod.rs`'s `run_in_fresh_mount_ns` uses, for
// the same reason: `run_isolated` alone, fork-only, does NOT isolate
// mounts) — and THEN a self bind-mount of `/tmp` onto itself
// (`mount(Some("/tmp"), "/tmp", ..., MS_BIND, ...)`), the standard trick
// for turning an ordinary directory into an actual mountpoint. That bind
// mount exists only inside this forked child's private namespace copy and
// is torn down for free when the child exits, so `MS_REMOUNT` on `/tmp`
// inside these tests now has a real, safely-disposable target to act on,
// and can never reach the VM's real root filesystem regardless of which
// way the ordering/flags questions above resolve.
//
// `kestrel_security::caps::DEFAULT_CAPABILITIES` already excludes SysAdmin,
// so it's exactly the "keep everything but SysAdmin" bounding set these
// tests need.

use kestrel_oci::runtime::LinuxCapabilitiesBuilder;
use kestrel_security::caps::{apply_capabilities, DEFAULT_CAPABILITIES};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};

/// Same containment discipline as `kestrel-rootfs/tests/common/mod.rs`'s
/// `run_in_fresh_mount_ns`, reimplemented locally (that helper lives in a
/// different crate's `tests/` tree and isn't importable from here), PLUS a
/// self bind-mount of `/tmp` so `MS_REMOUNT` below has an actual,
/// disposable mountpoint to target. See the module-level doc comment above
/// for the full reasoning.
fn run_in_fresh_mount_ns(f: impl FnOnce() + std::panic::UnwindSafe) {
    kestrel_ns::test_util::run_isolated(|| {
        unshare(CloneFlags::CLONE_NEWNS).expect("unshare(CLONE_NEWNS)");
        mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>)
            .expect("remount / as MS_PRIVATE|MS_REC");
        // Turn /tmp into a real mountpoint (self bind-mount), confined to
        // this private namespace copy and gone when this child exits.
        mount(Some("/tmp"), "/tmp", None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .expect("self bind-mount /tmp so it's remountable");
        f();
    });
}

#[test]
#[ignore = "requires root"]
fn test_caps_dropped_blocks_mount() {
    run_in_fresh_mount_ns(|| {
        // Keep everything BUT SysAdmin in the bounding set — the OCI
        // default-ish shape without the one capability mount(2) needs.
        // DEFAULT_CAPABILITIES already excludes SysAdmin (see its doc
        // comment in caps.rs), so it's exactly this set.
        let bounding: kestrel_oci::runtime::Capabilities = DEFAULT_CAPABILITIES.iter().copied().collect();

        let linux_caps = LinuxCapabilitiesBuilder::default()
            .bounding(bounding.clone())
            .effective(bounding.clone())
            .permitted(bounding.clone())
            .inheritable(bounding.clone())
            .ambient(bounding)
            .build()
            .unwrap();

        apply_capabilities(Some(&linux_caps)).expect("apply_capabilities");

        // We're still root (uid 0) here — capabilities, not uid, are what
        // gate mount() at this point. Attempting a real remount of our
        // private self-bind-mounted /tmp (see module doc / run_in_fresh_mount_ns)
        // without CAP_SYS_ADMIN in the effective set must fail EPERM.
        let err = mount(None::<&str>, "/tmp", None::<&str>, MsFlags::MS_REMOUNT, None::<&str>)
            .expect_err("mount() must fail once CAP_SYS_ADMIN is dropped");
        assert_eq!(err, nix::errno::Errno::EPERM);
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_capabilities_none_is_a_no_op() {
    run_in_fresh_mount_ns(|| {
        apply_capabilities(None).expect("None must be a clean no-op, not an error");
        // A real remount of our private self-bind-mounted /tmp must STILL
        // work — proving nothing was dropped. Confined to this forked
        // child's private namespace copy (see module doc) and vanishes
        // when the child exits, never reaching the VM's real mount table.
        mount(None::<&str>, "/tmp", None::<&str>, MsFlags::MS_REMOUNT, None::<&str>)
            .expect("mount() must still work when apply_capabilities(None) touched nothing");
    });
}
