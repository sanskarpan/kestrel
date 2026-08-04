// crates/kestrel-security/src/apply.rs

use std::os::fd::OwnedFd;

use anyhow::{Context, Result};
use kestrel_oci::runtime::{LinuxSeccomp, Process};
use nix::unistd::{setgroups, setresgid, setresuid, Gid, Uid};

use crate::caps::apply_capabilities;
use crate::noprivs::set_no_new_privs;
use crate::rlimits::apply_rlimits;
use crate::seccomp::install_seccomp;

/// The full Phase 5 pipeline, in the order PROMPT.md's Phase 5 section and
/// SPEC.md §8 both specify. Called by [`kestrel_init::exec::exec_into`]
/// (Task 12) immediately before execve() — every step here operates on
/// the CURRENT process, and several are irreversible, which is why the
/// order is load-bearing rather than stylistic.
///
/// **Preconditions.**
/// - The calling process must currently hold root-equivalent privilege —
///   specifically CAP_SETUID and CAP_SETGID (needed by step 4's
///   `setresuid`/`setresgid`/`setgroups`), and its Permitted capability set
///   must be a superset of every target set `p.capabilities()` asks for
///   (see [`apply_capabilities`]'s own precondition doc — this is always
///   true for the fresh, typically-root process this function is designed
///   to run against exactly once).
/// - Within step 4, `setgroups`/`setresgid` may run in either order
///   relative to each other — see the comment at that call site for why.
///
/// **On any `Err`, the caller MUST NOT execve().** A failure partway
/// through leaves the process in a partial-privilege-drop state — e.g.
/// capabilities already reduced (step 2) and/or the GID already changed
/// (step 4) while the UID is still 0/root — and that state must never be
/// allowed to run untrusted code. Every error here is meant to be fatal to
/// the whole container-start attempt, not something the caller retries or
/// papers over.
pub fn apply_all(p: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Option<OwnedFd>> {
    // (1) rlimits — some can't be raised after the uid drop in step (4).
    apply_rlimits(p.rlimits().as_deref()).context("applying rlimits")?;
    if let Some(score) = p.oom_score_adj() {
        crate::rlimits::set_oom_score_adj(score).context("setting oom_score_adj")?;
    }

    // (2) Capabilities. Bounding-set drops are IRREVERSIBLE, so this must
    //     come after anything that still needed a capability (rlimits
    //     above needs none; the uid/gid drop in step (4) needs
    //     CAP_SETUID/CAP_SETGID, which is why this runs before it).
    apply_capabilities(p.capabilities().as_ref()).context("applying capabilities")?;

    // (3) no_new_privs. Must precede seccomp: an unprivileged process can
    //     only install a seccomp filter if no_new_privs is set. Also
    //     permanently neuters setuid/setcap binaries execve()'d afterward.
    //     Honors the spec's own toggle (default false/unset, matching
    //     runc) rather than unconditionally forcing it on.
    if p.no_new_privileges().unwrap_or(false) {
        set_no_new_privs().context("setting no_new_privs")?;
    }

    // (4) User/group. AFTER capabilities, so CAP_SETUID/CAP_SETGID were
    //     still available. Unconditional — the real User type's uid/gid
    //     are plain u32 (default 0), not Option, so an "unset" user in
    //     the spec correctly means "run as uid 0/gid 0", not "skip this".
    //
    //     setgroups/setresgid can run in either order relative to each
    //     other — only the setresuid transition below affects capabilities
    //     (the kernel clears caps on a UID-to-nonzero transition; GID
    //     changes don't), so this order is a stylistic choice, not a
    //     correctness requirement, unlike PROMPT.md's illustrative
    //     setresgid-first sketch. setresuid must still come last: it's the
    //     step that can drop capabilities, so anything else needing the
    //     current privilege set (setgroups, setresgid) must precede it.
    let user = p.user();
    if let Some(additional) = user.additional_gids().as_deref().filter(|g| !g.is_empty()) {
        let gids: Vec<Gid> = additional.iter().map(|g| Gid::from_raw(*g)).collect();
        setgroups(&gids).context("setgroups")?;
    }
    let gid = Gid::from_raw(user.gid());
    setresgid(gid, gid, gid).context("setresgid")?;
    let uid = Uid::from_raw(user.uid());
    setresuid(uid, uid, uid).context("setresuid")?;

    // (5) Seccomp LAST, immediately before exec, so the entrypoint's very
    //     first syscall is already filtered — and so our own setup
    //     syscalls above aren't blocked by the container's own profile.
    let notify_fd = seccomp.map(install_seccomp).transpose()?.flatten();

    Ok(notify_fd)
}
