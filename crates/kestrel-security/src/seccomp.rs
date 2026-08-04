//! Seccomp profile loading and filter building. See
//! docs/superpowers/specs/2026-08-03-phase5-security-design.md and
//! SPEC.md §8.3.
//!
//! Two halves: [`load_default_profile`] loads and parses
//! `profiles/seccomp/default.json` into a `LinuxSeccomp`; [`install_seccomp`]
//! translates a parsed `LinuxSeccomp` into a loaded seccomp-bpf filter via
//! `libseccomp` (`translate_action`/`translate_arch`/`translate_operator`/
//! `translate_arg_comparisons` do the per-field translation between
//! `kestrel-oci`'s and `libseccomp`'s independently-shaped types).

use std::path::Path;

use anyhow::{Context, Result};
use kestrel_oci::runtime::LinuxSeccomp;

/// Loads and parses `profiles/seccomp/default.json` (relative to the
/// workspace root) into a `LinuxSeccomp`, using kestrel-oci's existing
/// serde support for the runtime-spec types.
///
/// `workspace_root` is caller-supplied on purpose: this function is meant
/// for test/dev use (this crate's own tests pass `CARGO_MANIFEST_DIR`-
/// derived paths), not for production profile loading. A real `kestreld`
/// resolves its seccomp profile path from daemon config (SPEC.md §17's
/// `seccomp_profile` setting, e.g. `/etc/kestrel/profiles/seccomp/default.json`),
/// not from this workspace-relative helper.
pub fn load_default_profile(workspace_root: &Path) -> Result<LinuxSeccomp> {
    let path = workspace_root.join("profiles/seccomp/default.json");
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("parsing {} as LinuxSeccomp", path.display()))
}

#[cfg(test)]
mod loader_tests {
    use super::*;

    #[test]
    fn test_load_default_profile_parses() {
        // CARGO_MANIFEST_DIR is crates/kestrel-security; workspace root is
        // two levels up.
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        let profile = load_default_profile(workspace_root).expect("default.json must parse as LinuxSeccomp");
        assert!(!profile.syscalls().as_ref().map(|s| s.is_empty()).unwrap_or(true), "profile must have at least one syscall rule");
    }
}

// ---------------------------------------------------------------------------
// Filter building and loading (install_seccomp), SPEC.md §8.3.
//
// The libseccomp 0.3.0 <-> kestrel-oci translation below was written against
// the ACTUAL vendored source of both crates (not guessed):
//   - kestrel-oci's LinuxSeccomp/LinuxSeccompAction/Arch/LinuxSeccompOperator/
//     LinuxSyscall/LinuxSeccompArg: oci-spec-0.10.0/src/runtime/linux.rs
//     (lines ~1068-1387, incl. LinuxSeccompAction::as_u32's real fallback
//     values, which this file's default-errno/default-trace-value choices
//     deliberately mirror).
//   - libseccomp's ScmpAction/ScmpArch/ScmpCompareOp/ScmpArgCompare/
//     ScmpFilterContext/ScmpSyscall: the vendored libseccomp-0.3.0 crate
//     source under ~/.cargo/registry/src/*/libseccomp-0.3.0/src/{action,
//     arch,compare_op,arg_compare,filter_context,notify,syscall}.rs, inside
//     the Lima VM (this is a Linux-only, pkg-config-gated crate that can't
//     be inspected from the macOS host).
//
// Corrections made vs. the plan's best-effort sketch of the libseccomp side
// (documented here since the plan explicitly called this the
// least-verified part of the whole phase):
//
//   1. `ScmpFilterContext::new` DOES NOT EXIST in libseccomp 0.3.0 — the
//      plan's instruction to prefer it over an allegedly-deprecated
//      `new_filter` had it backwards for this version. `new_filter` is the
//      one and only constructor (not deprecated, no `#[deprecated]`
//      attribute on it in the vendored source). Using it below.
//   2. `ScmpAction::Trace` wraps `u16`, not `u32` — `errno_ret` (`Option<u32>`)
//      is converted with a checked `u16::try_from` rather than an `as` cast,
//      so an out-of-range profile value is a loud error instead of silent
//      truncation.
//   3. `ScmpArch` in this libseccomp version has 20 variants, not the 21 the
//      plan guessed at. Checked field-by-field against oci-spec's real
//      `Arch` (24 variants): `ScmpArch` is missing `LoongArch64`, `M68k`,
//      `Sh`, and `Sheb` specifically — NOT `Parisc`/`Parisc64`/`Riscv64`,
//      which the plan flagged as possibly-missing but which are in fact
//      present in this libseccomp version. `translate_arch` below maps all
//      20 that exist and bails loudly on the 4 that don't, per the plan's
//      own instruction to fail loud rather than silently drop an arch.
//   4. `ScmpArgCompare::new(arg: u32, op: ScmpCompareOp, datum: u64)` and
//      `ScmpCompareOp::MaskedEqual(mask: u64)` (with the compare-against
//      value passed separately as `datum`) matched the plan's guess
//      exactly — confirmed against `arg_compare.rs`'s doc example and its
//      own `MaskedEqual` unit test.
//   5. `ScmpAction::KillThread`/`ScmpFilterContext::{add_rule,
//      add_rule_conditional, load}`/`ScmpSyscall::from_name`/
//      `ScmpFilterContext::get_notify_fd` (`-> Result<ScmpFd>`, `ScmpFd =
//      RawFd = i32`) all matched the plan's guessed signatures exactly.

use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::bail;
use kestrel_oci::runtime::{Arch, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompOperator};
use libseccomp::{ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// Builds and loads a seccomp-bpf filter from `profile`, per SPEC.md §8.3.
/// Must be called AFTER no_new_privs (Task 6) and LAST in `apply_all`
/// (Task 10), immediately before execve — everything this process does
/// after `load()` returns, including its own remaining setup code, is
/// subject to the filter.
///
/// Returns `Some(fd)` if the profile uses SCMP_ACT_NOTIFY anywhere (a
/// supervisor — Task 9's `run_notify_loop`, eventually called from
/// kestreld — can read violations off it), `None` otherwise.
pub fn install_seccomp(profile: &LinuxSeccomp) -> Result<Option<OwnedFd>> {
    let default_action = translate_action(profile.default_action(), profile.default_errno_ret())?;
    // NOTE: `ScmpFilterContext::new` does not exist in libseccomp 0.3.0;
    // `new_filter` is the real (non-deprecated) constructor — see the
    // module-level correction notes above.
    let mut ctx = ScmpFilterContext::new_filter(default_action).context("creating seccomp filter context")?;

    for arch in profile.architectures().iter().flatten() {
        ctx.add_arch(translate_arch(*arch)?).with_context(|| format!("adding arch {arch:?}"))?;
    }

    let mut uses_notify = matches!(profile.default_action(), LinuxSeccompAction::ScmpActNotify);
    for rule in profile.syscalls().iter().flatten() {
        let action = translate_action(rule.action(), rule.errno_ret())?;
        uses_notify |= matches!(rule.action(), LinuxSeccompAction::ScmpActNotify);
        for name in rule.names() {
            let Ok(sc) = ScmpSyscall::from_name(name) else {
                // CHECKLIST.md: unknown syscall names must be skipped with
                // a warning, never fail the whole container — a profile
                // written for a newer/older kernel may reference syscalls
                // this kernel doesn't recognize by that name.
                tracing::warn!(syscall = %name, "unknown syscall in seccomp profile, skipping");
                continue;
            };
            match rule.args() {
                None => ctx.add_rule(action, sc).with_context(|| format!("adding rule for {name}"))?,
                Some(args) if args.is_empty() => {
                    ctx.add_rule(action, sc).with_context(|| format!("adding rule for {name}"))?
                }
                Some(args) => {
                    let cmps = translate_arg_comparisons(args)?;
                    ctx.add_rule_conditional(action, sc, &cmps)
                        .with_context(|| format!("adding conditional rule for {name}"))?;
                }
            }
        }
    }

    ctx.load().context("loading seccomp filter into the kernel")?;

    if uses_notify {
        let fd = ctx.get_notify_fd().context("getting seccomp notify fd")?;
        // SAFETY: `fd` is a valid, open fd handed to us by libseccomp after
        // a successful ctx.load(); ScmpFd is a raw fd type (`RawFd = i32`,
        // verified against notify.rs) with no ownership semantics of its
        // own, so wrapping it in OwnedFd here is what actually gives it
        // correct close-on-drop behavior, matching this crate's convention
        // of using owned fd types at API boundaries. libseccomp's own docs
        // note the fd must not be closed by anything other than through
        // this ownership transfer.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Some(owned))
    } else {
        Ok(None)
    }
}

/// `errno_ret` is only meaningful for `ScmpActErrno`/`ScmpActTrace` (see
/// `LinuxSeccompAction::as_u32`'s own doc comment) — passed through for
/// those two, ignored otherwise. Defaults mirror
/// `LinuxSeccompAction::as_u32`'s own fallbacks exactly (verified against
/// oci-spec-0.10.0's real source, not assumed): `0x00050001` for
/// `ScmpActErrno` with no `errno_ret` set (errno 1 = EPERM) and
/// `0x7ff00001` for `ScmpActTrace` (trace value 1) — both "low byte 1",
/// which is why both arms below default to `1`, not `0`.
fn translate_action(action: LinuxSeccompAction, errno_ret: Option<u32>) -> Result<ScmpAction> {
    Ok(match action {
        LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => ScmpAction::KillThread,
        LinuxSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
        LinuxSeccompAction::ScmpActTrap => ScmpAction::Trap,
        LinuxSeccompAction::ScmpActErrno => {
            let errno = errno_ret.unwrap_or(libc::EPERM as u32);
            ScmpAction::Errno(errno as i32)
        }
        LinuxSeccompAction::ScmpActNotify => ScmpAction::Notify,
        LinuxSeccompAction::ScmpActTrace => {
            // ScmpAction::Trace wraps a `u16`, unlike Errno's `i32` — a
            // checked conversion here turns an out-of-range profile value
            // into a loud error instead of a silently truncated one.
            let trace_val = errno_ret.unwrap_or(1);
            let trace_val = u16::try_from(trace_val)
                .with_context(|| format!("SCMP_ACT_TRACE value {trace_val} does not fit in u16"))?;
            ScmpAction::Trace(trace_val)
        }
        LinuxSeccompAction::ScmpActLog => ScmpAction::Log,
        LinuxSeccompAction::ScmpActAllow => ScmpAction::Allow,
    })
}

/// Maps `kestrel_oci::runtime::Arch` (24 variants, verified against
/// oci-spec-0.10.0/src/runtime/linux.rs) onto `libseccomp::ScmpArch` (20
/// variants in the resolved libseccomp 0.3.0, verified against its vendored
/// arch.rs). The 4 without a real mapping in this libseccomp version —
/// `ScmpArchLoongarch64`, `ScmpArchM68k`, `ScmpArchSh`, `ScmpArchSheb` —
/// bail loudly rather than being silently dropped from the filter: a
/// missing arch on an arch-specific syscall rule means the filter simply
/// doesn't apply to that arch at all, which is not "fails safe."
fn translate_arch(arch: Arch) -> Result<ScmpArch> {
    Ok(match arch {
        Arch::ScmpArchNative => ScmpArch::Native,
        Arch::ScmpArchX86 => ScmpArch::X86,
        Arch::ScmpArchX86_64 => ScmpArch::X8664,
        Arch::ScmpArchX32 => ScmpArch::X32,
        Arch::ScmpArchArm => ScmpArch::Arm,
        Arch::ScmpArchAarch64 => ScmpArch::Aarch64,
        Arch::ScmpArchMips => ScmpArch::Mips,
        Arch::ScmpArchMips64 => ScmpArch::Mips64,
        Arch::ScmpArchMips64n32 => ScmpArch::Mips64N32,
        Arch::ScmpArchMipsel => ScmpArch::Mipsel,
        Arch::ScmpArchMipsel64 => ScmpArch::Mipsel64,
        Arch::ScmpArchMipsel64n32 => ScmpArch::Mipsel64N32,
        Arch::ScmpArchPpc => ScmpArch::Ppc,
        Arch::ScmpArchPpc64 => ScmpArch::Ppc64,
        Arch::ScmpArchPpc64le => ScmpArch::Ppc64Le,
        Arch::ScmpArchS390 => ScmpArch::S390,
        Arch::ScmpArchS390x => ScmpArch::S390X,
        Arch::ScmpArchParisc => ScmpArch::Parisc,
        Arch::ScmpArchParisc64 => ScmpArch::Parisc64,
        Arch::ScmpArchRiscv64 => ScmpArch::Riscv64,
        other @ (Arch::ScmpArchLoongarch64 | Arch::ScmpArchM68k | Arch::ScmpArchSh | Arch::ScmpArchSheb) => {
            bail!("no ScmpArch mapping for {other:?} in this libseccomp-rs version (libseccomp 0.3.0's ScmpArch has no LoongArch64/M68k/Sh/Sheb variant)")
        }
    })
}

fn translate_operator(op: LinuxSeccompOperator) -> ScmpCompareOp {
    match op {
        LinuxSeccompOperator::ScmpCmpNe => ScmpCompareOp::NotEqual,
        LinuxSeccompOperator::ScmpCmpLt => ScmpCompareOp::Less,
        LinuxSeccompOperator::ScmpCmpLe => ScmpCompareOp::LessOrEqual,
        LinuxSeccompOperator::ScmpCmpEq => ScmpCompareOp::Equal,
        LinuxSeccompOperator::ScmpCmpGe => ScmpCompareOp::GreaterEqual,
        LinuxSeccompOperator::ScmpCmpGt => ScmpCompareOp::Greater,
        // Placeholder mask — never actually reaches ScmpArgCompare::new in
        // this shape; translate_arg_comparisons below builds the real
        // MaskedEqual(mask) directly from LinuxSeccompArg::value() instead
        // of routing it through this function, since the mask isn't known
        // to translate_operator (it only sees the *operator*, not the arg).
        LinuxSeccompOperator::ScmpCmpMaskedEq => ScmpCompareOp::MaskedEqual(0),
    }
}

/// `LinuxSeccompArg`'s `value`/`value_two` and `ScmpArgCompare`'s
/// `op`+`datum` encode `SCMP_CMP_MASKED_EQ` differently, verified against
/// both crates' real source rather than assumed:
///   - OCI spec (`LinuxSeccompArg`): `value` = the mask, `value_two` = the
///     value to compare against after masking.
///   - libseccomp (`ScmpCompareOp::MaskedEqual(mask)` + `ScmpArgCompare::
///     new(arg, op, datum)`): `mask` lives inside the `ScmpCompareOp`
///     variant itself, `datum` (the constructor's third argument) is the
///     compare-against value — confirmed against `arg_compare.rs`'s `new()`
///     doc example and its `test_scmpargcompare` unit test, which
///     constructs `ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(mask),
///     datum)` and asserts the underlying `scmp_arg_cmp.{datum_a,datum_b}`
///     end up as `{mask, datum}` respectively.
///
/// So: mask = `a.value()` (goes into `ScmpCompareOp::MaskedEqual`), compare
/// value = `a.value_two()` (goes into `ScmpArgCompare::new`'s `datum`
/// parameter) for the masked case; for every other operator, `a.value()`
/// alone is the compare value and `value_two` is unused (the OCI spec
/// itself only documents `value_two` as meaningful for `ScmpCmpMaskedEq`).
fn translate_arg_comparisons(args: &[LinuxSeccompArg]) -> Result<Vec<ScmpArgCompare>> {
    args.iter()
        .map(|a| {
            let (op, compare_value) = if matches!(a.op(), LinuxSeccompOperator::ScmpCmpMaskedEq) {
                (ScmpCompareOp::MaskedEqual(a.value()), a.value_two().unwrap_or(0))
            } else {
                (translate_operator(a.op()), a.value())
            };
            Ok(ScmpArgCompare::new(a.index() as u32, op, compare_value))
        })
        .collect()
}

#[cfg(test)]
mod install_tests {
    use super::*;

    /// Every `LinuxSeccompAction` variant this project targets must
    /// translate without error — mirrors caps.rs's
    /// `test_translate_capability_covers_the_default_set` pattern. This is
    /// the test that would have immediately caught the `Trace(u32)` vs.
    /// `Trace(u16)` mismatch against the plan's original sketch had the
    /// vendored-source check not already caught it.
    #[test]
    fn test_translate_action_covers_all_nine_variants() {
        for action in [
            LinuxSeccompAction::ScmpActKill,
            LinuxSeccompAction::ScmpActKillThread,
            LinuxSeccompAction::ScmpActKillProcess,
            LinuxSeccompAction::ScmpActTrap,
            LinuxSeccompAction::ScmpActErrno,
            LinuxSeccompAction::ScmpActNotify,
            LinuxSeccompAction::ScmpActTrace,
            LinuxSeccompAction::ScmpActLog,
            LinuxSeccompAction::ScmpActAllow,
        ] {
            translate_action(action, Some(1)).unwrap_or_else(|e| panic!("{action} failed to translate: {e}"));
        }
    }

    #[test]
    fn test_translate_action_kill_and_kill_thread_both_map_to_kill_thread() {
        // ScmpAction has no separate "Kill" variant in libseccomp 0.3.0 —
        // SCMP_ACT_KILL is a backward-compat alias for SCMP_ACT_KILL_THREAD
        // on both sides (confirmed against oci-spec's LinuxSeccompAction
        // doc comment and libseccomp's ScmpAction::from_str, which maps
        // both "SCMP_ACT_KILL_THREAD" and "SCMP_ACT_KILL" to KillThread).
        assert_eq!(translate_action(LinuxSeccompAction::ScmpActKill, None).unwrap(), ScmpAction::KillThread);
        assert_eq!(translate_action(LinuxSeccompAction::ScmpActKillThread, None).unwrap(), ScmpAction::KillThread);
    }

    #[test]
    fn test_translate_action_errno_defaults_to_eperm() {
        assert_eq!(translate_action(LinuxSeccompAction::ScmpActErrno, None).unwrap(), ScmpAction::Errno(libc::EPERM));
    }

    #[test]
    fn test_translate_action_errno_uses_configured_value() {
        assert_eq!(translate_action(LinuxSeccompAction::ScmpActErrno, Some(42)).unwrap(), ScmpAction::Errno(42));
    }

    #[test]
    fn test_translate_action_trace_out_of_u16_range_bails() {
        assert!(translate_action(LinuxSeccompAction::ScmpActTrace, Some(u32::from(u16::MAX) + 1)).is_err());
    }

    /// At minimum this project's two real deployment targets (the Lima VM
    /// is aarch64, x86_64 is the other realistic target) must translate —
    /// per the plan's own instruction on what's non-negotiable to cover.
    #[test]
    fn test_translate_arch_covers_real_deployment_targets() {
        assert_eq!(translate_arch(Arch::ScmpArchX86_64).unwrap(), ScmpArch::X8664);
        assert_eq!(translate_arch(Arch::ScmpArchAarch64).unwrap(), ScmpArch::Aarch64);
    }

    /// All 20 `Arch` variants with a real `ScmpArch` counterpart in this
    /// libseccomp version must translate successfully.
    #[test]
    fn test_translate_arch_covers_all_mapped_variants() {
        for arch in [
            Arch::ScmpArchNative, Arch::ScmpArchX86, Arch::ScmpArchX86_64, Arch::ScmpArchX32,
            Arch::ScmpArchArm, Arch::ScmpArchAarch64, Arch::ScmpArchMips, Arch::ScmpArchMips64,
            Arch::ScmpArchMips64n32, Arch::ScmpArchMipsel, Arch::ScmpArchMipsel64,
            Arch::ScmpArchMipsel64n32, Arch::ScmpArchPpc, Arch::ScmpArchPpc64, Arch::ScmpArchPpc64le,
            Arch::ScmpArchS390, Arch::ScmpArchS390x, Arch::ScmpArchParisc, Arch::ScmpArchParisc64,
            Arch::ScmpArchRiscv64,
        ] {
            translate_arch(arch).unwrap_or_else(|e| panic!("{arch:?} failed to translate: {e}"));
        }
    }

    /// The 4 `Arch` variants libseccomp 0.3.0 genuinely has no `ScmpArch`
    /// counterpart for must bail loudly, not silently disappear from the
    /// filter.
    #[test]
    fn test_translate_arch_bails_on_unmapped_variants() {
        for arch in [Arch::ScmpArchLoongarch64, Arch::ScmpArchM68k, Arch::ScmpArchSh, Arch::ScmpArchSheb] {
            assert!(translate_arch(arch).is_err(), "{arch:?} was expected to have no ScmpArch mapping");
        }
    }

    /// All 7 `LinuxSeccompOperator` variants must translate.
    #[test]
    fn test_translate_operator_covers_all_seven_variants() {
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpNe), ScmpCompareOp::NotEqual);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpLt), ScmpCompareOp::Less);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpLe), ScmpCompareOp::LessOrEqual);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpEq), ScmpCompareOp::Equal);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpGe), ScmpCompareOp::GreaterEqual);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpGt), ScmpCompareOp::Greater);
        assert_eq!(translate_operator(LinuxSeccompOperator::ScmpCmpMaskedEq), ScmpCompareOp::MaskedEqual(0));
    }

    #[test]
    fn test_translate_arg_comparisons_plain_operator_uses_value_as_datum() {
        use kestrel_oci::runtime::LinuxSeccompArgBuilder;
        let arg = LinuxSeccompArgBuilder::default()
            .index(0usize)
            .value(123u64)
            .op(LinuxSeccompOperator::ScmpCmpEq)
            .build()
            .unwrap();
        let cmps = translate_arg_comparisons(&[arg]).unwrap();
        assert_eq!(cmps, vec![ScmpArgCompare::new(0, ScmpCompareOp::Equal, 123)]);
    }

    #[test]
    fn test_translate_arg_comparisons_masked_eq_splits_value_and_value_two() {
        use kestrel_oci::runtime::LinuxSeccompArgBuilder;
        let arg = LinuxSeccompArgBuilder::default()
            .index(1usize)
            .value(0xff00u64) // the mask
            .value_two(0x1200u64) // the value to compare after masking
            .op(LinuxSeccompOperator::ScmpCmpMaskedEq)
            .build()
            .unwrap();
        let cmps = translate_arg_comparisons(&[arg]).unwrap();
        assert_eq!(cmps, vec![ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(0xff00), 0x1200)]);
    }
}
