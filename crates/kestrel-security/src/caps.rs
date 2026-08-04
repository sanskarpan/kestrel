// crates/kestrel-security/src/caps.rs

use std::collections::HashSet;
use std::str::FromStr;

use anyhow::{Context, Result};
use kestrel_oci::runtime::Capability as OciCap;
use kestrel_oci::runtime::LinuxCapabilities;

/// `oci_spec::runtime::Capability`'s `Display` renders e.g. `"SYS_ADMIN"`
/// (no `CAP_` prefix — verified against that crate's own test suite).
/// `caps::Capability`'s variants are literally named `CAP_SYS_ADMIN` etc.,
/// and its `FromStr` expects exactly that prefixed form. This bridges the
/// two by name, not by hand-maintaining a parallel enum mapping — any
/// capability either crate adds in the future just works as long as both
/// sides agree on the underlying kernel capability name.
pub fn translate_capability(oci_cap: kestrel_oci::runtime::Capability) -> Result<::caps::Capability> {
    let name = format!("CAP_{oci_cap}");
    ::caps::Capability::from_str(&name)
        .with_context(|| format!("no caps::Capability matching oci capability {oci_cap} (looked up as {name:?})"))
}

use ::caps::CapSet;

/// Applies `caps` to the CURRENT process/thread, in the order PROMPT.md's
/// Phase 5 section and SPEC.md §8.1 both specify: ambient clear → bounding
/// drop (IRREVERSIBLE — once dropped, not even a setuid-root binary can
/// regain it, so this must run before anything that still needs a
/// capability) → permitted/inheritable/effective → ambient raise (last,
/// since this is what survives execve() of a non-setuid binary).
///
/// Each of the five sets is `Option` in the real OCI spec type: `None`
/// means "this spec left this set unconstrained," which this function
/// treats as a no-op for that set — NOT as "drop everything" (that's what
/// an explicit `Some(empty set)` means). `None` entirely is the common case
/// (a spec author who didn't think about capabilities at all).
///
/// **Precondition: this is a privilege DROP.** The caller's CURRENT
/// Permitted set must already be a superset of every target set passed in
/// `caps` (true for the fresh, typically-root process this always runs
/// against per SPEC.md's design — called once, immediately, never
/// incrementally). This is what makes the Effective-before-Permitted
/// ordering below correct: it relies on the old (pre-call) Permitted set
/// being able to absorb whatever the new Effective set is, which only
/// holds when Effective's target is already ⊆ the caller's real Permitted
/// set. If this function were ever called to RAISE capabilities after an
/// initial drop (Permitted target not already ⊆ current Permitted), this
/// ordering would fail the same way the reverse ordering fails for the
/// drop case — just mirrored (Permitted-before-Effective would work
/// instead). Not a silent-corruption risk either way: a violated ordering
/// surfaces as a loud `capset` `EPERM` via the `?` below, never silent
/// misconfiguration — but callers must not repurpose this function for an
/// incremental raise without revisiting this ordering.
pub fn apply_capabilities(caps: Option<&LinuxCapabilities>) -> Result<()> {
    let Some(c) = caps else { return Ok(()) };

    ::caps::clear(None, CapSet::Ambient).context("clearing ambient capabilities")?;

    if let Some(bounding) = c.bounding() {
        let keep: HashSet<::caps::Capability> = translate_set(bounding)?;
        for cap in ::caps::all() {
            if !keep.contains(&cap) {
                ::caps::drop(None, CapSet::Bounding, cap)
                    .with_context(|| format!("dropping {cap:?} from bounding set"))?;
            }
        }
    }

    // Effective is set BEFORE Permitted (the plan's own doc comment groups
    // the three as an unordered "permitted/inheritable/effective" step,
    // but empirically only one relative order between Effective and
    // Permitted actually works): the `caps` crate's `set()` does a
    // capget()-modify-one-field-capset() round trip per call, so whichever
    // field it does NOT touch is resubmitted at whatever value the
    // preceding capget() just read. The kernel's capset(2) requires the
    // submitted (effective, permitted) pair to satisfy effective ⊆
    // permitted on EVERY such call. Starting from a full-privilege root
    // process and shrinking, setting Permitted first would resubmit the
    // OLD (still-full) Effective alongside the NEW (shrunk) Permitted —
    // violating that invariant and failing the whole capset() with EPERM
    // before Effective is ever touched. Shrinking Effective first avoids
    // this: it resubmits the OLD (still-full) Permitted, which any
    // subset trivially satisfies, and by the time Permitted is shrunk to
    // the same target set, Effective (already shrunk) is trivially a
    // subset of it too. Verified against a real EPERM failure on this
    // exact function before the reorder.
    if let Some(effective) = c.effective() {
        let translated = translate_set(effective)?;
        ::caps::set(None, CapSet::Effective, &translated)
            .with_context(|| format!("setting effective set to {translated:?}"))?;
    }
    if let Some(permitted) = c.permitted() {
        let translated = translate_set(permitted)?;
        ::caps::set(None, CapSet::Permitted, &translated)
            .with_context(|| format!("setting permitted set to {translated:?}"))?;
    }
    if let Some(inheritable) = c.inheritable() {
        let translated = translate_set(inheritable)?;
        ::caps::set(None, CapSet::Inheritable, &translated)
            .with_context(|| format!("setting inheritable set to {translated:?}"))?;
    }
    if let Some(ambient) = c.ambient() {
        for cap in translate_set(ambient)? {
            ::caps::raise(None, CapSet::Ambient, cap).with_context(|| format!("raising {cap:?} into ambient"))?;
        }
    }
    Ok(())
}

fn translate_set(oci_caps: &kestrel_oci::runtime::Capabilities) -> Result<HashSet<::caps::Capability>> {
    oci_caps.iter().map(|c| translate_capability(*c)).collect()
}

#[cfg(test)]
mod translate_tests {
    use super::*;
    use kestrel_oci::runtime::Capability as OciCap;

    /// Every variant this project actually uses in DEFAULT_CAPABILITIES
    /// must translate successfully — the specific set most likely to
    /// matter in practice.
    #[test]
    fn test_translate_capability_covers_the_default_set() {
        for cap in [
            OciCap::Chown, OciCap::DacOverride, OciCap::Fsetid, OciCap::Fowner,
            OciCap::Mknod, OciCap::NetRaw, OciCap::Setgid, OciCap::Setuid,
            OciCap::Setfcap, OciCap::Setpcap, OciCap::NetBindService,
            OciCap::SysChroot, OciCap::Kill, OciCap::AuditWrite,
        ] {
            translate_capability(cap).unwrap_or_else(|e| panic!("{cap} failed to translate: {e}"));
        }
    }

    #[test]
    fn test_translate_capability_sys_admin() {
        let translated = translate_capability(OciCap::SysAdmin).unwrap();
        assert_eq!(translated.to_string(), "CAP_SYS_ADMIN");
    }
}

/// The Docker-compatible default set, SPEC.md §8.1. Notably absent:
/// SysAdmin (mount/namespace creation — effectively root), SysPtrace,
/// SysModule, NetAdmin, DacReadSearch (enables open_by_handle_at, the
/// "Shocker" container-escape exploit).
pub const DEFAULT_CAPABILITIES: &[OciCap] = &[
    OciCap::Chown, OciCap::DacOverride, OciCap::Fsetid, OciCap::Fowner,
    OciCap::Mknod, OciCap::NetRaw, OciCap::Setgid, OciCap::Setuid,
    OciCap::Setfcap, OciCap::Setpcap, OciCap::NetBindService,
    OciCap::SysChroot, OciCap::Kill, OciCap::AuditWrite,
];

/// `--cap-add`/`--cap-drop` resolution against [`DEFAULT_CAPABILITIES`].
/// Drop wins over add when a capability appears in both lists (matches
/// Docker's own semantics: an explicit drop is a stronger signal than the
/// default inclusion). Pure function — the CLI flag PARSING that produces
/// `add`/`drop` is Phase 10's job; this is the resolution logic itself.
pub fn resolve_cap_add_drop(add: &[OciCap], drop: &[OciCap]) -> HashSet<OciCap> {
    let mut result: HashSet<OciCap> = DEFAULT_CAPABILITIES.iter().copied().collect();
    result.extend(add.iter().copied());
    for d in drop {
        result.remove(d);
    }
    result
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    #[test]
    fn test_default_capabilities_has_14_entries() {
        assert_eq!(DEFAULT_CAPABILITIES.len(), 14);
    }

    #[test]
    fn test_resolve_with_no_changes_returns_default() {
        let resolved = resolve_cap_add_drop(&[], &[]);
        assert_eq!(resolved, DEFAULT_CAPABILITIES.iter().copied().collect());
    }

    #[test]
    fn test_resolve_add_extends_default() {
        let resolved = resolve_cap_add_drop(&[OciCap::SysPtrace], &[]);
        assert!(resolved.contains(&OciCap::SysPtrace));
        assert!(resolved.contains(&OciCap::Chown)); // default still present
    }

    #[test]
    fn test_resolve_drop_removes_from_default() {
        let resolved = resolve_cap_add_drop(&[], &[OciCap::Kill]);
        assert!(!resolved.contains(&OciCap::Kill));
    }

    #[test]
    fn test_resolve_drop_wins_over_add_for_same_capability() {
        let resolved = resolve_cap_add_drop(&[OciCap::SysPtrace], &[OciCap::SysPtrace]);
        assert!(!resolved.contains(&OciCap::SysPtrace), "an explicit drop must win over an explicit add for the same cap");
    }
}
