# Phase 5 — Security Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestrel-security` (capabilities, `no_new_privs`, rlimits, `oom_score_adj`, seccomp filter building + notify) and a *minimal* `kestrel-init` (just `exec_into()` and `PR_SET_PDEATHSIG` — not the PID-1 reaper, which is Phase 8), per PROMPT.md's Phase 5 section, SPEC.md §8, and CHECKLIST.md's Phase 5 (20 tasks).

**Architecture:** `kestrel-security` is a pure library exposing `apply::apply_all(process, seccomp)`, composing five ordered, individually-irreversible steps. `kestrel-init` gets exactly one new capability: turning `apply_all()` + a real `execve()` into a single tested function, used both as `kestrel-init`'s eventual real job and as this phase's own strongest test vehicle. Every real type (`Process`, `LinuxCapabilities`, `PosixRlimit`, `LinuxSeccomp`) is consumed directly from `kestrel-oci`'s re-exports of `oci_spec::runtime` — this plan was written after reading that crate's actual vendored source, not assumed from PROMPT.md's abbreviated sketch, and several real field types differ from that sketch (documented inline per task).

**Tech Stack:** `caps` (capability sets), `libseccomp` (wraps the VM's `libseccomp-dev` via `libseccomp-sys`+`pkg-config`), `nix` (`prctl` feature for `no_new_privs`/`PR_SET_PDEATHSIG`, `resource` feature for `setrlimit`), `kestrel-oci` (spec types), `kestrel-ns` (dev-dep, `test_util::run_isolated`).

---

## Real-API corrections this plan makes relative to PROMPT.md's/SPEC.md's sketch

Read directly from `oci-spec-0.10.0`'s vendored source (`~/.cargo/registry/.../oci-spec-0.10.0/src/runtime/{process.rs,capability.rs}`) rather than assumed:

- `LinuxCapabilities`'s five set fields are **`Option<Capabilities>`** (`Capabilities = HashSet<Capability>`), not bare sets. `None` means "this spec didn't constrain this set at all" — `apply_capabilities` must treat that as a no-op for that specific set, not an error, and specifically must **not** touch the bounding set at all when `bounding` is `None` (as opposed to `Some(empty set)`, which legitimately means "drop everything").
- `User.uid`/`User.gid` are plain **`u32`** (default 0), not `Option<u32>` — the uid/gid-apply step in `apply_all` is unconditional.
- `Process.args`/`Process.env` are `Option<Vec<String>>`; `Process.rlimits` is `Option<Vec<PosixRlimit>>`; `Process.capabilities` is `Option<LinuxCapabilities>`; `Process.cwd` is a plain (non-optional) `PathBuf`; `Process.no_new_privileges` is `Option<bool>` (the spec's own toggle — `apply_all` must honor it, not hardcode always-on as PROMPT.md's sketch does); `Process.oom_score_adj` is `Option<i32>`, directly on `Process` (no separate threading needed).
- `oci_spec::runtime::Capability` (the enum *inside* `Capabilities`) is a **different type** from the `caps` crate's own `Capability` enum. `oci_spec`'s has a `strum`-derived `Display` producing e.g. `"SYS_ADMIN"` (no `CAP_` prefix — confirmed by that crate's own test suite). `caps::Capability`'s variants are literally named `CAP_SYS_ADMIN` etc. (prefix baked into the variant name), and its `FromStr` expects exactly that prefixed form. A real translation function is required — Task 2 builds and tests it.
- `PosixRlimitType`'s 15 variants (`RlimitCpu`, `RlimitFsize`, `RlimitData`, `RlimitStack`, `RlimitCore`, `RlimitRss`, `RlimitNproc`, `RlimitNofile`, `RlimitMemlock`, `RlimitAs`, `RlimitLocks`, `RlimitSigpending`, `RlimitMsgqueue`, `RlimitNice`, `RlimitRtprio`, `RlimitRttime`) need translating to `nix::sys::resource::Resource`'s `RLIMIT_*` variants — another real translation function, Task 5.
- `ScmpFilterContext::new_filter` (PROMPT.md's sketch) is a **deprecated alias** for `ScmpFilterContext::new` — this plan uses `new`.

---

## File Structure

```
crates/kestrel-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── caps.rs       — translate_capability, apply_capabilities, DEFAULT_CAPABILITIES, resolve_cap_add_drop
│   ├── rlimits.rs     — translate_rlimit_type, apply_rlimits, set_oom_score_adj
│   ├── noprivs.rs      — set_no_new_privs (thin wrapper, documents the irreversibility)
│   ├── seccomp.rs      — install_seccomp, DEFAULT_SECCOMP_PROFILE loader
│   ├── notify.rs        — NotifyEvent, handle_one_notification, run_notify_loop
│   └── apply.rs          — apply_all
└── tests/
    ├── caps.rs
    ├── rlimits.rs
    ├── seccomp.rs
    └── notify.rs

crates/kestrel-init/
├── Cargo.toml
├── src/
│   ├── main.rs        — unchanged stub (still "not yet implemented" — Phase 8 wires the real binary)
│   ├── lib.rs           — NEW: pub mod exec; pub mod pdeathsig;
│   ├── exec.rs           — exec_into()
│   └── pdeathsig.rs      — set_parent_death_signal()
└── tests/
    ├── pdeathsig.rs
    ├── fixtures/
    │   ├── setuid_check.rs     — [[bin]] fixture: exit(0) if non-root euid, exit(1) if root
    │   └── denied_syscall.rs   — [[bin]] fixture: exit(0) if a syscall is blocked as configured, exit(1) if it unexpectedly succeeds
    └── exec_via_kestrel_init.rs

profiles/seccomp/default.json   — ~44-syscall Docker-equivalent deny profile
```

---

## Task 1: `kestrel-security` crate scaffolding

**Files:**
- Modify: `crates/kestrel-security/Cargo.toml`
- Modify: `crates/kestrel-security/src/lib.rs`

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "kestrel-security"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
nix = { workspace = true, features = ["prctl", "resource", "user"] }
libc.workspace = true
caps = "0.5"
libseccomp = "0.3"
kestrel-oci = { path = "../kestrel-oci" }

[dev-dependencies]
kestrel-ns = { path = "../kestrel-ns" }
```

Before trusting the `caps`/`libseccomp` version pins above, run (inside the VM) `cargo add caps libseccomp --dry-run -p kestrel-security` to confirm the actual latest resolvable versions, and adjust if different — this project's established practice is to verify against what actually resolves, not a guessed pin. If `libseccomp`'s build fails because `pkg-config` can't find `libseccomp-dev`, run `pkg-config --modversion libseccomp` first to confirm it's actually on the VM (Phase 0's provisioning installed it, but confirm rather than assume).

- [ ] **Step 2: Write lib.rs**

```rust
#![deny(clippy::undocumented_unsafe_blocks)]

//! Capabilities, no_new_privs, rlimits, and seccomp for kestrel. See
//! docs/superpowers/specs/2026-08-03-phase5-security-design.md.

pub mod caps;
```

Only `caps` declared for now — each later task adds one `pub mod` line as it creates its file, keeping the crate always buildable.

- [ ] **Step 3: Confirm builds**

Create a minimal placeholder `crates/kestrel-security/src/caps.rs` with just a doc comment, run `cargo build -p kestrel-security` inside the VM, confirm it succeeds. Task 2 overwrites the placeholder with real content.

---

## Task 2: Capability translation layer (`caps.rs`, part 1)

**Files:**
- Create: `crates/kestrel-security/src/caps.rs`

Pure, unprivileged. Bridges `oci_spec::runtime::Capability` (the spec type) and `caps::Capability` (the crate that actually manipulates kernel capability sets).

- [ ] **Step 1: Write the translation function and its tests**

```rust
// crates/kestrel-security/src/caps.rs

use std::collections::HashSet;
use std::str::FromStr;

use anyhow::{Context, Result};
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

#[cfg(test)]
mod translate_tests {
    use super::*;
    use kestrel_oci::runtime::Capability as OciCap;

    /// Every variant this project actually uses in DEFAULT_CAPABILITIES
    /// (Task 4) must translate successfully — the specific set most likely
    /// to matter in practice.
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
```

- [ ] **Step 2: Run**

Run: `cargo test -p kestrel-security translate`
Expected: 2 passed. If any variant fails to translate, that's a real finding (either crate's coverage genuinely differs) — investigate and document rather than silently dropping the failing capability from `DEFAULT_CAPABILITIES`.

---

## Task 3: `apply_capabilities()` (`caps.rs`, part 2)

**Files:**
- Modify: `crates/kestrel-security/src/caps.rs`
- Modify: `crates/kestrel-security/src/lib.rs`
- Create: `crates/kestrel-security/tests/caps.rs`

- [ ] **Step 1: Implement, honoring the real `Option<Capabilities>` typing**

Append to `crates/kestrel-security/src/caps.rs`:

```rust
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

    if let Some(permitted) = c.effective() {
        // `effective` is applied via CapSet::Effective below; this branch
        // intentionally left for permitted/inheritable which follow.
        let _ = permitted;
    }
    if let Some(permitted) = c.permitted() {
        ::caps::set(None, CapSet::Permitted, &translate_set(permitted)?).context("setting permitted set")?;
    }
    if let Some(inheritable) = c.inheritable() {
        ::caps::set(None, CapSet::Inheritable, &translate_set(inheritable)?).context("setting inheritable set")?;
    }
    if let Some(effective) = c.effective() {
        ::caps::set(None, CapSet::Effective, &translate_set(effective)?).context("setting effective set")?;
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
```

Fix the accidental dead `if let Some(permitted) = c.effective() { ... }` block above before finalizing — it was a placeholder to mark where the four non-bounding sets go; replace it with nothing (delete it entirely), since the four `if let Some(...)` blocks immediately below already cover permitted/inheritable/effective/ambient correctly. This is flagged explicitly so the implementer doesn't ship dead code.

- [ ] **Step 2: Wire into lib.rs** — already `pub mod caps;` from Task 1, no change needed.

- [ ] **Step 3: Write the root-gated test**

```rust
// crates/kestrel-security/tests/caps.rs

use kestrel_oci::runtime::{Capability as OciCap, LinuxCapabilitiesBuilder};
use kestrel_security::caps::apply_capabilities;

#[test]
#[ignore = "requires root"]
fn test_caps_dropped_blocks_mount() {
    kestrel_ns::test_util::run_isolated(|| {
        // Keep everything BUT SysAdmin in the bounding set — the OCI
        // default-ish shape without the one capability mount(2) needs.
        let keep: Vec<OciCap> = kestrel_security::caps::DEFAULT_CAPABILITIES
            .iter()
            .copied()
            .filter(|c| *c != OciCap::SysAdmin)
            .collect();
        let bounding: kestrel_oci::runtime::Capabilities = keep.iter().copied().collect();

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
        // gate mount() at this point. Attempting a real mount without
        // CAP_SYS_ADMIN in the bounding/effective set must fail EPERM.
        use nix::mount::{mount, MsFlags};
        let err = mount(None::<&str>, "/tmp", None::<&str>, MsFlags::MS_REMOUNT, None::<&str>)
            .expect_err("mount() must fail once CAP_SYS_ADMIN is dropped");
        assert_eq!(err, nix::errno::Errno::EPERM);
    });
}

#[test]
#[ignore = "requires root"]
fn test_apply_capabilities_none_is_a_no_op() {
    kestrel_ns::test_util::run_isolated(|| {
        apply_capabilities(None).expect("None must be a clean no-op, not an error");
        // A real mount must STILL work — proving nothing was dropped.
        use nix::mount::{mount, MsFlags};
        mount(None::<&str>, "/tmp", None::<&str>, MsFlags::MS_REMOUNT, None::<&str>)
            .expect("mount() must still work when apply_capabilities(None) touched nothing");
    });
}
```

- [ ] **Step 4: Run**

Run: `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-security --test caps -- --ignored`
Expected: 2 passed.

---

## Task 4: `DEFAULT_CAPABILITIES` and `resolve_cap_add_drop()`

**Files:**
- Modify: `crates/kestrel-security/src/caps.rs`

Pure, unprivileged.

- [ ] **Step 1: Implement with tests**

Append to `crates/kestrel-security/src/caps.rs`:

```rust
use kestrel_oci::runtime::Capability as OciCap;

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
```

- [ ] **Step 2: Run**

Run: `cargo test -p kestrel-security caps::`
Expected: 6 new tests pass (10 total in the file so far).

---

## Task 5: rlimits and `oom_score_adj` (`rlimits.rs`)

**Files:**
- Create: `crates/kestrel-security/src/rlimits.rs`
- Modify: `crates/kestrel-security/src/lib.rs`
- Create: `crates/kestrel-security/tests/rlimits.rs`

Setting your OWN rlimits/oom_score_adj downward, or within your existing hard limit, doesn't need root — only *raising a hard limit* needs `CAP_SYS_RESOURCE`. So most of this is unprivileged-testable; only the "raise beyond current hard limit" edge case needs root.

- [ ] **Step 1: Implement rlimit type translation and `apply_rlimits`**

```rust
// crates/kestrel-security/src/rlimits.rs

use anyhow::{Context, Result};
use kestrel_oci::runtime::{PosixRlimit, PosixRlimitType};
use nix::sys::resource::{setrlimit, Resource};

/// `oci_spec`'s 15 `PosixRlimitType` variants map 1:1 onto `nix`'s
/// `Resource::RLIMIT_*` — verified by reading both enums directly (not
/// assumed). Kept as an explicit `match` (not a derive/macro) so a future
/// kernel/spec addition to either side fails to compile here instead of
/// silently mismapping.
fn translate_rlimit_type(t: PosixRlimitType) -> Resource {
    match t {
        PosixRlimitType::RlimitCpu => Resource::RLIMIT_CPU,
        PosixRlimitType::RlimitFsize => Resource::RLIMIT_FSIZE,
        PosixRlimitType::RlimitData => Resource::RLIMIT_DATA,
        PosixRlimitType::RlimitStack => Resource::RLIMIT_STACK,
        PosixRlimitType::RlimitCore => Resource::RLIMIT_CORE,
        PosixRlimitType::RlimitRss => Resource::RLIMIT_RSS,
        PosixRlimitType::RlimitNproc => Resource::RLIMIT_NPROC,
        PosixRlimitType::RlimitNofile => Resource::RLIMIT_NOFILE,
        PosixRlimitType::RlimitMemlock => Resource::RLIMIT_MEMLOCK,
        PosixRlimitType::RlimitAs => Resource::RLIMIT_AS,
        PosixRlimitType::RlimitLocks => Resource::RLIMIT_LOCKS,
        PosixRlimitType::RlimitSigpending => Resource::RLIMIT_SIGPENDING,
        PosixRlimitType::RlimitMsgqueue => Resource::RLIMIT_MSGQUEUE,
        PosixRlimitType::RlimitNice => Resource::RLIMIT_NICE,
        PosixRlimitType::RlimitRtprio => Resource::RLIMIT_RTPRIO,
        PosixRlimitType::RlimitRttime => Resource::RLIMIT_RTTIME,
    }
}

/// Applies every rlimit in `limits` to the current process. Must run
/// BEFORE the uid drop in `apply_all` — some limits cannot be raised once
/// privileges are dropped (CAP_SYS_RESOURCE is needed to raise a hard
/// limit, and that capability may itself be dropped by the bounding-set
/// step that runs after this one).
pub fn apply_rlimits(limits: Option<&[PosixRlimit]>) -> Result<()> {
    let Some(limits) = limits else { return Ok(()) };
    for rl in limits {
        let resource = translate_rlimit_type(rl.typ());
        setrlimit(resource, rl.soft(), rl.hard())
            .with_context(|| format!("setrlimit({:?}, soft={}, hard={})", rl.typ(), rl.soft(), rl.hard()))?;
    }
    Ok(())
}

/// Writes `/proc/self/oom_score_adj`. Range is -1000 (never killed first)
/// to 1000 (killed first); lowering below a value previously set by a
/// CAP_SYS_RESOURCE-holding process requires that same capability, but
/// setting your own to anything from your current value or higher never
/// needs privilege.
pub fn set_oom_score_adj(score: i32) -> Result<()> {
    anyhow::ensure!((-1000..=1000).contains(&score), "oom_score_adj {score} out of range [-1000, 1000]");
    std::fs::write("/proc/self/oom_score_adj", score.to_string())
        .with_context(|| format!("writing oom_score_adj={score}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_rlimit_type_covers_every_variant() {
        // Exhaustive match above already guarantees compile-time coverage;
        // this test just confirms a couple of the mappings are the
        // expected, non-transposed ones (a translation bug that swapped
        // e.g. RLIMIT_CPU and RLIMIT_NPROC would still compile).
        assert_eq!(translate_rlimit_type(PosixRlimitType::RlimitNofile), Resource::RLIMIT_NOFILE);
        assert_eq!(translate_rlimit_type(PosixRlimitType::RlimitCpu), Resource::RLIMIT_CPU);
    }
}
```

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod caps;
pub mod rlimits;
```

- [ ] **Step 3: Write unprivileged + root-gated tests**

```rust
// crates/kestrel-security/tests/rlimits.rs

use kestrel_oci::runtime::{PosixRlimitBuilder, PosixRlimitType};
use kestrel_security::rlimits::{apply_rlimits, set_oom_score_adj};

#[test]
fn test_apply_rlimits_none_is_a_no_op() {
    apply_rlimits(None).expect("None must be a clean no-op");
}

#[test]
fn test_apply_rlimits_lowers_nofile_limit() {
    kestrel_ns::test_util::run_isolated(|| {
        let current = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        let lower_soft = current.0.saturating_sub(1).max(64);
        let limit = PosixRlimitBuilder::default()
            .typ(PosixRlimitType::RlimitNofile)
            .soft(lower_soft)
            .hard(current.1) // hard limit unchanged — no privilege needed
            .build()
            .unwrap();
        apply_rlimits(Some(&[limit])).expect("lowering an rlimit never needs privilege");

        let after = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        assert_eq!(after.0, lower_soft);
    });
}

#[test]
fn test_set_oom_score_adj_rejects_out_of_range() {
    assert!(set_oom_score_adj(1001).is_err());
    assert!(set_oom_score_adj(-1001).is_err());
}

#[test]
fn test_set_oom_score_adj_writes_own_proc_file() {
    kestrel_ns::test_util::run_isolated(|| {
        set_oom_score_adj(500).expect("setting your own oom_score_adj upward from the default needs no privilege");
        let content = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        assert_eq!(content.trim(), "500");
    });
}
```

These four don't strictly need root, but stay wrapped in `run_isolated` anyway per this project's fork-isolation convention for any test that mutates real per-process kernel state, so one test's rlimit/oom_score_adj change can never bleed into another test running in the same `cargo test` binary.

- [ ] **Step 4: Run**

Run: `cargo test -p kestrel-security --test rlimits`
Expected: 4 passed (no `--ignored` needed — confirm none of these actually require root; if `test_apply_rlimits_lowers_nofile_limit` unexpectedly fails unprivileged in the VM's specific config, mark only that one `#[ignore = "requires root"]` rather than the whole file, and note why).

---

## Task 6: `no_new_privs` (`noprivs.rs`)

**Files:**
- Create: `crates/kestrel-security/src/noprivs.rs`
- Modify: `crates/kestrel-security/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-security/src/noprivs.rs

use anyhow::{Context, Result};

/// Sets PR_SET_NO_NEW_PRIVS on the calling thread. IRREVERSIBLE for the
/// lifetime of the process (and everything it execve()s). Must run before
/// seccomp installation (an unprivileged process may only load a seccomp
/// filter once this is set), and permanently prevents setuid/setcap
/// binaries execve()'d afterward from elevating.
pub fn set_no_new_privs() -> Result<()> {
    nix::sys::prctl::set_no_new_privs().context("prctl(PR_SET_NO_NEW_PRIVS, 1)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_no_new_privs_is_observable_afterward() {
        kestrel_ns::test_util::run_isolated(|| {
            assert!(!nix::sys::prctl::get_no_new_privs().unwrap(), "should start unset in a fresh process");
            set_no_new_privs().expect("set_no_new_privs");
            assert!(nix::sys::prctl::get_no_new_privs().unwrap(), "must be observably set afterward");
        });
    }
}
```

If `nix::sys::prctl::set_no_new_privs`/`get_no_new_privs` don't take exactly zero arguments in the resolved `nix` version (verify via `cargo doc -p nix --open` or grepping the vendored source, same discipline as every prior phase), adjust the call accordingly — docs.rs's module listing confirms both functions exist but not their exact signatures.

Needs `kestrel-ns` as a dev-dependency for this crate's `#[cfg(test)]` unit test too (not just integration tests in `tests/`) — add `kestrel-ns = { path = "../kestrel-ns" }` to `[dev-dependencies]` if not already resolvable for unit tests (it should already be, since Cargo dev-deps apply to both `tests/` and in-crate `#[cfg(test)]`).

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod caps;
pub mod noprivs;
pub mod rlimits;
```

- [ ] **Step 3: Run**

Run: `cargo test -p kestrel-security noprivs`
Expected: 1 passed.

---

## Task 7: Default seccomp profile (`profiles/seccomp/default.json`)

**Files:**
- Create: `profiles/seccomp/default.json`
- Create: `crates/kestrel-security/src/seccomp.rs` (loader only in this task; filter-building is Task 8)
- Modify: `crates/kestrel-security/src/lib.rs`

- [ ] **Step 1: Write the default profile JSON**

Per SPEC.md §8.3: "denies ~44 syscalls including kexec_load, init_module, mount, pivot_root, bpf, perf_event_open, ptrace (unless allowed), add_key, keyctl, userfaultfd, clone with namespace flags." Runc's own `default.json` (widely published, e.g. in the `opencontainers/runtime-spec` and Docker's `contrib/seccomp` repos) is the standard reference shape for this — a `defaultAction: SCMP_ACT_ERRNO`, an explicit `SCMP_ACT_ALLOW` list for the ~300 permitted syscalls is the more common real-world approach (default-deny-then-allowlist is what Docker/runc actually ship), but SPEC.md's own framing ("denies ~44 syscalls") describes a default-ALLOW-then-denylist shape instead. Follow SPEC.md's framing since it's this project's authoritative design doc: `defaultAction: "SCMP_ACT_ALLOW"`, with an explicit syscalls list of `action: "SCMP_ACT_ERRNO"` entries for the denied set. Write:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
        "mount", "umount2", "pivot_root", "chroot",
        "bpf", "perf_event_open",
        "add_key", "request_key", "keyctl",
        "userfaultfd",
        "swapon", "swapoff",
        "reboot", "sethostname", "setdomainname",
        "acct", "quotactl", "nfsservctl",
        "iopl", "ioperm",
        "settimeofday", "stime", "adjtimex", "clock_settime", "clock_adjtime",
        "ptrace", "process_vm_readv", "process_vm_writev",
        "kcmp", "lookup_dcookie",
        "open_by_handle_at", "name_to_handle_at",
        "unshare", "setns",
        "syslog",
        "vhangup",
        "uselib",
        "personality",
        "modify_ldt", "vm86", "vm86old",
        "move_pages", "mbind", "set_mempolicy", "migrate_pages"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

Count the `names` array and confirm it's in the "~44" ballpark SPEC.md describes (it should land in the low-to-mid 40s — adjust the list slightly if it's far off, but don't pad it artificially just to hit an exact number; the point is the denylist is representative of the real Docker-equivalent default, not that it hits exactly 44). `clone` itself is deliberately NOT in this simple name-based denylist — SPEC.md's "clone with namespace flags" needs an argument-comparison rule (Task 8 territory: `add_rule_conditional` with an `ScmpArgCompare` masking the `CLONE_NEW*` bits), not a blanket deny (a plain `clone()` without namespace flags is how threads are created and must stay allowed).

- [ ] **Step 2: Write the loader**

```rust
// crates/kestrel-security/src/seccomp.rs

use std::path::Path;

use anyhow::{Context, Result};
use kestrel_oci::runtime::LinuxSeccomp;

/// Loads and parses `profiles/seccomp/default.json` (relative to the
/// workspace root) into a `LinuxSeccomp`, using kestrel-oci's existing
/// serde support for the runtime-spec types.
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
```

Confirm `kestrel-oci`'s `LinuxSeccomp` type (re-exported from `oci_spec::runtime`) actually has `.syscalls()` and whatever other getters this test needs — read `kestrel-oci/src/lib.rs`'s `runtime` module list (already confirms `LinuxSeccomp` is exported) and, if needed, the vendored `oci-spec-0.10.0` source for its exact field/getter names, same verification discipline as every type referenced elsewhere in this plan.

- [ ] **Step 3: Add `serde_json` dependency and wire into lib.rs**

Add `serde_json.workspace = true` to `crates/kestrel-security/Cargo.toml`'s `[dependencies]`.

```rust
pub mod caps;
pub mod noprivs;
pub mod rlimits;
pub mod seccomp;
```

- [ ] **Step 4: Run**

Run: `cargo test -p kestrel-security seccomp::loader_tests`
Expected: 1 passed.

---

## Task 8: `install_seccomp()` — filter building and loading

**Files:**
- Modify: `crates/kestrel-security/src/seccomp.rs`
- Create: `crates/kestrel-security/tests/seccomp.rs`

`kestrel-oci`'s real seccomp types (read directly from
`oci-spec-0.10.0/src/runtime/linux.rs:1068-1387`, not guessed) are now
nailed down, so this task's translation functions have real bodies below
instead of placeholders:

- `LinuxSeccompAction` (9 variants): `ScmpActKill`, `ScmpActKillThread`,
  `ScmpActKillProcess`, `ScmpActTrap`, `ScmpActErrno`, `ScmpActNotify`,
  `ScmpActTrace`, `ScmpActLog`, `ScmpActAllow` (default). Has its own
  `.as_u32(errno_ret: Option<u32>) -> u32` — meaning `kestrel-security`
  could in principle bypass `libseccomp`'s `ScmpAction` entirely and build
  raw BPF, but this plan stays on `libseccomp`'s safe API surface per the
  design doc, translating to its `ScmpAction` enum instead.
- `Arch` (21 variants, `#[repr(u32)]` with real kernel `AUDIT_ARCH_*`
  values) — only `ScmpArchX86_64`/`ScmpArchAarch64` matter for this
  project's actual target platforms (the VM is aarch64, x86_64 is the
  other realistic deployment target), but the translation function covers
  all 21 for completeness and because an exhaustive `match` catches a
  future oci-spec upgrade adding a variant at compile time.
- `LinuxSeccompOperator` (7 variants: `ScmpCmpNe=1, ScmpCmpLt=2,
  ScmpCmpLe=3, ScmpCmpEq=4, ScmpCmpGe=5, ScmpCmpGt=6, ScmpCmpMaskedEq=7`)
  for `LinuxSeccompArg`'s `op` field.
- `LinuxSyscall { names: Vec<String>, action: LinuxSeccompAction,
  errno_ret: Option<u32>, args: Option<Vec<LinuxSeccompArg>> }` and
  `LinuxSeccompArg { index: usize, value: u64, value_two: Option<u64>, op:
  LinuxSeccompOperator }` — both plain (non-`Option`-wrapped internally)
  structs, all fields accessed via `getset`'s `get`/`get_copy` getters.

`libseccomp`'s own `ScmpAction`/`ScmpArch`/`ScmpCompareOp`/`ScmpArgCompare`
side of the translation is the one part of this task that couldn't be
pinned down from vendored source (it's a Linux-only crate with a
`pkg-config` build dependency on `libseccomp-dev`, so it has never actually
been fetched into this repo's cargo registry cache — even on the Lima VM,
until `cargo build -p kestrel-security` runs for the first time). The match
arms below are written with high confidence based on `libseccomp-rs`'s
well-established, stable public API shape, but **must be verified against
`cargo doc -p libseccomp --open` (or the vendored source under
`~/.cargo/registry/src/*/libseccomp-*/`) inside the VM before trusting
variant names exactly** — if any arm doesn't compile, fix the variant name
to match what's actually there rather than restructuring the translation
approach itself, which is correct regardless of minor naming drift.

- [ ] **Step 1: Implement, per SPEC.md §8.3 (using `ScmpFilterContext::new`, not the deprecated `new_filter`)**

Append to `crates/kestrel-security/src/seccomp.rs`:

```rust
use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::bail;
use kestrel_oci::runtime::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompOperator};
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
    let mut ctx = ScmpFilterContext::new(default_action).context("creating seccomp filter context")?;

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
        // a successful ctx.load(); ScmpFd is a raw fd type with no
        // ownership semantics of its own, so wrapping it in OwnedFd here is
        // what actually gives it correct close-on-drop behavior, matching
        // this crate's convention of using owned fd types at API
        // boundaries. libseccomp's own docs note the fd must not be closed
        // by anything other than through this ownership transfer.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Some(owned))
    } else {
        Ok(None)
    }
}

/// `errno_ret` is only meaningful for `ScmpActErrno`/`ScmpActTrace` (see
/// `LinuxSeccompAction::as_u32`'s own doc comment) — passed through as
/// `Some(n)` for those two, ignored otherwise. Defaults to `EPERM` if the
/// spec left `errno_ret` unset on an `Errno` action, matching
/// `LinuxSeccompAction::as_u32`'s own fallback (`0x00050001`, i.e. errno 1
/// = EPERM) rather than inventing a different default.
fn translate_action(action: LinuxSeccompAction, errno_ret: Option<u32>) -> Result<ScmpAction> {
    let errno = errno_ret.unwrap_or(libc::EPERM as u32) as i32;
    Ok(match action {
        LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => ScmpAction::KillThread,
        LinuxSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
        LinuxSeccompAction::ScmpActTrap => ScmpAction::Trap,
        LinuxSeccompAction::ScmpActErrno => ScmpAction::Errno(errno),
        LinuxSeccompAction::ScmpActNotify => ScmpAction::Notify,
        LinuxSeccompAction::ScmpActTrace => ScmpAction::Trace(errno_ret.unwrap_or(0)),
        LinuxSeccompAction::ScmpActLog => ScmpAction::Log,
        LinuxSeccompAction::ScmpActAllow => ScmpAction::Allow,
    })
}

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
        // The remaining 4 (Parisc/Parisc64/Riscv64/Loongarch64/M68k/Sh/Sheb
        // — whichever this specific libseccomp version doesn't expose) may
        // not have a 1:1 ScmpArch variant in every libseccomp-rs release;
        // bail loudly rather than silently dropping the architecture from
        // the filter if one is genuinely missing, since a missing arch on
        // a mismatched-arch syscall means the filter doesn't apply at all
        // to that arch, not that it fails safe.
        other => bail!("no ScmpArch mapping for {other:?} in this libseccomp-rs version — verify the real variant list and extend this match"),
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
        LinuxSeccompOperator::ScmpCmpMaskedEq => ScmpCompareOp::MaskedEqual(0), // mask filled in by caller
    }
}

fn translate_arg_comparisons(args: &[LinuxSeccompArg]) -> Result<Vec<ScmpArgCompare>> {
    args.iter()
        .map(|a| {
            let op = if matches!(a.op(), LinuxSeccompOperator::ScmpCmpMaskedEq) {
                // MaskedEqual carries the mask as its own value in
                // libseccomp's ScmpCompareOp, whereas the OCI spec encodes
                // it as `value` (the mask) + `value_two` (the value to
                // compare against after masking) on LinuxSeccompArg —
                // different shapes for the same concept, verify this
                // exact mapping against ScmpCompareOp::MaskedEqual's real
                // constructor/field meaning before trusting it.
                ScmpCompareOp::MaskedEqual(a.value())
            } else {
                translate_operator(a.op())
            };
            let compare_value = if matches!(a.op(), LinuxSeccompOperator::ScmpCmpMaskedEq) {
                a.value_two().unwrap_or(0)
            } else {
                a.value()
            };
            // Verify ScmpArgCompare's real constructor signature (this
            // plan assumes `ScmpArgCompare::new(arg_index, op, value)` —
            // confirm against the resolved crate; the scmp_cmp! macro
            // mentioned in libseccomp's docs is an alternative call shape
            // for the same thing if the plain constructor differs).
            Ok(ScmpArgCompare::new(a.index() as u32, op, compare_value))
        })
        .collect()
}
```

Write unit tests translating every `LinuxSeccompAction`/`Arch`/`LinuxSeccompOperator` variant this project actually targets (all 9 actions; at minimum `ScmpArchX86_64`/`ScmpArchAarch64` for architectures, matching this project's real deployment targets; all 7 operators), mirroring Task 2's `test_translate_capability_covers_the_default_set` pattern — these tests will immediately surface any variant-name mismatch against the real `libseccomp` crate.

- [ ] **Step 2: Write the root-gated tests**

```rust
// crates/kestrel-security/tests/seccomp.rs

use kestrel_oci::runtime::{LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, Arch};
use kestrel_security::seccomp::install_seccomp;

fn deny_personality_profile() -> kestrel_oci::runtime::LinuxSeccomp {
    let rule = LinuxSyscallBuilder::default()
        .names(vec!["personality".to_string()])
        .action(LinuxSeccompAction::ScmpActErrno)
        .errno_ret(libc::EPERM as u32)
        .build()
        .unwrap();
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
        .syscalls(vec![rule])
        .build()
        .unwrap()
}

#[test]
#[ignore = "requires root"]
fn test_seccomp_blocks_syscall_with_configured_errno() {
    kestrel_ns::test_util::run_isolated(|| {
        install_seccomp(&deny_personality_profile()).expect("install_seccomp");
        let ret = unsafe { libc::personality(0xffffffff) };
        assert_eq!(ret, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    });
}

#[test]
#[ignore = "requires root"]
fn test_install_seccomp_unknown_syscall_name_is_skipped_not_fatal() {
    kestrel_ns::test_util::run_isolated(|| {
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["this_syscall_does_not_exist_kestrel_test".to_string(), "personality".to_string()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EPERM as u32)
            .build()
            .unwrap();
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();
        install_seccomp(&profile).expect("must not fail on an unknown syscall name mixed in with a real one");
        // The real name in the same rule must still have been applied.
        let ret = unsafe { libc::personality(0xffffffff) };
        assert_eq!(ret, -1);
    });
}
```

Confirm `LinuxSeccompBuilder`/`LinuxSyscallBuilder` are the real generated builder type names (derive_builder's convention, matching every other `*Builder` already used elsewhere in this codebase, e.g. `LinuxCapabilitiesBuilder` in Task 3) before trusting this verbatim.

- [ ] **Step 3: Run**

Run: `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-security --test seccomp -- --ignored`
Expected: 2 passed.

---

## Task 9: Seccomp notify (`notify.rs`)

**Files:**
- Create: `crates/kestrel-security/src/notify.rs`
- Modify: `crates/kestrel-security/src/lib.rs`
- Create: `crates/kestrel-security/tests/notify.rs`

Builds the fd-decode-respond loop described in the design doc §4a — real, tested, no `kestreld` dependency.

- [ ] **Step 1: Implement**

```rust
// crates/kestrel-security/src/notify.rs

use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::SystemTime;

use anyhow::{Context, Result};
use libseccomp::{notify_id_valid, ScmpNotifReq, ScmpNotifResp};

#[derive(Debug, Clone)]
pub struct NotifyEvent {
    pub pid: u32,
    pub syscall: String,
    pub args: [u64; 6],
    pub timestamp: SystemTime,
}

/// Blocks until one seccomp-notify request arrives on `fd`, decodes it,
/// responds with ENOSYS (so the calling process's blocked syscall returns
/// a real, well-defined error rather than hanging forever), and returns
/// the decoded event. The TOCTOU check (`notify_id_valid`) is required by
/// libseccomp's own documented usage pattern — the notifying process may
/// have been killed or the fd may have been reused between the request
/// arriving and this function responding to it; skipping the check risks
/// responding to the wrong process.
pub fn handle_one_notification(fd: BorrowedFd) -> Result<NotifyEvent> {
    let req = ScmpNotifReq::receive(fd.as_raw_fd()).context("receiving seccomp notif request")?;

    notify_id_valid(fd.as_raw_fd(), req.id).context("notify_id_valid check failed — request is stale")?;

    let event = NotifyEvent {
        pid: req.pid,
        syscall: req.data.syscall.get_name().unwrap_or_else(|_| format!("syscall#{:?}", req.data.syscall)),
        args: req.data.args,
        timestamp: SystemTime::now(),
    };

    let resp = ScmpNotifResp::new_error(req.id, libc::ENOSYS);
    resp.respond(fd.as_raw_fd()).context("responding to seccomp notif request")?;

    Ok(event)
}

/// Repeatedly calls [`handle_one_notification`], invoking `on_event` for
/// each decoded notification, until `handle_one_notification` returns an
/// error (e.g. the fd was closed because the filtered process exited).
/// `kestreld` (Phase 9) is expected to call this from its own thread and
/// forward each event over SSE — this function itself has no HTTP/async
/// dependency.
pub fn run_notify_loop(fd: BorrowedFd, mut on_event: impl FnMut(NotifyEvent)) -> Result<()> {
    loop {
        match handle_one_notification(fd) {
            Ok(event) => on_event(event),
            Err(e) => {
                tracing::info!(error = %e, "notify loop ending (fd likely closed)");
                return Ok(());
            }
        }
    }
}
```

The exact field/method names on `ScmpNotifReq`/`ScmpNotifResp` (`.receive()`, `.id`, `.pid`, `.data.syscall`, `.data.args`, `ScmpNotifResp::new_error`, `.respond()`) are written from the design doc's own explicit caveat that these need final confirmation against the resolved `libseccomp` crate version — **verify every one of these against `cargo doc -p libseccomp --open` (or the vendored source under `~/.cargo/registry/src/*/libseccomp-*/`) inside the VM before writing the real implementation**, and correct any that don't match. This is the single highest-uncertainty API surface in this entire plan; budget real verification time for it rather than assuming the sketch above is exact.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod caps;
pub mod noprivs;
pub mod notify;
pub mod rlimits;
pub mod seccomp;
```

- [ ] **Step 3: Write the root-gated test**

```rust
// crates/kestrel-security/tests/notify.rs

use std::os::fd::AsFd;

use kestrel_oci::runtime::{Arch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};
use kestrel_security::notify::handle_one_notification;
use kestrel_security::seccomp::install_seccomp;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

#[test]
#[ignore = "requires root"]
fn test_handle_one_notification_captures_pid_syscall_and_args() {
    kestrel_ns::test_util::run_isolated(|| {
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["personality".to_string()])
            .action(LinuxSeccompAction::ScmpActNotify)
            .build()
            .unwrap();
        let profile = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();

        // install_seccomp affects only the CALLING process/thread's own
        // filter — a fork() inherits an installed filter, so the notify
        // fd obtained here stays valid and meaningful for a child that
        // forks AFTER this point, which is exactly what we need: a
        // separate process whose notified syscall we can wait on and
        // whose pid we can independently confirm in the decoded event.
        let notify_fd = install_seccomp(&profile).expect("install_seccomp").expect("profile uses notify, fd must be Some");

        // SAFETY: fork() duplicates the process; the child below only
        // calls the one notified syscall and exits, no other
        // non-async-signal-safe work happens between fork and exit,
        // matching kestrel-ns's own run_isolated convention for what's
        // safe in this window.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let _ = unsafe { libc::personality(0xffffffff) }; // blocks until the parent responds below
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                let event = handle_one_notification(notify_fd.as_fd()).expect("handle_one_notification");
                assert_eq!(event.pid, child.as_raw() as u32, "event must report the actual notified process's pid");
                assert_eq!(event.syscall, "personality");

                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(p, 0)) if p == child => {}
                    other => panic!("notified child did not exit cleanly after being responded to: {other:?}"),
                }
            }
        }
    });
}
```

Confirm `Pid` import above is actually used or remove it — included here defensively since `ForkResult::Parent { child }`'s type may or may not already bring `Pid` into scope depending on how the match binds it; delete the explicit `use nix::unistd::Pid;` if the compiler flags it as unused once this is actually implemented.

- [ ] **Step 4: Run**

Run: `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-security --test notify -- --ignored`
Expected: 1 passed.

---

## Task 10: `apply_all()` (`apply.rs`)

**Files:**
- Create: `crates/kestrel-security/src/apply.rs`
- Modify: `crates/kestrel-security/src/lib.rs`

- [ ] **Step 1: Implement the ordered pipeline**

```rust
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
    let user = p.user();
    if let Some(additional) = user.additional_gids().as_deref() {
        if !additional.is_empty() {
            let gids: Vec<Gid> = additional.iter().map(|g| Gid::from_raw(*g)).collect();
            setgroups(&gids).context("setgroups")?;
        }
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
```

Verify `nix::unistd::{setgroups, setresgid, setresuid, Gid, Uid}`'s exact signatures against the resolved `nix` version — `kestrel-ns/src/idmap.rs` (Phase 2) already uses `setresuid`/`setresgid` successfully, so cross-check the call shape used there rather than re-deriving from scratch.

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod apply;
pub mod caps;
pub mod noprivs;
pub mod notify;
pub mod rlimits;
pub mod seccomp;
```

- [ ] **Step 3: Confirm it builds**

Run: `cargo build -p kestrel-security`
Expected: clean build. `apply_all` itself is exercised end-to-end in Task 13, not unit-tested in isolation here (its five steps are each already tested individually in Tasks 3/5/6/8; Task 13's lifecycle test is what proves the *composition and order* is correct, matching how Phase 4's Task 12 was the composition-proving capstone rather than duplicating per-component tests).

---

## Task 11: Minimal `kestrel-init` scaffolding + `set_parent_death_signal()`

**Files:**
- Modify: `crates/kestrel-init/Cargo.toml`
- Modify: `crates/kestrel-init/src/main.rs` (unchanged — still the stub; a real `main` is Phase 8's job)
- Create: `crates/kestrel-init/src/lib.rs`
- Create: `crates/kestrel-init/src/pdeathsig.rs`
- Create: `crates/kestrel-init/tests/pdeathsig.rs`

- [ ] **Step 1: Cargo.toml**

```toml
[package]
name = "kestrel-init"
edition.workspace = true
version.workspace = true

[[bin]]
name = "kestrel-init"
path = "src/main.rs"

[dependencies]
anyhow.workspace = true
nix = { workspace = true, features = ["prctl", "process", "signal", "user"] }
kestrel-oci = { path = "../kestrel-oci" }
kestrel-security = { path = "../kestrel-security" }

[dev-dependencies]
kestrel-ns = { path = "../kestrel-ns" }
```

`kestrel-init` gains a `lib.rs` alongside its existing `main.rs` binary target — the binary stays an unimplemented stub (Phase 8's job), but the library half (what this phase actually builds: `exec_into`, `set_parent_death_signal`) needs to be `pub` and testable independently of a real binary entry point, matching how `kestrel-runtime` already splits `main.rs`/library modules.

- [ ] **Step 2: `src/lib.rs`**

```rust
#![deny(clippy::undocumented_unsafe_blocks)]

//! Minimal kestrel-init library surface for Phase 5: applying the security
//! profile immediately before execve(), and PR_SET_PDEATHSIG self-
//! protection. The PID-1 reaper (signal forwarding, zombie reaping) is
//! Phase 8's job — see docs/superpowers/specs/2026-08-03-phase5-security-design.md
//! §4b for why that split is deliberate.

pub mod pdeathsig;
```

- [ ] **Step 3: `src/pdeathsig.rs`**

```rust
// crates/kestrel-init/src/pdeathsig.rs

use anyhow::{Context, Result};
use nix::sys::signal::Signal;

/// Sets PR_SET_PDEATHSIG(sig) on the calling process — if the parent
/// (kestrel-runtime) dies, the kernel delivers `sig` to this process
/// automatically, so kestrel-init never becomes an orphan supervising a
/// container with no one left to report its exit status to. Must be set
/// early (before any privilege-dropping steps that might affect signal
/// delivery permissions) and is re-armed to the caller's real parent at
/// the moment of the call — if the parent has ALREADY died by the time
/// this runs, the signal fires essentially immediately rather than never.
pub fn set_parent_death_signal(sig: Signal) -> Result<()> {
    nix::sys::prctl::set_pdeathsig(Some(sig)).context("prctl(PR_SET_PDEATHSIG)")
}
```

Verify `nix::sys::prctl::set_pdeathsig`'s exact signature (confirmed to exist via docs.rs's module listing; confirm whether it takes `Option<Signal>` or a bare `Signal`, and adjust).

- [ ] **Step 4: Root-gated test**

```rust
// crates/kestrel-init/tests/pdeathsig.rs

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};

use kestrel_init::pdeathsig::set_parent_death_signal;

#[test]
#[ignore = "requires root"]
fn test_pdeathsig_delivers_when_parent_dies() {
    kestrel_ns::test_util::run_isolated(|| {
        // A THIRD level of fork here (inside run_isolated's own forked
        // child): we need a genuine parent-then-child pair where we can
        // kill the parent and observe the child's reaction, which
        // run_isolated's own single fork doesn't give us on its own.
        // SAFETY: fork() duplicates the process; the child below only
        // calls async-signal-safe operations (prctl, kill, sleep, exit)
        // before exiting, matching kestrel-ns's own run_isolated
        // convention for what's safe between fork and _exit.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                // Grandchild: arm PDEATHSIG for SIGUSR1, then just sleep —
                // its own SIGUSR1 handler (default: terminate) firing is
                // what we observe from the grandparent below.
                set_parent_death_signal(Signal::SIGUSR1).expect("set_parent_death_signal");
                std::thread::sleep(std::time::Duration::from_secs(5));
                std::process::exit(111); // only reached if PDEATHSIG never fired
            }
            ForkResult::Parent { child: middle_pid } => {
                // This intermediate process is the grandchild's "parent" —
                // kill IT (not run_isolated's own process) to trigger
                // PDEATHSIG in the grandchild.
                nix::sys::signal::kill(middle_pid, Signal::SIGKILL).expect("kill middle process");
                match waitpid(middle_pid, None) {
                    Ok(WaitStatus::Signaled(_, Signal::SIGKILL, _)) => {}
                    other => panic!("expected middle process killed by SIGKILL, got {other:?}"),
                }
                // Give the kernel a moment to deliver PDEATHSIG to the
                // orphaned grandchild, then confirm it's gone (default
                // SIGUSR1 action is to terminate the process).
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Reaping the grandchild directly isn't possible from here
                // (it's not our direct child once reparented) — instead,
                // confirm via /proc that it no longer exists, which is
                // sufficient proof PDEATHSIG (or something) killed it well
                // before its own 5-second sleep would have.
            }
        }
    });
}
```

Self-review this test carefully before finalizing: forking a THIRD level (inside `run_isolated`'s own fork) needs its own zombie-reaping story, since the grandchild reparents to whatever subreaper is active (recall `kestrel-ns::stages::stage1` sets `PR_SET_CHILD_SUBREAPER` — that's a different, unrelated call path, not automatically active here). Consider whether checking `/proc/<pid>/exists` is reliable enough (a PID can be reused) or whether a more robust signal — e.g. having the grandchild write a "still alive" heartbeat to a pipe the intermediate process holds, and checking the read end returns EOF (pipe closed on grandchild exit) rather than more data — would be a stronger proof. Prefer the pipe-EOF approach if implementing this from scratch, since PID reuse makes the `/proc` check genuinely unreliable on a busy system, however unlikely in a test VM.

- [ ] **Step 5: Run**

Run: `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-init --test pdeathsig -- --ignored`
Expected: 1 passed.

---

## Task 12: `exec_into()`, fixture binaries, and the two exec-vehicle tests

**Files:**
- Create: `crates/kestrel-init/src/exec.rs`
- Modify: `crates/kestrel-init/src/lib.rs`
- Modify: `crates/kestrel-init/Cargo.toml` (fixture `[[bin]]` targets)
- Create: `crates/kestrel-init/tests/fixtures/setuid_check.rs`
- Create: `crates/kestrel-init/tests/fixtures/denied_syscall.rs`
- Create: `crates/kestrel-init/tests/exec_via_kestrel_init.rs`

- [ ] **Step 1: Implement `exec_into`**

```rust
// crates/kestrel-init/src/exec.rs

use std::convert::Infallible;
use std::ffi::CString;

use anyhow::{ensure, Context, Result};
use kestrel_oci::runtime::{LinuxSeccomp, Process};
use nix::unistd::execve;

/// Applies the full Phase 5 security pipeline to the CURRENT process, then
/// execve()s into `process.args()`. Never returns on success (the process
/// image is replaced) — the `Result<Infallible>` return type makes that
/// contract checkable by the compiler at every call site, matching the
/// convention `Ok(x): Infallible` establishes elsewhere in Rust's std for
/// "this either diverges or errors."
pub fn exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Infallible> {
    std::env::set_current_dir(process.cwd())
        .with_context(|| format!("chdir to {}", process.cwd().display()))?;

    // apply_all runs BEFORE the chdir above is questioned further — cwd
    // itself needs no special privilege, so its exact position relative to
    // apply_all's five steps doesn't matter; done first here simply
    // because a failed chdir should abort before we've dropped anything.
    kestrel_security::apply::apply_all(process, seccomp).context("apply_all")?;

    let args = process.args().as_deref().filter(|a| !a.is_empty())
        .context("process.args must specify at least the program to exec")?;
    let program = CString::new(args[0].as_str()).context("program path contains a NUL byte")?;
    let argv: Vec<CString> = args.iter().map(|a| CString::new(a.as_str())).collect::<Result<_, _>>()
        .context("an argument contains a NUL byte")?;
    let envp: Vec<CString> = process.env().iter().flatten().map(|e| CString::new(e.as_str())).collect::<Result<_, _>>()
        .context("an env entry contains a NUL byte")?;

    let err = execve(&program, &argv, &envp).expect_err("execve only returns on failure");
    Err(err).with_context(|| format!("execve({:?}, {:?})", program, argv))
}
```

Note the last line: `execve` in `nix` returns `Result<Infallible>` itself on most platforms (it genuinely cannot return `Ok` — a successful exec replaces the process image and never returns to this stack frame at all), so `.expect_err(...)` on success is correct, not a bug — verify this matches the actual `nix::unistd::execve` signature in the resolved version and adjust the unwrapping if it differs (e.g. if it returns a bare `Result<Infallible, Errno>` rather than needing the `expect_err` dance at all, simplify accordingly).

- [ ] **Step 2: Wire into lib.rs**

```rust
pub mod exec;
pub mod pdeathsig;
```

- [ ] **Step 3: Add fixture `[[bin]]` targets to Cargo.toml**

Add to `crates/kestrel-init/Cargo.toml`:

```toml
[[bin]]
name = "fixture-setuid-check"
path = "tests/fixtures/setuid_check.rs"

[[bin]]
name = "fixture-denied-syscall"
path = "tests/fixtures/denied_syscall.rs"

[dev-dependencies]
kestrel-ns = { path = "../kestrel-ns" }
nix = { workspace = true, features = ["user"] }
```

(Merge the `nix` dev-dependency into the existing `[dev-dependencies]` block from Task 11 rather than duplicating the table.)

- [ ] **Step 4: Write the fixture binaries**

```rust
// crates/kestrel-init/tests/fixtures/setuid_check.rs

//! Test fixture, not part of the real kestrel-init binary. Exits 0 if the
//! EFFECTIVE uid is non-root (proving no_new_privs blocked this setuid-
//! root binary from elevating), exits 1 if it's root (proving it did
//! elevate — a real bug in the no_new_privs pipeline).
fn main() {
    let euid = nix::unistd::geteuid();
    std::process::exit(if euid.is_root() { 1 } else { 0 });
}
```

```rust
// crates/kestrel-init/tests/fixtures/denied_syscall.rs

//! Test fixture, not part of the real kestrel-init binary. Calls a
//! syscall the accompanying test's seccomp profile denies via
//! SCMP_ACT_ERRNO (chosen over SCMP_ACT_KILL specifically so this fixture
//! can observe and report the outcome via its own exit code, rather than
//! dying by SIGSYS — which `kestrel_ns::test_util::run_isolated`'s parent-
//! side waitpid check would otherwise interpret as an unrelated test
//! failure rather than "the syscall was correctly blocked"). Exits 0 if
//! the syscall fails with the configured errno (correctly blocked before
//! this fixture's own code could do anything else), exits 1 if it
//! unexpectedly succeeds.
fn main() {
    // Use the SAME syscall Task 8/9 settled on (e.g. `personality`) for
    // consistency across the whole seccomp test suite.
    let ret = unsafe { libc::personality(0xffffffff) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    std::process::exit(if ret == -1 && errno == Some(libc::EPERM) { 0 } else { 1 });
}
```

- [ ] **Step 5: Write the two exec-vehicle integration tests**

```rust
// crates/kestrel-init/tests/exec_via_kestrel_init.rs

use std::os::unix::fs::PermissionsExt;

use kestrel_oci::runtime::{Arch, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, ProcessBuilder, UserBuilder};
use kestrel_init::exec::exec_into;

// No generic `fixture_path(name)` helper — `CARGO_BIN_EXE_<name>` must be a
// literal argument to `env!()`, resolved at compile time; it can't be
// composed from a runtime string. Each test below inlines its own
// `env!("CARGO_BIN_EXE_fixture-...")` call directly instead.

#[test]
#[ignore = "requires root"]
fn test_no_new_privs_blocks_setuid_elevation() {
    let fixture = std::path::PathBuf::from(env!("CARGO_BIN_EXE_fixture-setuid-check"));

    kestrel_ns::test_util::run_isolated(move || {
        // Copy the fixture to a scratch location and make it setuid-root —
        // both need real root, which this whole test already runs as.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("setuid-check");
        std::fs::copy(&fixture, &target).expect("copy fixture");
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        perms.set_mode(0o4755); // setuid + rwxr-xr-x
        std::fs::set_permissions(&target, perms).expect("chmod u+s");

        let user = UserBuilder::default().uid(1000u32).gid(1000u32).build().unwrap();
        let process = ProcessBuilder::default()
            .user(user)
            .args(vec![target.to_string_lossy().into_owned()])
            .cwd(std::path::PathBuf::from("/"))
            .no_new_privileges(true)
            .build()
            .unwrap();

        // exec_into replaces THIS (already-forked, disposable) process's
        // image entirely — its exit code IS the test result, observed by
        // run_isolated's own waitpid in the real parent process.
        let _ = exec_into(&process, None);
        unreachable!("exec_into only returns on failure");
    });
}

#[test]
#[ignore = "requires root"]
fn test_seccomp_filter_is_active_before_entrypoints_first_syscall() {
    let fixture = std::path::PathBuf::from(env!("CARGO_BIN_EXE_fixture-denied-syscall"));

    kestrel_ns::test_util::run_isolated(move || {
        // Denies `personality` via SCMP_ACT_ERRNO, matching the fixture's
        // own hardcoded choice — same construction as Task 8's
        // deny_personality_profile(), duplicated here rather than shared
        // across crates since kestrel-init's tests don't otherwise need a
        // dependency on kestrel-security's test-only code.
        let rule = LinuxSyscallBuilder::default()
            .names(vec!["personality".to_string()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EPERM as u32)
            .build()
            .unwrap();
        let seccomp = LinuxSeccompBuilder::default()
            .default_action(LinuxSeccompAction::ScmpActAllow)
            .architectures(vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64])
            .syscalls(vec![rule])
            .build()
            .unwrap();

        let process = ProcessBuilder::default()
            .args(vec![fixture.to_string_lossy().into_owned()])
            .cwd(std::path::PathBuf::from("/"))
            .build()
            .unwrap();

        let _ = exec_into(&process, Some(&seccomp));
        unreachable!("exec_into only returns on failure");
    });
}
```

Fix the broken `fixture_path` helper stub before finalizing — it's left in as a marker of a wrong approach (trying to build a `CARGO_BIN_EXE_<name>` lookup from a runtime string), which doesn't work because `env!()` requires its argument to be resolvable at compile time as a literal, not composed from a runtime parameter. The two tests below it already work around this correctly by inlining the literal `env!("CARGO_BIN_EXE_fixture-setuid-check")`/`env!("CARGO_BIN_EXE_fixture-denied-syscall")` directly — delete the broken helper function entirely rather than trying to make it generic.

Also: `no_new_privileges(true)` must actually be threaded through to `apply_all`'s step (3) check (`p.no_new_privileges().unwrap_or(false)`) — confirm this wiring is correct by re-reading Task 10's `apply_all` before trusting this test's setup.

- [ ] **Step 6: Run**

Run: `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-init --test exec_via_kestrel_init -- --ignored`
Expected: 2 passed.

---

## Task 13: Full end-to-end security-pipeline lifecycle test

**Files:**
- Create: `crates/kestrel-security/tests/lifecycle.rs`
- Modify: `crates/kestrel-security/Cargo.toml` (dev-dep on `kestrel-init`)

Proves the whole phase's composition and ORDER (not just each piece individually): a `Process` spec with rlimits, a restricted capability set, `no_new_privileges`, a non-root user, and a seccomp profile, all applied via one `exec_into` call into a fixture that reports back what it actually observes about its own security state.

- [ ] **Step 1: Add the dev-dependency**

Add to `crates/kestrel-security/Cargo.toml`'s `[dev-dependencies]`:

```toml
kestrel-init = { path = "../kestrel-init" }
```

- [ ] **Step 2: Write a reporting fixture binary and the test**

Add another `[[bin]]` fixture to `kestrel-security`'s own `Cargo.toml` (or reuse `kestrel-init`'s existing fixture pattern by adding a new fixture there instead, whichever avoids a circular dev-dependency — `kestrel-security` dev-depending on `kestrel-init`, which itself depends on `kestrel-security` as a REGULAR (non-dev) dependency, is fine in Cargo as long as the cycle is dev-dep-only in one direction, matching the same pattern already established between `kestrel-ns`/`kestrel-cgroup` in Phase 3; confirm this actually builds before proceeding, and if Cargo rejects it, put the fixture and the test in `kestrel-init`'s own `tests/` instead).

```rust
// fixture binary: reports uid/euid, whether CAP_SYS_ADMIN is in the
// effective set (via the `caps` crate, since it's already a kestrel-init
// dependency transitively through kestrel-security), the current
// RLIMIT_NOFILE soft limit, and whether a denied syscall fails as
// expected — each as a distinct line on stdout, so the test can assert on
// all of them from one real execve()'d process rather than five separate
// exec cycles.
fn main() {
    println!("uid={}", nix::unistd::getuid());
    println!("euid={}", nix::unistd::geteuid());
    println!("has_sys_admin={}", caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_SYS_ADMIN).unwrap_or(false));
    let (soft, _hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
    println!("nofile_soft={soft}");
    let ret = unsafe { libc::personality(0xffffffff) };
    println!("denied_syscall_blocked={}", ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM));
}
```

Since `exec_into` never returns and its caller is itself inside `run_isolated`'s forked child, capturing this fixture's STDOUT for assertions (rather than just its exit code, as Task 12's simpler fixtures did) needs the test to set up a pipe BEFORE forking and have the fixture's fd 1 point at the write end — set this up via `nix::unistd::dup2` onto `STDOUT_FILENO` before calling `exec_into` (dup2 survives across `execve`), with the read end held by the real (non-forked) test process to read after `waitpid` confirms the child exited.

- [ ] **Step 3: Run**

Run (inside the VM): `sudo -E $(command -v cargo || echo "$HOME/.cargo/bin/cargo") test -p kestrel-security --test lifecycle -- --ignored`
Expected: 1 passed, with the captured stdout confirming: non-root uid/euid, `has_sys_admin=false`, a lowered `nofile_soft`, and `denied_syscall_blocked=true` — i.e., every one of the five `apply_all` steps demonstrably took effect on the real, exec'd process, in the composition this phase set out to prove.

---

## Task 14: Workspace-wide verification and cleanup

**Files:** none new — verification only.

- [ ] **Step 1:** `cargo build --workspace` — clean.
- [ ] **Step 2:** `cargo test --workspace` — all non-`#[ignore]`d tests pass.
- [ ] **Step 3:** `make test-root` — every root-gated test in the workspace passes, including this phase's ~15 new ones.
- [ ] **Step 4:** `cargo clippy --workspace --all-targets -- -D warnings` — clean. Pay particular attention to `clippy::undocumented_unsafe_blocks` in `kestrel-security`/`kestrel-init` — the only `unsafe` blocks either crate should need are the `OwnedFd::from_raw_fd` wrap in `install_seccomp` (Task 8) and the triple-fork in the PDEATHSIG test (Task 11); every other syscall in this plan goes through `nix`'s safe wrappers.
- [ ] **Step 5:** `make check-no-tokio` — still passes (this phase adds nothing async).
- [ ] **Step 6:** Grep the whole `crates/kestrel-security` and `crates/kestrel-init` trees for `todo!()`/`unimplemented!()` and confirm zero matches. None are expected — Tasks 8/9/12's translation functions and tests are written with real bodies throughout this plan, not placeholders — but Task 8's `libseccomp`-side variant names (`ScmpAction`/`ScmpArch`/`ScmpCompareOp`/`ScmpArgCompare`) were written from strong prior knowledge of that crate's stable API shape rather than from vendored source (it's never been fetched into this repo's cargo cache before), so confirm the implementer didn't need to stub anything out while reconciling minor naming drift there.
- [ ] **Step 7:** Sweep the VM for mount/`/tmp` leaks after the full root-gated run (`mount | wc -l`, `ls /tmp | grep '^\.tmp'`) — this phase doesn't call `mount()` in its own production code, but Task 3's `test_caps_dropped_blocks_mount`/`test_apply_capabilities_none_is_a_no_op` tests do call real `mount()`/`MS_REMOUNT` against `/tmp` directly (not inside a fresh mount namespace, since remounting an *existing* mount doesn't create a new mountpoint the way `kestrel-rootfs`'s tests do) — confirm neither leaves `/tmp` in a different mount state than before (e.g. actually remounted read-only) by checking `findmnt /tmp` before and after.
- [ ] **Step 8:** Extend the Makefile's top-of-file NOTE comment (last touched in Phase 4) to mention `kestrel-security`/`kestrel-init` now also require the Lima VM (real capability/seccomp syscalls, no macOS equivalent).

---

## Self-Review Notes

**Spec coverage:** CHECKLIST.md's Phase 5 items map to tasks as: capabilities apply-order/irreversibility/default-set/cap-add-drop/status-reporting → Tasks 2-4 (status reporting via `/proc/<pid>/status` is `caps::read`, already covered by the `caps` crate directly — no new kestrel-security code needed beyond re-exporting `::caps::read`, which Task 3's `apply_capabilities` doc comment should note but doesn't need its own task). no_new_privs-before-seccomp/rlimits/oom_score_adj/PDEATHSIG → Tasks 5, 6, 11. Seccomp filter-building/arg-comparisons/unknown-syscall-skip/load-order/default-profile → Tasks 7-8. SCMP_ACT_NOTIFY/daemon-side-supervisor-primitive → Task 9 (the daemon itself stays out of scope per the design doc). All five 🔴 test items plus the 🟡 notify test → Tasks 3, 8, 9, 12 (the design doc's decision to route the trickiest two through real `execve()` via `kestrel-init` is reflected in Task 12, not simulated in `kestrel-security` alone).

**Placeholder scan:** no `todo!()`/`unimplemented!()` remain — after an initial draft left three translation functions as explicit stubs pending verification of `kestrel-oci`'s real seccomp types, that verification was actually done (reading `oci-spec-0.10.0/src/runtime/linux.rs:1068-1387` directly) and Tasks 8/9/12 were rewritten with real, complete match arms and test bodies against the confirmed types. The one piece that couldn't be verified from vendored source — `libseccomp`'s own `ScmpAction`/`ScmpArch`/`ScmpCompareOp`/`ScmpArgCompare` variant names, since that crate has a `pkg-config` build dependency and has never been fetched into this repo's cargo cache — is written with real, complete code based on that crate's well-established stable API shape, with an explicit instruction to verify variant names (not restructure the approach) against `cargo doc -p libseccomp` inside the VM if anything doesn't compile as written.

**Type consistency:** `apply_capabilities(Option<&LinuxCapabilities>)`, `apply_rlimits(Option<&[PosixRlimit]>)`, `install_seccomp(&LinuxSeccomp) -> Result<Option<OwnedFd>>`, and `apply_all(&Process, Option<&LinuxSeccomp>) -> Result<Option<OwnedFd>>` all match their real usage sites across Tasks 3/5/8/10/12/13 consistently — double-checked against each other during this self-review pass, not just against the design doc.

**Known judgment calls flagged for the implementer/reviewer to verify against the live VM before trusting this plan as written**, continuing this project's established "verify, don't assume" discipline:
- Task 8's `translate_action`/`translate_arch`/`translate_arg_comparisons` (the `libseccomp`-crate-facing halves specifically — the `kestrel-oci`-facing halves are verified against real vendored source and should be trusted as written) and Task 9's `ScmpNotifReq`/`ScmpNotifResp` field/method names are the highest-uncertainty surface in this plan — budget real time for `cargo doc -p libseccomp` / vendored-source reading to confirm exact variant/method names before treating either as final, even though both now have complete, real (not stubbed) code to start from.
- Task 7's default seccomp profile syscall list is a reasonable reconstruction of "the Docker-equivalent ~44-syscall deny set" from public knowledge of runc/Docker's real default profile, not a byte-for-byte copy of any specific upstream file (none was available to consult directly) — treat the exact syscall names as a starting point to sanity-check against a real reference (e.g. `docker info --format '{{.SecurityOptions}}'` if Docker happens to be available anywhere, or the publicly documented moby/moby `profiles/seccomp/default.json` shape) rather than gospel.
- Task 11's triple-fork PDEATHSIG test's liveness-check approach (the `/proc` existence check vs. the suggested pipe-EOF alternative) is flagged as a real design decision for the implementer to make deliberately, not an oversight.
