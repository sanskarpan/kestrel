# docs/SECURITY.md — Capabilities, Seccomp, and Threat Model

Kestrel's security boundary: what it enforces, what it does not, and known gaps.

## Capability Defaults

Five sets, applied in irreversible order (bounding drops cannot be undone):

```rust
pub fn apply_capabilities(caps: &LinuxCapabilities) -> Result<()> {
    caps::clear(None, CapSet::Ambient)?;                 // 1. ambient first
    for cap in caps::all() { if !caps.bounding.contains(&cap) { caps::drop(None, Bounding, cap)?; } } // 2. bounding (irreversible)
    caps::set(None, Permitted,   &caps.permitted)?;      // 3. permitted / inheritable / effective
    caps::set(None, Inheritable, &caps.inheritable)?;
    caps::set(None, Effective,   &caps.effective)?;
    for cap in &caps.ambient { caps::raise(None, Ambient, *cap)?; } // 4. ambient last (survives exec of non-privileged binary)
}
```

Default 14-cap set (Docker-compatible):

```
CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW,
SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE
```

**Deliberately absent:** `SYS_ADMIN` (mount/namespace creation ≈ root), `SYS_PTRACE`, `SYS_MODULE`, `NET_ADMIN`, `DAC_READ_SEARCH` (enables `open_by_handle_at`, the Shocker exploit), `SYS_TIME`, `SYSLOG`, etc.

`--cap-add` / `--cap-drop` resolved against this default. All 5 sets reported via `/proc/<pid>/status` and `GET /containers/:id/caps`.

## no_new_privs, rlimits, oom_score_adj

```rust
prctl::set_no_new_privs(true)?;   // MUST be before seccomp; irreversible; blocks setuid/setcap elevation
// rlimits: every RLIMIT_* from the spec
// oom_score_adj: write /proc/<pid>/oom_score_adj
// pdeathsig: PR_SET_PDEATHSIG on init
```

`test_no_new_privs_blocks_setuid` asserts a setuid-root binary inside does not elevate; `test_caps_dropped` asserts `mount()` returns `EPERM` without `CAP_SYS_ADMIN`.

## Seccomp

Filter built from `LinuxSeccomp` (OCI spec): default action, arch list, per-syscall rules + `SCMP_CMP_*` argument comparisons. Load **after** `no_new_privs`, **immediately before** `execve`.

```rust
pub fn install_seccomp(profile: &LinuxSeccomp) -> Result<Option<OwnedFd>> {
    let mut ctx = ScmpFilterContext::new_filter(profile.default_action.into())?;
    for arch in &profile.architectures { ctx.add_arch((*arch).into())?; }
    for rule in &profile.syscalls {
        for name in &rule.names {
            let sc = match ScmpSyscall::from_name(name) { Ok(s) => s, Err(_) => { warn!(name); continue; } }; // unknown → skip
            if rule.args.is_empty() { ctx.add_rule(rule.action.into(), sc)?; }
            else { ctx.add_rule_conditional(rule.action.into(), sc, &cmps)?; }
        }
    }
    ctx.load()?;
    if profile.uses_notify() { Ok(Some(ctx.get_notify_fd()?)) } else { Ok(None) }
}
```

**Default profile** (`profiles/seccomp/default.json`, Docker-equivalent, ~44 denied):

```
kexec_load, init_module, delete_module, mount, umount2, pivot_root, bpf, perf_event_open,
ptrace (unless allowed), add_key, keyctl, userfaultfd, clone with namespace flags,
reboot, swapon/swapoff, syslog, clock_settime, settimeofday, …
```

Unknown syscall names → skip with warning (forward compatibility), never fail the container.

**Violation capture** (`SCMP_ACT_NOTIFY`): the kernel hands a notify fd; the daemon passes it via `SCM_RIGHTS`, reads `seccomp_notif` in a supervisor thread, logs `{pid, syscall, args}`, responds `ENOSYS`, and emits `seccomp.violation` SSE. The UI's Security view streams this live. `SCMP_ACT_KILL` is supported but kills without explanation.

Tests: `test_seccomp_blocks_syscall`, `test_seccomp_before_exec`, `test_seccomp_notify_captures`.

## Masked & Readonly Paths

Applied after `pivot_root`, before `execve`:

* **Masked** (`/proc/acpi`, `/proc/kcore`, `/proc/keys`, `/sys/firmware`, …): bind `/dev/null` (files) or empty ro `tmpfs` (dirs).
* **Readonly** (`/proc/bus`, `/proc/sys`, `/proc/sysrq-trigger`, …): bind-mount then remount `MS_RDONLY` (single-call `MS_BIND|MS_RDONLY` silently ignores `RDONLY`).

## Threat Model

**Assumed trusted:** host kernel ≥ 5.11, cgroup v2, `kestreld` (runs as root or delegated via userns), the image registry (TLS + digest verification during pull, before persist).

**Enforced boundary:**

```
  Host kernel
  ┌─────────────────────────────────────────────┐
  │  kestreld (root)                            │
  │   └─ kestrel-runtime (single-threaded)      │
  │       └─ kestrel-init (PID1, reaper) ─ exec │
  │           └─ container entrypoint           │◄── caps dropped, no_new_privs, seccomp,
  │               (no CAP_SYS_ADMIN)            │    masked/RO mounts, cgroup limits,
  │                                             │    netns (no host interfaces), read-only rootfs
  └─────────────────────────────────────────────┘
```

* Container cannot `mount`/`pivot_root`/`bpf`/`ptrace` host, cannot escape `chroot`-style (uses `pivot_root`), cannot gain priv via setuid, cannot exceed `memory.max`/`pids.max`/`cpu.max` without throttle/OOM, cannot see host PIDs/mounts/network.

**Known gaps / non-goals:**

| Gap | Status | Mitigation |
|-----|--------|------------|
| AppArmor/SELinux profiles | Not yet applied (stretch) | seccomp + caps cover the primary boundary |
| User namespace rootless fully delegated | Partial — `newuidmap` fallback; `pasta`/`slirp4netns` for net | rootless overlay `userxattr` done |
| CRIU checkpoint/restore | Stretch (Phase 14) | — |
| Wasm entrypoint (`wasmtime`) | Stretch | — |
| containerd shim v2 | Stretch | — |
| Signed images / cosign | Not in scope | digest verification on pull only |
| Encrypted layers | Not in scope | — |

## Verification

```bash
# Inside a default container, these must fail:
capsh --print | grep sys_admin   # absent
mount -t tmpfs none /mnt          # EPERM (no CAP_SYS_ADMIN)
./setuid-root-binary              # stays unprivileged (no_new_privs)
python3 -c 'import os; os.sched_setscheduler(0,0,os.sched_param(0))'  # EPERM per seccomp
cat /proc/sys/kernel/osrelease    # masked or RO
```

Every `unsafe` block carries `// SAFETY:` and `#![deny(clippy::undocumented_unsafe_blocks)]`.

## Further Reading

* `crates/kestrel-security/src/{caps,seccomp,runtime}.rs`, `crates/kestrel-init/src/reaper.rs`
* `profiles/seccomp/default.json`
* `docs/superpowers/specs/2026-08-03-phase5-security-design.md`
* SPEC §8, CHECKLIST Phase 5
