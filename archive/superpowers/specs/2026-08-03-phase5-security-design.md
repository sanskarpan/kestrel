# Kestrel — Phase 5 (Security Layer) Design

## Context

Phase 5 builds `kestrel-security`: capability sets, `no_new_privs`, rlimits,
and seccomp, applied to a container process in the strict order PROMPT.md's
own Phase 5 section and SPEC.md §8 both specify — "order is everything"
because several of these steps are individually irreversible (bounding-set
capability drops; loaded seccomp filters cannot be removed or loosened).

Per the user's explicit direction, this phase pushes further than the
original three "out of scope" deferrals warranted. Two of them turn out to
be substantially buildable now without jumping ahead into Phase 8/9's actual
territory; the reasoning for each is below.

## 1. Crate ownership

Per SPEC.md §16: `kestrel-security` owns "caps, seccomp, no_new_privs,
rlimits, notify". This phase also puts a *minimal* amount of new code in
`kestrel-init` (currently an empty stub) — see §4.

## 2. Real crate APIs (verified against docs.rs, not just PROMPT.md's sketch)

- **`caps`** (crates.io): `CapSet::{Ambient,Bounding,Effective,Inheritable,Permitted}`;
  `caps::{clear,drop,raise,set,read,has_cap}(thread_id: Option<i32>, set, ...)`,
  `caps::all() -> CapsHashSet` (a `HashSet<Capability>`). `None` for
  `thread_id` means "the calling thread."
- **`libseccomp`** (crates.io, wraps the VM's already-installed
  `libseccomp-dev` via `libseccomp-sys` + a `pkg-config` build dependency —
  confirmed present since Phase 0's provisioning script installs
  `libseccomp-dev`). `ScmpFilterContext::new(default_action) -> Result<Self>`
  — **note**: PROMPT.md's/SPEC.md's sample uses `new_filter`, which docs.rs
  confirms is a *deprecated alias* for `new`; this plan uses `new` and flags
  the drift rather than reproducing the deprecated name, consistent with how
  every earlier phase corrected stale API names found in the master specs.
  `ctx.load()`, `ctx.get_notify_fd() -> Result<ScmpFd>` (confirmed to exist).
  `ScmpNotifReq`/`ScmpNotifResp`/`ScmpNotifData`/`notify_id_valid` exist for
  the notify path; their exact method signatures need final confirmation
  against the resolved crate version inside the VM at implementation time
  (docs.rs's rendering didn't expose full signatures) — same "verify against
  the real, resolved version" discipline every previous phase has applied to
  `nix`.
- **`oci_spec::runtime` types** (already re-exported via `kestrel-oci`),
  read directly from the vendored source rather than assumed from PROMPT.md's
  sketch:
  - `LinuxCapabilities`'s five fields are `Option<Capabilities>` where
    `Capabilities = HashSet<Capability>` — **not** bare sets as PROMPT.md's
    `c.bounding.contains(&cap)` implies. `apply_capabilities` must treat
    `None` as "no change to this set" (or, for `bounding`, as "don't touch
    the bounding set" — see §3), not as an error.
  - `User`'s `uid`/`gid` are plain `u32` (`#[serde(default)]`, defaulting to
    0), **not** `Option<u32>` as PROMPT.md's `if let Some(gid) = ...` sketch
    implies. `additional_gids` genuinely is `Option<Vec<u32>>`. This means
    the uid/gid application steps are unconditional (an unset `User` in the
    spec means uid=0/gid=0 — root — which is correct OCI default behavior,
    not "skip the syscall").
  - `oci_spec::runtime::Capability` (the enum inside `Capabilities`) is a
    **different type** from `caps::Capability` (the `caps` crate's own
    enum) — one is OCI-spec's representation, the other is the `caps`
    crate's. A real translation function is needed:
    `oci_spec::runtime::Capability` has a `strum`-derived `Display` that
    renders e.g. `Capability::SysAdmin` as `"SYS_ADMIN"` (no `CAP_` prefix —
    confirmed by that crate's own test suite); `caps::Capability` needs the
    `CAP_`-prefixed form. `translate_capability()` bridges the two via
    `format!("CAP_{oci_cap}")` parsed through whatever `caps::Capability`'s
    own `FromStr`/parsing entry point turns out to be (exact method name
    verified at implementation time) — unit-tested against every one of the
    ~40 capability variants both crates share, with an explicit test for
    what happens on the (currently believed to be none, but verify) variants
    either crate might be missing relative to the other's kernel-version
    coverage.

## 3. `apply_all()` — the ordered pipeline

Matches PROMPT.md/SPEC.md exactly, adjusted for the real `Option<Capabilities>`
typing above:

1. **rlimits** — some limits can't be raised after a uid drop. Also written
   here: `oom_score_adj` (a plain `/proc/self/oom_score_adj` write, CHECKLIST
   groups it with rlimits).
2. **Capabilities** — ambient clear → bounding drop (irreversible; only
   touches the bounding set if `LinuxCapabilities.bounding` is `Some`, since
   `None` means "the spec author didn't ask us to constrain this at all",
   not "drop everything") → permitted/inheritable/effective set → ambient
   raise.
3. **`no_new_privs`** — must precede seccomp.
4. **uid/gid** — after capabilities, while `CAP_SETUID`/`CAP_SETGID` are
   still available. Unconditional per the real `User` typing above.
5. **Seccomp** — last, immediately pre-exec.

## 4. The two un-deferred pieces

### 4a. Seccomp notify — the fd-and-decode-loop, without `kestreld`

SPEC.md's description of the notify supervisor conflates two genuinely
separable things: (a) reading `ScmpNotifReq` off the fd, decoding
`{pid, syscall, args}`, responding (the TOCTOU-safe way, via
`notify_id_valid` before `ScmpNotifResp`) — pure kernel/fd mechanics with no
dependency on an HTTP server or async runtime — and (b) streaming that data
to a web UI over SSE, which genuinely does need `kestreld`.

This phase builds (a) as a real, tested library function:
`handle_one_notification(fd) -> Result<NotifyEvent>` (blocking, single-shot)
and a thin `run_notify_loop(fd, on_event: impl FnMut(NotifyEvent)) -> Result<()>`
wrapper around it. `kestreld` (Phase 9) will later just call this from its
own thread and forward each `NotifyEvent` over SSE — a real, reusable
building block, not throwaway scaffolding.

### 4b. Minimal `kestrel-init`: apply-then-exec, plus `PR_SET_PDEATHSIG`

`kestrel-init`'s actual substantial job — the PID-1 reaper (SIGCHLD-driven
zombie reaping, signal forwarding) — is separately and clearly scoped to
PROMPT.md's own "Phase 8 — PID 1: the reaper" section and stays deferred;
building it now would mean redoing it when Phase 8 assembles the full
container lifecycle around it.

But `apply_all()`'s own contract ("called by kestrel-init immediately before
execve()") already implies the strongest possible test for this phase is a
*real* `execve()`, not a simulated one. So `kestrel-init` gains exactly one
function now: `exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Infallible>`,
which calls `kestrel_security::apply::apply_all()` then `execve()`s into
`process.args()`. This becomes the actual vehicle for
`test_no_new_privs_blocks_setuid` and `test_seccomp_before_exec` — proving
those properties survive a real `execve()`, which is strictly stronger than
asserting on in-process state before ever calling exec.

Alongside it: `set_parent_death_signal()` (`PR_SET_PDEATHSIG` via
`nix::sys::prctl` or a raw `prctl()` call if `nix` doesn't expose it),
tested by forking a child, setting it, killing the parent, and observing the
child receives the configured signal — self-contained, no dependency on the
reaper existing.

Neither addition wires anything into `kestrel-runtime`'s CLI or a real
create/start flow — that composition (namespaces + cgroups + rootfs +
security, orchestrated from one lifecycle command) is still Phase 8's job.
This is narrowly "build and test the two functions Phase 5's own test suite
needs to prove properties survive a real exec," which is consistent with
how `kestrel-rootfs`'s `pin_namespace`/`kestrel-cgroup`'s `clone_into_cgroup`
were both built and tested as standalone primitives well before their real
callers existed.

## 5. Default capability set & seccomp profile

- `DEFAULT_CAPABILITIES`: the 14-cap Docker-compatible set from SPEC.md
  §8.1 (`CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW, SETGID, SETUID,
  SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE`),
  expressed as `oci_spec::runtime::Capability` values (so it composes
  directly with spec-derived `LinuxCapabilities`, not a separate
  `caps::Capability` list).
- `resolve_cap_add_drop(default: &[Capability], add: &[Capability], drop: &[Capability]) -> HashSet<Capability>`:
  pure function, `--cap-add`/`--cap-drop` resolution against the default —
  built and tested now; the clap flag *parsing* that produces `add`/`drop`
  lists stays Phase 10's job (no independent correctness property to test
  early — it's just argument plumbing).
- `profiles/seccomp/default.json` at the repo root (per SPEC.md §16): the
  ~44-denied-syscall Docker-equivalent profile (`kexec_load`, `init_module`,
  `mount`, `pivot_root`, `bpf`, `perf_event_open`, `ptrace` unless allowed,
  `add_key`, `keyctl`, `userfaultfd`, namespace-flagged `clone`, etc.),
  loaded and deserialized into `LinuxSeccomp` via `kestrel-oci`'s existing
  JSON round-trip support.

## 6. Testing strategy

Continues this project's "prove it against the real kernel" bias.
Everything privileged runs via `kestrel_ns::test_util::run_isolated`
(fork-per-test, dev-dependency, same as every crate since Phase 3) —
essential here specifically because bounding-set drops, `no_new_privs`, and
loaded seccomp filters are irreversible *within a process*, so each test
needs its own disposable child, not just for convenience but for
correctness of the test itself.

- `test_caps_dropped`: drop `CAP_SYS_ADMIN` from bounding, attempt a real
  `mount()` in the same child, assert `EPERM`.
- `test_no_new_privs_blocks_setuid`: via `kestrel_init::exec_into` — build
  a tiny setuid-root fixture binary (compiled once, `chmod +s`'d by root),
  set `no_new_privs`, exec it as a non-root uid, confirm `geteuid()` inside
  stays non-root.
- `test_seccomp_blocks_syscall`: filter denying an observable syscall
  (`ScmpAction::Errno`), load, call directly, assert the configured errno.
- `test_seccomp_before_exec`: via `kestrel_init::exec_into` — load a filter
  denying a syscall, exec into a fixture binary whose first action is that
  syscall, confirm it's blocked immediately (proving the filter survives
  `execve` and is active before the entrypoint's own code runs).
- `test_seccomp_notify_captures`: `SCMP_ACT_NOTIFY` filter, `get_notify_fd()`,
  trigger the syscall from a child, `handle_one_notification()` on the fd,
  assert the returned `NotifyEvent` has the right pid/syscall/args.
- `test_pdeathsig_delivers_on_parent_exit`: fork, set PDEATHSIG in the
  child, kill the parent, confirm the child receives the configured signal.
- Pure/unprivileged: `translate_capability()` round-tripped against every
  shared variant, `resolve_cap_add_drop()`'s add/drop/default interaction,
  the default seccomp profile JSON parses into a valid `LinuxSeccomp`.

## Out of scope for this increment

- **Web/SSE wiring** for seccomp-notify violations — needs `kestreld`'s
  actual HTTP/SSE server and the React dashboard's event stream; no
  meaningful partial version exists without the network layer.
- **The PID-1 reaper** (SIGCHLD loop, zombie reaping, signal forwarding) —
  substantial, independently-scoped functionality per PROMPT.md's own Phase
  8 section.
- **`--cap-add`/`--cap-drop` CLI flag parsing** — needs Phase 10's clap
  subcommand structure; the resolution logic it will call is built now.
- Wiring any of this into `kestrel-runtime`'s actual `create`/`start`
  lifecycle (Phase 8 assembly, per PROMPT.md's Rule #3: Phases 2-5 are each
  independently tested before Phase 8 assembles them).
