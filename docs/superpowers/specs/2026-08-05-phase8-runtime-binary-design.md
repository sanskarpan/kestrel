# Kestrel — Phase 8 (Runtime Binary) Design

## Context

Phase 8 builds `kestrel-runtime`'s nine lifecycle subcommands
(`create`/`start`/`state`/`kill`/`delete`/`exec`/`ps`/`pause`/`resume`) and
turns `kestrel-init` from its current minimal state (`exec_into` +
`pdeathsig`, Phase 5) into the full static PID-1 binary: mounts →
`createContainer` hooks → pivot_root → sethostname → time-ns offsets →
block on the exec FIFO → `startContainer` hooks → caps/no_new_privs/seccomp
→ `execve`, plus a `SIGCHLD` reaper loop that doesn't exist yet. (This
ordering — `createContainer` hooks BEFORE `pivot_root` — follows SPEC.md
§9.3's hook table, not CHECKLIST.md's own terser bullet list, which reads
as post-pivot; §1 below resolves this conflict explicitly and treats
SPEC.md's table as authoritative.)

This is fundamentally an **assembly** phase, not a from-scratch build:
`kestrel-ns::stages::run_stages` (Phase 2) already implements the full
three-stage fork/unshare dance; `CgroupManager` (Phase 3) already handles
cgroup creation/controller setup; `kestrel-rootfs` (Phase 4),
`kestrel-security` (Phase 5), and `kestrel-net` (Phase 7) are all built
and independently tested. `kestrel-oci` already has more scaffolding than
expected going into this phase: `state::{State, Status}` (matching
SPEC.md §9.2's schema exactly, including the `Paused` status kestrel adds
beyond the official OCI schema), `raw::RawSpec` (round-trip-safe
`config.json` handling), `validate::SpecExt::validate()`, `default_spec`,
and `user::ResolvedUser`. Phase 8's job is wiring all of this into a real,
runnable container lifecycle — plus the genuinely new pieces: hook
execution, the exec FIFO, bootstrap-data transport across the `execve`
into `kestrel-init`, and `kestrel-init`'s reaper loop.

Confirmed with you before writing this: full 24-task scope (every
CHECKLIST item here is 🔴, no optional items to defer this time), and the
5 required tests use a synthetic hand-built rootfs (a tiny tar with one
static binary), not a real pulled image — kept fast and offline, since
these tests are about `kestrel-runtime`'s own lifecycle correctness, not
image pulling (already proven separately in Phase 6).

## 1. The `kestrel-runtime` / `kestrel-init` split — resolving where each hook and mount step actually runs

SPEC.md §9.3's hook table specifies WHICH namespace each hook runs in,
and that directly determines which binary executes it:

| Hook | Namespace | Executed by |
|---|---|---|
| `createRuntime` | runtime (host) | `kestrel-runtime` itself, host-side, before `kestrel-init` is exec'd |
| `createContainer` | container mount ns | `kestrel-init`, after rootfs is mounted, before `pivot_root` completes |
| `startContainer` | container | `kestrel-init`, immediately before `execve` |
| `poststart` | runtime | `kestrel-runtime`, after `start` unblocks the FIFO |
| `poststop` | runtime | `kestrel-runtime`, after `delete` finishes teardown |

`createRuntime` is explicitly "this is where CNI runs" — CNI plugins need
host-side network-namespace access to attach a veth into the container's
(already-created, at this point) netns, exactly matching `kestrel-net`'s
own architecture (Phase 7's `nsenter` joins a pinned netns from the host
side). This confirms `createRuntime` fires from `kestrel-runtime`'s own
process, not from inside the container's evolving namespace set.

**`createContainer` timing — SPEC.md's table wins over CHECKLIST's
paraphrase.** CHECKLIST's own bullet list ("mounts → pivot_root →
sethostname → time-ns offsets → createContainer hooks → …") reads as
post-pivot; SPEC.md §9.3's table says pre-pivot ("before pivot_root
completes"). These genuinely conflict, and this design commits to
SPEC.md's table as authoritative — it's the more detailed, deliberately-
written source or this exact question, whereas CHECKLIST's bullet list is
a terser summary elsewhere shown to compress/reorder details (e.g. its
"mounts → pivot_root" phrasing doesn't itself distinguish "mount the
overlay" from "mount /proc et al" the way Phase 4's actual implementation
does). Concretely: `createContainer` fires after `mount_overlay` +
`setup_standard_mounts` + `apply_default_masks` (rootfs is fully staged)
but BEFORE the `pivot_root` call itself — this is also the only ordering
that makes semantic sense for a hook whose whole purpose (per the real
OCI spec) is to let tooling modify the container's rootfs contents before
it becomes the visible `/`.

**The process hand-off — a dedicated, two-phase sync socket, not the
Phase-2-internal one.** `run_stages`'s `child_action: impl FnOnce() +
'static` (verified against the real signature in
`crates/kestrel-ns/src/stages.rs`) takes **no parameters** — the
`RequestMaps`/`MapsDone`/`ReportPid` socket `stage1()` uses internally for
id-map coordination is entirely local to that function and is never
threaded through to `child_action`. Phase 8 needs its **own** socketpair,
created by `create.rs` *before* calling `run_stages`, with one end moved
by value into the `child_action` closure (legal — the closure is
`'static`) and the other end kept by `create.rs` itself. This is also
where CHECKLIST's "Bootstrap data … passed to the child over the sync
socket" phrasing is satisfied for real, as a Phase-8-specific protocol —
distinct from, and not to be confused with, Phase 2's own internal
stage0/stage1 id-map sync socket, which is a different concept that
happens to also be called a "sync socket."

Placement in the cgroup is handled automatically by `run_stages` itself
when `create.rs` passes a real `cgroup_fd` — `stages.rs`'s
`CLONE_INTO_CGROUP` fast path places stage2 in the target cgroup
atomically, before `child_action` ever runs, which is what SPEC.md §18's
"no window where the container runs unconstrained" invariant requires.
`child_action` does not need to (and must not) manually join a cgroup.

**Why `child_action` blocks before it execs — this closes a real race**:
if `child_action` executed immediately (build Bootstrap, `execve`), it
would race `createRuntime` hooks, which run in `create.rs` back on the
host side and can take arbitrary time (CNI plugin execution, etc.) — a
slow `createRuntime` hook could lose that race, letting the container
start running (or fail) before its network is even attached. So the
two-phase protocol is:

1. `create.rs` creates the dedicated socketpair, calls `run_stages` (one
   socket end moved into `child_action`), and gets back `init_pid` almost
   immediately (as soon as stage1 reports it — `child_action` is already
   running by this point, but see step 2).
2. `child_action`'s FIRST action is to **block reading** on its socket
   end — it does nothing else until it receives a message. It builds and
   sends nothing; it only receives.
3. Back in `create.rs` (host side, still holding its own socket end):
   `create.rs` runs `createRuntime` hooks. Only once they all succeed
   does it build the `Bootstrap` payload (JSON: the resolved rootfs mount
   plan and layer chain-ids, the `Process`/`LinuxCapabilities`/`LinuxSeccomp`
   spec, `createContainer`/`startContainer` hook definitions, hostname,
   time-ns offsets, the exec-FIFO's in-container bind-mount target path,
   the container id) and sends it as the single message `child_action` is
   waiting for.
4. `child_action` receives the Bootstrap payload, and *then* `execve`s
   directly into `kestrel-init`, with the same socket fd inherited
   (non-`O_CLOEXEC`) so `kestrel-init` can read the already-buffered
   Bootstrap bytes as literally its first action (no second round-trip
   needed — the payload was already delivered to the fd in step 3, before
   the exec; `kestrel-init` just needs to read what's sitting in the
   socket buffer, not wait for anything new).

If a `createRuntime` hook fails, `create.rs` never sends the Bootstrap
message; instead it sends an explicit abort message (or simply closes its
end, which `child_action`'s blocking read observes as EOF) and
`child_action` exits without ever calling `execve` — the container never
starts running with a failed/incomplete host-side setup.

`kestrel-init`, once it has the Bootstrap payload, does EVERYTHING from
that point on: `mount_overlay` (reusing `kestrel-rootfs`, unchanged from
Phase 4) → `setup_standard_mounts` → `apply_default_masks` → bind-mount
the exec FIFO into the container (see the FIFO discussion in §3) →
`createContainer` hooks (rootfs staged, still pre-pivot, per the
resolution above) → `pivot_root` → `sethostname` → time-ns offsets → open
the (now container-relative) exec FIFO path and block → `startContainer`
hooks → `kestrel_security::apply::apply_all` (caps/no_new_privs/seccomp,
unchanged from Phase 5, reused as a library call since `kestrel-init`
already depends on `kestrel-security`) → fork once more and exec the real
entrypoint (see the PID-1/reaper split in §3 — `kestrel-init` does NOT
itself `execve` into the entrypoint).

This resolves an apparent tension in the checklist wording ("a separate
static binary ... copied into the container at a fixed path"): at the
moment `kestrel-runtime`'s stage2 `execve`s into it, the mount namespace
has only just been unshared (a private copy of the host's mount table,
nothing diverged yet) — `kestrel-init`'s real host-filesystem path is
still fully resolvable at that instant, so no literal copy-into-the-container
step is needed for `execve` itself to succeed. The reason it must be
**statically linked** (`-C target-feature=+crt-static`, already a
CHECKLIST bullet) is that once it's running as the process image, it goes
on to `pivot_root` — after which the old root (and therefore any dynamic
libraries it might have needed) is gone. A dynamically-linked binary
would need to have every `.so` it depends on already resolved into memory
before that point, which `execve`-time dynamic linking doesn't guarantee
survives a later `pivot_root`; static linking sidesteps the question
entirely. "Copied into the container" is the checklist's shorthand for
this survives-losing-the-original-root property, not a literal file-copy
step this phase needs to implement. **Real toolchain risk, flagged not
solved here**: true static linking on Linux in practice means a `musl`
target (`x86_64-unknown-linux-musl`/`aarch64-unknown-linux-musl`), and
`kestrel-init` depends on `kestrel-security`, which depends on the
`libseccomp` crate — a C-library FFI binding. Whether `libseccomp` links
cleanly against musl (statically) is a real open question this design
does not resolve; the implementation plan must verify this early (build
`kestrel-init` for a musl target and confirm it links and runs) rather
than discovering it's a problem deep into the phase.

**`exec` (entering an ALREADY-running container) is simpler but has one
sharp edge: it still needs a fork.** The container's mount namespace is
already pivoted, so `kestrel exec` never needs `kestrel-init` or a rootfs
redo — but `setns(fd, CLONE_NEWPID)` does **not** move the calling
process into the target PID namespace, only its *subsequently forked
children* (the same constraint SPEC.md §4.2 point 3 states for
*creating* a PID namespace applies equally to *joining* one via `setns`).
`kestrel_ns::join::join_namespaces` (Phase 2/4, unchanged) does a flat
loop over `JOIN_ORDER` including `NsType::Pid` with no special-casing for
this — calling it and then `execve`ing directly in the same process would
leave the exec'd process in `kestrel-runtime`'s OWN original PID
namespace despite being in the container's mount/net/uts/ipc namespaces,
silently breaking `ps`/reaping/`kill` semantics for it. The fix (the same
one `runc exec`/`nsenter` use): after `join_namespaces` returns,
`exec_cmd.rs` (`kestrel-runtime` is single-threaded per Rule #2, so a
plain `fork()` here is as safe as every other fork this project does from
a single-threaded context) forks once more; the CHILD (now genuinely born
inside the container's PID namespace) calls `kestrel_init::exec::exec_into`
as a **library call** (not by re-exec'ing the `kestrel-init` binary — no
rootfs/pivot work needs redoing); the PARENT (`kestrel-runtime`'s own
`exec` process) `waitpid()`s on that child directly and exits with its
exit code, so the exit code still propagates cleanly to the CLI caller.
This means `kestrel-runtime` gains `kestrel-init` as a regular (not just
binary-invocation) dependency.

## 2. New modules in `kestrel-runtime`

- `bundle.rs` — loads and validates an OCI bundle: `config.json` via
  `kestrel_oci::raw::RawSpec` (preserves unknown fields for
  potential future re-serialization, though Phase 8 never writes
  `config.json` back out — reading is the only need here, so plain
  `Spec` would also work; `RawSpec` is used anyway for consistency with
  the crate's own stated convention of "use `RawSpec` wherever a
  `config.json` gets read," even though this call site happens to be
  read-only), then `SpecExt::validate()` (already built, Phase-0/1-era
  work).
- `state.rs` — atomic `state.json` read/write (write-temp-then-rename,
  the same atomicity pattern used everywhere else in this project) around
  `kestrel_oci::state::{State, Status}`. **`State` gains one new field
  this phase, `exit_code: Option<i32>`** — not part of the official OCI
  state schema, but neither is `Status::Paused`, which is already a
  precedented kestrel-specific extension to this same type (see §
  "exit-code plumbing" below for why this is needed and who writes it).
  `status` refreshing on read: `state` (the subcommand) re-derives
  `status` by checking whether `pid` is still alive (`kill(pid, 0)`)
  rather than trusting a possibly-stale on-disk value, per CHECKLIST's
  explicit requirement ("refreshing `status` by checking the pid") — but
  see below: liveness-checking alone can't distinguish "still running"
  from "exited, not yet reaped by an unrelated process," so this is
  necessary but not sufficient for correctness; the exit-code mechanism
  below is what actually closes the gap.
- `bootstrap.rs` — the `Bootstrap` payload type (serde, JSON) and the
  two-phase socket protocol described in §1 (`create.rs`'s host-side
  sender half, and the receiver half `kestrel-init` calls as its first
  action). Defined in a **new `kestrel_oci::bootstrap` module** (not
  `kestrel-runtime`) since both `kestrel-runtime` and `kestrel-init` need
  it and both already depend on `kestrel-oci` — matching the same
  "shared types live in the crate both sides already depend on" pattern
  `kestrel-oci::state` already established. Deliberately named to avoid
  colliding with CHECKLIST's own looser use of "bootstrap data" (which,
  read in context, mostly refers to what Phase 2's `NamespacePlan`
  already carries) — this `Bootstrap` type is the superset Phase 8 adds
  on top: the resolved rootfs mount plan, `Process`/`LinuxCapabilities`/
  `LinuxSeccomp`, hook definitions, hostname, time-ns offsets, the
  exec-FIFO's in-container target path, and the container id.
- `hooks.rs` — hook execution: given a `Vec<Hook>` (`oci_spec::runtime::Hook`
  — note this is the SINGULAR per-hook type, `{path, args, env, timeout}`;
  `kestrel-oci`'s `runtime` module already re-exports the PLURAL `Hooks`
  container struct, `{create_runtime, create_container, start_container,
  poststart, poststop}`, but not `Hook` itself — confirmed by reading
  `kestrel-oci/src/lib.rs`'s re-export list directly, this is a real,
  small addition this task needs to make, not something already done)
  and stdin content (some hooks
  receive the container state as JSON on stdin per the OCI spec), runs
  each sequentially. **Timeout enforcement without threads** (Rule #2
  forbids `kestrel-runtime` from spawning threads, transitively): spawn
  the hook via `std::process::Command::spawn()` (a child *process*, not a
  thread — fine), then poll `try_wait()` in a loop against a deadline
  computed from the hook's configured timeout, sleeping briefly between
  polls; if the deadline elapses before the child exits, `SIGKILL` it and
  reap it via a final blocking `wait()`. `kestrel-runtime` calls this for
  `createRuntime`/`poststart`/`poststop`; `kestrel-init` calls the same
  function (linked in, not re-implemented) for `createContainer`/
  `startContainer`.
- **Exit-code plumbing** (closes a real gap the initial draft of this
  design left unresolved): per SPEC.md §4.2, the `create` process writes
  `state.json` and exits immediately — nothing in `kestrel-runtime`'s own
  process lineage survives to `wait()` on the container's eventual death,
  so there is no in-process way for `kestrel-runtime` to observe or
  report an exit code later. Resolution: `kestrel-init`'s reaper (§3), the
  one process that legitimately DOES `wait()` on the real entrypoint
  (directly, as its own forked child — see §3), is what writes the
  outcome. When the entrypoint dies, the reaper updates `state.json`
  itself — `status = Stopped`, `exit_code = Some(code)` — using the exact
  same atomic write-temp-then-rename logic `kestrel-runtime` uses (so
  this logic must be reusable from `kestrel-init` too; it lives in
  `kestrel_oci::state` itself as a small `State::write_atomic(&self, path)`
  method, rather than duplicated in both binaries' own `state.rs`
  wrapper modules). This means `kestrel-init` needs to know the
  `state.json` path — included in the `Bootstrap` payload. `kestrel-runtime`'s
  `state`/`delete` subcommands then read this field directly rather than
  needing any live IPC with a long-dead process.
- `create.rs` / `start.rs` / `state_cmd.rs` / `kill.rs` / `delete.rs` /
  `exec_cmd.rs` / `ps.rs` / `pause.rs` / `resume.rs` — one module per
  subcommand, each a thin orchestration layer over the primitives above
  and the already-built Phase 2-7 crates.
  - `create.rs` is the largest: loads the bundle, builds the
    `NamespacePlan`, creates the cgroup, creates the exec FIFO at the
    host path CHECKLIST specifies (`/run/kestrel/<id>/exec.fifo` —
    `mkfifo`, this module's explicit responsibility), calls `run_stages`,
    runs `createRuntime` hooks, sends the `Bootstrap` payload (§1's
    two-phase protocol), writes the initial `state.json`
    (`Status::Creating` → `Status::Created` once `kestrel-init` confirms
    the FIFO is open and blocked-on — needs one more small sync signal
    from `kestrel-init` back to `create.rs`, e.g. a second, short message
    on the same bootstrap socket, or a distinct small pipe; the plan
    should settle on one specific mechanism rather than leaving this
    vague).
  - `delete.rs` deserves explicit ordering, given how many subsystems it
    touches: (1) if running and `--force`, kill the container first
    (reusing `kill.rs`'s own logic, `--all`-equivalent via `cgroup.kill`)
    and wait for it to actually stop; (2) unmount the overlay
    (`kestrel_rootfs::overlay::unmount_overlay`); (3) remove the cgroup
    (`CgroupManager::destroy`); (4) unpin namespaces
    (`kestrel_ns::pin::unpin_namespace` for each pinned type); (5) tear
    down networking (`kestrel_net::bridge::teardown_bridge_network` for
    bridge-mode, a no-op for host/none); (6) run `poststop` hooks; (7)
    remove the `state.json`/bundle-scratch directory itself last, only
    after every other step succeeded (so a partial failure leaves enough
    on disk to diagnose and retry, rather than erasing the evidence).
    Partial-failure handling: each step's error is logged and collected,
    not immediately fatal — `delete` should attempt every step and report
    an aggregate error at the end, since e.g. a namespace-unpin failure
    shouldn't prevent the cgroup from also being cleaned up.
  - `pause.rs`/`resume.rs`/`kill.rs --all` do NOT need new `kestrel-cgroup`
    additions after all — an earlier draft of this design claimed
    `CgroupManager::freeze()`/`thaw()`/`kill_all()` were missing, but
    `crates/kestrel-cgroup/src/control.rs` already implements `freeze(&self,
    frozen: bool)` (with `cgroup.events` polling to confirm the freeze
    actually completed) and `kill_all(&self)` (with a pre-5.14-kernel
    fallback for hosts without a real `cgroup.kill` file) — both already
    built and unit-tested. `pause.rs`/`resume.rs`/`kill.rs --all` simply
    call these directly; this task's job here is pure orchestration, zero
    new cgroup-layer code.
- `cli.rs` — the `clap` derive tying the nine subcommands together, plus
  the single-threaded assertion (`preflight::assert_single_threaded`,
  already built and wired into `main.rs`) at startup.

## 3. New work in `kestrel-init`

- `bootstrap.rs` (thin, calls into `kestrel_oci::bootstrap::recv_bootstrap`)
  — the very first thing `main()` does, reading from the inherited socket
  fd `execve` preserved.
- `mounts.rs`-equivalent orchestration (not new logic — calls
  `kestrel_rootfs::{overlay::mount_overlay, mounts::setup_standard_mounts,
  mask::apply_default_masks, pivot::pivot_root}` in the established Phase
  4 order) plus `sethostname`/time-ns-offset application (new, small —
  `sethostname(2)` and writing `/proc/self/timens_offsets`, both
  documented, narrow syscalls).
- **`fifo.rs` — resolving how a host-created FIFO survives `pivot_root`.**
  CHECKLIST's own step order puts "open exec fifo, block" AFTER
  `pivot_root`, but the FIFO is created by `create.rs` at a HOST path
  (`/run/kestrel/<id>/exec.fifo`) — a plain host path is not resolvable
  from inside the container's mount namespace once `pivot_root` has
  switched `/` to the merged rootfs. The fix: the FIFO's directory (or
  the FIFO file itself) is **bind-mounted into the container's rootfs**
  as one more entry in the standard mount set `kestrel-init` sets up
  pre-pivot (alongside `/proc`/`/sys`/`/dev`), landing at a fixed
  in-container path (e.g. `/.kestrel/exec.fifo`) included in the
  `Bootstrap` payload. `create.rs`'s side (`start.rs`, really — `start`
  is what opens it for writing) uses the ORIGINAL host path; `kestrel-init`
  opens the CONTAINER-relative path, post-pivot, matching CHECKLIST's
  literal step order — both paths resolve to the same underlying FIFO
  inode via the bind mount, so the blocking-open semantics
  (`OpenOptions::read(true).open(...)` blocks until a writer also opens
  it) work correctly across the pivot boundary. This is the second,
  independent motivation (alongside Phase 7's own `/etc/hosts`-wiring
  need, noted in that phase's design as deferred to "Phase 8's assembly
  concern") for a generic "bind-mount an arbitrary host file into the
  container's rootfs" primitive — this phase is where that primitive
  actually gets built, in `kestrel-rootfs` or directly in `kestrel-init`'s
  own mount-orchestration code (a plan-time judgment call: shared enough
  utility that `kestrel-rootfs` is the more natural home, matching how
  every other generic mount primitive in this project already lives
  there).
- `reaper.rs` — the `SIGCHLD` reap loop CHECKLIST describes: block all
  signals except the synchronous-fault set (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE`)
  and create the `signalfd` **before any forking happens** (see the
  ordering note below — CHECKLIST is explicit about this and the initial
  draft of this design got the ordering wrong), a `signalfd`-driven loop,
  `waitpid(-1, WNOHANG)` **in a loop** on every `SIGCHLD` (a single
  delivery can cover multiple deaths — signals don't queue), forwarding
  every other received signal to the entrypoint's pid, exiting with the
  entrypoint's own exit code or `128 + signum` if it died by signal.
  SPEC.md §12 already has a worked skeleton for this (`run_init`) — this
  task adapts that skeleton to real code, verifying `signalfd`/`SigSet`
  APIs against the real `nix` version this workspace pins, not trusting
  the skeleton as literal compilable Rust.
- `main.rs` — ties `bootstrap` → `mount_overlay`/`setup_standard_mounts`/
  `apply_default_masks` → FIFO bind-mount → `createContainer` hooks →
  **`pivot_root`** → `sethostname`/time-ns offsets → `fifo::block` →
  `startContainer` hooks → `kestrel_security::apply::apply_all` →
  **block signals + create the
  `signalfd` (per `reaper.rs` above) BEFORE forking the entrypoint** — a
  signal arriving in the gap between fork and signal-masking could
  otherwise be missed by the `signalfd` loop entirely, leaving a zombie
  unreaped until some unrelated later `SIGCHLD` happens to trigger a
  cleanup sweep — → fork the real entrypoint process → `reaper::run_init(entrypoint_pid,
  signalfd)` (the armed `signalfd` is now a parameter the reaper
  receives, not something it creates internally, unlike SPEC.md §12's
  own sketch, which conflates "created inside `run_init`" with "created
  before fork" in a way that's only consistent if `run_init` itself is
  called before the fork and does the fork internally — this design
  makes that ordering explicit rather than leaving it to be inferred).

This is a genuine architectural fork in `kestrel-init`'s own design worth
being explicit about: PID 1 does NOT `execve` into the user's entrypoint
directly (that would replace PID 1's own image, losing the ability to
reap orphans afterward). Instead, PID 1 `fork()`s one more time; the
FORKED CHILD (now PID 2 in the new namespace) is what actually
`execve`s into the entrypoint via `kestrel_init::exec::exec_into`; PID 1
itself stays alive running `reaper::run_init`, watching that child (and
any orphans that get reparented to it) until the whole namespace's work
is done, then — per the exit-code plumbing in §2 — writes the outcome to
`state.json` before its own final exit. SPEC.md §12's `run_init(child:
Pid)` skeleton's signature already implies exactly this shape (`child` is
a parameter, meaning some earlier caller already forked it) — confirms
this reading rather than inventing it.

**`pdeathsig` is explicitly NOT used to tie container lifetime to
`kestrel-runtime`'s `create` process.** Phase 5 already built
`PR_SET_PDEATHSIG` support (`kestrel-init/src/pdeathsig.rs`), and it
would be a natural-looking move to re-arm it here — but `PR_SET_PDEATHSIG`'s
target is whichever process is the caller's parent AT THE MOMENT the
`prctl` call is made, and does not auto-rearm across later reparenting.
Since `create` is designed (SPEC.md §4.2, §9.1's whole `created` vs.
`running` state split) to exit immediately after writing `state.json`,
arming `pdeathsig` against it (or against any ancestor in that
short-lived lineage) would kill the container the instant `create`
returns — destroying the entire point of the create/start split. Phase
5's `pdeathsig` module remains available for a different purpose (e.g. a
future `kestreld`-owned exec session that legitimately wants
death-linked child lifetime) but is not part of this phase's
create/start/init lifecycle at all.

## 4. Testing strategy

- **Synthetic test rootfs**: a tiny tar built directly in the test suite
  containing one statically-linked binary (compiled once as a fixture,
  matching the same `-C target-feature=+crt-static` build the real
  `kestrel-init` binary itself needs — this project already has this
  exact pattern from Phase 5's `kestrel-init/tests/fixtures/*.rs`, reused
  here) that can print its args/env, sleep, exit with a specific code, or
  spawn-and-abandon children on request (parameterized via argv, so one
  fixture binary covers `test_exit_code_propagates`,
  `test_signal_exit_code`, and `test_zombie_reaping`'s different needs
  without three separate fixtures).
- **`test_create_then_start`**: after `create`, assert (via `state`) the
  process exists (a real pid, alive) but the fixture's own "I ran" marker
  (e.g. a file it would write, or output captured before/after `start`)
  hasn't appeared; after `start`, it has.
- **`test_exit_code_propagates`**: fixture exits 42 → poll `state`
  (`kestrel_oci::state::State::exit_code`, written by `kestrel-init`'s
  reaper per §2's exit-code plumbing) until `status == Stopped`, assert
  `exit_code == Some(42)` — grounded in the real, designed mechanism now,
  not a hedge.
- **`test_signal_exit_code`**: `kill -KILL` the container → poll `state`
  the same way → `exit_code == Some(137)` (`128 + SIGKILL`).
- **`test_zombie_reaping`**: fixture spawns and abandons 10,000 children
  (double-forking or similar to guarantee they orphan to PID 1) →
  `pids.current` (the cgroup's own live counter, already readable via
  `kestrel-cgroup`) returns to baseline once they've all been reaped —
  proving the reaper's `WNOHANG` loop genuinely drains multiple deaths
  per `SIGCHLD`, not just one. **Resource-limit note**: 10,000 forks
  needs the container's own `pids.max` (cgroup) set generously (or
  `"max"`) for this specific test's cgroup, and the Lima VM's own
  process/fd-limit defaults should be checked before assuming a bare
  `fork()` loop won't hit `EAGAIN` for reasons unrelated to reaper
  correctness — the implementation plan should verify actual achieved
  fork count and headroom rather than assuming 10,000 will always
  succeed cleanly on any machine this runs on.
- **`test_hooks_fire_in_order`**: all 5 hook phases append a
  phase-identifying line to a shared file (passed via a hook argument or
  env var); assert the file's final content is in the exact expected
  order (`createRuntime`, `createContainer`, `startContainer`, `poststart`,
  `poststop`).
- Root-gated (`#[ignore]`), run inside the Lima VM — same pattern as
  every phase since Phase 2.

## Out of scope for this increment

`kestreld` (the daemon) forking+exec'ing `kestrel-runtime` rather than
linking it — that invariant matters to Phase 9's own design, not this
one; `kestrel-runtime` here is built and tested purely as a standalone
CLI, the same way `runc` itself is usable directly. Rootless namespace
creation's own edge cases beyond what Phase 2's `NamespacePlan`/`stages.rs`
already handle. Any TUI/CLI-frontend polish (Phases 10-11) — this phase
produces the `kestrel-runtime` binary's subcommands, not a human-friendly
wrapper CLI around them (that's Phase 10's `kestrel` binary, which will
itself likely shell out to or link `kestrel-runtime`'s logic — a decision
for that phase, not this one). Real-image-based end-to-end testing (the
5 required tests use a synthetic rootfs per the confirmed scope decision
above); a real-pulled-image capstone test was considered and explicitly
deferred, not silently dropped.
