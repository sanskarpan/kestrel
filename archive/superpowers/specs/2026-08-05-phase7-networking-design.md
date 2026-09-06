# Kestrel — Phase 7 (Networking) Design

## Context

Phase 7 builds `kestrel-net`: CHECKLIST.md's Phase 7 section (24 tasks) and
SPEC.md §11 describe network-namespace lifecycle, a bridge/veth data path set
up entirely through `rtnetlink` (no shelling out to `ip`/`brctl`), IPAM,
NAT (MASQUERADE egress, DNAT for published ports), the four networking
modes (`bridge`/`host`/`none`/`container:<id>`), `/etc/hosts` and friends,
and an embedded DNS resolver for container-name lookups. This is currently
an empty stub crate (`crates/kestrel-net/src/lib.rs` says "not yet
implemented").

Two scope decisions were made before this design was written:

- **NAT is implemented by shelling out to `iptables`**, not a pure-Rust
  netfilter crate. CHECKLIST's "no shelling out" constraint is worded
  specifically under the "Bridge & veth (rtnetlink only, no shelling out)"
  heading — it does not extend to the NAT section, and every argument
  passed to `iptables` is a fixed, internally-constructed list (subnet
  CIDR, chain names, IPs/ports from IPAM), never raw user input, so this
  isn't a shell-injection risk in the way a naive "shell out to whatever
  the user gives us" design would be.
- **The embedded DNS resolver (🟡) is in scope; rootless pasta/slirp4netns
  delegation (🟡) is explicitly deferred**, same "un-defer selectively,
  document what stays deferred" pattern Phase 5 used for its own 🟡 items.
  Rootless delegation needs a second, structurally different networking
  code path (subprocess lifecycle, FD passing, a different privilege
  model) that's a clean, independently-testable follow-up rather than
  something that belongs bolted onto this phase's primary rootful path.

## 1. Crate ownership — reusing `kestrel-ns`, not duplicating it

`kestrel-net` gains a regular dependency on `kestrel-ns` (Phase 2/3,
already stable) and reuses two of its primitives directly, rather than
reimplementing namespace pinning a second time (the same "reuse, don't
duplicate" discipline Phase 6 applied to `kestrel-rootfs::chain_id`):

- `kestrel_ns::pin::{pin_namespace, unpin_namespace}` and `NsType::Net`
  (already present — `NsType`'s `CLONE_NEWNET` mapping has existed since
  Phase 2) for creating and tearing down the netns pin itself.
- A **new** primitive that doesn't exist yet: CHECKLIST asks for
  `nsenter(fd, closure)` that *restores the original namespace on the way
  out*. `kestrel_ns::join::join_namespaces` is a one-way join (used once,
  at final container exec, to enter a full namespace set and never look
  back) — it has no restore semantics and isn't the right tool here. This
  phase adds `kestrel_ns::join::with_namespace(ns_type: NsType, fd:
  BorrowedFd, f: impl FnOnce() -> Result<T>) -> Result<T>`: opens
  `/proc/self/ns/<type>` to remember the caller's current namespace,
  `setns`s into `fd`, runs `f`, `setns`s back to the remembered namespace
  before returning (via a guard whose `Drop` does the restore, so a panic
  inside `f` doesn't leave the calling thread stuck in the wrong
  namespace). This is a generically useful "temporarily join a namespace"
  primitive, not networking-specific, so it belongs in `kestrel-ns` rather
  than being duplicated inside `kestrel-net`. `kestrel-net`'s own
  `nsenter(fd, closure)` (CHECKLIST's literal ask) is a thin
  `NsType::Net`-specialized wrapper around it.

This is a one-way dependency (`kestrel-net → kestrel-ns`); `kestrel-ns` has
no reason to ever depend back on `kestrel-net`, so — unlike Phase 6's
`kestrel-image`/`kestrel-rootfs` situation — there's no dev-dependency-cycle
question to verify here at all.

`kestrel-net` pins network namespaces at `/run/kestrel/netns/<id>` — a
dedicated top-level path, per CHECKLIST, distinct from the general
`/run/kestrel/<id>/ns/<type>` pin layout SPEC.md §6 describes for a
container's full namespace set. A netns can exist and be referenced
(`container:<id>` mode joins another container's netns) independently of
whether that container's other namespaces have even been created yet, so
giving it its own stable, predictable path — keyed by container id,
resolvable before or after the rest of that container's namespace set
exists — is deliberate, not an inconsistency with the general pin layout.

## 2. New modules in `kestrel-net`

- `netns.rs` — `create_netns(id) -> Result<PathBuf>` and
  `teardown_netns(id)` (unpin, remove the file) built on the reused
  `kestrel-ns` primitives. `nsenter(pin_path, closure)` — the
  `NsType::Net`-specialized wrapper described above.

  **`create_netns` does NOT use a raw `fork()`.** `kestrel-ns`'s own
  `run_isolated`/three-stage-dance fork pattern is only proven safe inside
  `kestrel-runtime`, a process Rule #2 *guarantees* is single-threaded at
  that point. `kestrel-net` is explicitly multi-threaded (tokio
  `rt-multi-thread`, §3) — a raw `fork()` from one of its threads only
  duplicates the calling thread; if any other thread (allocator, tracing
  subscriber, tokio's own internals) held a lock at the instant of fork,
  the child can deadlock the moment it touches that lock, which
  `unshare()`+pinning-related bookkeeping plausibly would. Instead,
  `create_netns` spawns a tiny, dedicated helper subprocess via
  `tokio::process::Command` (`std`/`tokio`'s `Command` uses `posix_spawn`
  on Linux specifically to avoid this class of multi-threaded-fork hazard,
  unlike a raw `nix::unistd::fork()` call). The helper binary
  (`crates/kestrel-net/src/bin/netns-helper.rs`, spawned with `stdin`
  piped) does exactly three things, all async-signal-safe: `unshare(CLONE_NEWNET)`,
  write a single readiness byte to its own stdout (so the parent knows the
  unshare succeeded before proceeding), then block reading from stdin
  until EOF (the parent closing the pipe) or a byte arrives, then exit.
  The parent reads the readiness byte, calls `kestrel_ns::pin::pin_namespace(helper_pid,
  NsType::Net, target)` (the namespace persists via the bind-mount pin
  even after the helper exits — pinning is what keeps it alive, not the
  process), then closes the helper's stdin to let it exit and reaps it.
  This keeps the multi-threaded async code path entirely free of raw
  `fork()`.
- `bridge.rs` — `ensure_bridge(name, gateway, subnet) -> Result<BridgeHandle>`:
  create via `rtnetlink` if absent, assign the gateway address, bring up.
  Idempotent (checking for an existing link by name before creating).
  Also names the composed, single-call teardown entrypoint that mirrors
  `attach_bridge`'s composed setup: `teardown_bridge_network(id) ->
  Result<()>`, calling (in order) veth/link deletion, `ipam::release`,
  `nat::teardown_network_nat(id)`, and `netns::teardown_netns(id)` — the
  one function Phase 8's `delete` command calls to tear down a bridge-mode
  container's networking as a single unit, and the one
  `test_teardown_leaves_no_rules` calls before diffing state.
- `veth.rs` — veth pair creation, moving the peer into the target netns
  **by fd** (`setns_by_fd`, not by pid — a pid-based move is a real TOCTOU
  hazard if the target process exits and its pid is reused between
  namespace creation and the move), enslaving the host end to the bridge,
  MTU, bring-up; inside the netns (via `nsenter`): rename to `eth0`,
  assign the IPAM-allocated address, bring up, bring `lo` up, add the
  default route via the bridge gateway. Deterministic MAC: a fixed
  locally-administered OUI prefix (`02:xx`, per IEEE 802's
  locally-administered-address bit) plus bytes derived from the
  container's allocated IP, so the MAC is stable across container
  restarts without needing separate persisted state.
- `ipam.rs` — a bitmap allocator over a `/24`-or-configurable subnet,
  persisted to disk as JSON under the data dir (matching the write-temp-
  then-rename atomicity discipline `kestrel-image`'s `ContentStore`
  (`crates/kestrel-image/src/store.rs`) already established — `LayerStore`,
  by contrast, is `kestrel-rootfs`'s, not `kestrel-image`'s; it's the
  atomicity *pattern* being reused here, not either specific type).
  Reserves network/broadcast/gateway addresses up front so they're never
  handed out to a container. `release(ip)` on container delete; a
  `sweep()` reconciling the persisted bitmap against actually-running
  containers on daemon start, releasing anything whose owning container no
  longer exists (leak recovery from a crash mid-lifecycle).
- `nat.rs` — `ensure_masquerade(subnet, bridge_name)`,
  `add_dnat(published_port, container_ip)`/`remove_dnat(...)`,
  `teardown_network_nat(id)`, all via `std::process::Command::new("iptables")`
  with argument VECTORS (never a shell string).

  **Chain structure fixes a real teardown-correctness gap**: SPEC.md
  §11.3's own example inserts MASQUERADE/hairpin/FORWARD rules directly
  into the shared built-in chains (`POSTROUTING`, `FORWARD`), with only
  per-port DNAT going into a dedicated chain — rules planted directly in a
  shared chain can't be removed by a chain flush, only by an exact
  argument-identical `-D` delete, which is real work to get right and
  fragile across a daemon restart. Instead, `kestrel-net` owns **two**
  custom chains, `KESTREL-POSTROUTING` and `KESTREL-FORWARD`, each linked
  into its respective built-in chain by exactly **one** jump rule
  (`POSTROUTING -j KESTREL-POSTROUTING`, `FORWARD -j KESTREL-FORWARD`) —
  the same pattern Docker itself uses for its own `DOCKER`/`DOCKER-USER`
  chains. Every actual MASQUERADE/hairpin/DNAT/FORWARD-accept rule this
  project creates lives inside these two fully-kestrel-owned chains.
  Teardown (`teardown_network_nat`, and the workspace-wide equivalent for
  a full daemon shutdown) is then simple and exact: flush + delete the two
  custom chains, and remove the two single jump rules by their own exact
  (short, fixed) spec — no argument-identical-matching problem for the
  bulk of the rules at all. Idempotent: every add operation checks for the
  rule's existence first (`iptables -C ...`) before inserting, so
  re-running setup (e.g. after a daemon restart) doesn't duplicate rules.
  Also sets `net.ipv4.ip_forward=1` and
  `net.bridge.bridge-nf-call-iptables=1` via `/proc/sys` writes (no need
  to shell out to `sysctl` for this part — direct file writes are simpler
  and equally correct); the latter path only exists if `br_netfilter` is
  loaded, an assumption about the Lima VM's kernel config that
  `ensure_masquerade` checks explicitly and fails loudly on (a clear
  "load the br_netfilter module" error) rather than silently no-op-ing if
  the `/proc/sys` path is missing.
- `modes.rs` — `NetworkConfig` enum/dispatcher: `Bridge(BridgeConfig)`
  (the full path above), `Host` (skip `CLONE_NEWNET` entirely — shares the
  host network stack, so this mode does essentially nothing at the
  `kestrel-net` layer beyond being a recognized, explicit no-op), `None`
  (new netns, `lo` up, nothing else), `Container(String)` (resolve the
  referenced container's pinned netns path and `setns` into it directly,
  no new netns of its own — pod-style shared networking).

  **`container:<id>` resolution is explicitly one-hop only.** Only
  `Bridge` and `None` modes ever create+pin a netns at
  `/run/kestrel/netns/<id>` (only they call `CLONE_NEWNET`); `Host` mode
  never does. `Container(String)` mode itself also never creates its own
  pin — it joins the referenced one directly. Two validation rules follow
  from this, checked at network-setup time (before any netns/veth work
  starts, so failure is immediate and clear rather than a confusing
  downstream `setns(ENOENT)`): (1) referencing a container whose mode is
  `Host` is a hard error (`"cannot join network of container <id>: it has
  no network namespace (mode=host)"`) — there is nothing to resolve `/run/kestrel/netns/<id>`
  to. (2) referencing a container that is *itself* in `Container(...)`
  mode is also a hard error, not silently resolved transitively — chained
  pod-sharing (A shares B's net, C wants to share A's-which-is-really-B's)
  adds real complexity (what happens if B is deleted while A and C both
  reference it transitively?) that neither CHECKLIST nor SPEC asks for;
  keeping this a flat, one-hop-only relationship is a deliberate
  simplification, not an oversight. A caller that wants three containers
  sharing one network should have all three reference the same
  `Bridge`/`None`-mode owner directly.
- `hosts.rs` — generates `/etc/hosts` (container's own hostname/IP plus
  any configured extra entries), `/etc/hostname`, and `/etc/resolv.conf`
  (pointing at the bridge gateway IP when the embedded resolver is
  active, or copying the host's own `/etc/resolv.conf` for `host`/`none`
  modes) as real files under a per-container directory, ready to be
  bind-mounted into the container once Phase 8 adds a generic
  bind-mount-arbitrary-file step to container assembly — `kestrel-rootfs`
  (Phase 4) currently only has fixed-purpose mount helpers
  (`setup_standard_mounts` for fixed fs-type mounts, `bind_default_devices`
  for a fixed device-node list), not yet a generic "bind-mount this file
  into that container" primitive, so that's real, not-yet-built Phase 8
  work, not something this phase can lean on today. `kestrel-net` only
  generates the file *contents*; the
  actual bind-mount-into-the-container-rootfs step is Phase 8's assembly
  concern (`kestrel-runtime`'s `create` command), consistent with this
  project's "build the mechanism here, wire it into the daemon/runtime
  later" pattern already used by Phase 5's seccomp-notify and Phase 6's
  pull progress callback.
- `dns.rs` — a minimal async UDP server (`tokio::net::UdpSocket`) bound to
  the bridge gateway IP on port 53, answering A-record queries for
  container names by looking them up against the same IPAM allocation
  records `ipam.rs` maintains (no separate DNS-specific storage). Anything
  it doesn't recognize is either NXDOMAIN or (a config option) forwarded
  upstream to the host's real resolver — forwarding is a reasonable
  default so container DNS isn't strictly limited to sibling-container
  lookups, but the forwarding path is a straightforward proxy, not a
  caching resolver; no negative-caching, no recursion, kept intentionally
  minimal, matching this item's 🟡 (best-effort) status in the checklist.

## 3. Async runtime

Same justification as Phase 6, re-verified against this phase's actual
need rather than assumed: the real `rtnetlink` crate is async/tokio-based
— netlink sockets in Rust's ecosystem are built on an async foundation
because the underlying protocol is inherently request/response-over-a-
socket, and `rtnetlink` doesn't offer a blocking API. **SPEC.md §11.2's
own pseudocode's exact `.execute().await?` chaining style
(`handle.link().set(peer_idx).setns_by_fd(netns_fd).execute().await?`)
does NOT match the real, current `rtnetlink` crate API one-for-one** —
checked against the crate's actual source: `setns_by_fd`/`controller`/`up`
now live on a separately-built `LinkMessageBuilder`, not chained directly
off `handle.link().set(idx)`. The underlying capabilities genuinely exist
(fd-based netns move, bridge enslavement, link up, all present in the real
crate), so SPEC's pseudocode is directionally right about what's
*possible*, just not literally compilable as written — this gets nailed
down against the exact pinned crate version during plan-writing, not
trusted as a literal transcription. PROMPT.md's Rule #2 (`kestrel-runtime`
single-threaded, no async runtime) is scoped to `kestrel-runtime`
specifically, not other crates — already established and re-verified in
Phase 6, applies unchanged here. `kestrel-net` gets `tokio` + `rtnetlink` +
`futures-util` (for stream consumption of rtnetlink's responses) as its
own dependency stack, independent of `kestreld`'s not-yet-built async
stack.

The one place this phase's async code meets synchronous, root-privileged,
fork-sensitive code is `nsenter`/`with_namespace`: `setns` itself is a
synchronous syscall, and the closures run through it (bridge/veth setup
*inside* a netns) are synchronous rtnetlink calls too. A raw `setns()`
changes the CURRENT THREAD's namespace membership and must not race
against tokio's work-stealing scheduler migrating the async task to a
different OS thread mid-closure — so any `nsenter`-wrapped section must
run on ONE pinned OS thread for its whole duration. `tokio::task::block_in_place`
(not `Handle::block_on`, which panics if called reentrantly from a thread
already inside a tokio runtime worker — the two are not interchangeable
alternatives, and only `block_in_place` is actually safe here) is the
mechanism: it runs the given closure on the current worker thread while
telling tokio's scheduler not to migrate other tasks onto it, without
spawning a fresh OS thread. This only works on the multi-threaded runtime
flavor (which `kestrel-net` already uses). This gets verified for real
against `rtnetlink`'s and tokio's actual APIs during plan-writing
(following this project's "verify against real vendored source, don't
trust a pseudocode sketch" discipline), not assumed correct here.

`dns.rs`'s UDP resolver is a different lifetime shape from the rest of
this crate's short, request/response-shaped netlink calls — it must run
continuously for as long as bridge-mode networking is active, not
complete-and-return. `kestrel-net` does NOT own a persistent
`tokio::Runtime` of its own for this. `dns::serve(gateway_ip, ipam: Arc<Ipam>) -> impl Future<Output = Result<()>>`
is a plain async function; whatever process owns an async runtime at the
point bridge networking is actually wired up (a test harness in this
phase, `kestreld` in Phase 9) is responsible for `tokio::spawn`ing it and
holding the resulting `JoinHandle` for its own shutdown sequencing — the
same "build the mechanism, the daemon owns scheduling it" pattern Phase
5's `run_notify_loop` already established. This keeps the claim that
`kestrel-net`'s tokio usage is independent of `kestreld`'s own stack
accurate: `kestrel-net` never spins up its own background runtime thread
that would need reconciling with `kestreld`'s later.

## 4. Testing strategy

Continues the project's established split:

- **Deterministic, no root/network**: IPAM bitmap allocation/release/
  reservation logic, deterministic MAC derivation, NAT rule
  argument-vector construction (asserting the exact `iptables` args built,
  without actually invoking the binary — a fake `Command` runner or simply
  testing the pure argument-building functions in isolation), `/etc/hosts`
  /`/etc/resolv.conf` content generation.
- **Root-gated (`#[ignore]`), real kernel networking, run inside the Lima
  VM** — same pattern as every phase since Phase 2 — covering the 5
  CHECKLIST-required scenarios: `test_none_mode_only_lo` (exactly one
  interface after netns setup), `test_bridge_egress` (a container reaches
  a real external address), `test_inter_container` (two containers on the
  same bridge ping each other), `test_published_port` (a `curl` from the
  VM's host network namespace to `localhost:<hostport>` reaches the
  container), `test_teardown_leaves_no_rules` (diffing `iptables-save`
  output and `ip link`/`ip addr` state before and after full setup+
  teardown, proving zero residue — the same "before/after diff, not just
  no-error" rigor Phase 4's `pivot_root` lifecycle test applied to
  `/proc/self/mountinfo`).
- One capstone-style test (not explicitly in CHECKLIST's 5, but a natural
  extension given this project's established pattern of one composing
  test per phase) exercising `container:<id>` mode: two containers where
  the second joins the first's already-pinned netns and can reach a
  socket the first is listening on — proving the shared-netns "pod" path
  actually works end to end, not just that the mode is recognized.
- `host` mode gets its own small root-gated test too (`test_host_mode_shares_host_stack`):
  bundled into the same required 🔴 CHECKLIST bullet as `none`/`container:<id>`,
  but with no dedicated test named in CHECKLIST's own list, it would
  otherwise be the one mode with zero direct coverage. Asserts that a
  process set up under `Host` mode sees the SAME interface list as the
  VM's real host namespace (proving `CLONE_NEWNET` was genuinely skipped,
  not just that no error occurred).

## Out of scope for this increment

Rootless pasta/slirp4netns delegation (🟡, deferred per the scope decision
above). Wiring `hosts.rs`'s generated files into an actual bind-mount
during container creation, and wiring `NetworkConfig` into
`kestrel-runtime`'s `create`/`delete` command flow — both Phase 8 assembly
concerns, same "phases are independently tested before Phase 8 assembly"
rule applied to every prior phase. IPv6 (SPEC.md/CHECKLIST.md's Phase 7
section is IPv4-only throughout; no IPv6 pseudocode or checklist item
exists to implement against). Any `kestreld` HTTP/API surface for network
configuration (Phase 9).
