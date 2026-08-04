# CHECKLIST.md — Container Runtime from Scratch (`kestrel`)

> Priority: 🔴 blocking · 🟡 important · 🟢 enhancement · 🔵 stretch
> **Phases 2–5 (namespaces, cgroups, rootfs, security) are the kernel core. Each must be independently testable before the runtime binary is assembled in Phase 8.**
> **Requires: Linux ≥ 5.11, cgroup v2 unified, root (or a delegated userns for rootless work).**

---

## Phase 0 — Bootstrap & Environment Guard (14 tasks)

- [ ] 🔴 `cargo new --lib` workspace; 12 member crates per SPEC §16
- [ ] 🔴 Workspace `Cargo.toml`: shared deps `nix`, `libc`, `rustix`, `anyhow`, `thiserror`, `serde`, `serde_json`, `tracing`
- [ ] 🔴 `kestrel-runtime` deps must **exclude** `tokio` — enforce with a `cargo deny` rule or a test that inspects `cargo tree`
- [ ] 🔴 `crates/kestrel-oci`: pull in `oci-spec` and re-export; add local extension types
- [ ] 🔴 Preflight check binary: kernel ≥ 5.11, cgroup2 mounted at `/sys/fs/cgroup`, `overlay` in `/proc/filesystems`, `unprivileged_userns_clone` enabled
- [ ] 🔴 Preflight also reports which controllers are available in `/sys/fs/cgroup/cgroup.controllers`
- [ ] 🔴 `tracing` setup with a `container_id` span field threaded through every subsystem
- [ ] 🔴 Error model: `thiserror` per crate, `anyhow` only at binary boundaries
- [ ] 🔴 `Makefile`: `build`, `test`, `test-root` (integration, needs sudo), `oci-conformance`, `web-dev`, `tui`
- [ ] 🔴 Vagrant/QEMU dev VM definition — **do not develop this on your main machine**; a bad `pivot_root` or `umount` can wedge the host
- [ ] 🔴 `cd web && bun create vite . --template react-ts`
- [ ] 🔴 `bun add @tanstack/react-query @tanstack/react-table d3 recharts @xterm/xterm @xterm/addon-fit zustand clsx lucide-react`
- [ ] 🔴 `bun add -d tailwindcss postcss autoprefixer @types/d3`; `bunx shadcn@latest init` + add `button card table badge tabs dialog select tooltip sheet progress separator scroll-area`
- [ ] 🔴 `web/vite.config.ts`: proxy `/v1` and `/events` → `http://localhost:7777`

---

## Phase 1 — OCI Spec Types (12 tasks)

- [ ] 🔴 `Spec`, `Process`, `Root`, `Mount`, `Linux`, `LinuxResources`, `LinuxNamespace`, `LinuxIdMapping`
- [ ] 🔴 `LinuxCapabilities` (5 sets), `LinuxSeccomp`, `LinuxDevice`, `LinuxRlimit`
- [ ] 🔴 `Hooks` with all 5 phases (`createRuntime`, `createContainer`, `startContainer`, `poststart`, `poststop`) + deprecated `prestart`
- [ ] 🔴 `State { ociVersion, id, status, pid, bundle, annotations }` with `Status` enum
- [ ] 🔴 `Spec::validate()`: root path present, process args non-empty, no duplicate namespace types, id-map coverage
- [ ] 🔴 Default spec generator (`kestrel spec`) matching `runc spec` output
- [ ] 🔴 Image config → runtime spec translation (Env, Cmd, Entrypoint, WorkingDir, User, ExposedPorts, Volumes)
- [ ] 🔴 `User` resolution: numeric, `name`, `name:group`, `uid:gid` — resolve against the **container's** `/etc/passwd`, not the host's
- [ ] 🔴 Serde round-trip preserves unknown fields (forward compatibility)
- [ ] 🔴 Unit test: parse the official OCI example `config.json` without loss
- [ ] 🔴 Unit test: `validate()` rejects duplicate namespaces, empty args, missing root
- [ ] 🔴 Unit test: user resolution against a synthetic `/etc/passwd`

---

## Phase 2 — Namespaces (28 tasks)

**Core**
- [ ] 🔴 `NsType` enum (8 variants) with `clone_flag()` and `proc_name()`
- [ ] 🔴 `CLONE_NEWTIME = 0x00000080` — not in `nix`, define manually
- [ ] 🔴 `NamespacePlan`: which to create, which to join, in what order
- [ ] 🔴 `unshare_namespaces(flags)` wrapper with errno context
- [ ] 🔴 `setns_ordered(pins)` — **user namespace LAST** (entering it drops the caps needed for the rest)
- [ ] 🔴 `pin_namespace(pid, ns, target)`: create target file, bind-mount `/proc/<pid>/ns/<t>`
- [ ] 🔴 `unpin_namespace`: `umount2(MNT_DETACH)` + unlink
- [ ] 🔴 `read_ns_inode(pid, ns)` from the `/proc/<pid>/ns/<t>` symlink target (`net:[4026532001]`)

**ID maps**
- [ ] 🔴 `IdMapping { container_id, host_id, size }`
- [ ] 🔴 `write_id_maps(pid, uid, gid)` — **`setgroups=deny` BEFORE `gid_map`** (CVE-2014-8989)
- [ ] 🔴 All map lines in a **single** `write()` — the kernel permits exactly one write per namespace
- [ ] 🔴 Ignore `ENOENT` on `setgroups` for pre-3.19 kernels
- [ ] 🟡 Rootless: parse `/etc/subuid`, `/etc/subgid`; build maps from the allocated range
- [ ] 🟡 Rootless: `newuidmap`/`newgidmap` fallback when the range exceeds what we can map directly

**The three-stage dance**
- [ ] 🔴 `socketpair(AF_UNIX, SOCK_SEQPACKET)` for stage synchronization
- [ ] 🔴 Sync protocol enum: `RequestMaps`, `MapsDone`, `ReportPid`, `Ready`, `Error(String)`
- [ ] 🔴 STAGE 0: clone with everything **except** `CLONE_NEWPID`; write maps; receive grandchild PID
- [ ] 🔴 STAGE 1: request maps; `setresuid(0,0,0)`; `unshare(CLONE_NEWPID)`; fork; report PID; `_exit(0)`
- [ ] 🔴 STAGE 2 becomes PID 1 — reparented to the host init when STAGE 1 exits
- [ ] 🔴 Every stage writes errors to the sync socket so the parent surfaces a real message instead of a silent hang
- [ ] 🔴 Timeout on every sync read — a wedged stage must fail, not block forever

**Tests**
- [ ] 🔴 `test_uts_isolation`: sethostname inside; host hostname unchanged
- [ ] 🔴 `test_pid_isolation`: init sees itself as PID 1; `/proc` lists only container processes
- [ ] 🔴 `test_userns_maps`: uid 0 inside maps to the invoking uid outside
- [ ] 🔴 `test_setgroups_deny_required`: writing `gid_map` without denying setgroups returns `EPERM`
- [ ] 🔴 `test_ns_inode_differs`: container ns inode ≠ host ns inode for all 8
- [ ] 🔴 `test_pin_survives_pid1_exit`: pinned ns still enterable after PID 1 dies
- [ ] 🔴 `test_join_order`: joining user-first then net fails; net-first then user succeeds
- [ ] 🔴 `test_single_threaded`: assert `/proc/self/status` `Threads: 1` throughout setup

---

## Phase 3 — cgroups v2 (30 tasks)

**Manager**
- [ ] 🔴 `CgroupManager { root, path, delegated }`; detect v2 by `statfs` magic `CGROUP2_SUPER_MAGIC`
- [ ] 🔴 Refuse to run on v1/hybrid with a clear error naming `systemd.unified_cgroup_hierarchy=1`
- [ ] 🔴 `read_available_controllers()` from `cgroup.controllers`
- [ ] 🔴 `enable_controllers_in_parents()` — walk root→parent writing `+cpu +memory +io +pids`; **never enable in the leaf itself**
- [ ] 🔴 Respect the **no-internal-process rule**: containers always get a leaf cgroup
- [ ] 🔴 `create()`, `destroy()` (with retry on `EBUSY` while processes exit)
- [ ] 🔴 `add_process(pid)` → `cgroup.procs`

**Controllers**
- [ ] 🔴 `cpu.max` = `"<quota> <period>"` or `"max <period>"`
- [ ] 🔴 `cpu.weight` from OCI `shares` via the v1→v2 conversion (`1 + (s-2)*9999/262142`)
- [ ] 🔴 `cpuset.cpus`, `cpuset.mems`
- [ ] 🔴 `memory.max` (hard), `memory.high` (throttle), `memory.low`, `memory.min`
- [ ] 🔴 `memory.swap.max` — v2 swap is **separate**, not memory+swap as in v1
- [ ] 🔴 `pids.max`
- [ ] 🔴 `io.max` per-device `rbps/wbps/riops/wiops`; `io.weight`
- [ ] 🔴 `hugetlb.<size>.max` when the controller is present
- [ ] 🟡 Unified `"max"` / `"-1"` / `0` limit formatting helper

**Runtime control**
- [ ] 🔴 `freeze(bool)` via `cgroup.freeze`; poll `cgroup.events` for `frozen 1`
- [ ] 🔴 `kill_all()` via `cgroup.kill` (5.14+), fallback to iterating `cgroup.procs`
- [ ] 🔴 `is_populated()` from `cgroup.events` `populated`

**Stats & PSI**
- [ ] 🔴 `stats()`: parse `cpu.stat` (`usage_usec`, `nr_throttled`, `throttled_usec`), `memory.current`, `memory.peak`, `memory.stat`, `io.stat`, `pids.current`
- [ ] 🔴 `oom_events()` from `memory.events` — `oom_kill` is the authoritative OOM signal, **not** exit code 137
- [ ] 🔴 `Psi { some, full }` parser for `cpu.pressure` / `memory.pressure` / `io.pressure` (note: `cpu` has no `full` on older kernels)
- [ ] 🟡 PSI threshold triggers: write `"some <stall_us> <window_us>"`, `poll(POLLPRI)` — event-driven, not polled
- [ ] 🟡 Graceful degradation when `CONFIG_PSI` is off

**clone3**
- [ ] 🟡 `CloneArgs` repr(C) struct; `CLONE_INTO_CGROUP = 0x200000000000`
- [ ] 🟡 `clone_into_cgroup(flags, cgroup_fd)` via `SYS_clone3`
- [ ] 🟡 Fallback to `fork()` + write `cgroup.procs` on `ENOSYS`

**Tests**
- [ ] 🔴 `test_memory_limit_ooms`: allocate past `memory.max`; `memory.events.oom_kill` increments
- [ ] 🔴 `test_cpu_throttle`: busy loop under `cpu.max=50000 100000`; `cpu.stat.nr_throttled` > 0
- [ ] 🔴 `test_pids_limit`: fork bomb stopped at `pids.max`; host unaffected
- [ ] 🔴 `test_no_internal_processes`: writing a PID to a cgroup with `subtree_control` set fails
- [ ] 🔴 `test_freeze_thaw`: frozen process makes no progress; thaw resumes it
- [ ] 🟡 `test_clone_into_cgroup_no_window`: memory bomb in the first instruction still OOM-killed

---

## Phase 4 — Rootfs, OverlayFS & pivot_root (30 tasks)

**Snapshotter**
- [ ] 🔴 Directory layout per SPEC §6.1
- [ ] 🔴 `chain_id(diff_ids)` computation
- [ ] 🔴 Layer store keyed by chainID; `parent` file records the chain
- [ ] 🔴 **Symlink farm**: `l/<6-char>` → `../layers/<chain>/diff`; `chdir(data_dir)` before mount so option strings stay under 4096 bytes
- [ ] 🔴 `Snapshot { lower_links, upper, work, merged }`; `work` must be **empty** at mount time
- [ ] 🔴 `mount_overlay()`: lowerdir colon-joined, **reversed** (rightmost = bottom)
- [ ] 🔴 `userxattr` when rootless (5.11+); `metacopy=on`; `redirect_dir=on`
- [ ] 🔴 `unmount_overlay()` with `MNT_DETACH` and busy-retry
- [ ] 🟡 Driver fallback chain: `overlay2` → `fuse-overlayfs` → `vfs`

**Layer application**
- [ ] 🔴 `apply_layer(tar, dest)`: stream-extract with digest verification
- [ ] 🔴 `.wh.<name>` → `mknod` char device `0:0`
- [ ] 🔴 `.wh..wh..opq` → xattr `{trusted|user}.overlay.opaque = "y"`
- [ ] 🔴 Path traversal guard: reject entries escaping `dest` via `..` or absolute paths or symlink targets
- [ ] 🔴 Preserve uid/gid/mode/xattrs/times; remap ids when rootless
- [ ] 🔴 Hardlink handling across a single layer

**pivot_root**
- [ ] 🔴 `mount(None, "/", MS_REC|MS_PRIVATE)` **first** — without it pivot_root fails and mounts leak to the host
- [ ] 🔴 Bind-mount `new_root` onto itself so it satisfies "must be a mount point"
- [ ] 🔴 `chdir(new_root)`; `pivot_root(".", ".")`
- [ ] 🔴 `mount(None, ".", MS_REC|MS_SLAVE)` before detaching, so the umount cannot propagate
- [ ] 🔴 `umount2(".", MNT_DETACH)`; `chdir("/")`
- [ ] 🔴 `msMoveRoot` + `chroot` fallback for environments where pivot_root is unavailable

**Standard mounts**
- [ ] 🔴 `/proc`, `/sys`, `/sys/fs/cgroup`, `/dev` (tmpfs), `/dev/pts` (newinstance), `/dev/shm`, `/dev/mqueue`
- [ ] 🔴 Device nodes via `mknod`; **bind-mount from host when rootless**
- [ ] 🔴 `/dev/console` from the allocated pty when a TTY is requested
- [ ] 🔴 Symlinks: `/dev/{fd,stdin,stdout,stderr}` → `/proc/self/fd/*`
- [ ] 🔴 User bind mounts with correct flags; `ro` requires **bind then remount** (single-call `MS_BIND|MS_RDONLY` silently ignores RDONLY)
- [ ] 🔴 Mount propagation per spec (`rprivate` default)
- [ ] 🔴 `mask_path()`: `/dev/null` bind for files, empty ro tmpfs for directories
- [ ] 🔴 `make_readonly()` two-call sequence
- [ ] 🔴 Apply the OCI default masked + readonly path lists

**Copy-up tracing**
- [ ] 🟡 `scan_copy_ups()`: walk upperdir, classify Data / MetadataOnly / Whiteout / Opaque
- [ ] 🟡 Attribute each to its origin layer chainID; compute amplification ratio

**Tests**
- [ ] 🔴 `test_whiteout_hides_lower`: delete in merged → char dev 0:0 in upper, entry gone from merged, lower untouched
- [ ] 🔴 `test_opaque_dir`: `rm -rf` + recreate a lower dir → opaque xattr, lower contents fully hidden
- [ ] 🔴 `test_copyup_on_write`: append one byte to a lower file → full file appears in upper
- [ ] 🔴 `test_pivot_root_no_escape`: attempt the classic `fchdir` chroot escape → fails
- [ ] 🔴 `test_host_mounts_unchanged`: `/proc/self/mountinfo` on the host identical before and after a full container lifecycle
- [ ] 🔴 `test_readonly_bind_actually_readonly`: single-call `MS_BIND|MS_RDONLY` is writable (proving the bug), two-call is not
- [ ] 🔴 `test_tar_path_traversal_rejected`: malicious layer with `../../etc/passwd` is refused

---

## Phase 5 — Security (20 tasks)

**Capabilities**
- [ ] 🔴 Apply order: clear ambient → drop bounding → set permitted/inheritable/effective → raise ambient
- [ ] 🔴 Bounding-set drops are irreversible — verify none of the 5 sets is applied before bounding
- [ ] 🔴 Default 14-capability set
- [ ] 🔴 `--cap-add` / `--cap-drop` resolution against the default
- [ ] 🔴 Report all 5 sets from `/proc/<pid>/status` for the API

**no_new_privs & rlimits**
- [ ] 🔴 `prctl(PR_SET_NO_NEW_PRIVS, 1)` **before** seccomp
- [ ] 🔴 All `RLIMIT_*` from the spec
- [ ] 🔴 `oom_score_adj` written to `/proc/<pid>/oom_score_adj`
- [ ] 🔴 `PR_SET_PDEATHSIG` on the init process

**Seccomp**
- [ ] 🔴 Build filter context from `LinuxSeccomp`; default action, arch list, per-syscall rules
- [ ] 🔴 Argument comparisons (`SCMP_CMP_*`) for conditional rules
- [ ] 🔴 Unknown syscall names → skip with a warning, never fail the container
- [ ] 🔴 Load **after** `no_new_privs`, **immediately before** `execve`
- [ ] 🔴 Ship the Docker-equivalent default profile (~44 denied syscalls) in `profiles/seccomp/default.json`
- [ ] 🟡 `SCMP_ACT_NOTIFY` support: obtain the notify fd, pass it to the daemon via SCM_RIGHTS
- [ ] 🟡 Daemon-side notify supervisor: read `seccomp_notif`, log `{pid, syscall, args}`, respond `ENOSYS`, emit SSE

**Tests**
- [ ] 🔴 `test_caps_dropped`: `CAP_SYS_ADMIN` absent → `mount()` inside returns `EPERM`
- [ ] 🔴 `test_no_new_privs_blocks_setuid`: a setuid-root binary inside does not elevate
- [ ] 🔴 `test_seccomp_blocks_syscall`: a denied syscall returns the configured errno
- [ ] 🔴 `test_seccomp_before_exec`: the entrypoint's first syscall is already filtered
- [ ] 🟡 `test_seccomp_notify_captures`: violation appears in the daemon's log with correct syscall name

---

## Phase 6 — Image Store & Registry (24 tasks)

**Content store**
- [ ] 🔴 `content/blobs/sha256/<digest>` layout; write-to-temp-then-rename for atomicity
- [ ] 🔴 `Digest` newtype with parse/display/verify
- [ ] 🔴 Streaming digest verification during download — reject before the blob is fully written
- [ ] 🔴 Refcounting so `rmi` never deletes a blob another image needs
- [ ] 🔴 `oci-layout` + `index.json` for local image export

**Manifests**
- [ ] 🔴 `ImageManifest`, `ImageIndex`, `ImageConfig`, `Descriptor` types
- [ ] 🔴 Platform selection from an index (`os`, `architecture`, `variant`)
- [ ] 🔴 Docker v2 schema 2 ↔ OCI manifest compatibility (media type mapping)
- [ ] 🔴 **diffID vs digest**: diffID = SHA-256 of the *uncompressed* tar; digest = SHA-256 of the *compressed* blob
- [ ] 🔴 `chain_id()` per SPEC §10.1

**Registry client**
- [ ] 🔴 `GET /v2/` → parse `WWW-Authenticate` → token fetch with correct `scope`
- [ ] 🔴 Manifest fetch with a full `Accept` header covering all four media types
- [ ] 🔴 Blob download with `Range` resume support
- [ ] 🔴 Bounded-parallel layer download (default 4) with per-layer progress events
- [ ] 🔴 Reference parsing: `[registry/]name[:tag][@digest]`, defaulting to `docker.io/library/*:latest`
- [ ] 🟡 `docker.io` → `registry-1.docker.io` host rewrite
- [ ] 🟡 Retry with backoff on 429/5xx
- [ ] 🟡 Anonymous + basic + bearer auth

**Extraction**
- [ ] 🔴 Decompress gzip / zstd while computing the diffID
- [ ] 🔴 Skip extraction when the chainID layer already exists (dedup)
- [ ] 🔴 Emit `image.pull.progress` SSE per layer

**Tests**
- [ ] 🔴 `test_chain_id_known_values`: hardcoded diffIDs → expected chainIDs
- [ ] 🔴 `test_digest_mismatch_rejected`: corrupt a blob mid-stream → error, nothing persisted
- [ ] 🔴 `test_layer_dedup`: pull two images sharing a base → base extracted once
- [ ] 🟡 `test_pull_alpine_e2e`: real pull, then run `/bin/true` from it

---

## Phase 7 — Networking (24 tasks)

**netns**
- [ ] 🔴 Create a netns and pin it at `/run/kestrel/netns/<id>`
- [ ] 🔴 `nsenter(fd, closure)` helper that restores the original netns on the way out
- [ ] 🔴 Teardown: unmount pin, remove file

**Bridge & veth (rtnetlink only, no shelling out)**
- [ ] 🔴 `ensure_bridge(name, gateway, subnet)`: create if absent, assign gateway, bring up
- [ ] 🔴 `veth` pair creation
- [ ] 🔴 Move the peer into the netns **by fd** (`setns_by_fd`), not by pid
- [ ] 🔴 Enslave the host end to the bridge; set MTU; bring up
- [ ] 🔴 Inside the netns: rename to `eth0`, assign address, bring up, `lo` up
- [ ] 🔴 Default route via the bridge gateway
- [ ] 🔴 Deterministic MAC derived from the IP (stable across restarts)

**IPAM**
- [ ] 🔴 Bitmap allocator over the subnet; persist to disk
- [ ] 🔴 Reserve network, broadcast, and gateway addresses
- [ ] 🔴 Release on container delete; leak-sweep on daemon start

**NAT**
- [ ] 🔴 `sysctl net.ipv4.ip_forward=1`; `net.bridge.bridge-nf-call-iptables=1`
- [ ] 🔴 POSTROUTING MASQUERADE for the subnet, excluding the bridge itself
- [ ] 🔴 A dedicated `KESTREL` chain so teardown never touches unrelated rules
- [ ] 🔴 DNAT per published port; hairpin MASQUERADE rule
- [ ] 🔴 FORWARD accept rules incl. conntrack ESTABLISHED,RELATED
- [ ] 🔴 Idempotent add (check-then-insert) and complete teardown

**Modes & DNS**
- [ ] 🔴 `host` (no netns), `none` (lo only), `container:<id>` (join existing netns)
- [ ] 🔴 Generate `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` and bind-mount them in
- [ ] 🟡 Embedded DNS resolver on the bridge gateway for container-name resolution
- [ ] 🟡 Rootless: detect and delegate to `pasta` (preferred) or `slirp4netns`

**Tests**
- [ ] 🔴 `test_none_mode_only_lo`: exactly one interface
- [ ] 🔴 `test_bridge_egress`: container reaches an external address
- [ ] 🔴 `test_inter_container`: two containers on the bridge ping each other
- [ ] 🔴 `test_published_port`: host `curl localhost:<hostport>` reaches the container
- [ ] 🔴 `test_teardown_leaves_no_rules`: iptables + `ip link` identical before/after

---

## Phase 8 — Runtime Binary (`kestrel-runtime`) (24 tasks)

- [ ] 🔴 `clap` subcommands: `create`, `start`, `state`, `kill`, `delete`, `exec`, `ps`, `pause`, `resume`
- [ ] 🔴 **Assert single-threaded at startup** and fail loudly otherwise
- [ ] 🔴 `create`: load bundle, validate spec, create cgroup, run the three-stage dance
- [ ] 🔴 Bootstrap data (namespace paths, clone flags, id maps) passed to the child over the sync socket
- [ ] 🔴 Write `state.json` atomically (temp + rename)
- [ ] 🔴 Create the exec FIFO at `/run/kestrel/<id>/exec.fifo`
- [ ] 🔴 `createRuntime` hooks fire **after** namespaces exist, **before** pivot_root — this is where CNI would run
- [ ] 🔴 `start`: open the FIFO for writing → unblocks init; then `poststart` hooks
- [ ] 🔴 `state`: read and print `state.json`, refreshing `status` by checking the pid
- [ ] 🔴 `kill`: signal by name or number; `--all` uses `cgroup.kill`
- [ ] 🔴 `delete`: kill if running (`--force`), unmount overlay, remove cgroup, unpin namespaces, teardown net, `poststop` hooks
- [ ] 🔴 `exec`: `setns` into the pinned namespaces in the correct order, apply caps/seccomp, exec
- [ ] 🔴 `pause`/`resume` via `cgroup.freeze`

**kestrel-init (PID 1)**
- [ ] 🔴 Separate static binary (`-C target-feature=+crt-static`), copied into the container at a fixed path
- [ ] 🔴 Receives config over the sync socket, never reads host files after pivot_root
- [ ] 🔴 Order: mounts → pivot_root → sethostname → time-ns offsets → `createContainer` hooks → **block on FIFO** → `startContainer` hooks → caps → no_new_privs → seccomp → `execve`
- [ ] 🔴 Signal blocking before fork; `signalfd` for the reaper loop
- [ ] 🔴 `SIGCHLD` reap loop must `waitpid(-1, WNOHANG)` in a loop — one SIGCHLD can cover many deaths
- [ ] 🔴 Forward all other signals to the entrypoint
- [ ] 🔴 Exit with the entrypoint's code, or `128 + signum`

**Tests**
- [ ] 🔴 `test_create_then_start`: after `create`, the process exists but the entrypoint has not run; after `start` it has
- [ ] 🔴 `test_exit_code_propagates`: `exit 42` → runtime exits 42
- [ ] 🔴 `test_signal_exit_code`: killed by SIGKILL → 137
- [ ] 🔴 `test_zombie_reaping`: spawn+abandon 10,000 children → `pids.current` returns to baseline
- [ ] 🔴 `test_hooks_fire_in_order`: all 5 phases append to a file in the expected sequence

---

## Phase 9 — Daemon (`kestreld`) (24 tasks)

- [ ] 🔴 `tokio` + `axum`; listen on both a Unix socket and `127.0.0.1:7777`
- [ ] 🔴 Container registry: in-memory map persisted to `/run/kestrel/containers/<id>/`
- [ ] 🔴 State recovery on daemon restart — running containers must survive a daemon bounce
- [ ] 🔴 **`fork+exec` `kestrel-runtime`**, never link it (preserves the single-thread invariant)
- [ ] 🔴 `POST /containers`: image resolve → snapshot → spec build → net attach → runtime create
- [ ] 🔴 Lifecycle endpoints: start/stop/kill/pause/unpause/delete
- [ ] 🔴 `stop`: SIGTERM → grace period → SIGKILL
- [ ] 🔴 `GET /containers/:id` full inspect
- [ ] 🔴 Log capture: pipe stdout/stderr to `/var/lib/kestrel/containers/<id>/<stream>.log` with json-lines framing
- [ ] 🔴 `GET /logs` SSE with `follow`, `tail`, `since`
- [ ] 🔴 `WS /attach` bidirectional stdio; pty allocation when `-t`
- [ ] 🔴 `POST /resize` → `TIOCSWINSZ`
- [ ] 🔴 Metrics sampler at 1 Hz: cgroup stats + PSI for every running container
- [ ] 🔴 OOM watcher: poll `memory.events.oom_kill`, emit an event on increment
- [ ] 🟡 Copy-up scanner every 5 s → `copyup` events
- [ ] 🟡 Seccomp-notify supervisor → `seccomp.violation` events
- [ ] 🔴 `GET /events` SSE with all event types
- [ ] 🔴 Introspection endpoints: `/namespaces`, `/cgroup`, `/pressure`, `/layers`, `/copyups`, `/mounts`, `/caps`, `/seccomp`, `/network`
- [ ] 🔴 `GET /system/namespaces`: scan `/proc/*/ns/*`, build the PID↔namespace graph
- [ ] 🔴 `GET /system/topology`: bridges, veth pairs (via `IFLA_LINK` peer index), netns, NAT rules
- [ ] 🔴 Image endpoints incl. pull with per-layer SSE progress
- [ ] 🟡 `GET /images/dedup`: logical vs physical bytes across all images
- [ ] 🔴 Graceful shutdown: SIGTERM → stop accepting → flush logs → leave containers running
- [ ] 🔴 Leak sweep on startup: orphaned netns, stale overlay mounts, empty cgroups

---

## Phase 10 — CLI (16 tasks)

- [ ] 🔴 `clap` derive with all subcommands from SPEC §15
- [ ] 🔴 `run` = create + start + (optional) attach + (optional) `--rm`
- [ ] 🔴 Flag parsing: `-p`, `-v`, `-e`, `--memory`, `--cpus`, `--pids-limit`, `--cap-add/drop`, `--network`, `--user`, `--read-only`
- [ ] 🔴 Human-readable size parsing (`512m`, `1.5g`) and `--cpus 1.5` → `cpu.max`
- [ ] 🔴 `ps` table + `--format json`
- [ ] 🔴 `logs -f`, `exec -it`, `inspect --format`
- [ ] 🔴 `stats` streaming table
- [ ] 🔴 `images`, `pull` with a progress bar per layer, `rmi`, `history`
- [ ] 🟡 `ns ID` — the 8 namespaces with inode numbers and what's shared with whom
- [ ] 🟡 `ns tree` — host-wide namespace membership tree
- [ ] 🟡 `diff ID` — changed files, distinguishing added/modified(copy-up)/deleted(whiteout)
- [ ] 🟡 `copyups ID` — table sorted by bytes, plus the amplification ratio
- [ ] 🟡 `pressure ID` — live PSI
- [ ] 🟡 `caps ID`, `seccomp ID`, `net topology`
- [ ] 🟢 `explain ID` — replay the recorded creation trace as a narrative
- [ ] 🔴 Shell completions for bash/zsh/fish

---

## Phase 11 — TUI (14 tasks)

- [ ] 🟡 `ratatui` + `crossterm`; alternate screen, raw mode, restore on panic
- [ ] 🟡 Layout: container list (left) + detail pane (right) + status bar
- [ ] 🟡 List: id, name, image, state chip, uptime, CPU%, mem bar
- [ ] 🟡 Navigation: `j`/`k`/arrows, `/` filter, `Tab` switches detail tab
- [ ] 🟡 Detail tabs: Stats · Namespaces · Layers · Mounts · Network · Logs
- [ ] 🟡 Stats tab: CPU/memory sparklines + PSI gauges
- [ ] 🟡 Namespaces tab: 8 rows with inode + "shared with N containers"
- [ ] 🟡 Layers tab: overlay stack with sizes, upperdir growth
- [ ] 🟡 Logs tab: scrollback with follow toggle
- [ ] 🟡 Actions: `s` start, `S` stop, `p` pause, `d` delete (confirm), `e` exec, `r` restart
- [ ] 🟡 `e` suspends the TUI, runs an interactive exec, restores on exit
- [ ] 🟡 SSE-driven refresh over the Unix socket, 1 Hz stats
- [ ] 🟢 Help overlay (`?`)
- [ ] 🟢 Color themes; respects `NO_COLOR`

---

## Phase 12 — Web Dashboard (34 tasks)

**Foundation**
- [ ] 🔴 `src/api/client.ts` typed fetch; `src/api/queries.ts` TanStack Query hooks
- [ ] 🔴 `src/sse/client.ts` EventSource with reconnect backoff; zustand store fed by events
- [ ] 🔴 App shell: sidebar nav, container selector, connection health indicator

**View 1 — Container list**
- [ ] 🔴 TanStack Table: id, image, state chip, uptime, CPU%, mem bar, PIDs, ports
- [ ] 🔴 Inline actions with confirmation for destructive ones
- [ ] 🟡 Expandable row with live sparklines

**View 2 — Namespace Explorer ⭐**
- [ ] 🔴 D3 force graph: process nodes (circles, sized by RSS) + namespace nodes (rects, colored by type)
- [ ] 🔴 Namespace nodes labelled with inode number; edges = membership
- [ ] 🔴 Per-type visibility toggles (8 checkboxes)
- [ ] 🔴 **Shared namespaces visually converge** — two containers sharing a netns pull to one node
- [ ] 🟡 Click a namespace → member PID table with host PID and in-namespace PID side by side
- [ ] 🟡 Host namespaces rendered distinctly (dashed border)
- [ ] 🟢 Zoom/pan, drag-to-pin

**View 3 — Layer & Copy-Up Inspector ⭐**
- [ ] 🔴 Overlay stack as stacked horizontal bars, bottom-to-top, sized by layer bytes
- [ ] 🔴 Each layer labelled with chainID prefix, size, and originating instruction if known
- [ ] 🔴 Upperdir highlighted distinctly
- [ ] 🔴 Copy-up table: path, bytes, source layer, timestamp, kind
- [ ] 🔴 **Amplification ratio callout** — logical writes vs physical bytes
- [ ] 🟡 Whiteout / opaque panel listing what the container deleted
- [ ] 🟡 Shared-layer indicator: which other containers use this layer

**View 4 — Resource & Pressure ⭐**
- [ ] 🔴 CPU chart: usage vs `cpu.max`, throttle events as red markers
- [ ] 🔴 Memory chart: current, `high` line, `max` line, `peak` marker, OOM as vertical rules
- [ ] 🔴 **PSI charts** for cpu/memory/io — `some` and `full` overlaid, `full` shaded darker
- [ ] 🔴 IO chart: read/write bytes and IOPS against `io.max`
- [ ] 🟡 Time-range selector; pause-on-hover
- [ ] 🟡 Threshold alert banners driven by PSI trigger events

**View 5 — Network Topology**
- [ ] 🟡 D3: bridges, containers, veth pair edges labelled `vethXXXX@ifN ↔ eth0`, host uplink
- [ ] 🟡 NAT rules annotated on the bridge→uplink edge
- [ ] 🟡 Click a container → routes + its DNAT/MASQUERADE rules

**View 6 — Security**
- [ ] 🟡 Capability matrix: all caps × 5 sets, granted/dropped, diffed against the default
- [ ] 🟡 Seccomp profile viewer with a searchable syscall table
- [ ] 🟡 Live violation feed from `seccomp.violation` events

**View 7 — Terminal**
- [ ] 🟡 xterm.js over the attach WebSocket
- [ ] 🟡 Fit addon + resize propagation to `/resize`
- [ ] 🟢 Exec-into-container launcher with shell selection

---

## Phase 13 — Integration Tests & Conformance (22 tasks)

**Isolation**
- [ ] 🔴 `test_full_isolation`: all 8 namespaces; verify hostname, PID view, mount table, network, cgroup path
- [ ] 🔴 `test_no_host_escape`: chroot-escape attempt fails; no host path reachable
- [ ] 🔴 `test_host_mountinfo_unchanged`: byte-identical before/after full lifecycle
- [ ] 🔴 `test_host_ns_count_unchanged`: no leaked namespaces after delete

**Resources**
- [ ] 🔴 `test_memory_oom_kill`: OOM at the limit; `oom_kill` counter increments; host unaffected
- [ ] 🔴 `test_cpu_quota_enforced`: measured CPU ≈ configured quota ±5%
- [ ] 🔴 `test_fork_bomb_contained`: `pids.max` holds; host stays responsive
- [ ] 🔴 `test_psi_rises_under_pressure`: memory thrash → `memory.pressure.some` climbs

**Filesystem**
- [ ] 🔴 `test_layer_isolation`: writes in container A invisible to container B from the same image
- [ ] 🔴 `test_image_unmodified`: after heavy container writes, lower layers are byte-identical
- [ ] 🔴 `test_copyup_accounting`: reported copy-up bytes == actual upperdir growth

**Lifecycle**
- [ ] 🔴 `test_create_start_stop_delete` full cycle with state assertions at each step
- [ ] 🔴 `test_exec_joins_namespaces`: exec'd process shares all 8 ns inodes with PID 1
- [ ] 🔴 `test_pause_freezes`: no progress while frozen, resumes cleanly
- [ ] 🔴 `test_daemon_restart_survives`: containers still running and controllable after daemon bounce

**Networking**
- [ ] 🔴 `test_network_modes`: bridge/host/none/container all behave as specified
- [ ] 🔴 `test_port_publish_roundtrip`: HTTP server in container reachable on the host port
- [ ] 🔴 `test_network_teardown_clean`: iptables + links identical before/after

**Conformance & quality**
- [ ] 🔴 `oci-runtime-tools` validation suite passes
- [ ] 🔴 Run a real `alpine`, `busybox`, and `nginx` image end-to-end
- [ ] 🟡 `cargo clippy -- -D warnings`; `cargo fmt --check`
- [ ] 🟡 Every `unsafe` block carries a `// SAFETY:` comment; `#![deny(clippy::undocumented_unsafe_blocks)]`

---

## Phase 14 — Docs & Polish (12 tasks)

- [ ] 🟢 `README.md`: what it is, the Rust rationale, quickstart, VM setup warning
- [ ] 🟢 `docs/NAMESPACES.md`: the three-stage dance explained with a diagram
- [ ] 🟢 `docs/CGROUPS.md`: v2 rules, controller reference, PSI interpretation guide
- [ ] 🟢 `docs/OVERLAY.md`: layer model, whiteouts, copy-up, the symlink-farm rationale
- [ ] 🟢 `docs/SECURITY.md`: capability defaults, seccomp profile, threat model, known gaps
- [ ] 🟢 ASCII architecture diagram
- [ ] 🟢 Annotated `kestrel explain` sample output
- [ ] 🟡 `--verbose` tracing that names each setup phase with timing
- [ ] 🟡 Error messages that name the failing syscall, its arguments, and the likely fix
- [ ] 🔵 CRIU checkpoint/restore
- [ ] 🔵 Wasm workloads via wasmtime as an alternate "entrypoint"
- [ ] 🔵 containerd shim v2 so real containerd can drive `kestrel`

---

## Summary

| Phase | Tasks |
|---|---|
| 0. Bootstrap & Environment Guard | 14 |
| 1. OCI Spec Types | 12 |
| 2. Namespaces | 28 |
| 3. cgroups v2 | 30 |
| 4. Rootfs, OverlayFS & pivot_root | 30 |
| 5. Security | 20 |
| 6. Image Store & Registry | 24 |
| 7. Networking | 24 |
| 8. Runtime Binary | 24 |
| 9. Daemon | 24 |
| 10. CLI | 16 |
| 11. TUI | 14 |
| 12. Web Dashboard | 34 |
| 13. Integration Tests & Conformance | 22 |
| 14. Docs & Polish | 12 |
| **TOTAL** | **328** |
