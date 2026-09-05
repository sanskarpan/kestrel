# CHECKLIST.md — Container Runtime from Scratch (`kestrel`)

> Priority: 🔴 blocking · 🟡 important · 🟢 enhancement · 🔵 stretch
> **Phases 2–5 (namespaces, cgroups, rootfs, security) are the kernel core. Each must be independently testable before the runtime binary is assembled in Phase 8.**
> **Requires: Linux ≥ 5.11, cgroup v2 unified, root (or a delegated userns for rootless work).**

---

## Phase 0 — Bootstrap & Environment Guard (14 tasks)

- [x] 🔴 `cargo new --lib` workspace; 12 member crates per SPEC §16
- [x] 🔴 Workspace `Cargo.toml`: shared deps `nix`, `libc`, `rustix`, `anyhow`, `thiserror`, `serde`, `serde_json`, `tracing`
- [x] 🔴 `kestrel-runtime` deps must **exclude** `tokio` — enforce with a `cargo deny` rule or a test that inspects `cargo tree`
- [x] 🔴 `crates/kestrel-oci`: pull in `oci-spec` and re-export; add local extension types
- [x] 🔴 Preflight check binary: kernel ≥ 5.11, cgroup2 mounted at `/sys/fs/cgroup`, `overlay` in `/proc/filesystems`, `unprivileged_userns_clone` enabled
- [x] 🔴 Preflight also reports which controllers are available in `/sys/fs/cgroup/cgroup.controllers`
- [x] 🔴 `tracing` setup with a `container_id` span field threaded through every subsystem
- [x] 🔴 Error model: `thiserror` per crate, `anyhow` only at binary boundaries
- [x] 🔴 `Makefile`: `build`, `test`, `test-root` (integration, needs sudo), `oci-conformance`, `web-dev`, `tui`
- [x] 🔴 Vagrant/QEMU dev VM definition — **do not develop this on your main machine**; a bad `pivot_root` or `umount` can wedge the host
- [x] 🔴 `cd web && bun create vite . --template react-ts`
- [x] 🔴 `bun add @tanstack/react-query @tanstack/react-table d3 recharts @xterm/xterm @xterm/addon-fit zustand clsx lucide-react`
- [x] 🔴 `bun add -d tailwindcss postcss autoprefixer @types/d3`; `bunx shadcn@latest init` + add `button card table badge tabs dialog select tooltip sheet progress separator scroll-area`
- [x] 🔴 `web/vite.config.ts`: proxy `/v1` and `/events` → `http://localhost:7777`

---

## Phase 1 — OCI Spec Types (12 tasks)

- [x] 🔴 `Spec`, `Process`, `Root`, `Mount`, `Linux`, `LinuxResources`, `LinuxNamespace`, `LinuxIdMapping`
- [x] 🔴 `LinuxCapabilities` (5 sets), `LinuxSeccomp`, `LinuxDevice`, `LinuxRlimit`
- [x] 🔴 `Hooks` with all 5 phases (`createRuntime`, `createContainer`, `startContainer`, `poststart`, `poststop`) + deprecated `prestart`
- [x] 🔴 `State { ociVersion, id, status, pid, bundle, annotations }` with `Status` enum
- [x] 🔴 `Spec::validate()`: root path present, process args non-empty, no duplicate namespace types, id-map coverage
- [x] 🔴 Default spec generator (`kestrel spec`) matching `runc spec` output
- [x] 🔴 Image config → runtime spec translation (Env, Cmd, Entrypoint, WorkingDir, User, ExposedPorts, Volumes)
- [x] 🔴 `User` resolution: numeric, `name`, `name:group`, `uid:gid` — resolve against the **container's** `/etc/passwd`, not the host's
- [x] 🔴 Serde round-trip preserves unknown fields (forward compatibility)
- [x] 🔴 Unit test: parse the official OCI example `config.json` without loss
- [x] 🔴 Unit test: `validate()` rejects duplicate namespaces, empty args, missing root
- [x] 🔴 Unit test: user resolution against a synthetic `/etc/passwd`

---

## Phase 2 — Namespaces (28 tasks)

**Core**
- [x] 🔴 `NsType` enum (8 variants) with `clone_flag()` and `proc_name()`
- [x] 🔴 `CLONE_NEWTIME = 0x00000080` — not in `nix`, define manually
- [x] 🔴 `NamespacePlan`: which to create, which to join, in what order
- [x] 🔴 `unshare_namespaces(flags)` wrapper with errno context
- [x] 🔴 `setns_ordered(pins)` — **user namespace LAST** (entering it drops the caps needed for the rest)
- [x] 🔴 `pin_namespace(pid, ns, target)`: create target file, bind-mount `/proc/<pid>/ns/<t>`
- [x] 🔴 `unpin_namespace`: `umount2(MNT_DETACH)` + unlink
- [x] 🔴 `read_ns_inode(pid, ns)` from the `/proc/<pid>/ns/<t>` symlink target (`net:[4026532001]`)

**ID maps**
- [x] 🔴 `IdMapping { container_id, host_id, size }`
- [x] 🔴 `write_id_maps(pid, uid, gid)` — **`setgroups=deny` BEFORE `gid_map`** (CVE-2014-8989)
- [x] 🔴 All map lines in a **single** `write()` — the kernel permits exactly one write per namespace
- [x] 🔴 Ignore `ENOENT` on `setgroups` for pre-3.19 kernels
- [x] 🟡 Rootless: parse `/etc/subuid`, `/etc/subgid`; build maps from the allocated range
- [x] 🟡 Rootless: `newuidmap`/`newgidmap` fallback when the range exceeds what we can map directly

**The three-stage dance**
- [x] 🔴 `socketpair(AF_UNIX, SOCK_SEQPACKET)` for stage synchronization
- [x] 🔴 Sync protocol enum: `RequestMaps`, `MapsDone`, `ReportPid`, `Ready`, `Error(String)`
- [x] 🔴 STAGE 0: clone with everything **except** `CLONE_NEWPID`; write maps; receive grandchild PID
- [x] 🔴 STAGE 1: request maps; `setresuid(0,0,0)`; `unshare(CLONE_NEWPID)`; fork; report PID; `_exit(0)`
- [x] 🔴 STAGE 2 becomes PID 1 — reparented to the host init when STAGE 1 exits
- [x] 🔴 Every stage writes errors to the sync socket so the parent surfaces a real message instead of a silent hang
- [x] 🔴 Timeout on every sync read — a wedged stage must fail, not block forever

**Tests**
- [x] 🔴 `test_uts_isolation`: sethostname inside; host hostname unchanged
- [x] 🔴 `test_pid_isolation`: init sees itself as PID 1; `/proc` lists only container processes
- [x] 🔴 `test_userns_maps`: uid 0 inside maps to the invoking uid outside
- [x] 🔴 `test_setgroups_deny_required`: writing `gid_map` without denying setgroups returns `EPERM`
- [x] 🔴 `test_ns_inode_differs`: container ns inode ≠ host ns inode for all 8
- [x] 🔴 `test_pin_survives_pid1_exit`: pinned ns still enterable after PID 1 dies
- [x] 🔴 `test_join_order`: joining user-first then net fails; net-first then user succeeds
- [x] 🔴 `test_single_threaded`: assert `/proc/self/status` `Threads: 1` throughout setup

---

## Phase 3 — cgroups v2 (30 tasks)

**Manager**
- [x] 🔴 `CgroupManager { root, path, delegated }`; detect v2 by `statfs` magic `CGROUP2_SUPER_MAGIC`
- [x] 🔴 Refuse to run on v1/hybrid with a clear error naming `systemd.unified_cgroup_hierarchy=1`
- [x] 🔴 `read_available_controllers()` from `cgroup.controllers`
- [x] 🔴 `enable_controllers_in_parents()` — walk root→parent writing `+cpu +memory +io +pids`; **never enable in the leaf itself**
- [x] 🔴 Respect the **no-internal-process rule**: containers always get a leaf cgroup
- [x] 🔴 `create()`, `destroy()` (with retry on `EBUSY` while processes exit)
- [x] 🔴 `add_process(pid)` → `cgroup.procs`

**Controllers**
- [x] 🔴 `cpu.max` = `"<quota> <period>"` or `"max <period>"`
- [x] 🔴 `cpu.weight` from OCI `shares` via the v1→v2 conversion (`1 + (s-2)*9999/262142`)
- [x] 🔴 `cpuset.cpus`, `cpuset.mems`
- [x] 🔴 `memory.max` (hard), `memory.high` (throttle), `memory.low`, `memory.min`
- [x] 🔴 `memory.swap.max` — v2 swap is **separate**, not memory+swap as in v1
- [x] 🔴 `pids.max`
- [x] 🔴 `io.max` per-device `rbps/wbps/riops/wiops`; `io.weight`
- [x] 🔴 `hugetlb.<size>.max` when the controller is present
- [x] 🟡 Unified `"max"` / `"-1"` / `0` limit formatting helper

**Runtime control**
- [x] 🔴 `freeze(bool)` via `cgroup.freeze`; poll `cgroup.events` for `frozen 1`
- [x] 🔴 `kill_all()` via `cgroup.kill` (5.14+), fallback to iterating `cgroup.procs`
- [x] 🔴 `is_populated()` from `cgroup.events` `populated`

**Stats & PSI**
- [x] 🔴 `stats()`: parse `cpu.stat` (`usage_usec`, `nr_throttled`, `throttled_usec`), `memory.current`, `memory.peak`, `memory.stat`, `io.stat`, `pids.current`
- [x] 🔴 `oom_events()` from `memory.events` — `oom_kill` is the authoritative OOM signal, **not** exit code 137
- [x] 🔴 `Psi { some, full }` parser for `cpu.pressure` / `memory.pressure` / `io.pressure` (note: `cpu` has no `full` on older kernels)
- [x] 🟡 PSI threshold triggers: write `"some <stall_us> <window_us>"`, `poll(POLLPRI)` — event-driven, not polled
- [x] 🟡 Graceful degradation when `CONFIG_PSI` is off

**clone3**
- [x] 🟡 `CloneArgs` repr(C) struct; `CLONE_INTO_CGROUP = 0x200000000000`
- [x] 🟡 `clone_into_cgroup(flags, cgroup_fd)` via `SYS_clone3`
- [x] 🟡 Fallback to `fork()` + write `cgroup.procs` on `ENOSYS`

**Tests**
- [x] 🔴 `test_memory_limit_ooms`: allocate past `memory.max`; `memory.events.oom_kill` increments
- [x] 🔴 `test_cpu_throttle`: busy loop under `cpu.max=50000 100000`; `cpu.stat.nr_throttled` > 0
- [x] 🔴 `test_pids_limit`: fork bomb stopped at `pids.max`; host unaffected
- [x] 🔴 `test_no_internal_processes`: writing a PID to a cgroup with `subtree_control` set fails
- [x] 🔴 `test_freeze_thaw`: frozen process makes no progress; thaw resumes it
- [x] 🟡 `test_clone_into_cgroup_no_window`: memory bomb in the first instruction still OOM-killed

---

## Phase 4 — Rootfs, OverlayFS & pivot_root (30 tasks)

**Snapshotter**
- [x] 🔴 Directory layout per SPEC §6.1
- [x] 🔴 `chain_id(diff_ids)` computation
- [x] 🔴 Layer store keyed by chainID; `parent` file records the chain
- [x] 🔴 **Symlink farm**: `l/<6-char>` → `../layers/<chain>/diff`; `chdir(data_dir)` before mount so option strings stay under 4096 bytes
- [x] 🔴 `Snapshot { lower_links, upper, work, merged }`; `work` must be **empty** at mount time
- [x] 🔴 `mount_overlay()`: lowerdir colon-joined, **reversed** (rightmost = bottom)
- [x] 🔴 `userxattr` when rootless (5.11+); `metacopy=on`; `redirect_dir=on`
- [x] 🔴 `unmount_overlay()` with `MNT_DETACH` and busy-retry
- [x] 🟡 Driver fallback chain: `overlay2` → `fuse-overlayfs` → `vfs`

**Layer application**
- [x] 🔴 `apply_layer(tar, dest)`: stream-extract with digest verification
- [x] 🔴 `.wh.<name>` → `mknod` char device `0:0`
- [x] 🔴 `.wh..wh..opq` → xattr `{trusted|user}.overlay.opaque = "y"`
- [x] 🔴 Path traversal guard: reject entries escaping `dest` via `..` or absolute paths or symlink targets
- [x] 🔴 Preserve uid/gid/mode/xattrs/times; remap ids when rootless
- [x] 🔴 Hardlink handling across a single layer

**pivot_root**
- [x] 🔴 `mount(None, "/", MS_REC|MS_PRIVATE)` **first** — without it pivot_root fails and mounts leak to the host
- [x] 🔴 Bind-mount `new_root` onto itself so it satisfies "must be a mount point"
- [x] 🔴 `chdir(new_root)`; `pivot_root(".", ".")`
- [x] 🔴 `mount(None, ".", MS_REC|MS_SLAVE)` before detaching, so the umount cannot propagate
- [x] 🔴 `umount2(".", MNT_DETACH)`; `chdir("/")`
- [x] 🔴 `msMoveRoot` + `chroot` fallback for environments where pivot_root is unavailable

**Standard mounts**
- [x] 🔴 `/proc`, `/sys`, `/sys/fs/cgroup`, `/dev` (tmpfs), `/dev/pts` (newinstance), `/dev/shm`, `/dev/mqueue`
- [x] 🔴 Device nodes via `mknod`; **bind-mount from host when rootless**
- [x] 🔴 `/dev/console` from the allocated pty when a TTY is requested
- [x] 🔴 Symlinks: `/dev/{fd,stdin,stdout,stderr}` → `/proc/self/fd/*`
- [x] 🔴 User bind mounts with correct flags; `ro` requires **bind then remount** (single-call `MS_BIND|MS_RDONLY` silently ignores RDONLY)
- [x] 🔴 Mount propagation per spec (`rprivate` default)
- [x] 🔴 `mask_path()`: `/dev/null` bind for files, empty ro tmpfs for directories
- [x] 🔴 `make_readonly()` two-call sequence
- [x] 🔴 Apply the OCI default masked + readonly path lists

**Copy-up tracing**
- [x] 🟡 `scan_copy_ups()`: walk upperdir, classify Data / MetadataOnly / Whiteout / Opaque
- [x] 🟡 Attribute each to its origin layer chainID; compute amplification ratio

**Tests**
- [x] 🔴 `test_whiteout_hides_lower`: delete in merged → char dev 0:0 in upper, entry gone from merged, lower untouched
- [x] 🔴 `test_opaque_dir`: `rm -rf` + recreate a lower dir → opaque xattr, lower contents fully hidden
- [x] 🔴 `test_copyup_on_write`: append one byte to a lower file → full file appears in upper
- [x] 🔴 `test_pivot_root_no_escape`: attempt the classic `fchdir` chroot escape → fails
- [x] 🔴 `test_host_mounts_unchanged`: `/proc/self/mountinfo` on the host identical before and after a full container lifecycle
- [x] 🔴 `test_readonly_bind_actually_readonly`: single-call `MS_BIND|MS_RDONLY` is writable (proving the bug), two-call is not
- [x] 🔴 `test_tar_path_traversal_rejected`: malicious layer with `../../etc/passwd` is refused

---

## Phase 5 — Security (20 tasks)

**Capabilities**
- [x] 🔴 Apply order: clear ambient → drop bounding → set permitted/inheritable/effective → raise ambient
- [x] 🔴 Bounding-set drops are irreversible — verify none of the 5 sets is applied before bounding
- [x] 🔴 Default 14-capability set
- [x] 🔴 `--cap-add` / `--cap-drop` resolution against the default
- [x] 🔴 Report all 5 sets from `/proc/<pid>/status` for the API

**no_new_privs & rlimits**
- [x] 🔴 `prctl(PR_SET_NO_NEW_PRIVS, 1)` **before** seccomp
- [x] 🔴 All `RLIMIT_*` from the spec
- [x] 🔴 `oom_score_adj` written to `/proc/<pid>/oom_score_adj`
- [x] 🔴 `PR_SET_PDEATHSIG` on the init process

**Seccomp**
- [x] 🔴 Build filter context from `LinuxSeccomp`; default action, arch list, per-syscall rules
- [x] 🔴 Argument comparisons (`SCMP_CMP_*`) for conditional rules
- [x] 🔴 Unknown syscall names → skip with a warning, never fail the container
- [x] 🔴 Load **after** `no_new_privs`, **immediately before** `execve`
- [x] 🔴 Ship the Docker-equivalent default profile (~44 denied syscalls) in `profiles/seccomp/default.json`
- [x] 🟡 `SCMP_ACT_NOTIFY` support: obtain the notify fd, pass it to the daemon via SCM_RIGHTS
- [x] 🟡 Daemon-side notify supervisor: read `seccomp_notif`, log `{pid, syscall, args}`, respond `ENOSYS`, emit SSE

**Tests**
- [x] 🔴 `test_caps_dropped`: `CAP_SYS_ADMIN` absent → `mount()` inside returns `EPERM`
- [x] 🔴 `test_no_new_privs_blocks_setuid`: a setuid-root binary inside does not elevate
- [x] 🔴 `test_seccomp_blocks_syscall`: a denied syscall returns the configured errno
- [x] 🔴 `test_seccomp_before_exec`: the entrypoint's first syscall is already filtered
- [x] 🟡 `test_seccomp_notify_captures`: violation appears in the daemon's log with correct syscall name

---

## Phase 6 — Image Store & Registry (24 tasks)

**Content store**
- [x] 🔴 `content/blobs/sha256/<digest>` layout; write-to-temp-then-rename for atomicity
- [x] 🔴 `Digest` newtype with parse/display/verify
- [x] 🔴 Streaming digest verification during download — reject before the blob is fully written
- [x] 🔴 Refcounting so `rmi` never deletes a blob another image needs
- [x] 🔴 `oci-layout` + `index.json` for local image export

**Manifests**
- [x] 🔴 `ImageManifest`, `ImageIndex`, `ImageConfig`, `Descriptor` types
- [x] 🔴 Platform selection from an index (`os`, `architecture`, `variant`)
- [x] 🔴 Docker v2 schema 2 ↔ OCI manifest compatibility (media type mapping)
- [x] 🔴 **diffID vs digest**: diffID = SHA-256 of the *uncompressed* tar; digest = SHA-256 of the *compressed* blob
- [x] 🔴 `chain_id()` per SPEC §10.1

**Registry client**
- [x] 🔴 `GET /v2/` → parse `WWW-Authenticate` → token fetch with correct `scope`
- [x] 🔴 Manifest fetch with a full `Accept` header covering all four media types
- [x] 🔴 Blob download with `Range` resume support
- [x] 🔴 Bounded-parallel layer download (default 4) with per-layer progress events
- [x] 🔴 Reference parsing: `[registry/]name[:tag][@digest]`, defaulting to `docker.io/library/*:latest`
- [x] 🟡 `docker.io` → `registry-1.docker.io` host rewrite
- [x] 🟡 Retry with backoff on 429/5xx
- [x] 🟡 Anonymous + basic + bearer auth

**Extraction**
- [x] 🔴 Decompress gzip / zstd while computing the diffID
- [x] 🔴 Skip extraction when the chainID layer already exists (dedup)
- [x] 🔴 Emit `image.pull.progress` SSE per layer

**Tests**
- [x] 🔴 `test_chain_id_known_values`: hardcoded diffIDs → expected chainIDs
- [x] 🔴 `test_digest_mismatch_rejected`: corrupt a blob mid-stream → error, nothing persisted
- [x] 🔴 `test_layer_dedup`: pull two images sharing a base → base extracted once
- [x] 🟡 `test_pull_alpine_e2e`: real pull, then run `/bin/true` from it

---

## Phase 7 — Networking (24 tasks)

**netns**
- [x] 🔴 Create a netns and pin it at `/run/kestrel/netns/<id>`
- [x] 🔴 `nsenter(fd, closure)` helper that restores the original netns on the way out
- [x] 🔴 Teardown: unmount pin, remove file

**Bridge & veth (rtnetlink only, no shelling out)**
- [x] 🔴 `ensure_bridge(name, gateway, subnet)`: create if absent, assign gateway, bring up
- [x] 🔴 `veth` pair creation
- [x] 🔴 Move the peer into the netns **by fd** (`setns_by_fd`), not by pid
- [x] 🔴 Enslave the host end to the bridge; set MTU; bring up
- [x] 🔴 Inside the netns: rename to `eth0`, assign address, bring up, `lo` up
- [x] 🔴 Default route via the bridge gateway
- [x] 🔴 Deterministic MAC derived from the IP (stable across restarts)

**IPAM**
- [x] 🔴 Bitmap allocator over the subnet; persist to disk
- [x] 🔴 Reserve network, broadcast, and gateway addresses
- [x] 🔴 Release on container delete; leak-sweep on daemon start

**NAT**
- [x] 🔴 `sysctl net.ipv4.ip_forward=1`; `net.bridge.bridge-nf-call-iptables=1`
- [x] 🔴 POSTROUTING MASQUERADE for the subnet, excluding the bridge itself
- [x] 🔴 A dedicated `KESTREL` chain so teardown never touches unrelated rules
- [x] 🔴 DNAT per published port; hairpin MASQUERADE rule
- [x] 🔴 FORWARD accept rules incl. conntrack ESTABLISHED,RELATED
- [x] 🔴 Idempotent add (check-then-insert) and complete teardown

**Modes & DNS**
- [x] 🔴 `host` (no netns), `none` (lo only), `container:<id>` (join existing netns)
- [x] 🔴 Generate `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` and bind-mount them in
- [x] 🟡 Embedded DNS resolver on the bridge gateway for container-name resolution
- [x] 🟡 Rootless: detect and delegate to `pasta` (preferred) or `slirp4netns`

**Tests**
- [x] 🔴 `test_none_mode_only_lo`: exactly one interface
- [x] 🔴 `test_bridge_egress`: container reaches an external address
- [x] 🔴 `test_inter_container`: two containers on the bridge ping each other
- [x] 🔴 `test_published_port`: host `curl localhost:<hostport>` reaches the container
- [x] 🔴 `test_teardown_leaves_no_rules`: iptables + `ip link` identical before/after

---

## Phase 8 — Runtime Binary (`kestrel-runtime`) (24 tasks)

- [x] 🔴 `clap` subcommands: `create`, `start`, `state`, `kill`, `delete`, `exec`, `ps`, `pause`, `resume`
- [x] 🔴 **Assert single-threaded at startup** and fail loudly otherwise
- [x] 🔴 `create`: load bundle, validate spec, create cgroup, run the three-stage dance
- [x] 🔴 Bootstrap data (namespace paths, clone flags, id maps) passed to the child over the sync socket
- [x] 🔴 Write `state.json` atomically (temp + rename)
- [x] 🔴 Create the exec FIFO at `/run/kestrel/<id>/exec.fifo`
- [x] 🔴 `createRuntime` hooks fire **after** namespaces exist, **before** pivot_root — this is where CNI would run
- [x] 🔴 `start`: open the FIFO for writing → unblocks init; then `poststart` hooks
- [x] 🔴 `state`: read and print `state.json`, refreshing `status` by checking the pid
- [x] 🔴 `kill`: signal by name or number; `--all` uses `cgroup.kill`
- [x] 🔴 `delete`: kill if running (`--force`), unmount overlay, remove cgroup, unpin namespaces, teardown net, `poststop` hooks
- [x] 🔴 `exec`: `setns` into the pinned namespaces in the correct order, apply caps/seccomp, exec
- [x] 🔴 `pause`/`resume` via `cgroup.freeze`

**kestrel-init (PID 1)**
- [x] 🔴 Separate static binary (`-C target-feature=+crt-static`), copied into the container at a fixed path
- [x] 🔴 Receives config over the sync socket, never reads host files after pivot_root
- [x] 🔴 Order: mounts → pivot_root → sethostname → time-ns offsets → `createContainer` hooks → **block on FIFO** → `startContainer` hooks → caps → no_new_privs → seccomp → `execve`
- [x] 🔴 Signal blocking before fork; `signalfd` for the reaper loop
- [x] 🔴 `SIGCHLD` reap loop must `waitpid(-1, WNOHANG)` in a loop — one SIGCHLD can cover many deaths
- [x] 🔴 Forward all other signals to the entrypoint
- [x] 🔴 Exit with the entrypoint's code, or `128 + signum`

**Tests**
- [x] 🔴 `test_create_then_start`: after `create`, the process exists but the entrypoint has not run; after `start` it has
- [x] 🔴 `test_exit_code_propagates`: `exit 42` → runtime exits 42
- [x] 🔴 `test_signal_exit_code`: killed by SIGKILL → 137
- [x] 🔴 `test_zombie_reaping`: spawn+abandon 10,000 children → `pids.current` returns to baseline
- [x] 🔴 `test_hooks_fire_in_order`: all 5 phases append to a file in the expected sequence

---

## Phase 9 — Daemon (`kestreld`) (24 tasks)

- [x] 🔴 `tokio` + `axum`; listen on both a Unix socket and `127.0.0.1:7777`
- [x] 🔴 Container registry: in-memory map persisted to `/run/kestrel/containers/<id>/`
- [x] 🔴 State recovery on daemon restart — running containers must survive a daemon bounce
- [x] 🔴 **`fork+exec` `kestrel-runtime`**, never link it (preserves the single-thread invariant)
- [x] 🔴 `POST /containers`: image resolve → snapshot → spec build → net attach → runtime create
- [x] 🔴 Lifecycle endpoints: start/stop/kill/pause/unpause/delete
- [x] 🔴 `stop`: SIGTERM → grace period → SIGKILL
- [x] 🔴 `GET /containers/:id` full inspect
- [x] 🔴 Log capture: pipe stdout/stderr to `/var/lib/kestrel/containers/<id>/<stream>.log` with json-lines framing
- [x] 🔴 `GET /logs` SSE with `follow`, `tail`, `since`
- [x] 🔴 `WS /attach` bidirectional stdio; pty allocation when `-t`
- [x] 🔴 `POST /resize` → `TIOCSWINSZ`
- [x] 🔴 Metrics sampler at 1 Hz: cgroup stats + PSI for every running container
- [x] 🔴 OOM watcher: poll `memory.events.oom_kill`, emit an event on increment
- [x] 🟡 Copy-up scanner every 5 s → `copyup` events
- [x] 🟡 Seccomp-notify supervisor → `seccomp.violation` events
- [x] 🔴 `GET /events` SSE with all event types
- [x] 🔴 Introspection endpoints: `/namespaces`, `/cgroup`, `/pressure`, `/layers`, `/copyups`, `/mounts`, `/caps`, `/seccomp`, `/network`
- [x] 🔴 `GET /system/namespaces`: scan `/proc/*/ns/*`, build the PID↔namespace graph
- [x] 🔴 `GET /system/topology`: bridges, veth pairs (via `IFLA_LINK` peer index), netns, NAT rules
- [x] 🔴 Image endpoints incl. pull with per-layer SSE progress
- [x] 🟡 `GET /images/dedup`: logical vs physical bytes across all images
- [x] 🔴 Graceful shutdown: SIGTERM → stop accepting → flush logs → leave containers running
- [x] 🔴 Leak sweep on startup: orphaned netns, stale overlay mounts, empty cgroups

---

## Phase 10 — CLI (16 tasks)

- [x] 🔴 `clap` derive with all subcommands from SPEC §15
- [x] 🔴 `run` = create + start + (optional) attach + (optional) `--rm`
- [x] 🔴 Flag parsing: `-p`, `-v`, `-e`, `--memory`, `--cpus`, `--pids-limit`, `--cap-add/drop`, `--network`, `--user`, `--read-only`
- [x] 🔴 Human-readable size parsing (`512m`, `1.5g`) and `--cpus 1.5` → `cpu.max`
- [x] 🔴 `ps` table + `--format json`
- [x] 🔴 `logs -f`, `exec -it`, `inspect --format`
- [x] 🔴 `stats` streaming table
- [x] 🔴 `images`, `pull` with a progress bar per layer, `rmi`, `history`
- [x] 🟡 `ns ID` — the 8 namespaces with inode numbers and what's shared with whom
- [x] 🟡 `ns tree` — host-wide namespace membership tree
- [x] 🟡 `diff ID` — changed files, distinguishing added/modified(copy-up)/deleted(whiteout)
- [x] 🟡 `copyups ID` — table sorted by bytes, plus the amplification ratio
- [x] 🟡 `pressure ID` — live PSI
- [x] 🟡 `caps ID`, `seccomp ID`, `net topology`
- [x] 🟢 `explain ID` — replay the recorded creation trace as a narrative
- [x] 🔴 Shell completions for bash/zsh/fish

---

## Phase 11 — TUI (14 tasks)

- [x] 🟡 `ratatui` + `crossterm`; alternate screen, raw mode, restore on panic
- [x] 🟡 Layout: container list (left) + detail pane (right) + status bar
- [x] 🟡 List: id, name, image, state chip, uptime, CPU%, mem bar
- [x] 🟡 Navigation: `j`/`k`/arrows, `/` filter, `Tab` switches detail tab
- [x] 🟡 Detail tabs: Stats · Namespaces · Layers · Mounts · Network · Logs
- [x] 🟡 Stats tab: CPU/memory sparklines + PSI gauges
- [x] 🟡 Namespaces tab: 8 rows with inode + "shared with N containers"
- [x] 🟡 Layers tab: overlay stack with sizes, upperdir growth
- [x] 🟡 Logs tab: scrollback with follow toggle
- [x] 🟡 Actions: `s` start, `S` stop, `p` pause, `d` delete (confirm), `e` exec, `r` restart
- [x] 🟡 `e` suspends the TUI, runs an interactive exec, restores on exit
- [x] 🟡 SSE-driven refresh over the Unix socket, 1 Hz stats
- [x] 🟢 Help overlay (`?`)
- [x] 🟢 Color themes; respects `NO_COLOR`

---

## Phase 12 — Web Dashboard (34 tasks)

**Foundation**
- [x] 🔴 `src/api/client.ts` typed fetch; `src/api/queries.ts` TanStack Query hooks
- [x] 🔴 `src/sse/client.ts` EventSource with reconnect backoff; zustand store fed by events
- [x] 🔴 App shell: sidebar nav, container selector, connection health indicator

**View 1 — Container list**
- [x] 🔴 TanStack Table: id, image, state chip, uptime, CPU%, mem bar, PIDs, ports
- [x] 🔴 Inline actions with confirmation for destructive ones
- [x] 🟡 Expandable row with live sparklines

**View 2 — Namespace Explorer ⭐**
- [x] 🔴 D3 force graph: process nodes (circles, sized by RSS) + namespace nodes (rects, colored by type)
- [x] 🔴 Namespace nodes labelled with inode number; edges = membership
- [x] 🔴 Per-type visibility toggles (8 checkboxes)
- [x] 🔴 **Shared namespaces visually converge** — two containers sharing a netns pull to one node
- [x] 🟡 Click a namespace → member PID table with host PID and in-namespace PID side by side
- [x] 🟡 Host namespaces rendered distinctly (dashed border)
- [x] 🟢 Zoom/pan, drag-to-pin

**View 3 — Layer & Copy-Up Inspector ⭐**
- [x] 🔴 Overlay stack as stacked horizontal bars, bottom-to-top, sized by layer bytes
- [x] 🔴 Each layer labelled with chainID prefix, size, and originating instruction if known
- [x] 🔴 Upperdir highlighted distinctly
- [x] 🔴 Copy-up table: path, bytes, source layer, timestamp, kind
- [x] 🔴 **Amplification ratio callout** — logical writes vs physical bytes
- [x] 🟡 Whiteout / opaque panel listing what the container deleted
- [x] 🟡 Shared-layer indicator: which other containers use this layer

**View 4 — Resource & Pressure ⭐**
- [x] 🔴 CPU chart: usage vs `cpu.max`, throttle events as red markers
- [x] 🔴 Memory chart: current, `high` line, `max` line, `peak` marker, OOM as vertical rules
- [x] 🔴 **PSI charts** for cpu/memory/io — `some` and `full` overlaid, `full` shaded darker
- [x] 🔴 IO chart: read/write bytes and IOPS against `io.max`
- [x] 🟡 Time-range selector; pause-on-hover
- [x] 🟡 Threshold alert banners driven by PSI trigger events

**View 5 — Network Topology**
- [x] 🟡 D3: bridges, containers, veth pair edges labelled `vethXXXX@ifN ↔ eth0`, host uplink
- [x] 🟡 NAT rules annotated on the bridge→uplink edge
- [x] 🟡 Click a container → routes + its DNAT/MASQUERADE rules

**View 6 — Security**
- [x] 🟡 Capability matrix: all caps × 5 sets, granted/dropped, diffed against the default
- [x] 🟡 Seccomp profile viewer with a searchable syscall table
- [x] 🟡 Live violation feed from `seccomp.violation` events

**View 7 — Terminal**
- [x] 🟡 xterm.js over the attach WebSocket
- [x] 🟡 Fit addon + resize propagation to `/resize`
- [x] 🟢 Exec-into-container launcher with shell selection

---

## Phase 13 — Integration Tests & Conformance (22 tasks)

**Isolation**
- [x] 🔴 `test_full_isolation`: all 8 namespaces; verify hostname, PID view, mount table, network, cgroup path
- [x] 🔴 `test_no_host_escape`: chroot-escape attempt fails; no host path reachable
- [x] 🔴 `test_host_mountinfo_unchanged`: byte-identical before/after full lifecycle
- [x] 🔴 `test_host_ns_count_unchanged`: no leaked namespaces after delete

**Resources**
- [x] 🔴 `test_memory_oom_kill`: OOM at the limit; `oom_kill` counter increments; host unaffected
- [x] 🔴 `test_cpu_quota_enforced`: measured CPU ≈ configured quota ±5%
- [x] 🔴 `test_fork_bomb_contained`: `pids.max` holds; host stays responsive
- [x] 🔴 `test_psi_rises_under_pressure`: memory thrash → `memory.pressure.some` climbs

**Filesystem**
- [x] 🔴 `test_layer_isolation`: writes in container A invisible to container B from the same image
- [x] 🔴 `test_image_unmodified`: after heavy container writes, lower layers are byte-identical
- [x] 🔴 `test_copyup_accounting`: reported copy-up bytes == actual upperdir growth

**Lifecycle**
- [x] 🔴 `test_create_start_stop_delete` full cycle with state assertions at each step
- [x] 🔴 `test_exec_joins_namespaces`: exec'd process shares all 8 ns inodes with PID 1
- [x] 🔴 `test_pause_freezes`: no progress while frozen, resumes cleanly
- [x] 🔴 `test_daemon_restart_survives`: containers still running and controllable after daemon bounce

**Networking**
- [x] 🔴 `test_network_modes`: bridge/host/none/container all behave as specified
- [x] 🔴 `test_port_publish_roundtrip`: HTTP server in container reachable on the host port
- [x] 🔴 `test_network_teardown_clean`: iptables + links identical before/after

**Conformance & quality**
- [x] 🔴 `oci-runtime-tools` validation suite passes
- [x] 🔴 Run a real `alpine`, `busybox`, and `nginx` image end-to-end
- [x] 🟡 `cargo clippy -- -D warnings`; `cargo fmt --check`
- [x] 🟡 Every `unsafe` block carries a `// SAFETY:` comment; `#![deny(clippy::undocumented_unsafe_blocks)]`

---

## Phase 14 — Docs & Polish (12 tasks)

- [x] 🟢 `README.md`: what it is, the Rust rationale, quickstart, VM setup warning
- [x] 🟢 `docs/NAMESPACES.md`: the three-stage dance explained with a diagram
- [x] 🟢 `docs/CGROUPS.md`: v2 rules, controller reference, PSI interpretation guide
- [x] 🟢 `docs/OVERLAY.md`: layer model, whiteouts, copy-up, the symlink-farm rationale
- [x] 🟢 `docs/SECURITY.md`: capability defaults, seccomp profile, threat model, known gaps
- [x] 🟢 ASCII architecture diagram
- [x] 🟢 Annotated `kestrel explain` sample output
- [x] 🟡 `--verbose` tracing that names each setup phase with timing
- [x] 🟡 Error messages that name the failing syscall, its arguments, and the likely fix
- [x] 🔵 CRIU checkpoint/restore — documented in `docs/STRETCH.md` (out-of-scope, design notes)
- [x] 🔵 Wasm workloads via wasmtime as an alternate "entrypoint" — documented in `docs/STRETCH.md`
- [x] 🔵 containerd shim v2 so real containerd can drive `kestrel` — documented in `docs/STRETCH.md`

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
> **Status (2026-09-04):** All 328 tasks complete — Phases 0–14 verified (`cargo build --workspace` + `npm --prefix web run build` + `sudo -E cargo test -- --ignored` in Lima VM, plus `cargo clippy -D warnings` / `cargo fmt --check` and `docs/STRETCH.md` for blue items). Every `unsafe` has `// SAFETY:` and `#![deny(clippy::undocumented_unsafe_blocks)]` where applicable.
