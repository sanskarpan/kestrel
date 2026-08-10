# Phase 9: Daemon (`kestreld`) — Design

## 1. Goal

Build `kestreld`: a `tokio`+`axum` daemon that owns container lifecycle orchestration, log capture, live attach, metrics/event streaming, and image management — exposed over both a Unix socket and `127.0.0.1:7777`, per SPEC.md §13. `kestreld` never links `kestrel-runtime` as a library (Rule #2: `kestrel-runtime` is single-threaded, no async, no thread spawning, transitively) — it always `fork+exec`s it as a subprocess, exactly as SPEC.md §3's architecture diagram shows.

`crates/kestreld/` currently contains only a 4-line placeholder `main.rs` and a `Cargo.toml` with a single `anyhow` dependency — this is a fully greenfield implementation.

## 2. New component: `kestrel-shim`

**Not listed in SPEC.md's §16 File Structure — this is a deliberate, explicitly-flagged addition.** Justification: `kestreld` itself owning each container's stdio pipe/PTY directly would mean a `kestreld` restart either SIGPIPEs the container's entrypoint (pipe reader gone) or permanently loses live-attach capability for already-running containers, since anonymous pipe/PTY fds don't survive a process restart. CHECKLIST.md's Phase 9 requires "running containers must survive a daemon bounce" — for that to include *live attach*, not just state, something has to durably own the fd independent of `kestreld`'s own lifetime. This is exactly the problem containerd's shim solves, and the same shape is the right fix here.

**Role:** own one container's stdio (pipe or PTY) for its entire lifetime, independent of `kestreld`. Nothing more — no bundle parsing, no OCI logic, no namespace awareness.

**Invocation** (by `kestreld`): `kestrel-shim --id <id> --run-dir <run-dir> --data-dir <data-dir> --tty <bool> -- kestrel-runtime create <id> --bundle <path> --run-dir <run-dir> --data-dir <data-dir>`

**Lifecycle:**
1. Allocate a PTY (`openpty`, via `nix::pty`) if `--tty`, else two pipes (stdout, stderr) plus `/dev/null` for stdin (non-interactive default).
2. Spawn the given command (`kestrel-runtime create ...`) with the slave/write-ends as its stdio; close its own copies of those ends immediately after spawn (standard fd-hygiene, mirroring `create.rs`'s own `host_end`/`init_end` handling).
3. Wait synchronously for that child to exit. Report success/failure back to `kestreld` over the shim's own stdout as a single-line JSON status message (`{"ok":true}` / `{"ok":false,"error":"..."}`) — `kestreld` reads exactly one line from the shim's stdout before treating the shim as "handed off." (The shim's OWN stdout here is distinct from the container's captured stdout, which is the pipe/PTY it allocated in step 1 — no conflict.)
4. If `create` failed: exit, propagating the failure. Nothing to hold open.
5. If `create` succeeded: daemonize (`setsid()`, redirect its own stdin/stdout/stderr to `/dev/null` now that the status line has been sent, ignore `SIGHUP`) so it survives `kestreld` exiting or restarting.
6. Event loop: read from the pipe/PTY master; for each line, append `{"ts":"<rfc3339>","stream":"stdout"|"stderr","msg":"<line>"}\n` to `<data_dir>/containers/<id>/output.jsonl` (`O_APPEND`, survives everything). Simultaneously, listen on `<run_dir>/<id>/attach.sock` (`SOCK_STREAM`, `SOCK_SEQPACKET` not needed) for `kestreld` connections — see §5 for the framing protocol.
7. Exit once the pipe/PTY read returns EOF (every writer — `kestrel-init` and the entrypoint — has exited and closed its copy), after a final flush. Remove `attach.sock`.

**Async runtime:** `tokio` (current-thread or small multi-thread runtime) — the shim isn't `kestrel-runtime`, Rule #2 doesn't apply to it, and using `tokio` keeps its pipe/PTY-read + socket-accept loop simple and consistent with the rest of the workspace.

## 3. Container registry & state recovery

`kestreld`'s registry is `Arc<RwLock<HashMap<String, ContainerHandle>>>` — a cache, not a second source of truth. The real source of truth is `kestrel-runtime`'s own `<run_dir>/<id>/state.json` (already durable, already atomic-write, already what `kestrel-runtime state`/`ps` read).

**On startup** (state recovery + leak sweep, CHECKLIST's two 🔴 items):
1. Scan `<run_dir>/*/state.json`. For each, `State::read` it, and for each non-`Stopped` status, rebuild a `ContainerHandle` (id, bundle path from `state.bundle`, cached `State`).
2. For each recovered handle, probe `<run_dir>/<id>/attach.sock` (connect, don't block long) — if reachable, the shim is still alive and live attach/streaming works immediately; if not, only `output.jsonl` tailing works for that container until... nothing brings it back; a dead shim means the container's own stdio is gone too (the shim held the only reader), which only happens if the shim itself crashed independent of the container — a real but rare failure mode, logged as a warning, not treated as fatal.
3. Leak sweep (CHECKLIST's other 🔴 item, previously-untouched territory): for each `<run_dir>/<id>` **not** matching a real `state.json`-backed container (orphaned directories), and each cgroup under `<data_dir>/cgroups/kestrel/*` with no matching registry entry, and each netns pin under `<run_dir>/netns/*` with no matching entry — log and clean up. This reuses `kestrel_runtime::delete`'s own teardown primitives where possible rather than re-implementing them.

`ContainerHandle` fields: `id`, `bundle_path`, `tty: bool`, `network: Option<NetworkInfo>` (populated by `kestreld` itself when it set up bridge-mode networking — see §9), last-read `State` (refreshed on demand, not cached indefinitely — every read-path endpoint re-reads `state.json`, matching `kestrel_runtime::state_cmd`'s own `RefreshedState`/staleness-detection convention rather than trusting an in-memory copy that could drift).

## 4. Container lifecycle endpoints

| Endpoint | Real mechanism |
|---|---|
| `POST /containers` | Resolve image (pull if needed, §10) → materialize bundle (§4a) → spawn `kestrel-shim` (§2) → on success, registry entry created with `Status::Created` |
| `POST /containers/:id/start` | `kestrel-runtime start <id>` (no shim involved — start only unblocks the FIFO; stdio was already locked in at `create` time, inherited straight through `kestrel-init`'s later fork of the entrypoint) |
| `POST /containers/:id/stop` | SIGTERM via `kestrel-runtime kill <id> SIGTERM`, poll `state.json` for `Stopped` up to a grace period (configurable, default matches OCI convention ~10s), then `kestrel-runtime kill <id> SIGKILL` if still running |
| `POST /containers/:id/kill` | `kestrel-runtime kill <id> <signal>` directly |
| `POST /containers/:id/pause` / `unpause` | `kestrel-runtime pause`/`resume <id>` |
| `DELETE /containers/:id` | `kestrel-runtime delete <id> [--force]`; on success, remove the registry entry, remove `<data_dir>/containers/<id>/` |
| `POST /containers/:id/exec` | `kestrel-runtime exec <id> -- <cmd>`, spawned by `kestreld` directly (not the shim — a NEW, one-off pipe/PTY per exec invocation, torn down when the exec'd process exits; no durability requirement for one-off exec sessions the way there is for the entrypoint) |
| `GET /containers/:id/top` | Read `state.json` for the entrypoint's host pid, then walk `/proc/<pid>/task/*/children` recursively (same technique `kestrel_runtime::start::resolve_entrypoint_host_pid` already established) to list every process in the container, reporting both host and container-namespace pids (container-side via `/proc/<host-pid>/status`'s `NSpid` field, which lists the pid as seen in every ancestor pid namespace) |

**4a. Network attachment ordering (bridge mode) — CORRECTED after adversarial plan review.** `build_namespace_plan` (`crates/kestrel-runtime/src/create.rs:305-332`) skips any `LinuxNamespace` with a `path()` set from the "create fresh" list — but, contrary to this section's original wording, that is NOT a working join mechanism: the function's own doc comment is explicit that "joining an existing namespace at create-time is a materially different feature... not solved here." A path-set namespace is currently just silently dropped, with no compensating `setns`. Implementing bridge-mode networking as originally described here would silently leave the container in the host's network namespace.

**Real fix (implementation plan Task 4):** `NamespacePlan` gains a `join: Vec<(NsType, PathBuf)>` field; `build_namespace_plan` routes path-set namespaces into it instead of dropping them; `kestrel_ns::stages::stage1` performs each `setns()` in `plan.join` as its *first* action, before any `unshare()` — including before `unshare(CLONE_NEWUSER)` — because `setns` into a namespace owned by the host's original user namespace needs privilege in that owning userns, which the calling process only reliably has before it unshares into a new one. This mirrors the privilege-ordering principle `kestrel_ns::join::join_namespaces`'s own `JOIN_ORDER` already documents for a different call path (`kestrel exec`), applied here for the first time to the create-time path.

With that mechanism real, the flow is: (1) `kestreld` calls `kestrel_net::netns::create_netns` itself (a plain async call, in-process — `kestrel-net` isn't `kestrel-runtime`, Rule #2 doesn't restrict it) to create and pin a netns *before* invoking `create`; (2) write that pin path into the bundle's `config.json` as the `Network` namespace's `path` — now genuinely joined via Task 4's mechanism, not silently dropped; (3) only after `create()` returns successfully (container has a real pid, its network namespace is the one just created) call `kestrel-net`'s veth/bridge/NAT setup, targeting that same pinned netns path via `nsenter`/`with_namespace`. Host-mode and `none` networking skip step 1 entirely (no `path` set, or `Network` omitted from the plan for host mode per existing `LinuxNamespaceType` semantics). `container:<id>` mode reuses another container's already-pinned netns path directly, no new `create_netns` call.

**4b. Bundle materialization for image-based containers (real gap-fill in `kestrel-runtime`):**

`create.rs`'s `stage_bundle_rootfs_as_synthetic_layer` (`crates/kestrel-runtime/src/create.rs:225-256`) is hardcoded to treat a bundle's `root.path()` as ONE new synthetic layer via a full recursive copy — there is no path for "use these already-pulled layer chain-ids directly." Everything downstream (`Snapshotter::prepare_snapshot`, `mount_overlay`, `kestrel-init`'s own mount code) already handles an arbitrary multi-entry chain-id list generically (`MountPlan.lower_chain_ids: Vec<String>` was never restricted to length 1) — the gap is narrowly in this one host-side function.

**Fix:** `kestreld` writes a `kestrel.lowerChainIds` annotation (comma-joined) into the bundle's `config.json` before invoking `create` (real, viable — `Spec::annotations()` is a genuine, unfiltered field that survives `bundle::load`, confirmed against real vendored `oci-spec` source). `stage_bundle_rootfs_as_synthetic_layer` gains a new first check: if `bundle.spec.spec.annotations()` contains `kestrel.lowerChainIds`, split it and return a `MountPlan` referencing those chain-ids directly (no `ensure_layer`, no copy) — falling back to the existing synthetic-single-layer behavior only when the annotation is absent (preserving every existing Phase 8 test's behavior exactly, since none of them set this annotation).

This is the mechanism that makes Phase 6's whole content-addressed layer store actually pay off at container-creation time — without it, every `kestreld`-created container would pay a full rootfs copy on every `create`, defeating the dedup Phase 6 built.

## 5. I/O: logs, attach, resize

**Logs** (`GET /containers/:id/logs`, `?follow&tail&since`): tail `<data_dir>/containers/<id>/output.jsonl` directly. `follow` uses `notify`-style file watching (or simple poll-on-modify, given this project's existing poll-based conventions elsewhere — e.g. `PsiWatcher`) to stream new lines as SSE `data:` events. `tail`/`since` are plain line-count/timestamp filters over the same file. This works identically whether the shim is currently reachable or not, and survives any number of `kestreld` restarts — it's just a file.

**Attach** (`WS /containers/:id/attach`): `kestreld` connects to `<run_dir>/<id>/attach.sock`, bridges the WebSocket to that Unix socket. Framing over the socket (both directions): 1-byte type tag + `u32` LE length + payload —
- `0x01 DATA`: raw bytes, forwarded verbatim in both directions (container output → WS client; WS client keystrokes → container stdin, only meaningful for `tty` containers where the PTY master accepts writes)
- `0x02 RESIZE`: payload = `u16` rows + `u16` cols LE, shim issues `TIOCSWINSZ` on its PTY master fd
- `0x03 CLOSE`: either side may send, socket closes after

Non-tty containers don't support attach's write-direction (no PTY to write into meaningfully — the entrypoint's stdin is `/dev/null` per §2 step 1) but DO support the read-direction as a live-tail equivalent to `logs -f`; `kestreld` documents (and the API can reject up front) that `POST /resize` and stdin-writes over `attach` 409 for non-tty containers.

**`POST /resize`**: `kestreld` looks up the container's `attach.sock`, sends a `0x02 RESIZE` frame — same channel, no separate mechanism needed.

## 6. Metrics sampler, OOM watcher, copy-up scanner, event bus

**Event bus:** `tokio::sync::broadcast::Sender<Event>`, where `Event` is an enum matching SPEC.md §13's exact type list (`container.create|start|die|oom|pause|unpause|destroy`, `image.pull.progress|pull.done`, `net.attach|detach`, `copyup`, `seccomp.violation`, `psi.threshold`, `cgroup.throttle`). Every internal watcher below publishes to this bus; `GET /events` (SSE) is a raw subscriber with no filtering (filtering by type is a client-side concern, matching SPEC.md's endpoint description — no query params listed for it).

**Metrics sampler** (1Hz, `metrics_interval_ms` from config): for each `Running` registry entry, read `CgroupManager::cpu_stat`, `memory_current`, `pids_current`, and `pressure(Cpu|Memory|Io)` — all real, already-built (`crates/kestrel-cgroup/src/stats.rs`, `psi.rs`). **Real gap:** no `io.stat` reader exists (`crates/kestrel-cgroup/src/stats.rs` has zero io-stat code; `resources.rs::apply_io` is a writer only). New task: add `io_stat()` mirroring `cpu_stat`'s tolerant-parse convention, but per-device (`io.stat`'s real line format is `<major>:<minor> rbytes=N wbytes=N rios=N wios=N dbytes=N dios=N`, not `cpu.stat`'s flat single-key-per-line shape — a distinct parser, same tolerant-skip philosophy).

**OOM watcher:** same 1Hz tick (or its own faster interval — 1Hz is sufficient, OOM kills aren't so time-sensitive that sub-second polling matters), call `oom_kill_count()`, diff against last-seen count per container, emit `container.oom` on increase.

**Copy-up scanner** (5s interval, `copyup_scan_interval_s`): for each running container, call `kestrel_rootfs::copyup::scan_copy_ups(upper_dir, &lowers)` — real, ready, already handles data/metadata-only/whiteout/opaque classification with size + origin layer (`crates/kestrel-rootfs/src/copyup.rs`). Diff against previously-seen paths (a `HashSet<PathBuf>` per container) to emit only NEW copy-ups as `copyup` events, not the whole set every tick.

## 7. Seccomp-notify supervisor (real gap, new channel required)

Confirmed: `apply_all` (`crates/kestrel-security/src/apply.rs`) already returns `Option<OwnedFd>` from `install_seccomp`, but `kestrel-init`'s `exec_into` (`crates/kestrel-init/src/exec.rs:16-24`) discards it as an unnamed temporary — **the fd is silently closed today**, meaning seccomp-notify is currently a complete no-op end-to-end, not just unwired to a UI. The original bootstrap socketpair (`create.rs`'s `host_end`/`init_end`) is confirmed closed on the host side by the time this fd would exist (it closes the moment `create()` returns, which is well before `start` — separately invoked — ever unblocks the FIFO and lets `kestrel-init` fork+exec the entrypoint where `install_seccomp` actually runs). A distinct new channel is structurally required.

**Mechanism:** before calling `kestrel-runtime start`, `kestreld` ensures the shim has a `<run_dir>/<id>/seccomp.sock` listener ready (the shim opens this unconditionally in step 6 of its lifecycle, cheap to always have available). `exec_into`'s signature gains an optional `notify_sink: Option<&Path>` parameter; when present and `apply_all` returns `Some(fd)`, `exec_into` connects to that path and sends the fd via `SCM_RIGHTS` (one-shot, before `execve`) rather than letting it drop. The shim receives the fd, spawns `kestrel_security::notify::run_notify_loop` on a `spawn_blocking` task, and forwards each `NotifyEvent` to `kestreld` as a `seccomp.violation` message over the SAME `attach.sock` connection convention (a 4th frame type, `0x04 SECCOMP_EVENT`) or a dedicated small channel — reusing `attach.sock`'s existing connection machinery is simpler than adding a second socket kestreld has to manage per container.

This is CHECKLIST's one 🟡 (non-required) item touching the fd-passing chain — scoped last in the implementation plan precisely because it's the most speculative/highest-risk piece and the least load-bearing if time runs short.

## 8. Introspection endpoints

| Endpoint | Backing |
|---|---|
| `/containers/:id/namespaces` | Walk `<run_dir>/<id>/ns/*` (already-pinned namespace files from `create.rs`'s `pin_namespaces`), `stat()` each for inode number; "shared with" computed by comparing inodes across all containers' pin directories |
| `/containers/:id/cgroup` | `CgroupManager` reads: `cpu_stat`, `memory_current`, `pids_current`, new `io_stat`, plus raw `cpu.max`/`memory.max`/`pids.max` file reads for configured limits |
| `/containers/:id/pressure` | `pressure(Cpu\|Memory\|Io)` × 3, already real |
| `/containers/:id/layers` | `LayerStore` + the container's `MountPlan.lower_chain_ids` (persisted where? — see note below) |
| `/containers/:id/copyups` | Same `scan_copy_ups` call as the background scanner (§6), on-demand instead of diffed |
| `/containers/:id/mounts` | Parse `/proc/<pid>/mountinfo` from inside the container's pinned mount namespace (via `kestrel_ns::join::with_namespace`, already real) for propagation types |
| `/containers/:id/caps` | Read the bundle's `config.json` `process.capabilities` (all 5 sets) — already fully typed via `oci_spec::runtime::LinuxCapabilities` |
| `/containers/:id/seccomp` | Active profile from `config.json` + accumulated violation log (from §7's `SECCOMP_EVENT` stream, kept in a per-container ring buffer) |
| `/containers/:id/network` | `kestreld`'s own `NetworkInfo` (§3) — since it's `kestreld`, not `kestrel-runtime`, that calls `kestrel-net`'s async functions directly to set up bridge-mode networking, it's the natural owner of "what did I set up for this container," rather than re-discovering it from the kernel (confirmed: `kestrel-net` has almost no read-back/introspection API today — everything is create/ensure/delete-oriented, so kestreld-side bookkeeping is the pragmatic choice, not a re-derivation from kernel state) |
| `/system/namespaces` | Scan `/proc/*/ns/*` host-wide, build the PID↔namespace graph (new code — no existing helper for this host-wide scan, distinct from the per-container pin-based query above) |
| `/system/topology` | `kestreld`'s own aggregated bookkeeping across all containers' `NetworkInfo` (bridge name, veth pairs, subnet, NAT rules it applied) — same reasoning as `/network` above |

**Note on `/layers` and `MountPlan` persistence:** `Bootstrap`/`MountPlan` is currently a one-shot payload sent over the bootstrap socket and never itself persisted to disk — `kestrel-runtime` doesn't need it again after `create()` returns. For `/containers/:id/layers` to work after the fact, `kestreld` needs to remember (or re-derive) the chain-ids it used. Simplest: `kestreld` writes the resolved chain-id list into its own per-container metadata file (`<data_dir>/containers/<id>/layers.json`) at create time, alongside the annotation it already writes into `config.json` — no `kestrel-runtime`/`kestrel-oci` changes needed, this is purely `kestreld`-side bookkeeping.

## 9. Image endpoints

`GET/POST /images`, `/images/pull`: `pull_image_with_client` (`crates/kestrel-image/src/pull.rs`) already takes an `on_progress: impl FnMut(PullProgress)` callback with an SSE-friendly incremental event shape (`ManifestFetched`, `LayerStart`, `LayerDeduped`, `LayerDownloaded`, `LayerExtracted`, `Complete`) — `kestreld` wires this directly to a `tokio::sync::mpsc` channel forwarded as SSE, and separately publishes each event onto the main event bus (§6) as `image.pull.progress`/`image.pull.done`.

`GET /images/:ref`, `/images/:ref/layers`: read `ContentStore`'s `oci-layout`/manifest files directly — no "list images" API exists yet (confirmed), so this endpoint does its own directory walk over the content store's index, a new but small piece of code.

`DELETE /images/:ref`: `ContentStore::remove_ref` + `remove_blob_if_unreferenced` (real, ready).

`GET /images/dedup` (🟡): compute logical bytes (sum of each image's uncompressed layer sizes, double-counting shared layers) vs. physical bytes (actual on-disk blob store size, once per unique digest) — new aggregation code over `ContentStore`'s existing blob listing, no missing primitives.

## 10. Graceful shutdown & startup leak sweep

**Shutdown** (SIGTERM to `kestreld` itself): stop accepting new HTTP/WS connections, let in-flight requests finish (`axum::serve`'s `with_graceful_shutdown`), flush any buffered log-file writes `kestreld` itself might be doing (none, per §5 — log writing is entirely the shim's job, so this is mostly a non-issue for `kestreld`'s own shutdown), exit. **Containers keep running** — this is the whole point of the shim architecture (§2): nothing about a container's process tree is a child of `kestreld`.

**Leak sweep**: covered in §3 (startup, not shutdown — CHECKLIST's wording is "leak sweep on startup").

## 11. Configuration

SPEC.md §17's `/etc/kestrel/config.toml` shape is already fully specified — `kestreld` parses it via `serde`/`toml` (new dependency, not yet in the workspace) with the documented defaults, CLI-overridable for at least `socket`/`http_addr`/`state_dir`/`data_dir` (matching `kestrel-runtime`'s own `--run-dir`/`--data-dir` flag convention).

## 12. New/changed dependencies

- `kestreld`: `tokio` (full), `axum`, `tower-http` (CORS/tracing middleware), `serde`+`toml` (config), `tokio-tungstenite` or `axum`'s built-in WS support (prefer axum's own `axum::extract::ws`, avoids a second WS crate).
- `kestrel-shim` (new crate): `tokio`, `nix` (pty, socket, signal), `serde_json` (log line framing).
- `tokio`/`axum` are NOT promoted to `[workspace.dependencies]` unless version conflicts force it — `kestrel-image`/`kestrel-net` already each pin their own tokio feature sets independently; `kestreld`/`kestrel-shim` follow the same per-crate-features convention already established, at whatever tokio `"1"` resolves to.

## 13. Testing strategy

Given `kestreld` orchestrates real subprocesses, real namespaces, real cgroups — root-gated integration tests are unavoidable, same discipline as every phase since Phase 2. Key test surfaces:
- `kestrel-shim` in isolation: spawn a trivial command, verify the durable log file gets written, verify `attach.sock` accepts a connection and relays bytes both ways, verify EOF-triggered clean exit.
- `kestreld`'s HTTP surface: `axum::Router` is testable via `tower::ServiceExt::oneshot` without a real bound socket for most endpoints; lifecycle endpoints (`create`/`start`/`stop`/`delete`) still need root + the real Lima VM, same as `kestrel-runtime`'s own capstone tests — likely reusing `lifecycle_fixture` as the container entrypoint again.
- State-recovery-across-restart: create a container, kill the `kestreld` process (not the container), start a NEW `kestreld` process pointed at the same `run_dir`/`data_dir`, confirm the container is rediscovered AND `attach.sock` is still reachable through the surviving shim — this is the test that actually proves §2's whole reason for existing.

## 14. Out of scope for this phase

- CRIU checkpoint/restore (SPEC.md's own "stretch" list).
- `rootless_backend` (pasta/slirp4netns) — SPEC.md §17 config has the field, but rootless networking itself was already out of scope through Phase 7.
- `systemd` cgroup manager mode (`[cgroup] manager = "cgroupfs" | "systemd"` — only `cgroupfs` is real today).
- Full production-grade config-reload-without-restart — `kestreld` re-reads config only on startup.
