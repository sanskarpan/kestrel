# `kestrel explain <id>` — Annotated Sample Output

`kestrel explain` replays the recorded creation trace for a container as a
timed narrative — every syscall class, in order, with arguments, timing, and
the hint the operator would need if that step had failed. It is the flagship
educational command (SPEC §15, CHECKLIST Phase 10 & 14).

The trace is recorded during `create`/`start` by the verbose tracing spans
(`--verbose` / `RUST_LOG=debug`). Each span is named `<subsystem>.<phase>`
and carries `container_id`, `elapsed_ms`, and the syscall-adjacent context
fields below. `explain` renders those spans in human order; `RUST_LOG=debug`
streams them live.

---

## Example: `kestrel explain demo-nginx` (verbose run)

```
$ kestrel --verbose run --name demo-nginx -p 8080:80 nginx:alpine -- nginx -g 'daemon off;'
2026-09-04T10:12:00.000Z  INFO verbose tracing enabled (RUST_LOG=debug)
$ kestrel explain demo-nginx
```

### 1 — CLI → Daemon (`POST /containers`)

```
[+0.000ms] phase=cli.create              container_id=demo-nginx  image=nginx:alpine  ports=[8080:80]  cmd=["nginx","-g","daemon off;"]
  → POST http://127.0.0.1:7777/containers  body={image, cmd, env, tty=false, memory_bytes=null, pids_limit=null}
  annotate: daemon resolves registry-1.docker.io, fetches manifest (Accept: 4 media types), pulls 3 layers in parallel
```

> **Teaching:** `create` is decoupled from `start` per OCI spec. The daemon
> builds a bundle under `/var/lib/kestrel/bundles/demo-nginx/` before any
> kernel state exists.

---

### 2 — Image → Snapshot (`prepare_snapshot` + symlink farm)

```
[+42.11ms] phase=snapshot.prepare         lower_chain_ids=[sha256:aaa, sha256:bbb, sha256:ccc]  driver=overlay2
  syscall: mkdir -p /var/lib/kestrel/layers/<chain>/diff + parent file
  annotate: each layer keyed by chainID (diffID hashing); parent links form the chain
  [hint if failed: "symlink farm l/<6-char> -> ../layers/<chain>/diff; opts must stay <4096 bytes; chdir(data_dir) before mount"]

[+48.03ms] phase=snapshot.symlink_farm    l/abc123 -> ../layers/sha256:aaa/diff  (3 links, bottom-to-top order)
[+49.10ms] phase=overlay.build_opts       lowerdir=l/ccc:l/bbb:l/aaa,upperdir=.../upper,workdir=.../work,metacopy=on,redirect_dir=on
```

---

### 3 — Daemon → Runtime (`fork+exec kestrel-runtime create`)

```
[+55.20ms] phase=runtime.create          container_id=demo-nginx  bundle=/var/lib/kestrel/bundles/demo-nginx  run_dir=/run/kestrel  data_dir=/var/lib/kestrel
  syscall: fork+exec(kestrel-runtime)  args=["create","demo-nginx","--bundle","/var/lib/kestrel/bundles/demo-nginx"]
  annotate: runtime is never linked (single-thread invariant); runtime asserts Threads:1
  [hint if failed: "kestrel-runtime not found near kestreld binary; build workspace first (cargo build --workspace)"]
```

---

### 4 — Runtime setup (host side, before `run_stages`)

```
[+56.01ms] phase=runtime.cgroup.create   path=/sys/fs/cgroup/kestrel/demo-nginx
  syscall: mkdir(path=/sys/fs/cgroup/kestrel/demo-nginx) + enable_controllers_in_parents()
  annotate: walks root→parent writing cgroup.subtree_control "+cpu +memory +io +pids"; never in leaf (no-internal-process rule)
  [hint if failed: "cgroup2 required (statfs CGROUP2_SUPER_MAGIC); boot with systemd.unified_cgroup_hierarchy=1"]

[+56.40ms] phase=cgroup.resources.apply_cpu    cpu.max="max 100000"  cpu.weight="100"
[+56.55ms] phase=cgroup.resources.apply_mem   memory.max="max" memory.high="max"
[+56.60ms] phase=cgroup.resources.apply_pids  pids.max="max"
  syscall: write(fd=/sys/fs/cgroup/kestrel/demo-nginx/<controller>, data="<value>")
  [hint if failed: "controller not enabled in parent's subtree_control; write "+cpu" to each ancestor first; value syntax must be '<quota> <period>'"]

[+57.00ms] phase=ns.plan.build             create=[Mount,Uts,Ipc,Pid,Net,Cgroup,Time,User]  join=[]  uid_map=[0:1000:1]  gid_map=[0:1000:1]
[+57.20ms] phase=cgroup.fd.open            syscall: open(fd=/sys/fs/cgroup/kestrel/demo-nginx, O_DIRECTORY) for CLONE_INTO_CGROUP

[+57.50ms] phase=runtime.fifo.create       syscall: mkfifo(/run/kestrel/demo-nginx/exec.fifo, 0600)
  annotate: state.json written atomically (temp+rename) as Creating before any fork; exec.fifo blocks init until start
  [hint if failed: "mkfifo failed: run_dir must be tmpfs /run/kestrel, check permissions"]

[+58.00ms] phase=runtime.bootstrap.socket  syscall: socketpair(AF_UNIX, SOCK_STREAM, 0) -> host_fd=7 init_fd=8 (no CLOEXEC on init side)
  annotate: host_fd gets FD_CLOEXEC; child closes host copy immediately to avoid hang on hook failure
```

---

### 5 — Three-stage dance (`kestrel-ns::stages::run_stages`)

```
[+58.50ms] phase=ns.stage0.clone           flags=CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWCGROUP|CLONE_NEWTIME (no CLONE_NEWPID yet)
  syscall: socketpair(AF_UNIX, SOCK_SEQPACKET, SOCK_CLOEXEC) for sync
  syscall: prctl(PR_SET_CHILD_SUBREAPER, 1)  [ensures PID 1 reparents to runtime, not host init]
  syscall: fork() -> stage1 pid=5012
  [hint if failed: "fork EAGAIN: hit pids.max or memory limit; check cgroup limits"]

[+59.00ms] phase=ns.stage1.join_preexisting  (none in this plan; if container:<id> mode, would do setns(fd, clone_flag) here before any unshare)
  annotate: join runs BEFORE unshare(CLONE_NEWUSER) — joining after drops caps (EPERM)

[+59.10ms] phase=ns.stage1.unshare_user    syscall: unshare(CLONE_NEWUSER)
  [hint if failed: "unprivileged_userns_clone disabled; sysctl -w kernel.unprivileged_userns_clone=1 or run via newuidmap fallback"]

[+59.12ms] phase=ns.stage1.sync.RequestMaps -> stage0
[+59.30ms] phase=ns.stage0.write_maps      syscall: write(/proc/5012/uid_map, "0 1000 1")  (single write, all lines)
                                           write(/proc/5012/setgroups, "deny")  [CVE-2014-8989: deny before gid_map]
                                           write(/proc/5012/gid_map, "0 1000 1")
  [hint if failed: "EPERM missing setgroups=deny before gid_map; or /etc/subuid range too small (use newuidmap fallback)"]

[+59.40ms] phase=ns.stage1.sync.MapsDone  -> stage1
[+59.41ms] phase=ns.stage1.setresuid       syscall: setresuid(0,0,0) / setresgid(0,0,0)  [now root inside userns]
[+59.45ms] phase=ns.stage1.unshare_rest    syscall: unshare(CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWCGROUP|CLONE_NEWTIME)
[+59.50ms] phase=ns.stage1.unshare_pid     syscall: unshare(CLONE_NEWPID)  (affects children only)
[+59.60ms] phase=ns.stage1.clone_into_cgroup  syscall: clone3(CLONE_INTO_CGROUP, fd=6) -> stage2 pid=5013 (PID 1, atomically in cgroup; ENOSYS fallback: fork+write cgroup.procs)
  annotate: cgroup dir fd kept open since runtime.cgroup.fd.open; closed only after run_stages returns
[+59.70ms] phase=ns.stage1.ReportPid(5013) -> stage0; stage1 _exit(0); PID 1 reparented to runtime (subreaper)
[+59.75ms] phase=ns.stage0.state_write     state.json: status=Created pid=5013 (atomic temp+rename)
```

> **Timing note:** In `--verbose` the actual `elapsed_ms` per phase is emitted by
> `tracing::info!(phase, elapsed_ms, "done")`; values above are representative
> for a local VM. The ASCII timeline in `docs/NAMESPACES.md` shows the same
> sequence.

---

### 6 — `kestrel-init` (PID 1, inside new namespaces)

```
[+60.00ms] phase=init.recv_bootstrap       fd=3 (BOOTSTRAP_FD)  syscall: recv_go_ahead (blocks; EOF means createRuntime hooks failed)
  [hint if failed: "parent closed socket without go-ahead: check createRuntime hooks logs"]

[+60.10ms] phase=init.mounts.private       syscall: mount(NULL, "/", MS_REC|MS_PRIVATE, NULL)  [detach from host propagation; without it pivot_root fails/leaks]
[+60.12ms] phase=init.mounts.overlay       syscall: mount("overlay", merged=/var/lib/kestrel/snapshots/demo-nginx/merged, "overlay", "lowerdir=...,upperdir=...,workdir=...")
  [hint if failed: "workdir must be empty; lowerdir opts >4096 bytes means symlink farm not applied"]

[+60.20ms] phase=init.pivot_root           syscall: mount(MS_BIND|MS_REC, new_root, new_root)  (ensure mount point)
                                           syscall: chdir(new_root)
                                           syscall: pivot_root(".", ".")  (stacks old root over new)
                                           syscall: mount(MS_REC|MS_SLAVE, ".", NULL)  (prevent umount propagation)
                                           syscall: umount2(".", MNT_DETACH)  (detach old root)
                                           syscall: chdir("/")
  [hint if failed: "pivot_root EINVAL: new_root not a mount point; EPERM: need CAP_SYS_ADMIN"]

[+60.40ms] phase=init.mounts.standard      /proc (/proc), /sys, /sys/fs/cgroup, /dev (tmpfs), /dev/pts (newinstance), /dev/shm, /dev/mqueue, /dev/null binds, masked/RO paths
  annotate: RO remount is 2 calls (bind then MS_REMOUNT|MS_RDONLY); single MS_BIND|MS_RDONLY silently ignores RDONLY
[+60.60ms] phase=init.hooks.createContainer  (none configured here)  [runs after pivot, before FIFO block]
[+60.70ms] phase=init.block_fifo           syscall: open("/.kestrel/exec.fifo", O_RDONLY) blocks until start

[+60.80ms] phase=init.pin_namespaces       syscall: mount(MS_BIND, src=/proc/5013/ns/<type>, target=/run/kestrel/demo-nginx/ns/<type>) per type
  annotate: Mount ns pin may warn EINVAL on Lima VM (known bind-mount limitation); rest pinned atomically or rolled back
  [hint if failed: "needs CAP_SYS_ADMIN in host mount ns; stale pin rolled back, no partial pins left"]

[+61.00ms] phase=runtime.hooks.createRuntime  (host side, after run_stages returns, before go-ahead)
  syscall: fork+exec each hook with OCI state.json; timeout 30s
  [hint if failed: "go-ahead byte never sent; child observes EOF and _exit(1) without exec"]
```

---

### 7 — `kestrel start demo-nginx` (unblock FIFO)

```
[+5.20s ] phase=runtime.start             container_id=demo-nginx
  syscall: open(/run/kestrel/demo-nginx/exec.fifo, O_WRONLY)  [unblocks PID 1]
[+5.21s ] phase=init.startContainer_hooks  (none)
[+5.22s ] phase=init.caps                  syscall: capset(bounding, permitted, effective, inheritable, ambient)  [bounding drops irreversible]
  annotate: 14-cap default (no SYS_ADMIN, no NET_ADMIN); --cap-add/drop resolved here
[+5.23s ] phase=init.no_new_privs          syscall: prctl(PR_SET_NO_NEW_PRIVS, 1)  [must be before seccomp]
[+5.24s ] phase=init.seccomp               syscall: seccomp(SECCOMP_SET_MODE_FILTER, flags, filter)  [after no_new_privs, immediately before execve]
  annotate: unknown syscall names skipped with warn; ~44 denied by default profile
[+5.25s ] phase=init.execve                syscall: execve("/bin/sh", ["/bin/sh","-c","nginx -g 'daemon off;'"], env=[...])
  annotate: cgroup membership already in effect (clone_into_cgroup before first instruction, no window); signalfd reaper loop starts:
          prctl(PR_SET_PDEATHSIG), sigprocmask(block), signalfd, waitpid(-1, WNOHANG) loop
  [hint if failed: "ENOENT: entrypoint not in container rootfs; or ETXTBSY: still busy after pivot"]
```

---

### 8 — Post-start (daemon)

```
[+5.30s ] phase=kestreld.metrics.tick      cgroup stats (cpu.stat, memory.current/peak, io.stat, pids.current) + PSI (some/full) at 1Hz
[+5.31s ] phase=kestreld.events.emit       container.started event on SSE bus (GET /events)
[+5.35s ] phase=kestreld.copyup.scan       upperdir walk every 5s: Data/MetadataOnly/Whiteout/Opaque + amplification ratio
```

---

## Reading the trace without `--verbose`

Without `--verbose`, `kestrel explain <id>` still renders from the persisted
`state.json` + `meta.json` + live introspection (`/namespaces`, `/cgroup`,
`/mounts`, `/caps`, `/seccomp`, `/layers`):

```
$ kestrel explain demo-nginx
explain demo-nginx: replaying creation trace (showing inspect + namespaces + cgroup)
...
```

With `--verbose` (or `RUST_LOG=debug`), every phase above appears as a
`timing` span; `kestrel --verbose create/start` streams it live, and
`kestrel explain` reprints the recorded spans with `elapsed_ms` so the
container's birth reads as a single narrative.

## Further reading

- `docs/NAMESPACES.md` — three-stage dance diagram + timing ASCII
- `docs/CGROUPS.md` — v2 rules and PSI
- `docs/OVERLAY.md` — symlink farm rationale
- `docs/SECURITY.md` — caps/seccomp ordering
- `crates/kestrel-runtime/src/main.rs:timed_phase` — per-phase timing helper
- `crates/kestreld/src/main.rs:timed_phase*` — daemon setup phases
