# SPEC.md — Container Runtime from Scratch (`kestrel`)

> **Backend: Rust 2021 (edition 2021, MSRV 1.75+)** — OCI runtime, image store, storage driver, networking, daemon
> **Frontend: React 18 + TypeScript + Vite + Tailwind + shadcn/ui + D3 + Recharts** (web dashboard) **and ratatui** (TUI)
> **Target: Linux ≥ 5.11** (userxattr overlayfs, `clone3`, `CLONE_INTO_CGROUP`, cgroup v2 unified)

---

## §1 Language Decision — Rust, and this one is not close

### The runc/Go problem

Every previous project in this series used Go, correctly. This one must not, and there is a specific, concrete reason.

Two kernel operations that a container runtime performs **require a single-threaded process**:

- `setns(fd, CLONE_NEWUSER)` — joining an existing user namespace
- `unshare(CLONE_NEWUSER)` — creating one
- `setns(fd, CLONE_NEWNS)` — mount namespaces are **per-thread**, not per-process

The Go runtime spawns OS threads during initialization, before `main()` runs, and the goroutine scheduler freely migrates goroutines between threads. A `setns()` performed on one thread does not apply to the goroutine after it is rescheduled elsewhere.

runc's solution is a **C constructor that runs before the Go runtime boots**:

```c
// runc/libcontainer/nsenter/nsenter.go
/*
#cgo CFLAGS: -Wall
extern void nsexec();
void __attribute__((constructor)) init(void) { nsexec(); }
*/
import "C"
```

`nsexec.c` is ~1000 lines of C implementing a three-stage fork dance (STAGE_PARENT → STAGE_CHILD → STAGE_INIT) with pipe-based synchronization, all executing before Go exists. runc's own maintainers have an open issue titled *"nsexec: moving as much as we can to Go"* which concludes that `setns(CLONE_NEWUSER)` alone makes removing the C shim impossible.

**A from-scratch container runtime in Go is really a container runtime in C with a Go wrapper.** For a project whose entire purpose is understanding namespaces and cgroups, that is exactly backwards.

### Why Rust solves this cleanly

| Requirement | Rust |
|---|---|
| Single-threaded at `main()` | ✅ No runtime threads. `unshare(CLONE_NEWUSER)` just works. |
| Raw syscalls | ✅ `nix`, `libc`, `rustix` — thin, safe, zero-cost wrappers |
| `clone3` / `CLONE_INTO_CGROUP` | ✅ Direct `syscall(SYS_clone3, …)`; no stdlib to fight |
| Memory safety while running as **root with CAP_SYS_ADMIN** | ✅ The security argument. runc has shipped CVEs in its C shim. |
| No GC pause during container setup | ✅ Deterministic; matters for high-density short-lived containers |
| Precise `unsafe` boundaries | ✅ Every raw syscall is an auditable `unsafe` block |

This is not theoretical: **youki** is a production OCI runtime in Rust, passes the OCI conformance suite, and is used as a containerd/Podman drop-in. Its stated rationale is exactly the above — *"the Go runtime's constraints in runc have led to a mixed implementation with C, which has sometimes resulted in security vulnerabilities. Rust allows for a pure Rust implementation."*

### Crate selection

| Crate | Role |
|---|---|
| `nix` | namespaces, mount, pivot_root, signals, wait, sched |
| `libc` | raw constants, `syscall()` for `clone3` |
| `rustix` | modern, `no_std`-friendly syscall layer for hot paths |
| `caps` | capability set manipulation |
| `libseccomp` (or hand-rolled BPF) | seccomp filter assembly |
| `oci-spec` | OCI Runtime + Image Spec types (serde-derived) |
| `netlink-packet-route` + `rtnetlink` | veth, bridge, addresses, routes — **no shelling out to `ip`** |
| `nftables` bindings / `iptables` via netlink | NAT rules |
| `sha2`, `flate2`, `tar`, `zstd` | image layer digest + extraction |
| `reqwest` + `oci-distribution` | registry client |
| `axum` + `tokio` | daemon HTTP API + SSE |
| `clap` | CLI |
| `ratatui` + `crossterm` | TUI |
| `tracing` | structured logs, spans for lifecycle phases |

**Explicitly avoided:** `tokio` inside the runtime binary. Container creation is a synchronous fork/exec dance where an async runtime spawning threads would reintroduce the exact problem we chose Rust to avoid. `kestrel-runtime` is **strictly single-threaded, no async**. Only `kestreld` (the daemon) uses tokio, and it `fork+exec`s the runtime binary rather than linking it.

### Frontend: two interfaces, both justified

A container runtime is a CLI tool, so a **ratatui TUI** (`kestrel top`) is the natural day-to-day interface — lazydocker-style, no browser needed, works over SSH.

But the *educational* payload of this project is making invisible kernel state visible, and several of those artifacts genuinely need pixels:

- **Namespace membership graph** — which PIDs live in which of 8 namespaces (D3 force/tree)
- **OverlayFS layer stack** — lowerdir chain, whiteouts, copy-up events with sizes
- **cgroup resource + PSI charts** — throttle events, memory pressure over time (Recharts)
- **Network topology** — veth pairs, bridges, netns, NAT rules (D3)

So: **React + Vite + Tailwind + shadcn/ui + D3 (topology) + Recharts (time series) + xterm.js (attach/exec terminal)**, fed by SSE from `kestreld`.

---

## §2 Concepts Covered

| Area | Concepts |
|---|---|
| Namespaces | All 8: `mnt`, `uts`, `ipc`, `pid`, `net`, `user`, `cgroup`, `time`; creation ordering, `setns` vs `unshare` vs `clone`, persistence via bind-mounted `/proc/PID/ns/*` |
| User namespaces | uid/gid maps, `setgroups=deny`, `/etc/subuid`, `newuidmap`, rootless containers, capability semantics inside a userns |
| PID namespaces | PID 1 semantics, zombie reaping, signal delivery rules, `pid_for_children`, no re-entry |
| cgroups v2 | Unified hierarchy, `cgroup.subtree_control`, no-internal-process rule, `cpu.max`/`cpu.weight`, `memory.max`/`high`/`low`, `io.max`, `pids.max`, `cpuset`, freezer, `memory.events` OOM counting, delegation |
| PSI | `cpu.pressure`, `memory.pressure`, `io.pressure`; `some` vs `full`; poll-based threshold triggers |
| OverlayFS | lowerdir stacking order, upperdir, workdir constraints, whiteouts (char dev 0:0), opaque dirs, copy-up, `metacopy`, `redirect_dir`, `userxattr`, `index`, `volatile` |
| Root pivot | `pivot_root(".", ".")` idiom, `MS_PRIVATE`/`MS_SLAVE` propagation, why `chroot` is escapable |
| Mounts | Propagation types, bind mounts, `/proc`, `/sys`, `/dev`, `devpts`, `mqueue`, `tmpfs`, masked & readonly paths |
| Security | Capability sets (bounding/permitted/effective/inheritable/ambient), `no_new_privs`, seccomp BPF, `seccomp_unotify`, rlimits, `oom_score_adj` |
| OCI Runtime Spec | `config.json`, lifecycle state machine, `state.json`, all 5 hook phases |
| OCI Image Spec | Content-addressable store, manifests, index, config, layer diffIDs vs digests, `oci-layout` |
| Registry | Distribution API v2, token auth, chunked blob pull, cross-repo blob mount |
| Networking | netns lifecycle, veth pairs, Linux bridge, IPAM, NAT (MASQUERADE/DNAT), port publishing, DNS injection, network modes |
| Init | PID 1 responsibilities, `SIGCHLD` reaping loop, signal forwarding, exit-code propagation |
| Observability | Copy-up tracing, seccomp violation capture, namespace inventory, live PSI, layer dedup analysis |
| Beyond Docker | Time namespace demo, copy-up heatmap, PSI-driven pressure alerts, checkpoint/restore (CRIU) stretch |

---

## §3 Architecture

```
┌──────────────┐        ┌────────────────┐
│  Web UI      │        │  TUI           │
│  React+D3    │        │  ratatui       │
└──────┬───────┘        └────────┬───────┘
       │ REST + SSE               │ Unix socket
       └───────────┬──────────────┘
                   ▼
        ┌────────────────────────┐
        │  kestreld (daemon)     │  tokio + axum
        │  ├ container registry  │  in-memory + on-disk state
        │  ├ event bus (SSE)     │
        │  ├ metrics sampler     │  cgroup + PSI @ 1Hz
        │  └ image manager       │
        └───────────┬────────────┘
                    │ fork + exec (never linked in-process)
                    ▼
        ┌────────────────────────┐
        │  kestrel-runtime       │  SINGLE-THREADED, NO ASYNC
        │  (OCI runtime binary)  │
        │  create/start/kill/... │
        └───────────┬────────────┘
                    │ clone3 / unshare
        ┌───────────▼────────────┐
        │  kestrel-init (PID 1)  │  tiny static binary
        │  ├ finalize rootfs     │
        │  ├ apply seccomp/caps  │
        │  ├ exec entrypoint     │
        │  └ reap zombies        │
        └───────────┬────────────┘
                    ▼
             container process

  Supporting subsystems (libraries, used by runtime + daemon):
   kestrel-oci        OCI spec types & validation
   kestrel-ns         namespace creation, uid/gid maps
   kestrel-cgroup     cgroups v2 manager
   kestrel-rootfs     overlayfs snapshotter, mounts, pivot_root
   kestrel-security   caps, seccomp, no_new_privs, rlimits
   kestrel-net        netns, veth, bridge, IPAM, NAT
   kestrel-image      content store, registry client, layer extraction
```

**Why the daemon `fork+exec`s the runtime instead of calling it as a library:** the daemon is multi-threaded (tokio). The runtime must be single-threaded. A hard process boundary makes that invariant structural rather than a comment someone will violate.

---

## §4 Namespaces

### 4.1 The eight namespaces

| Namespace | Flag | Isolates | Kernel |
|---|---|---|---|
| Mount | `CLONE_NEWNS` | mount table | 2.4.19 |
| UTS | `CLONE_NEWUTS` | hostname, domainname | 2.6.19 |
| IPC | `CLONE_NEWIPC` | SysV IPC, POSIX mqueues | 2.6.19 |
| PID | `CLONE_NEWPID` | process ID space | 2.6.24 |
| Network | `CLONE_NEWNET` | interfaces, routes, netfilter, sockets | 2.6.29 |
| User | `CLONE_NEWUSER` | UID/GID, capabilities, keys | 3.8 |
| Cgroup | `CLONE_NEWCGROUP` | cgroup root view | 4.6 |
| Time | `CLONE_NEWTIME` | `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME` offsets | 5.6 |

```rust
// crates/kestrel-ns/src/lib.rs
use nix::sched::CloneFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NsType { Mount, Uts, Ipc, Pid, Net, User, Cgroup, Time }

impl NsType {
    pub fn clone_flag(self) -> CloneFlags {
        match self {
            NsType::Mount  => CloneFlags::CLONE_NEWNS,
            NsType::Uts    => CloneFlags::CLONE_NEWUTS,
            NsType::Ipc    => CloneFlags::CLONE_NEWIPC,
            NsType::Pid    => CloneFlags::CLONE_NEWPID,
            NsType::Net    => CloneFlags::CLONE_NEWNET,
            NsType::User   => CloneFlags::CLONE_NEWUSER,
            NsType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
            NsType::Time   => CloneFlags::from_bits_retain(0x0000_0080), // CLONE_NEWTIME
        }
    }
    /// Path component under /proc/<pid>/ns/
    pub fn proc_name(self) -> &'static str {
        match self {
            NsType::Mount => "mnt",  NsType::Uts    => "uts",
            NsType::Ipc   => "ipc",  NsType::Pid    => "pid",
            NsType::Net   => "net",  NsType::User   => "user",
            NsType::Cgroup=> "cgroup", NsType::Time => "time",
        }
    }
}
```

### 4.2 The creation-order problem

Three constraints conflict:

1. **User namespace must come first.** Inside a new userns the process holds a full capability set in that namespace, which is what makes the remaining unshares possible unprivileged.
2. **uid/gid maps must be written by a process *outside* the new userns**, because writing them requires `CAP_SETUID`/`CAP_SETGID` in the *parent* namespace.
3. **`unshare(CLONE_NEWPID)` does not move the caller.** It only affects *subsequently forked children*. The caller stays in the old PID namespace; the next `fork()` produces PID 1 of the new one.

The resolution is a three-stage process, exactly as runc's `nsexec.c` does it — but in safe Rust, because we're single-threaded:

```
STAGE 0 (kestrel-runtime, parent)
  ├─ create sync socketpair
  ├─ clone(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC
  │        | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME)   ← NOT NEWPID
  │        (or unshare then fork, for CLONE_INTO_CGROUP via clone3)
  ├─ wait for child's REQUEST_MAPS
  ├─ write /proc/<child>/uid_map
  ├─ write /proc/<child>/setgroups = "deny"      ← MUST precede gid_map
  ├─ write /proc/<child>/gid_map
  ├─ send MAPS_DONE
  ├─ receive grandchild PID
  └─ write state.json, exit (for `create`) / wait (for `run`)

STAGE 1 (child — has all namespaces except PID)
  ├─ send REQUEST_MAPS, wait for MAPS_DONE
  ├─ setresuid(0,0,0) / setresgid(0,0,0)   ← now root inside the userns
  ├─ unshare(CLONE_NEWPID)                 ← affects our children only
  ├─ fork()  →  grandchild becomes PID 1
  ├─ send grandchild PID to STAGE 0
  └─ _exit(0)                              ← STAGE 1 dies; PID 1 is reparented

STAGE 2 (grandchild — PID 1 in the new PID namespace)
  ├─ join cgroup (or was placed there by CLONE_INTO_CGROUP)
  ├─ mount("", "/", MS_REC | MS_PRIVATE)   ← detach from host propagation
  ├─ build rootfs: overlay mount, /proc, /sys, /dev, devpts, mqueue, tmpfs
  ├─ apply masked + readonly paths
  ├─ pivot_root(".", ".")  +  umount2(".", MNT_DETACH)
  ├─ sethostname, set time-ns offsets
  ├─ run createContainer hooks
  ├─ open exec fifo, block  ← this is what makes `create` ≠ `start`
  ├─ run startContainer hooks
  ├─ drop capabilities, set no_new_privs, install seccomp filter
  └─ execve(entrypoint)
```

### 4.3 Why `setgroups=deny` is mandatory

Writing `gid_map` in a user namespace created by an unprivileged process fails with `EPERM` unless `/proc/<pid>/setgroups` has been set to `"deny"` first. This is a **security fix** (CVE-2014-8989): without it, an unprivileged user could map a group they belong to, then `setgroups()` to *drop* that group, thereby escaping a negative-permission ACL (a file with `group nobody: ---`).

```rust
pub fn write_id_maps(pid: Pid, uid_maps: &[IdMapping], gid_maps: &[IdMapping]) -> Result<()> {
    let base = format!("/proc/{pid}");

    // uid_map first — no ordering constraint against setgroups
    fs::write(format!("{base}/uid_map"), render_map(uid_maps))?;

    // CVE-2014-8989: setgroups MUST be denied before gid_map is written by an
    // unprivileged process, or the write fails with EPERM. Ignore ENOENT for
    // pre-3.19 kernels that lack the file.
    match fs::write(format!("{base}/setgroups"), "deny") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    fs::write(format!("{base}/gid_map"), render_map(gid_maps))?;
    Ok(())
}

fn render_map(maps: &[IdMapping]) -> String {
    // "<container_id> <host_id> <size>\n" per line
    maps.iter()
        .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
        .collect::<Vec<_>>()
        .join("\n")
}
```

Note: a single `write()` must contain **all** lines. The kernel accepts exactly one write to `uid_map`/`gid_map` per namespace.

### 4.4 Namespace persistence and `join`

To support `kestrel exec` (entering a running container), namespaces are pinned by bind-mounting `/proc/<pid>/ns/<type>` onto a file under `/run/kestrel/<id>/ns/`. This keeps the namespace alive even if PID 1 exits, and gives a stable path for `setns`.

```rust
pub fn pin_namespace(pid: Pid, ns: NsType, target: &Path) -> Result<()> {
    fs::File::create(target)?;                       // bind-mount target must exist
    let src = format!("/proc/{pid}/ns/{}", ns.proc_name());
    mount(Some(src.as_str()), target, None::<&str>, MsFlags::MS_BIND, None::<&str>)?;
    Ok(())
}

/// Order matters: user namespace LAST, because entering it drops the
/// capabilities needed to enter the others.
pub fn join_namespaces(pins: &BTreeMap<NsType, PathBuf>) -> Result<()> {
    const ORDER: &[NsType] = &[
        NsType::Cgroup, NsType::Ipc, NsType::Uts, NsType::Net,
        NsType::Pid,    NsType::Mount, NsType::Time, NsType::User,
    ];
    for ns in ORDER {
        if let Some(p) = pins.get(ns) {
            let fd = fs::File::open(p)?;
            setns(fd.as_fd(), ns.clone_flag())?;
        }
    }
    Ok(())
}
```

---

## §5 cgroups v2

### 5.1 Layout and the two structural rules

```
/sys/fs/cgroup/                       ← cgroup2 root
├── cgroup.controllers                 "cpuset cpu io memory hugetlb pids"
├── cgroup.subtree_control             "+cpu +memory +pids"  ← what CHILDREN may use
├── cgroup.procs
├── cpu.pressure  memory.pressure  io.pressure   ← PSI, always present
└── kestrel/
    ├── cgroup.subtree_control         "+cpu +memory +pids +io"
    └── <container-id>/
        ├── cgroup.procs      cgroup.threads   cgroup.freeze   cgroup.kill
        ├── cgroup.events                      ← "populated 0|1"
        ├── cpu.max  cpu.weight  cpu.stat  cpu.pressure
        ├── memory.max  memory.high  memory.low  memory.min
        ├── memory.current  memory.peak  memory.events  memory.stat  memory.pressure
        ├── memory.swap.max  memory.swap.current
        ├── io.max  io.weight  io.stat  io.pressure
        ├── pids.max  pids.current  pids.events
        └── cpuset.cpus  cpuset.mems  cpuset.cpus.effective
```

**Rule 1 — top-down enabling.** A controller's interface files appear in a cgroup only if the *parent* listed it in `cgroup.subtree_control`. Enabling a controller for children does **not** enable it for the cgroup itself.

**Rule 2 — no internal processes.** A cgroup with children enabled in `subtree_control` may not itself contain processes (except the root). This is why containers get a leaf cgroup and the runtime never puts processes in `kestrel/` directly.

### 5.2 Controller interface

```rust
// crates/kestrel-cgroup/src/lib.rs

pub struct CgroupManager {
    root: PathBuf,          // /sys/fs/cgroup
    path: PathBuf,          // /sys/fs/cgroup/kestrel/<id>
    delegated: bool,        // rootless: we own a delegated subtree
}

impl CgroupManager {
    pub fn create(&self, resources: &LinuxResources) -> Result<()> {
        fs::create_dir_all(&self.path)?;
        self.enable_controllers_in_parents()?;
        self.apply(resources)
    }

    /// Walk from root to our parent, adding "+cpu +memory +io +pids" at each level.
    /// Required by Rule 1 — a controller unavailable in the parent's
    /// subtree_control means our interface files simply do not exist.
    fn enable_controllers_in_parents(&self) -> Result<()> {
        let available = self.read_available_controllers(&self.root)?;
        let want: Vec<&str> = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"]
            .into_iter().filter(|c| available.contains(*c)).collect();
        let spec = want.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ");

        let mut cur = self.root.clone();
        for comp in self.path.strip_prefix(&self.root)?.components() {
            // Enable in `cur` so that `cur/comp` gets the files
            let _ = fs::write(cur.join("cgroup.subtree_control"), &spec);
            cur = cur.join(comp);
            if cur == self.path { break; }  // do NOT enable in the leaf itself
        }
        Ok(())
    }

    pub fn apply(&self, r: &LinuxResources) -> Result<()> {
        if let Some(cpu) = &r.cpu {
            // cpu.max: "<quota> <period>" or "max <period>"
            if let (Some(q), p) = (cpu.quota, cpu.period.unwrap_or(100_000)) {
                let quota = if q <= 0 { "max".to_string() } else { q.to_string() };
                self.write("cpu.max", &format!("{quota} {p}"))?;
            }
            // cgroup v1 "shares" (2..262144, default 1024) → v2 "weight" (1..10000, default 100)
            if let Some(shares) = cpu.shares {
                self.write("cpu.weight", &shares_to_weight(shares).to_string())?;
            }
            if let Some(cpus) = &cpu.cpus { self.write("cpuset.cpus", cpus)?; }
            if let Some(mems) = &cpu.mems { self.write("cpuset.mems", mems)?; }
        }

        if let Some(m) = &r.memory {
            // memory.max = hard limit (OOM kill above)
            if let Some(limit) = m.limit { self.write("memory.max", &fmt_limit(limit))?; }
            // memory.high = throttle point — reclaim aggressively, do NOT kill.
            // Setting only memory.max gives you a cliff; memory.high gives a ramp.
            if let Some(r) = m.reservation { self.write("memory.high", &fmt_limit(r))?; }
            // v2 swap is SEPARATE, not "memory+swap" as in v1.
            if let Some(s) = m.swap { self.write("memory.swap.max", &fmt_limit(s))?; }
        }

        if let Some(p) = &r.pids { self.write("pids.max", &fmt_limit(p.limit))?; }

        if let Some(io) = &r.block_io {
            if let Some(w) = io.weight {
                self.write("io.weight", &blkio_weight_to_io_weight(w).to_string())?;
            }
            for t in io.throttle_read_bps_device.iter().flatten() {
                self.write("io.max", &format!("{}:{} rbps={}", t.major, t.minor, t.rate))?;
            }
        }
        Ok(())
    }

    /// Freezer — cgroup v2 replaces v1's freezer controller with a single file.
    pub fn freeze(&self, frozen: bool) -> Result<()> {
        self.write("cgroup.freeze", if frozen { "1" } else { "0" })
    }

    /// Atomic kill of every process in the cgroup (kernel 5.14+). Far more
    /// reliable than iterating cgroup.procs, which races against fork().
    pub fn kill_all(&self) -> Result<()> { self.write("cgroup.kill", "1") }

    pub fn stats(&self) -> Result<CgroupStats> { /* parse cpu.stat, memory.*, io.stat, pids.* */ }
    pub fn pressure(&self, res: PsiResource) -> Result<Psi> { /* parse *.pressure */ }
}

/// v1 shares [2, 262144] → v2 weight [1, 10000], log-ish mapping used by
/// systemd and runc so migrated configs behave the same.
fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 { return 100; }
    let s = shares.clamp(2, 262_144) as f64;
    (1.0 + ((s - 2.0) * 9999.0) / 262_142.0).round() as u64
}
```

### 5.3 Pressure Stall Information (PSI)

PSI is the single most useful signal cgroup v2 added, and Docker does not surface it. `kestrel` does.

```
$ cat /sys/fs/cgroup/kestrel/abc123/memory.pressure
some avg10=12.43 avg60=8.91 avg300=3.02 total=8213445
full avg10=4.11  avg60=2.30 avg300=0.88 total=2011923
```

- **`some`** — at least one task stalled waiting on the resource
- **`full`** — *every* runnable task stalled simultaneously (pure lost work)
- `avgN` — percentage of the last N seconds spent stalled
- `total` — cumulative microseconds

```rust
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PsiLine { pub avg10: f64, pub avg60: f64, pub avg300: f64, pub total_us: u64 }

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Psi { pub some: PsiLine, pub full: Option<PsiLine> }  // cpu has no `full`

/// PSI threshold triggers: write a trigger spec, then poll(POLLPRI).
/// This is an *event*, not a poll loop — the kernel wakes us only on breach.
pub fn watch_pressure(path: &Path, stall_us: u64, window_us: u64) -> Result<PsiWatcher> {
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    write!(&f, "some {stall_us} {window_us}")?;
    Ok(PsiWatcher { file: f })
}
```

### 5.4 OOM detection

```rust
/// memory.events is the authoritative OOM signal. Counting SIGKILL exits is
/// unreliable — a container can be SIGKILLed for many reasons.
pub fn oom_events(&self) -> Result<MemoryEvents> {
    let s = self.read("memory.events")?;
    // low 0 / high 12 / max 3 / oom 1 / oom_kill 1
    Ok(MemoryEvents {
        low: parse_kv(&s, "low")?, high: parse_kv(&s, "high")?,
        max: parse_kv(&s, "max")?, oom: parse_kv(&s, "oom")?,
        oom_kill: parse_kv(&s, "oom_kill")?,
    })
}
```

The daemon polls `memory.events` at 1 Hz; an increment in `oom_kill` emits an `OomKilled` event to the UI immediately.

### 5.5 `CLONE_INTO_CGROUP` (kernel 5.7+)

The classic sequence — fork, then write the PID to `cgroup.procs` — has a race: the child runs briefly *outside* the cgroup and can allocate memory or spawn processes before limits apply. `clone3` fixes this atomically.

```rust
#[repr(C)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64,
    exit_signal: u64, stack: u64, stack_size: u64,
    tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}

const CLONE_INTO_CGROUP: u64 = 0x2000_0000_0000;

/// Spawn directly into the target cgroup: limits are enforced from the very
/// first instruction the child executes.
pub unsafe fn clone_into_cgroup(flags: u64, cgroup_fd: RawFd) -> Result<Pid> {
    let mut args = CloneArgs {
        flags: flags | CLONE_INTO_CGROUP,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd as u64,
        ..Zeroable::zeroed()
    };
    let rc = libc::syscall(libc::SYS_clone3, &mut args as *mut _, size_of::<CloneArgs>());
    if rc < 0 { return Err(io::Error::last_os_error().into()); }
    Ok(Pid::from_raw(rc as i32))
}
```

---

## §6 OverlayFS Storage Driver

### 6.1 Layout

```
/var/lib/kestrel/
├── content/                          content-addressable blob store
│   └── blobs/sha256/<digest>         gzip/zstd tar layers, manifests, configs
├── layers/
│   └── <chain-id>/
│       ├── diff/                     extracted layer contents (a lowerdir)
│       ├── link                      short name for the lowerdir symlink trick
│       └── parent                    chain-id of the parent layer
├── l/<short>  ->  ../layers/<chain-id>/diff   symlink farm (see §6.3)
├── snapshots/
│   └── <container-id>/
│       ├── upper/                    writable layer
│       ├── work/                     overlayfs scratch — MUST be empty at mount
│       └── merged/                   the mountpoint
└── containers/<id>/{config.json,state.json,ns/}
```

### 6.2 The mount

```rust
pub fn mount_overlay(&self, snap: &Snapshot) -> Result<()> {
    // lowerdir is colon-separated and RIGHTMOST IS BOTTOM.
    // Image layers are stored bottom-first, so reverse them.
    let lowers: Vec<String> = snap.lower_links.iter().rev()
        .map(|l| format!("l/{l}")).collect();

    let mut opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowers.join(":"),
        snap.upper.display(),
        snap.work.display()
    );

    if self.rootless {
        // Kernel 5.11+: use user.overlay.* xattrs instead of trusted.overlay.*,
        // which an unprivileged user cannot set. Without this, rootless overlay
        // mounts fail on the first whiteout.
        opts.push_str(",userxattr");
    }
    if self.metacopy {
        // chmod/chown copies metadata only; data copy-up deferred to first write.
        opts.push_str(",metacopy=on");
    }
    if self.redirect_dir {
        opts.push_str(",redirect_dir=on");  // makes lower-dir rename work
    }

    mount(Some("overlay"), &snap.merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))?;
    Ok(())
}
```

### 6.3 Why the symlink farm exists

Mount option strings are capped at one page (4096 bytes). An image with 40 layers, each with a 64-hex-char chain ID under a long prefix, blows past that. Docker's overlay2 driver solves it by symlinking each `diff/` directory to a short random name under `l/`:

```
/var/lib/kestrel/l/DPFA3D  ->  ../layers/sha256:9f8a…/diff
```

and then `chdir`ing to `/var/lib/kestrel` before mounting so the option string can use relative paths. This is not an optimization — deep images simply fail to mount without it.

### 6.4 Whiteouts and opaque directories

| Concept | On-disk representation |
|---|---|
| Deleted file | Character device, major 0, minor 0, at the same path in upperdir |
| Deleted+recreated dir | Directory in upperdir with xattr `trusted.overlay.opaque="y"` (or `user.overlay.opaque` with `userxattr`) |
| Renamed dir from lower | xattr `trusted.overlay.redirect=<path>` |

OCI image layers encode deletions as `.wh.<name>` files (and `.wh..wh..opq` for opaque dirs) inside the tar. Extraction must translate:

```rust
pub fn apply_layer(tar: impl Read, dest: &Path, rootless: bool) -> Result<LayerStats> {
    let ns = if rootless { "user.overlay" } else { "trusted.overlay" };
    for entry in Archive::new(tar).entries()? {
        let entry = entry?;
        let path = entry.path()?;
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if name == ".wh..wh..opq" {
            // Whole-directory opacity marker
            let dir = dest.join(path.parent().unwrap());
            xattr::set(&dir, &format!("{ns}.opaque"), b"y")?;
            continue;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            // Single-entry deletion → character device 0:0
            let wh = dest.join(path.parent().unwrap()).join(target);
            let _ = fs::remove_file(&wh);
            mknod(&wh, SFlag::S_IFCHR, Mode::empty(), makedev(0, 0))?;
            continue;
        }
        entry.unpack_in(dest)?;
    }
    Ok(stats)
}
```

### 6.5 Copy-up tracing (a feature Docker does not have)

Copy-up is the single biggest source of surprise disk usage and latency in containers: writing one byte to a 2 GB file in a lower layer copies all 2 GB. `kestrel` makes this visible by walking `upperdir` and correlating against the lower stack.

```rust
pub struct CopyUpEvent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub from_layer: String,     // which chain-id it came from
    pub detected_at: SystemTime,
    pub kind: CopyUpKind,       // Data | MetadataOnly | Whiteout | Opaque
}

/// Periodic scan of upperdir. For each regular file present in upper AND in
/// some lower, this was a copy-up. metacopy files carry an xattr pointing at
/// the origin, letting us distinguish metadata-only from full data copies.
pub fn scan_copy_ups(snap: &Snapshot, ns: &str) -> Result<Vec<CopyUpEvent>> { /* … */ }
```

Surfaced in the UI as a **copy-up heatmap** — the top files by bytes copied, plus a running total the container has amplified beyond its logical writes.

### 6.6 Rootless: overlayfs or fuse-overlayfs

| Kernel | Approach |
|---|---|
| ≥ 5.11 in a user namespace | Native overlayfs with `-o userxattr` |
| < 5.11 | `fuse-overlayfs` fallback |
| No FUSE either | `vfs` driver — full copy per layer, correct but slow |

Detection is at runtime by attempting the native mount and falling back on `EPERM`/`EINVAL`.

---

## §7 Rootfs Construction & `pivot_root`

### 7.1 Why not `chroot`

`chroot()` changes the process's root directory but **does not change the mount table**, and a process holding a file descriptor to a directory outside the new root — or with `CAP_SYS_CHROOT` and a second `chroot` — can walk out with `fchdir(fd); chdir("..")` repeatedly. It's an isolation hint, not a boundary.

`pivot_root()` swaps the **mount** that serves as root for the entire mount namespace, and the old root is then unmounted. There is no remaining path to the host filesystem.

### 7.2 The modern idiom

```rust
/// The `pivot_root(".", ".")` trick, documented in pivot_root(2) NOTES.
/// It works because pivot_root stacks the old root ON TOP OF the new root at
/// the same location; the subsequent MNT_DETACH unmounts only the old one.
/// This avoids needing a temporary directory inside the container image.
pub fn pivot_root(new_root: &Path) -> Result<()> {
    let old_cwd = File::open(".")?;

    // 1. Detach from host mount propagation. Without this, our mounts and
    //    unmounts leak back to the host (systemd marks / as MS_SHARED), and
    //    pivot_root refuses to run at all.
    mount(None::<&str>, "/", None::<&str>,
          MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)?;

    // 2. pivot_root requires new_root to be a mount point. If the overlay
    //    merged dir is already a mount this is a no-op; bind-mounting it to
    //    itself guarantees the property either way.
    mount(Some(new_root), new_root, None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)?;

    // 3. Must be CWD for the "." form.
    chdir(new_root)?;

    // 4. Swap. Old root is now stacked over "." .
    nix::unistd::pivot_root(".", ".")?;

    // 5. Explicitly make the old root MS_SLAVE before detaching so the
    //    umount cannot propagate to the host namespace.
    mount(None::<&str>, ".", None::<&str>,
          MsFlags::MS_REC | MsFlags::MS_SLAVE, None::<&str>)?;

    // 6. Detach the old root. Lazy detach because submounts may be busy.
    umount2(".", MntFlags::MNT_DETACH)?;

    chdir("/")?;
    drop(old_cwd);
    Ok(())
}
```

### 7.3 Standard mounts

Performed *before* `pivot_root`, into the merged directory:

| Target | Type | Options |
|---|---|---|
| `/proc` | `proc` | `nosuid,noexec,nodev` |
| `/sys` | `sysfs` | `nosuid,noexec,nodev,ro` |
| `/sys/fs/cgroup` | `cgroup2` | `nosuid,noexec,nodev,relatime,ro` (rw if cgroupns) |
| `/dev` | `tmpfs` | `nosuid,strictatime,mode=755,size=65536k` |
| `/dev/pts` | `devpts` | `nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5` |
| `/dev/shm` | `tmpfs` | `nosuid,noexec,nodev,mode=1777,size=65536k` |
| `/dev/mqueue` | `mqueue` | `nosuid,noexec,nodev` |

Device nodes (`/dev/null`, `zero`, `full`, `random`, `urandom`, `tty`) are created with `mknod` when privileged, or **bind-mounted from the host** when rootless (an unprivileged user cannot `mknod`).

### 7.4 Masked and read-only paths

The OCI spec's default masked paths hide host information leaks:

```rust
const DEFAULT_MASKED: &[&str] = &[
    "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
    "/proc/sched_debug", "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap",
];
const DEFAULT_READONLY: &[&str] = &[
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
];

/// Directories are masked with an empty read-only tmpfs; files with /dev/null.
pub fn mask_path(p: &Path) -> Result<()> {
    match mount(Some("/dev/null"), p, None::<&str>, MsFlags::MS_BIND, None::<&str>) {
        Err(Errno::ENOTDIR) | Err(Errno::EISDIR) => {
            mount(Some("tmpfs"), p, Some("tmpfs"), MsFlags::MS_RDONLY, Some("size=0k"))?;
        }
        r => r?,
    }
    Ok(())
}

/// Read-only requires TWO mounts: bind first, then remount with MS_RDONLY.
/// A single mount() with MS_BIND|MS_RDONLY silently ignores the RDONLY flag —
/// a classic and very quiet bug.
pub fn make_readonly(p: &Path) -> Result<()> {
    mount(Some(p), p, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)?;
    mount(None::<&str>, p, None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
          None::<&str>)?;
    Ok(())
}
```

---

## §8 Security Layer

### 8.1 Capabilities

Five sets, applied in a specific order because dropping from the bounding set is irreversible:

```rust
pub fn apply_capabilities(caps: &LinuxCapabilities) -> Result<()> {
    // 1. Ambient must be cleared first — you cannot raise a cap into ambient
    //    that is not in both permitted and inheritable.
    caps::clear(None, CapSet::Ambient)?;

    // 2. Bounding set: irreversible. Drop everything not requested.
    for cap in caps::all() {
        if !caps.bounding.contains(&cap) {
            caps::drop(None, CapSet::Bounding, cap)?;
        }
    }

    // 3. Effective / permitted / inheritable
    caps::set(None, CapSet::Permitted,   &caps.permitted)?;
    caps::set(None, CapSet::Inheritable, &caps.inheritable)?;
    caps::set(None, CapSet::Effective,   &caps.effective)?;

    // 4. Ambient last — survives execve() of a non-privileged binary,
    //    which is how a non-root container process keeps e.g. CAP_NET_BIND_SERVICE.
    for cap in &caps.ambient { caps::raise(None, CapSet::Ambient, *cap)?; }
    Ok(())
}
```

Default set (Docker-compatible, 14 caps):
`CHOWN`, `DAC_OVERRIDE`, `FSETID`, `FOWNER`, `MKNOD`, `NET_RAW`, `SETGID`, `SETUID`, `SETFCAP`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `KILL`, `AUDIT_WRITE`.

Notably **absent**: `SYS_ADMIN` (mount, namespace creation — effectively root), `SYS_PTRACE`, `SYS_MODULE`, `NET_ADMIN`, `DAC_READ_SEARCH` (enables `open_by_handle_at`, the Shocker exploit).

### 8.2 `no_new_privs`

```rust
// MUST be set BEFORE seccomp for unprivileged filter installation, and it
// permanently prevents setuid/setcap binaries from elevating. Irreversible.
prctl::set_no_new_privs(true)?;
```

### 8.3 Seccomp

```rust
pub fn install_seccomp(profile: &LinuxSeccomp) -> Result<Option<OwnedFd>> {
    let mut ctx = ScmpFilterContext::new_filter(profile.default_action.into())?;

    for arch in &profile.architectures { ctx.add_arch((*arch).into())?; }

    for rule in &profile.syscalls {
        for name in &rule.names {
            let sc = ScmpSyscall::from_name(name)?;   // unknown syscall → skip, not fail
            if rule.args.is_empty() {
                ctx.add_rule(rule.action.into(), sc)?;
            } else {
                let cmps: Vec<ScmpArgCompare> = rule.args.iter().map(Into::into).collect();
                ctx.add_rule_conditional(rule.action.into(), sc, &cmps)?;
            }
        }
    }

    ctx.load()?;

    // SCMP_ACT_NOTIFY: the kernel hands us an fd; a supervisor can inspect and
    // emulate blocked syscalls in userspace. This is how kestrel captures
    // violations for the UI instead of just killing the process silently.
    if profile.uses_notify() { Ok(Some(ctx.get_notify_fd()?)) } else { Ok(None) }
}
```

The default profile denies ~44 syscalls including `kexec_load`, `init_module`, `mount`, `pivot_root`, `bpf`, `perf_event_open`, `ptrace` (unless allowed), `add_key`, `keyctl`, `userfaultfd`, `clone` with namespace flags.

### 8.4 Seccomp notify → live violation feed

Instead of `SCMP_ACT_KILL` (process dies, no explanation), `kestrel` supports `SCMP_ACT_NOTIFY` on a configurable set. A supervisor thread in `kestreld` reads notifications, records `{pid, syscall, args, timestamp}`, streams them to the UI, and responds with `ENOSYS`. Developers get an audit trail of exactly which syscall their container tried to make.

---

## §9 OCI Runtime Spec

### 9.1 Lifecycle state machine

```
                 create                start
   [ nonexistent ] ──────► [ creating ] ──► [ created ] ──────► [ running ]
                                                 │                    │
                                                 │  delete            │ process exits
                                                 ▼                    ▼
                                            [ stopped ] ◄────────────┘
                                                 │  delete
                                                 ▼
                                          [ nonexistent ]

  Additional: pause/resume via cgroup.freeze  →  [ paused ]
```

The `created` state exists so orchestrators can configure networking, attach to stdio, and set up the cgroup **before any container code runs**. It is implemented with a **FIFO**: the init process opens `/run/kestrel/<id>/exec.fifo` for reading and blocks; `start` opens it for writing, unblocking init, which then `execve`s.

```rust
// kestrel-init, after all setup, before exec
let fifo = OpenOptions::new().read(true).open("/run/kestrel/exec.fifo")?;
let mut buf = [0u8; 1];
fifo.read_exact(&mut buf)?;   // blocks until `kestrel start`
// ... hooks, drop caps, seccomp ...
execvpe(&argv[0], &argv, &envp)?;
```

### 9.2 `state.json`

```rust
#[derive(Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")] pub oci_version: String,
    pub id: String,
    pub status: Status,          // creating|created|running|stopped|paused
    pub pid: Option<i32>,        // in the RUNTIME's pid namespace, not the container's
    pub bundle: PathBuf,
    #[serde(default)] pub annotations: HashMap<String, String>,
}
```

### 9.3 Hooks

| Phase | Namespace | Purpose |
|---|---|---|
| `createRuntime` | runtime (host) | after namespaces exist, before pivot_root — **this is where CNI runs** |
| `createContainer` | container mount ns | rootfs is ready, before pivot_root completes |
| `startContainer` | container | immediately before `execve` |
| `poststart` | runtime | after start returns |
| `poststop` | runtime | after delete — network teardown |

(`prestart` is deprecated in favour of `createRuntime` but supported for compatibility.)

---

## §10 OCI Image Spec & Registry

### 10.1 Content store

```
content/blobs/sha256/<64-hex>
```

Everything — manifests, configs, layer tarballs — is stored by the SHA-256 of its bytes. Pull is idempotent and layers dedupe across images for free.

**diffID vs digest** — the distinction that trips up every first implementation:

- **digest** = SHA-256 of the *compressed* blob as it is transferred. Used in the manifest, used to fetch.
- **diffID** = SHA-256 of the *uncompressed* tar. Used in the image config's `rootfs.diff_ids`.

**chainID** identifies a stack of layers:
```
chainID(0)   = diffID(0)
chainID(n)   = SHA256( chainID(n-1) + " " + diffID(n) )
```
Two images sharing a base share chainIDs, so extracted layers are shared on disk.

```rust
pub fn chain_id(diff_ids: &[String]) -> String {
    let mut chain = diff_ids[0].clone();
    for d in &diff_ids[1..] {
        chain = format!("sha256:{:x}", Sha256::digest(format!("{chain} {d}").as_bytes()));
    }
    chain
}
```

### 10.2 Pull

```
GET  /v2/                                     → 401 + WWW-Authenticate
GET  <realm>?service=…&scope=repository:x:pull → { token }
GET  /v2/<name>/manifests/<ref>               Accept: manifest.v2+json, oci.image.index.v1+json
  ├ if index → select by platform (os/arch/variant) → GET the manifest
GET  /v2/<name>/blobs/<config-digest>         → image config JSON
for each layer (parallel, bounded):
  GET /v2/<name>/blobs/<layer-digest>         → verify digest while streaming
```

Digest verification happens **during** the stream, not after, so a corrupt or malicious blob is rejected before it is fully written.

---

## §11 Networking

### 11.1 Modes

| Mode | Behaviour |
|---|---|
| `bridge` | new netns, veth to `kestrel0` bridge, IPAM, NAT egress, DNAT for published ports |
| `host` | no `CLONE_NEWNET` — shares the host stack |
| `none` | new netns with only `lo` |
| `container:<id>` | `setns` into another container's netns (pod semantics) |

### 11.2 Bridge setup, entirely via netlink

No shelling out to `ip` or `brctl` — `rtnetlink` gives typed, error-checked operations.

```rust
pub async fn attach_bridge(&self, id: &str, netns_fd: RawFd, cfg: &NetConfig) -> Result<Endpoint> {
    let (host_if, cont_if) = (format!("veth{}", &id[..8]), "eth0".to_string());

    // 1. veth pair — both ends start in the host netns
    self.handle.link().add().veth(host_if.clone(), "tmp-peer".into()).execute().await?;

    // 2. Move the peer into the container's netns by fd
    let peer_idx = self.index_of("tmp-peer").await?;
    self.handle.link().set(peer_idx).setns_by_fd(netns_fd).execute().await?;

    // 3. Host side: enslave to the bridge, bring up
    let br_idx = self.ensure_bridge(&cfg.bridge_name, cfg.gateway, cfg.subnet).await?;
    let host_idx = self.index_of(&host_if).await?;
    self.handle.link().set(host_idx).controller(br_idx).up().execute().await?;

    // 4. Container side: rename, address, routes, lo up — inside the netns
    let ip = self.ipam.allocate(&cfg.subnet, id)?;
    nsenter(netns_fd, || {
        let h = new_netlink_handle()?;
        h.link().set_name(peer_idx, cont_if.clone())?;
        h.address().add(peer_idx, ip, cfg.subnet.prefix_len())?;
        h.link().set(peer_idx).up()?;
        h.link().set_by_name("lo").up()?;
        h.route().add().v4().gateway(cfg.gateway)?;   // default via bridge
        Ok(())
    })?;

    // 5. NAT: masquerade egress; DNAT for each published port
    self.nat.ensure_masquerade(cfg.subnet, &cfg.bridge_name)?;
    for p in &cfg.published { self.nat.add_dnat(p, ip)?; }

    Ok(Endpoint { ip, host_if, cont_if, mac: self.mac_of(peer_idx).await? })
}
```

### 11.3 NAT rules

```
# egress: rewrite container source to host address
-t nat -A POSTROUTING -s 172.29.0.0/16 ! -o kestrel0 -j MASQUERADE

# ingress: publish host:8080 → container:80
-t nat -A KESTREL -p tcp --dport 8080 -j DNAT --to-destination 172.29.0.5:80

# hairpin: container reaching its own published port via the host address
-t nat -A POSTROUTING -s 172.29.0.5 -d 172.29.0.5 -p tcp --dport 80 -j MASQUERADE

# forwarding
-A FORWARD -i kestrel0 ! -o kestrel0 -j ACCEPT
-A FORWARD -i kestrel0 -o kestrel0 -j ACCEPT              # inter-container
-A FORWARD -o kestrel0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

Plus `net.ipv4.ip_forward=1` and `net.bridge.bridge-nf-call-iptables=1`.

### 11.4 Rootless networking

An unprivileged user cannot create veth pairs or bridges in the host netns. Two userspace options:

- **slirp4netns** — full userspace TCP/IP stack; slower, but propagates source IPs
- **pasta** (from `passt`) — translates L2 frames to L4 host sockets; faster, now the default in Podman

`kestrel` shells out to whichever is present, preferring `pasta`.

---

## §12 The Init Process (PID 1)

PID 1 in a namespace has kernel-special semantics that break naive entrypoints:

1. **No default signal handlers.** The kernel does not apply default actions for signals PID 1 has not explicitly handled. `SIGTERM` to a shell script entrypoint does nothing.
2. **Orphan reaping.** All orphaned processes in the namespace reparent to PID 1. If it doesn't `wait()`, zombies accumulate until `pids.max` is hit.
3. **Death kills the namespace.** When PID 1 exits, every other process gets `SIGKILL`.

```rust
// crates/kestrel-init/src/reaper.rs

pub fn run_init(child: Pid) -> Result<i32> {
    // Block signals before forking so nothing is lost in the window.
    let mut mask = SigSet::all();
    mask.remove(Signal::SIGSEGV); mask.remove(Signal::SIGBUS);
    mask.remove(Signal::SIGILL);  mask.remove(Signal::SIGFPE);
    mask.thread_block()?;
    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)?;

    let mut child_status: Option<i32> = None;

    loop {
        let si = sfd.read_signal()?.ok_or(Error::SignalFdEof)?;
        match Signal::try_from(si.ssi_signo as i32)? {
            Signal::SIGCHLD => {
                // Loop — a single SIGCHLD can represent MULTIPLE exited children.
                // Signals are not queued; one delivery may cover N deaths.
                loop {
                    match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::Exited(p, code)) => {
                            if p == child { child_status = Some(code); }
                        }
                        Ok(WaitStatus::Signaled(p, sig, _)) => {
                            if p == child { child_status = Some(128 + sig as i32); }
                        }
                        Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                        _ => continue,
                    }
                }
                if let Some(code) = child_status {
                    // Give any remaining orphans a moment, then exit with the
                    // entrypoint's code so `kestrel wait` is accurate.
                    return Ok(code);
                }
            }
            // Forward everything else to the real entrypoint.
            sig => { let _ = kill(child, sig); }
        }
    }
}
```

---

## §13 Daemon API

Base: `http://localhost:7777/v1` (also on `/run/kestrel.sock`)

### Containers
| Method | Path | Description |
|---|---|---|
| `GET` | `/containers` | list with filters |
| `POST` | `/containers` | create from image + spec |
| `GET` | `/containers/:id` | full inspect: state, ns inventory, cgroup, net, mounts |
| `POST` | `/containers/:id/start` | open the exec fifo |
| `POST` | `/containers/:id/stop` | SIGTERM, grace, SIGKILL |
| `POST` | `/containers/:id/kill` | signal directly |
| `POST` | `/containers/:id/pause` / `unpause` | `cgroup.freeze` |
| `DELETE` | `/containers/:id` | teardown |
| `POST` | `/containers/:id/exec` | new process in existing namespaces |
| `GET` | `/containers/:id/logs` | SSE stream, `?follow&tail&since` |
| `WS` | `/containers/:id/attach` | bidirectional stdio (xterm.js) |
| `POST` | `/containers/:id/resize` | TTY winsize |
| `GET` | `/containers/:id/top` | processes, both host and container PIDs |

### Introspection — the pedagogically interesting half
| Method | Path | Description |
|---|---|---|
| `GET` | `/containers/:id/namespaces` | 8 namespaces with inode numbers + sharing info |
| `GET` | `/containers/:id/cgroup` | full controller state |
| `GET` | `/containers/:id/pressure` | live PSI for cpu/memory/io |
| `GET` | `/containers/:id/layers` | overlay stack: lowerdirs, upper, whiteouts, opaques |
| `GET` | `/containers/:id/copyups` | copy-up events with sizes and origin layers |
| `GET` | `/containers/:id/mounts` | the container's mount table with propagation types |
| `GET` | `/containers/:id/caps` | all five capability sets |
| `GET` | `/containers/:id/seccomp` | active profile + violation log |
| `GET` | `/containers/:id/network` | veth pair, bridge, IP, routes, NAT rules |
| `GET` | `/system/namespaces` | host-wide namespace graph (PID → namespaces) |
| `GET` | `/system/topology` | full network topology for the D3 view |

### Images
| Method | Path | Description |
|---|---|---|
| `GET` `POST` | `/images` · `/images/pull` | list · pull (SSE progress per layer) |
| `GET` | `/images/:ref` | manifest, config, layer list |
| `GET` | `/images/:ref/layers` | diffIDs, digests, chainIDs, sizes, shared-with |
| `DELETE` | `/images/:ref` | remove (refcount-aware) |
| `GET` | `/images/dedup` | dedup analysis: logical vs physical bytes |

### Events
`GET /events` — SSE. Types: `container.create|start|die|oom|pause|unpause|destroy`, `image.pull.progress|pull.done`, `net.attach|detach`, `copyup`, `seccomp.violation`, `psi.threshold`, `cgroup.throttle`.

---

## §14 Frontend

### 14.1 Web dashboard — seven views

**View 1 · Container list** — TanStack Table: id, image, state chip, uptime, CPU%, mem/limit bar, PIDs, published ports. Inline start/stop/pause/kill. Row expands to a live sparkline strip.

**View 2 · Namespace Explorer** ⭐
D3 force graph. Two node kinds: **processes** (circles, sized by RSS) and **namespaces** (rounded rects, coloured by type, labelled with the inode number). An edge means "process is a member of namespace".

The payload: shared namespaces are *visually obvious*. Two containers in a pod sharing a netns show as two process clusters converging on one net-namespace node. A `--network host` container has an edge to the host's net namespace. Toggle each of the 8 types on/off. Selecting a namespace lists every member PID with both host and in-namespace PIDs side by side.

**View 3 · Layer & Copy-Up Inspector** ⭐
Top: the overlay stack as horizontal bars, bottom-to-top — each lowerdir labelled with chainID, size, and the Dockerfile instruction that produced it; then upperdir highlighted.

Bottom: a **copy-up table** sorted by bytes — path, size, source layer, timestamp, kind (Data / MetadataOnly / Whiteout / Opaque). A prominent **amplification ratio** ("container wrote 4 KiB logically, 2.1 GiB physically") because that number is genuinely shocking the first time you see it.

Side panel: whiteouts and opaque dirs found in upperdir, i.e. exactly what the container deleted.

**View 4 · Resource & Pressure** ⭐
Recharts, 1 Hz:
- CPU: usage vs `cpu.max` with **throttle events** as red markers from `cpu.stat`'s `nr_throttled`
- Memory: `memory.current`, `memory.high` line, `memory.max` line, `memory.peak` marker, OOM events as red vertical rules
- PSI: three stacked area charts (cpu/memory/io), `some` and `full` overlaid — `full` shaded darker
- IO: read/write bytes and IOPS against `io.max`

The PSI charts are the differentiator. A container at 60% CPU with `memory.pressure.full avg10=15` is being destroyed by page-cache thrash, and no CPU/memory percentage view shows that.

**View 5 · Network Topology** — D3. Bridges as rounded rects, containers as nodes, veth pairs as labelled edges (`veth9a3f@if12 ↔ eth0`), the host uplink, and NAT rules rendered as annotations on the bridge→uplink edge. Clicking a container shows its routes and iptables rules.

**View 6 · Security Panel** — capability matrix (all 40+ caps × 5 sets, granted/dropped), seccomp profile viewer with a searchable syscall table, and a **live violation feed** from seccomp-notify. Diff view against the default profile.

**View 7 · Terminal** — xterm.js over the attach WebSocket. Exec into a container, resize propagates via `/resize`.

Stack: `react` · `vite` · `tailwindcss` · `shadcn/ui` · `@tanstack/react-query` · `@tanstack/react-table` · `d3` (views 2 & 5) · `recharts` (view 4) · `@xterm/xterm` (view 7) · `zustand` (SSE event store).

### 14.2 TUI (`kestrel top`)

`ratatui` + `crossterm`. Panes: container list (j/k), detail (tab-switched: Stats / Namespaces / Layers / Mounts / Logs), a sparkline row, and a command bar (`s` start, `S` stop, `p` pause, `d` delete, `e` exec, `l` logs, `/` filter). Talks to the daemon over the Unix socket. No browser, works over SSH — which is how you actually debug a container host.

---

## §15 CLI

```
kestrel run [-d] [--name N] [-p H:C] [-v SRC:DST[:ro]] [-e K=V] [--rm]
            [--memory 512m] [--memory-reservation 256m] [--cpus 1.5] [--cpu-shares 512]
            [--pids-limit 100] [--network bridge|host|none|container:ID]
            [--cap-add C] [--cap-drop C] [--security-opt seccomp=P] [--read-only]
            [--user U[:G]] [--workdir W] [--hostname H] [--rootless]
            IMAGE [CMD...]

kestrel ps [-a] [--filter K=V] [--format json|table]
kestrel exec [-it] ID CMD...
kestrel logs [-f] [--tail N] [--since T] ID
kestrel inspect ID [--format go-template]
kestrel stop|start|restart|pause|unpause|kill|rm ID
kestrel stats [--no-stream] [ID...]
kestrel top ID

kestrel images | pull REF | rmi REF | history REF | layers REF | dedup

# The teaching subcommands — no equivalent in docker
kestrel ns ID                 # the 8 namespaces, inode numbers, what's shared
kestrel ns tree               # host-wide namespace membership tree
kestrel diff ID               # changed files vs image (like docker diff, but shows WHY)
kestrel copyups ID            # copy-up events with sizes and amplification ratio
kestrel pressure ID           # live PSI
kestrel caps ID               # all five capability sets
kestrel seccomp ID            # profile + violations
kestrel net topology          # bridges, veths, netns, NAT
kestrel explain ID            # step-by-step replay of everything create/start did

# OCI runtime interface (drop-in for containerd/podman)
kestrel-runtime create|start|state|kill|delete [--bundle B] ID
```

`kestrel explain` is the flagship educational command: it replays the recorded creation trace — every syscall class, in order, with arguments and timing — so you can read the container's birth as a narrative.

---

## §16 File Structure

```
kestrel/
├── Cargo.toml                      # workspace
├── crates/
│   ├── kestrel-oci/                # spec types, validation, defaults
│   ├── kestrel-ns/                 # namespaces, id maps, pinning, setns ordering
│   ├── kestrel-cgroup/             # cgroup v2 manager, PSI, freezer, clone3
│   ├── kestrel-rootfs/             # overlay snapshotter, mounts, pivot_root, masking
│   ├── kestrel-security/           # caps, seccomp, no_new_privs, rlimits, notify
│   ├── kestrel-net/                # netns, veth, bridge, IPAM, NAT, rootless
│   ├── kestrel-image/              # content store, registry, layer apply, chainID
│   ├── kestrel-runtime/            # SINGLE-THREADED lifecycle binary
│   ├── kestrel-init/               # static PID 1
│   ├── kestreld/                   # tokio daemon: API, SSE, metrics sampler
│   ├── kestrel-cli/                # clap CLI
│   └── kestrel-tui/                # ratatui
├── web/                            # React dashboard
│   └── src/{api,components/{containers,namespaces,layers,resources,network,security,terminal},store}
├── tests/
│   ├── integration/                # requires root + kernel features
│   └── oci-conformance/            # runtime-tools validation suite
├── profiles/seccomp/default.json
└── Makefile
```

---

## §17 Configuration

```toml
# /etc/kestrel/config.toml
[daemon]
socket = "/run/kestrel.sock"
http_addr = "127.0.0.1:7777"
state_dir = "/run/kestrel"
data_dir  = "/var/lib/kestrel"
metrics_interval_ms = 1000

[storage]
driver = "overlay2"          # overlay2 | fuse-overlayfs | vfs
metacopy = true
redirect_dir = true
userxattr = "auto"           # auto | true | false
copyup_scan_interval_s = 5

[cgroup]
root = "/sys/fs/cgroup"
parent = "kestrel"
manager = "cgroupfs"         # cgroupfs | systemd
psi_enabled = true
psi_trigger_stall_us = 150000
psi_trigger_window_us = 1000000

[network]
bridge = "kestrel0"
subnet = "172.29.0.0/16"
gateway = "172.29.0.1"
mtu = 1500
iptables = true
rootless_backend = "pasta"   # pasta | slirp4netns

[security]
seccomp_profile = "/etc/kestrel/profiles/seccomp/default.json"
no_new_privs = true
default_caps = ["CHOWN","DAC_OVERRIDE","FSETID","FOWNER","MKNOD","NET_RAW",
                "SETGID","SETUID","SETFCAP","SETPCAP","NET_BIND_SERVICE",
                "SYS_CHROOT","KILL","AUDIT_WRITE"]
seccomp_notify = false

[rootless]
enabled = false
subuid_file = "/etc/subuid"
subgid_file = "/etc/subgid"
```

---

## §18 Correctness Properties

1. **Namespace isolation is complete.** A container with all 8 namespaces sees only its own processes (`/proc` shows PID 1..N), its own mounts, its own hostname, its own network stack, and cgroup paths rooted at its own cgroup.

2. **No host filesystem reachable after pivot_root.** After the pivot, no path — including via retained file descriptors — resolves outside the container rootfs. Verified by attempting the classic `chroot` escape and confirming failure.

3. **Mount changes never propagate to the host.** After `mount(MS_REC|MS_PRIVATE)` on `/`, the host mount table is byte-identical before and after a container's full lifecycle.

4. **cgroup limits are enforced from instruction zero.** With `CLONE_INTO_CGROUP`, no window exists in which the container process runs unconstrained. A memory bomb in the entrypoint's first line is still OOM-killed at the limit.

5. **PID 1 reaps every orphan.** After a workload that spawns and abandons 10,000 children, `pids.current` returns to the live-process count; no zombies remain.

6. **Exit codes propagate.** `kestrel run` returns the entrypoint's exit code; signal deaths return `128 + signum`.

7. **Layers are content-addressed and shared.** Two images with a common base extract that base exactly once; `dedup` reports the saved bytes.

8. **Whiteouts hide lower entries.** A file deleted in a container is invisible in `merged`, present unchanged in the lower layer, and represented as a `0:0` char device in `upper`.

9. **Copy-up accounting is exact.** Reported copy-up bytes equal the actual `upperdir` growth attributable to lower-layer files.

10. **Capabilities are dropped irreversibly.** After start, no capability outside the configured bounding set can be regained, including via setuid binaries (`no_new_privs`).

11. **Seccomp is installed before exec.** The first instruction of the entrypoint already runs under the filter.

12. **Network isolation and reachability.** A `none`-mode container has only `lo`. A `bridge`-mode container reaches the internet via NAT, reaches sibling containers directly, and is reachable on published ports — while the host's other netns are unaffected.

13. **The runtime is single-threaded.** `/proc/self/status` reports `Threads: 1` for the entire duration of `kestrel-runtime`'s namespace setup. Asserted in a test.

14. **OCI conformance.** Passes `runtime-tools` validation for lifecycle, config parsing, hooks, and state.

---

## §19 Performance Targets

| Metric | Target |
|---|---|
| `create` → `created` (warm cache) | < 25 ms |
| `create` + `start` → entrypoint's first instruction | < 50 ms |
| `delete` (incl. netns + overlay teardown) | < 20 ms |
| Runtime binary RSS during setup | < 8 MiB |
| Layer extraction throughput | > 400 MiB/s (zstd), > 180 MiB/s (gzip) |
| Registry pull, 4 parallel layers | network-bound |
| Overlay mount (40 layers) | < 5 ms |
| cgroup stats sample (all controllers + PSI) | < 1 ms/container |
| Daemon RSS, 100 idle containers | < 60 MiB |
| SSE event → UI paint | < 50 ms |
| Namespace graph render (500 processes) | < 16 ms/frame |
