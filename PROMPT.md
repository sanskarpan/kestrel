# CLAUDE CODE PROMPT — Container Runtime from Scratch (`kestrel`)

## Project Mission

Build a Docker-class container runtime from scratch:

- **Backend: Rust** — all 8 Linux namespaces, cgroups v2 (incl. PSI), OverlayFS snapshotter, `pivot_root`, capabilities + seccomp, OCI Runtime & Image Spec, registry client, veth/bridge/NAT networking, PID-1 init with zombie reaping
- **Frontend: React + TypeScript + Vite + Tailwind + shadcn/ui + D3 + Recharts + xterm.js** — a dashboard that makes invisible kernel state visible
- **Second interface: ratatui TUI** — because a container runtime is a CLI tool and you debug hosts over SSH

**Read `container-SPEC.md` and `container-CHECKLIST.md` before writing any code.**

### Three rules that override everything

1. **Develop in a VM.** A wrong `umount2` or `pivot_root` can wedge the host filesystem. Vagrant/QEMU with a snapshot you can roll back to. This is in Phase 0 for a reason.

2. **`kestrel-runtime` is single-threaded and has no async runtime.** No `tokio`, no `rayon`, no thread spawning, transitively. `setns(CLONE_NEWUSER)` and `unshare(CLONE_NEWUSER)` require a single-threaded process, and mount namespaces are per-thread. This is the entire reason the project is in Rust rather than Go — do not undo it. Assert it at startup.

3. **Phases 2–5 are the kernel core.** Namespaces, cgroups, rootfs, security. Each must have passing tests in isolation before Phase 8 assembles them. If `pivot_root` is subtly wrong, every layer above it inherits an unfixable bug.

---

## Phase 0 — Bootstrap

```bash
cargo new --lib kestrel && cd kestrel
# workspace members per SPEC §16

# runtime crate deps — note what is ABSENT
cargo add -p kestrel-runtime nix libc rustix caps libseccomp oci-spec \
                             serde serde_json thiserror anyhow tracing
# daemon may use tokio; runtime may NOT
cargo add -p kestreld tokio axum tower-http rtnetlink netlink-packet-route \
                      reqwest sha2 flate2 zstd tar

cd web
bun create vite . --template react-ts
bun add @tanstack/react-query @tanstack/react-table d3 recharts \
        @xterm/xterm @xterm/addon-fit zustand clsx lucide-react
bun add -d tailwindcss postcss autoprefixer @types/d3
bunx tailwindcss init -p && bunx shadcn@latest init
```

**Preflight check — write this first, it saves hours of confusing failures:**

```rust
// crates/kestrel-runtime/src/preflight.rs

pub fn check_environment() -> Result<EnvReport> {
    let mut r = EnvReport::default();

    // cgroup v2 unified. On v1/hybrid, everything in Phase 3 silently
    // misbehaves in ways that look like our bugs.
    let st = statfs("/sys/fs/cgroup")?;
    if st.filesystem_type() != FsType(libc::CGROUP2_SUPER_MAGIC as _) {
        bail!("cgroup v2 required. Boot with systemd.unified_cgroup_hierarchy=1 \
               (or cgroup_no_v1=all) and reboot.");
    }
    r.controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?
        .split_whitespace().map(String::from).collect();

    // overlayfs
    if !fs::read_to_string("/proc/filesystems")?.contains("overlay") {
        bail!("overlayfs not available: modprobe overlay");
    }

    // PSI is a kernel config option; degrade gracefully rather than failing
    r.psi = Path::new("/proc/pressure/cpu").exists();

    // 5.11 gives us userxattr overlay in a userns, which rootless needs
    r.kernel = parse_kernel_version()?;
    if r.kernel < (5, 11, 0) {
        warn!("kernel {:?} < 5.11: rootless overlay will fall back to fuse-overlayfs", r.kernel);
    }

    // clone3 + CLONE_INTO_CGROUP
    r.clone3 = probe_clone3();

    Ok(r)
}

/// Rule 2, enforced. If this ever fires, someone added a dependency that
/// spawns threads and the userns syscalls are about to start failing with
/// EINVAL in a way that is very hard to trace back to its cause.
pub fn assert_single_threaded() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let threads: usize = status.lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1);
    ensure!(threads == 1,
        "kestrel-runtime must be single-threaded (found {threads}). \
         Some dependency spawned a thread. setns(CLONE_NEWUSER) will fail.");
    Ok(())
}
```

---

## Phase 2 — Namespaces: the three-stage dance

This is the hardest 200 lines in the project. Get it right and everything else follows.

### Why three stages

- **User namespace must be created before the others** so the process holds capabilities inside it.
- **uid/gid maps must be written from outside** the new userns, by a process that has `CAP_SETUID` in the parent namespace. So the child must pause and ask the parent.
- **`unshare(CLONE_NEWPID)` does not move the caller.** It only affects children created afterwards. So a second fork is mandatory, and *that* child is PID 1.

```rust
// crates/kestrel-ns/src/stages.rs

#[derive(Serialize, Deserialize, Debug)]
enum Sync {
    RequestMaps,
    MapsDone,
    ReportPid(i32),
    Ready,
    Error(String),
}

pub struct StageResult { pub init_pid: Pid, pub stage1_pid: Pid }

pub fn run_stages(plan: &NamespacePlan, cgroup_fd: Option<RawFd>) -> Result<StageResult> {
    assert_single_threaded()?;

    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)?;

    // Everything EXCEPT CLONE_NEWPID. PID ns is unshared in stage 1, because
    // the caller of unshare(CLONE_NEWPID) stays in the old namespace — only
    // its subsequent children land in the new one.
    let mut flags = plan.clone_flags();
    flags.remove(CloneFlags::CLONE_NEWPID);

    match unsafe { fork()? } {
        ForkResult::Child => {
            drop(parent_sock);
            // Any error here must be REPORTED, not just exited on, or the
            // parent hangs forever on the sync read with no diagnosis.
            if let Err(e) = stage1(&child_sock, flags, plan, cgroup_fd) {
                let _ = send_sync(&child_sock, &Sync::Error(format!("{e:#}")));
            }
            unsafe { libc::_exit(1) };
        }
        ForkResult::Parent { child: stage1_pid } => {
            drop(child_sock);
            stage0(&parent_sock, stage1_pid, plan)
                .map(|init_pid| StageResult { init_pid, stage1_pid })
        }
    }
}

// ─────────────────────────── STAGE 0 (runtime, host namespaces) ───────────
fn stage0(sock: &OwnedFd, stage1_pid: Pid, plan: &NamespacePlan) -> Result<Pid> {
    match recv_sync_timeout(sock, Duration::from_secs(10))? {
        Sync::RequestMaps => {}
        Sync::Error(e) => bail!("stage1 failed before maps: {e}"),
        other => bail!("unexpected sync from stage1: {other:?}"),
    }

    if plan.has_user_ns() {
        write_id_maps(stage1_pid, &plan.uid_maps, &plan.gid_maps)?;
    }
    send_sync(sock, &Sync::MapsDone)?;

    let init_pid = match recv_sync_timeout(sock, Duration::from_secs(30))? {
        Sync::ReportPid(p) => Pid::from_raw(p),
        Sync::Error(e) => bail!("stage1 failed after maps: {e}"),
        other => bail!("expected ReportPid, got {other:?}"),
    };

    // Stage 1 exits immediately after reporting; reap it so it does not
    // linger as a zombie in the runtime's process table.
    let _ = waitpid(stage1_pid, None);
    Ok(init_pid)
}

// ─────────── STAGE 1 (all namespaces except PID; still has old PID) ────────
fn stage1(sock: &OwnedFd, flags: CloneFlags, plan: &NamespacePlan,
          cgroup_fd: Option<RawFd>) -> Result<()> {
    prctl::set_name("kestrel:[1:CHILD]")?;

    // Create the user namespace FIRST and alone. Combining it with the others
    // in one unshare() works, but separating makes the ordering explicit and
    // the failure modes far easier to read.
    if plan.has_user_ns() {
        unshare(CloneFlags::CLONE_NEWUSER)?;
        send_sync(sock, &Sync::RequestMaps)?;
        match recv_sync_timeout(sock, Duration::from_secs(10))? {
            Sync::MapsDone => {}
            other => bail!("expected MapsDone, got {other:?}"),
        }
        // We are mapped to 0 inside the userns but our euid is still the old
        // value. setresuid makes us actually root in here, which the remaining
        // unshares require.
        setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))?;
        setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))?;
    }

    // Everything else, minus user (already done) and pid (handled next).
    let rest = flags - CloneFlags::CLONE_NEWUSER;
    if !rest.is_empty() { unshare(rest)?; }

    // Does NOT move us. Our next child becomes PID 1 of the new namespace.
    if plan.has_pid_ns() { unshare(CloneFlags::CLONE_NEWPID)?; }

    let init_pid = if let Some(fd) = cgroup_fd {
        // clone3 + CLONE_INTO_CGROUP: the child is IN the cgroup before its
        // first instruction. The fork-then-write-cgroup.procs approach leaves
        // a window where the container runs unconstrained.
        unsafe { clone_into_cgroup(libc::SIGCHLD as u64, fd)? }
    } else {
        match unsafe { fork()? } {
            ForkResult::Child => {
                // STAGE 2 — we are PID 1. Never returns.
                stage2_never_returns()
            }
            ForkResult::Parent { child } => child,
        }
    };

    send_sync(sock, &Sync::ReportPid(init_pid.as_raw()))?;

    // Stage 1 must exit so PID 1 is reparented and the process tree is clean.
    unsafe { libc::_exit(0) };
}
```

### `write_id_maps` — the CVE that dictates the ordering

```rust
// crates/kestrel-ns/src/idmap.rs

pub fn write_id_maps(pid: Pid, uid: &[IdMapping], gid: &[IdMapping]) -> Result<()> {
    let base = format!("/proc/{pid}");

    // The kernel accepts exactly ONE write to uid_map/gid_map per namespace.
    // All lines must go in a single write() call.
    fs::write(format!("{base}/uid_map"), render(uid))
        .with_context(|| format!("writing uid_map for pid {pid}"))?;

    // CVE-2014-8989. Without denying setgroups first, an unprivileged process
    // writing gid_map gets EPERM. The reason is a real escape: a user could map
    // a group they belong to, then setgroups() to DROP it, escaping a negative
    // ACL (a file with `group foo: ---`).
    // ENOENT on kernels < 3.19 where the file does not exist.
    match fs::write(format!("{base}/setgroups"), "deny") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("denying setgroups"),
    }

    fs::write(format!("{base}/gid_map"), render(gid))
        .with_context(|| format!("writing gid_map for pid {pid}"))?;
    Ok(())
}

fn render(maps: &[IdMapping]) -> String {
    maps.iter()
        .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
        .collect::<Vec<_>>()
        .join("\n") + "\n"
}
```

### `setns` ordering for `exec`

```rust
/// User namespace LAST. Entering a user namespace drops the capabilities you
/// need to enter the others, so joining user-first makes every subsequent
/// setns() fail with EPERM. This ordering bug produces the exact error in
/// runc issue #4390.
pub fn join_namespaces(pins: &BTreeMap<NsType, PathBuf>) -> Result<()> {
    const ORDER: &[NsType] = &[
        NsType::Cgroup, NsType::Ipc,  NsType::Uts,  NsType::Net,
        NsType::Pid,    NsType::Mount, NsType::Time, NsType::User,
    ];
    for ns in ORDER {
        let Some(path) = pins.get(ns) else { continue };
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        setns(f.as_fd(), ns.clone_flag())
            .with_context(|| format!("setns into {:?}", ns))?;
    }
    Ok(())
}
```

**Tests that gate Phase 3:**

```rust
#[test]
fn test_setgroups_deny_required() {
    // Prove the CVE-2014-8989 constraint empirically so the ordering never
    // gets "cleaned up" by a future refactor.
    let child = spawn_userns_child();
    fs::write(format!("/proc/{child}/uid_map"), "0 1000 1\n").unwrap();
    let err = fs::write(format!("/proc/{child}/gid_map"), "0 1000 1\n").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EPERM),
        "gid_map without setgroups=deny must fail with EPERM");

    fs::write(format!("/proc/{child}/setgroups"), "deny").unwrap();
    fs::write(format!("/proc/{child}/gid_map"), "0 1000 1\n").unwrap();
}

#[test]
fn test_join_order_matters() {
    let pins = pin_all_namespaces(container_pid());
    // user first → the rest fail
    assert!(join_user_then_net(&pins).is_err());
    // canonical order → succeeds
    assert!(join_namespaces(&pins).is_ok());
}
```

---

## Phase 3 — cgroups v2

### Controller enabling: the top-down rule

```rust
// crates/kestrel-cgroup/src/manager.rs

/// A controller's interface files exist in a cgroup only if its PARENT listed
/// that controller in cgroup.subtree_control. Enabling it in the cgroup itself
/// does nothing for that cgroup — it enables it for its children.
///
/// Combined with the no-internal-process rule (a cgroup with subtree_control
/// set may not contain processes), this means containers ALWAYS get a leaf
/// cgroup and we enable controllers in every ancestor but not in the leaf.
fn enable_controllers_in_parents(&self) -> Result<()> {
    let available = self.read_controllers(&self.root)?;
    let want = ["cpu", "memory", "io", "pids", "cpuset", "hugetlb"]
        .into_iter().filter(|c| available.contains(*c))
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>().join(" ");

    let rel = self.path.strip_prefix(&self.root)?;
    let mut cur = self.root.clone();
    for comp in rel.components() {
        // Writing to cur enables the controllers for cur's CHILDREN.
        // A failure here is often benign (already enabled), so log and continue.
        if let Err(e) = fs::write(cur.join("cgroup.subtree_control"), &want) {
            debug!("subtree_control {} <- {want}: {e}", cur.display());
        }
        cur = cur.join(comp);
        if cur == self.path { break; }   // never enable in the leaf itself
    }
    Ok(())
}
```

### `CLONE_INTO_CGROUP` — closing the unconstrained window

```rust
// crates/kestrel-cgroup/src/clone3.rs

#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64, pub pidfd: u64, pub child_tid: u64, pub parent_tid: u64,
    pub exit_signal: u64, pub stack: u64, pub stack_size: u64,
    pub tls: u64, pub set_tid: u64, pub set_tid_size: u64, pub cgroup: u64,
}

pub const CLONE_INTO_CGROUP: u64 = 0x2000_0000_0000;

/// The classic sequence — fork(), then write the pid to cgroup.procs — leaves
/// a window in which the child runs with NO limits. A memory bomb on the
/// entrypoint's first line escapes memory.max. clone3 places the child in the
/// cgroup atomically at creation.
///
/// # Safety
/// Caller must be single-threaded and must handle the child branch (rc == 0)
/// without touching any state that assumes a parent context.
pub unsafe fn clone_into_cgroup(exit_signal: u64, cgroup_fd: RawFd) -> Result<Pid> {
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP,
        exit_signal,
        cgroup: cgroup_fd as u64,
        ..Default::default()
    };
    let rc = libc::syscall(
        libc::SYS_clone3,
        &mut args as *mut CloneArgs,
        std::mem::size_of::<CloneArgs>(),
    );
    match rc {
        -1 => Err(io::Error::last_os_error()).context("clone3(CLONE_INTO_CGROUP)"),
        0  => stage2_never_returns(),      // child
        n  => Ok(Pid::from_raw(n as i32)), // parent
    }
}
```

### PSI parsing

```rust
// crates/kestrel-cgroup/src/psi.rs

/// some avg10=12.43 avg60=8.91 avg300=3.02 total=8213445
/// full avg10=4.11  avg60=2.30 avg300=0.88 total=2011923
///
/// `some` = at least one task stalled.
/// `full` = EVERY runnable task stalled — pure lost work. cpu.pressure has no
/// `full` line on older kernels, hence Option.
pub fn parse_psi(s: &str) -> Result<Psi> {
    let mut some = None;
    let mut full = None;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next().unwrap_or_default();
        let mut l = PsiLine::default();
        for kv in it {
            let (k, v) = kv.split_once('=').context("malformed psi field")?;
            match k {
                "avg10"  => l.avg10  = v.parse()?,
                "avg60"  => l.avg60  = v.parse()?,
                "avg300" => l.avg300 = v.parse()?,
                "total"  => l.total_us = v.parse()?,
                _ => {}
            }
        }
        match kind { "some" => some = Some(l), "full" => full = Some(l), _ => {} }
    }
    Ok(Psi { some: some.context("psi missing `some` line")?, full })
}

/// Event-driven pressure alerts. Write a trigger spec, then poll(POLLPRI):
/// the kernel wakes us only when the threshold is breached, instead of us
/// burning CPU polling a file every 100ms.
pub fn watch(path: &Path, stall_us: u64, window_us: u64) -> Result<PsiWatcher> {
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    // window must be 500ms..10s; stall must be < window
    write!(&f, "some {stall_us} {window_us}")?;
    Ok(PsiWatcher { file: f })
}
```

### OOM detection

```rust
/// memory.events.oom_kill is authoritative. Exit code 137 (128+SIGKILL) is NOT
/// — a container is SIGKILLed for many reasons, and conflating them produces
/// false "OOMKilled" statuses, which is a bug Docker itself has shipped.
pub fn oom_kill_count(&self) -> Result<u64> {
    let s = self.read("memory.events")?;
    s.lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .and_then(|v| v.trim().parse().ok())
        .context("memory.events missing oom_kill")
}
```

---

## Phase 4 — Rootfs

### `pivot_root` — every line matters

```rust
// crates/kestrel-rootfs/src/pivot.rs

/// The `pivot_root(".", ".")` idiom from pivot_root(2) NOTES.
/// It works because pivot_root stacks the old root ON TOP of the new root at
/// the same mount point; the following MNT_DETACH removes only the old one.
/// No temporary directory needs to exist inside the container image.
pub fn pivot_root(new_root: &Path) -> Result<()> {
    // (1) Detach from host mount propagation.
    //     systemd marks / as MS_SHARED. Without this:
    //       - our mounts leak into the host mount namespace
    //       - the umount2 below propagates and can unmount the HOST root
    //       - pivot_root refuses outright (it checks propagation types)
    mount(None::<&str>, "/", None::<&str>,
          MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("making / private (required before pivot_root)")?;

    // (2) pivot_root requires new_root to BE a mount point. If the overlay is
    //     already mounted here this is a cheap no-op; otherwise it makes the
    //     requirement true.
    mount(Some(new_root), new_root, None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .context("bind-mounting new_root onto itself")?;

    // (3) The "." form requires new_root to be CWD.
    chdir(new_root)?;

    // (4) Swap. Old root is now stacked over ".".
    nix::unistd::pivot_root(".", ".").context("pivot_root(\".\", \".\")")?;

    // (5) Explicitly mark the old root MS_SLAVE before detaching. Belt and
    //     braces on top of step (1): guarantees the umount cannot propagate.
    mount(None::<&str>, ".", None::<&str>,
          MsFlags::MS_REC | MsFlags::MS_SLAVE, None::<&str>)?;

    // (6) Lazy detach — submounts may still be busy; MNT_DETACH defers cleanup.
    umount2(".", MntFlags::MNT_DETACH).context("detaching old root")?;

    chdir("/")?;
    Ok(())
}
```

### Read-only bind mounts need two calls

```rust
/// A SINGLE mount() with MS_BIND|MS_RDONLY SILENTLY IGNORES MS_RDONLY.
/// The kernel creates a writable bind mount and returns success. This is the
/// quietest bug in the whole mount API: your --read-only volume is writable
/// and nothing tells you.
pub fn bind_readonly(src: &Path, dst: &Path) -> Result<()> {
    mount(Some(src), dst, None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)?;
    // The remount is what actually applies RDONLY.
    mount(None::<&str>, dst, None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
          None::<&str>)?;
    Ok(())
}
```

### Overlay mount with the symlink farm

```rust
// crates/kestrel-rootfs/src/overlay.rs

/// Mount option strings are capped at ONE PAGE (4096 bytes). A 40-layer image
/// with 64-hex-char chain IDs under /var/lib/kestrel/layers/ blows past that
/// and the mount fails with EINVAL for no obvious reason.
///
/// Docker's overlay2 driver solves it with a symlink farm: each layer's diff/
/// gets a 6-char symlink under l/, and we chdir() to the data dir so option
/// strings can use short relative paths.
pub fn mount_overlay(&self, snap: &Snapshot) -> Result<()> {
    let _guard = ChdirGuard::to(&self.data_dir)?;   // restores CWD on drop

    // lowerdir is colon-separated and RIGHTMOST IS THE BOTTOM LAYER.
    // Layers are stored bottom-first, so reverse.
    let lowers = snap.lower_links.iter().rev()
        .map(|l| format!("l/{l}"))
        .collect::<Vec<_>>().join(":");

    let mut opts = format!(
        "lowerdir={lowers},upperdir={},workdir={}",
        rel(&snap.upper, &self.data_dir)?.display(),
        rel(&snap.work,  &self.data_dir)?.display(),
    );

    if self.rootless {
        // 5.11+. Unprivileged users cannot set trusted.* xattrs, so without
        // this the first whiteout creation fails with EPERM.
        opts.push_str(",userxattr");
    }
    if self.metacopy   { opts.push_str(",metacopy=on"); }
    if self.redirect   { opts.push_str(",redirect_dir=on"); }

    ensure!(opts.len() < 4096,
        "overlay options {} bytes exceed one page — symlink farm not applied?", opts.len());

    // workdir MUST be empty. A stale work/ from a crashed container makes the
    // mount fail or, worse, succeed with corrupt state.
    clear_dir(&snap.work)?;

    mount(Some("overlay"), &snap.merged, Some("overlay"),
          MsFlags::empty(), Some(opts.as_str()))
        .with_context(|| format!("overlay mount opts={opts}"))?;
    Ok(())
}
```

### Layer extraction: whiteouts and path traversal

```rust
pub fn apply_layer(tar: impl Read, dest: &Path, rootless: bool) -> Result<LayerStats> {
    let ns = if rootless { "user.overlay" } else { "trusted.overlay" };
    let dest = dest.canonicalize()?;
    let mut stats = LayerStats::default();

    for entry in Archive::new(tar).entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();

        // SECURITY: a malicious layer with `../../etc/passwd` or an absolute
        // path would write outside the layer directory. Reject before touching
        // the filesystem. This is a real CVE class (tar-slip).
        let target = dest.join(&path);
        ensure!(target.starts_with(&dest), "path traversal in layer: {}", path.display());

        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        // Whole-directory opacity: everything below in lower layers is hidden.
        if name == ".wh..wh..opq" {
            let dir = dest.join(path.parent().unwrap_or(Path::new("")));
            xattr::set(&dir, &format!("{ns}.opaque"), b"y")?;
            stats.opaques += 1;
            continue;
        }

        // Single deletion: overlayfs represents it as a char device 0:0.
        if let Some(victim) = name.strip_prefix(".wh.") {
            let wh = dest.join(path.parent().unwrap_or(Path::new(""))).join(victim);
            let _ = fs::remove_file(&wh);
            let _ = fs::remove_dir_all(&wh);
            mknod(&wh, SFlag::S_IFCHR, Mode::empty(), makedev(0, 0))
                .with_context(|| format!("creating whiteout {}", wh.display()))?;
            stats.whiteouts += 1;
            continue;
        }

        entry.set_preserve_permissions(true);
        entry.set_unpack_xattrs(true);
        entry.unpack_in(&dest)?;
        stats.files += 1;
        stats.bytes += entry.size();
    }
    Ok(stats)
}
```

---

## Phase 5 — Security: order is everything

```rust
// crates/kestrel-security/src/apply.rs

/// Called by kestrel-init immediately before execve(). The ordering below is
/// not stylistic — each step depends on the previous one.
pub fn apply_all(p: &Process, seccomp: Option<&LinuxSeccomp>) -> Result<Option<OwnedFd>> {
    // (1) rlimits — must precede the setuid, since some limits cannot be
    //     raised after privileges are dropped.
    for rl in &p.rlimits { setrlimit(rl.typ, rl.soft, rl.hard)?; }

    // (2) Capabilities. Bounding-set drops are IRREVERSIBLE, so this must come
    //     after anything that still needed a capability.
    apply_capabilities(p.capabilities.as_ref())?;

    // (3) no_new_privs. Must precede seccomp: an unprivileged process can only
    //     install a seccomp filter if no_new_privs is set. Also permanently
    //     neuters setuid/setcap binaries inside the container.
    prctl::set_no_new_privs(true)?;

    // (4) User/group. AFTER capabilities so we still had CAP_SETUID/SETGID.
    if let Some(gid) = p.user.gid { setresgid(gid, gid, gid)?; }
    if !p.user.additional_gids.is_empty() { setgroups(&p.user.additional_gids)?; }
    if let Some(uid) = p.user.uid { setresuid(uid, uid, uid)?; }

    // (5) Seccomp LAST, immediately before exec, so the entrypoint's very first
    //     syscall is already filtered — and so our own setup syscalls above
    //     aren't blocked by the container's own profile.
    let notify_fd = seccomp.map(install_seccomp).transpose()?.flatten();

    Ok(notify_fd)
}

fn apply_capabilities(caps: Option<&LinuxCapabilities>) -> Result<()> {
    let Some(c) = caps else { return Ok(()) };

    // Ambient first: you cannot raise a cap into ambient unless it is in both
    // permitted and inheritable, and clearing first avoids inherited surprises.
    caps::clear(None, CapSet::Ambient)?;

    // Bounding set — IRREVERSIBLE. Once dropped, not even a setuid-root binary
    // can regain it. Do this before setting the other four.
    for cap in caps::all() {
        if !c.bounding.contains(&cap) {
            // EPERM here means we lack CAP_SETPCAP; surface it rather than
            // silently running with a wider bounding set than requested.
            caps::drop(None, CapSet::Bounding, cap)
                .with_context(|| format!("dropping {cap:?} from bounding set"))?;
        }
    }

    caps::set(None, CapSet::Permitted,   &c.permitted)?;
    caps::set(None, CapSet::Inheritable, &c.inheritable)?;
    caps::set(None, CapSet::Effective,   &c.effective)?;

    // Ambient last — this is what survives execve() of a non-setuid binary,
    // letting a non-root container process keep e.g. CAP_NET_BIND_SERVICE.
    for cap in &c.ambient { caps::raise(None, CapSet::Ambient, *cap)?; }
    Ok(())
}
```

---

## Phase 8 — PID 1: the reaper

```rust
// crates/kestrel-init/src/reaper.rs

/// PID 1 in a namespace has three kernel-special behaviours that break naive
/// entrypoints:
///   1. No default signal handlers. SIGTERM to an unhandling PID 1 does nothing.
///   2. Every orphan in the namespace reparents here. Not reaping them fills
///      pids.max with zombies.
///   3. When PID 1 exits, the kernel SIGKILLs everything else in the namespace.
pub fn supervise(child: Pid) -> Result<i32> {
    // Block signals BEFORE the child exists so nothing is lost in the window
    // between fork and handler installation.
    let mut mask = SigSet::all();
    for s in [Signal::SIGSEGV, Signal::SIGBUS, Signal::SIGILL, Signal::SIGFPE] {
        mask.remove(s);   // never block synchronous faults
    }
    mask.thread_block()?;
    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC)?;

    let mut exit_code: Option<i32> = None;

    loop {
        let si = sfd.read_signal()?.context("signalfd EOF")?;
        let sig = Signal::try_from(si.ssi_signo as i32)?;

        if sig == Signal::SIGCHLD {
            // CRITICAL: loop. Standard signals are NOT queued — a single
            // SIGCHLD delivery can represent many exited children. Calling
            // waitpid once per SIGCHLD leaks zombies under load.
            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(p, code)) => {
                        if p == child { exit_code = Some(code); }
                    }
                    Ok(WaitStatus::Signaled(p, s, _)) => {
                        if p == child { exit_code = Some(128 + s as i32); }
                    }
                    Ok(WaitStatus::StillAlive) => break,
                    Err(Errno::ECHILD) => break,
                    Ok(_) => continue,          // stopped/continued — keep reaping
                    Err(Errno::EINTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(code) = exit_code { return Ok(code); }
        } else {
            // Forward everything else to the real entrypoint. Without this,
            // `docker stop`-style SIGTERM is swallowed and the container only
            // ever dies by SIGKILL after the grace period.
            let _ = kill(child, sig);
        }
    }
}
```

---

## Frontend — the two views that justify a browser

### Namespace Explorer (D3)

```tsx
// web/src/components/namespaces/NamespaceGraph.tsx

type Node =
  | { kind: 'process'; id: string; pid: number; comm: string; rss: number; containerId?: string }
  | { kind: 'namespace'; id: string; nsType: NsType; inode: number; memberCount: number };

const NS_COLOR: Record<NsType, string> = {
  mnt: '#3b82f6', uts: '#8b5cf6', ipc: '#ec4899', pid: '#22c55e',
  net: '#f97316', user: '#ef4444', cgroup: '#14b8a6', time: '#a855f7',
};

export function NamespaceGraph({ data, visible }: Props) {
  const ref = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const nodes = data.nodes.filter(n => n.kind === 'process' || visible.has(n.nsType));
    const links = data.links.filter(l => nodes.some(n => n.id === l.target));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d: any) => d.id).distance(70))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(w / 2, h / 2))
      .force('collide', d3.forceCollide().radius((d: any) =>
        d.kind === 'namespace' ? 34 : 8 + Math.log1p(d.rss / 1e6) * 3));

    // THE PAYOFF: because membership is an edge, two containers sharing a
    // network namespace physically converge on one node. Pod semantics,
    // --network container:X, and --network host all become visually obvious
    // instead of being a line in `inspect` output nobody reads.
  }, [data, visible]);

  return <svg ref={ref} />;
}
```

### Copy-Up Inspector — the number that surprises people

```tsx
// web/src/components/layers/CopyUpPanel.tsx

export function CopyUpPanel({ containerId }: { containerId: string }) {
  const { data } = useCopyUps(containerId);
  if (!data) return <Skeleton />;

  const amplification = data.physicalBytes / Math.max(data.logicalBytes, 1);

  return (
    <div className="space-y-4">
      {/* Writing one byte to a 2 GiB file in a lower layer copies all 2 GiB.
          This is the single biggest source of surprise disk usage and startup
          latency in containers, and no mainstream tool surfaces it. */}
      <Card className={amplification > 10 ? 'border-red-500' : ''}>
        <CardHeader><CardTitle>Write Amplification</CardTitle></CardHeader>
        <CardContent>
          <div className="text-4xl font-mono tabular-nums">
            {amplification.toFixed(1)}×
          </div>
          <p className="text-sm text-muted-foreground">
            Container wrote <b>{fmtBytes(data.logicalBytes)}</b> logically,
            causing <b>{fmtBytes(data.physicalBytes)}</b> of copy-up.
          </p>
        </CardContent>
      </Card>

      <DataTable
        columns={[
          { header: 'Path',   accessorKey: 'path', cell: c => <code>{c.getValue()}</code> },
          { header: 'Copied', accessorKey: 'sizeBytes', cell: c => fmtBytes(c.getValue()) },
          { header: 'From layer', accessorKey: 'fromLayer',
            cell: c => <Badge variant="outline">{c.getValue().slice(7, 19)}</Badge> },
          { header: 'Kind', accessorKey: 'kind',
            cell: c => <Badge variant={c.getValue() === 'Data' ? 'destructive' : 'secondary'}>
                         {c.getValue()}</Badge> },
        ]}
        data={data.events}
        initialSorting={[{ id: 'sizeBytes', desc: true }]}
      />
    </div>
  );
}
```

### PSI chart

```tsx
// web/src/components/resources/PressureChart.tsx

/// `some` = at least one task stalled. `full` = EVERY runnable task stalled,
/// i.e. pure lost work. A container at 60% CPU with memory.pressure.full
/// avg10=15 is being destroyed by page-cache thrash — and no CPU% or memory%
/// view in Docker or Kubernetes shows that.
export function PressureChart({ resource, series }: Props) {
  return (
    <ResponsiveContainer height={180}>
      <AreaChart data={series}>
        <XAxis dataKey="t" tickFormatter={fmtTime} />
        <YAxis domain={[0, 100]} unit="%" />
        <Tooltip content={<PsiTooltip />} />
        <Area type="monotone" dataKey="some" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.22} />
        <Area type="monotone" dataKey="full" stroke="#ef4444" fill="#ef4444" fillOpacity={0.55} />
        <ReferenceLine y={20} stroke="#ef4444" strokeDasharray="4 4"
                       label={{ value: 'sustained stall', position: 'right' }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
```

---

## Integration Tests

```rust
#[test]
#[ignore = "requires root"]
fn test_no_host_escape() {
    // The classic chroot escape: hold an fd to a directory outside the new
    // root, fchdir to it, then walk up with chdir(".."). Under chroot this
    // works. Under pivot_root there is no mount to walk into.
    let out = run_in_container(r#"
        python3 -c '
import os
try:
    fd = os.open("/", os.O_RDONLY)
    os.fchdir(fd)
    for _ in range(64): os.chdir("..")
    os.chroot(".")
    print("ESCAPED" if os.path.exists("/etc/shadow") and open("/etc/hostname").read() != "container" else "CONTAINED")
except Exception:
    print("CONTAINED")'
    "#);
    assert_eq!(out.trim(), "CONTAINED");
}

#[test]
#[ignore = "requires root"]
fn test_host_mountinfo_unchanged() {
    // Mount propagation bugs are silent and catastrophic: the container's
    // mounts leak into the host and never get cleaned up. Byte-comparing
    // mountinfo is the only reliable detector.
    let before = fs::read_to_string("/proc/self/mountinfo").unwrap();
    let c = Container::run("alpine", &["sh", "-c", "mount -t tmpfs t /mnt; sleep 1"]);
    c.wait().unwrap();
    c.delete().unwrap();
    let after = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert_eq!(normalize(&before), normalize(&after), "container leaked mounts to host");
}

#[test]
#[ignore = "requires root"]
fn test_zombie_reaping() {
    // 10,000 orphans. If PID 1 does not waitpid() in a LOOP per SIGCHLD,
    // zombies accumulate and pids.max is eventually exhausted.
    let c = Container::run("alpine", &["sh", "-c", r#"
        for i in $(seq 1 10000); do (sleep 0.001 &) ; done
        sleep 3
        ps -eo stat | grep -c '^Z' || true
    "#]);
    let out = c.wait_output().unwrap();
    assert_eq!(out.trim(), "0", "zombies remained: PID 1 is not reaping correctly");
}

#[test]
#[ignore = "requires root"]
fn test_clone_into_cgroup_no_window() {
    // With fork-then-write-cgroup.procs there is a window where the container
    // runs unconstrained. A memory bomb on line 1 escapes memory.max. With
    // CLONE_INTO_CGROUP it cannot.
    let c = Container::builder("alpine")
        .memory_limit(32 * MiB)
        .cmd(&["sh", "-c", "head -c 200M /dev/zero | tail -c 200M > /dev/null"])
        .run();
    let st = c.wait().unwrap();
    assert_eq!(c.cgroup().oom_kill_count().unwrap(), 1, "memory limit was not enforced from t=0");
    assert_eq!(st, 137);
}

#[test]
#[ignore = "requires root"]
fn test_readonly_bind_needs_two_calls() {
    // Proves the mount API footgun so nobody "simplifies" bind_readonly().
    let d = tempdir().unwrap();
    let (src, dst) = (d.path().join("s"), d.path().join("d"));
    fs::create_dir_all(&src).unwrap(); fs::create_dir_all(&dst).unwrap();

    // Single call: MS_RDONLY is silently ignored, mount is WRITABLE.
    mount(Some(&src), &dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>).unwrap();
    assert!(fs::write(dst.join("x"), b"1").is_ok(), "single-call bind should be writable");
    umount(&dst).unwrap();

    // Two calls: actually read-only.
    bind_readonly(&src, &dst).unwrap();
    assert!(fs::write(dst.join("y"), b"1").is_err());
    umount2(&dst, MntFlags::MNT_DETACH).unwrap();
}
```

---

## Correctness Invariants

1. **Single-threaded runtime** — `test_single_threaded` asserts `Threads: 1` throughout setup
2. **`setgroups=deny` before `gid_map`** — `test_setgroups_deny_required` proves the EPERM
3. **`setns` order, user last** — `test_join_order_matters`
4. **No host escape after pivot_root** — `test_no_host_escape`
5. **No mount leakage** — `test_host_mountinfo_unchanged`
6. **Read-only binds need two calls** — `test_readonly_bind_needs_two_calls`
7. **Limits enforced from t=0** — `test_clone_into_cgroup_no_window`
8. **Zombies reaped** — `test_zombie_reaping` with 10,000 orphans
9. **Exit codes propagate** — `exit 42` → 42; SIGKILL → 137
10. **Whiteouts are char dev 0:0** — `test_whiteout_hides_lower`
11. **Layer dedup by chainID** — shared base extracted once
12. **Path traversal rejected** — `test_tar_path_traversal_rejected`
13. **Network teardown is complete** — iptables and links identical before/after
14. **OCI conformance** — `runtime-tools` suite passes

---

## Code Standards

**Rust**
- `kestrel-runtime` has **no async runtime and spawns no threads**, transitively. Enforce with a dependency check in CI, not a comment.
- Every `unsafe` block carries a `// SAFETY:` comment. `#![deny(clippy::undocumented_unsafe_blocks)]`.
- Every syscall wrapper adds context naming the syscall and its arguments. `EPERM` from `setns` is useless; *"setns into Net namespace /run/kestrel/abc/ns/net: EPERM"* is actionable.
- Errors during the fork dance are **sent over the sync socket**, never just `_exit()`. A silent stage failure means the parent blocks forever with no diagnosis.
- Every sync socket read has a timeout.
- `MS_REC | MS_PRIVATE` on `/` before **any** mount work. This is the difference between a container and a host-corrupting bug.
- Cleanup is idempotent and runs on every path including panic. Leaked netns, overlay mounts, and cgroups accumulate until the machine needs a reboot.

**Frontend**
- SSE with reconnect backoff; the daemon restarting must not require a page reload
- D3 owns the SVG; React owns the DOM around it. No fighting over children.
- 1 Hz metrics with a ring buffer capped at 300 samples (5 minutes)
- Destructive actions (kill, rm) always confirm

---

## Startup

```bash
# In the VM. Not on your laptop.
vagrant up && vagrant ssh

sudo ./target/debug/kestreld &          # daemon
cd web && bun run dev                   # http://localhost:5173
./target/debug/kestrel-tui              # or the TUI

sudo -E make test-root                  # integration tests
make oci-conformance
```

**First thing to run:**

```bash
kestrel run --rm alpine echo hello
```

Then open the **Namespace Explorer**. Run three containers, one with `--network host` and two with `--network container:<id>`. The graph makes namespace sharing physically visible: the host-network container has an edge to the *host's* net namespace node; the two joined containers converge on a single shared net namespace while keeping separate PID and mount namespaces. That single picture explains what Kubernetes pods actually are better than any amount of documentation.

**Then run the copy-up demo:**

```bash
kestrel run --rm -it alpine sh -c 'dd if=/dev/zero of=/big bs=1M count=500; echo x >> /big'
kestrel copyups <id>
```

Appending one byte to a 500 MiB file copies the whole thing. The amplification card reads **500,000×**. That number is the reason `COPY` ordering in Dockerfiles matters, and seeing it once is worth more than reading about it ten times.

**Then the pressure demo:**

```bash
kestrel run --memory 128m --rm alpine sh -c 'while :; do dd if=/dev/zero of=/t bs=1M count=100; rm /t; done'
```

Watch **View 4**. CPU sits low, memory stays under the limit, nothing looks wrong — and `memory.pressure.full` climbs past 20%. The container is spending a fifth of its wall-clock time with *every* task stalled on page reclaim. That is the diagnostic Docker and Kubernetes still do not show you, and it is why cgroup v2's PSI is the most useful thing in this entire project.
