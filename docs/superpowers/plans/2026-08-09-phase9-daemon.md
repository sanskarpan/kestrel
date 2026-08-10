# Phase 9: Daemon (`kestreld`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `kestreld` (tokio+axum daemon: container lifecycle, logs, attach, metrics, events, introspection, images) and a new `kestrel-shim` crate (durable per-container stdio owner, survives daemon restarts), plus four small, real gap-fills in already-shipped Phase 8/earlier code that Phase 9 genuinely needs.

**Architecture:** `kestreld` never links `kestrel-runtime` — it `fork+exec`s `kestrel-shim`, which itself `fork+exec`s `kestrel-runtime create`. The shim outlives `kestreld`, owns the container's stdio pipe/PTY, writes a durable log file, and serves a Unix socket for live attach/resize/seccomp-events that a (possibly restarted) `kestreld` reconnects to. See `docs/superpowers/specs/2026-08-09-phase9-daemon-design.md` for full rationale — every task below cites the relevant design section.

**Tech Stack:** `tokio`, `axum` (HTTP/WS/SSE), `tower-http`, `serde`+`toml` (config), `nix` (PTY/socket/signal), existing `kestrel-*` crates called directly (async ones like `kestrel-net`/`kestrel-image` in-process; `kestrel-runtime` only ever as a subprocess).

**Revision note:** this plan was adversarially reviewed before implementation began. The review found one severe blocking defect (bridge-mode networking assumed a namespace-join-by-path mechanism that does not exist in `create()` — confirmed by reading `build_namespace_plan`'s own doc comment, which explicitly says joining an existing namespace at create-time "is a materially different feature... not solved here") plus a CLI-flag-ordering bug, a missing Cargo.toml dependency, and an unresolved registry-recovery placeholder. All are fixed in this revision — see the new Task 4, and the explicit fixes called out in Tasks 2, 8, 13/14 ordering, and 16-17.

---

## Task 1: `kestrel-shim` — scaffolding, PTY/pipe allocation, spawn + status handshake

**Files:**
- Create: `crates/kestrel-shim/Cargo.toml`
- Create: `crates/kestrel-shim/src/main.rs`
- Create: `crates/kestrel-shim/src/io.rs`
- Modify: root `Cargo.toml` (add `"crates/kestrel-shim"` to `[workspace] members`)

- [ ] **Step 1: Cargo.toml**

```toml
[package]
name = "kestrel-shim"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
serde.workspace = true
serde_json.workspace = true
nix = { workspace = true, features = ["process", "signal", "term", "fs"] }
libc.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros", "process", "net", "io-util", "signal", "fs", "sync"] }
clap = { version = "4", features = ["derive"] }
```

Run `cargo add --dry-run` for anything not already resolved elsewhere in the workspace before trusting these versions verbatim — same discipline as every prior phase's Task 1. `nix`'s `"term"` feature gates `openpty`/`Winsize` — confirm this against the real, currently-vendored `nix` 0.29 docs (`cargo doc -p nix --open` inside the VM, or check `~/.cargo/registry/src/*/nix-0.29.0/src/pty.rs`) before writing code that calls it.

- [ ] **Step 2: CLI args**

```rust
// crates/kestrel-shim/src/main.rs (top)
use std::path::PathBuf;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    id: String,
    #[arg(long)]
    run_dir: PathBuf,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    tty: bool,
    /// Everything after `--` is the command to run (kestrel-runtime create ...).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}
```

- [ ] **Step 3: PTY/pipe allocation (`io.rs`)**

```rust
// crates/kestrel-shim/src/io.rs
use std::os::fd::{AsRawFd, OwnedFd};
use anyhow::{Context, Result};

/// What the shim allocated for the container's stdio: either a PTY
/// (master kept, slave handed to the child) or two plain pipes
/// (stdout/stderr read ends kept, write ends handed to the child) plus
/// `/dev/null` for stdin (non-interactive default — see design doc §2
/// step 1).
pub enum ContainerIo {
    Pty {
        master: OwnedFd,
        slave: OwnedFd,
    },
    Pipes {
        stdout_read: OwnedFd,
        stdout_write: OwnedFd,
        stderr_read: OwnedFd,
        stderr_write: OwnedFd,
    },
}

pub fn allocate(tty: bool) -> Result<ContainerIo> {
    if tty {
        // nix::pty::openpty returns OpenptyResult { master: OwnedFd, slave: OwnedFd }.
        let result = nix::pty::openpty(None, None).context("openpty")?;
        Ok(ContainerIo::Pty { master: result.master, slave: result.slave })
    } else {
        let (stdout_read, stdout_write) = nix::unistd::pipe().context("stdout pipe")?;
        let (stderr_read, stderr_write) = nix::unistd::pipe().context("stderr pipe")?;
        Ok(ContainerIo::Pipes { stdout_read, stdout_write, stderr_read, stderr_write })
    }
}
```

Verify `nix::pty::openpty`'s real return type against the vendored source before trusting `OpenptyResult { master, slave }` verbatim — nix has changed this API's shape across versions historically; confirm for 0.29 specifically.

- [ ] **Step 4: Spawn + stdio wiring + status handshake (`main.rs`, async main)**

```rust
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let io = kestrel_shim::io::allocate(args.tty)?;

    let (child_stdin, child_stdout, child_stderr): (std::process::Stdio, std::process::Stdio, std::process::Stdio) = match &io {
        ContainerIo::Pty { slave, .. } => {
            let dup = |fd: &OwnedFd| -> std::process::Stdio {
                let raw = nix::unistd::dup(fd.as_raw_fd()).expect("dup pty slave");
                unsafe { std::process::Stdio::from_raw_fd(raw) }
            };
            (dup(slave), dup(slave), dup(slave))
        }
        ContainerIo::Pipes { stdout_write, stderr_write, .. } => {
            let devnull = std::fs::File::open("/dev/null")?;
            let dup = |fd: &OwnedFd| -> std::process::Stdio {
                let raw = nix::unistd::dup(fd.as_raw_fd()).expect("dup pipe write end");
                unsafe { std::process::Stdio::from_raw_fd(raw) }
            };
            (devnull.into(), dup(stdout_write), dup(stderr_write))
        }
    };

    let mut cmd = tokio::process::Command::new(&args.command[0]);
    cmd.args(&args.command[1..])
        .stdin(child_stdin)
        .stdout(child_stdout)
        .stderr(child_stderr);
    let status = cmd.status().await.context("spawning and waiting on kestrel-runtime create")?;

    // Report status as a single JSON line on THIS process's own stdout —
    // distinct from the container's captured stdio, which lives entirely
    // in `io` above (dup'd fds, never this process's fd 1). kestreld
    // reads exactly one line before treating the shim as handed off.
    if status.success() {
        println!("{{\"ok\":true}}");
    } else {
        println!("{{\"ok\":false,\"error\":\"kestrel-runtime create exited with {status}\"}}");
        std::process::exit(1);
    }

    // Task 2 continues here: daemonize, then run the log+attach.sock loop.
    kestrel_shim::daemon::run(args.id, args.run_dir, args.data_dir, io).await
}
```

Note the `Stdio::from_raw_fd` uses (`unsafe`) — this crate does NOT have `#![deny(clippy::undocumented_unsafe_blocks)]` the way `kestrel-init` does, but document each `unsafe` block's safety reasoning anyway (matching this whole project's established discipline) even without the lint forcing it.

**The exact `kestrel-runtime create` invocation `kestreld` passes as `args.command`** (relevant for Task 8's caller — confirmed via adversarial review that flag ordering matters): `kestrel-runtime --run-dir <run_dir> --data-dir <data_dir> create <id> --bundle <path>` — the global `--run-dir`/`--data-dir` flags MUST precede the `create` subcommand token (verified empirically against the real `clap` `Cli` struct in `crates/kestrel-runtime/src/cli.rs:18-26`: `cargo run -- create id --bundle x --run-dir y` fails to parse; `cargo run -- --run-dir y create id --bundle x` succeeds). The shim itself is agnostic to this — it just execs whatever `args.command` says — but every CALLER of the shim (Task 8) must get this order right.

- [ ] **Step 2: Run**

`cargo build -p kestrel-shim` inside the VM. Write a minimal test: spawn `kestrel-shim --id t1 --run-dir <tmp> --data-dir <tmp> --tty false -- /bin/echo hello`, capture the shim's own stdout, assert it's exactly `{"ok":true}\n`. (This test doesn't yet verify the container's OWN stdout — that's Task 2, once `daemon::run` exists; for now `daemon::run` can be a minimal stub that just returns `Ok(())` immediately after being called, so this task's own scaffolding is independently testable — Task 2 replaces the stub body for real.)

## Context

Task 1 of 23. Establishes the shim's process/IO scaffolding. Task 2 fills in `daemon::run`'s real body (log capture, attach.sock, daemonization).

## Your Job

1. Implement Cargo.toml, CLI parsing, PTY/pipe allocation, spawn+wiring, and the status handshake exactly as specified — verify the real `nix` 0.29 `openpty` signature first.
2. Add a minimal `daemon::run` stub (returns `Ok(())` immediately) so this task compiles and is independently testable.
3. Write and run the described test.
4. Do NOT commit/branch/push. Report back.

---

## Task 2: `kestrel-shim` — durable log writing, `attach.sock` framing, daemonization

**Files:**
- Create: `crates/kestrel-shim/src/daemon.rs`
- Create: `crates/kestrel-shim/src/framing.rs`
- Modify: `crates/kestrel-shim/src/main.rs` (wire `mod daemon; mod framing;`)
- Create: `crates/kestrel-shim/tests/shim_lifecycle.rs`

- [ ] **Step 1: Framing protocol (`framing.rs`)**

Per design doc §5 — 1-byte type tag + `u32` LE length + payload, both directions over `attach.sock`.

```rust
// crates/kestrel-shim/src/framing.rs
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_RESIZE: u8 = 0x02;
pub const TYPE_CLOSE: u8 = 0x03;
pub const TYPE_SECCOMP_EVENT: u8 = 0x04; // Task 16

pub enum Frame {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Close,
    SeccompEvent(Vec<u8>), // serde_json-encoded NotifyEvent, Task 16
}

pub async fn write_frame(w: &mut (impl tokio::io::AsyncWrite + Unpin), frame: &Frame) -> Result<()> {
    let (ty, payload): (u8, Vec<u8>) = match frame {
        Frame::Data(bytes) => (TYPE_DATA, bytes.clone()),
        Frame::Resize { rows, cols } => {
            let mut p = Vec::with_capacity(4);
            p.extend_from_slice(&rows.to_le_bytes());
            p.extend_from_slice(&cols.to_le_bytes());
            (TYPE_RESIZE, p)
        }
        Frame::Close => (TYPE_CLOSE, Vec::new()),
        Frame::SeccompEvent(bytes) => (TYPE_SECCOMP_EVENT, bytes.clone()),
    };
    w.write_u8(ty).await?;
    w.write_u32_le(payload.len() as u32).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Frame> {
    let ty = r.read_u8().await.context("reading frame type")?;
    let len = r.read_u32_le().await.context("reading frame length")? as usize;
    // Defensive cap — a container/attach client can't make the shim allocate
    // unboundedly on a corrupt/malicious length prefix.
    if len > 16 * 1024 * 1024 {
        bail!("frame length {len} exceeds 16MiB cap");
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.context("reading frame payload")?;
    match ty {
        TYPE_DATA => Ok(Frame::Data(payload)),
        TYPE_RESIZE => {
            if payload.len() != 4 {
                bail!("RESIZE frame must be 4 bytes, got {}", payload.len());
            }
            let rows = u16::from_le_bytes([payload[0], payload[1]]);
            let cols = u16::from_le_bytes([payload[2], payload[3]]);
            Ok(Frame::Resize { rows, cols })
        }
        TYPE_CLOSE => Ok(Frame::Close),
        TYPE_SECCOMP_EVENT => Ok(Frame::SeccompEvent(payload)),
        other => bail!("unknown frame type {other}"),
    }
}
```

- [ ] **Step 2: Daemonization + main loop (`daemon.rs`)**

```rust
// crates/kestrel-shim/src/daemon.rs
use std::path::PathBuf;
use anyhow::{Context, Result};
use tokio::net::UnixListener;

use crate::io::ContainerIo;

pub async fn run(id: String, run_dir: PathBuf, data_dir: PathBuf, io: ContainerIo) -> Result<()> {
    // Daemonize: detach from whatever controlling terminal/session kestreld's
    // own fork gave us, so a SIGHUP to kestreld's process group doesn't
    // propagate here. setsid() requires we are NOT already a process group
    // leader — true here since kestreld just fork+exec'd us directly (not
    // via a shell), so this process's pid is fresh.
    nix::unistd::setsid().context("setsid")?;

    let log_dir = data_dir.join("containers").join(&id);
    tokio::fs::create_dir_all(&log_dir).await.context("creating container log dir")?;
    let log_path = log_dir.join("output.jsonl");
    let log_file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
        .context("opening output.jsonl")?;

    let sock_dir = run_dir.join(&id);
    tokio::fs::create_dir_all(&sock_dir).await.context("creating run_dir/<id>")?;
    let attach_sock_path = sock_dir.join("attach.sock");
    let _ = tokio::fs::remove_file(&attach_sock_path).await; // stale socket from a crashed prior shim
    let attach_listener = UnixListener::bind(&attach_sock_path).context("binding attach.sock")?;

    // Broadcast every byte read from the container's stdio to every
    // currently-connected attach.sock client, AND to the log-writer below.
    let (tx, _rx) = tokio::sync::broadcast::channel::<Vec<u8>>(256);

    tokio::select! {
        result = read_and_log_loop(io_read_handles(&io), log_file, tx.clone()) => { result?; }
        _ = accept_loop(attach_listener, tx.clone(), pty_master_write_handle(&io)) => {}
    }

    let _ = tokio::fs::remove_file(&attach_sock_path).await;
    Ok(())
}
```

Real fd→async wiring (fill in `io_read_handles`/`pty_master_write_handle`, the pseudocode markers above): make each relevant fd non-blocking via `fcntl(F_SETFL, O_NONBLOCK)` right after `openpty`/`pipe()` in Task 1's `io::allocate` (add this there, not here — the fd needs to be non-blocking from the moment it's created), then wrap with `tokio::io::unix::AsyncFd::new(rawfd)`. For the `Pty` case, one read loop tags every chunk `"stdout"` (PTY merges stdout+stderr by construction). For the `Pipes` case, run TWO independent read loops (one per fd), each tagging output `"stdout"`/`"stderr"` respectively, both feeding the same `log_file`/`tx`.

**Real PTY behavior the read loop MUST handle** (confirmed during plan review as a genuine, easy-to-miss gap): a pipe read returns `Ok(0)` at EOF, but reading a PTY MASTER after every slave has closed classically returns `Err(EIO)`, not `Ok(0)`. The read loop must treat `Err(EIO)` on the PTY master identically to `Ok(0)` on a pipe — both mean "the container is gone, stop reading and finish up" — NOT as a real I/O error to propagate. Write this explicitly:

```rust
match master.read(&mut buf).await {
    Ok(0) => break, // pipes: clean EOF
    Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // PTY: last slave closed
    Err(e) => return Err(e).context("reading container stdio"),
    Ok(n) => { /* tag, log, broadcast buf[..n] */ }
}
```

- [ ] **Step 3: `accept_loop`** — for each `UnixListener::accept()`, spawn a task that: subscribes to `tx` (broadcast receiver) and forwards every byte-chunk as a `Frame::Data` write; concurrently reads frames from the socket — `Frame::Data` payloads get written to the PTY master (tty case only — for `Pipes`, there's no meaningful "write into the container's stdin" path per design doc §5, so just drop/ignore incoming `Data` frames on a non-tty attach connection, or reject the connection up front); `Frame::Resize` issues `TIOCSWINSZ` on the PTY master fd (tty only; ignore/log-and-ignore for non-tty); `Frame::Close` ends that connection's task. Multiple simultaneous attach connections are allowed (multiple `logs -f`/`attach` clients) — the `broadcast` channel already fans out correctly for this.

- [ ] **Step 4: Exit condition** — `read_and_log_loop` ends when the read hits the EOF/EIO condition from Step 2 (every writer closed its copy: the entrypoint exited AND `kestrel-init`, which held its own copy the whole time, exited too). On that, flush `log_file`, return from `run()`, triggering the `tokio::select!`'s cleanup (remove `attach.sock`) and process exit.

- [ ] **Step 5: Tests (`tests/shim_lifecycle.rs`, root-gated)**

1. `test_shim_captures_output_and_survives_kestreld_analog`: spawn `kestrel-shim ... -- /bin/sh -c 'echo one; sleep 1; echo two'` (no real `kestrel-runtime` needed for THIS test — the shim doesn't care what command it wraps), wait for it to exit (proving EOF-triggered exit works for the PIPES case), read `output.jsonl`, assert both lines present with correct `stream`/`msg` fields in order.
2. `test_pty_eof_via_eio_exits_cleanly`: spawn `kestrel-shim --tty true -- /bin/sh -c 'echo hi; exit 0'`, confirm the shim process itself exits cleanly (bounded time, exit code 0) — specifically exercises the PTY EIO-as-EOF path from Step 2, not just the pipes path test 1 already covers.
3. `test_attach_sock_relays_bytes_both_ways` (tty case): spawn `kestrel-shim --tty true -- /bin/cat`, connect to `attach.sock`, send `Frame::Data(b"hello\n")`, assert it comes back (cat echoes stdin to stdout, which is the same PTY, which the shim relays back over the socket) — proves the full loop: WS-side write → PTY master → PTY slave → cat's stdin → cat's stdout → PTY master → broadcast → socket.
4. `test_resize_issues_tiocswinsz`: attach, send `Frame::Resize{rows:40,cols:120}`, verify via `ioctl(master_fd, TIOCGWINSZ)` that the PTY's window size actually changed.

## Context

Task 2 of 23. Completes `kestrel-shim` — the durable stdio owner the rest of Phase 9's I/O design depends on. Read design doc §2 and §5 in full before starting; this is the highest-risk task in the phase (real PTY/fd/async plumbing, genuinely new to this codebase — no existing PTY code anywhere to copy from, confirmed during design grounding). The PTY EIO-vs-EOF distinction in Step 2 is real and was specifically caught by adversarial plan review — do not skip test 2.

## Your Job

1. Implement the framing protocol exactly as specified — it's a small, complete contract, don't improvise a different shape.
2. Make the relevant fds non-blocking at allocation time (Task 1's `io::allocate`) and wire the real `AsyncFd` read loop(s), handling EIO-as-EOF for the PTY case explicitly.
3. Implement daemonization, the accept loop, and the exit condition.
4. Write and pass all 4 described tests, root-gated.
5. Self-review: what happens if a client attaches AFTER the container has already exited (shim already mid-EOF-cleanup, or already gone)? Confirm the `bind`/`connect` failure path is a clean, understandable error, not a hang.
6. Do NOT commit/branch/push. Report back in detail — this task is expected to surface real design gaps in the sketch above; document what you had to change and why.

---

## Task 3: Gap-fill — `kestrel-runtime create.rs` pre-existing-layer-chain fast path

**Files:**
- Modify: `crates/kestrel-runtime/src/create.rs`
- Modify/Create: a new root-gated test proving the fast path (add to `crates/kestrel-runtime/tests/create_pins_namespaces.rs` or a new `tests/create_from_layers.rs` — check which is the better fit once you've read both)

- [ ] **Step 1: Implement**

Real gap confirmed during design grounding: `stage_bundle_rootfs_as_synthetic_layer` (`crates/kestrel-runtime/src/create.rs:225-256`) unconditionally treats a bundle's `root.path()` as ONE new synthetic layer via a full recursive copy. Add a fast path checked FIRST:

```rust
const LOWER_CHAIN_IDS_ANNOTATION: &str = "kestrel.lowerChainIds";

fn stage_bundle_rootfs_as_synthetic_layer(
    id: &str,
    bundle: &Bundle,
    data_dir: &Path,
) -> Result<MountPlan> {
    if let Some(annotations) = bundle.spec.spec.annotations() {
        if let Some(csv) = annotations.get(LOWER_CHAIN_IDS_ANNOTATION) {
            let lower_chain_ids: Vec<String> = csv.split(',').map(str::to_string).collect();
            anyhow::ensure!(!lower_chain_ids.is_empty(), "{LOWER_CHAIN_IDS_ANNOTATION} annotation is present but empty");
            return Ok(MountPlan { lower_chain_ids, rootless: false });
        }
    }

    // ... existing synthetic-single-layer logic, unchanged, as the fallback.
}
```

Verified during adversarial review: `bundle.spec.spec.annotations()`'s real return type is `&Option<HashMap<String, String>>` (confirmed against vendored `oci-spec-0.10.0/src/runtime/mod.rs:135`, `#[getset(get="pub")]` at line 56) and survives `bundle::load` unfiltered (`RawSpec`'s `#[serde(flatten)] spec: Spec` at `raw.rs:21-23`). Write the real code against this confirmed shape.

Decide (and document in a comment) whether `rootless` should also be annotation-driven eventually — for THIS task, hardcoding `false` matches the existing synthetic-layer branch's own behavior, so no regression either way; leave a clear comment noting `kestreld` doesn't yet have a rootless story (out of scope per design doc §14) so this is deliberately not wired further.

- [ ] **Step 2: Test**

Root-gated: build a `LayerStore` + `ensure_layer` a couple of real layers directly (reusing whatever test helper pattern `kestrel-rootfs`'s own tests use), get their chain-ids, write a bundle `config.json` with the `kestrel.lowerChainIds` annotation set to those chain-ids (comma-joined) instead of a `rootfs/` directory existing at all (prove the fast path genuinely skips the copy — assert no `bundle_dir/rootfs` is ever read), call the real `create()`, confirm it succeeds and the resulting overlay's merged view contains files from BOTH layers (proving the multi-entry chain-id list actually mounted correctly, not just that `create()` didn't error).

- [ ] **Step 3: Run**

`cargo build -p kestrel-runtime`, then the new test root-gated (`sudo -E cargo test -p kestrel-runtime --test <file> -- --ignored --test-threads=1`, timeout-wrapped per this project's established operational rule). Also re-run the FULL existing `kestrel-runtime` root-gated suite to confirm the fallback path (no annotation) is completely unaffected — every Phase 8 test must still pass unchanged.

## Context

Task 3 of 23. This is the mechanism that makes Phase 6's content-addressed layer store actually pay off at container-creation time for `kestreld`-created containers — without it, every `kestreld` `POST /containers` would pay a full rootfs copy, defeating the whole point of layer dedup. See design doc §4b.

## Your Job

1. Implement the annotation-checked fast path exactly as specified.
2. Write and pass the new test.
3. Re-run the full existing `kestrel-runtime` root-gated suite — zero regressions expected.
4. Do NOT commit/branch/push. Report back.

---

## Task 4: Gap-fill — namespace-join-by-path support (`kestrel-ns` + `kestrel-runtime`)

**This task did not exist in the original plan draft — added after adversarial review found the original design's bridge-mode networking scheme was structurally broken.** `build_namespace_plan` (`crates/kestrel-runtime/src/create.rs:305-332`) already skips any `LinuxNamespace` with a `path()` set from the "create fresh" list — but nothing compensates by actually JOINING that path. Its own doc comment (`create.rs:297-303`) is explicit: *"this is create's OWN namespace plan, describing namespaces THIS container creates fresh, not namespaces it joins... joining an existing namespace at create-time is a materially different feature from what this function builds, not solved here."* Without this task, writing a pinned netns path into a bundle's `config.json` (as Task 8's bridge-mode step and Task 17 both need to do) would cause that namespace type to simply be omitted from what `create()` unshares, with NO compensating join — the container's PID 1 would silently stay in the host's network namespace. This task builds the real mechanism.

**Files:**
- Modify: `crates/kestrel-ns/src/types.rs` (`NamespacePlan` gains a `join` field)
- Modify: `crates/kestrel-ns/src/stages.rs` (`stage1` performs the joins)
- Modify: `crates/kestrel-runtime/src/create.rs` (`build_namespace_plan` routes `path`-set namespaces into `plan.join` instead of silently dropping them)
- Modify: `crates/kestrel-ns/tests/dance.rs` or a new test file (real, root-gated proof)

- [ ] **Step 1: Extend `NamespacePlan`**

```rust
// crates/kestrel-ns/src/types.rs
pub struct NamespacePlan {
    pub create: Vec<NsType>,
    pub join: Vec<(NsType, std::path::PathBuf)>, // NEW
    pub uid_maps: Vec<IdMapping>,
    pub gid_maps: Vec<IdMapping>,
}
```

Update every existing `NamespacePlan` construction site across the workspace (`grep -rn "NamespacePlan {" crates/`) to add `join: Vec::new()` (or the real default derive if `NamespacePlan` already derives `Default` — check first) — this is a breaking struct-literal change, find every call site rather than assuming.

- [ ] **Step 2: `stage1` performs the joins — BEFORE any `unshare()`**

Real ordering analysis (do not deviate without re-verifying against the kernel semantics this depends on): `setns()` into a namespace owned by the HOST's original user namespace requires capabilities in that owning user namespace. If `stage1` unshares a NEW user namespace first (as it already does when `plan.has_user_ns()`), the calling process's capabilities become relative to that new, unprivileged-from-the-host's-perspective namespace, and a subsequent `setns()` into a host-owned namespace (like the netns `kestrel-net::create_netns` pinned, which was created by a plain host-level helper process, not inside any container's fresh user namespace) would very likely fail with `EPERM`. The fix: perform every `plan.join` `setns()` call as `stage1`'s ABSOLUTE FIRST action, before the existing `if plan.has_user_ns()` block — at that point the calling process still holds whatever privileges it started `run_stages` with (real root, per this project's rootful-only current scope), matching the same "join needs privilege in the target's owning userns" principle `kestrel_ns::join::join_namespaces`'s own `JOIN_ORDER` doc comment already establishes for a DIFFERENT call path (`kestrel exec`) — this task applies the identical principle to the CREATE-time path for the first time.

```rust
// crates/kestrel-ns/src/stages.rs, stage1, as the very first statement:
fn stage1(
    sock: &UnixDatagram,
    flags: CloneFlags,
    plan: &NamespacePlan,
    cgroup_fd: Option<RawFd>,
    child_action: impl FnOnce() + 'static,
) -> Result<()> {
    for (ns_type, path) in &plan.join {
        let f = std::fs::File::open(path)
            .with_context(|| format!("opening namespace join target {}", path.display()))?;
        nix::sched::setns(&f, ns_type.clone_flag())
            .with_context(|| format!("setns into pre-existing {ns_type:?} namespace at {}", path.display()))?;
    }

    // ... existing has_user_ns() block, unchanged, follows.
```

- [ ] **Step 3: `build_namespace_plan` routes path-set namespaces into `join`**

```rust
// crates/kestrel-runtime/src/create.rs — inside the existing loop over `linux.namespaces()`
for ns in namespaces {
    if let Some(path) = ns.path() {
        join.push((map_ns_type(ns.typ()), PathBuf::from(path)));
        continue;
    }
    create.push(map_ns_type(ns.typ()));
}
```

(Replacing the existing `if ns.path().is_some() { continue; }` bare skip at `create.rs:313-315` with real routing.) Update `NamespacePlan { create, join, uid_maps, gid_maps }`'s construction at the end of `build_namespace_plan` accordingly.

- [ ] **Step 4: Test** — root-gated, proves the actual property this task exists for: use `kestrel_ns::stages::run_stages` directly (not through `kestrel-runtime create`'s CLI — that's Task 8's job to prove end-to-end) with a plan whose `create` list unshares a fresh UTS namespace as normal, but whose `join` list points at a namespace pinned by a SEPARATE, already-running helper process (spin one up in the test the same way `kestrel-ns/tests/pin.rs` or `join.rs` already do) — confirm the resulting `init_pid`'s namespace (via `/proc/<init_pid>/ns/<type>`, compared by inode) matches the pre-existing pinned one, NOT a freshly-unshared one. Use `NsType::Uts` for this proof (simpler to set up a distinguishable "pre-existing" UTS namespace via a different hostname than a real netns would be) — the mechanism is namespace-type-agnostic, so proving it once generically is sufficient; Task 17's own end-to-end test is where the REAL network-namespace case gets exercised.

- [ ] **Step 5: Run** — `cargo build -p kestrel-ns -p kestrel-runtime`, the new test root-gated, and the FULL existing `kestrel-ns`/`kestrel-runtime` root-gated suites to confirm zero regressions (every existing `NamespacePlan` construction site must still compile and behave identically now that `join` defaults to empty).

## Context

Task 4 of 23. Blocks Task 8 (bridge-mode's `path`-injection step) and Task 17 (network attachment) — do not attempt either before this lands. This is genuinely new, subtle namespace/privilege-ordering work in already-shipped Phase 2/8 code — treat it with the same rigor this project has applied to every other cross-phase gap-fill (verify the privilege-ordering reasoning empirically, don't just trust the analysis above blindly; if `setns` into a host-owned namespace from stage1's very first line behaves differently than reasoned here, that's a real, reportable finding, not a sign to silently work around it).

## Your Job

1. Read `crates/kestrel-ns/src/stages.rs`, `types.rs`, `crates/kestrel-ns/src/join.rs` (for the `JOIN_ORDER`/privilege-ordering precedent), and `crates/kestrel-runtime/src/create.rs`'s `build_namespace_plan` in full before writing anything.
2. Implement Steps 1-3 exactly as specified, updating every existing `NamespacePlan` construction site.
3. Empirically verify the join-before-any-unshare ordering actually works (real root-gated test, Step 4) — do not assume the reasoning above is correct without proof.
4. Confirm zero regressions in the full existing `kestrel-ns`/`kestrel-runtime` root-gated suites.
5. Do NOT commit/branch/push. Report back in detail, including explicit confirmation (or correction) of the privilege-ordering reasoning above.

---

## Task 5: Gap-fill — `kestrel-cgroup` `io_stat` reader

**Files:**
- Modify: `crates/kestrel-cgroup/src/stats.rs`

- [ ] **Step 1: Implement**

`io.stat`'s real format is per-device, not `cpu.stat`'s flat single-key-per-line shape: `<major>:<minor> rbytes=N wbytes=N rios=N wios=N dbytes=N dios=N` (one line per device with I/O activity). Confirmed via design grounding and adversarial review: zero existing `io_stat`/`io.stat` code anywhere in this crate; `resources.rs::apply_io` is write-only.

```rust
// crates/kestrel-cgroup/src/stats.rs — add alongside cpu_stat/memory_current/pids_current

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IoDeviceStat {
    pub major: u32,
    pub minor: u32,
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub dbytes: u64,
    pub dios: u64,
}

impl CgroupManager {
    pub fn io_stat(&self) -> Result<Vec<IoDeviceStat>> {
        let contents = fs::read_to_string(self.path.join("io.stat"))
            .with_context(|| format!("reading io.stat at {}", self.path.display()))?;
        Ok(parse_io_stat(&contents))
    }
}

fn parse_io_stat(contents: &str) -> Vec<IoDeviceStat> {
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let dev = parts.next()?;
            let (major_str, minor_str) = dev.split_once(':')?;
            let mut stat = IoDeviceStat {
                major: major_str.parse().ok()?,
                minor: minor_str.parse().ok()?,
                ..Default::default()
            };
            for kv in parts {
                let Some((key, value)) = kv.split_once('=') else {
                    tracing::warn!(kv, "io.stat: malformed key=value pair, skipping");
                    continue;
                };
                let Ok(value) = value.parse::<u64>() else {
                    tracing::warn!(key, value, "io.stat: non-numeric value, skipping");
                    continue;
                };
                match key {
                    "rbytes" => stat.rbytes = value,
                    "wbytes" => stat.wbytes = value,
                    "rios" => stat.rios = value,
                    "wios" => stat.wios = value,
                    "dbytes" => stat.dbytes = value,
                    "dios" => stat.dios = value,
                    other => tracing::warn!(key = other, "io.stat: unrecognized field, skipping"),
                }
            }
            Some(stat)
        })
        .collect()
}
```

This follows `parse_cpu_stat`'s established tolerant-parse philosophy (skip malformed fields with a warning rather than aborting the whole read) but is a genuinely different parser shape (per-device, multiple lines).

- [ ] **Step 2: Tests**

Unit test `parse_io_stat` directly against real sample `io.stat` content (a 2-device example, plus one malformed-field-tolerance case), matching this file's existing unit-test conventions for `parse_cpu_stat`. Root-gated integration test: create a real cgroup, run some I/O inside it (e.g. `dd` a small file), call `io_stat()`, assert at least one device shows nonzero `wbytes`.

- [ ] **Step 3: Run**

`cargo test -p kestrel-cgroup --lib` (unit tests) and the new root-gated integration test.

## Context

Task 5 of 23. Closes the one real gap in `kestrel-cgroup`'s stats surface that Phase 9's metrics sampler (Task 13) and `/containers/:id/cgroup` introspection endpoint (Task 18) both need. See design doc §6.

## Your Job

1. Implement `io_stat`/`parse_io_stat` exactly as specified.
2. Write and pass both the unit and integration tests.
3. Do NOT commit/branch/push. Report back.

---

## Task 6: `kestreld` — Cargo.toml, config parsing, dual-listener `main.rs` skeleton

**Files:**
- Modify: `crates/kestreld/Cargo.toml`
- Create: `crates/kestreld/src/lib.rs`
- Create: `crates/kestreld/src/config.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: Cargo.toml**

```toml
[package]
name = "kestreld"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
serde.workspace = true
serde_json.workspace = true
toml = "0.8"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "process", "net", "fs", "io-util", "signal", "sync", "time"] }
axum = { version = "0.7", features = ["ws"] }
tower-http = { version = "0.5", features = ["trace", "cors"] }
nix = { workspace = true, features = ["process", "signal", "fs"] }
libc.workspace = true
kestrel-oci = { path = "../kestrel-oci" }
```

Confirm real, currently-resolvable versions via `cargo add --dry-run` inside the VM. `axum = "0.7"`'s support for serving directly over a bound `UnixListener` via `axum::serve` is confirmed real (axum's own repo has a `#[cfg(unix)]` compile-test for exactly this) — Step 3 below can be implemented directly, no fallback plumbing needed.

- [ ] **Step 2: `config.rs`** — mirror SPEC.md §17's exact TOML shape with `#[derive(Deserialize)]` structs (`DaemonConfig`, `StorageConfig`, `CgroupConfig`, `NetworkConfig`, `SecurityConfig`, `RootlessConfig`), a `Config::load(path: &Path) -> Result<Config>` that parses real TOML, and `Config::default()` matching every default value SPEC.md §17 lists verbatim (`socket = "/run/kestrel.sock"`, `http_addr = "127.0.0.1:7777"`, etc.). Also add `DaemonConfig::stop_grace_period_s: u64` (default `10`) — a new field beyond SPEC.md §17's literal text, needed by Task 9's `stop` sequencing; document why it's added. Write a unit test parsing SPEC.md §17's exact example TOML block and asserting every field round-trips.

- [ ] **Step 3: `main.rs` skeleton** — parse config (default path `/etc/kestrel/config.toml`, overridable via `--config`), build an `axum::Router` (empty for now — later tasks add routes via `.merge()`/`.route()`), bind BOTH listeners concurrently:

```rust
let unix_listener = tokio::net::UnixListener::bind(&config.daemon.socket)?;
let tcp_listener = tokio::net::TcpListener::bind(&config.daemon.http_addr).await?;

tokio::try_join!(
    axum::serve(unix_listener, router.clone().into_make_service()).into_future(),
    axum::serve(tcp_listener, router.into_make_service()).into_future(),
)?;
```

## Context

Task 6 of 23. The skeleton every later `kestreld` task adds routes/background tasks onto. No container logic yet.

## Your Job

1. Implement Cargo.toml (verify real versions), `config.rs` (verify it against SPEC.md §17 exactly, plus the new `stop_grace_period_s` field), and the dual-listener `main.rs`.
2. Confirm `cargo build -p kestreld` and `cargo run -p kestreld -- --config <tmp-config>` both work (binds both listeners, serves an empty router, doesn't crash).
3. Do NOT commit/branch/push. Report back.

---

## Task 7: `kestreld` — container registry, state recovery, startup leak sweep

**Files:**
- Create: `crates/kestreld/src/registry.rs`
- Create: `crates/kestreld/src/leak_sweep.rs`
- Modify: `crates/kestreld/src/main.rs`
- Modify: `crates/kestreld/Cargo.toml` (add `kestrel-cgroup`, `kestrel-ns` — for leak-sweep's cgroup/namespace-pin cleanup; do NOT add `kestrel-runtime` as a library dependency, per Rule #2/design doc §1)

- [ ] **Step 1: `ContainerHandle` + registry (`registry.rs`)**

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use kestrel_oci::state::State;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ContainerMeta {
    pub tty: bool,
    // Task 17 adds `network: Option<crate::network::NetworkInfo>` here later —
    // this struct is the SAME persisted file both this task's recovery path
    // and Task 17's network-attachment path read/write, not two separate
    // mechanisms. Adding a field here is additive (`#[serde(default)]` on
    // new fields) so this task's own reader/writer never needs to change
    // shape again later, only grow.
}

#[derive(Clone)]
pub struct ContainerHandle {
    pub id: String,
    pub bundle_path: PathBuf,
    pub meta: ContainerMeta,
}

pub type Registry = Arc<RwLock<HashMap<String, ContainerHandle>>>;

pub fn meta_path(data_dir: &std::path::Path, id: &str) -> PathBuf {
    data_dir.join("containers").join(id).join("meta.json")
}

pub async fn read_meta(data_dir: &std::path::Path, id: &str) -> ContainerMeta {
    // Missing/corrupt meta.json is non-fatal — a container created by a
    // pre-Task-7 kestreld binary, or one whose meta write raced a crash,
    // still gets a real (if defaulted) registry entry rather than being
    // dropped from recovery entirely.
    let path = meta_path(data_dir, id);
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => ContainerMeta::default(),
    }
}

/// Always re-reads state.json rather than trusting any cached copy — see
/// design doc §3's note on why kestreld doesn't cache State itself.
pub async fn read_state(run_dir: &std::path::Path, id: &str) -> anyhow::Result<State> {
    let path = run_dir.join(id).join("state.json");
    tokio::task::spawn_blocking(move || State::read(&path)).await?
}
```

(`ContainerMeta` needs `#[derive(Default)]` too — add it, with `tty: false` as the sensible default.) Task 8's `POST /containers` handler is responsible for WRITING `meta.json` at create time (real `tty` value, not a placeholder) — this task's job is only the type + reader; confirm Task 8's own steps include the writer before considering this task's contract satisfied.

- [ ] **Step 2: State recovery (in `main.rs`, called at startup before serving)**

```rust
async fn recover_registry(run_dir: &Path, data_dir: &Path) -> Result<Registry> {
    let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
    let mut entries = tokio::fs::read_dir(run_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let id = entry.file_name().to_string_lossy().into_owned();
        let state_path = entry.path().join("state.json");
        if !state_path.exists() {
            continue; // not a container dir (e.g. `netns/`) — leak_sweep handles genuine orphans
        }
        let Ok(state) = kestrel_oci::state::State::read(&state_path) else { continue };
        if state.status == kestrel_oci::state::Status::Stopped {
            continue; // no live shim to reconnect to, nothing to recover
        }
        let attach_sock = run_dir.join(&id).join("attach.sock");
        let shim_alive = tokio::net::UnixStream::connect(&attach_sock).await.is_ok();
        let meta = read_meta(data_dir, &id).await; // real tty/network metadata, not a placeholder
        tracing::info!(id, shim_alive, status = ?state.status, tty = meta.tty, "recovered container from state.json");
        registry.write().await.insert(id.clone(), ContainerHandle {
            id,
            bundle_path: state.bundle,
            meta,
        });
    }
    Ok(registry)
}
```

This closes the recovery gap adversarial review flagged in the original draft — `meta.json` (real, persisted at create time by Task 8) is read back here directly, not left as a `false`/`None` placeholder.

- [ ] **Step 3: Leak sweep (`leak_sweep.rs`)**

For each `<data_dir>/cgroups/kestrel/*` directory with no matching registry entry: attempt `CgroupManager::new(...).destroy()`, log success/failure, don't fail startup on individual cleanup errors. Same pattern for `<run_dir>/netns/*` pins with no matching entry (`kestrel_net::netns::teardown_netns` — this DOES pull in a `kestrel-net` dependency for `kestreld`, separate from the leak-sweep-only `kestrel-cgroup`/`kestrel-ns` deps this task's Cargo.toml step adds; note this now so Task 8/17 don't redundantly re-discover the need) and `<run_dir>/<id>/ns/*` pins under container dirs that no longer have a `state.json` (orphaned namespace pins — use `kestrel_ns::pin::unpin_namespace` directly).

- [ ] **Step 4: Wire into `main.rs`** — call `recover_registry` then `leak_sweep::run` before binding listeners; log a summary (`N containers recovered, M leaked resources cleaned`).

- [ ] **Step 5: Tests** — root-gated: create a real container via `kestrel_runtime::create::create` directly in the test (reusing this project's established test-fixture patterns from `kestrel-runtime`'s own tests) plus a real `meta.json` written alongside it (matching Task 8's future writer's exact shape), simulate a "previous kestreld crash" by NOT cleaning it up, run `recover_registry`, assert it's found AND `meta.tty` round-trips correctly (not defaulted); separately, leave an orphaned cgroup dir with no `state.json` behind, run `leak_sweep::run`, assert it's gone afterward.

## Context

Task 7 of 23. CHECKLIST's two 🔴 "state recovery" and "leak sweep on startup" items. Depends on Task 6's skeleton. Task 8 must write `meta.json` for this task's recovery path to have real data to read — treat that as a hard contract between the two tasks, not an optional nicety.

## Your Job

1. Implement `registry.rs` and `leak_sweep.rs` exactly as specified, including the `meta.json` read-back that closes the original plan's recovery-placeholder gap.
2. Wire both into `main.rs`'s startup sequence.
3. Write and pass both described tests, root-gated.
4. Do NOT commit/branch/push. Report back.

---

## Task 8: `kestreld` — bundle materialization + `POST /containers`

**Files:**
- Create: `crates/kestreld/src/bundle.rs`
- Create: `crates/kestreld/src/api/containers.rs`
- Create: `crates/kestreld/src/api/mod.rs`
- Modify: `crates/kestreld/src/main.rs`
- Modify: `crates/kestreld/Cargo.toml` (add `kestrel-image`, `kestrel-net` — needed for the bridge-mode `create_netns` call this task makes, per Task 4's now-real join mechanism — and `uuid` or similar for id generation)

- [ ] **Step 1: Request/response shapes**

```rust
// crates/kestreld/src/api/containers.rs
#[derive(serde::Deserialize)]
pub struct CreateContainerRequest {
    pub image: Option<String>,       // e.g. "docker.io/library/alpine:latest" — pulled if not already present
    pub bundle_rootfs: Option<PathBuf>, // alternative: a plain, already-extracted rootfs dir (Task 3's fallback path)
    pub name: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub tty: bool,
    #[serde(default)]
    pub memory_bytes: Option<i64>,
    #[serde(default)]
    pub pids_limit: Option<i64>,
    pub network_mode: Option<String>, // "bridge" | "host" | "none" | "container:<id>"
}

#[derive(serde::Serialize)]
pub struct CreateContainerResponse {
    pub id: String,
}
```

- [ ] **Step 2: Bundle materialization (`bundle.rs`)**

Given a `CreateContainerRequest`: resolve `image` (pull via `kestrel_image::pull::pull_image_with_client` if not already in the content store — Task 20 wires real progress reporting; for THIS task, a blocking pull with progress discarded is fine, refined later) OR use `bundle_rootfs` directly; build a real `config.json` via `kestrel_oci::default_spec::default_spec()` + overrides (cmd/env/tty/resources), set the `kestrel.lowerChainIds` annotation (Task 3) when using an image, write it to a fresh bundle dir at `<data_dir>/bundles/<id>/config.json` (a plain `rootfs/` dir only needed for the `bundle_rootfs` fallback case, per Task 3's fast path skipping it entirely for the image case).

**Bridge-mode network namespace creation, using Task 4's real join mechanism** (design doc §4a, now structurally sound): when `network_mode == "bridge"`, call `kestrel_net::netns::create_netns(run_dir, id)` HERE, before writing `config.json`, and set the resulting pin path as the `Network` namespace's `path` in the spec's `linux.namespaces` list — `build_namespace_plan` (Task 4, Step 3) now correctly routes this into `NamespacePlan.join` rather than silently dropping it, and `stages.rs::stage1` (Task 4, Step 2) genuinely joins it before `create()`'s process does anything else. Host-mode and `none` networking skip this entirely (no `Network` namespace path set — `none` mode still gets a fresh, empty netns via the normal "create" path since it's not omitted from the spec's namespace list, only lacks a `path`; host mode omits the `Network` namespace from the list altogether, matching existing `LinuxNamespaceType` semantics already used elsewhere in this codebase — confirm this against real `default_spec()`/namespace-list conventions before assuming). `container:<id>` mode reuses another container's already-pinned netns path directly via `kestrel_net::modes::resolve_container_mode`, no new `create_netns` call.

Also write `<data_dir>/containers/<id>/meta.json` (Task 7's `ContainerMeta`, real `tty` value) as part of this step — this is the writer half of Task 7's recovery contract.

- [ ] **Step 3: `POST /containers` handler** — generate an id (random, e.g. `uuid` crate or a shorter scheme matching this project's existing test-fixture id conventions — check what `kestrel-runtime`'s own tests use for id generation and stay consistent if there's a real precedent, otherwise pick a reasonable one and document it), materialize the bundle (Step 2), spawn `kestrel-shim --id <id> --run-dir <run_dir> --data-dir <data_dir> --tty <tty> -- kestrel-runtime --run-dir <run_dir> --data-dir <data_dir> create <id> --bundle <bundle_dir>` via `tokio::process::Command` — **note the flag order: `--run-dir`/`--data-dir` come BEFORE the `create` subcommand token**, confirmed against the real `clap` `Cli` struct during adversarial review (the original plan draft had this backwards) — read exactly one line from the shim's stdout (the status handshake, Task 1), parse the `{"ok":...}` JSON, register in the `Registry` on success, return `201 { "id": ... }` or a real error status on failure (including tearing down any `create_netns`-allocated netns on a failed create, so a failed `POST /containers` doesn't leak a pinned namespace).

- [ ] **Step 4: Tests** — root-gated: `POST /containers` with a plain `bundle_rootfs` pointing at a synthetic rootfs (reuse `kestrel-runtime`'s own `lifecycle_fixture`/`build_synthetic_rootfs` test infra if it's reachable from `kestreld`'s own test crate, or build an equivalent minimal one), assert `201` + a real id, assert `state.json` shows `Created`, assert `<run_dir>/<id>/attach.sock` is connectable (shim alive), assert `meta.json` was written with the correct `tty` value. Separately: `POST /containers` with `network_mode: "bridge"`, confirm (via Task 4's real join mechanism) the container's network namespace genuinely differs from the host's (`/proc/<pid>/ns/net` inode comparison) — this is the first real end-to-end proof that Task 4's gap-fill actually works through the full HTTP path, not just in isolation.

## Context

Task 8 of 23. The first real end-to-end path: HTTP request → shim → `kestrel-runtime create`. Depends on Task 1 (shim spawn contract), Task 3 (annotation fast path), Task 4 (namespace-join mechanism — hard dependency for the bridge-mode step), Task 6 (router skeleton), Task 7 (registry + `meta.json` contract).

## Your Job

1. Implement the request/response shapes, bundle materialization (including the corrected flag order and the real Task-4-backed netns join), and the handler exactly as specified.
2. Verify the shim-spawn + status-handshake contract matches Task 1's real implementation exactly (re-read it, don't assume).
3. Write `meta.json` for real, closing Task 7's recovery contract.
4. Write and pass both described tests, including the bridge-mode namespace-isolation proof.
5. Do NOT commit/branch/push. Report back.

---

## Task 9: `kestreld` — lifecycle endpoints (start/stop/kill/pause/unpause/delete) + list/inspect

**Files:**
- Create: `crates/kestreld/src/runtime_cli.rs` (thin subprocess-invocation helper shared by every lifecycle endpoint)
- Modify: `crates/kestreld/src/api/containers.rs`
- Modify: `crates/kestreld/src/main.rs` (register routes)

- [ ] **Step 1: `runtime_cli.rs`** — one small helper, reused by every endpoint below. Resolve the real `kestrel-runtime` binary the same way `kestrel_runtime::create::resolve_kestrel_init_path` resolves `kestrel-init` (sibling of `current_exe()`) — this is a real, established sibling-binary convention in this project's deployment layout, not a PATH lookup; the code below reflects that (a bare `Command::new("kestrel-runtime")` PATH-lookup sketch would contradict this and was flagged during adversarial review as inconsistent — don't write that version):

```rust
fn resolve_kestrel_runtime_path() -> anyhow::Result<PathBuf> {
    let current_exe = std::env::current_exe().context("resolving current_exe")?;
    let parent = current_exe.parent().context("current_exe has no parent dir")?;
    Ok(parent.join("kestrel-runtime"))
}

pub async fn run_kestrel_runtime(run_dir: &Path, data_dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let bin = resolve_kestrel_runtime_path()?;
    let status = tokio::process::Command::new(&bin)
        .arg("--run-dir").arg(run_dir)
        .arg("--data-dir").arg(data_dir)
        .args(args) // args is the SUBCOMMAND and its own flags, e.g. ["kill", id, signal]
        .status()
        .await?;
    anyhow::ensure!(status.success(), "kestrel-runtime {:?} failed: {status}", args);
    Ok(())
}
```

- [ ] **Step 2: Endpoints** — each is a thin `axum` handler calling `run_kestrel_runtime` with the right args:
  - `POST /containers/:id/start` → `["start", id]`
  - `POST /containers/:id/kill?signal=SIGTERM` → `["kill", id, signal]`
  - `POST /containers/:id/pause` → `["pause", id]`
  - `POST /containers/:id/unpause` → `["resume", id]`
  - `DELETE /containers/:id?force=true` → `["delete", id, "--force"]` (conditionally), then remove the registry entry + `<data_dir>/containers/<id>/` on success, plus (if `network_mode` was `bridge`) tear down the netns/veth/NAT — Task 17 owns the REAL teardown implementation; for THIS task, call a `crate::network::teardown(...)` stub that's a no-op if Task 17 hasn't landed yet in your dispatch order, and a real call once it has — coordinate with Task 17's actual signature once it exists rather than guessing it here.
  - `POST /containers/:id/stop` — NOT a direct passthrough: SIGTERM (`kill SIGTERM`), poll `state.json` every 200ms up to `config.daemon.stop_grace_period_s` (Task 6), then SIGKILL if still not `Stopped`

- [ ] **Step 3: List/inspect** — `GET /containers` (iterate the registry, `read_state` each, return an array), `GET /containers/:id` (single inspect: `State` + `ContainerHandle` fields merged into one response struct — namespaces/cgroup/network sub-objects are Task 18/17's job, this task's `GET /containers/:id` returns the base fields only, with those richer fields as `null`/omitted until later tasks fill them in for real).

- [ ] **Step 4: Tests** — root-gated end-to-end: create → start → poll for `Running` → stop → poll for `Stopped` with a real `exit_code`; separately, create → delete without starting (proves the force-kill-a-Created-container path Phase 8 already handles correctly propagates through here too); write a real test proving the `stop` grace-period path specifically (a container that ignores SIGTERM for longer than the grace period, confirming SIGKILL still happens), not just the happy path.

## Context

Task 9 of 23. The bulk of CHECKLIST's 🔴 lifecycle-endpoint items. Depends on Task 8 (a container must exist to operate on).

## Your Job

1. Implement `runtime_cli.rs` (using the sibling-binary resolution shown above, not a PATH lookup) and every endpoint listed.
2. Get `stop`'s SIGTERM→grace→SIGKILL sequencing right, with a real test for the grace-period path.
3. Do NOT commit/branch/push. Report back.

---

## Task 10: `kestreld` — exec endpoint + top endpoint

**Files:**
- Modify: `crates/kestreld/src/api/containers.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: `POST /containers/:id/exec`** — spawns `kestrel-runtime --run-dir <run_dir> --data-dir <data_dir> exec <id> -- <cmd>` directly (NOT via the shim — one-off, no durability requirement, per design doc §4; same corrected flag order as Task 8/9). If the request wants a TTY for this exec session, allocate a PTY here in `kestreld` itself (reuse `kestrel-shim`'s `io::allocate` logic — consider whether to extract it into a small shared internal crate/module vs. duplicating a ~15-line function; given its small size, duplicating with a clear comment referencing the shim's version is acceptable, but note the decision either way, and remember Task 2 moved the fd-non-blocking setup INTO `io::allocate` itself, so any duplicated copy needs that too) and bridge it over the SAME WS-attach mechanism as the entrypoint (a one-off, ungoverned-by-any-shim WS session that ends when the exec'd process exits — no `attach.sock` durability needed since there's no "reconnect after kestreld restart" requirement for a one-off exec).

- [ ] **Step 2: `GET /containers/:id/top`** — read `state.json` for the entrypoint's real host pid. **Note (corrected during adversarial review): `kestrel_runtime::start::resolve_entrypoint_host_pid` is a single-target, single-level lookup with retry/zombie-detection logic, NOT a general recursive tree walker, and it's a private function — this task needs genuinely NEW recursive code, following the SAME TECHNIQUE (walking `/proc/<pid>/task/*/children`) but generalized to walk the whole tree, not literally reused code.** Recursively walk `/proc/<pid>/task/*/children` starting from the entrypoint's host pid to enumerate every process in the container, and for each, read `/proc/<pid>/status`'s `NSpid` line to report both host and container-namespace pids (the LAST value in `NSpid`'s space-separated list is the pid as seen inside the deepest/innermost pid namespace — confirm this against the real `proc(5)` semantics before trusting it, and handle the case where `NSpid` has only one value, meaning the process isn't in a nested pid namespace at all — shouldn't happen for a real container process, but don't crash if it does).

- [ ] **Step 3: Tests** — root-gated: `exec` a simple command (e.g. `echo hi`) against a running container, confirm output round-trips over the WS bridge; `exec` with a nonzero exit code, confirm it's reported; `top` against a container running `lifecycle_fixture spawn-abandon N` (reusing Phase 8's own fixture), confirm multiple processes are listed with plausible host/container pid pairs.

## Context

Task 10 of 23. Depends on Task 9 (container must be running).

## Your Job

1. Implement both endpoints exactly as specified.
2. Write genuinely new recursive `/proc` tree-walking code for `top`, informed by (not copy-pasted from) `resolve_entrypoint_host_pid`'s technique.
3. Write and pass the described tests.
4. Do NOT commit/branch/push. Report back.

---

## Task 11: `kestreld` — logs endpoint (tail + SSE follow)

**Files:**
- Create: `crates/kestreld/src/api/logs.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: `GET /containers/:id/logs?follow&tail&since`** — parse `<data_dir>/containers/<id>/output.jsonl` line-by-line (each line already valid JSON per the shim's own write format, Task 2). `tail=N` returns only the last N lines (read the file, keep a bounded ring buffer while scanning — don't load unbounded files fully into memory for large logs; a simple approach: seek from the end in chunks, or just read fully if simplicity is preferred for now with a documented note that this isn't optimized for very large log files yet). `since=<rfc3339>` filters by the `ts` field. Without `follow`, return the filtered set as a single JSON array or newline-delimited response (pick one, document it — newline-delimited matches the underlying file format most directly). With `follow=true`, switch to SSE: after emitting the filtered historical set, watch the file for new appends (poll `fs::metadata` for size growth every ~200ms — matching this project's established poll-based-not-inotify convention seen elsewhere, e.g. `PsiWatcher`) and emit each new line as an SSE `data:` event as it's appended.

- [ ] **Step 2: Tests** — write some lines to a real `output.jsonl` (or exercise it via a real running container from Task 9), request without `follow`, confirm exact content/filtering; request WITH `follow=true`, then append more lines to the file mid-request (or let a real running container produce more output), confirm the SSE stream delivers them live within a bounded time.

## Context

Task 11 of 23. Depends on Task 2 (shim writes `output.jsonl`) and Task 6 (router).

## Your Job

1. Implement the endpoint exactly as specified, including all three query params.
2. Write and pass both described tests.
3. Do NOT commit/branch/push. Report back.

---

## Task 12: `kestreld` — attach WS endpoint + resize endpoint

**Files:**
- Create: `crates/kestreld/src/api/attach.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: `WS /containers/:id/attach`** — on WS upgrade, connect to `<run_dir>/<id>/attach.sock`, then run two concurrent loops (`tokio::select!` or two spawned tasks joined): (a) read frames from the Unix socket (Task 2's framing), forward `Frame::Data` payloads as WS binary messages; (b) read WS messages from the client, wrap each as `Frame::Data` and write to the Unix socket. End both loops cleanly when either side closes.

- [ ] **Step 2: `POST /containers/:id/resize`** — body `{"rows": u16, "cols": u16}`, connect to `attach.sock` (a fresh short-lived connection is fine — the shim's `accept_loop`, Task 2, already handles multiple concurrent connections), send `Frame::Resize`, close.

- [ ] **Step 3: Reject non-tty appropriately** — per design doc §5, non-tty containers' attach connections should still deliver output (read-direction) but reject incoming data/resize with a clear error (checked via the registry's `ContainerHandle.meta.tty` field, not by asking the shim) — a `409` for `POST /resize` on a non-tty container, and either silently drop or explicitly error incoming WS binary frames for a non-tty attach (pick one, document it — an explicit WS close-with-reason is more honest than silent dropping).

- [ ] **Step 4: Tests** — root-gated: create a tty container running `lifecycle_fixture` in some interactive-friendly mode (check whether the fixture needs a new argv branch for this, e.g. an "echo stdin back" mode useful for testing attach — if the existing `lifecycle_fixture` doesn't have anything suitable, add a small, additive argv mode, matching that file's established doc-comment convention), attach over WS, send bytes, confirm they echo back; resize, confirm no error; attach to a non-tty container, confirm resize 409s.

## Context

Task 12 of 23. Depends on Task 2 (shim's `attach.sock` protocol) and Task 8 (container exists). This is where the shim's design pays off — should be a fairly direct bridge, not much new logic.

## Your Job

1. Implement both endpoints exactly as specified.
2. Determine whether `lifecycle_fixture` needs a new argv mode for a meaningful attach test, and add one if so.
3. Write and pass the described tests.
4. Do NOT commit/branch/push. Report back.

---

## Task 13: `kestreld` — metrics sampler (1Hz), status-transition detection, OOM watcher

**Files:**
- Create: `crates/kestreld/src/metrics.rs`
- Modify: `crates/kestreld/src/main.rs`

**Reordered ahead of the event-bus task (adversarial review found the original draft had Task 12/event-bus depending on THIS task's poller while being sequenced before it, risking duplicate events — this task now owns the ONE status-transition poller outright, and the event-bus task, next, simply consumes what this task publishes).**

- [ ] **Step 1: Implement** — a `tokio::spawn`ed loop, `tokio::time::interval(config.daemon.metrics_interval_ms)`: for each `Running` registry entry, read `CgroupManager::cpu_stat`, `memory_current`, `pids_current`, `pressure(Cpu|Memory|Io)` × 3, `io_stat` (Task 5). This same tick owns the ONE status-transition poller the whole daemon uses: re-read `state.json`, compare against the last-seen status per container (a `HashMap<String, kestrel_oci::state::Status>` the sampler task owns), and — via a channel/callback the NEXT task (event bus) provides — signal any transition that occurred (this task doesn't need to know about `Event`/the broadcast channel's real type yet; expose a `tokio::sync::mpsc::Sender<(String, StatusTransition)>` or similar this task sends into, that Task 14 is the one thing that actually turns into real `Event`s — keep this task's own code decoupled from the event enum's shape).

Also fold in the OOM watcher here (small, same tick): `oom_kill_count()` per container, diff against last-seen, signal an OOM occurrence through the same channel — CHECKLIST's OOM item doesn't need its own separate interval/task.

Detect PSI-threshold crossings (compare against `config.cgroup.psi_trigger_stall_us`/`psi_trigger_window_us`) and throttle increases (`cpu_stat().nr_throttled` increasing) — signal both through the same channel.

- [ ] **Step 2: Tests** — root-gated: run a container under a tight `memory.max`, confirm a PSI-threshold signal fires within a reasonable window; run one that gets killed externally (not via `stop`), confirm a status-transition signal fires; a container whose entrypoint gets OOM-killed under a tight `memory.max` (check whether `lifecycle_fixture` needs a new "allocate and hold N MiB" argv mode, add one if so), confirm an OOM signal fires.

## Context

Task 13 of 23. Depends on Task 5 (`io_stat`). Deliberately positioned BEFORE Task 14 (event bus) this time — Task 14 is the ONLY thing that turns this task's raw signals into published `Event`s, closing the duplicate-event risk the original draft had.

## Your Job

1. Implement the sampler/poller loop exactly as specified, decoupled from any concrete `Event` type (a generic signal channel Task 14 consumes).
2. Fold in OOM watching and PSI/throttle threshold detection into the same tick — do not build separate intervals for these.
3. Write and pass all 3 described tests.
4. Do NOT commit/branch/push. Report back.

---

## Task 14: `kestreld` — event bus + `GET /events` SSE

**Files:**
- Create: `crates/kestreld/src/events.rs`
- Modify: `crates/kestreld/src/main.rs`
- Modify: every earlier lifecycle-endpoint handler (Task 9) to publish the relevant event

- [ ] **Step 1: `events.rs`**

```rust
#[derive(Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "container.create")] ContainerCreate { id: String },
    #[serde(rename = "container.start")] ContainerStart { id: String },
    #[serde(rename = "container.die")] ContainerDie { id: String, exit_code: Option<i32> },
    #[serde(rename = "container.oom")] ContainerOom { id: String },
    #[serde(rename = "container.pause")] ContainerPause { id: String },
    #[serde(rename = "container.unpause")] ContainerUnpause { id: String },
    #[serde(rename = "container.destroy")] ContainerDestroy { id: String },
    #[serde(rename = "image.pull.progress")] ImagePullProgress { reference: String, detail: String },
    #[serde(rename = "image.pull.done")] ImagePullDone { reference: String },
    #[serde(rename = "net.attach")] NetAttach { id: String },
    #[serde(rename = "net.detach")] NetDetach { id: String },
    #[serde(rename = "copyup")] CopyUp { id: String, path: String, size_bytes: u64 },
    #[serde(rename = "seccomp.violation")] SeccompViolation { id: String, syscall: String },
    #[serde(rename = "psi.threshold")] PsiThreshold { id: String, resource: String },
    #[serde(rename = "cgroup.throttle")] CgroupThrottle { id: String },
}

pub type EventBus = tokio::sync::broadcast::Sender<Event>;
```

- [ ] **Step 2: `GET /events`** — SSE handler subscribing a fresh `Receiver`, forwarding every `Event` as `data: <json>\n\n`; handle `broadcast::error::RecvError::Lagged` gracefully (log + continue, don't kill the whole SSE stream over one dropped event).

- [ ] **Step 3: Wire publishers** — `POST /containers` (Task 8) publishes `ContainerCreate`; `start` (Task 9) → `ContainerStart`; `pause`/`unpause` (Task 9) → their events; `delete` (Task 9) → `ContainerDestroy`. **Consume Task 13's signal channel here** — a small `tokio::spawn`ed task that receives Task 13's generic `(String, StatusTransition)`/OOM/PSI/throttle signals and translates each into the right real `Event`, publishing it on THIS bus. This is the ONLY place status-transition/OOM/PSI/throttle signals become real events — Task 13 itself never touches the `EventBus` type.

## Context

Task 14 of 23. The backbone every later observability task (15, 20) publishes onto. Depends on Task 13 (consumes its signal channel — no duplicate-poller risk now, since Task 13 owns the one poller and this task is its only consumer).

## Your Job

1. Implement `events.rs` and the SSE endpoint.
2. Wire publishers into every Task 9 handler, plus the Task 13 signal-channel consumer described in Step 3.
3. Write a test: subscribe to `/events`, trigger a create+start+stop cycle via the real endpoints, assert the right event sequence arrives in order with no duplicates.
4. Do NOT commit/branch/push. Report back.

---

## Task 15: `kestreld` — copy-up scanner

**Files:**
- Create: `crates/kestreld/src/copyup_scanner.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: Implement** — separate `tokio::spawn`ed loop (genuinely separate interval from Task 13's 1Hz sampler, per its own `config.storage.copyup_scan_interval_s`, default 5s): for each running container, call `kestrel_rootfs::copyup::scan_copy_ups(upper_dir, &lowers)` (real, ready per design doc §6), diff against a per-container `HashSet<PathBuf>` of previously-seen paths, publish `Event::CopyUp` (Task 14's bus) only for genuinely new entries.

- [ ] **Step 2: Test** — root-gated: a container whose entrypoint writes to a file that exists in a lower layer (triggering a real copy-up), confirm a `copyup` event fires with the right path/size, and confirm a SECOND write to the SAME file does NOT re-fire (the dedup-against-previously-seen check working correctly).

## Context

Task 15 of 23. Depends on Task 14 (event bus) and Task 3's `CopyUpEvent` type already existing (real, from Phase 4 — confirmed nothing new needed there).

## Your Job

1. Implement the scanner loop exactly as specified.
2. Write and pass the test, including the no-duplicate-refire assertion.
3. Do NOT commit/branch/push. Report back.

---

## Task 16: Seccomp-notify fd hand-back + supervisor

**Files:**
- Modify: `crates/kestrel-security/src/apply.rs`
- Modify: `crates/kestrel-init/src/exec.rs`
- Modify: `crates/kestrel-init/src/main.rs` (thread the new parameter through)
- Modify: `crates/kestrel-oci/src/bootstrap.rs` (`Bootstrap` gains `seccomp_notify_sink: Option<PathBuf>`)
- Modify: `crates/kestrel-runtime/src/create.rs` (`build_bootstrap` populates it)
- Modify: `crates/kestrel-shim/src/daemon.rs` (add `seccomp.sock` listener + `run_notify_loop` integration)
- New/modified tests across all of the above

**This is CHECKLIST's one 🟡 (non-required) item in this phase — deliberately scoped last.** If time/complexity runs short, everything through Task 15 + 17-23 stands on its own without this task; do not let this one block the rest of the plan.

- [ ] **Step 1: Thread the notify fd out of `apply_all`'s caller** — `exec_into` (`crates/kestrel-init/src/exec.rs:16-24`) currently discards `apply_all`'s returned `Option<OwnedFd>` as an unnamed temporary (confirmed during design grounding AND independently re-confirmed during adversarial plan review — genuinely dropped/closed today, not a no-op placeholder). Change its signature to accept an optional sink:

```rust
pub fn exec_into(process: &Process, seccomp: Option<&LinuxSeccomp>, notify_sink: Option<&Path>) -> Result<Infallible> {
    // ... existing chdir + apply_all call, but bind the result:
    let notify_fd = kestrel_security::apply::apply_all(process, seccomp).context("apply_all")?;
    if let (Some(fd), Some(sink_path)) = (notify_fd, notify_sink) {
        send_fd_to_socket(&fd, sink_path).context("sending seccomp-notify fd to shim")?;
    }
    // ... existing args/argv/envp + execve, unchanged (this IS a direct execve
    // in-place, not a fork — confirmed during adversarial review; the fd-send
    // happens synchronously just before that execve, in the same process
    // that's about to replace its own image)
}

fn send_fd_to_socket(fd: &OwnedFd, path: &Path) -> Result<()> {
    // Connect to a UnixDatagram or SOCK_STREAM at `path`, send `fd` via SCM_RIGHTS
    // (nix::sys::socket::sendmsg with ControlMessage::ScmRights), one-shot, before execve.
}
```

Verify `nix`'s real `sendmsg`/`ControlMessage::ScmRights` API shape against the vendored 0.29 source before writing this — fd-passing via `SCM_RIGHTS` has a specific, easy-to-get-subtly-wrong call shape (needs at least one byte of real data alongside the control message on some platforms/socket types — confirm Linux's actual requirement here rather than assuming).

- [ ] **Step 2: Wire the parameter through `main.rs`'s fork+exec of the entrypoint** — `Bootstrap` (`crates/kestrel-oci/src/bootstrap.rs`) gains `seccomp_notify_sink: Option<PathBuf>`, populated by `create.rs`'s `build_bootstrap` only when the process spec actually requests `SCMP_ACT_NOTIFY` anywhere (check via the same logic `install_seccomp`'s own doc comment describes). Set to `<run_dir>/<id>/seccomp.sock` when applicable. Confirmed structurally sound timing during adversarial review: the shim binds its socket(s) right after `create` succeeds, well before `start` (a separate, later API call) ever triggers `kestrel-init`'s `execve()` where the fd-send happens — no race.

- [ ] **Step 3: Shim-side listener** — the shim (already listening on `attach.sock` per Task 2) additionally listens on `<run_dir>/<id>/seccomp.sock` (always listens, cheap, simply never receives a connection for containers that don't use it). On receiving the fd via `SCM_RIGHTS`, spawn `kestrel_security::notify::run_notify_loop` (real, ready, per design grounding) on a `tokio::task::spawn_blocking` (it's a blocking read loop, not async), forwarding each `NotifyEvent` as a `Frame::SeccompEvent` (Task 2's framing, type `0x04`) over the EXISTING `attach.sock` connection convention.

- [ ] **Step 4: `kestreld`-side consumption** — the attach-WS bridge (Task 12) and/or a dedicated internal subscriber reads `Frame::SeccompEvent` frames arriving over `attach.sock` connections and publishes them as `Event::SeccompViolation` onto the event bus (Task 14).

- [ ] **Step 5: Tests** — root-gated, real end-to-end: a container whose seccomp profile sets `SCMP_ACT_NOTIFY` on a specific syscall (reuse Phase 5's own seccomp-notify test fixtures/profile-building patterns if they exist — check `crates/kestrel-security/tests/` first), trigger that syscall from inside the container, confirm a `seccomp.violation` event actually arrives at `kestreld`'s event bus with the right syscall name.

## Context

Task 16 of 23. The highest-risk, most speculative task in the plan (real kernel-level fd-passing across a fork+exec boundary, genuinely new plumbing touching FOUR crates including two from Phase 5/8). Explicitly the first thing to cut/defer if time runs short — CHECKLIST marks it 🟡 for exactly this reason. Depends on Task 2 (shim's socket-listening infra) and Task 14 (event bus).

## Your Job

1. Read `crates/kestrel-security/src/apply.rs`, `notify.rs`, `crates/kestrel-init/src/exec.rs`, and `crates/kestrel-oci/src/bootstrap.rs` in full before touching anything.
2. Implement all 4 steps, verifying the real `nix` SCM_RIGHTS API shape first.
3. Write and pass the end-to-end test.
4. If this proves substantially harder than expected, report BLOCKED with a clear description of what's stuck rather than shipping a half-working fd-passing mechanism.
5. Do NOT commit/branch/push. Report back.

---

## Task 17: `kestreld` — network attachment (bridge mode) + `/containers/:id/network` + `/system/topology`

**Files:**
- Create: `crates/kestreld/src/network.rs`
- Create: `crates/kestreld/src/api/network.rs`
- Modify: `crates/kestreld/src/api/containers.rs` (Task 9's `delete` handler gets the real teardown call it stubbed out)
- Modify: `crates/kestreld/src/registry.rs` (`ContainerMeta` gains the `network` field, per Task 7's forward note)
- Modify: `crates/kestreld/src/main.rs`
- Modify: `crates/kestreld/Cargo.toml` (add `ipnetwork` — `kestrel-net` was already added in Task 8)

- [ ] **Step 1: `NetworkInfo` + extend `ContainerMeta`** — per design doc §8/§4a, this is `kestreld`'s own bookkeeping (confirmed during grounding: `kestrel-net` has almost no read-back API, so kestreld remembering what it set up is the pragmatic choice, not a kernel re-derivation).

```rust
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct NetworkInfo {
    pub mode: String, // "bridge" | "host" | "none" | "container:<id>"
    pub bridge_name: Option<String>,
    pub ip: Option<std::net::Ipv4Addr>,
    pub gateway: Option<std::net::Ipv4Addr>,
    pub published_ports: Vec<(u16, u16)>, // (host_port, container_port)
}
```

```rust
// crates/kestreld/src/registry.rs — extend Task 7's ContainerMeta:
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ContainerMeta {
    pub tty: bool,
    #[serde(default)]
    pub network: Option<crate::network::NetworkInfo>, // NEW — additive, old meta.json files still parse
}
```

**Also fix `recover_registry` (Task 7) to actually populate `ContainerHandle`'s equivalent field from this** — Task 7's `read_meta` already reads the WHOLE `ContainerMeta` struct, so once this field exists on `ContainerMeta`, recovery gets it "for free" via the existing reader — confirm this is genuinely true by re-reading Task 7's `recover_registry` code, don't just assume the additive-field claim holds without checking the actual call site.

- [ ] **Step 2: Attachment sequence** — exactly the real, tested call order from `kestrel-net`'s own `tests/lifecycle.rs` (confirmed during design grounding AND re-confirmed during adversarial review — reuse this order directly): `Ipam::load` + `.allocate(id)` → `ensure_bridge` → (Task 8 already calls `create_netns` + injects the pin path before `create()` runs, using Task 4's real join mechanism) → (AFTER `create()` succeeds) `attach_veth` → `ensure_masquerade` → `add_dnat` per published port. Write the resulting `NetworkInfo` into `meta.json` (Step 1's extended `ContainerMeta`) so it survives a `kestreld` restart.

- [ ] **Step 3: Delete-time teardown** — reverse order: `remove_dnat` per port, `teardown_netns`, `Ipam::release`. This is the REAL implementation of the `crate::network::teardown(...)` call Task 9's `delete` handler stubbed out — go back and confirm Task 9's stub call site matches this function's real signature exactly.

- [ ] **Step 4: `GET /containers/:id/network`** — return the persisted `NetworkInfo` directly (from `meta.json`, not a separate file — Step 1's design keeps ONE metadata file per container, not two).

- [ ] **Step 5: `GET /system/topology`** — aggregate `NetworkInfo` across every registry entry (bridge names, subnets, per-container IPs/veth associations) into a reasonable first cut: `{"bridges": [{"name", "subnet", "containers": [{"id","ip"}]}]}`.

- [ ] **Step 6: Tests** — root-gated, real end-to-end: create two bridge-mode containers (via the real HTTP API, exercising Task 8's `create_netns`-at-create-time step, Task 4's join mechanism, and THIS task's post-create veth/bridge/NAT attachment all together for the first time), confirm they can reach each other (reusing the same ping/TCP-based proof technique `kestrel-net`'s own `test_inter_container` uses), confirm `/containers/:id/network` reports correct IPs, confirm `/system/topology` lists both under the same bridge; delete one, confirm its `NetworkInfo`/IPAM allocation are both released; restart `kestreld`, confirm `/containers/:id/network` for the surviving container still reports correctly (proves the `meta.json`-persistence half of this task's contribution to restart-durability).

## Context

Task 17 of 23. Depends on Task 4 (namespace-join mechanism — hard dependency), Task 8 (netns creation + `path` injection at bundle-materialization time), Task 9 (the `delete` handler's stub this task fills in for real), Task 14 (event bus, for `net.attach`/`net.detach`). Read design doc §4a/§8 and the real `kestrel-net/tests/lifecycle.rs` call sequence before starting.

## Your Job

1. Implement `network.rs`, the extended `ContainerMeta`, the attachment sequence's post-create half, delete-time teardown, and both endpoints.
2. Confirm the `recover_registry`/Task-9-delete-stub integration points genuinely close the loop — re-read the actual code at both call sites, don't assume.
3. Write and pass the described tests, including the restart-persistence proof.
4. Do NOT commit/branch/push. Report back.

---

## Task 18: `kestreld` — introspection endpoints, part A (namespaces, cgroup, pressure, mounts, caps)

**Files:**
- Create: `crates/kestreld/src/api/introspect.rs`
- Modify: `crates/kestreld/src/main.rs`

**Split from a single oversized "all introspection endpoints" task per adversarial review — this is the half with the most novel/riskiest code (raw `mountinfo` parsing, cross-container inode comparison); Task 19 covers the more mechanical remainder.**

- [ ] **Step 1: `/containers/:id/namespaces`** — walk `<run_dir>/<id>/ns/*` (real, pinned per-container namespace files from Phase 8's `create.rs::pin_namespaces`), `stat()` each for its inode; "shared with" computed by cross-referencing inodes against every OTHER container's own `ns/*` pins (only meaningful for `container:<id>` network-sharing mode, per this project's own namespace model — most namespace types are never shared between containers).

- [ ] **Step 2: `/containers/:id/cgroup`** — `cpu_stat`, `memory_current`, `pids_current`, `io_stat` (Task 5), plus raw reads of `cpu.max`/`memory.max`/`pids.max` for the CONFIGURED limits (not just current usage) — these are plain file reads, `fs::read_to_string` is enough.

- [ ] **Step 3: `/containers/:id/pressure`** — `pressure(Cpu|Memory|Io)` × 3, direct passthrough of the real, already-built API.

- [ ] **Step 4: `/containers/:id/mounts`** — `kestrel_ns::join::with_namespace` (real, from Phase 7) into the container's pinned mount namespace, parse `/proc/self/mountinfo` from inside (propagation type is field 7 of each `mountinfo` line — write a real, tested parser against a real sample, don't guess the format from memory without verifying it).

- [ ] **Step 5: `/containers/:id/caps`** — read the bundle's `config.json` `process.capabilities` directly (already fully typed via `oci_spec::runtime::LinuxCapabilities`, no new parsing needed).

- [ ] **Step 6: Tests** — one root-gated test per endpoint against a real running container, asserting real, specific values (inode numbers that are actually consistent with `/proc/<pid>/ns/*`, cgroup numbers that move when you generate real load, a real parsed `mountinfo` propagation type) — not just "200 OK."

## Context

Task 18 of 23. Depends on Task 5 (`io_stat`), Task 9 (containers to introspect).

## Your Job

1. Implement all 5 endpoints.
2. Write a real, specific test per endpoint.
3. Do NOT commit/branch/push. Report back.

---

## Task 19: `kestreld` — introspection endpoints, part B (layers, copyups, seccomp, system/namespaces)

**Files:**
- Modify: `crates/kestreld/src/api/introspect.rs`
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: `/containers/:id/layers`** — read `<data_dir>/containers/<id>/layers.json` (`kestreld` persists the resolved chain-id list at create time, since `MountPlan` itself is never persisted by `kestrel-runtime` — add this write to Task 8's bundle-materialization step if it isn't already there; check first, don't duplicate); for each chain-id, resolve its `LayerStore` diff-dir size (`fs::metadata` walk) and origin.

- [ ] **Step 2: `/containers/:id/copyups`** — same `scan_copy_ups` call as Task 15's background scanner, on-demand (not diffed against previously-seen — this endpoint always returns the FULL current set).

- [ ] **Step 3: `/containers/:id/seccomp`** — active profile from `config.json` + accumulated violation log (a per-container ring buffer `kestreld` maintains, fed by Task 16's `SeccompViolation` events if that task landed; if Task 16 was deferred, this endpoint still returns the profile with an empty violation log — don't make this endpoint hard-fail just because Task 16 might not exist).

- [ ] **Step 4: `/system/namespaces`** — host-wide scan of `/proc/*/ns/*` (new code — confirmed during grounding this has no existing helper, distinct from the per-container pin-based query in Task 18 Step 1), building a `{pid: {ns_type: inode}}` graph.

- [ ] **Step 5: Tests** — one root-gated test per endpoint, same real-value-not-200-OK standard as Task 18.

## Context

Task 19 of 23. Depends on Task 8 (needs to confirm/add the `layers.json` write), Task 15 (copy-up scanner's `scan_copy_ups` usage pattern to reuse), optionally Task 16 (seccomp violations).

## Your Job

1. Implement all 4 endpoints. Confirm whether Task 8 already writes `layers.json`; add it there if not (small addition to an earlier task, flag clearly in your report that you touched Task 8's code).
2. Write a real, specific test per endpoint.
3. Do NOT commit/branch/push. Report back.

---

## Task 20: `kestreld` — image endpoints

**Files:**
- Create: `crates/kestreld/src/api/images.rs`
- Modify: `crates/kestreld/src/main.rs`
- Modify: `crates/kestreld/Cargo.toml` (add `kestrel-image`)

- [ ] **Step 1: `POST /images/pull`** — real SSE progress, finally wiring `pull_image_with_client`'s `on_progress` callback (confirmed real, ready, already SSE-shaped per design grounding) through a `tokio::sync::mpsc` channel forwarded as SSE `data:` events; each `PullProgress` variant also published onto the event bus as `image.pull.progress`/`image.pull.done` (Task 14).

- [ ] **Step 2: `GET /images`** — directory walk over the content store's `oci-layout`/index (no "list" API exists yet, confirmed during grounding — small new code, not a missing primitive).

- [ ] **Step 3: `GET /images/:ref`**, **`/images/:ref/layers`** — manifest/config/layer-list read via `ContentStore` + `manifest.rs` helpers (real, ready).

- [ ] **Step 4: `DELETE /images/:ref`** — `ContentStore::remove_ref` + `remove_blob_if_unreferenced` (real, ready, direct passthrough).

- [ ] **Step 5: `GET /images/dedup`** (🟡) — logical bytes (sum of each image's uncompressed layer sizes, double-counting shared layers across images) vs. physical bytes (actual on-disk blob store size, once per unique digest) — new aggregation code, no missing primitives per design grounding.

- [ ] **Step 6: Tests** — root-gated (network-gated for the real pull, matching Phase 6's own `KESTREL_TEST_NETWORK=1`-gated precedent in `kestrel-image/tests/pull_e2e.rs` — reuse that exact gating convention): pull a real small image, confirm SSE progress events arrive in a sane order, confirm `GET /images` lists it afterward, confirm `DELETE` removes it and `is_referenced` correctly reflects zero refs.

## Context

Task 20 of 23. Depends on Task 14 (event bus).

## Your Job

1. Implement all 5 endpoints.
2. Reuse Phase 6's `KESTREL_TEST_NETWORK=1` gating convention exactly for the real-pull test.
3. Write and pass the described tests.
4. Do NOT commit/branch/push. Report back.

---

## Task 21: `kestreld` — graceful shutdown

**Files:**
- Modify: `crates/kestreld/src/main.rs`

- [ ] **Step 1: Implement** — `axum::serve(...).with_graceful_shutdown(shutdown_signal())` on BOTH listeners (Task 6's dual-serve), where `shutdown_signal` awaits `tokio::signal::unix::signal(SignalKind::terminate())`. On shutdown: stop accepting new connections (axum's own graceful-shutdown handles this), let in-flight HTTP requests finish naturally, then exit — no explicit container-teardown step (confirmed per design doc §10: containers are NOT children of `kestreld`, nothing about their process tree depends on `kestreld` staying alive, so "graceful shutdown" here genuinely means just "stop serving cleanly," not "stop containers").

- [ ] **Step 2: Test** — start `kestreld`, create+start a real container, send SIGTERM to `kestreld`'s own process, confirm it exits promptly (bounded time) AND the container is STILL RUNNING afterward (the actual property this design exists to guarantee) — this is a real, meaningful assertion, not a formality.

## Context

Task 21 of 23. Small, but tests the single most important property the whole shim architecture (Task 2) was built to provide.

## Your Job

1. Implement graceful shutdown on both listeners.
2. Write and pass the test, with the real "container survives kestreld's own SIGTERM" assertion.
3. Do NOT commit/branch/push. Report back.

---

## Task 22: Capstone integration tests

**Files:**
- Create: `crates/kestreld/tests/capstone.rs`

- [ ] **Step 1: `test_full_lifecycle_via_http`** — create → start → poll running → logs show expected output → exec a command → stop → delete, entirely through the real HTTP API (no direct `kestrel_runtime`/`kestrel_shim` calls) against a real bound `kestreld` instance.

- [ ] **Step 2: `test_daemon_restart_preserves_running_container_and_live_attach`** — the test design doc §13 calls out as the one that actually proves the shim architecture's reason for existing: create+start a container via one `kestreld` instance, kill that `kestreld` PROCESS (not the container), start a fresh `kestreld` instance pointed at the same `run_dir`/`data_dir`, confirm: (a) `GET /containers/:id` shows it still running, (b) `WS attach` to it still works (bytes round-trip through the SURVIVING shim) — this specifically exercises the `meta.json`-based `tty` recovery fix from Task 7/8, so a regression there would surface here, (c) `logs` shows continuous output spanning across the restart with no gap.

- [ ] **Step 3: `test_events_and_metrics_flow_end_to_end`** — subscribe to `/events`, create+start+stop a container, assert the full expected event sequence with NO duplicates (specifically exercising the Task 13/14 duplicate-event fix); separately confirm `/containers/:id/pressure` returns real, non-placeholder PSI numbers while it's running.

- [ ] **Step 4: `test_image_pull_and_container_from_image`** (network-gated, `KESTREL_TEST_NETWORK=1`) — real pull → create a container FROM that pulled image (exercising Task 3's annotation fast path for real, end to end) → confirm it runs correctly → confirm `/containers/:id/layers` reports the real chain-ids used.

- [ ] **Step 5: `test_bridge_network_container_to_container`** — two bridge-mode containers created via HTTP, confirm real network connectivity between them (exercising Task 4's namespace-join gap-fill + Task 17's attachment sequence together, end to end, for the first time outside Task 17's own more narrowly-scoped test).

## Context

Task 22 of 23. The composing capstone for the whole phase, same role Task 16 played in Phase 8 — expect real integration bugs to surface here that no individual task's own tests could catch, ESPECIALLY around the areas adversarial review already flagged as risky (namespace joining, PTY EOF/EIO, event deduplication, registry recovery). Depends on every prior task.

## Your Job

1. Implement all 5 tests with real, specific assertions.
2. Debug real failures for real — root-cause and fix at the source (whichever crate/task actually has the bug), same discipline as Phase 8's Task 16.
3. Confirm zero residue in the VM's real state (processes, cgroups, mounts, namespace pins, netns, `attach.sock`/`seccomp.sock` files) after the full suite runs.
4. Do NOT commit/branch/push. Report back in detail, including any cross-task integration bugs found and how you fixed them.

---

## Task 23: Workspace-wide verification and cleanup

**Files:** none new — verification only, plus Makefile notes for `kestreld`/`kestrel-shim`'s own root-gated test invocation quirks if any emerge.

- [ ] **Step 1:** `cargo build --workspace` — clean.
- [ ] **Step 2:** `cargo test --workspace` — all non-ignored tests pass.
- [ ] **Step 3:** `make test-root` (updated if needed for any new test-concurrency constraints `kestreld`/`kestrel-shim`'s tests introduce, same category of issue Phase 8's own verification task found and fixed) — every root-gated test passes.
- [ ] **Step 4:** `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] **Step 5:** `make check-no-tokio` — re-verify. `kestreld`/`kestrel-shim` USE tokio (expected, by design) — the check must still confirm `kestrel-runtime` itself has no tokio/thread-spawning edge; re-read the check script to confirm it's still asking the right question now that tokio is pervasive elsewhere in the workspace.
- [ ] **Step 6:** Grep for `todo!()`/`unimplemented!()` in `crates/kestreld` and `crates/kestrel-shim` — zero matches expected.
- [ ] **Step 7:** Confirm no crate depends on `kestrel-runtime` as a library (`grep` every `Cargo.toml` for `kestrel-runtime = { path`) — the fork+exec-only boundary design doc §1 requires must still hold after 22 tasks of new code.
- [ ] **Step 8:** Re-confirm the namespace-join privilege-ordering reasoning from Task 4 held up under real, broader use across Tasks 8/17 — grep for any workaround/retry-loop that might have been added around `setns` calls during later tasks as a signal the original ordering analysis needed correction; if found, make sure it's documented as a real, understood fix, not a silently-papered-over flake.

## Context

Task 23 of 23, final task of the phase.

## Your Job

1. Run all 8 steps.
2. Fix anything genuinely broken.
3. Confirm zero residue after any root-gated runs.
4. Report: is Phase 9 genuinely complete and ready to report to the user?

---

## Self-Review Notes (post-adversarial-review revision)

- **Spec coverage:** every 🔴 CHECKLIST.md Phase 9 item maps to a task above. Both 🟡 items (copy-up scanner, seccomp-notify) map to Tasks 15 and 16 respectively, with 16 explicitly flagged as the one safe-to-defer task.
- **Real gaps surfaced during design/review, now first-class tasks:** the `kestrel-runtime` chain-id annotation fast path (3), the namespace-join-by-path mechanism (4 — added after adversarial review found the original plan's bridge-mode design was structurally broken), `kestrel-cgroup` `io_stat` (5), and seccomp-notify fd hand-back (16) — all confirmed via direct code reading, not assumed.
- **Blocking issues from adversarial review, all addressed:** namespace-join mechanism → new Task 4; CLI flag ordering → corrected in Tasks 1, 8, 9, 10; Task 8's missing `kestrel-net` dependency → added; registry-recovery placeholder → closed via `meta.json` read/write contract spanning Tasks 7/8/17.
- **Notable issues from adversarial review, all addressed:** Task 12/13 circular dependency → reordered (metrics/poller now Task 13, event bus Task 14, one-directional dependency); PTY EIO-vs-EOF → explicit in Task 2 Step 2 + its own test; `resolve_entrypoint_host_pid` reuse claim → reworded in Task 10; oversized introspection task → split into Tasks 18/19.
- **Minor issues from adversarial review, all addressed:** axum/UnixListener hedge dropped (Task 6); execve-not-fork wording fixed (Task 16); `runtime_cli.rs` sketch now matches sibling-binary-resolution prose (Task 9).
- **New crate flagged clearly:** `kestrel-shim` is explicitly called out (design doc §2, Task 1's header) as a deliberate addition beyond SPEC.md's original `§16 File Structure`.
