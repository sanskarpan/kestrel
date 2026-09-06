# Kestrel Phase 0 + Phase 1 Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `kestrel` Cargo workspace (12 crates), a Lima dev VM, the `web/` Vite scaffold, and the `kestrel-oci` crate's OCI Runtime/Image Spec types — the first two of fourteen phases in `CHECKLIST.md`, producing a workspace that builds and tests cleanly on macOS.

**Architecture:** `kestrel-oci` wraps the real `oci-spec` crate (v0.10.0) and re-exports its runtime/image types rather than hand-rolling the OCI schema; kestrel-specific logic (`validate()`, default-spec generation, image→spec translation, user resolution, forward-compatible round-trip) is added as extension traits and free functions on top. The other 11 crates get compiling stubs now and real implementations in later phases. `kestrel-runtime`'s `preflight.rs` and `assert_single_threaded()` are `cfg`-gated so the workspace still builds on macOS even though they can only be *run* inside the Lima VM.

**Tech Stack:** Rust (workspace, `nix`, `libc`, `rustix`, `anyhow`, `thiserror`, `serde`/`serde_json`, `tracing`, `oci-spec = "0.10.0"`), Lima (Ubuntu 24.04, `vz` backend), Bun + Vite + React + TypeScript + Tailwind + shadcn/ui.

**Git note:** Per explicit user instruction, git is **not** in play for this work — do not `git init`, `git add`, or `git commit` anything. Every task below ends with a "mark complete" step instead of a commit step; files are simply left on disk.

---

## File Structure

```
Container-Runtime/
├── Cargo.toml                          # workspace root (Task 1)
├── .gitignore                          # target/, node_modules/, .lima logs (Task 1)
├── Makefile                            # Task 5
├── .lima/kestrel.yaml                  # Task 6
├── crates/
│   ├── kestrel-oci/
│   │   ├── Cargo.toml                  # Task 8
│   │   └── src/
│   │       ├── lib.rs                  # Task 8: re-exports
│   │       ├── state.rs                # Task 9: kestrel-local State/Status
│   │       ├── validate.rs             # Task 10: Spec::validate()
│   │       ├── default_spec.rs         # Task 11: default spec generator
│   │       ├── image.rs                # Task 12: image config -> runtime spec
│   │       ├── user.rs                 # Task 13: user resolution
│   │       └── raw.rs                  # Task 14: forward-compatible wrapper
│   │   └── tests/
│   │       └── fixtures/
│   │           └── oci_example_config.json   # Task 14
│   ├── kestrel-ns/       {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-cgroup/   {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-rootfs/   {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-security/ {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-net/      {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-image/    {Cargo.toml, src/lib.rs}       # stub, Task 1
│   ├── kestrel-runtime/
│   │   ├── Cargo.toml                  # Task 1, deps refined Task 2
│   │   └── src/
│   │       ├── main.rs                 # Task 1 stub -> Task 3 wiring
│   │       ├── lib.rs                  # Task 1
│   │       └── preflight.rs            # Task 2
│   ├── kestrel-init/     {Cargo.toml, src/main.rs}      # stub, Task 1
│   ├── kestreld/         {Cargo.toml, src/main.rs}      # stub, Task 1
│   ├── kestrel-cli/      {Cargo.toml, src/main.rs}      # stub, Task 1
│   └── kestrel-tui/      {Cargo.toml, src/main.rs}      # stub, Task 1
├── scripts/
│   └── check-no-tokio-in-runtime.sh    # Task 4
└── web/                                 # Task 7
    ├── vite.config.ts
    ├── src/...
    └── ...
```

---

## Task 1: Workspace skeleton — 12 compiling crates

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.gitignore`
- Create: `crates/kestrel-oci/Cargo.toml`, `crates/kestrel-oci/src/lib.rs`
- Create: `crates/kestrel-ns/Cargo.toml`, `crates/kestrel-ns/src/lib.rs`
- Create: `crates/kestrel-cgroup/Cargo.toml`, `crates/kestrel-cgroup/src/lib.rs`
- Create: `crates/kestrel-rootfs/Cargo.toml`, `crates/kestrel-rootfs/src/lib.rs`
- Create: `crates/kestrel-security/Cargo.toml`, `crates/kestrel-security/src/lib.rs`
- Create: `crates/kestrel-net/Cargo.toml`, `crates/kestrel-net/src/lib.rs`
- Create: `crates/kestrel-image/Cargo.toml`, `crates/kestrel-image/src/lib.rs`
- Create: `crates/kestrel-runtime/Cargo.toml`, `crates/kestrel-runtime/src/lib.rs`, `crates/kestrel-runtime/src/main.rs`
- Create: `crates/kestrel-init/Cargo.toml`, `crates/kestrel-init/src/main.rs`
- Create: `crates/kestreld/Cargo.toml`, `crates/kestreld/src/main.rs`
- Create: `crates/kestrel-cli/Cargo.toml`, `crates/kestrel-cli/src/main.rs`
- Create: `crates/kestrel-tui/Cargo.toml`, `crates/kestrel-tui/src/main.rs`

Only the *shared* dependencies from CHECKLIST.md's Phase 0 (`nix`, `libc`, `rustix`, `anyhow`, `thiserror`, `serde`, `serde_json`, `tracing`) are wired in this task, as workspace-level dependencies. Crate-specific dependencies (`oci-spec` for `kestrel-oci` in Task 8; `caps`/`libseccomp` for `kestrel-security`; `rtnetlink`/`netlink-packet-route` for `kestrel-net`; `tokio`/`axum` for `kestreld`; etc.) are **deliberately deferred to the phase that implements each crate** — several of those are Linux-only at the dependency-graph level (not just at the call-site level) and would break `cargo build --workspace` on this macOS host if pulled in before they're needed.

- [ ] **Step 1: Write the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/kestrel-oci",
    "crates/kestrel-ns",
    "crates/kestrel-cgroup",
    "crates/kestrel-rootfs",
    "crates/kestrel-security",
    "crates/kestrel-net",
    "crates/kestrel-image",
    "crates/kestrel-runtime",
    "crates/kestrel-init",
    "crates/kestreld",
    "crates/kestrel-cli",
    "crates/kestrel-tui",
]

[workspace.package]
edition = "2021"
version = "0.1.0"

[workspace.dependencies]
nix = { version = "0.29", default-features = false }
libc = "0.2"
rustix = "0.38"
anyhow = "1"
thiserror = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

- [ ] **Step 2: Write `.gitignore`**

```
/target
**/target
node_modules/
web/dist/
.lima/*.log
.DS_Store
```

- [ ] **Step 3: Create `kestrel-oci` skeleton**

`crates/kestrel-oci/Cargo.toml`:

```toml
[package]
name = "kestrel-oci"
edition.workspace = true
version.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
```

`crates/kestrel-oci/src/lib.rs`:

```rust
//! OCI Runtime & Image Spec types. Phase 1 fills this in; see
//! docs/superpowers/plans/2026-07-31-phase0-phase1-bootstrap.md.
```

- [ ] **Step 4: Create the six library-crate stubs**

For each of `kestrel-ns`, `kestrel-cgroup`, `kestrel-rootfs`, `kestrel-security`,
`kestrel-net`, `kestrel-image`, create `Cargo.toml`:

```toml
[package]
name = "<CRATE_NAME>"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
```

and `src/lib.rs`:

```rust
//! <CRATE_NAME> — not yet implemented. See CHECKLIST.md for the phase
//! that owns this crate.
```

(Substitute the real crate name in both the `name` field and the doc comment
for each of the six.)

- [ ] **Step 5: Create `kestrel-runtime`**

`crates/kestrel-runtime/Cargo.toml`:

```toml
[package]
name = "kestrel-runtime"
edition.workspace = true
version.workspace = true

[dependencies]
nix = { workspace = true, features = ["fs", "user", "sched", "process"] }
libc.workspace = true
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

`crates/kestrel-runtime/src/lib.rs`:

```rust
pub mod preflight;
```

`crates/kestrel-runtime/src/main.rs`:

```rust
fn main() {
    println!("kestrel-runtime: not yet implemented (Phase 8)");
}
```

(`preflight.rs` itself is Task 2 — leave `pub mod preflight;` pointing at a
file that doesn't exist yet; Task 2's Step 1 creates it.)

- [ ] **Step 6: Create the four binary-crate stubs**

For each of `kestrel-init`, `kestreld`, `kestrel-cli`, `kestrel-tui`, create
`Cargo.toml`:

```toml
[package]
name = "<CRATE_NAME>"
edition.workspace = true
version.workspace = true

[dependencies]
anyhow.workspace = true
```

and `src/main.rs`:

```rust
fn main() {
    println!("<CRATE_NAME>: not yet implemented");
}
```

- [ ] **Step 7: Verify the workspace compiles**

Run: `cargo build --workspace`
Expected: `Compiling kestrel-oci ... Compiling kestrel-tui ...` then
`Finished` with no errors. (This will fail until Task 2 creates
`preflight.rs` — if you're executing tasks in order, come back and re-run
this after Task 2 instead of blocking here.)

- [ ] **Step 8: Mark task complete**

No git action (see Git note above) — leave the files as written.

---

## Task 2: `kestrel-runtime` preflight check

**Files:**
- Create: `crates/kestrel-runtime/src/preflight.rs`

Implements PROMPT.md's `check_environment()` sample. The Linux-only body
(`statfs` magic-number check, `/proc/filesystems`, `/proc/pressure/cpu`,
`clone3` probe) is gated behind `#[cfg(target_os = "linux")]`; on any other
host `check_environment()` returns a clear "unsupported platform" error
instead of failing to compile. The kernel-version parser is pulled out as a
pure function so it's unit-testable on macOS.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-runtime/src/preflight.rs (top of file, tests module)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version_with_suffix() {
        assert_eq!(parse_kernel_version("6.8.0-45-generic").unwrap(), (6, 8, 0));
    }

    #[test]
    fn test_parse_kernel_version_plain() {
        assert_eq!(parse_kernel_version("5.11.0").unwrap(), (5, 11, 0));
    }

    #[test]
    fn test_parse_kernel_version_rejects_garbage() {
        assert!(parse_kernel_version("not-a-version").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kestrel-runtime parse_kernel_version`
Expected: FAIL — `cannot find function 'parse_kernel_version' in this scope`

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-runtime/src/preflight.rs

use anyhow::{bail, Context, Result};

#[derive(Debug, Default)]
pub struct EnvReport {
    pub controllers: Vec<String>,
    pub psi: bool,
    pub kernel: (u32, u32, u32),
    pub clone3: bool,
}

/// Parses a `uname -r`-style release string ("6.8.0-45-generic") into
/// (major, minor, patch), ignoring any distro suffix after the third
/// numeric component.
pub fn parse_kernel_version(release: &str) -> Result<(u32, u32, u32)> {
    let core = release.split('-').next().unwrap_or(release);
    let mut parts = core.split('.');
    let major = parts
        .next()
        .context("missing major version")?
        .parse()
        .context("major version not numeric")?;
    let minor = parts
        .next()
        .context("missing minor version")?
        .parse()
        .context("minor version not numeric")?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse()
        .context("patch version not numeric")?;
    Ok((major, minor, patch))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::statfs::statfs;
    use std::fs;
    use std::path::Path;

    pub fn check_environment() -> Result<EnvReport> {
        let mut r = EnvReport::default();

        // cgroup v2 unified. On v1/hybrid, everything in Phase 3 silently
        // misbehaves in ways that look like our bugs.
        let st = statfs("/sys/fs/cgroup").context("statfs /sys/fs/cgroup")?;
        if st.filesystem_type() != nix::sys::statfs::CGROUP2_SUPER_MAGIC {
            bail!(
                "cgroup v2 required. Boot with systemd.unified_cgroup_hierarchy=1 \
                 (or cgroup_no_v1=all) and reboot."
            );
        }
        r.controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .context("reading /sys/fs/cgroup/cgroup.controllers")?
            .split_whitespace()
            .map(String::from)
            .collect();

        // overlayfs
        if !fs::read_to_string("/proc/filesystems")
            .context("reading /proc/filesystems")?
            .contains("overlay")
        {
            bail!("overlayfs not available: modprobe overlay");
        }

        // PSI is a kernel config option; degrade gracefully rather than failing.
        r.psi = Path::new("/proc/pressure/cpu").exists();

        // 5.11 gives us userxattr overlay in a userns, which rootless needs.
        let uname = nix::sys::utsname::uname().context("uname()")?;
        r.kernel = parse_kernel_version(uname.release().to_string_lossy().as_ref())?;
        if r.kernel < (5, 11, 0) {
            tracing::warn!(
                kernel = ?r.kernel,
                "kernel < 5.11: rootless overlay will fall back to fuse-overlayfs"
            );
        }

        r.clone3 = probe_clone3();

        Ok(r)
    }

    /// clone3(2) with a null args pointer: ENOSYS means the syscall itself
    /// is unavailable; any other errno (typically EFAULT) means the kernel
    /// recognizes the syscall number and rejected the bogus arguments —
    /// i.e. clone3 exists.
    fn probe_clone3() -> bool {
        let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null_mut::<u8>(), 0usize) };
        rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
    }
}

#[cfg(target_os = "linux")]
pub use linux::check_environment;

#[cfg(not(target_os = "linux"))]
pub fn check_environment() -> Result<EnvReport> {
    bail!(
        "kestrel-runtime preflight requires Linux (cgroup v2, overlayfs, /proc); \
         run this inside the Lima VM, not on the host."
    )
}

/// Rule 2, enforced. If this ever fires, someone added a dependency that
/// spawns threads and the userns syscalls are about to start failing with
/// EINVAL in a way that is very hard to trace back to its cause.
pub fn assert_single_threaded() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("reading /proc/self/status")?;
    let threads = parse_thread_count(&status);
    anyhow::ensure!(
        threads == 1,
        "kestrel-runtime must be single-threaded (found {threads}). \
         Some dependency spawned a thread. setns(CLONE_NEWUSER) will fail."
    );
    Ok(())
}

fn parse_thread_count(status: &str) -> usize {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1)
}
```

Add a second tests block entry for `parse_thread_count` right below the
existing `mod tests` (same file, same block):

```rust
    #[test]
    fn test_parse_thread_count() {
        let status = "Name:\tfoo\nThreads:\t3\nVmSize:\t1024 kB\n";
        assert_eq!(parse_thread_count(status), 3);
    }

    #[test]
    fn test_parse_thread_count_missing_defaults_to_one() {
        assert_eq!(parse_thread_count("Name:\tfoo\n"), 1);
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p kestrel-runtime`
Expected: `test result: ok. 5 passed` (3 kernel-version tests + 2 thread-count
tests)

- [ ] **Step 5: Verify the whole workspace still builds**

Run: `cargo build --workspace`
Expected: `Finished` with no errors — this also completes Task 1 Step 7,
which was blocked on this file existing.

- [ ] **Step 6: Mark task complete**

---

## Task 3: `main.rs` wiring + tracing convention

**Files:**
- Modify: `crates/kestrel-runtime/src/main.rs`

Wires `assert_single_threaded()` and `tracing` init into the entry point, and
establishes the `container_id` span-field convention CHECKLIST.md Phase 0
calls for. This is the only binary in scope this phase, so the convention is
documented here for the other binaries (`kestreld`, `kestrel-cli`,
`kestrel-init`, `kestrel-tui`) to follow when their phases land.

- [ ] **Step 1: Replace the stub `main.rs`**

```rust
// crates/kestrel-runtime/src/main.rs

use kestrel_runtime::preflight;

/// Every subsystem that logs during a container's lifecycle should open its
/// span with `tracing::info_span!("...", container_id = %id)` so logs from
/// namespaces, cgroups, rootfs, and security setup for the same container
/// can be correlated. This binary has nothing to open a span *for* yet
/// (Phase 8 adds the `create`/`start`/... subcommands) — this just wires the
/// subscriber so that convention is ready to use.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

fn main() -> anyhow::Result<()> {
    init_tracing();

    preflight::assert_single_threaded()?;

    match preflight::check_environment() {
        Ok(report) => tracing::info!(?report, "preflight checks passed"),
        Err(e) => tracing::error!(error = %e, "preflight checks failed"),
    }

    println!("kestrel-runtime: preflight only (Phase 8 adds subcommands)");
    Ok(())
}
```

`EnvReport` needs `Debug` for the `?report` format — it already derives
`Default` in Task 2; add `Debug` there too:

```rust
// crates/kestrel-runtime/src/preflight.rs — change the derive line
#[derive(Debug, Default)]
pub struct EnvReport {
```

(If Task 2 already wrote `#[derive(Debug, Default)]`, this step is a no-op —
the code above already includes it for exactly this reason.)

- [ ] **Step 2: Build and smoke-run**

Run: `cargo build --workspace && cargo run -p kestrel-runtime`
Expected: prints a `preflight checks failed` tracing line (since this is
macOS, not Linux) followed by `kestrel-runtime: preflight only (Phase 8 adds
subcommands)`, and exits 0 — `assert_single_threaded` succeeds because
`cargo run`'s process here is macOS and `/proc/self/status` doesn't exist,
so... **note:** on macOS, `assert_single_threaded()`'s `fs::read_to_string`
will itself error (no `/proc`), which propagates via `?` and makes `main`
return `Err`, printing an error and exiting non-zero. That's correct,
expected behavior for this host per the design doc ("only `preflight.rs`
needs the Lima VM to run") — confirm the error message names
`/proc/self/status`, not a panic or garbled output.
Expected exact behavior: process exits non-zero with
`Error: reading /proc/self/status` (or similar, wrapped by `anyhow::Context`)
printed to stderr.

- [ ] **Step 3: Mark task complete**

---

## Task 4: `tokio`-in-`kestrel-runtime` guard

**Files:**
- Create: `scripts/check-no-tokio-in-runtime.sh`

Enforces PROMPT.md Rule #2 as an automated check rather than a comment, per
CHECKLIST.md Phase 0.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# scripts/check-no-tokio-in-runtime.sh
#
# kestrel-runtime must stay single-threaded with no async runtime (Rule #2,
# PROMPT.md). tokio transitively spawning a thread makes setns(CLONE_NEWUSER)
# fail with EINVAL in a way that's very hard to trace back to this file.
set -euo pipefail

if cargo tree -p kestrel-runtime --edges normal 2>/dev/null | grep -qE '(^| )tokio( |v)'; then
    echo "FAIL: kestrel-runtime depends on tokio (directly or transitively)." >&2
    echo "This violates PROMPT.md Rule #2 — see the comment in preflight.rs." >&2
    cargo tree -p kestrel-runtime --edges normal | grep -E '(^| )tokio( |v)' >&2
    exit 1
fi

echo "OK: kestrel-runtime has no tokio dependency."
```

- [ ] **Step 2: Make it executable and run it**

Run: `chmod +x scripts/check-no-tokio-in-runtime.sh && ./scripts/check-no-tokio-in-runtime.sh`
Expected: `OK: kestrel-runtime has no tokio dependency.` (there is no `Cargo.lock`
yet on a fresh checkout — if `cargo tree` errors because the workspace hasn't
been built, run `cargo build --workspace` first, then re-run the script.)

- [ ] **Step 3: Mark task complete**

---

## Task 5: `Makefile`

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Write the Makefile**

```makefile
.PHONY: build test test-root oci-conformance web-dev tui vm-up vm-ssh vm-provision check-no-tokio

build:
	cargo build --workspace

test: check-no-tokio
	cargo test --workspace

check-no-tokio:
	./scripts/check-no-tokio-in-runtime.sh

test-root:
	@echo "test-root requires the Lima VM (Phase 2+). Run 'make vm-ssh' then" \
	      "'sudo -E cargo test --workspace -- --ignored' inside it." >&2
	@exit 1

oci-conformance:
	@echo "oci-conformance requires runtime-tools + the Lima VM (Phase 13)." >&2
	@exit 1

web-dev:
	cd web && bun run dev

tui:
	cargo run -p kestrel-tui

vm-up:
	limactl start --tty=false .lima/kestrel.yaml

vm-ssh:
	limactl shell kestrel

vm-provision:
	limactl start --tty=false .lima/kestrel.yaml || limactl stop kestrel && limactl start --tty=false .lima/kestrel.yaml
```

- [ ] **Step 2: Verify the targets that don't need the VM**

Run: `make build && make test`
Expected: both succeed (same output as Task 2/4's direct `cargo`/script
invocations, just routed through `make`).

- [ ] **Step 3: Mark task complete**

---

## Task 6: Lima VM config

**Files:**
- Create: `.lima/kestrel.yaml`

Ubuntu 24.04 arm64, `vz` backend (native Apple Silicon virtualization, no
QEMU emulation), repo mounted read-write, ports 7777/5173 forwarded,
provisioning installs the Rust toolchain, C build tooling, and `bun`.

- [ ] **Step 1: Write the Lima config**

```yaml
# .lima/kestrel.yaml
vmType: vz
os: Linux
arch: aarch64
images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: aarch64

cpus: 4
memory: "8GiB"
disk: "40GiB"

mounts:
  - location: "~/dev/Research/Projects/Container-Runtime"
    mountPoint: "/home/kestrel.linux/Container-Runtime"
    writable: true

portForwards:
  - guestPort: 7777
    hostIP: "127.0.0.1"
  - guestPort: 5173
    hostIP: "127.0.0.1"

provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      apt-get update
      apt-get install -y build-essential pkg-config libseccomp-dev \
          iproute2 iptables curl unzip
  - mode: user
    script: |
      #!/bin/bash
      set -eux
      if [ ! -d "$HOME/.cargo" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      fi
      if [ ! -d "$HOME/.bun" ]; then
        curl -fsSL https://bun.sh/install | bash
      fi

message: |
  Repo is mounted at /home/kestrel.linux/Container-Runtime.
  Run 'limactl shell kestrel' then 'cd Container-Runtime' to start working.
```

- [ ] **Step 2: Verify the config is well-formed (dry parse, no VM boot yet)**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.lima/kestrel.yaml'))" && echo "valid YAML"`
Expected: `valid YAML` — this deliberately stops short of actually running
`limactl start`, since installing Lima and booting a multi-GB VM image is a
real resource commitment. Booting it for real is a manual step for the user
(`make vm-up`) once Lima itself is installed (`brew install lima`), not part
of this plan's automated verification.

- [ ] **Step 3: Mark task complete**

---

## Task 7: `web/` Vite scaffold

**Files:**
- Create: `web/` (via `bun create vite`)
- Modify: `web/vite.config.ts`

- [ ] **Step 1: Scaffold the Vite project**

Run (from repo root):
```bash
cd web 2>/dev/null || (bun create vite web --template react-ts && cd web)
```
If `web/` doesn't exist yet, `bun create vite web --template react-ts` creates
it non-interactively with the React+TypeScript template.
Expected: `web/` now contains `package.json`, `src/`, `vite.config.ts`, etc.

- [ ] **Step 2: Install dependencies**

Run (inside `web/`):
```bash
bun add @tanstack/react-query @tanstack/react-table d3 recharts \
        @xterm/xterm @xterm/addon-fit zustand clsx lucide-react
bun add -d tailwindcss postcss autoprefixer @types/d3
```
Expected: `bun.lock` updated, `bun install` (implicit) completes with no
errors.

- [ ] **Step 3: Init Tailwind + shadcn/ui**

Run (inside `web/`):
```bash
bunx tailwindcss init -p
bunx shadcn@latest init -d
bunx shadcn@latest add button card table badge tabs dialog select tooltip sheet progress separator scroll-area
```
Expected: `tailwind.config.js`, `postcss.config.js`, and
`src/components/ui/{button,card,table,badge,tabs,dialog,select,tooltip,sheet,progress,separator,scroll-area}.tsx`
all exist.

- [ ] **Step 4: Wire the dev-server proxy to the daemon**

Read the generated `web/vite.config.ts` first (its exact contents depend on
what the scaffold + shadcn init produced), then add a `server.proxy` block
so `/v1` (REST) and `/events` (SSE) requests from the Vite dev server reach
`kestreld` on port 7777 without CORS setup:

```ts
// web/vite.config.ts — add alongside the existing plugins/resolve config
export default defineConfig({
  // ...existing scaffold-generated config (plugins, resolve.alias, etc.)...
  server: {
    proxy: {
      '/v1': 'http://localhost:7777',
      '/events': {
        target: 'http://localhost:7777',
        ws: false,
      },
    },
  },
})
```

- [ ] **Step 5: Verify it builds**

Run: `cd web && bun run build`
Expected: `vite build` completes, emitting `web/dist/`.

- [ ] **Step 6: Mark task complete**

---

## Task 8: `kestrel-oci` — pull in `oci-spec` and re-export

**Files:**
- Modify: `crates/kestrel-oci/Cargo.toml`
- Modify: `crates/kestrel-oci/src/lib.rs`

`oci-spec` 0.10.0 exposes `oci_spec::runtime::*` (Spec, Process, Root, Mount,
Linux, LinuxResources, LinuxNamespace, LinuxNamespaceType, LinuxIdMapping,
LinuxCapabilities, LinuxSeccomp, LinuxDevice, PosixRlimit, Hooks, State) and
`oci_spec::image::*` (ImageConfiguration, ImageManifest, ImageIndex,
Descriptor, Config). CHECKLIST.md calls the rlimit type `LinuxRlimit`; the
real crate calls it `PosixRlimit` — re-export it under both names so the
plan's own naming and the crate's naming both work.

- [ ] **Step 1: Add the dependency**

```toml
# crates/kestrel-oci/Cargo.toml
[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
oci-spec = "0.10.0"
```

- [ ] **Step 2: Re-export in `lib.rs`**

```rust
// crates/kestrel-oci/src/lib.rs

//! OCI Runtime & Image Spec types, re-exported from `oci-spec`, plus
//! kestrel-specific extensions (validation, default-spec generation,
//! image-config translation, user resolution, forward-compatible parsing).

pub mod state;
pub mod validate;
pub mod default_spec;
pub mod image;
pub mod user;
pub mod raw;

pub mod runtime {
    pub use oci_spec::runtime::{
        Hooks, Linux, LinuxCapabilities, LinuxDevice, LinuxIdMapping, LinuxNamespace,
        LinuxNamespaceType, LinuxResources, LinuxSeccomp, Mount, PosixRlimit,
        PosixRlimit as LinuxRlimit, Process, Root, Spec, SpecBuilder, User,
    };
}

pub mod image_spec {
    pub use oci_spec::image::{Config, Descriptor, ImageConfiguration, ImageIndex, ImageManifest};
}
```

Every module listed (`state`, `validate`, `default_spec`, `image`, `user`,
`raw`) is created by a later task in this file — `lib.rs` references them now
so each task only has to add the file, not also touch `lib.rs` again.

- [ ] **Step 3: Create placeholder files so the module tree compiles**

```rust
// crates/kestrel-oci/src/state.rs
// filled in by Task 9
```
```rust
// crates/kestrel-oci/src/validate.rs
// filled in by Task 10
```
```rust
// crates/kestrel-oci/src/default_spec.rs
// filled in by Task 11
```
```rust
// crates/kestrel-oci/src/image.rs
// filled in by Task 12
```
```rust
// crates/kestrel-oci/src/user.rs
// filled in by Task 13
```
```rust
// crates/kestrel-oci/src/raw.rs
// filled in by Task 14
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p kestrel-oci`
Expected: `Finished` — this pulls `oci-spec` and its dependency tree; expect
it to take longer than the earlier stub builds the first time.

- [ ] **Step 5: Mark task complete**

---

## Task 9: kestrel-local `State`/`Status`

**Files:**
- Create content in: `crates/kestrel-oci/src/state.rs`

Per SPEC.md §9.2, this is **not** `oci_spec::runtime::State` — kestrel's
`Status` needs a `Paused` variant (via `cgroup.freeze`) that isn't part of
the official OCI runtime-spec schema, so it's kestrel's own type.

- [ ] **Step 1: Write the failing test**

```rust
// crates/kestrel-oci/src/state.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_round_trips_through_json() {
        let s = State {
            oci_version: "1.0.2".into(),
            id: "abc123".into(),
            status: Status::Running,
            pid: Some(4242),
            bundle: "/var/lib/kestrel/bundles/abc123".into(),
            annotations: Default::default(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"ociVersion\":\"1.0.2\""));
        assert!(json.contains("\"status\":\"running\""));
        let back: State = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "abc123");
        assert_eq!(back.status, Status::Running);
    }

    #[test]
    fn test_status_paused_is_not_part_of_oci_schema_but_serializes() {
        let json = serde_json::to_string(&Status::Paused).unwrap();
        assert_eq!(json, "\"paused\"");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kestrel-oci state::`
Expected: FAIL — `State`/`Status` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-oci/src/state.rs (above the tests module)

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
    /// Not part of the official OCI runtime-spec state schema — kestrel's
    /// extension for `cgroup.freeze`-backed pause/resume (SPEC.md §9.1).
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    /// In the RUNTIME's pid namespace, not the container's.
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kestrel-oci state::`
Expected: `test result: ok. 2 passed`

- [ ] **Step 5: Mark task complete**

---

## Task 10: `Spec::validate()`

**Files:**
- Create content in: `crates/kestrel-oci/src/validate.rs`

Implemented as an extension trait (`SpecExt`) on `oci_spec::runtime::Spec`
rather than a wrapper type, since Rust's orphan rule allows implementing our
own trait for a foreign type. Checks: root path present, non-empty process
args, no duplicate namespace types, id-map coverage when a user namespace is
requested.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-oci/src/validate.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespace, LinuxNamespaceType, ProcessBuilder,
        RootBuilder, SpecBuilder,
    };

    fn minimal_valid_spec() -> Spec {
        SpecBuilder::default()
            .root(RootBuilder::default().path("rootfs").build().unwrap())
            .process(ProcessBuilder::default().args(vec!["sh".into()]).build().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn test_valid_spec_passes() {
        assert!(minimal_valid_spec().validate().is_ok());
    }

    #[test]
    fn test_missing_root_rejected() {
        let mut s = minimal_valid_spec();
        s.set_root(None);
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_empty_process_args_rejected() {
        let mut s = minimal_valid_spec();
        s.set_process(Some(ProcessBuilder::default().args(vec![]).build().unwrap()));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_duplicate_namespace_rejected() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::Pid);
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns.clone(), ns])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_user_namespace_without_id_maps_rejected() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::User);
        let linux = LinuxBuilder::default().namespaces(vec![ns]).build().unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_user_namespace_with_id_maps_accepted() {
        let mut s = minimal_valid_spec();
        let mut ns = LinuxNamespace::default();
        ns.set_typ(LinuxNamespaceType::User);
        let mapping = LinuxIdMappingBuilder::default()
            .container_id(0u32)
            .host_id(1000u32)
            .size(1u32)
            .build()
            .unwrap();
        let linux = LinuxBuilder::default()
            .namespaces(vec![ns])
            .uid_mappings(vec![mapping.clone()])
            .gid_mappings(vec![mapping])
            .build()
            .unwrap();
        s.set_linux(Some(linux));
        assert!(s.validate().is_ok());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p kestrel-oci validate::`
Expected: FAIL — `validate` method not found on `Spec` (trait not yet
defined/imported).

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-oci/src/validate.rs (above the tests module)

use std::collections::HashSet;

use thiserror::Error;

use crate::runtime::Spec;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("spec has no root, or root has an empty path")]
    MissingRoot,
    #[error("process.args must be non-empty")]
    EmptyProcessArgs,
    #[error("duplicate namespace type in linux.namespaces: {0:?}")]
    DuplicateNamespace(crate::runtime::LinuxNamespaceType),
    #[error("linux.namespaces requests a user namespace but uid_mappings/gid_mappings are missing or empty")]
    MissingIdMapCoverage,
}

pub trait SpecExt {
    fn validate(&self) -> Result<(), ValidationError>;
}

impl SpecExt for Spec {
    fn validate(&self) -> Result<(), ValidationError> {
        let root_ok = self
            .root()
            .as_ref()
            .map(|r| !r.path().as_os_str().is_empty())
            .unwrap_or(false);
        if !root_ok {
            return Err(ValidationError::MissingRoot);
        }

        let args_ok = self
            .process()
            .as_ref()
            .and_then(|p| p.args().clone())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if !args_ok {
            return Err(ValidationError::EmptyProcessArgs);
        }

        let Some(linux) = self.linux() else {
            return Ok(());
        };
        let namespaces = linux.namespaces().clone().unwrap_or_default();

        let mut seen = HashSet::new();
        for ns in &namespaces {
            if !seen.insert(ns.typ()) {
                return Err(ValidationError::DuplicateNamespace(ns.typ()));
            }
        }

        let wants_userns = namespaces
            .iter()
            .any(|ns| ns.typ() == crate::runtime::LinuxNamespaceType::User);
        if wants_userns {
            let uid_ok = linux.uid_mappings().clone().map(|m| !m.is_empty()).unwrap_or(false);
            let gid_ok = linux.gid_mappings().clone().map(|m| !m.is_empty()).unwrap_or(false);
            if !uid_ok || !gid_ok {
                return Err(ValidationError::MissingIdMapCoverage);
            }
        }

        Ok(())
    }
}
```

`LinuxNamespaceType` needs `Hash` to go in a `HashSet` — if `cargo build`
reports it's missing that derive in the installed `oci-spec` version, switch
`seen: HashSet<_>` to a `Vec<_>` with a linear `.contains()` check instead
(namespace lists are at most 8 entries long, so this isn't a performance
concern):

```rust
        let mut seen: Vec<crate::runtime::LinuxNamespaceType> = Vec::new();
        for ns in &namespaces {
            if seen.contains(&ns.typ()) {
                return Err(ValidationError::DuplicateNamespace(ns.typ()));
            }
            seen.push(ns.typ());
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p kestrel-oci validate::`
Expected: `test result: ok. 6 passed`

If a builder method name doesn't match what's in the installed `oci-spec`
0.10.0 (builder APIs occasionally rename fields between minor versions), run
`cargo doc -p oci-spec --open` and adjust the builder call to match — the
*shape* of the test (which fields get set) stays the same either way.

- [ ] **Step 5: Mark task complete**

---

## Task 11: Default spec generator

**Files:**
- Create content in: `crates/kestrel-oci/src/default_spec.rs`

Produces a minimal-but-valid `Spec` matching `runc spec`'s well-known
default shape: a `rootfs` root, `sh` as the entrypoint, the standard mount
set, and the mount/pid/network/ipc/uts/cgroup namespaces (no user namespace
by default, matching `runc spec`'s non-rootless default).

- [ ] **Step 1: Write the failing test**

```rust
// crates/kestrel-oci/src/default_spec.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::LinuxNamespaceType;
    use crate::validate::SpecExt;

    #[test]
    fn test_default_spec_is_valid() {
        assert!(default_spec().validate().is_ok());
    }

    #[test]
    fn test_default_spec_has_standard_namespaces() {
        let spec = default_spec();
        let types: Vec<_> = spec
            .linux()
            .as_ref()
            .unwrap()
            .namespaces()
            .clone()
            .unwrap()
            .into_iter()
            .map(|ns| ns.typ())
            .collect();
        for want in [
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Cgroup,
        ] {
            assert!(types.contains(&want), "missing namespace {want:?}");
        }
        assert!(!types.contains(&LinuxNamespaceType::User), "not rootless by default");
    }

    #[test]
    fn test_default_spec_standard_mounts_present() {
        let spec = default_spec();
        let destinations: Vec<_> = spec
            .mounts()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.destination().clone())
            .collect();
        for want in ["/proc", "/dev", "/dev/pts", "/dev/shm", "/sys", "/sys/fs/cgroup"] {
            assert!(
                destinations.iter().any(|d| d == std::path::Path::new(want)),
                "missing mount {want}"
            );
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p kestrel-oci default_spec::`
Expected: FAIL — `default_spec` function not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-oci/src/default_spec.rs (above the tests module)

use crate::runtime::{
    LinuxBuilder, LinuxNamespace, LinuxNamespaceType, MountBuilder, ProcessBuilder, RootBuilder,
    Spec, SpecBuilder,
};

fn ns(typ: LinuxNamespaceType) -> LinuxNamespace {
    let mut n = LinuxNamespace::default();
    n.set_typ(typ);
    n
}

fn mount(destination: &str, typ: &str, source: &str, options: &[&str]) -> crate::runtime::Mount {
    MountBuilder::default()
        .destination(destination)
        .typ(typ.to_string())
        .source(source)
        .options(options.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .build()
        .unwrap()
}

/// Matches `runc spec`'s default bundle shape: a non-rootless container
/// with the standard namespace/mount set and `sh` as the entrypoint.
pub fn default_spec() -> Spec {
    let namespaces = vec![
        ns(LinuxNamespaceType::Pid),
        ns(LinuxNamespaceType::Network),
        ns(LinuxNamespaceType::Ipc),
        ns(LinuxNamespaceType::Uts),
        ns(LinuxNamespaceType::Mount),
        ns(LinuxNamespaceType::Cgroup),
    ];

    let mounts = vec![
        mount("/proc", "proc", "proc", &[]),
        mount("/dev", "tmpfs", "tmpfs", &["nosuid", "strictatime", "mode=755", "size=65536k"]),
        mount(
            "/dev/pts",
            "devpts",
            "devpts",
            &["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"],
        ),
        mount("/dev/shm", "tmpfs", "shm", &["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]),
        mount("/dev/mqueue", "mqueue", "mqueue", &["nosuid", "noexec", "nodev"]),
        mount("/sys", "sysfs", "sysfs", &["nosuid", "noexec", "nodev", "ro"]),
        mount(
            "/sys/fs/cgroup",
            "cgroup",
            "cgroup",
            &["nosuid", "noexec", "nodev", "relatime", "ro"],
        ),
    ];

    SpecBuilder::default()
        .version("1.0.2")
        .root(RootBuilder::default().path("rootfs").readonly(false).build().unwrap())
        .hostname("kestrel")
        .process(
            ProcessBuilder::default()
                .terminal(true)
                .args(vec!["sh".to_string()])
                .cwd("/")
                .env(vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "TERM=xterm".to_string(),
                ])
                .build()
                .unwrap(),
        )
        .mounts(mounts)
        .linux(LinuxBuilder::default().namespaces(namespaces).build().unwrap())
        .build()
        .unwrap()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p kestrel-oci default_spec::`
Expected: `test result: ok. 3 passed`

- [ ] **Step 5: Mark task complete**

---

## Task 12: Image config → runtime spec translation

**Files:**
- Create content in: `crates/kestrel-oci/src/image.rs`

Applies an `ImageConfiguration`'s `Env`, `Cmd`, `Entrypoint`, `WorkingDir`
onto a base `Spec`'s `process`. `User` and `ExposedPorts`/`Volumes` are
intentionally **not** handled here: `User` needs Task 13's `/etc/passwd`
resolution (which needs a real rootfs, not available at this phase), and
`ExposedPorts`/`Volumes` feed the *networking* and *mount* layers built in
Phase 7/Phase 4 — applying them here would be dead code with nothing to
consume it yet. Per Docker/OCI image-spec semantics, `Cmd` is only used when
`Entrypoint` is absent; when both are present they concatenate
(`entrypoint + cmd`).

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-oci/src/image.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_spec::default_spec;
    use oci_spec::image::{ConfigBuilder, ImageConfigurationBuilder};

    fn image_config(cfg: oci_spec::image::Config) -> oci_spec::image::ImageConfiguration {
        ImageConfigurationBuilder::default()
            .architecture(oci_spec::image::Arch::Amd64)
            .os(oci_spec::image::Os::Linux)
            .config(cfg)
            .rootfs(
                oci_spec::image::RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(vec![])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn test_entrypoint_and_cmd_concatenate() {
        let cfg = ConfigBuilder::default()
            .entrypoint(vec!["/entry.sh".to_string()])
            .cmd(vec!["--flag".to_string()])
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        assert_eq!(
            spec.process().as_ref().unwrap().args().clone().unwrap(),
            vec!["/entry.sh".to_string(), "--flag".to_string()]
        );
    }

    #[test]
    fn test_cmd_only_used_when_entrypoint_absent() {
        let cfg = ConfigBuilder::default().cmd(vec!["sh".to_string(), "-c".to_string()]).build().unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        assert_eq!(
            spec.process().as_ref().unwrap().args().clone().unwrap(),
            vec!["sh".to_string(), "-c".to_string()]
        );
    }

    #[test]
    fn test_env_and_working_dir_applied() {
        let cfg = ConfigBuilder::default()
            .env(vec!["FOO=bar".to_string()])
            .working_dir("/app".to_string())
            .build()
            .unwrap();
        let spec = apply_image_config(default_spec(), &image_config(cfg));
        let process = spec.process().as_ref().unwrap();
        assert!(process.env().clone().unwrap().contains(&"FOO=bar".to_string()));
        assert_eq!(process.cwd(), &std::path::PathBuf::from("/app"));
    }

    #[test]
    fn test_missing_config_is_a_noop() {
        let img = ImageConfigurationBuilder::default()
            .architecture(oci_spec::image::Arch::Amd64)
            .os(oci_spec::image::Os::Linux)
            .rootfs(
                oci_spec::image::RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(vec![])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let before = default_spec();
        let before_args = before.process().as_ref().unwrap().args().clone();
        let after = apply_image_config(before, &img);
        assert_eq!(after.process().as_ref().unwrap().args().clone(), before_args);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p kestrel-oci image::`
Expected: FAIL — `apply_image_config` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-oci/src/image.rs (above the tests module)

use crate::image_spec::ImageConfiguration;
use crate::runtime::Spec;

/// Applies an image's Env/Cmd/Entrypoint/WorkingDir onto a base runtime
/// spec's process. Does not touch `User` (needs Task 13's `/etc/passwd`
/// resolution against a real rootfs) or `ExposedPorts`/`Volumes` (consumed
/// by the networking/mount layers, not the process spec).
pub fn apply_image_config(mut spec: Spec, img: &ImageConfiguration) -> Spec {
    let Some(cfg) = img.config().clone() else {
        return spec;
    };

    let mut process = spec.process().clone().unwrap_or_default();

    if let Some(env) = cfg.env() {
        let mut merged = process.env().clone().unwrap_or_default();
        merged.extend(env.iter().cloned());
        process.set_env(Some(merged));
    }

    let entrypoint = cfg.entrypoint().clone().unwrap_or_default();
    let cmd = cfg.cmd().clone().unwrap_or_default();
    let args: Vec<String> = if !entrypoint.is_empty() {
        entrypoint.into_iter().chain(cmd).collect()
    } else if !cmd.is_empty() {
        cmd
    } else {
        Vec::new()
    };
    if !args.is_empty() {
        process.set_args(Some(args));
    }

    if let Some(wd) = cfg.working_dir() {
        if !wd.is_empty() {
            process.set_cwd(wd.into());
        }
    }

    spec.set_process(Some(process));
    spec
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p kestrel-oci image::`
Expected: `test result: ok. 4 passed`

- [ ] **Step 5: Mark task complete**

---

## Task 13: User resolution against the container's `/etc/passwd`

**Files:**
- Create content in: `crates/kestrel-oci/src/user.rs`

Resolves the four OCI/Docker user-spec formats (`uid`, `uid:gid`, `name`,
`name:group`) against a **caller-supplied** `/etc/passwd`/`/etc/group`
source — deliberately not "the host's `/etc/passwd`", and deliberately not
reading a real file path directly, so the function is testable with a
synthetic fixture and safe to call once Phase 4 has a real rootfs mounted
(it'll pass that rootfs's `/etc/passwd` contents in, not the runtime's own).

- [ ] **Step 1: Write the failing tests**

```rust
// crates/kestrel-oci/src/user.rs

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
app:x:1000:1000:app:/home/app:/bin/sh
";
    const GROUP: &str = "\
root:x:0:
nogroup:x:65534:
app:x:1000:
";

    #[test]
    fn test_numeric_uid_only() {
        let r = resolve_user("1000", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 1000, gid: 0 });
    }

    #[test]
    fn test_numeric_uid_gid() {
        let r = resolve_user("1000:1000", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 1000, gid: 1000 });
    }

    #[test]
    fn test_name_only_uses_passwd_gid() {
        let r = resolve_user("app", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 1000, gid: 1000 });
    }

    #[test]
    fn test_name_colon_group() {
        let r = resolve_user("app:root", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 1000, gid: 0 });
    }

    #[test]
    fn test_unknown_name_rejected() {
        assert!(resolve_user("ghost", PASSWD, GROUP).is_err());
    }

    #[test]
    fn test_unknown_group_name_rejected() {
        assert!(resolve_user("app:ghost-group", PASSWD, GROUP).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p kestrel-oci user::`
Expected: FAIL — `resolve_user`/`ResolvedUser` not defined.

- [ ] **Step 3: Write the implementation**

```rust
// crates/kestrel-oci/src/user.rs (above the tests module)

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Error)]
pub enum UserResolveError {
    #[error("unknown user {0:?} in /etc/passwd")]
    UnknownUser(String),
    #[error("unknown group {0:?} in /etc/group")]
    UnknownGroup(String),
    #[error("malformed /etc/passwd or /etc/group entry: {0}")]
    Malformed(String),
}

struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
}

fn parse_passwd(passwd: &str) -> Result<Vec<PasswdEntry>, UserResolveError> {
    passwd
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 4 {
                return Err(UserResolveError::Malformed(line.to_string()));
            }
            let uid = fields[2]
                .parse()
                .map_err(|_| UserResolveError::Malformed(line.to_string()))?;
            let gid = fields[3]
                .parse()
                .map_err(|_| UserResolveError::Malformed(line.to_string()))?;
            Ok(PasswdEntry { name: fields[0].to_string(), uid, gid })
        })
        .collect()
}

fn group_gid(group: &str, name: &str) -> Result<u32, UserResolveError> {
    group
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.first() == Some(&name)).then(|| fields.get(2)?.parse().ok()).flatten()
        })
        .ok_or_else(|| UserResolveError::UnknownGroup(name.to_string()))
}

/// Resolves `spec` (one of `uid`, `uid:gid`, `name`, `name:group`) against
/// the **container's** `/etc/passwd` and `/etc/group` contents, passed in by
/// the caller — never the host's. Callers in later phases read those two
/// files from the mounted-but-not-yet-pivoted rootfs and pass their
/// contents here.
pub fn resolve_user(spec: &str, passwd: &str, group: &str) -> Result<ResolvedUser, UserResolveError> {
    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    let uid_from_number = user_part.parse::<u32>().ok();

    let entries = parse_passwd(passwd)?;
    let (uid, default_gid) = if let Some(uid) = uid_from_number {
        let default_gid = entries.iter().find(|e| e.uid == uid).map(|e| e.gid).unwrap_or(0);
        (uid, default_gid)
    } else {
        let entry = entries
            .iter()
            .find(|e| e.name == user_part)
            .ok_or_else(|| UserResolveError::UnknownUser(user_part.to_string()))?;
        (entry.uid, entry.gid)
    };

    let gid = match group_part {
        None => default_gid,
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => group_gid(group, g)?,
        },
    };

    Ok(ResolvedUser { uid, gid })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p kestrel-oci user::`
Expected: `test result: ok. 6 passed`

- [ ] **Step 5: Mark task complete**

---

## Task 14: Forward-compatible round trip + official example fixture

**Files:**
- Create: `crates/kestrel-oci/tests/fixtures/oci_example_config.json`
- Create content in: `crates/kestrel-oci/src/raw.rs`
- Create: `crates/kestrel-oci/tests/round_trip.rs`

`oci_spec::runtime::Spec` deserializes only the fields it knows about;
plain `serde_json::from_str::<Spec>(json)` silently drops anything it
doesn't recognize, and a subsequent `to_string` would produce a
*different* JSON document than the input — losing forward compatibility
with future/vendor OCI fields. `RawSpec` wraps `Spec` with a
`#[serde(flatten)]` catch-all map: because flatten deserializes the whole
object into an intermediate representation first and lets each flattened
field claim the keys it recognizes, whatever `Spec` doesn't claim lands in
`extra` and comes back out on serialize.

- [ ] **Step 1: Save the official OCI example config.json as a fixture**

```json
{
    "ociVersion": "1.0.1",
    "process": {
        "terminal": true,
        "user": {
            "uid": 1,
            "gid": 1,
            "additionalGids": [5, 6]
        },
        "args": ["sh"],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        ],
        "cwd": "/",
        "capabilities": {
            "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
            "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
            "inheritable": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
            "effective": ["CAP_AUDIT_WRITE", "CAP_KILL"],
            "ambient": ["CAP_NET_BIND_SERVICE"]
        },
        "rlimits": [
            {"type": "RLIMIT_CORE", "hard": 1024, "soft": 1024},
            {"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}
        ],
        "noNewPrivileges": true
    },
    "root": {"path": "rootfs", "readonly": true},
    "hostname": "slartibartfast",
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
        },
        {
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]
        },
        {
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]
        },
        {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"]},
        {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev"]},
        {
            "destination": "/sys/fs/cgroup",
            "type": "cgroup",
            "source": "cgroup",
            "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]
        }
    ],
    "hooks": {
        "prestart": [
            {"path": "/usr/bin/fix-mounts", "args": ["fix-mounts", "arg1", "arg2"], "env": ["key1=value1"]},
            {"path": "/usr/bin/setup-network"}
        ],
        "poststart": [{"path": "/usr/bin/notify-start", "timeout": 5}],
        "poststop": [{"path": "/usr/sbin/cleanup.sh", "args": ["cleanup.sh", "-f"]}]
    },
    "linux": {
        "devices": [
            {"path": "/dev/fuse", "type": "c", "major": 10, "minor": 229, "fileMode": 438, "uid": 0, "gid": 0},
            {"path": "/dev/sda", "type": "b", "major": 8, "minor": 0, "fileMode": 432, "uid": 0, "gid": 0}
        ],
        "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 32000}],
        "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 32000}],
        "sysctl": {"net.ipv4.ip_forward": "1", "net.core.somaxconn": "256"},
        "cgroupsPath": "/myRuntime/myContainer",
        "resources": {
            "pids": {"limit": 32771},
            "memory": {"limit": 536870912, "reservation": 536870912, "swap": 536870912, "swappiness": 0, "disableOOMKiller": false},
            "cpu": {"shares": 1024, "quota": 1000000, "period": 500000, "realtimeRuntime": 950000, "realtimePeriod": 1000000, "cpus": "2-3", "mems": "0-7"},
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 10, "minor": 229, "access": "rw"},
                {"allow": true, "type": "b", "major": 8, "minor": 0, "access": "r"}
            ]
        },
        "rootfsPropagation": "slave",
        "seccomp": {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            "syscalls": [{"names": ["getcwd", "chmod"], "action": "SCMP_ACT_ERRNO"}]
        },
        "namespaces": [
            {"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"},
            {"type": "mount"}, {"type": "user"}, {"type": "cgroup"}
        ],
        "maskedPaths": ["/proc/kcore", "/proc/latency_stats", "/proc/timer_stats", "/proc/sched_debug"],
        "readonlyPaths": ["/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        "mountLabel": "system_u:object_r:svirt_sandbox_file_t:s0:c715,c811"
    },
    "annotations": {"com.example.key1": "value1", "com.example.key2": "value2"}
}
```

(Trimmed of the `apparmorProfile`/`ioPriority`/`timeOffsets`/`blockIO`/
`hugepageLimits`/`network` fields from the upstream doc's version, which
are newer/platform-specific schema additions some `oci-spec` 0.10.0 struct
fields may not model yet — the trimmed fixture still exercises every OCI
type CHECKLIST.md Phase 1 lists. If `cargo build` shows `oci-spec` 0.10.0
*does* support those extra fields, feel free to add them back in; the
round-trip test doesn't depend on which subset is present.)

- [ ] **Step 2: Write the failing round-trip test**

```rust
// crates/kestrel-oci/tests/round_trip.rs

use kestrel_oci::raw::RawSpec;

const FIXTURE: &str = include_str!("fixtures/oci_example_config.json");

#[test]
fn test_official_example_round_trips_without_loss() {
    let parsed: RawSpec = serde_json::from_str(FIXTURE).expect("parse fixture");
    let reserialized = serde_json::to_value(&parsed).expect("serialize back");
    let original: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(reserialized, original, "round trip must not add, drop, or reorder-lose fields");
}

#[test]
fn test_unknown_top_level_field_survives_round_trip() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["ociVendorExtensionField"] = serde_json::json!("kept-me");

    let parsed: RawSpec = serde_json::from_value(value.clone()).expect("parse with extra field");
    let reserialized = serde_json::to_value(&parsed).expect("serialize back");

    assert_eq!(
        reserialized.get("ociVendorExtensionField"),
        Some(&serde_json::json!("kept-me")),
        "unknown field must survive the round trip (forward compatibility)"
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p kestrel-oci --test round_trip`
Expected: FAIL — `kestrel_oci::raw::RawSpec` not defined.

- [ ] **Step 4: Write the implementation**

```rust
// crates/kestrel-oci/src/raw.rs

use serde::{Deserialize, Serialize};

use crate::runtime::Spec;

/// Wraps `Spec` with a flatten catch-all so fields the installed
/// `oci-spec` version doesn't model yet (future schema additions, vendor
/// extensions) survive a parse-then-reserialize round trip instead of being
/// silently dropped. Use this wherever a `config.json` gets read and later
/// re-written (e.g. `kestreld` normalizing a bundle) — use plain `Spec`
/// wherever the value is only ever read once and never written back out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSpec {
    #[serde(flatten)]
    pub spec: Spec,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p kestrel-oci --test round_trip`
Expected: `test result: ok. 2 passed`

If `test_official_example_round_trips_without_loss` fails with a field-value
diff (not a missing/extra field, but e.g. a number formatted differently),
that's `serde_json::Value` canonicalization, not data loss — compare the
*parsed* `RawSpec` values instead of the raw JSON text in that case, or note
the specific field and confirm manually that no bytes of container-relevant
data were lost.

- [ ] **Step 6: Run the full `kestrel-oci` suite**

Run: `cargo test -p kestrel-oci`
Expected: all tests from Tasks 9–14 pass together (state: 2, validate: 6,
default_spec: 3, image: 4, user: 6, raw/round_trip: 2 — 23 total).

- [ ] **Step 7: Mark task complete**

---

## Final Verification

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace`
Expected: `Finished` with no errors across all 12 crates.

- [ ] **Step 2: Full test suite + tokio guard**

Run: `make test`
Expected: `OK: kestrel-runtime has no tokio dependency.` followed by
`cargo test --workspace` passing (kestrel-oci's 23 tests + kestrel-runtime's
5 preflight tests; the other 10 crates have no tests yet — that's expected,
they're stubs).

- [ ] **Step 3: Web scaffold build**

Run: `cd web && bun run build`
Expected: succeeds, emits `web/dist/`.

- [ ] **Step 4: Confirm scope boundary**

Run: `git diff --stat` (informational only — no `git add`/`commit`, per the
Git note above) or just eyeball `find crates web scripts .lima Makefile
-type f` — everything touched should map to a task in this plan. Nothing in
`kestrel-ns`, `kestrel-cgroup`, `kestrel-rootfs`, `kestrel-security`,
`kestrel-net`, `kestrel-image`, `kestrel-init`, `kestreld`, `kestrel-cli`,
`kestrel-tui` beyond their Task 1 stub should have real logic — that's
Phase 2 onward, out of scope here.

## Self-Review Notes

- **Spec coverage:** every CHECKLIST.md Phase 0 bullet maps to Tasks 1–7;
  every Phase 1 bullet maps to Tasks 8–14 (the `oci-spec` re-export covers
  the type-listing bullets; `validate()`/default-spec/image-translation/
  user-resolution/round-trip bullets each have their own task).
- **Known API-drift risk:** Tasks 9–14 were written against `oci-spec`
  0.10.0's documented API (confirmed via docs.rs for `Spec`, `Process`,
  `User`, `LinuxNamespace`/`LinuxNamespaceType`, `ImageConfiguration`/
  `Config`); builder method names for less-central types (`RootBuilder`,
  `MountBuilder`, `LinuxIdMappingBuilder`, `ConfigBuilder`,
  `ImageConfigurationBuilder`, `RootFsBuilder`) were inferred from the
  crate's consistent naming convention rather than individually fetched.
  If any of those don't match, `cargo build`'s error will name the exact
  missing/misspelled method — fix the call site to match, the test's
  *intent* doesn't change.
