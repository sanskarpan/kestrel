// crates/kestrel-shim/src/main.rs
//
//! `kestrel-shim`'s entry point. See
//! docs/superpowers/specs/2026-08-09-phase9-daemon-design.md §2: the shim
//! allocates a PTY or pipes for a container's stdio (`kestrel_shim::io`),
//! spawns the given command (`kestrel-runtime create ...`) with that
//! stdio wired in, waits for it to exit, and reports success/failure back
//! to `kestreld` as a single-line JSON status message on the shim's OWN
//! stdout (distinct from the container's captured stdio, which lives
//! entirely in the allocated PTY/pipes, never this process's fd 1).
//!
//! `kestrel_shim::daemon::run` (Task 2) takes over after the status
//! handshake below: daemonizes, then runs the durable
//! log-capture/`attach.sock` event loop until the container's stdio hits
//! EOF/EIO.
//!
//! **Invocation** (by `kestreld`, once Task 8 wires the real caller):
//! `kestrel-shim --id <id> --run-dir <run-dir> --data-dir <data-dir>
//! --tty <bool> -- kestrel-runtime --run-dir <run_dir> --data-dir
//! <data_dir> create <id> --bundle <path>`. Note the global
//! `--run-dir`/`--data-dir` flags precede the `create` subcommand token —
//! verified against `crates/kestrel-runtime/src/cli.rs`'s real `Cli`
//! struct: `run_dir`/`data_dir` are plain (non-`global`) fields on `Cli`
//! itself, sibling to the `#[command(subcommand)] command: Command`
//! field, so `clap` only accepts them before the subcommand token (e.g.
//! `kestrel-runtime create id --bundle x --run-dir y` fails to parse;
//! `kestrel-runtime --run-dir y create id --bundle x` succeeds). The shim
//! itself is agnostic to this — it just execs whatever `args.command`
//! says — but every caller of the shim must get this order right.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use kestrel_shim::io::ContainerIo;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    id: String,
    #[arg(long)]
    run_dir: PathBuf,
    #[arg(long)]
    data_dir: PathBuf,
    // Deviation from the plan's literal sketch (`#[arg(long)] tty: bool`),
    // found by empirically checking real clap 4.6 derive behavior in the
    // VM: a bare `bool` field defaults to `ArgAction::SetTrue` (a
    // no-value flag), NOT "expects an explicit true/false value". Under
    // that default, `--tty false -- /bin/echo hello` parses as `tty =
    // true` with `command = ["false", "--", "/bin/echo", "hello"]` — the
    // literal string "false" (and even the "--" separator) get swallowed
    // into the trailing var-arg command vector instead of being consumed
    // as `tty`'s value, silently corrupting the command to run (verified
    // via a standalone repro: `cargo run -- ... --tty false -- /bin/echo
    // hello` printed `Args { tty: true, command: ["false", "--",
    // "/bin/echo", "hello"] }`). `action = clap::ArgAction::Set` makes
    // clap consume the next token as `tty`'s value (parsed via `bool`'s
    // `FromStr`, accepting exactly "true"/"false"), matching both the
    // plan's own `--tty <bool>`/`--tty false` invocation examples and the
    // design doc's `--tty <bool>` CLI shape. Verified fixed by the same
    // repro: `--tty false -- /bin/echo hello` now parses as `tty = false,
    // command = ["/bin/echo", "hello"]`.
    #[arg(long, action = clap::ArgAction::Set)]
    tty: bool,
    /// Everything after `--` is the command to run (kestrel-runtime create ...).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

/// Matches `kestrel-runtime`'s own `init_tracing` convention — without this,
/// every `tracing::warn!` this crate emits (attach-connection errors,
/// accept-loop failures, PTY-write/TIOCSWINSZ failures) goes to the default
/// no-op dispatcher and is silently swallowed, never visible anywhere.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();
    let io = kestrel_shim::io::allocate(args.tty)?;

    let (child_stdin, child_stdout, child_stderr): (
        std::process::Stdio,
        std::process::Stdio,
        std::process::Stdio,
    ) = match &io {
        ContainerIo::Pty { slave, .. } => {
            // SAFETY: `nix::unistd::dup` returns a freshly-duplicated,
            // valid, open fd that this process exclusively owns at this
            // point (nothing else has a handle to it yet). Handing it to
            // `Stdio::from_raw_fd` transfers that ownership to the
            // `Stdio`/child-process machinery, which closes it exactly
            // once (either on drop, if unused, or when `dup2`'d into the
            // child's fd table and then closed post-fork) — never
            // double-closed or leaked, matching this project's existing
            // `create.rs`/`bootstrap.rs`/`start.rs` `from_raw_fd`
            // precedent.
            let dup = |fd: &OwnedFd| -> std::process::Stdio {
                let raw = nix::unistd::dup(fd.as_raw_fd()).expect("dup pty slave");
                unsafe { std::process::Stdio::from_raw_fd(raw) }
            };
            (dup(slave), dup(slave), dup(slave))
        }
        ContainerIo::Pipes {
            stdout_write,
            stderr_write,
            ..
        } => {
            let devnull = std::fs::File::open("/dev/null").context("opening /dev/null for stdin")?;
            // SAFETY: see the identical `dup`/`from_raw_fd` safety note
            // in the `ContainerIo::Pty` arm above — same reasoning
            // applies verbatim to the pipe write ends here.
            let dup = |fd: &OwnedFd| -> std::process::Stdio {
                let raw = nix::unistd::dup(fd.as_raw_fd()).expect("dup pipe write end");
                unsafe { std::process::Stdio::from_raw_fd(raw) }
            };
            (devnull.into(), dup(stdout_write), dup(stderr_write))
        }
    };

    // `cmd` is deliberately scoped to this block, not left as a `main()`-
    // level local: `tokio::process::Command::status()` takes `&mut self`,
    // not `self` — spawning and waiting does NOT consume the `Command`,
    // so the `Stdio` values passed to `.stdin()`/`.stdout()`/`.stderr()`
    // above stay alive as fields of `cmd` for as long as `cmd` itself
    // does, independent of whether the child has exited. Confirmed via a
    // real `/proc/self/fd` dump during development: right after
    // `cmd.status().await` returned successfully, the dup'd child-stdio
    // fds built above were STILL open in this process — not closed by
    // spawning/waiting, only by `cmd` itself being dropped. Left
    // unscoped, `cmd` would otherwise live until `main()` returns (past
    // the entire `daemon::run` call), meaning these extra dup'd copies of
    // the pipes' write-ends / PTY slave would keep the container's stdio
    // artificially "held open" from the shim's own side for its whole
    // life — silently reproducing the exact EOF/EIO-never-fires bug
    // `ContainerIo::into_daemon_io` (see `io.rs`) exists to fix for `io`'s
    // OWN copies. Scoping `cmd` here ensures ITS copies are gone before
    // `daemon::run` (and therefore `into_daemon_io`) ever runs.
    let status = {
        let mut cmd = tokio::process::Command::new(&args.command[0]);
        cmd.args(&args.command[1..])
            .stdin(child_stdin)
            .stdout(child_stdout)
            .stderr(child_stderr);
        cmd.status()
            .await
            .context("spawning and waiting on kestrel-runtime create")?
    };

    // Report status as a single JSON line on THIS process's own stdout —
    // distinct from the container's captured stdio, which lives entirely
    // in `io` above (dup'd fds, never this process's fd 1). kestreld
    // reads exactly one line before treating the shim as handed off.
    // Explicit flush before `daemon::run` redirects this process's own
    // stdout to `/dev/null` (design doc §2 step 5) — `println!`'s per-line
    // auto-flush covers ordinary terminal/pipe use, but making the flush
    // explicit here removes any doubt about ordering relative to that
    // later `dup2`: if the line were still sitting in a userspace buffer
    // when fd 1 gets remapped, the flush would silently write to
    // `/dev/null` instead of the real pipe `kestreld` is reading the
    // handshake from.
    if status.success() {
        println!("{{\"ok\":true}}");
    } else {
        println!("{{\"ok\":false,\"error\":\"kestrel-runtime create exited with {status}\"}}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(1);
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Daemonize, then run the log+attach.sock loop until the container's
    // stdio hits EOF/EIO (see kestrel_shim::daemon's module doc).
    kestrel_shim::daemon::run(args.id, args.run_dir, args.data_dir, io).await
}
