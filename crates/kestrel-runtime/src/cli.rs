// crates/kestrel-runtime/src/cli.rs
//
//! Command-line surface for the `kestrel-runtime` binary: argument parsing
//! (`Cli`/`Command`) plus the two small, real translation functions
//! `main.rs` needs to go from raw CLI input to the typed values every
//! subcommand module (Tasks 3, 8-13) actually expects — `parse_signal`
//! (`kill`'s `signal: String` -> `nix::sys::signal::Signal`) and
//! `build_exec_process` (`exec`'s `command: Vec<String>` ->
//! `kestrel_oci::runtime::Process`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kestrel_oci::runtime::{Process, ProcessBuilder};
use nix::sys::signal::Signal;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(long, default_value = "/run/kestrel")]
    pub run_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/kestrel")]
    pub data_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum Command {
    Create {
        id: String,
        #[arg(long)]
        bundle: PathBuf,
    },
    Start {
        id: String,
    },
    State {
        id: String,
    },
    Kill {
        id: String,
        signal: String,
        #[arg(long)]
        all: bool,
    },
    Delete {
        id: String,
        #[arg(long)]
        force: bool,
    },
    Exec {
        id: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    Ps,
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
}

/// Parses a `kestrel kill <id> <signal>` signal argument into a real
/// `nix::sys::signal::Signal`, accepting a bare number ("9"), a bare name
/// ("KILL"), or the full `SIG`-prefixed name ("SIGKILL"), case-insensitively.
///
/// `nix::sys::signal::Signal` DOES implement `FromStr` in this workspace's
/// nix 0.29 (`nix::sys::signal::signal::impl FromStr for Signal`,
/// `src/sys/signal.rs`) — but only for the exact uppercase, `SIG`-prefixed
/// spelling (e.g. `"SIGKILL"`, not `"kill"` or `"9"`). Rather than hand-copy
/// nix's own name table into a manual match (which would silently drift if
/// nix ever adds/removes a signal), this normalizes the input to that exact
/// shape (uppercase, `SIG`-prefixed) and delegates to nix's real `FromStr`
/// impl. Numeric input is tried first via `Signal::try_from(i32)` (also a
/// real nix impl, not hand-rolled), since a normalized numeric string isn't
/// meaningful input to the name path.
pub fn parse_signal(raw: &str) -> Result<Signal> {
    if let Ok(n) = raw.parse::<i32>() {
        return Signal::try_from(n).with_context(|| format!("invalid signal number: {n}"));
    }

    let upper = raw.to_ascii_uppercase();
    let name = if upper.starts_with("SIG") {
        upper
    } else {
        format!("SIG{upper}")
    };
    name.parse::<Signal>()
        .map_err(|_| anyhow::anyhow!("invalid signal: {raw:?} (expected a name like KILL/SIGKILL or a number like 9)"))
}

/// Builds a minimal `Process` for `kestrel exec <id> <command...>` from the
/// CLI's raw command tokens.
///
/// **`ProcessBuilder::default()` is not a blank slate.** oci-spec's
/// hand-written `impl Default for Process` (see also this project's own
/// `kestrel-security/tests/apply.rs` note discovering the same thing) bakes
/// in real values for every unconfigured field: `user` = uid 0/gid 0,
/// `capabilities` = `Some({CAP_AUDIT_WRITE, CAP_KILL, CAP_NET_BIND_SERVICE})`
/// — a bounding set that notably EXCLUDES `CAP_SETUID`/`CAP_SETGID` —
/// `no_new_privileges` = `true`, `rlimits` = `[NOFILE: 1024]`, and `env` =
/// `[PATH=..., TERM=xterm]`.
///
/// That missing `CAP_SETUID`/`CAP_SETGID` matters in general because
/// `kestrel_security::apply::apply_all`'s step 4 unconditionally calls
/// `setresuid`/`setresgid` to `process.user()`'s uid/gid — after step 2 has
/// already applied `process.capabilities()`'s bounding set. But it's a
/// non-issue for THIS use case specifically: `exec`'s target user is left at
/// the builder's default (uid 0/gid 0), and `setresuid`/`setresgid` to a uid
/// the calling process already holds never requires CAP_SETUID/CAP_SETGID —
/// only crossing to a genuinely different uid/gid does (see
/// `apply_all`'s own doc comment). `exec_cmd::exec`'s forked child is still
/// whatever identity it already had after `join_namespaces` (typically the
/// same root identity `kestrel-runtime` itself runs as), so the default
/// user/capabilities/no_new_privileges/rlimits/env are all safe to leave
/// alone here. Only `args` (the whole point of the CLI's `command` argument)
/// and `cwd` (the plan's explicit "/" default) need to be set explicitly.
pub fn build_exec_process(command: &[String]) -> Result<Process> {
    anyhow::ensure!(
        !command.is_empty(),
        "exec requires at least one command argument"
    );
    ProcessBuilder::default()
        .args(command.to_vec())
        .cwd("/")
        .build()
        .map_err(|e| anyhow::anyhow!("building exec process: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signal_numeric() {
        assert_eq!(parse_signal("9").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("15").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_name_with_sig_prefix() {
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_name_without_sig_prefix() {
        assert_eq!(parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
        assert_eq!(parse_signal("USR1").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn test_parse_signal_case_insensitive() {
        assert_eq!(parse_signal("kill").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("sigkill").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("Kill").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SigKill").unwrap(), Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_rejects_invalid_input() {
        assert!(parse_signal("not-a-signal").is_err());
        assert!(parse_signal("").is_err());
        assert!(parse_signal("9999999999").is_err());
        assert!(parse_signal("0").is_err());
    }

    #[test]
    fn test_build_exec_process_sets_args_and_cwd() {
        let process = build_exec_process(&["echo".to_string(), "hi".to_string()]).unwrap();
        assert_eq!(
            process.args().clone().unwrap(),
            vec!["echo".to_string(), "hi".to_string()]
        );
        assert_eq!(process.cwd(), std::path::Path::new("/"));
    }

    #[test]
    fn test_build_exec_process_rejects_empty_command() {
        assert!(build_exec_process(&[]).is_err());
    }
}
