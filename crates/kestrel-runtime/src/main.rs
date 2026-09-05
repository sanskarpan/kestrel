use kestrel_runtime::cli::{build_exec_process, parse_signal, Cli, Command};
use kestrel_runtime::preflight;

/// Every subsystem that logs during a container's lifecycle should open its
/// span with `tracing::info_span!("...", container_id = %id)` so logs from
/// namespaces, cgroups, rootfs, and security setup for the same container
/// can be correlated. This just wires the subscriber so that convention is
/// ready to use — individual subcommand modules are the ones that actually
/// open spans.
///
/// `--verbose` sets `RUST_LOG=debug` when no explicit `RUST_LOG` is present
/// and installs a `debug`-level filter so each setup phase emits a timed
/// span (e.g. `phase="cgroup.create" elapsed_ms=...`). Without it the
/// subscriber honors `RUST_LOG` verbatim (default `warn` if unset).
fn init_tracing(verbose: bool) {
    let filter = if verbose {
        // `RUST_LOG` wins if the caller explicitly set it; otherwise force
        // `debug` so `--verbose` alone is sufficient. `tracing_subscriber`
        // reads `RUST_LOG` only via `from_default_env()`, so we synthesize
        // an EnvFilter at `debug` when the env var is absent.
        if std::env::var("RUST_LOG").is_ok() {
            tracing_subscriber::EnvFilter::from_default_env()
        } else {
            tracing_subscriber::EnvFilter::new("debug")
        }
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Wraps `f` in a timed tracing span named `phase`. When `--verbose` is
/// active (i.e. the subscriber is at `debug`), this emits
/// `phase start` + `phase done elapsed_ms=N` at `info` level so a caller
/// can read the container's birth as a timed narrative. The helper is
/// crate-private so each subcommand in `main.rs` and the deeper
/// `create.rs`/`delete.rs` etc modules can instrument their own phases
/// without re-deriving timing logic.
pub(crate) fn timed_phase<T, E>(phase: &str, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let start = std::time::Instant::now();
    tracing::info!(phase, "starting");
    let res = f();
    let elapsed = start.elapsed();
    match &res {
        Ok(_) => tracing::info!(phase, elapsed_ms = elapsed.as_millis() as u64, "done"),
        Err(_) => tracing::warn!(phase, elapsed_ms = elapsed.as_millis() as u64, "failed"),
    }
    res
}

fn main() -> anyhow::Result<()> {
    // Parse CLI first so `--verbose` can influence the trace subscriber.
    // `clap` is cheap and has no side effects before `init_tracing`.
    let cli = <Cli as clap::Parser>::parse();
    init_tracing(cli.verbose);
    if cli.verbose {
        tracing::info!(verbose = true, "verbose tracing enabled (RUST_LOG=debug)");
    }

    preflight::assert_single_threaded()?;

    if let Err(e) = preflight::check_environment() {
        tracing::warn!(error = %e, "preflight environment checks failed");
    }
    match cli.command {
        Command::Create { id, bundle } => timed_phase("runtime.create", || {
            let b = kestrel_runtime::bundle::load(&bundle)?;
            kestrel_runtime::create::create(&id, &b, &cli.run_dir, &cli.data_dir)
        }),
        Command::Start { id } => timed_phase("runtime.start", || {
            kestrel_runtime::start::start(&id, &cli.run_dir)
        }),
        Command::State { id } => timed_phase("runtime.state", || {
            let state = kestrel_runtime::state_cmd::state(&id, &cli.run_dir)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(())
        }),
        Command::Kill { id, signal, all } => timed_phase("runtime.kill", || {
            let sig = parse_signal(&signal)?;
            kestrel_runtime::kill::kill(&id, &cli.run_dir, &cli.data_dir, sig, all)
        }),
        Command::Delete { id, force } => timed_phase("runtime.delete", || {
            kestrel_runtime::delete::delete(&id, &cli.run_dir, &cli.data_dir, force)
        }),
        Command::Exec { id, command } => timed_phase("runtime.exec", || {
            let process = build_exec_process(&command)?;
            let code = kestrel_runtime::exec_cmd::exec(&id, &cli.run_dir, &process)?;
            std::process::exit(code);
        }),
        Command::Ps => timed_phase("runtime.ps", || {
            for state in kestrel_runtime::ps::list(&cli.run_dir)? {
                println!("{}\t{:?}\t{:?}", state.id, state.status, state.pid);
            }
            Ok(())
        }),
        Command::Pause { id } => timed_phase("runtime.pause", || {
            kestrel_runtime::pause::pause(&id, &cli.run_dir, &cli.data_dir)
        }),
        Command::Resume { id } => timed_phase("runtime.resume", || {
            kestrel_runtime::resume::resume(&id, &cli.run_dir, &cli.data_dir)
        }),
    }
}
