use kestrel_runtime::cli::{build_exec_process, parse_signal, Cli, Command};
use kestrel_runtime::preflight;

/// Every subsystem that logs during a container's lifecycle should open its
/// span with `tracing::info_span!("...", container_id = %id)` so logs from
/// namespaces, cgroups, rootfs, and security setup for the same container
/// can be correlated. This just wires the subscriber so that convention is
/// ready to use — individual subcommand modules are the ones that actually
/// open spans.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

fn main() -> anyhow::Result<()> {
    init_tracing();

    preflight::assert_single_threaded()?;

    if let Err(e) = preflight::check_environment() {
        tracing::warn!(error = %e, "preflight environment checks failed");
    }

    let cli = <Cli as clap::Parser>::parse();
    match cli.command {
        Command::Create { id, bundle } => {
            let b = kestrel_runtime::bundle::load(&bundle)?;
            kestrel_runtime::create::create(&id, &b, &cli.run_dir, &cli.data_dir)
        }
        Command::Start { id } => kestrel_runtime::start::start(&id, &cli.run_dir),
        Command::State { id } => {
            let state = kestrel_runtime::state_cmd::state(&id, &cli.run_dir)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(())
        }
        Command::Kill { id, signal, all } => {
            let sig = parse_signal(&signal)?;
            kestrel_runtime::kill::kill(&id, &cli.run_dir, &cli.data_dir, sig, all)
        }
        Command::Delete { id, force } => {
            kestrel_runtime::delete::delete(&id, &cli.run_dir, &cli.data_dir, force)
        }
        Command::Exec { id, command } => {
            let process = build_exec_process(&command)?;
            let code = kestrel_runtime::exec_cmd::exec(&id, &cli.run_dir, &process)?;
            std::process::exit(code);
        }
        Command::Ps => {
            for state in kestrel_runtime::ps::list(&cli.run_dir)? {
                println!("{}\t{:?}\t{:?}", state.id, state.status, state.pid);
            }
            Ok(())
        }
        Command::Pause { id } => kestrel_runtime::pause::pause(&id, &cli.run_dir, &cli.data_dir),
        Command::Resume { id } => kestrel_runtime::resume::resume(&id, &cli.run_dir, &cli.data_dir),
    }
}
