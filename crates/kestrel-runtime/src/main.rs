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
