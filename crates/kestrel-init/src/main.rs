// crates/kestrel-init/src/main.rs
//
//! `kestrel-init`'s PID-1 entry point. See
//! docs/superpowers/specs/2026-08-05-phase8-runtime-binary-design.md §1/§3
//! for the full design this wires together: bootstrap receive → rootfs
//! staging → `createContainer` hooks → `pivot_root` → hostname/time-ns →
//! block on the exec FIFO → `startContainer` hooks → block signals + arm
//! the signalfd → fork the entrypoint → reap loop → exit-code plumbing.
//!
//! NOTE for Task 16 (capstone tests): this binary must be built via the
//! `build-kestrel-init-static` Makefile target (statically linked, per
//! Task 5's `-C target-feature=+crt-static` verification), NOT a plain
//! `cargo build -p kestrel-init`. A dynamically-linked `kestrel-init`
//! cannot serve as PID 1 inside a freshly `pivot_root`'d container — the
//! dynamic linker and its shared libraries live on the HOST rootfs, which
//! is no longer reachable once `pivot_root` has swapped `/` to the
//! container's merged rootfs. Using the wrong (dynamic) binary here will
//! not fail at build time; it will fail at container-run time, inside the
//! container, in a way that's easy to misdiagnose as a bug in this
//! `main.rs` rather than a wrong-artifact mistake.

fn main() -> anyhow::Result<()> {
    use anyhow::Context;

    let bootstrap = kestrel_init::bootstrap::receive()?;

    // `bootstrap.state_json_path` is a HOST path (`run_dir/<id>/state.json`
    // — a plain tempdir-rooted path in every caller so far). Two spots
    // below (the post-fork pid update, and the final exit-code write) need
    // to read-modify-write it AFTER `pivot::pivot_root` has already
    // swapped this process's `/` to the container's merged rootfs — at
    // which point the host path is simply gone; nothing under the new
    // root resolves it. Root-caused (Phase 8 Task 16) via a real
    // reproduction: without this, the post-fork pid update's
    // `State::read(&bootstrap.state_json_path)` fails outright with plain
    // `ENOENT`, and because that happens AFTER the entrypoint has already
    // been forked, `main`'s `?`-propagated `Err` exits this process (PID 1
    // of the container's pid namespace) immediately afterward — which the
    // kernel responds to by SIGKILLing every other process in that pid
    // namespace on the spot (`pid_namespaces(7)`), including the
    // just-forked entrypoint, before it ever gets to run at all.
    //
    // Fix: open the state.json's parent directory as an fd BEFORE the
    // pivot (while the host path is still reachable), and use
    // `/proc/self/fd/<fd>` — a "magic symlink" the kernel resolves back to
    // the real underlying directory regardless of the CURRENT mount
    // namespace's root — to keep reaching it afterward. This only works
    // because `/proc` is mounted at `<merged>/proc` before the pivot
    // (`mounts::stage_rootfs`'s `setup_standard_mounts` call) and stays
    // mounted at the container's own `/proc` after it; no new Bootstrap
    // field, no new bind mount, and `kestrel_oci::state::State::read`/
    // `write_atomic` need no changes at all, since this is still just an
    // ordinary path string as far as they're concerned.
    let state_dir_fd = {
        let state_dir = bootstrap
            .state_json_path
            .parent()
            .context("bootstrap.state_json_path has no parent directory")?;
        // `O_CLOEXEC`: this fd must NOT leak across the later `execve` into
        // the container's own entrypoint (`exec::exec_into`, in the forked
        // child below) — it's purely an internal bookkeeping handle for
        // THIS process's own post-pivot state.json access, not something
        // the user's workload should ever see on its own fd table.
        nix::fcntl::open(
            state_dir,
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .with_context(|| format!("opening {} (pre-pivot, to survive pivot_root)", state_dir.display()))?
    };
    let state_json_file_name = bootstrap
        .state_json_path
        .file_name()
        .context("bootstrap.state_json_path has no file name")?;
    // Valid both before and after the pivot below — see the comment above.
    let state_json_path_durable: std::path::PathBuf =
        std::path::PathBuf::from(format!("/proc/self/fd/{state_dir_fd}")).join(state_json_file_name);

    // Phase 9 Task 16: connect to `kestrel-shim`'s `seccomp.sock` NOW,
    // before `pivot_root` below, for the exact same reason
    // `state_dir_fd`/`state_json_path_durable` above are resolved
    // pre-pivot — `bootstrap.seccomp_notify_sink` is a HOST path
    // (`run_dir/<id>/seccomp.sock`), unreachable from inside this
    // process's mount namespace once `pivot_root` has run. Unlike a path,
    // a live socket CONNECTION has no ongoing dependency on the path it
    // was established through, so (unlike `state_json_path_durable`) no
    // `/proc/self/fd/<fd>` trick is needed here — just keep the resulting
    // `OwnedFd` alive across `pivot_root` and the later `fork()` (fork
    // duplicates the whole fd table regardless of mount-namespace changes
    // in between) for `exec::exec_into` to use in the forked child, right
    // before its own `execve`. Root-caused via a real reproduction
    // (`kestreld`'s own Task 16 capstone test): connecting from INSIDE
    // `exec_into` itself (post-pivot, as this task's own plan sketch
    // originally called for) fails with `ENOENT` every time, silently —
    // `exec_into`'s error is discarded by its caller's `std::process::exit
    // (127)` below — which looked like a generic, hard-to-diagnose exec
    // failure until traced back to this exact cause. See
    // `exec::connect_notify_sink`'s own doc comment for the full story.
    let notify_conn: Option<std::os::fd::OwnedFd> = bootstrap
        .seccomp_notify_sink
        .as_deref()
        .map(kestrel_init::exec::connect_notify_sink)
        .transpose()?;

    let merged = kestrel_init::mounts::stage_rootfs(std::path::Path::new("/var/lib/kestrel"), &bootstrap)?;

    let state_bytes = state_json_bytes(&bootstrap)?;
    kestrel_oci::hooks::run_hooks(&bootstrap.hooks.create_container, &state_bytes)?;

    kestrel_init::mounts::pivot(&merged)?;
    kestrel_init::mounts::apply_hostname_and_time(&bootstrap)?;

    kestrel_init::fifo::block_until_started(&bootstrap.fifo_container_path)?;

    kestrel_oci::hooks::run_hooks(&bootstrap.hooks.start_container, &state_bytes)?;

    // Block signals + arm the signalfd BEFORE forking the entrypoint —
    // a signal arriving in the gap between fork and signal-masking
    // could otherwise be missed by the signalfd loop entirely, leaving
    // a zombie unreaped until some unrelated later SIGCHLD happens to
    // trigger a cleanup sweep.
    let mut mask = nix::sys::signal::SigSet::all();
    mask.remove(nix::sys::signal::Signal::SIGSEGV);
    mask.remove(nix::sys::signal::Signal::SIGBUS);
    mask.remove(nix::sys::signal::Signal::SIGILL);
    mask.remove(nix::sys::signal::Signal::SIGFPE);
    mask.thread_block()?;
    let sfd = nix::sys::signalfd::SignalFd::with_flags(&mask, nix::sys::signalfd::SfdFlags::SFD_CLOEXEC)?;

    let entrypoint_pid = match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { child } => {
            // PID 1 (this process) has no further use for its own copy of
            // the pre-pivot seccomp-notify connection — only the forked
            // child (about to exec_into) needs it. Explicit close here
            // rather than letting it linger open for this container's
            // entire remaining lifetime, matching this codebase's
            // established "close your own inherited copy promptly" fd-
            // hygiene convention (e.g. `kestrel-runtime create.rs`'s
            // `host_end`/`init_end` handling).
            drop(notify_conn);
            child
        }
        nix::unistd::ForkResult::Child => {
            // apply_all (caps/no_new_privs/seccomp) + execve — all inside
            // exec_into, applied to THIS (soon-to-be-replaced) child
            // process, not PID 1 itself.
            let _: anyhow::Result<std::convert::Infallible> = kestrel_init::exec::exec_into(
                &bootstrap.process,
                bootstrap.seccomp.as_ref(),
                notify_conn.as_ref().map(std::os::fd::AsFd::as_fd),
            );
            std::process::exit(127); // only reached if exec_into itself returned Err
        }
    };

    // NOTE, so a future reader doesn't reintroduce this: this used to be
    // the spot where `kestrel-init` itself updated `state.json`'s `pid`
    // from its own pid to the entrypoint's — it no longer does. Root-caused
    // (Phase 8 Task 16, via a real reproduction that left `delete()`
    // reporting a live process at "pid 2"): `entrypoint_pid` here (the
    // return value of THIS process's own `fork()` call) is expressed in
    // `kestrel-init`'s OWN pid namespace — the container's — not the
    // RUNTIME's, because `kestrel-init` itself runs as PID 1 of a freshly
    // unshared pid namespace and has no visibility into any OUTER
    // namespace's view of its own children at all. `state.json`'s `pid`
    // field is documented (`kestrel_oci::state::State::pid`'s own doc
    // comment) to be "in the RUNTIME's pid namespace" specifically, so
    // writing the raw local value here (typically a tiny number like `2`)
    // would silently corrupt that field with a namespace-local pid that
    // usually collides with a real, unrelated, always-alive process on the
    // HOST (pid 2 is commonly `kthreadd`) — exactly the false-positive
    // `delete()`'s liveness check (`kill(pid, None)`) hit. Only the
    // RUNTIME side (which already knows kestrel-init's own real,
    // host-relative pid from `create()`'s `run_stages` return value) can
    // correctly resolve the entrypoint's host-relative pid, by reading
    // `/proc/<kestrel-init's host pid>/task/.../children` from ITS OWN
    // (host) namespace — see `kestrel-runtime`'s `start.rs`, which now
    // does exactly this immediately after unblocking this same FIFO.
    let exit_code = kestrel_init::reaper::run_init(entrypoint_pid, &sfd)?;

    // Exit-code plumbing (Phase 8 design §2): write the final outcome to
    // state.json before PID 1 itself exits.
    let mut state = kestrel_oci::state::State::read(&state_json_path_durable)?;
    state.status = kestrel_oci::state::Status::Stopped;
    state.exit_code = Some(exit_code);
    state.write_atomic(&state_json_path_durable)?;

    std::process::exit(exit_code);
}

fn state_json_bytes(bootstrap: &kestrel_oci::bootstrap::Bootstrap) -> anyhow::Result<Vec<u8>> {
    // create.rs (a later task) will already have written a real
    // state.json (status Creating/Created) to bootstrap.state_json_path
    // before kestrel-init ever runs — reading it back byte-for-byte
    // avoids duplicating State-construction logic here and guarantees
    // hooks see exactly the same state a human running `kestrel state
    // <id>` would see at that moment.
    use anyhow::Context;
    std::fs::read(&bootstrap.state_json_path).with_context(|| format!("reading {}", bootstrap.state_json_path.display()))
}
