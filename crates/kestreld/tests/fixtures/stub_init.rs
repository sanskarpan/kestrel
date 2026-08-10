// crates/kestreld/tests/fixtures/stub_init.rs
//
//! Stand-in "kestrel-init" used only by this crate's own root-gated
//! `recover_registry` test (`src/main.rs`'s `#[cfg(test)] mod tests`).
//! `kestrel_runtime::create::create()`'s `child_action` closure `execv`s
//! into a sibling binary literally named `kestrel-init` (see
//! `kestrel-runtime`'s `create.rs::resolve_kestrel_init_path`) once
//! createRuntime hooks succeed. That test only needs a real, on-disk
//! `state.json` with a live (non-`Stopped`) status and a real pid to
//! recover — it has no need to exercise the real `kestrel-init`'s full
//! pivot_root/mount/exec-entrypoint machinery, which is exhaustively
//! covered elsewhere (`kestrel-init`'s and `kestrel-runtime`'s own test
//! suites).
//!
//! Verbatim copy of `kestrel-runtime`'s own `tests/fixtures/stub_init.rs`
//! fixture: block forever, so the forked process stays alive (and its
//! namespaces/pid stay valid) for the whole duration of the test. The
//! test SIGKILLs + reaps it during cleanup.

fn main() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
