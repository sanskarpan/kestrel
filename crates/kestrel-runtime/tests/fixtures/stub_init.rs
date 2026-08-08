// crates/kestrel-runtime/tests/fixtures/stub_init.rs
//
//! Stand-in "kestrel-init" used only by
//! `tests/create_pins_namespaces.rs`. `create::create()`'s
//! `child_action` closure `execv`s into a sibling binary literally named
//! `kestrel-init` (see `create.rs`'s `resolve_kestrel_init_path`) once
//! createRuntime hooks succeed. That test only cares about proving
//! `create()` pins the container's namespaces correctly — it has no need
//! to exercise the real `kestrel-init`'s full pivot_root/mount/exec-
//! entrypoint machinery (that's exhaustively covered elsewhere, e.g.
//! `kestrel-init/tests/exec_via_kestrel_init.rs`).
//!
//! What the test DOES need is for the forked process to stay alive
//! indefinitely once it's execve'd into this binary, so its namespaces
//! remain valid, live pin targets for the whole duration of the test
//! (rather than racing the test's own pinning/assertions against this
//! process exiting). This binary's only job is exactly that: block
//! forever. The test SIGKILLs + reaps it during cleanup.

fn main() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
