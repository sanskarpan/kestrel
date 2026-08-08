// crates/kestrel-runtime/tests/common/mod.rs

//! Shared test helpers for Task 16's capstone `tests/lifecycle.rs` (and any
//! other integration test file under `tests/` that needs a synthetic
//! container rootfs). NOT a standalone test binary itself — `cargo test`
//! only auto-discovers files directly under `tests/`, so this module is
//! meant to be pulled in via `mod common;` from a real test entry point
//! (e.g. `tests/lifecycle.rs`), matching Rust's standard `tests/common/
//! mod.rs` convention for code shared across multiple integration test
//! binaries without itself becoming one.
//!
//! IMPORTANT for whoever wires this in: `env!("CARGO_BIN_EXE_<name>")`
//! (used below) is resolved by cargo/rustc AT COMPILE TIME, and only for
//! crates that are real integration-test entry points (a `.rs` file
//! directly under `tests/`) — cargo only sets `CARGO_BIN_EXE_*` env vars
//! for those compilation units, not for `tests/common/mod.rs` in
//! isolation (which has no `Cargo.toml`-visible target of its own; it's
//! just source text `mod`-included into whichever test file pulls it in).
//! Verified (Task 15) that this module does NOT compile/link standalone
//! and is NOT meant to — it only works once `mod common;`'d into a real
//! `tests/*.rs` file that itself depends (transitively, via this
//! function) on the `lifecycle_fixture` `[[bin]]` target existing in this
//! crate's `Cargo.toml`, which makes `CARGO_BIN_EXE_lifecycle_fixture`
//! available to every integration test binary in this crate.
//!
//! Also note (Task 15 finding, see `tests/fixtures/lifecycle_fixture.rs`'s
//! own doc comment for the full reasoning): the fixture binary this
//! function copies in needs to be the STATICALLY linked build (`cargo
//! build --target aarch64-unknown-linux-gnu` with `RUSTFLAGS="-C target-
//! feature=+crt-static"`, produced by the Makefile's
//! `build-lifecycle-fixture-static` target), not a plain `cargo
//! test`-built dynamically linked one. Confirmed (Task 15 spec-compliance
//! review, with a real `chroot`) that `env!("CARGO_BIN_EXE_
//! lifecycle_fixture")` — cargo/rustc's normal way of locating a test's
//! sibling `[[bin]]` artifact — resolves to the DYNAMICALLY linked build
//! under a plain `cargo test` invocation, and a dynamically-linked binary
//! alone inside this bare synthetic rootfs (no loader, no `.so`s) fails at
//! exec time with ENOENT once actually `chroot`/`pivot_root`'d into.
//! Deliberately does NOT use `env!("CARGO_BIN_EXE_lifecycle_fixture")`
//! below for exactly this reason: that env var is a silent trap here, not
//! a shortcut. Instead, `build_synthetic_rootfs` locates the static
//! artifact directly at the fixed path `build-lifecycle-fixture-static`
//! produces, and panics with an actionable message (rather than silently
//! falling back to the dynamic default) if that artifact is missing OR
//! does not actually look static — so run `make
//! build-lifecycle-fixture-static` before any test that calls this
//! function.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the statically-linked `lifecycle_fixture` artifact produced by
/// the Makefile's `build-lifecycle-fixture-static` target — mirrors
/// `build-kestrel-init-static`'s own `target/<triple>/debug/<bin>` output
/// convention (see that Makefile target's comment). Computed from
/// `CARGO_MANIFEST_DIR` (this crate's own directory, resolved at compile
/// time) rather than trusting a hardcoded absolute path, since the
/// workspace's `target/` dir is two levels up from
/// `crates/kestrel-runtime` and this repo has no `.cargo/config.toml`
/// override of that default location.
fn static_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture")
}

/// Builds a minimal synthetic rootfs DIRECTORY (not a tar — Task 16's
/// tests create real OCI bundles, which need an already-extracted rootfs
/// directory per Task 8's "plain bundle" resolution, not a
/// layered/tarball image) at `dest`, containing the `lifecycle_fixture`
/// fixture binary at the fixed path `<dest>/fixture` (mode 0o755).
/// Returns `dest` unchanged, for chaining into bundle-construction code.
///
/// Panics loudly (rather than silently copying a broken artifact) if the
/// statically-linked fixture hasn't been built yet, or if whatever is
/// found at that path doesn't actually look statically linked (in case a
/// future rebuild accidentally overwrites it with a dynamic build).
pub fn build_synthetic_rootfs(dest: &Path) -> PathBuf {
    std::fs::create_dir_all(dest).unwrap();

    let fixture_path = static_fixture_path();
    if !fixture_path.exists() {
        panic!(
            "static lifecycle_fixture artifact not found at {}\n\
             Run `make build-lifecycle-fixture-static` first. The plain `cargo test`-built \
             CARGO_BIN_EXE_lifecycle_fixture is dynamically linked and will NOT run once \
             chroot'd/pivot_root'd into this synthetic rootfs (see tests/common/mod.rs's own doc \
             comment for why).",
            fixture_path.display()
        );
    }

    // Belt-and-suspenders: verify the artifact actually found at this path
    // really is static, in case someone later rebuilds a plain (dynamic)
    // binary over the same target path by mistake. Shells out to `file`
    // rather than parsing the ELF header ourselves — this workspace has no
    // ELF-parsing crate, and `file` is already this whole phase's
    // established manual-verification tool for static-linkedness.
    let file_output = Command::new("file")
        .arg(&fixture_path)
        .output()
        .unwrap_or_else(|e| panic!("run `file {}`: {e}", fixture_path.display()));
    let file_stdout = String::from_utf8_lossy(&file_output.stdout);
    if !file_output.status.success() || file_stdout.contains("dynamically linked") {
        panic!(
            "lifecycle_fixture artifact at {} does not look statically linked (`file` reported: {:?}).\n\
             Rebuild it with `make build-lifecycle-fixture-static`.",
            fixture_path.display(),
            file_stdout.trim()
        );
    }

    std::fs::copy(&fixture_path, dest.join("fixture")).unwrap_or_else(|e| {
        panic!("copy {} to {}: {e}", fixture_path.display(), dest.join("fixture").display())
    });
    std::fs::set_permissions(dest.join("fixture"), std::fs::Permissions::from_mode(0o755)).unwrap();
    dest.to_path_buf()
}
