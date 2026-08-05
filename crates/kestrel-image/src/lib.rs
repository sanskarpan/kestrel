pub mod apply;
pub mod auth;
pub mod digest;
pub mod manifest;
pub mod pull;
pub mod reference;
pub mod registry;
pub mod store;

/// Fork/namespace tests aside, this crate's fixture-building helper is also
/// shared by other crates' integration tests (e.g. `kestrel-rootfs/tests/
/// lifecycle.rs`, via a `[dev-dependencies]` edge). Not `#[cfg(test)]`-gated
/// for the same reason as `kestrel_ns::test_util`: `tests/*.rs` integration
/// binaries — in this crate and in dependents — compile against the crate's
/// normal public API, not its unit-test cfg. Intended for test code only;
/// not part of the crate's operational surface.
#[doc(hidden)]
pub mod test_util {
    use std::io::Cursor;

    use tar::{Builder, Header};

    /// Builds a tar archive from `entries` (path, contents) pairs via the
    /// `tar` crate's own validated `Builder::append_data` path. As of `tar`
    /// 0.4.46 that path rejects absolute paths and `..` components at build
    /// time, so this helper can only construct well-formed archives — good
    /// enough for ordinary fixture layers, but deliberately NOT usable for
    /// `apply_layer`'s own path-traversal tests, which need to reach
    /// `safe_join`'s guard via a raw-header write instead (kept local to
    /// `kestrel-image/tests/apply.rs`, not exposed here).
    pub fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, Cursor::new(*contents)).unwrap();
        }
        builder.into_inner().unwrap()
    }
}
