// crates/kestrel-init/tests/fixtures/setuid_check.rs

//! Test fixture, not part of the real kestrel-init binary. Exits 0 if the
//! EFFECTIVE uid is non-root (proving no_new_privs blocked this setuid-
//! root binary from elevating), exits 1 if it's root (proving it did
//! elevate — a real bug in the no_new_privs pipeline).
fn main() {
    let euid = nix::unistd::geteuid();
    std::process::exit(if euid.is_root() { 1 } else { 0 });
}
