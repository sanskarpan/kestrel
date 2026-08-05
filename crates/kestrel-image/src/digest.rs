use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

/// A content digest, `sha256:<64-hex>`. Only SHA-256 is supported — the
/// only algorithm the OCI distribution spec requires implementations to
/// support, and the only one this project's chain-ID/content-store design
/// ever produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    hex: String, // lowercase, 64 chars, no "sha256:" prefix
}

impl Digest {
    pub fn of_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Digest { hex: format!("{:x}", hasher.finalize()) }
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The path fragment this digest maps to under a content store's
    /// `blobs/sha256/` directory.
    pub fn store_relative_path(&self) -> String {
        format!("sha256/{}", self.hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let hex = s.strip_prefix("sha256:").context("digest must start with \"sha256:\"")?;
        bail_unless_valid_hex(hex)?;
        Ok(Digest { hex: hex.to_lowercase() })
    }
}

fn bail_unless_valid_hex(hex: &str) -> Result<()> {
    anyhow::ensure!(hex.len() == 64, "digest hex must be exactly 64 characters, got {}", hex.len());
    anyhow::ensure!(hex.chars().all(|c| c.is_ascii_hexdigit()), "digest hex must be all hex digits");
    Ok(())
}

/// Incrementally hashes bytes as they pass through, for verifying a
/// digest DURING a download rather than after it's fully buffered/written
/// — SPEC.md §10.2's explicit requirement, so a corrupt or malicious blob
/// is rejected before it's fully persisted. Wraps a plain `std::io::Read`;
/// the async registry client (Task 7) uses a parallel async-native
/// approach (hashing each chunk as it arrives from the byte stream) rather
/// than this synchronous wrapper, but both must agree on the same hashing
/// semantics — verified by Task 2's own tests and cross-checked against
/// Task 7's usage.
pub struct VerifyingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: std::io::Read> VerifyingReader<R> {
    pub fn new(inner: R) -> Self {
        VerifyingReader { inner, hasher: Sha256::new() }
    }

    /// Consumes the reader, returning the digest of everything read so far.
    /// Call only after fully reading `inner` (e.g. via `io::copy`).
    pub fn finish(self) -> Digest {
        Digest { hex: format!("{:x}", self.hasher.finalize()) }
    }
}

impl<R: std::io::Read> std::io::Read for VerifyingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_of_bytes_matches_known_sha256() {
        // Verified against `printf '' | sha256sum` inside the project's
        // Lima VM before trusting it, per this project's "verify, don't
        // assume" discipline.
        let d = Digest::of_bytes(b"");
        assert_eq!(d.to_string(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_display_roundtrips_through_from_str() {
        let d = Digest::of_bytes(b"hello world");
        let s = d.to_string();
        let parsed: Digest = s.parse().unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn test_from_str_rejects_missing_prefix() {
        assert!("deadbeef".parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_rejects_wrong_length() {
        assert!("sha256:deadbeef".parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_rejects_non_hex() {
        let bad = format!("sha256:{}", "z".repeat(64));
        assert!(bad.parse::<Digest>().is_err());
    }

    #[test]
    fn test_from_str_lowercases_hex() {
        let upper = format!("sha256:{}", "A".repeat(64));
        let d: Digest = upper.parse().unwrap();
        assert_eq!(d.hex(), "a".repeat(64));
    }

    #[test]
    fn test_verifying_reader_computes_correct_digest_while_passing_bytes_through() {
        let data = b"the quick brown fox";
        let mut vr = VerifyingReader::new(std::io::Cursor::new(data));
        let mut out = Vec::new();
        std::io::copy(&mut vr, &mut out).unwrap();
        assert_eq!(out, data, "reader must pass bytes through unchanged");
        assert_eq!(vr.finish(), Digest::of_bytes(data));
    }
}
