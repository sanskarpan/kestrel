// crates/kestrel-ns/src/rootless.rs

use anyhow::{Context, Result};

use crate::types::IdMapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubIdRange {
    pub start: u32,
    pub count: u32,
}

impl SubIdRange {
    /// A single contiguous range maps container ids [0, count) onto
    /// host ids [start, start+count).
    pub fn to_id_mappings(self) -> Vec<IdMapping> {
        vec![IdMapping {
            container_id: 0,
            host_id: self.start,
            size: self.count,
        }]
    }
}

/// Parses `/etc/subuid`/`/etc/subgid`-format content (`name:start:count`
/// per line) for the given username. Malformed lines are skipped, not
/// fatal — a single bad line elsewhere in the file shouldn't block a
/// lookup that would otherwise succeed.
///
/// Returns only the FIRST matching line for `username`. A file with
/// multiple ranges allocated to the same user (legal in `/etc/subuid`'s
/// format, e.g. after a re-allocation) has its later entries silently
/// ignored — this is an intentional simplification for kestrel's current
/// scope (single contiguous range per user), not an oversight.
pub fn parse_subid_range(contents: &str, username: &str) -> Result<SubIdRange> {
    contents
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.splitn(3, ':');
            let name = parts.next()?;
            if name != username {
                return None;
            }
            let start = parts.next()?.parse().ok()?;
            let count = parts.next()?.parse().ok()?;
            Some(SubIdRange { start, count })
        })
        .with_context(|| format!("no subuid/subgid entry for {username:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBUID: &str = "\
sanskar:100000:65536
root:231072:65536
";

    #[test]
    fn test_parse_subuid_finds_matching_user() {
        let range = parse_subid_range(SUBUID, "sanskar").unwrap();
        assert_eq!(
            range,
            SubIdRange {
                start: 100000,
                count: 65536
            }
        );
    }

    #[test]
    fn test_parse_subuid_unknown_user_rejected() {
        assert!(parse_subid_range(SUBUID, "ghost").is_err());
    }

    #[test]
    fn test_parse_subuid_malformed_line_skipped_not_fatal() {
        let with_garbage = "not-a-valid-line\nsanskar:100000:65536\n";
        let range = parse_subid_range(with_garbage, "sanskar").unwrap();
        assert_eq!(
            range,
            SubIdRange {
                start: 100000,
                count: 65536
            }
        );
    }

    #[test]
    fn test_build_single_range_id_mapping() {
        let range = SubIdRange {
            start: 100000,
            count: 65536,
        };
        let maps = range.to_id_mappings();
        assert_eq!(
            maps,
            vec![crate::types::IdMapping {
                container_id: 0,
                host_id: 100000,
                size: 65536
            }]
        );
    }
}
