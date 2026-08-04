// crates/kestrel-ns/src/inode.rs

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::types::NsType;

/// Reads the inode number a namespace symlink points at, e.g.
/// `/proc/1234/ns/net` -> `net:[4026531840]` -> `4026531840`.
pub fn read_ns_inode(pid: Pid, ns: NsType) -> Result<u64> {
    let path = format!("/proc/{pid}/ns/{}", ns.proc_name());
    let target = std::fs::read_link(&path).with_context(|| format!("reading link {path}"))?;
    let target = target
        .to_str()
        .context("ns link target is not valid UTF-8")?;
    parse_ns_link_target(target).with_context(|| format!("parsing ns link target {target:?}"))
}

fn parse_ns_link_target(target: &str) -> Result<u64> {
    let inner = target
        .split_once('[')
        .and_then(|(_, rest)| rest.strip_suffix(']'))
        .context("expected `type:[inode]` format")?;
    inner.parse().context("inode component is not numeric")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NsType;
    use nix::unistd::getpid;

    #[test]
    fn test_read_own_mount_ns_inode() {
        // /proc/self/ns/mnt always exists and always parses.
        let inode = read_ns_inode(getpid(), NsType::Mount).unwrap();
        assert!(inode > 0);
    }

    #[test]
    fn test_different_ns_types_have_different_inodes() {
        let mnt = read_ns_inode(getpid(), NsType::Mount).unwrap();
        let net = read_ns_inode(getpid(), NsType::Net).unwrap();
        assert_ne!(mnt, net);
    }

    #[test]
    fn test_parse_ns_link_target() {
        assert_eq!(
            parse_ns_link_target("net:[4026531840]").unwrap(),
            4026531840
        );
        assert_eq!(
            parse_ns_link_target("mnt:[4026531841]").unwrap(),
            4026531841
        );
    }

    #[test]
    fn test_parse_ns_link_target_rejects_garbage() {
        assert!(parse_ns_link_target("not-a-ns-link").is_err());
    }
}
