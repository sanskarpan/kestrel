// crates/kestrel-ns/src/idmap.rs

use std::fs;
use std::io;

use anyhow::{Context, Result};
use nix::unistd::Pid;

use crate::types::IdMapping;

/// Writes the uid/gid mappings for the user namespace of `pid`, in the one
/// order the kernel allows.
///
/// Two kernel invariants drive the structure here:
///
/// - **One write per namespace.** `/proc/[pid]/{uid,gid}_map` each accept
///   exactly one `write(2)` call for the lifetime of the namespace — every
///   mapping line must be assembled (via [`render_map`]) and written in a
///   single call, not appended incrementally.
/// - **CVE-2014-8989 ordering.** `gid_map` must not be written until
///   `/proc/[pid]/setgroups` has been set to `deny`. Without that, an
///   unprivileged process writing `gid_map` gets `EPERM` — and if it were
///   otherwise permitted, a process could map a group it belongs to, then
///   call `setgroups()` to drop it, escaping a negative ACL (a file with
///   `group foo: ---`). `setgroups` doesn't exist on kernels older than
///   3.19, so a missing file there is expected and not an error.
///
/// Returns an error (without touching `/proc`) if either map is empty,
/// since an empty map is silently accepted by `fs::write` (no syscall is
/// even issued for a zero-length buffer) and would leave the namespace's
/// id mapping completely unset with no error signal at all.
pub fn write_id_maps(pid: Pid, uid_maps: &[IdMapping], gid_maps: &[IdMapping]) -> Result<()> {
    anyhow::ensure!(
        !uid_maps.is_empty(),
        "write_id_maps called with empty uid_maps for pid {pid}"
    );
    anyhow::ensure!(
        !gid_maps.is_empty(),
        "write_id_maps called with empty gid_maps for pid {pid}"
    );

    let base = format!("/proc/{pid}");

    fs::write(format!("{base}/uid_map"), render_map(uid_maps))
        .with_context(|| format!("writing uid_map for pid {pid}: {uid_maps:?}"))?;

    // Deny setgroups before gid_map — see CVE-2014-8989 note above.
    match fs::write(format!("{base}/setgroups"), "deny") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::debug!(pid = %pid, "setgroups file absent, assuming pre-3.19 kernel");
        }
        Err(e) => return Err(e).context("denying setgroups"),
    }

    fs::write(format!("{base}/gid_map"), render_map(gid_maps))
        .with_context(|| format!("writing gid_map for pid {pid}: {gid_maps:?}"))?;
    Ok(())
}

pub fn render_map(maps: &[IdMapping]) -> String {
    maps.iter()
        .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::run_isolated;
    use nix::sched::{unshare, CloneFlags};
    use nix::unistd::{getgid, getuid};
    use std::fs;

    #[test]
    fn test_render_map_formats_lines() {
        let maps = [
            IdMapping {
                container_id: 0,
                host_id: 1000,
                size: 1,
            },
            IdMapping {
                container_id: 1,
                host_id: 100000,
                size: 65536,
            },
        ];
        assert_eq!(render_map(&maps), "0 1000 1\n1 100000 65536");
    }

    #[test]
    fn test_render_map_empty() {
        assert_eq!(render_map(&[]), "");
    }

    #[test]
    fn test_write_id_maps_rejects_empty_maps() {
        // Must fail before touching /proc at all -- no fork/unshare needed,
        // any Pid value works since the check short-circuits first.
        let pid = nix::unistd::getpid();
        let some_mapping = [IdMapping {
            container_id: 0,
            host_id: 1000,
            size: 1,
        }];

        let err = write_id_maps(pid, &[], &some_mapping).unwrap_err();
        assert!(err.to_string().contains("empty"), "error was: {err}");

        let err = write_id_maps(pid, &some_mapping, &[]).unwrap_err();
        assert!(err.to_string().contains("empty"), "error was: {err}");
    }

    #[test]
    fn test_setgroups_deny_required_before_gid_map() {
        // Proves the CVE-2014-8989 constraint empirically, in a real
        // unprivileged user namespace, so the ordering never gets "cleaned
        // up" by a future refactor. Must run in an isolated single-threaded
        // child (see test_util::run_isolated).
        run_isolated(|| {
            let uid = getuid();
            let gid = getgid();
            unshare(CloneFlags::CLONE_NEWUSER).expect("unshare(CLONE_NEWUSER)");
            let pid = nix::unistd::getpid();

            // Write uid_map directly (bypassing write_id_maps) so we can
            // attempt gid_map BEFORE setgroups=deny and observe the EPERM
            // this whole ordering exists to avoid.
            fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n")).unwrap();
            let err = fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))
                .expect_err("gid_map without setgroups=deny must fail");
            assert_eq!(err.raw_os_error(), Some(libc::EPERM));

            fs::write(format!("/proc/{pid}/setgroups"), "deny").unwrap();
            fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))
                .expect("gid_map after setgroups=deny must succeed");
        });
    }

    #[test]
    fn test_write_id_maps_end_to_end() {
        run_isolated(|| {
            let uid = getuid();
            let gid = getgid();
            unshare(CloneFlags::CLONE_NEWUSER).expect("unshare(CLONE_NEWUSER)");
            let pid = nix::unistd::getpid();

            write_id_maps(
                pid,
                &[IdMapping {
                    container_id: 0,
                    host_id: uid.as_raw(),
                    size: 1,
                }],
                &[IdMapping {
                    container_id: 0,
                    host_id: gid.as_raw(),
                    size: 1,
                }],
            )
            .expect("write_id_maps");

            let uid_map = fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
            // The kernel formats /proc/[pid]/uid_map with fixed-width
            // right-justified columns on read-back (e.g. "         0
            // 501          1\n"), regardless of the single-space format
            // written — so comparison must normalize whitespace rather
            // than substring-match the write format.
            let fields: Vec<&str> = uid_map.split_whitespace().collect();
            assert_eq!(fields, vec!["0", uid.to_string().as_str(), "1"]);
        });
    }
}
