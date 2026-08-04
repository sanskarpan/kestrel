// crates/kestrel-ns/src/types.rs

use nix::sched::CloneFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NsType {
    Mount,
    Uts,
    Ipc,
    Pid,
    Net,
    User,
    Cgroup,
    Time,
}

impl NsType {
    pub fn clone_flag(self) -> CloneFlags {
        match self {
            NsType::Mount => CloneFlags::CLONE_NEWNS,
            NsType::Uts => CloneFlags::CLONE_NEWUTS,
            NsType::Ipc => CloneFlags::CLONE_NEWIPC,
            NsType::Pid => CloneFlags::CLONE_NEWPID,
            NsType::Net => CloneFlags::CLONE_NEWNET,
            NsType::User => CloneFlags::CLONE_NEWUSER,
            NsType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
            // `nix`'s `CloneFlags` has no named flag for this, so
            // `from_bits` would return `None`; `from_bits_retain` accepts
            // the raw bit unconditionally.
            NsType::Time => CloneFlags::from_bits_retain(libc::CLONE_NEWTIME),
        }
    }

    /// Path component under `/proc/<pid>/ns/`.
    pub fn proc_name(self) -> &'static str {
        match self {
            NsType::Mount => "mnt",
            NsType::Uts => "uts",
            NsType::Ipc => "ipc",
            NsType::Pid => "pid",
            NsType::Net => "net",
            NsType::User => "user",
            NsType::Cgroup => "cgroup",
            NsType::Time => "time",
        }
    }
}

/// One line of a `/proc/[pid]/{uid,gid}_map` entry: `container_id host_id
/// size`. Field order here matches the kernel's documented format
/// (ID-inside-ns, ID-outside-ns, length) — `idmap.rs::render_map()` writes
/// them in this exact order, so getting `container_id`/`host_id` swapped
/// here would silently invert which side is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapping {
    /// The ID as seen inside the container's namespace.
    pub container_id: u32,
    /// The ID on the host (the namespace this plan is created from).
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct NamespacePlan {
    pub create: Vec<NsType>,
    pub uid_maps: Vec<IdMapping>,
    pub gid_maps: Vec<IdMapping>,
}

impl NamespacePlan {
    pub fn clone_flags(&self) -> CloneFlags {
        self.create
            .iter()
            .fold(CloneFlags::empty(), |acc, ns| acc | ns.clone_flag())
    }

    pub fn has_user_ns(&self) -> bool {
        self.create.contains(&NsType::User)
    }

    pub fn has_pid_ns(&self) -> bool {
        self.create.contains(&NsType::Pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sched::CloneFlags;

    #[test]
    fn test_all_8_variants_have_distinct_flags() {
        let all = [
            NsType::Mount,
            NsType::Uts,
            NsType::Ipc,
            NsType::Pid,
            NsType::Net,
            NsType::User,
            NsType::Cgroup,
            NsType::Time,
        ];
        let flags: Vec<CloneFlags> = all.iter().map(|n| n.clone_flag()).collect();
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(
                    flags[i], flags[j],
                    "{:?} and {:?} share a flag",
                    all[i], all[j]
                );
            }
        }
    }

    #[test]
    fn test_time_flag_matches_kernel_constant() {
        // CLONE_NEWTIME = 0x00000080, not exposed by nix's CloneFlags.
        assert_eq!(NsType::Time.clone_flag().bits(), 0x0000_0080);
    }

    #[test]
    fn test_proc_name_matches_proc_pid_ns_convention() {
        assert_eq!(NsType::Mount.proc_name(), "mnt");
        assert_eq!(NsType::Net.proc_name(), "net");
        assert_eq!(NsType::Cgroup.proc_name(), "cgroup");
    }

    #[test]
    fn test_plan_clone_flags_unions_all_requested() {
        let plan = NamespacePlan {
            create: vec![NsType::User, NsType::Pid, NsType::Mount],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        let flags = plan.clone_flags();
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(!flags.contains(CloneFlags::CLONE_NEWNET));
    }

    #[test]
    fn test_plan_has_user_ns() {
        let with = NamespacePlan {
            create: vec![NsType::User],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        let without = NamespacePlan {
            create: vec![NsType::Pid],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        assert!(with.has_user_ns());
        assert!(!without.has_user_ns());
    }

    #[test]
    fn test_plan_has_pid_ns() {
        let with = NamespacePlan {
            create: vec![NsType::Pid],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        let without = NamespacePlan {
            create: vec![NsType::User],
            uid_maps: vec![],
            gid_maps: vec![],
        };
        assert!(with.has_pid_ns());
        assert!(!without.has_pid_ns());
    }
}
