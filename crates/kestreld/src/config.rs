//! `kestreld` configuration: parses `/etc/kestrel/config.toml` (or a path
//! given via `--config`) into the structures below. The shape and every
//! default value here mirror SPEC.md `§17 Configuration` verbatim.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level configuration, one field per `SPEC.md §17` TOML table.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cgroup: CgroupConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub rootless: RootlessConfig,
}

impl Config {
    /// Parse a `kestreld` config file at `path`. Missing sections in the
    /// TOML fall back to each section's documented defaults (`#[serde(default)]`
    /// on every field below), so a partial config file is valid.
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let config: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub socket: String,
    pub http_addr: String,
    pub state_dir: String,
    pub data_dir: String,
    pub metrics_interval_ms: u64,
    /// NOT part of SPEC.md §17's literal TOML block. Added here for Task 9's
    /// `stop` sequencing (`POST /containers/:id/stop`): SIGTERM, poll
    /// `state.json` for `Stopped` up to this many seconds, then SIGKILL —
    /// see `docs/superpowers/specs/2026-08-09-phase9-daemon-design.md` §4's
    /// `stop` row ("grace period (configurable, default matches OCI
    /// convention ~10s)"). Defaults to 10 to match that OCI convention.
    pub stop_grace_period_s: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            socket: "/run/kestrel.sock".to_string(),
            http_addr: "127.0.0.1:7777".to_string(),
            state_dir: "/run/kestrel".to_string(),
            data_dir: "/var/lib/kestrel".to_string(),
            metrics_interval_ms: 1000,
            stop_grace_period_s: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct StorageConfig {
    /// `overlay2` | `fuse-overlayfs` | `vfs`
    pub driver: String,
    pub metacopy: bool,
    pub redirect_dir: bool,
    /// `auto` | `true` | `false` — kept as a string since SPEC.md documents
    /// `"auto"` as a valid value alongside boolean-shaped strings.
    pub userxattr: String,
    pub copyup_scan_interval_s: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            driver: "overlay2".to_string(),
            metacopy: true,
            redirect_dir: true,
            userxattr: "auto".to_string(),
            copyup_scan_interval_s: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct CgroupConfig {
    pub root: String,
    pub parent: String,
    /// `cgroupfs` | `systemd`
    pub manager: String,
    pub psi_enabled: bool,
    pub psi_trigger_stall_us: u64,
    pub psi_trigger_window_us: u64,
}

impl Default for CgroupConfig {
    fn default() -> Self {
        CgroupConfig {
            root: "/sys/fs/cgroup".to_string(),
            parent: "kestrel".to_string(),
            manager: "cgroupfs".to_string(),
            psi_enabled: true,
            psi_trigger_stall_us: 150_000,
            psi_trigger_window_us: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetworkConfig {
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    pub mtu: u32,
    pub iptables: bool,
    /// `pasta` | `slirp4voidnetns` (only the field is parsed here — rootless
    /// networking itself is out of scope through this phase, see design §14).
    pub rootless_backend: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            bridge: "kestrel0".to_string(),
            subnet: "172.29.0.0/16".to_string(),
            gateway: "172.29.0.1".to_string(),
            mtu: 1500,
            iptables: true,
            rootless_backend: "pasta".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecurityConfig {
    pub seccomp_profile: String,
    pub no_new_privs: bool,
    pub default_caps: Vec<String>,
    pub seccomp_notify: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            seccomp_profile: "/etc/kestrel/profiles/seccomp/default.json".to_string(),
            no_new_privs: true,
            default_caps: [
                "CHOWN",
                "DAC_OVERRIDE",
                "FSETID",
                "FOWNER",
                "MKNOD",
                "NET_RAW",
                "SETGID",
                "SETUID",
                "SETFCAP",
                "SETPCAP",
                "NET_BIND_SERVICE",
                "SYS_CHROOT",
                "KILL",
                "AUDIT_WRITE",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            seccomp_notify: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct RootlessConfig {
    pub enabled: bool,
    pub subuid_file: String,
    pub subgid_file: String,
}

impl Default for RootlessConfig {
    fn default() -> Self {
        RootlessConfig {
            enabled: false,
            subuid_file: "/etc/subuid".to_string(),
            subgid_file: "/etc/subgid".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC.md §17's exact example TOML block, verbatim.
    const SPEC_EXAMPLE_TOML: &str = r#"
# /etc/kestrel/config.toml
[daemon]
socket = "/run/kestrel.sock"
http_addr = "127.0.0.1:7777"
state_dir = "/run/kestrel"
data_dir  = "/var/lib/kestrel"
metrics_interval_ms = 1000

[storage]
driver = "overlay2"          # overlay2 | fuse-overlayfs | vfs
metacopy = true
redirect_dir = true
userxattr = "auto"           # auto | true | false
copyup_scan_interval_s = 5

[cgroup]
root = "/sys/fs/cgroup"
parent = "kestrel"
manager = "cgroupfs"         # cgroupfs | systemd
psi_enabled = true
psi_trigger_stall_us = 150000
psi_trigger_window_us = 1000000

[network]
bridge = "kestrel0"
subnet = "172.29.0.0/16"
gateway = "172.29.0.1"
mtu = 1500
iptables = true
rootless_backend = "pasta"   # pasta | slirp4netns

[security]
seccomp_profile = "/etc/kestrel/profiles/seccomp/default.json"
no_new_privs = true
default_caps = ["CHOWN","DAC_OVERRIDE","FSETID","FOWNER","MKNOD","NET_RAW",
                "SETGID","SETUID","SETFCAP","SETPCAP","NET_BIND_SERVICE",
                "SYS_CHROOT","KILL","AUDIT_WRITE"]
seccomp_notify = false

[rootless]
enabled = false
subuid_file = "/etc/subuid"
subgid_file = "/etc/subgid"
"#;

    #[test]
    fn spec_example_round_trips() {
        let parsed: Config = toml::from_str(SPEC_EXAMPLE_TOML).expect("valid TOML");

        assert_eq!(parsed.daemon.socket, "/run/kestrel.sock");
        assert_eq!(parsed.daemon.http_addr, "127.0.0.1:7777");
        assert_eq!(parsed.daemon.state_dir, "/run/kestrel");
        assert_eq!(parsed.daemon.data_dir, "/var/lib/kestrel");
        assert_eq!(parsed.daemon.metrics_interval_ms, 1000);
        // Not present in the SPEC.md TOML block itself; must fall back to
        // its own default via #[serde(default)] on DaemonConfig's struct.
        assert_eq!(parsed.daemon.stop_grace_period_s, 10);

        assert_eq!(parsed.storage.driver, "overlay2");
        assert!(parsed.storage.metacopy);
        assert!(parsed.storage.redirect_dir);
        assert_eq!(parsed.storage.userxattr, "auto");
        assert_eq!(parsed.storage.copyup_scan_interval_s, 5);

        assert_eq!(parsed.cgroup.root, "/sys/fs/cgroup");
        assert_eq!(parsed.cgroup.parent, "kestrel");
        assert_eq!(parsed.cgroup.manager, "cgroupfs");
        assert!(parsed.cgroup.psi_enabled);
        assert_eq!(parsed.cgroup.psi_trigger_stall_us, 150_000);
        assert_eq!(parsed.cgroup.psi_trigger_window_us, 1_000_000);

        assert_eq!(parsed.network.bridge, "kestrel0");
        assert_eq!(parsed.network.subnet, "172.29.0.0/16");
        assert_eq!(parsed.network.gateway, "172.29.0.1");
        assert_eq!(parsed.network.mtu, 1500);
        assert!(parsed.network.iptables);
        assert_eq!(parsed.network.rootless_backend, "pasta");

        assert_eq!(
            parsed.security.seccomp_profile,
            "/etc/kestrel/profiles/seccomp/default.json"
        );
        assert!(parsed.security.no_new_privs);
        assert_eq!(
            parsed.security.default_caps,
            vec![
                "CHOWN",
                "DAC_OVERRIDE",
                "FSETID",
                "FOWNER",
                "MKNOD",
                "NET_RAW",
                "SETGID",
                "SETUID",
                "SETFCAP",
                "SETPCAP",
                "NET_BIND_SERVICE",
                "SYS_CHROOT",
                "KILL",
                "AUDIT_WRITE",
            ]
        );
        assert!(!parsed.security.seccomp_notify);

        assert!(!parsed.rootless.enabled);
        assert_eq!(parsed.rootless.subuid_file, "/etc/subuid");
        assert_eq!(parsed.rootless.subgid_file, "/etc/subgid");

        // The example, taken as a whole, matches Config::default() except
        // for the fields it deliberately overrides (none, in this case --
        // SPEC.md's example already lists every documented default
        // verbatim), so a full-struct comparison against the default is a
        // valid round-trip assertion too.
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn load_from_real_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, SPEC_EXAMPLE_TOML).expect("write config");

        let config = Config::load(&path).expect("load config");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[daemon]\nsocket = \"/tmp/custom.sock\"\n").expect("write config");

        let config = Config::load(&path).expect("load config");
        assert_eq!(config.daemon.socket, "/tmp/custom.sock");
        assert_eq!(config.daemon.http_addr, "127.0.0.1:7777");
        assert_eq!(config.storage, StorageConfig::default());
    }

    #[test]
    fn missing_file_errors() {
        let err = Config::load(Path::new("/nonexistent/kestrel-config.toml"))
            .expect_err("missing file should error");
        assert!(err.to_string().contains("reading config file"));
    }
}
