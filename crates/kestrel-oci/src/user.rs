use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Error)]
pub enum UserResolveError {
    #[error("unknown user {0:?} in /etc/passwd")]
    UnknownUser(String),
    #[error("unknown group {0:?} in /etc/group")]
    UnknownGroup(String),
    #[error("malformed /etc/passwd or /etc/group entry: {0}")]
    Malformed(String),
}

struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
}

fn parse_passwd(passwd: &str) -> Result<Vec<PasswdEntry>, UserResolveError> {
    passwd
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 4 {
                return Err(UserResolveError::Malformed(line.to_string()));
            }
            let uid = fields[2]
                .parse()
                .map_err(|_| UserResolveError::Malformed(line.to_string()))?;
            let gid = fields[3]
                .parse()
                .map_err(|_| UserResolveError::Malformed(line.to_string()))?;
            Ok(PasswdEntry {
                name: fields[0].to_string(),
                uid,
                gid,
            })
        })
        .collect()
}

fn group_gid(group: &str, name: &str) -> Result<u32, UserResolveError> {
    for line in group
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&name) {
            return fields
                .get(2)
                .and_then(|g| g.parse().ok())
                .ok_or_else(|| UserResolveError::Malformed(line.to_string()));
        }
    }
    Err(UserResolveError::UnknownGroup(name.to_string()))
}

/// Resolves `spec` (one of `uid`, `uid:gid`, `name`, `name:group`) against
/// the **container's** `/etc/passwd` and `/etc/group` contents, passed in by
/// the caller — never the host's. Callers in later phases read those two
/// files from the mounted-but-not-yet-pivoted rootfs and pass their
/// contents here.
pub fn resolve_user(
    spec: &str,
    passwd: &str,
    group: &str,
) -> Result<ResolvedUser, UserResolveError> {
    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };

    let uid_from_number = user_part.parse::<u32>().ok();

    let entries = parse_passwd(passwd)?;
    let (uid, default_gid) = if let Some(uid) = uid_from_number {
        let default_gid = entries
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.gid)
            .unwrap_or(0);
        (uid, default_gid)
    } else {
        let entry = entries
            .iter()
            .find(|e| e.name == user_part)
            .ok_or_else(|| UserResolveError::UnknownUser(user_part.to_string()))?;
        (entry.uid, entry.gid)
    };

    let gid = match group_part {
        None => default_gid,
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => group_gid(group, g)?,
        },
    };

    Ok(ResolvedUser { uid, gid })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
app:x:1000:1000:app:/home/app:/bin/sh
";
    const GROUP: &str = "\
root:x:0:
nogroup:x:65534:
app:x:1000:
";

    #[test]
    fn test_numeric_uid_only() {
        let r = resolve_user("1000", PASSWD, GROUP).unwrap();
        assert_eq!(
            r,
            ResolvedUser {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn test_numeric_uid_not_in_passwd_defaults_gid_zero() {
        let r = resolve_user("9999", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 9999, gid: 0 });
    }

    #[test]
    fn test_numeric_uid_gid() {
        let r = resolve_user("1000:1000", PASSWD, GROUP).unwrap();
        assert_eq!(
            r,
            ResolvedUser {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn test_name_only_uses_passwd_gid() {
        let r = resolve_user("app", PASSWD, GROUP).unwrap();
        assert_eq!(
            r,
            ResolvedUser {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn test_name_colon_group() {
        let r = resolve_user("app:root", PASSWD, GROUP).unwrap();
        assert_eq!(r, ResolvedUser { uid: 1000, gid: 0 });
    }

    #[test]
    fn test_unknown_name_rejected() {
        assert!(resolve_user("ghost", PASSWD, GROUP).is_err());
    }

    #[test]
    fn test_unknown_group_name_rejected() {
        assert!(resolve_user("app:ghost-group", PASSWD, GROUP).is_err());
    }

    #[test]
    fn test_malformed_passwd_line_rejected() {
        let bad_passwd = "app:x:notanumber:1000:app:/home/app:/bin/sh\n";
        let err = resolve_user("app", bad_passwd, GROUP).unwrap_err();
        assert!(matches!(err, UserResolveError::Malformed(_)));
    }

    #[test]
    fn test_malformed_group_line_rejected() {
        let bad_group = "app:x:notanumber:\n";
        let err = resolve_user("app:app", PASSWD, bad_group).unwrap_err();
        assert!(matches!(err, UserResolveError::Malformed(_)));
    }
}
