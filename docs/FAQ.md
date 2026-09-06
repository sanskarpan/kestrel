# FAQ & Troubleshooting

## `pivot_root` / `mount` failures

**`failed to make / private ... needs CAP_SYS_ADMIN`**
You are not root (or not in a user namespace with the needed caps). Run the
daemon and privileged tests as root: `sudo -E cargo test ...`. Inside Lima,
use `limactl shell kestrel` then `sudo -E`.

**`new_root must be a mount point` / `EINVAL` from `pivot_root`**
The overlay was not mounted at the new root, or `/` is still `MS_SHARED`.
`pivot_root` requires the new root to be a mount point and the tree private —
kestrel does both automatically; if you hit this by hand you skipped the
self-bind-mount or the `MS_REC|MS_PRIVATE` remount (see `docs/OVERLAY.md`).

**Host mounts changed after a run**
A mount leaked out of the container's namespace — almost always a missing
`MS_PRIVATE|MS_REC` remount before mounting. `test_host_mountinfo_unchanged`
guards this in CI-gated VM tests; report it as a bug with
`/proc/self/mountinfo` before/after.

## cgroup failures

**`unified_cgroup_hierarchy=1` / "not cgroup v2"**
Kestrel is v2-only. Boot with `systemd.unified_cgroup_hierarchy=1`, or in a
container use a cgroupv2-enabled runtime. Verify:
`stat -f /sys/fs/cgroup` should report type `cgroup2fs`.

**`no such file or directory` writing `cgroup.procs` / controller files**
The controller is not enabled in the parent (`cgroup.subtree_control`).
Kestrel enables `+cpu +memory +io +pids` walking root→parent itself and never
in the leaf (the no-internal-process rule). If you manage cgroups by hand,
enable controllers top-down.

**OOM confusion: exit code 137 vs `oom_kill`**
The authoritative OOM signal is the `oom_kill` counter in `memory.events`,
not the exit code. Kestrel reports both (`kestrel stats`, `/pressure`).

## Network failures

**`operation not supported` creating bridges / veth**
Missing `CAP_SYS_ADMIN` in the host netns, or `CONFIG_BRIDGE_NETFILTER` off.
The daemon auto-loads `br_netfilter` where possible; otherwise
`sudo modprobe br_netfilter` and set `net.ipv4.ip_forward=1`.

**Published port unreachable from host**
Check the DNAT + hairpin MASQUERADE rules exist
(`iptables -t nat -L KESTREL-PREROUTING`) and that nothing else owns the host
port. `kestrel net topology` shows bridges, veth peers, and NAT rules.

**Two containers can't reach each other**
They must share a bridge (`--network bridge`, the default) — `none` gives
loopback only, `host` shares the host stack. See `kestrel ns tree`.

## User namespace failures

**`unshare(CLONE_NEWUSER): EPERM` / `gid_map ... EPERM`**
Unprivileged userns is blocked: Ubuntu needs
`kernel.apparmor_restrict_unprivileged_userns=0`, and `setgroups` must be
`deny` before `gid_map` (CVE-2014-8989 — enforced, never reordered).
Rootless also needs `newuidmap`/`newgidmap` + `/etc/subuid` entries.

## Image pull failures

**`401` then failure / token errors**
The registry challenge flow (`GET /v2/` → `WWW-Authenticate` → token with
`scope`) needs working DNS + HTTPS egress + correct clock (token expiry).
Retry with backoff is built in for 429/5xx; auth failures are fatal fast.

**Digest mismatch, nothing persisted**
The blob was corrupt mid-stream (or a registry bug). Safe by design:
streaming verification rejects before anything is written. Retry the pull.

## Test failures

**`mount: ... already mounted` in `lifecycle.rs`**
Run with `--test-threads=1` (required: `make test-root` does this). Parallel
mounts against the shared `/var/lib/kestrel/cgroups` collide — a harness
constraint, not a product bug.

**Privileged tests fail on stock GitHub runners**
Expected: runners restrict unprivileged userns. CI enables what it can
(`apparmor_restrict_unprivileged_userns=0`); the full privileged matrix runs
in the Lima VM gate (`make test-root`).

**Privileged tests fail in Lima with cgroup/namespace errors**
Stop any running demo daemon first (`stop` + `delete` every container, kill
`kestreld`, unmount anything you mounted under `/var/lib/kestrel`, remove
stale `bundles/`/`containers/`/`snapshots/`). The suite assumes a quiescent
machine: a live daemon's cgroups, mounts, and images collide with the tests'
assertions (verified: 7 spurious failures with a demo running, 22/22 green
after cleanup).

## Still stuck?

Open an issue with: kernel version, cgroup version, Lima-vs-native, commit
SHA, exact command, and the full error (kestrel errors always name the
syscall, its arguments, and the likely fix — paste all three).
