#!/usr/bin/env bash
# One-command demo for native Linux (needs root + cgroup v2).
# macOS users: use the Lima VM instead (`make vm-up`, see README).
#
#   sudo ./scripts/demo-linux.sh
#
# Builds (debug), starts a scratch daemon, pulls alpine, runs a hello
# container, and leaves the daemon running with pointers to the TUI,
# dashboard, and USER_GUIDE. Idempotent-ish: re-runs share /var/lib/kestrel.
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: this demo needs native Linux; on macOS use the Lima VM (make vm-up)" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root: sudo $0" >&2
  exit 1
fi
if [ "$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ]; then
  echo "error: cgroup v2 required at /sys/fs/cgroup (boot with systemd.unified_cgroup_hierarchy=1)" >&2
  exit 1
fi
# sudo's secure_path drops the user's ~/.cargo/bin, so plain `sudo $0`
# can't find cargo (same trap `make test-root` works around via
# `$(command -v cargo)` resolution before sudo runs). Recover it here.
if ! command -v cargo >/dev/null; then
  for cand in "/home/${SUDO_USER:-}/.cargo/bin" "$HOME/.cargo/bin" /home/*/.cargo/bin; do
    if [ -x "$cand/cargo" ]; then
      export PATH="$cand:$PATH"
      break
    fi
  done
fi
for tool in cargo curl python3; do
  command -v "$tool" >/dev/null || { echo "error: missing $tool" >&2; exit 1; }
done
# rustup toolchains live in the cargo owner's $HOME ($HOME under sudo is
# /root, which has no toolchain). Build with the owner's HOME so rustup
# resolves the stable toolchain; runtime steps don't depend on $HOME.
# <cargo> is $HOME/.cargo/bin/cargo — three dirnames up is $HOME.
export CARGO_OWNER_HOME
CARGO_OWNER_HOME=$(dirname "$(dirname "$(dirname "$(command -v cargo)")")")

cd "$(dirname "$0")/.."
echo "==> building (debug)…"
HOME="$CARGO_OWNER_HOME" cargo build -p kestreld -p kestrel-cli -p kestrel-runtime -p kestrel-shim
if [ ! -x target/aarch64-unknown-linux-gnu/debug/kestrel-init ] && [ ! -x target/debug/kestrel-init ]; then
  echo "==> building static kestrel-init…"
  HOME="$CARGO_OWNER_HOME" make build-kestrel-init-static >/dev/null
fi

RUNDIR=$(mktemp -d /tmp/kestrel-demo.XXXXXX)
PORT=17777
cat > "$RUNDIR/cfg.toml" <<EOF
[daemon]
socket = "$RUNDIR/k.sock"
http_addr = "127.0.0.1:$PORT"
state_dir = "$RUNDIR"
data_dir = "/var/lib/kestrel"
EOF
mkdir -p /var/lib/kestrel/cgroups
mountpoint -q /var/lib/kestrel/cgroups || mount -t cgroup2 none /var/lib/kestrel/cgroups
./target/debug/kestreld --config "$RUNDIR/cfg.toml" >"$RUNDIR/daemon.log" 2>&1 &
for _ in $(seq 1 100); do
  [ -S "$RUNDIR/k.sock" ] && break
  sleep 0.2
done
[ -S "$RUNDIR/k.sock" ] || { echo "error: daemon never created $RUNDIR/k.sock; see $RUNDIR/daemon.log" >&2; exit 1; }
BASE="http://127.0.0.1:$PORT"
echo "==> pulling alpine:latest…"
curl -s -N -X POST "$BASE/images/pull" -H 'content-type: application/json' \
  -d '{"reference":"alpine:latest"}' | tail -n 1
echo "==> running hello container…"
ID=$(curl -s -X POST "$BASE/containers" -H 'content-type: application/json' \
  -d '{"image":"alpine:latest","cmd":["/bin/echo","hello-from-kestrel"],"tty":false}' \
  | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4)
[ -n "$ID" ] || { echo "error: container create returned no id" >&2; exit 1; }
curl -s -X POST "$BASE/containers/$ID/start" >/dev/null
sleep 2
echo "==> logs:"
curl -s "$BASE/containers/$ID/logs"
echo "==> container ${ID:0:12} is running; daemon state in $RUNDIR"
echo "    TUI:       ./target/debug/kestrel-tui  (KESTREL_HOST=$BASE)"
echo "    dashboard: cd web && npm run dev  (proxies to :7777; point proxy at $PORT or set KESTREL_HOST)"
echo "    guide:     docs/USER_GUIDE.md"
echo "    cleanup:   curl -X POST $BASE/containers/$ID/stop; curl -X DELETE '$BASE/containers/$ID?force=true'; kill %1"
