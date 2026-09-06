# User Guide — Your First Kestrel Container

This guide walks through pull → run → exec → inspect → cleanup on a native
Linux host (or the Lima VM shell). Every command below was executed against
the real daemon; outputs are actual (ids/timestamps trimmed).

Prerequisites: Linux ≥ 5.11, cgroup v2, root. In the Lima VM you are already
`root`-capable via `sudo -E`; the daemon itself must run as root.

## 1. Start the daemon

```bash
cargo build -p kestreld -p kestrel-cli -p kestrel-runtime -p kestrel-shim
make build-kestrel-init-static   # static PID-1, required inside containers
sudo ./target/debug/kestreld --config /etc/kestrel/config.toml
# listens on 127.0.0.1:7777 and /run/kestrel.sock
```

The CLI binary is `target/debug/kestrel-cli` (package `kestrel-cli`). The
examples below assume it is on `PATH` as `kestrel-cli`; point it elsewhere
with `kestrel-cli --host http://127.0.0.1:7777 ps`.

## 2. Pull an image

```bash
kestrel-cli pull alpine:latest
# streams per-layer progress, ends with:
# {"type":"Complete","chain_ids":["sha256:b2848c02..."]}
```

Raw API equivalent:

```bash
curl -s -N -X POST localhost:7777/images/pull \
  -H 'content-type: application/json' \
  -d '{"reference":"alpine:latest"}'
# SSE events: {"type":"Progress",...} ... {"type":"Complete","chain_ids":[...]}
```

## 3. Run a container

```bash
kestrel-cli run --rm alpine:latest -- /bin/echo hello-from-kestrel
# hello-from-kestrel
```

`run` = create + start + attach; `--rm` deletes on exit. Detached instead:

```bash
ID=$(kestrel-cli run -d alpine:latest -- /bin/sh -c 'while true; do sleep 1; done')
kestrel-cli ps                       # table: id, status, pid, image
kestrel-cli logs $ID                 # container output
```

Raw API equivalent (`tty` is required):

```bash
ID=$(curl -s -X POST localhost:7777/containers \
  -H 'content-type: application/json' \
  -d '{"image":"alpine:latest","cmd":["/bin/sh","-c","while true; do sleep 1; done"],"tty":false}' \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
curl -s -X POST localhost:7777/containers/$ID/start
curl -s localhost:7777/containers/$ID   # {"id":"...","status":"running","pid":...,...}
```

## 4. Exec into it

```bash
kestrel-cli exec -it $ID -- /bin/sh
# / # hostname        <- container UTS namespace
# / # exit
```

Non-interactive: `kestrel-cli exec $ID -- /bin/echo exec-ok` → `exec-ok`.

## 5. Inspect it

```bash
kestrel-cli inspect $ID                  # full JSON (state, pid, network, ...)
kestrel-cli stats --no-stream $ID        # cgroup + PSI snapshot
kestrel-cli ns $ID                       # 8 namespaces with inodes
kestrel-cli explain $ID                  # narrated creation trace
```

## 6. Stop and clean up

```bash
kestrel-cli stop $ID     # SIGTERM, escalates to SIGKILL after grace period
kestrel-cli rm $ID       # delete (use -f to force a running container)
kestrel-cli rmi alpine:latest
```

## 7. Dashboard and TUI

```bash
kestrel-tui                       # lazydocker-style TUI (q quits, ? help)
cd web && npm run dev             # dashboard at :5173, proxies API to :7777
```

The dashboard's Container list, Namespace Explorer, Layer Inspector,
Resources, Network Topology, Security, and Terminal views all read the same
endpoints used above. Attach a container's terminal from View 7 to watch
seccomp violations land in the Security view live.

## What to read next

- `docs/FAQ.md` — when something fails (mount/cgroup/iptables/userns errors)
- `docs/BENCHMARKS.md` — measured start/exec latency and overhead
- `docs/EXPLAIN.md` — annotated `kestrel explain` sample output
- `docs/SECURITY.md` — threat model and known gaps (read before any
  untrusted workload)
