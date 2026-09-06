# Benchmarks

Measured in the Lima VM (vz, aarch64, 4 CPU / 8 GiB, Ubuntu 24.04) against
`kestreld` + `kestrel-cli` **debug** builds — treat absolute numbers as
ceiling estimates; release builds will be faster. Method: wall-clock around
daemon HTTP calls (`date +%s%N`), polling `GET /containers/:id` every 100 ms
for `Running` (±100 ms quantization on start figures).

Workload: `alpine:latest` (`/bin/sh -c 'while true; do sleep 1; done'`),
default resources, bridge networking off (`network_mode: null`).

## Results (2026-09-06)

| Operation | Measured | Notes |
|---|---|---|
| `POST /images/pull` alpine (cold, incl. network) | **5 478 ms** | single layer; dominated by download |
| create → `Running` (3 runs) | **15 881 / 14 525 / 14 008 ms** | snapshot + net attach + runtime dance + shim spawn, debug binaries |
| `exec /bin/echo` round-trip (CLI over WS) | **111 ms** | incl. CLI startup + WS handshake |
| `stop` (SIGTERM, sleep-loop workload) | **229 ms** | |
| `delete` (force) | **31 ms** | cgroup/pins/overlay/net teardown |
| `kestreld` RSS (idle, 3 containers) | **≈ 23.5 MB** | debug build |
| `kestrel-shim` RSS per container | **≈ 2.5 MB** | |
| container `memory.current` (sleep loop) | **≈ 5.3 MB** | via `/cgroup` endpoint |

## How to reproduce

```bash
# inside the VM, repo at ~/kestrel
cargo build -p kestreld -p kestrel-cli -p kestrel-runtime -p kestrel-shim
make build-kestrel-init-static
# start kestreld with a scratch state dir (see docs/USER_GUIDE.md),
# then time the same curl sequence as above.
```

## Not yet measured

- Head-to-head vs `runc run` on an identical bundle (runc is present in the
  VM; needs a shared rootfs fixture to be fair — future work).
- Release (`-O`) numbers; expect 2–5× better start latency (debug spawn +
  unofficially instrumented paths dominate).
- Pull throughput vs `docker pull`; exec pty vs pipe overhead; metrics
  sampler CPU at 50+ containers.

Re-run on release builds and update this table before any performance claim
leaves this file.
