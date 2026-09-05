# Contributing to Kestrel

## The One Rule: Use the Lima VM

Kestrel calls `mount`, `pivot_root`, `umount2`, and `unshare` against real
kernel state. **A bad `pivot_root` or `umount` can wedge your host — develop
only inside the disposable Lima VM** (`make vm-up` / `make vm-ssh`).
See `README.md` → "VM Warning" for details.

## Workflow

1. Fork, then branch from `main` (`feat/...`, `fix/...`, `chore/...`).
2. Inside the VM (`limactl shell kestrel`, repo at `~/kestrel`):
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   sudo -E $(command -v cargo) test --workspace -- --ignored --skip test_join_order_matters --test-threads=1
   ```
   On macOS hosts `make lint` routes clippy through Lima automatically.
3. Frontend: `npm --prefix web run build` and `npm --prefix web run lint`
   (zero warnings; `npm ci` for reproducible installs).
4. Open a PR against `main`. CI must be green; privileged-test evidence
   (Lima `test-root` output) belongs in the PR body for runtime changes.
5. Keep `CHECKLIST.md` boxes honest: check a box only with functional
   evidence, and link it.

## Conventions

- Every `unsafe` block carries a `// SAFETY:` comment; crate roots deny
  `clippy::undocumented_unsafe_blocks`.
- `kestrel-runtime` stays single-threaded and `tokio`-free
  (`scripts/check-no-tokio-in-runtime.sh` enforces it).
- Error messages name the failing syscall, its arguments, and the likely fix.
- `docs/superpowers/` is historical agent working material — read-only
  context, not a pattern to extend. Canonical references are `SPEC.md`,
  `CHECKLIST.md`, and the per-phase docs in `docs/`.
