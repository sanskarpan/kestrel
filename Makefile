# NOTE (Phase 2+): kestrel-ns and kestrel-cgroup implement real namespace/
# cgroup syscalls that only exist on Linux; kestrel-rootfs and kestrel-image
# (Phase 4) add real mount/pivot_root/mknod syscalls on top; kestrel-security
# and kestrel-init (Phase 5) add real capability/seccomp/prctl syscalls,
# including a pkg-config build dependency on the system's libseccomp-dev.
# kestrel-runtime depends on all of them. As a result the `build`, `test`,
# and `test-root` targets below only work inside the Lima VM (`make
# vm-ssh`) — `cargo build --workspace` on the bare macOS host will fail to
# compile these crates. This is expected: Phase 2's design doc already
# anticipated that every syscall this phase adds "doesn't exist on macOS."
# Phase 0/1's host-agnostic property was scoped to Phase 0/1 only, not the
# whole project.
#
# NOTE (Phase 6): kestrel-image also adds a real registry HTTP client on
# top of the above (async, via tokio — see check-no-tokio's own comment for
# why that doesn't apply to kestrel-runtime). Its one `#[ignore]`d e2e test
# (`pull_e2e`, in crates/kestrel-image/tests/pull_e2e.rs) additionally
# needs real network access to Docker Hub, gated behind its own
# `KESTREL_TEST_NETWORK=1` env var checked inside the test itself — plain
# `#[ignore]` isn't enough to keep it out of `test-root`'s `--ignored`
# sweep below, since that sweep re-includes every ignored test workspace-
# wide. Neither `test` nor `test-root` below run it for real: without
# `KESTREL_TEST_NETWORK=1` set, it just prints a skip message and returns.
# Run it for real with:
#   sudo -E KESTREL_TEST_NETWORK=1 cargo test -p kestrel-image --test pull_e2e -- --ignored --nocapture
#
# NOTE (Phase 7): kestrel-net adds a real bridge/veth network data path (via
# the rtnetlink crate) plus iptables-based NAT/port-publishing on top of the
# above — this crate needs `iptables` present in the VM (see nat.rs's
# DNAT/MASQUERADE chain management). Its root-gated tests manipulate real
# bridges, veths, network namespaces, and iptables nat/filter rules, but
# each such test is fully isolated via `unshare(CLONE_NEWNET)` before it
# runs (see crates/kestrel-net/tests/common/mod.rs's
# `run_in_isolated_netns`) — analogous to how kestrel-rootfs/kestrel-image's
# own tests/common/mod.rs isolates mount-namespace-mutating tests via
# `unshare(CLONE_NEWNS)` + a private MS_PRIVATE|MS_REC remount — so none of
# kestrel-net's test mutations ever touch the VM's actual host network
# state.
.PHONY: build test test-root oci-conformance web-dev tui vm-up vm-ssh vm-provision check-no-tokio build-kestrel-init-static build-lifecycle-fixture-static

build:
	cargo build --workspace

# kestrel-init runs as PID 1 INSIDE the container, after pivot_root has
# already swapped `/` to the container's merged rootfs — at that point the
# host's dynamic linker and shared libraries are no longer reachable, so a
# normal (dynamically-linked) `cargo build -p kestrel-init` output cannot
# actually serve as PID 1. This target is deliberately NOT folded into the
# default `build` above: doing so via a blanket `.cargo/config.toml`
# `[target.*] rustflags` would force `+crt-static` onto every binary this
# workspace builds for aarch64-unknown-linux-gnu — including
# kestrel-runtime and every test binary — which is broader than needed and
# risks unintended effects on binaries that were never meant to be static.
# Confirmed (Phase 8 Task 5) that plain `-C target-feature=+crt-static` on
# the default gnu target produces a genuinely static `kestrel-init` even
# though it depends on kestrel-security's libseccomp FFI binding; musl was
# tried first and rejected (see this plan's Task 5 notes).
#
# IMPORTANT for whoever builds Task 16's capstone test: that test needs to
# actually pivot_root and execve this binary as a real container's PID 1.
# It MUST reference the binary THIS target produces, not the default
# `cargo build`'s dynamically-linked one — using the wrong artifact will
# not fail at build time, only at container-run time, in a way that's easy
# to misdiagnose as a bug in kestrel-init's own logic.
build-kestrel-init-static:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --target aarch64-unknown-linux-gnu -p kestrel-init

# Same rationale as build-kestrel-init-static above, applied to
# kestrel-runtime's `lifecycle_fixture` [[bin]] target (Phase 8 Task 16's
# capstone-test entrypoint fixture): it is exec'd by an ALREADY-pivot_root'd
# kestrel-init INSIDE the container's own mount namespace (see
# crates/kestrel-runtime/tests/fixtures/lifecycle_fixture.rs's own doc
# comment), so a plain (dynamically-linked) `cargo build`/`cargo test`
# output cannot actually run once chroot'd/pivot_root'd into
# `tests/common/mod.rs::build_synthetic_rootfs`'s minimal rootfs, which
# deliberately provides no dynamic linker or libc. Empirically confirmed
# (Task 15) with a real `chroot`: the plain `cargo test`-built
# `CARGO_BIN_EXE_lifecycle_fixture` is dynamically linked and fails with
# ENOENT at exec time in that rootfs; this target's static output does not.
# `build_synthetic_rootfs` requires this exact target's output to exist (at
# target/aarch64-unknown-linux-gnu/debug/lifecycle_fixture) and panics with
# a message pointing back at this target if it's missing or not static.
build-lifecycle-fixture-static:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --target aarch64-unknown-linux-gnu -p kestrel-runtime --bin lifecycle_fixture

test: check-no-tokio
	cargo test --workspace

check-no-tokio:
	./scripts/check-no-tokio-in-runtime.sh

# sudo -E preserves the invoking user's environment (PATH, CARGO_HOME), but
# root's own PATH (via sudo's secure_path) doesn't include ~/.cargo/bin, so
# plain `sudo cargo` fails with "command not found" even with -E. The
# $(command -v cargo || echo "$HOME/.cargo/bin/cargo") resolves cargo's
# absolute path in THIS (non-root) shell first — before sudo ever runs — so
# sudo just execs a fixed path rather than doing its own PATH lookup; the
# fallback covers hosts where cargo isn't on PATH at all yet. The doubled
# $$ is Make's own escaping so a single literal $ reaches the shell.
#
# --skip test_join_order_matters: that specific test is permanently
# #[ignore]d (see crates/kestrel-ns/tests/join.rs) because it can't be
# reproduced under real root — running it here would turn a documented,
# expected skip into a reported failure, so it's excluded by name rather
# than left to fail. cargo test --skip matches by substring, not exact name,
# so if a future test's name happens to contain this string it would also
# be silently skipped — currently unique in the workspace (grep-checked).
# If this test is ever renamed, update this line too; nothing else will
# warn you.
test-root:
	sudo -E $$(command -v cargo || echo "$$HOME/.cargo/bin/cargo") test --workspace -- --ignored --skip test_join_order_matters

oci-conformance:
	@echo "oci-conformance requires runtime-tools + the Lima VM (Phase 13)." >&2
	@exit 1

web-dev:
	cd web && bun run dev

tui:
	cargo run -p kestrel-tui

vm-up:
	limactl start --tty=false .lima/kestrel.yaml

vm-ssh:
	limactl shell kestrel

vm-provision:
	limactl start --tty=false .lima/kestrel.yaml || (limactl stop kestrel && limactl start --tty=false .lima/kestrel.yaml)
