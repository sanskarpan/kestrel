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
.PHONY: build test test-root oci-conformance web-dev tui vm-up vm-ssh vm-provision check-no-tokio

build:
	cargo build --workspace

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
