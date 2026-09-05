## Summary
<!-- What changed and why. Link issues with Closes #N. -->

## Verification
<!-- Check all that apply; privileged-test evidence belongs here for runtime changes. -->
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` (via Lima on macOS)
- [ ] `cargo test --workspace`
- [ ] Lima privileged suite (`make test-root`) — paste result summary
- [ ] `npm --prefix web run build` + `npm --prefix web run lint`
- [ ] `CHECKLIST.md` boxes touched only with functional evidence
