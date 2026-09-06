# Kestrel — Container Runtime from Scratch

**Kestrel** is a from-scratch OCI container runtime, image store, and daemon
built in Rust: all 8 Linux namespaces, cgroups v2, OverlayFS, and NAT
networking without shelling out — the educational counterpoint to `runc`
that shows *why* containers work at the kernel level.

![Kestrel demo: ps, exec, explain](assets/demo.gif)

Start with the [user guide](USER_GUIDE.md) (first container in minutes),
keep the [FAQ](FAQ.md) nearby when something fails, and read the
[architecture spec](https://github.com/sanskarpan/kestrel/blob/main/SPEC.md)
for the kernel-by-kernel design. Source, issues, and releases live on
[GitHub](https://github.com/sanskarpan/kestrel).

| Dashboard (live container) | TUI (ratatui) |
|---|---|
| ![Web dashboard](assets/dashboard.png) | ![TUI](assets/tui.png) |
