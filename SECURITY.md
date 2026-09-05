# Security Policy

> `docs/SECURITY.md` is the design doc (capability defaults, seccomp profile,
> threat model). This file is the **policy**: how to report vulnerabilities
> and what to expect.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x: (pre-release)  |

## Reporting a Vulnerability

**Do not open a public issue for security bugs.** Instead:

1. Use GitHub's **private vulnerability reporting** on this repo
   (Security tab → Report a vulnerability), or
2. Email the maintainer via the address on the GitHub profile.

Include: affected version/commit, steps to reproduce, impact assessment
(container escape, privilege escalation, host DoS), and any logs.

## Response

- Acknowledgement within **72 hours**.
- Fix + patch release as fast as the severity demands; container-escape or
  privilege-escalation reports are treated as critical.
- Credit in the release notes unless you prefer anonymity.

## Scope Notes

Kestrel runs privileged syscalls (`mount`, `pivot_root`, `setns`, seccomp
installation) as root. The threat model in `docs/SECURITY.md` lists known
gaps — reports in those explicitly-documented areas are still welcome, but
please check that doc first.
