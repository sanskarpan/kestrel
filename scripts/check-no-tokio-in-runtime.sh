#!/usr/bin/env bash
# scripts/check-no-tokio-in-runtime.sh
#
# kestrel-runtime must stay single-threaded with no async runtime (Rule #2,
# PROMPT.md). tokio transitively spawning a thread makes setns(CLONE_NEWUSER)
# fail with EINVAL in a way that's very hard to trace back to this file.
set -euo pipefail

if ! tree_output=$(cargo tree -p kestrel-runtime --edges normal 2>&1); then
    echo "FAIL: 'cargo tree -p kestrel-runtime' itself failed — fix the build before this check is meaningful." >&2
    echo "$tree_output" >&2
    exit 1
fi

if echo "$tree_output" | grep -qE '(^| )tokio v'; then
    echo "FAIL: kestrel-runtime depends on tokio (directly or transitively)." >&2
    echo "This violates PROMPT.md Rule #2 — see the comment in preflight.rs." >&2
    echo "$tree_output" | grep -E '(^| )tokio v' >&2
    exit 1
fi

echo "OK: kestrel-runtime has no tokio dependency."
