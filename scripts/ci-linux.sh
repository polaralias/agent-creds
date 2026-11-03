#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ "${1:-}" != --session ]]; then
    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    export XDG_DATA_HOME="$fixture_dir/data"
    export XDG_RUNTIME_DIR="$fixture_dir/runtime"
    mkdir -m 700 "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
    xvfb-run -a dbus-run-session -- bash scripts/ci-linux.sh --session
else
    # A disposable keyring containing synthetic test values only.
    printf '%s' 'synthetic-ci-keyring-only' | gnome-keyring-daemon --unlock --components=secrets
    AGENT_CREDS_TEST_BROWSER=1 bash scripts/check-linux.sh
fi
