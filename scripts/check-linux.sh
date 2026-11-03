#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# Start this script inside an unlocked Secret Service session, for example:
# dbus-run-session -- bash -c 'gnome-keyring-daemon --unlock --components=secrets; bash scripts/check-linux.sh'
# Never put a real keyring password in argv or a checked-in script.
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --test cli_linux -- --ignored
if [[ "${AGENT_CREDS_TEST_BROWSER:-0}" == 1 ]]; then
    cargo test --locked --test browser_local -- --ignored
fi
