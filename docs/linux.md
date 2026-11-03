# Linux and WSL

Linux uses AES-256-GCM encrypted records and stores the vault key in a Secret Service keyring, such as GNOME Keyring. An unlocked keyring and a D-Bus user session are required for credential reads and writes. A minimal WSL installation usually needs these configured explicitly. There is no file-based key fallback.

On Ubuntu, install the native build and keyring dependencies:

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libdbus-1-dev gnome-keyring dbus-x11
```

Install Rust with Cargo, rustfmt and Clippy. Build with `cargo build --locked --release`. For ordinary use, run from a desktop or user session whose keyring is unlocked. `status` and `list` work without keyring access because they read cached public metadata only. If the keyring is unavailable, storage fails and the source file is retained.

The browser collector needs a Linux Chrome, Edge or Chromium binary and a graphical display. It does not drive a Windows browser from WSL. WSLg or a desktop session supplies the display; Xvfb can supply an isolated display for automated tests. Browser sandboxing remains enabled by the application.

## Run the checks

From an unlocked Secret Service session:

```sh
bash scripts/check-linux.sh
AGENT_CREDS_TEST_BROWSER=1 bash scripts/check-linux.sh
```

The runner checks formatting, strict linting, the regular test suite and the explicitly enabled native-keyring tests. The optional browser tests open only local fixture pages. The regular suite also checks that an unavailable Secret Service fails closed. Native integration tests are excluded from default `cargo test` because they need a real unlocked keyring and create synthetic per-vault keys in it. Run them in a disposable test account when you want a clean keyring afterward.

For a minimal WSL test account, start a private D-Bus session with `dbus-run-session -- bash`, then unlock that account's GNOME keyring before running the checks. A missing D-Bus session, a locked collection or an unavailable Secret Service is an environment prerequisite failure, not permission to store the master key in plaintext. Never supply a real keyring password in command arguments or a checked-in script.

See [verification](verification.md) for executed results and [security](security.md) for the OS-account trust boundary.
