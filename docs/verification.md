# Verification record

Verified on 2 November 2026 on Windows x86-64, with Rust/Cargo 1.99.1, Visual Studio 2022 Build Tools and installed Google Chrome. Test data consists only of synthetic fixture credentials. All integration services use synthetic loopback fixtures.

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |
| `cargo test --locked` | 20 passed; two headed-browser tests deliberately excluded from the default run |
| `cargo test --locked --test browser_local -- --ignored --nocapture` | Both headed-browser tests passed |
| `cargo build --locked --release` | Passed |
| Release executable `--version`, `--help`, `oauth --help` | Passed; version 0.1.0 and documented command names |

The regular suite includes ten unit tests, six Windows CLI integration tests and four local OAuth protocol tests. Windows CLI tests exercise real current-user DPAPI, encrypted persistence, source removal, metadata/ciphertext tampering, expiry refusal, lock conflicts, dotenv dry run/templates, client-secret configuration, refresh rotation persistence and process exit propagation. OAuth tests bind local mock servers and callbacks; they never invoke a real identity provider. They cover PKCE, forged-state rejection, client-secret post/basic methods, refresh-token rotation/retention and redirect/error suppression.

The headed-browser tests launch an owned fresh profile on loopback fixture pages. The successful flow observes the inert overlay and title prefix before setting an HttpOnly cookie, then checks that the collector returns only the requested value. The failure flow verifies that a same-name cookie on the wrong path is not accepted, capture times out, and `--no-banner` leaves the title and page unmarked. No temporary agent-creds browser profiles remained after these runs.

## Ubuntu 24.04 under WSL2

Verified on 2 November 2026 using WSL 2.7.3, kernel 6.6.114.1-microsoft-standard-WSL2, Rust/Cargo 1.99.1, GNOME Keyring 46.1 and Google Chrome 156.0.8078.79. Tests ran as a dedicated non-root user, with a real unlocked Secret Service over a private D-Bus session and a display provided by Xvfb. Browser sandboxing remained enabled. All service endpoints and credentials were synthetic fixtures.

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |
| `cargo test --locked` | 15 passed; five environment-dependent tests excluded |
| `cargo test --locked --test cli_linux -- --ignored` | Three native-keyring integration tests passed |
| `cargo test --locked --test browser_local -- --ignored` | Both Linux browser tests passed |
| `cargo build --locked --release` | Passed |
| Linux release executable `--version`, `oauth --help` | Passed on 3 November 2026; version 0.1.0 |

The 20 executed Linux tests cover the common unit/OAuth suite, real Secret Service-backed encryption across process restarts, private vault permissions, encrypted writes, child injection and exit propagation, metadata-only status without keyring access, expiry/tamper refusal, lock contention and refresh-token rotation persistence. An unavailable Secret Service refuses storage, retains the source and writes no credential record. The browser tests verify HttpOnly capture with an inert overlay/title and wrong-path-cookie timeout with the banner disabled.

No application-code change was required by the Linux run. The Linux test runner is [scripts/check-linux.sh](../scripts/check-linux.sh); prerequisites are in [Linux and WSL](linux.md). Local setup and test logs are ignored under `local-docs/wsl/`. The Linux release executable is retained locally at `target/linux-release/agent-creds`. The isolated test distribution is named `AgentCredsTest` and was stopped after verification; Docker Desktop was not modified.

## Repository publication setup (3 November 2026)

The public repository, CLI, browser overlay and package metadata use the name agent-creds. VERSION, Cargo.toml, Cargo.lock and CLI --version agree at 0.1.0. A build-time check refuses version drift, and the version updater has three passing tests covering tag/mirror mismatch, coordinated bumps and invalid input.

Windows verification passed 21 regular Rust tests and both headed-browser fixtures. Linux verification passed 16 regular Rust tests, three native-keyring integration tests and both serial browser fixtures. The browser transport now retries short socket read timeouts within a bounded 15-second operation deadline; a delayed-response regression test covers that path. This fixes false connection-loss errors under heavy machine load without weakening cookie selection or expiry checks.

Strict linting and formatting passed on both platforms. Windows/Linux release builds, archive content/checksum checks and Cargo source-package verification passed. actionlint 1.7.12 validated all GitHub workflows. Redacted Gitleaks scans of a tracked-file export and Git history found no leaks; ignored vaults, logs and virtual-machine data are excluded from the publication surface. The installed RKE directory scan was interrupted because it traversed ignored WSL disk data; the bounded export and history scans supplied the actual evidence.

Release automation is configured but no version tag or published release is created by repository bootstrap. See [releases](releases.md) for the publication trigger and [AGENTS.md](../AGENTS.md) / [CLAUDE.md](../CLAUDE.md) for agent guidance.

## Not established by this slice

- Native macOS Keychain runtime compatibility and other Linux distributions or desktop keyring implementations. Ubuntu 24.04 under WSL2 with GNOME Keyring is covered above.
- Minimum Rust 1.85 compatibility through an executed build; the declared minimum was not separately qualified.
- Real-provider OAuth interoperability, private-CA/corporate-proxy environments, token revocation or live remote cookie account validity.
- Independent security audit, resistance to hostile same-user execution, forced-termination cleanup, or forensic plaintext erasure. See [security](security.md).

## Repository setup

The repository, CLI and package are named `agent-creds`. The GitHub repository is [polaralias/agent-creds](https://github.com/polaralias/agent-creds). The initial implementation and Linux qualification were completed locally before remote bootstrap. Governance and release automation are described in [releases](releases.md); live repository settings should be checked in GitHub when relying on them.

The bootstrap uses the repo-setup Apache-2.0 default for commercial-friendly reuse with notices, plus NOTICE, CONTRIBUTING, AGENTS, CODEOWNERS, dormant release-draft configuration and `repo-admin.json`. `VERSION` and Cargo package version both read 0.1.0. The ignored `local-docs/` directory was created, and `.gitignore` covers local notes, workflow state, build output and common credential staging filenames. The generic names are convenience exclusions; do not rely on them as a secret scanner.

`engineering-workflow` was used for design, delivery and validation. RKE local continuation state is available, with task mode none; no OKF Tasks or upstream skill packages were changed. Future macOS and additional Linux qualification and release readiness should continue through engineering-workflow before publishing. This verification record does not authorize publishing a version release.
