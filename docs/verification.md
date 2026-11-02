# Verification record

Verified on 2 November 2026 on Windows x86-64, with Rust/Cargo 1.99.1, Visual Studio 2022 Build Tools and installed Google Chrome. Test data consists only of synthetic fixture credentials. The original workplace tool was read, not executed; no workplace platform or SSO endpoint was contacted.

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |
| `cargo test --locked` | 20 passed; two headed-browser tests deliberately excluded from the default run |
| `cargo test --locked --test browser_local -- --ignored --nocapture` | Both headed-browser tests passed |
| `cargo build --locked --release` | Passed |
| Release executable `--version`, `--help`, `oauth --help` | Passed; version 0.1.0 and documented command names |

The regular suite includes ten unit tests, six Windows CLI integration tests and four local OAuth protocol tests. Windows CLI tests exercise real current-user DPAPI, encrypted persistence, source removal, metadata/ciphertext tampering, expiry refusal, lock conflicts, dotenv dry run/templates, client-secret configuration, refresh rotation persistence and process exit propagation. OAuth tests bind local mock servers and callbacks; they never invoke a real identity provider. They cover PKCE, forged-state rejection, client-secret post/basic methods, refresh-token rotation/retention and redirect/error suppression.

The headed-browser tests launch an owned fresh profile on loopback fixture pages. The successful flow observes the inert overlay and title prefix before setting an HttpOnly cookie, then checks that the collector returns only the requested value. The failure flow verifies that a same-name cookie on the wrong path is not accepted, capture times out, and `--no-banner` leaves the title and page unmarked. No temporary Agent Credentials browser profiles remained after these runs.

## Not established by this slice

- Native macOS Keychain or Linux Secret Service runtime compatibility. Those backends are implemented but were not compiled or run on their target operating systems here.
- Minimum Rust 1.85 compatibility through an executed build; the declared minimum was not separately qualified.
- Real-provider OAuth interoperability, private-CA/corporate-proxy environments, token revocation or live remote cookie account validity.
- Independent security audit, resistance to hostile same-user execution, forced-termination cleanup, or forensic plaintext erasure. See [security](security.md).

## Repository setup

The repository display name is **Agent Credentials** and the binary/package name is `agent-creds`. The folder is `agent-creds`. A local `main` branch contains the bootstrap; implementation lives on `feat/initial-rust-implementation`. There is no Git remote or external publication. No GitHub description, ruleset or classic branch protection was applied or verified. CODEOWNERS exists locally for the configured maintainer; it has no remote enforcement.

The bootstrap uses the repo-setup Apache-2.0 default for commercial-friendly reuse with notices, plus NOTICE, CONTRIBUTING, AGENTS, CODEOWNERS, dormant release-draft configuration and `repo-admin.json`. `VERSION` and Cargo package version both read 0.1.0. The ignored `local-docs/` directory was created, and `.gitignore` covers local notes, workflow state, build output and common credential staging filenames. The generic names are convenience exclusions; do not rely on them as a secret scanner.

`engineering-workflow` was used for design, delivery and validation. RKE local continuation state is available, with task mode none; no OKF Tasks or upstream skill packages were changed. Future native-platform qualification and release readiness should continue through engineering-workflow before publishing. This is a local implementation delivery, not a public release approval.
