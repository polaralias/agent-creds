# Design and acceptance

The outcome is a generic local credential broker implemented in Rust. Service endpoints, cookie names, OAuth clients and scopes are supplied explicitly by the user.

## Implementation shape

`cli` owns command policy and child execution. `model` defines version-independent credential data and input validation. `vault` owns locking, native protection, metadata binding and atomic persistence. `browser` owns a disposable Chromium process and bounded DevTools calls. `oauth` owns generic authorization code/refresh flow, provider validation and the loopback callback.

One encrypted record transaction binds metadata and value. Cookie capture requests one cookie for one URL. Windows calls DPAPI directly. OAuth uses provider-neutral configuration. Raw-secret export and expired-credential overrides are not exposed. Dotenv import and blank templates provide bulk setup with strict collision and parser behaviour.

## Behaviour-to-verification matrix

| Feature / invariant | Observable acceptance | Verification |
|---|---|---|
| Store and inject | File is removed only after persistence; child receives intended value; parent unchanged; child exit code preserved | Windows and Linux CLI integration |
| No routine export | Status, templates and failure output omit fixture secrets; no `get` command | CLI integration and source review |
| Stored integrity | Expired, metadata-tampered or corrupt credentials prevent child launch | Windows and Linux CLI integration |
| Deterministic execution | Arguments after the program survive with or without `--`; duplicate destination variables fail | Parser and CLI integration |
| Concurrent mutation | Second broker refuses a held lock | Windows and Linux CLI integration |
| Cookie selection | Only explicitly named cookie is returned; unrelated cookies excluded; duplicate matches fail | Cookie unit tests and local browser fixture |
| Browser UX | HttpOnly capture works after inert notice/title appear | Explicit local headed-browser integration |
| PKCE and state | RFC7636 vector matches; forged/duplicate state and wrong path cannot authorize | Unit tests and local OAuth flow |
| Generic OAuth configuration | User endpoints/scopes/client auth accepted; security parameter overrides rejected | Validation and local flow tests |
| Refresh replay | Rotation saved; absent replacement retains latest refresh token | Local token-server tests and CLI persistence test |
| Endpoint failure | Redirect not followed; response body suppressed | Local token-server failure test |
| Dotenv safety | Dry run writes nothing; source retained by default; syntax, interpolation and duplicates rejected | Parser and CLI tests |

## Browser experiment

Hypothesis: installed Chromium's DevTools protocol supports named HttpOnly-cookie capture and a persistent inert notice without an additional browser automation runtime. Expected result: a local page observes the notice/title, then sets an HttpOnly cookie, and the Rust collector captures only that named value. Falsifier: the browser cannot expose that cookie or reliably instrument the owned page under the local fixture. Two inconclusive assumption-related failures require reconsidering the browser adapter rather than weakening acceptance. Fixture or compiler defects are implementation failures, not evidence against the hypothesis.

## Scope and limitations

The tool has a CLI-first interface. Provider-specific options fit explicit authorization parameters; token-endpoint extensions, custom CA/proxy support, revocation, device grant, DPoP and OIDC are outside the initial contract. Cookie expiry is a declared local deadline, not a server validity check. Multi-entry imports are preflighted but do not have an all-or-nothing filesystem transaction. Windows and Ubuntu 24.04 under WSL2 are verified; macOS and other Linux environments still require native qualification. See [security](security.md) and [verification](verification.md).
