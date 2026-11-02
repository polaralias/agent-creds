# Design and acceptance

The outcome is a generic local credential broker, implemented independently in Rust after inspecting the reference documentation and selected source. This is a source-informed rewrite, not a claim of legal clean room isolation. The reference remains outside the repository. No platform-specific URL, cookie list, tenant routing or AWS SSO implementation is retained.

## Implementation shape

`cli` owns command policy and child execution. `model` defines version-independent credential data and input validation. `vault` owns locking, native protection, metadata binding and atomic persistence. `browser` owns a disposable Chromium process and bounded DevTools calls. `oauth` owns generic authorization code/refresh flow, provider validation and the loopback callback.

Unlike the reference's separate index and keystore, one encrypted record transaction binds metadata and value. Unlike its platform-cookie collector, capture requests one cookie for one URL. Unlike a subprocess keystore bridge, Windows calls DPAPI directly. OAuth is a new provider-neutral implementation. `get`, `--allow-expired`, AWS login and tenant-specific assume-user handling are intentionally omitted. Dotenv import and blank templates preserve useful workflows with stricter collision and parser behaviour.

## Behaviour-to-verification matrix

| Feature / invariant | Observable acceptance | Verification |
|---|---|---|
| Store and inject | File is removed only after persistence; child receives intended value; parent unchanged; child exit code preserved | Windows CLI integration |
| No routine export | Status, templates and failure output omit fixture secrets; no `get` command | CLI integration and source review |
| Stored integrity | Expired, metadata-tampered or corrupt credentials prevent child launch | Windows CLI integration |
| Deterministic execution | Arguments after the program survive with or without `--`; duplicate destination variables fail | Parser and CLI integration |
| Concurrent mutation | Second broker refuses a held lock | Windows CLI integration |
| Cookie selection | Only explicitly named cookie is returned; unrelated cookies excluded; duplicate matches fail | Cookie unit tests and local browser fixture |
| Browser UX | HttpOnly capture works after inert notice/title appear | Explicit local headed-browser integration |
| PKCE and state | RFC7636 vector matches; forged/duplicate state and wrong path cannot authorize | Unit tests and local OAuth flow |
| Generic OAuth configuration | User endpoints/scopes/client auth accepted; security parameter overrides rejected | Validation and local flow tests |
| Refresh replay | Rotation saved; absent replacement retains latest refresh token | Local token-server tests and CLI persistence test |
| Endpoint failure | Redirect not followed; response body suppressed | Local token-server failure test |
| Dotenv safety | Dry run writes nothing; source retained by default; syntax, interpolation and duplicates rejected | Parser and CLI tests |

## Browser experiment

Hypothesis: installed Chromium's DevTools protocol can replace the optional Node/Playwright dependency while keeping named HttpOnly-cookie capture and a persistent inert notice. Expected result: a local page observes the notice/title, then sets an HttpOnly cookie, and the Rust collector captures only that named value. Falsifier: the browser cannot expose that cookie or reliably instrument the owned page under the local fixture. Two inconclusive assumption-related failures require reconsidering the browser adapter rather than weakening acceptance. Fixture or compiler defects are implementation failures, not evidence against the hypothesis.

## Scope and limitations

The repository is local only with a CLI-first interface. Provider-specific options fit explicit authorization parameters; token-endpoint extensions, custom CA/proxy support, revocation, device grant, DPoP and OIDC are outside the initial contract. Cookie expiry is a declared local deadline, not a server validity check. Multi-entry imports are preflighted but do not have an all-or-nothing filesystem transaction. macOS/Linux are implementation targets requiring native qualification; Windows is the verified platform for this slice. See [security](security.md) and [verification](verification.md).
