# agent-creds

`agent-creds` is a local credential broker written in Rust. Import credentials from files, collect a named browser cookie, or authorize a generic OAuth client, then inject the credential into a child process. Normal CLI output contains metadata only.

agent-creds provides provider-neutral credential storage, cookie capture and local OAuth. Source and development are hosted at [polaralias/agent-creds](https://github.com/polaralias/agent-creds).

## Build and install

Requires Rust 1.85 or later and platform build tools. Windows uses native DPAPI, macOS uses Keychain-backed encryption, and Linux requires an available Secret Service keyring. There is no plaintext fallback. Windows and Ubuntu 24.04 under WSL2 are verified. macOS and other Linux environments still require native qualification. See [Linux and WSL setup](docs/linux.md) for keyring prerequisites and repeatable checks.

```powershell
cargo build --locked --release
cargo install --locked --path .
agent-creds --help
```

If Cargo is not on PATH, use `& "$env:USERPROFILE\.cargo\bin\cargo.exe"` in PowerShell. `scripts/check.ps1` runs formatting, linting and automated tests. No Node runtime, Playwright or browser download is needed. Cookie capture uses installed Chrome, Edge or Chromium.

## Store and use a credential

Create the input file yourself, outside agent context, then:

```powershell
agent-creds store service-token --from-file .\token.secret --env SERVICE_TOKEN --expires 7d
agent-creds exec service-token -- python .\client.py
agent-creds status
agent-creds status --json
agent-creds list
agent-creds rm service-token
```

`store` removes the input file after the encrypted record is safely saved. Add `--keep` to retain it. A single final newline is removed; other whitespace is preserved. Overwrites require `--replace`. Omit `--expires` to store a secret without a local expiry deadline; `exec` will not impose a TTL on it. Expiry accepts `30m`, `12h`, `7d`, seconds, or an RFC3339 timestamp. Expired credentials are refused before the child starts.

`exec one,two -- program arguments...` forwards arguments directly, without shell expansion, and propagates the child's exit code. The `--` separator is recommended and optional. Credential names map to uppercase environment names with hyphens replaced by underscores, or you can set `--env`. Duplicate destination variables are rejected. There is deliberately no `get` command or expired-credential override.

## Capture any named cookie

```powershell
agent-creds cookie-scrape web-session --url https://app.example.com/ --cookie session_id --env WEB_SESSION
agent-creds cookie-scrape web-header --url https://app.example.com/api/ --cookie session_id --header --env COOKIE_HEADER
```

The browser starts with a fresh temporary profile. Log in normally. An inert bottom overlay and window-title prefix identify agent-creds. The overlay survives navigation and is added to new tabs. It never requests input or handles clicks. `--no-banner` disables both markers.

Capture waits until a tab is on the target origin and the named cookie exists for the exact target URL, using the browser's domain, path and secure-cookie matching. HttpOnly cookies work. Only that cookie's value is stored; `--header` stores `name=value`. Other cookies are not stored. Same-name ambiguity is refused rather than guessing. Specify the actual resource URL when paths matter. A matching cookie's presence is the completion condition; the tool cannot know whether it represents the intended account or a completed application login.

Options include `--browser auto|chrome|edge|chromium`, `--browser-path <executable>`, `--timeout <seconds>` and `--expires <duration-or-timestamp>`. Auto prefers Chrome, then Edge, then Chromium. An explicit browser selection does not fall back. Session cookies have unknown expiry unless you supply `--expires`; expiry is never inferred from an unrelated cookie. The browser is closed after success, timeout or a handled error, and its temporary profile is removed. Forced process termination can leave the browser/profile behind; close it and remove that temporary directory yourself.

## Generic local OAuth

Register an OAuth client with your provider and register an exact loopback redirect, such as `http://127.0.0.1:43821/callback`. Providers differ in whether they allow loopback callbacks, PKCE, refresh tokens, offline access and confidential native clients. This tool does not bypass those provider policies.

Create a JSON configuration locally. All fields below are examples, with no live service configured:

```json
{
  "authorization_url": "https://identity.example.com/authorize",
  "token_url": "https://identity.example.com/token",
  "client_id": "your-registered-client-id",
  "client_auth": "none",
  "redirect_uri": "http://127.0.0.1:43821/callback",
  "scopes": ["read", "offline_access"],
  "authorization_params": { "access_type": "offline" }
}
```

For a confidential client, add `client_secret` and set `client_auth` to `basic` or `post`, matching the provider. `none` is for public clients and rejects a supplied client secret. Configuration, including client ID and secret, is encrypted together. Unknown fields and attempts to override OAuth security parameters are rejected.

```powershell
agent-creds oauth configure example --from-file .\oauth-client.json --env EXAMPLE_ACCESS_TOKEN
agent-creds oauth login example
agent-creds exec example -- python .\api-client.py
agent-creds oauth refresh example
```

Authorization uses the system browser, random state, PKCE S256 and a callback listener bound only to `127.0.0.1`. The configured fixed port must be free. The listener validates the Host header, callback path and state. Incorrect-state requests do not consume the login. Login failure preserves existing credentials. Endpoints require HTTPS except loopback fixtures. Token requests never follow redirects; provider response bodies and transport details are suppressed on failure. The HTTP client bypasses environment proxy configuration. Providers requiring a corporate proxy or private CA need additional support.

`exec` refreshes OAuth access tokens when less than 60 seconds remain. Rotated refresh tokens are atomically persisted before the child launches. If a refresh response omits a replacement refresh token, the previous one is retained. If expiry is absent, `exec` refreshes every time; without a refresh token, authorize again. Only the access token enters the child's environment. The broker never injects the client secret or refresh token.

To replay an existing refresh token after configuring its client:

```powershell
agent-creds oauth import-refresh example --from-file .\refresh.token
```

The token is exchanged and its replacement is saved before the input file is removed. `--keep` retains the input. Configure again with `--replace` to change endpoints, scopes or client credentials; this deliberately resets authorization and requires a fresh login or refresh-token import. Request broader scopes through a new authorization, not a refresh replay. The implementation supports authorization code and refresh grants with Bearer access tokens; it does not implement device grants, client credentials, OIDC identity validation, DPoP, token exchange or provider-specific APIs.

## Dotenv import and blank templates

```powershell
agent-creds import-env .\credentials.env --dry-run
agent-creds import-env .\credentials.env --prefix SERVICE_ --exclude SERVICE_PUBLIC_URL
agent-creds template --out .\credentials.template.env
```

Dotenv files remain intact unless `--shred-source` is supplied. Empty values are skipped. Invalid syntax, duplicate keys, case-folding collisions and existing names without `--replace` are refused before writing. No shell is executed. Interpolation (`$`) and backticks are refused, including literal occurrences: use `store` for such values. All inputs are preflighted, but a disk failure during a multi-entry import may leave earlier entries saved; the source remains intact on failure. Templates contain names with blank values and refuse to overwrite an existing output file. OAuth entries are excluded from dotenv templates.

## Storage and security

Default vault locations follow OS local application data (`%LOCALAPPDATA%\agent-creds\data` on Windows, `~/Library/Application Support/agent-creds` on macOS, `$XDG_DATA_HOME/agent-creds` or `~/.local/share/agent-creds` on Linux). `--vault-dir <directory>` selects an isolated vault.

Windows encrypts each payload directly with current-user DPAPI through native FFI. macOS/Linux use AES-256-GCM with a per-vault key held by the OS keyring. Unix vault directories are mode `0700`. Windows relies on the user's local application directory ACLs; choose a private directory when overriding the location. An exclusive vault lock prevents conflicting local mutations and refreshes. Records are written through a synced temporary file and atomically replaced. Encrypted payloads bind the public metadata to prevent expiry/environment edits from changing execution. `status`, `list` and template export read cached public metadata without decryption or network access; metadata is not a live validity attestation.

Read [the threat model](docs/security.md), [the design and acceptance matrix](docs/design.md) and [verification notes](docs/verification.md) before deployment. Source removal overwrites then unlinks; it cannot guarantee forensic erasure on SSDs, backups or journalling filesystems. This is a local development tool, not yet an independently audited credential boundary.

Licensed under Apache-2.0. See [release and versioning guidance](docs/releases.md).
