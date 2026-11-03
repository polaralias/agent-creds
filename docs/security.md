# Security model

Agent Credentials reduces accidental disclosure through argv, shell history, plaintext credential files and routine broker output. It protects stored payloads using the OS account's protection facility, and exposes selected credentials to a child process for its lifetime.

## Authority boundary

The OS user account is the trust boundary. A program with arbitrary execution under that account can call `exec` with a program that prints a credential, read child-process environments, attach a debugger or use DPAPI/keyring facilities itself. The broker cannot enforce “an agent never sees a password” against an agent with that authority. Approve the child program and constrain its execution separately when enforcement is required. Child stdout/stderr are inherited and are not redacted; a child can reveal credentials in logs. Existing parent environment variables also remain available to the child.

The broker has no raw-secret export command. This reduces accidental exposure but does not create an authorization boundary around `exec`. Credential names and environment names are public. Status metadata is cached and unauthenticated until a payload is decrypted and compared. Do not use status as an access-control decision.

## Storage and mutation

Each versioned JSON record has public metadata and an authenticated encrypted payload containing both metadata and credentials. Decryption compares both copies before use. Corrupted ciphertext, altered expiry, altered environment name or mismatched entry identity fails closed. DPAPI is current-user scoped; GCM uses a random nonce per write and a per-canonical-vault-path master key in the native keyring. Moving a Unix vault changes its key identity and requires restoring/rebinding the appropriate key; copying encrypted files alone is not an export/import facility.

An exclusive process lock serializes operations within a vault. Browser login and OAuth authorization hold that lock, so other commands fail promptly with a busy message. The lock is released before running a child. Atomic file replacement prevents half-written records, but no filesystem transaction can guarantee recovery if an OAuth provider rotates a refresh token and the subsequent local write fails. In that case retry or authorize again. Full power-loss durability depends on the filesystem; file content is synced, but parent directory metadata is not explicitly fsynced.

Entry names exclude path separators, dots and non-ASCII characters. Input is bounded, symlink leaf paths are rejected, and source-removal paths must be outside the vault. These checks reduce mistakes; they do not defeat a hostile same-user process racing path replacement or changing ancestor directories. Use a private local vault, never a shared or network-writable directory. Hard links and OS administrators are outside the isolation claim.

Temporary plaintext serialization buffers and source reads use zeroizing wrappers. Rust strings, HTTP libraries, process environments, browser memory and allocator copies can retain additional copies. There is no claim of complete memory erasure, protection against swap/dumps, or forensic deletion. File imports necessarily begin with a user-created plaintext source file.

## Browser capture

Cookie capture launches an owned, fresh Chromium profile and a loopback DevTools endpoint on an ephemeral port. It never attaches to a user's existing browser or reads its profile. The browser protocol necessarily has authority over every page in that temporary profile. A malicious process running locally may discover and access the loopback debugging endpoint; it is not authenticated. The profile is discarded on normal completion. A force-kill or crash may leave a profile and browser process behind. Chromium may write its own profile state during login; the application does not promise a diskless browser session.

The overlay is informational, inert and uses text nodes. It does not intercept credentials. A hostile page can remove or imitate it, and page-wide effects can distort it; it is not a trusted OS security indicator. The title prefix is also a page-level aid. Capture only checks target-origin presence and the cookie's browser-defined applicability to the requested URL. It does not prove identity, account selection, CSRF validity or successful application authorization. Parent-domain cookies can apply to multiple hosts; no application-specific account-switch heuristics are implemented.

## OAuth

Authorization code flow uses PKCE S256 and random one-use state. The listener binds a literal loopback IP, validates method/Host/path/state, ignores forged states, rejects duplicate state/code values and times out. Provider errors terminate only after matching state. Access and refresh tokens are stored with the client configuration; only access tokens are eligible for injection. HTTPS token requests use certificate validation, no redirects, finite timeouts and bounded responses. OAuth error bodies, browser protocol errors and HTTP transport detail are not printed because they can contain credentials.

Local token replay intentionally contacts the endpoint configured by the user. The encrypted configuration is the source of that destination; there is no discovery or endpoint selection from provider response text. Protect the OAuth client configuration like a credential. Native-client secrets are not considered confidential from other programs on the same machine. ID tokens are ignored; this is not an OpenID Connect identity verifier.

All development integration endpoints are synthetic loopback fixtures. Tests do not contact remote identity providers or application services.
