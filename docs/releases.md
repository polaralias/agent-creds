# Versions and releases

`VERSION` is the canonical stable semantic version, currently `0.1.0`. Cargo.toml and the agent-creds entry in Cargo.lock mirror it. The CLI uses Cargo's package version, and build.rs rejects mismatches with VERSION. The pinned development toolchain is recorded in rust-toolchain.toml.

To prepare a new version on a feature branch:

```sh
python scripts/version.py --set 0.1.1
python scripts/version.py --check
```

Commit the three version files together with the related implementation, tests and documentation. Use a patch increment for compatible fixes, minor for compatible functionality and major for breaking changes. Before 1.0, document breaking changes explicitly and normally increment the minor version. Version changes do not create tags or publish packages.

## Pull requests and release drafts

CI verifies Windows and Ubuntu 24.04, including native Linux keyring and browser fixtures, version consistency, the version updater and Cargo source-package verification. The release-gate check aggregates both platform results. macOS is not a supported release artifact until native qualification is complete.

The Protect default branch ruleset requires one approving code-owner review, resolved conversations and a successful release-gate, and blocks branch deletion and non-fast-forward updates. Repository administrators have the explicitly configured always-bypass capability. Prefer normal reviewed PRs; admin bypass is an available override, not the ordinary workflow. A separate Protect version tags ruleset blocks updates and deletion of version tags, with the same explicit administrator bypass. CODEOWNERS must be present on the PR base branch.

Release Drafter updates a draft on main changes and PR activity. It reads main's VERSION for its exact vX.Y.Z draft name and tag, rather than calculating another version from labels. The draft's content groups PRs by category. Once a version is published, bump VERSION in the next development PR before preparing another release. The workflow can also be dispatched manually to refresh a draft.

## Tagged releases

When the user explicitly authorizes a release, tag a verified commit already on main with the exact version and push that tag:

```sh
git tag -a v0.1.0 -m "agent-creds v0.1.0"
git push origin v0.1.0
```

These commands are the publication trigger. Creating or pushing a branch does not publish a release.

The Publish Release workflow:

1. Requires the tag to equal VERSION and the tagged commit to be an ancestor of origin/main.
2. Reuses Windows/Linux CI, including the real credential-backend and local-browser checks.
3. Builds release executables with the locked dependencies and pinned Rust toolchain.
4. Verifies each executable's --version, packages the binary with Apache-2.0 LICENSE, NOTICE, usage/security documentation and VERSION, and creates SHA-256 checksum files.
5. Passes build artifacts to a separate publisher job. Only that job has contents:write; it never checks out or executes repository source.
6. Verifies archive checksums, fills the matching draft and publishes it, or creates a release if no draft exists. It refuses to replace assets of an already-published release.

Artifacts are agent-creds-X.Y.Z-x86_64-pc-windows-msvc.zip and agent-creds-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz, each with a .sha256 file. Linux builds target Ubuntu 24.04's glibc environment and require a Secret Service runtime; they are not a claim of static or universal Linux compatibility. No crates.io publication is configured.

Source packaging uses root-anchored Cargo include patterns and excludes local vault data, notes, caches, logs and built artifacts. CI checks Cargo's actual file list while ignored README and docs fixtures exist, so nested helper documentation cannot leak into the source package. Run `python scripts/check_package.py` locally to repeat that boundary check. See [verification](verification.md) and [security](security.md) for platform evidence and trust boundaries.
