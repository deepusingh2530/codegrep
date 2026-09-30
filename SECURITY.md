# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| latest release (see [Releases](https://github.com/deepusingh2530/codegrep/releases)) | ✅ |
| `main` (pre-release) | ✅ (best effort) |
| older releases | ❌ (upgrade; weekly cadence) |

## Who can change this repository

Only the maintainer can merge, and nothing reaches `main` without a pull
request: the default branch is protected by a ruleset that requires a PR,
green `test` + `deny` checks, resolved review threads, and linear history —
direct pushes, force pushes, and branch deletion are all rejected for every
account, including the maintainer's. The only automated writers are
Dependabot (dependency bumps) and the weekly release workflow (version bump,
tag, publish); both are visible in the Actions tab and are covered by the same
review expectations. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub private vulnerability reporting](https://github.com/deepusingh2530/codegrep/security/advisories/new)
(send the report privately to the maintainers). If you prefer email, open a
public issue asking for a contact address only (no details).

What's in scope:

- **The scanner** (crates/, CLI, library): memory-safety issues, path
  traversal, arbitrary file reads, command injection, sandbox escapes while
  scanning untrusted repositories, parser crashes (rule files or target code).
- **Supply chain**: malicious rules shipped in this repository, release
  artifact tampering (report if a published binary/SBOM/signature does not
  verify), compromised CI or workflow permissions.
- **Rule correctness with security impact**: a rule that silently *misses* a
  vulnerability class in a default configuration (false-negative claims need a
  fixture demonstrating the gap).

Out of scope: ordinary false positives, performance issues, feature requests
(use regular issues), vulnerabilities only reachable by the operator running
the scanner with elevated privileges on their own machine.

## Response expectations

- **Acknowledgement**: within 3 working days.
- **Initial assessment**: within 10 days.
- **Fix or mitigation**: coordinated disclosure; we aim for a patched release
  within 90 days, sooner for actively exploited issues (the weekly cadence
  helps).
- **Credit**: reporters are credited in the advisory unless they decline.

## Hardening notes for embedders

- The scanner is **offline by design**: no network calls during `scan`.
- Rule files are data, but they drive a matcher — treat untrusted rule packs
  like untrusted code; review before use. `cargo deny check` and the fixture
  gate protect *this* repository's corpus.
- Verify releases: binaries are attached to GitHub Releases with SBOMs and
  cosign signatures; crates.io artifacts are checksummed by the registry.
- `--config` refuses remote/registry URLs (offline-first): the scanner never
  fetches rules at runtime.
