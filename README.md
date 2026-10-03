<p align="center">
  <img src="assets/logo.svg" alt="scanward" width="320">
</p>

<p align="center">
  <a href="https://github.com/deepusingh2530/scanward/actions/workflows/ci.yml"><img src="https://github.com/deepusingh2530/scanward/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/scanward"><img src="https://img.shields.io/crates/v/scanward.svg" alt="crates.io"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-orange" alt="PolyForm Noncommercial 1.0.0"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.90%2B-orange?logo=rust&logoColor=white" alt="Rust 1.90+"></a>
</p>

<p align="center">
  <b>Fast, fully-offline multi-language SAST scanner.</b> A curated, original
  rule corpus (OWASP Top 10, framework-specific vulnerabilities, secrets, taint)
  with a scriptable CLI, parallel scanning, an incremental content-hash cache,
  and SARIF/JSON output. No network, no telemetry — deterministic results you
  can gate CI on.
</p>

## Highlights

- **Offline by design** — rules ship in-repo; `--offline` hard-refuses any
  network or external sidecar. Nothing phones home, ever.
- **Curated, original rules across 27 languages** — OWASP Top 10,
  Django/Flask/Express/Spring/Rails/Laravel hardening, secrets patterns, and
  intra-procedural taint with call summaries. Every rule has pass/fail
  fixtures.
- **Nothing is skipped silently** — files with unrecognized extensions are
  still scanned as the `generic` pseudolanguage (secrets + polyglot rules);
  27 languages recognized, 10 with tree-sitter AST.
- **Familiar SAST CLI** — `--config`, `--exclude`/`--include`,
  `--min-severity`, `--error` exit-code gating, `--baseline`/`--diff-only`
  diff-aware scans. Migration notes in [`docs/cli-migration.md`](docs/cli-migration.md).
- **Fast** — Aho-Corasick pre-filter skips non-candidate files, rayon scans
  in parallel, content-hash cache makes repeat scans incremental.
  Measured 28-140x faster than a widely-used Python-based SAST scanner in head-to-head benchmarks
  ([`docs/benchmarks.md`](docs/benchmarks.md)).
- **CI-ready output** — SARIF 2.1.0 (with rule metadata and
  `security-severity`) for GitHub code scanning, JSON for tooling, human
  table for terminals.
- **AI is optional and separate** — triage/autofix runs as a BYOK side-plane
  outside the scan hot path; the scanner never needs an API key.

## How scanward compares

scanward is one thing done well: pattern/taint SAST that runs offline in one
small binary with a rule corpus you can read. Most tools below solve a
different, adjacent problem, or solve SAST with much more machinery.

| Tool | Primary job | Detection model | Scope (own rules) | Offline scan | License / price |
| --- | --- | --- | --- | --- | --- |
| **scanward** | SAST gate for CI | original pattern + taint rules, no third-party rule content | 27 languages recognized, generic fallback; 10 with tree-sitter AST | yes, strict `--offline` | PolyForm Noncommercial — free for noncommercial use, commercial license on request |
| Python-based SAST baseline (the one in [`docs/benchmarks.md`](docs/benchmarks.md)) | SAST engine + rule registry | pattern + taint, registry-driven | 30+ languages, 2k community / 20k+ paid rules | OSS tier yes | OSS + commercial tier |
| Bandit | Python-only SAST | AST + bytecode dataflow | Python only | yes | Apache-2.0, free |
| Gitleaks | Secret scanning | regex + entropy over any text | language-agnostic | yes | MIT, free |
| Trivy | Dependency/IaC/misconfig scanning | advisory DB + config checks | SBOM, deps, IaC, containers | DB cache; registry pulls need network | Apache-2.0, free |
| CodeQL | Deep semantic SAST | compiled dataflow (QL) | ~10 languages, C-family, JVM, .NET, Go, JS/TS, Python, Ruby, Rust, Swift | DB builds locally, but query/library packs download | OSS CLI, free for public repos on GitHub |
| SonarQube | Quality-gate platform | rule analyzers + custom rules | 20+ analyzers, SAST among many | needs a running server | Community Build free, commercial for orgs |

Practical differences that decide a toolchain:

- **Single binary, zero setup** — `cargo install scanward` and scan. No
  container, no server, no registry account, no per-language install. Measured
  28-140x faster than the reference Python-based scanner in our benchmarks.
- **Corpus is auditable** — every rule is a small YAML file in
  [`rules/`](rules) with a fail-fixture and a pass-fixture, so a "finding" is
  always traceable to a reviewable pattern plus two tests.
- **Secrets/SCA are composable, not fused** — `--only secrets|sca` shells out to
  Gitleaks (MIT) and OSV-Scanner/Trivy (Apache-2.0) when you want their
  databases; the core scanner never links or embeds them, and `--offline` refuses
  both. Dependency licence and typosquat analysis need no external tool at all
  (`--only licenses|typosquat`), so they work offline.
- **Switching costs are low** — rule files written for the common portable
  pattern schema are translated on load ([`docs/rule-import.md`](docs/rule-import.md)),
  and CI wiring is a stock SARIF upload.
- **Where scanward is deliberately behind** — cross-file/cross-function taint,
  IDE/LSP integration, and platform features (dashboards, PR comments) live in
  other tools today; the known limitations are in
  [`docs/architecture.md`](docs/architecture.md).

<sub>Comparison reflects each tool's public documentation and license files as
of Sep 2026; scanward's own numbers are measured locally (see
[`docs/benchmarks.md`](docs/benchmarks.md)). Every rule is original — no
third-party rule content is used. scanward is
[PolyForm Noncommercial 1.0.0](LICENSE) (versions 0.12.0 and earlier are
[MIT](LICENSE-MIT)), so it is free for noncommercial use and needs a
commercial license for business use.</sub>

## Installation

### Container (nothing to install)

The image ships the rule corpus, so a bare run scans a mounted repository:

```sh
docker run --rm -v "$PWD:/src" ghcr.io/deepusingh2530/scanward
```

That is the whole command line — no flags, no rules path. It runs as a
non-root user, is multi-arch (amd64 + arm64), and every tag carries a
provenance attestation and an SBOM. Pass args to override the defaults:

```sh
docker run --rm -v "$PWD:/src" ghcr.io/deepusingh2530/scanward \
  scan /src --rules /rules --min-severity error --error
```

To build it yourself:

```sh
docker build -t scanward .
docker run --rm -v "$PWD:/src" scanward
```

### Prebuilt binary

Signed binaries and CycloneDX SBOMs are attached to each
[release](https://github.com/deepusingh2530/scanward/releases). Each archive
contains the binary **and the rule corpus**, plus a `scanward-corpus` wrapper
that points the scanner at it:

```sh
tar xzf scanward-v0.14.0-macos-arm64.tar.gz
./scanward-corpus scan .
```

Verify what you downloaded:

```sh
cosign verify-blob \
  --bundle scanward-v0.14.0-macos-arm64.sig.bundle \
  scanward-v0.14.0-macos-arm64.tar.gz \
  --certificate-identity-regexp "https://github.com/deepusingh2530/scanward/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Homebrew

```sh
brew install deepusingh2530/scanward/scanward   # tap
brew install scanward                          # once the formula is in core
scanward-corpus scan .
```

### From crates.io

```sh
cargo install scanward
```

Source build (Rust 1.90+):

```sh
git clone https://github.com/deepusingh2530/scanward.git
cargo install --path crates/scanward
# or
cargo install --git https://github.com/deepusingh2530/scanward scanward
```

## Usage

```sh
scanward scan .                                    # findings, human-readable
scanward scan . --config rules/ --sarif -o out.sarif
scanward scan . --junit -o results.xml             # JUnit XML for CI test tabs
scanward scan . --exclude 'vendor/**' --min-severity error --error
scanward scan . --baseline main --diff-only        # only lines changed vs main
scanward scan . --only secrets                     # gitleaks sidecar (if installed)
scanward scan . --only licenses                     # dependency licence policy (offline)
scanward scan . --only typosquat                    # dependency names that look impersonated
scanward rule test rules/                          # validate rules + run all fixtures
scanward scan --help
```

| Flag | Purpose |
| --- | --- |
| `--config <path>` | Rule file or directory, repeatable (supersedes `--rules`) |
| `--exclude` / `--include <glob>` | Path filters: globs (`*`, `**`, `?`) or plain substrings |
| `--min-severity <level>` | Findings floor: `error` \| `warning` \| `info` |
| `--error` | Exit 1 when findings remain (CI gating) |
| `--json` / `--sarif` / `--junit` | Machine-readable output: JSON, SARIF 2.1.0, or JUnit XML (`-o` writes to a file) |
| `--baseline <ref>` + `--diff-only` | Diff-aware scan of changed lines only |
| `--suppress <file>` | FP suppression file, repeatable (auto-discovers `.scanward-suppressions.yml` at the scan root) |
| `--only sast\|secrets\|sca\|licenses\|typosquat\|all` | SAST core, a native supply-chain check (`licenses`, `typosquat` — offline, no subprocess), or a sidecar: gitleaks / osv-scanner |
| `--license-policy <file>` | Licence allow/deny policy for `--only licenses` (default: `<path>/.scanward-licences.yml`) |
| `--offline` | Strict no-network mode (sidecars refused) |
| `--metrics`, `--jobs <N>`, `--no-cache`, `--cache-dir` | Observability and performance controls |

Exit codes: `0` success, non-zero on operational errors — and with `--error`,
non-zero when findings remain.

## Supported languages

| Language | Parsing | | Language | Parsing |
| --- | --- | --- | --- | --- |
| Bash | text | | PHP | tree-sitter |
| C / C++ | tree-sitter | | PowerShell | text |
| C# | tree-sitter | | Python | tree-sitter |
| Dart | text | | Ruby | tree-sitter |
| Dockerfile | text | | Rust | text |
| Elixir | text | | Scala | text |
| Go | tree-sitter | | SQL | text |
| HTML | text | | Swift | text |
| Java | tree-sitter | | Terraform | text |
| JavaScript | tree-sitter | | TypeScript | tree-sitter |
| JSON | text | | YAML | text |
| Kotlin | text | | Secrets (generic) | text |
| Lua | text | | | |
| OCaml | text | | | |

Ten languages are parsed with tree-sitter (Python, JavaScript, TypeScript,
Go, Java, Ruby, PHP, C#, C, C++); 16 more are scanned structurally at the
text level (Terraform, YAML, Dockerfile, Scala, OCaml, Kotlin, Bash, JSON,
HTML, Rust, Swift, Dart, Elixir, Lua, PowerShell, SQL). Files with
unrecognized extensions are still scanned as the `generic` pseudolanguage, so
no discovered file is ever skipped without being read. Coverage decisions are
documented in [`docs/coverage-policy.md`](docs/coverage-policy.md).

## False-positive management

Silence accepted findings two ways — a checked-in suppression file (every
entry requires a `reason`; optional owner/expiry with loud re-enable on
expiry) or inline comments at the finding:

```yaml
# .scanward-suppressions.yml — auto-discovered at the scan root
- rule: py-eval-exec
  path: "testdata/**"
  reason: sandboxed eval in the test harness
  expires: 2027-06-30
```

```python
eval(user)   # scanward-ignore(py-eval-exec)   # same line, rule-scoped
# scanward-ignore-next-line                    # annotate the line above
```

Renamed from `codegrep`? The legacy `codegrep-ignore` marker and
`.codegrep-suppressions.yml` are still honored, so existing suppressions keep
working without edits.

Suppressed counts are always surfaced (`--metrics` / `ScanReport.suppressed`)
— nothing is hidden without a trace. Details:
[`docs/suppressions.md`](docs/suppressions.md).

## CI/CD integration

Drop-in GitHub Actions job (fails the build on findings, uploads SARIF to
the Security tab):

```yaml
name: sast
on: [push, pull_request]
jobs:
  scanward:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo install --git https://github.com/deepusingh2530/scanward scanward
      - run: scanward scan . --min-severity error --error --sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

This repository's own [CI](.github/workflows/ci.yml) runs unit tests,
`clippy -D warnings`, the rule-corpus gate (every rule validated against its
fail/pass fixtures), a demo scan, a clean self-scan of `crates/`, and uploads
SARIF + JUnit artifacts.

## Use as a library

`scanward` is also a Rust library crate — embed scanning in your own tool
(e.g. a PR scanner) without shelling out:

```toml
[dependencies]
scanward = "0.12.0"
# or track main: scanward = { git = "https://github.com/deepusingh2530/scanward" }
```

```rust
use scanward::{scan, sarif_from, ScanOptions};

fn main() -> anyhow::Result<()> {
    let report = scan(&ScanOptions {
        path: "src".into(),
        rules: "scanward/rules".into(), // a checkout of this repo
        min_severity: Some("warning".into()),
        ..Default::default()
    })?;
    for f in &report.findings {
        eprintln!("{}:{} [{}] {}", f.path, f.line, f.severity, f.rule_id);
    }
    println!("{}", sarif_from(&report.findings)); // SARIF for upload
    // …or scanward::junit_from(&report.findings) for CI test reports
    Ok(())
}
```

Rules ship as YAML in this repository's [`rules/`](rules) directory — point
`ScanOptions::rules` (or `config`) at a local checkout (git submodule, clone,
or vendored copy); the scanner itself is fully offline. Runnable version:
[`crates/scanward/examples/scan.rs`](crates/scanward/examples/scan.rs).

```sh
cargo run -p scanward --example scan -- ./testdata ./rules
```

Already have rule files written for another scanner's pattern schema? Point
`--config` / `ScanOptions::config` at them — they are detected and translated
on load (strictly: unsupported constructs are skipped with a reported reason,
never silently weakened). See [`docs/rule-import.md`](docs/rule-import.md).

## Supply-chain checks (offline, native)

`--only licenses` and `--only typosquat` read your dependency manifests directly
— no subprocess, no network, no registry account. They build on the
[`cg-deps`](crates/cg-deps) inventory (`Cargo.toml`/`Cargo.lock`,
`package-lock.json`, `requirements.txt`, `pyproject.toml`, `poetry.lock`,
`go.mod`, `composer.lock`, `Gemfile.lock`).

**Licence policy** — allow/deny lists in `.scanward-licences.yml`:

```yaml
allow: ["MIT", "Apache-2.0", "BSD-3-Clause"]
deny: ["GPL-3.0", "AGPL-3.0"]
unlicensed: warn        # warn | ignore | error
scope: direct           # direct | all
```

Two rules the checker will not bend: **an absent licence is never treated as
free**, and **a licence we cannot map is reported as `unknown`, not accepted**.
It also distinguishes *undeclared* from *unknowable*: `Cargo.lock`, `go.mod`,
`Gemfile.lock` and `requirements.txt` carry no licence field at all, so those
entries come back as `unavailable` and never fail a gate. Reporting a Rust
crate as "unlicensed" when we simply never read its metadata would be a lie.

**Typosquatting** — flags inventory names one edit away from a widely used
package (Damerau-Levenshtein, so transpositions like `lodahs` count as one), plus
homoglyph swaps (`serd3`) and impersonating suffixes (`requests-secure`). Every
hit is a *suspect*, not a verdict: without registry access we cannot know whether
the name is taken, so the report names the package it resembles and the signal
that fired, and stays at `warning`.

**API security** — OpenAPI/Swagger specs are scanned as source: plaintext server
URLs, credentials embedded in a URL, API keys in query strings, HTTP Basic auth,
deprecated OAuth2 flows, remote `$ref` over http, external `$ref` dependencies,
debug surfaces, and Swagger 2.0.

**What stays a sidecar:** CVE matching (osv-scanner), secret scanning
(gitleaks), registry/registry-adjacent lookups, and container image OS
packages. Those need network or an external database; scanward refuses to
pretend otherwise. See `--only secrets|sca`.

## Architecture

| Crate | Role |
| --- | --- |
| [`crates/scanward`](crates/scanward) | Library API + CLI: `scan`, `rule test`, cache, SARIF/JSON output |
| [`crates/cg-rules`](crates/cg-rules) | YAML rule loading, validation, literal pre-filter index |
| [`crates/cg-matcher`](crates/cg-matcher) | Structural matcher: `$VAR`, `...`, regex/comparison checks |
| [`crates/cg-parser`](crates/cg-parser) | Language detection + tree-sitter parsing |
| [`crates/cg-taint`](crates/cg-taint) | Intra-procedural taint with function summaries |
| [`crates/cg-ir`](crates/cg-ir) | Shared intermediate representation |
| [`crates/cg-deps`](crates/cg-deps) | Dependency manifest inventory: version, ecosystem, licence, directness |

## Rule development

Rules are authored from JSON specs and generated into YAML:

```sh
$EDITOR scripts/specs/gap-sec-NN.json   # id, languages, pattern|mvr, fixtures
python3 scripts/mkrules.py scripts/specs/gap-sec-NN.json
./target/release/scanward rule test rules/   # gate: every rule needs fixtures
```

Fixtures live in `rules/tests/<rule-id>/` as `fail*` (must trigger) and
`pass*` (must stay clean) files — CI runs all of them, so a new rule ships
with its own precision test. New rules can also be synthesized locally with
`python3 scripts/rule-gen.py` (Ollama-local, validated — see
[`docs/rule-authoring.md`](docs/rule-authoring.md)).

## Contributing

`main` is protected: every change lands through a pull request — no direct
pushes, no force pushes, linear history, and CI must be green. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, the local gates, how to
author a rule or add a language, and the two non-negotiables (original content
only, offline stays offline). Security reports go through
[SECURITY.md](SECURITY.md), not the issue tracker.

## Documentation

- [Contributing guidelines (PR workflow, rule authoring)](CONTRIBUTING.md)
- [Licensing (noncommercial terms, version boundary, commercial licensing)](docs/licensing.md)
- [Weekly release cadence & CVE watch](docs/release-cadence.md)
- [Migration guide + CLI flag mapping](docs/cli-migration.md)
- [Measured performance benchmarks](docs/benchmarks.md)
- [Coverage policy (what we deliberately do not flag)](docs/coverage-policy.md)
- [Importing rules (portable pattern schema)](docs/rule-import.md)
- [False-positive management (suppressions)](docs/suppressions.md)
- [Architecture and engine invariants](docs/architecture.md)
- [Writing rules (engine contract, schema, fixtures)](docs/rule-authoring.md)
- [Documentation index](docs/README.md)

AI triage/autofix is a separate BYOK side-plane that never blocks `scan`:

```sh
python3 ai-triage/triage.py --mode triage --input findings.json
```

## License

**[PolyForm Noncommercial 1.0.0](LICENSE)** — free for personal, research,
educational, and other noncommercial use, including charities, schools, public
research bodies, and government. **Commercial use is not permitted** under these
terms; ask for a [commercial license](docs/licensing.md) if you need one.
The `codegrep` crate up to and including `0.12.0` was released under
[MIT](LICENSE-MIT) and remain so permanently.

> Required Notice: Copyright (c) 2026 Deepu Singh (https://github.com/deepusingh2530/scanward)

The engine and every rule are original work — no third-party scanner code or
rule-registry content is used (those registries carry non-MIT licenses).
Dependencies and sidecars keep their own licenses and are never linked:
Tree-sitter (MIT); secrets via `gitleaks` (MIT) and SCA via
`osv-scanner`/`trivy` (Apache-2.0), as separate processes. Full details,
including the version boundary and how to request a commercial license, are in
[`docs/licensing.md`](docs/licensing.md).
