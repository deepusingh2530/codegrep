# codegrep

[![CI](https://github.com/deepusingh2530/codegrep/actions/workflows/ci.yml/badge.svg)](https://github.com/deepusingh2530/codegrep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/rules-1183-orange.svg)](#supported-languages)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org)

**Fast, fully-offline multi-language SAST scanner.** 1183 MIT-original rules
(OWASP Top 10, framework-specific vulnerabilities, secrets, taint) with a
scriptable CLI, parallel scanning, an incremental content-hash cache, and
SARIF/JSON output. No network, no telemetry — deterministic results you can
gate CI on.

## Highlights

- **Offline by design** — rules ship in-repo; `--offline` hard-refuses any
  network or external sidecar. Nothing phones home, ever.
- **1183 original rules across 20 languages** — OWASP Top 10, Django/Flask/
  Express/Spring/Rails/Laravel hardening, secrets patterns, and intra-
  procedural taint with call summaries. Every rule has pass/fail fixtures.
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

## Installation

### From crates.io (recommended)

```sh
cargo install codegrep
```

### From source (Rust 1.90+)

```sh
git clone https://github.com/deepusingh2530/codegrep.git
cd codegrep
cargo install --path crates/codegrep
```

Or directly from GitHub:

```sh
cargo install --git https://github.com/deepusingh2530/codegrep codegrep
```

### Docker

```sh
docker build -t codegrep .
docker run --rm -v "$PWD:/src" -w /src codegrep scan /src --rules /rules
```

## Usage

```sh
codegrep scan .                                    # findings, human-readable
codegrep scan . --config rules/ --sarif -o out.sarif
codegrep scan . --junit -o results.xml             # JUnit XML for CI test tabs
codegrep scan . --exclude 'vendor/**' --min-severity error --error
codegrep scan . --baseline main --diff-only        # only lines changed vs main
codegrep scan . --only secrets                     # gitleaks sidecar (if installed)
codegrep rule test rules/                          # validate rules + run all fixtures
codegrep scan --help
```

| Flag | Purpose |
| --- | --- |
| `--config <path>` | Rule file or directory, repeatable (supersedes `--rules`) |
| `--exclude` / `--include <glob>` | Path filters: globs (`*`, `**`, `?`) or plain substrings |
| `--min-severity <level>` | Findings floor: `error` \| `warning` \| `info` |
| `--error` | Exit 1 when findings remain (CI gating) |
| `--json` / `--sarif` / `--junit` | Machine-readable output: JSON, SARIF 2.1.0, or JUnit XML (`-o` writes to a file) |
| `--baseline <ref>` + `--diff-only` | Diff-aware scan of changed lines only |
| `--suppress <file>` | FP suppression file, repeatable (auto-discovers `.codegrep-suppressions.yml` at the scan root) |
| `--only sast\|secrets\|sca\|all` | SAST core or gitleaks/osv-scanner sidecars |
| `--offline` | Strict no-network mode (sidecars refused) |
| `--metrics`, `--jobs <N>`, `--no-cache`, `--cache-dir` | Observability and performance controls |

Exit codes: `0` success, non-zero on operational errors — and with `--error`,
non-zero when findings remain.

## Supported languages

| Language | Rules | | Language | Rules |
| --- | ---: | --- | --- | ---: |
| Bash | 9 | | JSON | 7 |
| C / C++ | 16 | | Kotlin | 14 |
| C# | 38 | | OCaml | 16 |
| Dockerfile | 37 | | PHP | 45 |
| Go | 72 | | Python | 271 |
| HTML | 6 | | Ruby | 110 |
| Java | 110 | | Scala | 28 |
| JavaScript | 173 | | Secrets (generic) | 5 |
| Terraform | 92 | | TypeScript | 46 |
| YAML | 88 | | **Total** | **1183** |

Ten languages are parsed with tree-sitter (Python, JavaScript, TypeScript,
Go, Java, Ruby, PHP, C#, C, C++); the rest are scanned structurally at the
text level. Coverage decisions are documented in
[`docs/coverage-policy.md`](docs/coverage-policy.md).

## False-positive management

Silence accepted findings two ways — a checked-in suppression file (every
entry requires a `reason`; optional owner/expiry with loud re-enable on
expiry) or inline comments at the finding:

```yaml
# .codegrep-suppressions.yml — auto-discovered at the scan root
- rule: py-eval-exec
  path: "testdata/**"
  reason: sandboxed eval in the test harness
  expires: 2027-06-30
```

```python
eval(user)   # codegrep-ignore(py-eval-exec)   # same line, rule-scoped
# codegrep-ignore-next-line                    # annotate the line above
```

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
  codegrep:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo install --git https://github.com/deepusingh2530/codegrep codegrep
      - run: codegrep scan . --min-severity error --error --sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

This repository's own [CI](.github/workflows/ci.yml) runs unit tests,
`clippy -D warnings`, the rule-corpus gate (**1183 rules / 2152 fixtures**),
a demo scan, a clean self-scan of `crates/`, and uploads SARIF + JUnit artifacts.

## Use as a library

`codegrep` is also a Rust library crate — embed scanning in your own tool
(e.g. a PR scanner) without shelling out:

```toml
[dependencies]
codegrep = "0.12.0"
# or track main: codegrep = { git = "https://github.com/deepusingh2530/codegrep" }
```

```rust
use codegrep::{scan, sarif_from, ScanOptions};

fn main() -> anyhow::Result<()> {
    let report = scan(&ScanOptions {
        path: "src".into(),
        rules: "codegrep/rules".into(), // a checkout of this repo
        min_severity: Some("warning".into()),
        ..Default::default()
    })?;
    for f in &report.findings {
        eprintln!("{}:{} [{}] {}", f.path, f.line, f.severity, f.rule_id);
    }
    println!("{}", sarif_from(&report.findings)); // SARIF for upload
    // …or codegrep::junit_from(&report.findings) for CI test reports
    Ok(())
}
```

Rules ship as YAML in this repository's [`rules/`](rules) directory — point
`ScanOptions::rules` (or `config`) at a local checkout (git submodule, clone,
or vendored copy); the scanner itself is fully offline. Runnable version:
[`crates/codegrep/examples/scan.rs`](crates/codegrep/examples/scan.rs).

```sh
cargo run -p codegrep --example scan -- ./testdata ./rules
```

Already have rule files written for another scanner's pattern schema? Point
`--config` / `ScanOptions::config` at them — they are detected and translated
on load (strictly: unsupported constructs are skipped with a reported reason,
never silently weakened). See [`docs/rule-import.md`](docs/rule-import.md).

## Architecture

| Crate | Role |
| --- | --- |
| [`crates/codegrep`](crates/codegrep) | Library API + CLI: `scan`, `rule test`, cache, SARIF/JSON output |
| [`crates/cg-rules`](crates/cg-rules) | YAML rule loading, validation, literal pre-filter index |
| [`crates/cg-matcher`](crates/cg-matcher) | Structural matcher: `$VAR`, `...`, regex/comparison checks |
| [`crates/cg-parser`](crates/cg-parser) | Language detection + tree-sitter parsing |
| [`crates/cg-taint`](crates/cg-taint) | Intra-procedural taint with function summaries |
| [`crates/cg-ir`](crates/cg-ir) | Shared intermediate representation |

## Rule development

Rules are authored from JSON specs and generated into YAML:

```sh
$EDITOR scripts/specs/gap-sec-NN.json   # id, languages, pattern|mvr, fixtures
python3 scripts/mkrules.py scripts/specs/gap-sec-NN.json
./target/release/codegrep rule test rules/   # gate: every rule needs fixtures
```

Fixtures live in `rules/tests/<rule-id>/` as `fail*` (must trigger) and
`pass*` (must stay clean) files — CI runs all 2152 of them. New rules can
also be synthesized locally with `python3 scripts/rule-gen.py`
(Ollama-local, validated — see [`prompts/rule-generator.md`](prompts/rule-generator.md)).

## Documentation

- [Weekly release cadence & CVE watch](docs/release-cadence.md)
- [Migration guide + CLI flag mapping](docs/cli-migration.md)
- [Measured performance benchmarks](docs/benchmarks.md)
- [Coverage policy (what we deliberately do not flag)](docs/coverage-policy.md)
- [Importing rules (portable pattern schema)](docs/rule-import.md)
- [False-positive management (suppressions)](docs/suppressions.md)
- [Master prompt (architecture source of truth)](MASTER_PROMPT.md)

AI triage/autofix is a separate BYOK side-plane that never blocks `scan`:

```sh
python3 ai-triage/triage.py --mode triage --input findings.json
```

## License

[MIT](LICENSE) — engine and rules are original MIT code. No third-party
scanner code or rule-registry content is used (those registries carry
non-MIT licenses). Parsing via
Tree-sitter (MIT); secrets/SCA delegate to external `gitleaks` (MIT) /
`osv-scanner` (Apache-2.0) processes — never linked.
