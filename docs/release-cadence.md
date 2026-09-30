# Weekly release cadence & CVE watch

codegrep ships on a **weekly cadence** (Mondays, 06:00 UTC) so rules, security
patches, and coverage reports stay fresh. The `weekly` workflow
(`.github/workflows/weekly.yml`) is the driver.

## How "latest CVEs" map to codegrep

| Vector | Mechanism | Where |
| --- | --- | --- |
| New vulnerability *classes* in source code | **New rules** authored from `scripts/specs/` → `mkrules.py` (rule + fail/pass fixtures) → released weekly | `rules/`, `rules/tests/` |
| CVEs exercising CWEs we don't cover yet | **CVE watch**: NVD feed (last 7 days, CRITICAL/HIGH) cross-referenced against rule `metadata.cwe` → gap table | [`cve-coverage.md`](cve-coverage.md) (refreshed every run) |
| Vulnerable dependencies **in your project** | SCA sidecar against live advisory DB (OSV) | `codegrep scan --only sca` |
| Vulnerable dependencies **in codegrep itself** | `cargo audit` (rustsec) on every weekly run; `cargo update` pulls compatible fixes first | weekly workflow |

codegrep itself stays **fully offline** — the CVE watch is a report for rule
authoring, not data loaded into the scanner.

## What every weekly run does

1. `cargo update` — pull compatible security patches for Rust dependencies
2. `cargo audit` — fail (and open/refresh a blocker issue) on rustsec advisories
3. Gates — `cargo test`, `clippy -D warnings`, `codegrep rule test rules/`
   (all 2152 fixtures)
4. CVE watch — NVD window → `docs/cve-coverage.md` + workflow summary
5. Bump `crates/codegrep` patch version + CHANGELOG entry (`scripts/bump.sh`)
6. Commit + tag `v*` + `scripts/publish.sh` → crates.io

If any gate fails: no tag, no publish, and a
`[automation] weekly sync blocked` issue is opened/refreshed.

## Closing a CVE-watch gap (adding a rule)

```sh
$EDITOR scripts/specs/gap-sec-NN.json    # original spec: patterns + fail/pass fixtures
python3 scripts/mkrules.py scripts/specs/gap-sec-NN.json
./target/release/codegrep rule test rules/   # every rule needs fixtures (CI gate)
git push   # merged rules ride the next weekly release
```

Rules must be authored from scratch (this repo reads no third-party rule
content); the gap table tells you *which* CWEs and example CVEs need coverage.
Optional local assist: `python3 scripts/rule-gen.py` (Ollama, offline).

## Manual trigger / dry-run

```sh
gh workflow run weekly                      # dry-run: gates + CVE report only
gh workflow run weekly -f publish=true      # full release
```

Publishing requires the `CARGO_REGISTRY_TOKEN` repository secret (a crates.io
token with publish scope). Without it the workflow still commits and tags but
skips the crates.io upload with a warning.
