# Documentation

| Document | What it answers |
| --- | --- |
| [architecture.md](architecture.md) | How a scan flows, what each crate does, the invariants a change must preserve, deliberate limitations |
| [rule-authoring.md](rule-authoring.md) | How to write a rule: engine contract, schema, fixtures, validation loop, coverage checklist |
| [coverage-policy.md](coverage-policy.md) | What is deliberately *not* flagged, and why; the severity contract |
| [cve-coverage.md](cve-coverage.md) | Generated weekly CVE-watch gap table: which CWEs recent CVEs exercise that no rule covers yet |
| [release-cadence.md](release-cadence.md) | Weekly release flow, what each gate enforces, how a CVE gap becomes a rule |
| [cli-migration.md](cli-migration.md) | Flag-by-flag mapping from other scanners' CLIs to scanward |
| [benchmarks.md](benchmarks.md) | Measured performance against a reference scanner, with the method |
| [suppressions.md](suppressions.md) | False-positive management: suppression files and inline ignores |
| [rule-import.md](rule-import.md) | Using rules written in the portable pattern schema, and what is refused |
| [licensing.md](licensing.md) | Noncommercial terms, the MIT boundary for 0.12.0 and earlier, commercial licensing |
| [supply-chain.md](supply-chain.md) | Dependency inventory, licence policy and typosquat analysis: what is checked offline, and what needs a sidecar |

Project-level documents live at the repository root: [README](../README.md),
[CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md),
[CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md), [CHANGELOG](../CHANGELOG.md).

## Where things live

| Path | Contents |
| --- | --- |
| `rules/<lang>/` | Rule YAML, batched by category |
| `rules/tests/<rule-id>/` | `fail*` and `pass*` accuracy fixtures |
| `scripts/specs/` | JSON specs rules are generated from |
| `scripts/mkrules.py` | Spec → YAML + fixtures |
| `scripts/cve_watch.py` | Generates `cve-coverage.md` from the NVD feed |
| `crates/` | The engine (see [architecture.md](architecture.md)); `cg-deps` parses dependency manifests |
| `integrations/` | GitHub Action, pre-commit hooks |
| `ai-triage/` | Optional BYOK side-plane — never in the scan path |
| `testdata/` | Known-findings corpus with a fixed baseline count |
| `assets/` | Brand artwork and its usage rules |