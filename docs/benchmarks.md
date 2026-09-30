# codegrep — measured performance comparison (2026-09-14)

Baseline: a widely-used Python-based open-source SAST scanner, version
1.136.0 (installed locally), Apple ARM64. Test rules were 5 trivially-
equivalent patterns written for the comparison only (`os.system(...)`,
`eval(...)` x2, `exec.Command(...)`, `Runtime...exec(...)`). Nothing taken
from any third-party rule registry (those registries' licenses are not
compatible with this project's terms).

## Head-to-head numbers (measured, not estimated)

| Corpus | codegrep | Reference scanner | Ratio |
|---|---|---|---|
| 10 files (`testdata/`), 5 shared rules | <0.01s wall (1ms internal) | ~1.4s wall | ~140x |
| 2,000 clean files, 5 shared rules | 0.02s wall (25ms internal) | 1.82s wall | ~90x |
| 12,000 clean files, 5 shared rules | 0.13s wall | 3.61s wall | ~28x |
| 10,000 clean files, full 72-rule pack | 0.11s | n/a (registry not used) | — |

Findings parity on the shared 5-rule set over `testdata/`: **5 vs 5**.

Caveats: the reference scanner's wall time is dominated by fixed Python
startup (~1.3s even on 10 files), so the gap narrows as repos grow — codegrep
is still an order of magnitude faster at 12k files, and its Aho-Corasick
pre-filter means cost barely moves with rule count. Remote-registry config
(`--config auto`, network) was deliberately not tested.

## Feature matrix

| Dimension | Reference scanner (from public docs, Sep 2026) | codegrep | Estimate |
|---|---|---|---|
| Languages | 30+ GA | 27 recognized (10 with tree-sitter AST, 17 text-scanned incl. generic fallback) | ~90% |
| Rule count | 2,000+ community + 20,000+ paid tier | smaller curated corpus, 100% original | lower by count; OWASP Top-10 + framework packs + secrets, every rule with pass/fail fixtures |
| Pattern operators | metavars, ellipsis, regex, comparison, inside/not-inside, join, deep matching | `$VAR`, `$...ARGS`, `...`, regex, comparison, coarse `inside` | ~60% |
| Taint | cross-file/cross-function (paid tier), framework-aware | intra-file scopes + call summaries | ~25% |
| Offline scan | yes (OSS) | yes + strict `--offline` | 100% |
| Outputs | SARIF/JSON + GitLab, JUnit, EMACS, Vim... | SARIF 2.1.0 + JUnit XML + JSON + table | ~70% |
| Workflow | pre-commit, CI/diff-aware, LSP/IDE, PR comments, fingerprints, dashboard | CLI, CI job template, `--diff-only`, cache, dedup | ~40% |
| Secrets/SCA | built-in (paid tier + reachability) | own secret patterns + gitleaks/osv-scanner wrappers | ~30% |
| AI | managed autofix/triage | BYOK triage + verified autofix, offline fallback | ~20%, self-hosted |

Bottom line: engine bet validated (faster, parity on shared rules); depth gap
is rules + cross-file taint + platform. Scanning pipeline ~70%, detection
content ~10%, enterprise workflow ~35%.

## Reproduce

```sh
# shared-rule fixtures used for the timing above (local only, not shipped):
# /tmp/cgbench/r{1..5}.yaml (codegrep side)
./target/release/codegrep scan testdata --rules /tmp/cgbench --no-cache --metrics
```
