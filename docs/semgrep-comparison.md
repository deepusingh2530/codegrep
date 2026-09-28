# codegrep vs Semgrep — measured comparison (2026-09-14)

Baseline: Semgrep 1.136.0 (already installed on this machine), codegrep 0.3.0,
Apple ARM64. Test rules were 5 trivially-equivalent patterns written for the
comparison only (`os.system(...)`, `eval(...)` x2, `exec.Command(...)`,
`Runtime...exec(...)`). Nothing taken from Semgrep's rule registry
(Semgrep Rules License v1.0 is not commercially safe to copy).

## Head-to-head numbers (measured, not estimated)

| Corpus | codegrep 0.3.0 | Semgrep 1.136.0 | Ratio |
|---|---|---|---|
| 10 files (`testdata/`), 5 shared rules | <0.01s wall (1ms internal) | ~1.4s wall | ~140x |
| 2,000 clean files, 5 shared rules | 0.02s wall (25ms internal) | 1.82s wall | ~90x |
| 12,000 clean files, 5 shared rules | 0.13s wall | 3.61s wall | ~28x |
| 10,000 clean files, full 72-rule pack | 0.11s | n/a (registry not used) | — |

Findings parity on the shared 5-rule set over `testdata/`: **5 vs 5**.

Caveats: Semgrep wall time is dominated by fixed Python startup (~1.3s even
on 10 files), so the gap narrows as repos grow — codegrep is still an order of
magnitude faster at 12k files, and its Aho-Corasick pre-filter means cost
barely moves with rule count. `--config auto` (registry, network) was
deliberately not tested.

## Feature matrix

| Dimension | Semgrep (grounded in docs, Sep 2026) | codegrep | Estimate |
|---|---|---|---|
| Languages | 30+ GA | 8 (py/js/ts/go/java/ruby/php/csharp) | ~25% |
| Rule count | 2,000+ community + 20,000+ Pro | 72 original | ~3% by count; OWASP Top-10 + 6 framework packs |
| Pattern operators | metavars, ellipsis, regex, comparison, inside/not-inside, join, deep matching | `$VAR`, `$...ARGS`, `...`, regex, comparison, coarse `inside` | ~60% |
| Taint | cross-file/cross-function (Pro), framework-aware | intra-file scopes + call summaries | ~25% |
| Offline scan | yes (OSS) | yes + strict `--offline` | 100% |
| Outputs | SARIF/JSON + GitLab, JUnit, EMACS, Vim... | SARIF 2.1.0 + JSON + table | ~60% |
| Workflow | pre-commit, CI/diff-aware, LSP/IDE, PR comments, fingerprints, dashboard | CLI, GH Action, pre-commit hook, `--diff-only`, cache, dedup | ~40% |
| Secrets/SCA | built-in (Pro + reachability) | own secret patterns + gitleaks/osv-scanner wrappers | ~30% |
| AI | Pro autofix/triage (managed) | BYOK triage + verified autofix, offline fallback | ~20%, self-hosted |

Bottom line: engine bet validated (faster, parity on shared rules); depth gap
is rules + cross-file taint + platform. Scanning pipeline ~70%, detection
content ~10%, enterprise workflow ~35%.

## Reproduce

```sh
# shared-rule fixtures used for the timing above (local only, not shipped):
# /tmp/sgbench/bench.yaml (semgrep) and /tmp/cgbench/r{1..5}.yaml (codegrep)
SEMGREP_SEND_METRICS=off semgrep scan --config /tmp/sgbench/bench.yaml \
  --metrics=off --quiet --disable-version-check --json -o /dev/null testdata
./target/release/codegrep scan testdata --rules /tmp/cgbench --no-cache --metrics
```
