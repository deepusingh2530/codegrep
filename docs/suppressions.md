# False-positive management

Two complementary mechanisms, both offline and deterministic:

1. **Suppression files** — auditable, reviewable entries with a *required
   reason* (and optional owner/expiry). Checked into the repo so every
   silenced finding has a paper trail in PR review.
2. **Inline `codegrep-ignore` comments** — developer-ergonomic, right at the
   finding.

Both are reflected in `ScanReport.suppressed` / `--metrics` output
(`suppressed=N`), so a scan never silently hides findings.

## Suppression files

```yaml
# .codegrep-suppressions.yml (auto-discovered at the scan root)
- rule: py-eval-exec            # exact id, or glob like "py-*"
  path: "testdata/**"           # optional; same glob/substring style as --exclude
  line: 42                      # optional exact line
  reason: sandboxed eval in test harness   # REQUIRED — reviewed in PRs
  owner: platform-team          # optional, informational
  expires: 2027-06-30           # optional YYYY-MM-DD
```

All specified fields must match for a finding to be suppressed (AND).

| Behavior | Detail |
|---|---|
| Auto-discovery | `<scan-root>/.codegrep-suppressions.yml` (or `.yaml`) when no `--suppress` is given |
| Explicit files | `--suppress FILE` (repeatable) — **replaces** auto-discovery |
| Expired entries | Stop applying, emit a stderr warning, findings reappear |
| Validation | `reason` required; unknown keys rejected (`exires:` typo fails the scan, never silently no-ops); bad dates fail the scan |
| Library | `ScanOptions.suppress: Vec<String>`, `ScanReport.suppressed` |

```bash
codegrep scan . --suppress policy/suppressions.yml --metrics
```

## Inline comments

```python
os.system(cmd)                     # codegrep-ignore
subprocess.run(x, shell=True)      # codegrep-ignore(py-subprocess-shell, other-rule)
# codegrep-ignore-next-line
eval(payload)
```

Rules:

- **Same line only**: `# codegrep-ignore` suppresses findings on *its own*
  line; it never leaks to following lines.
- **Next line**: `codegrep-ignore-next-line` (on line N) suppresses findings
  on line N+1 — for statements you prefer to annotate above.
- **Scoped**: `codegrep-ignore(rule-a, rule-b)` suppresses only the listed
  rule ids; bare form suppresses every finding on that line.
- **Comment marker required**: the token must sit in a comment (`#`, `//`,
  `<!--`, `/*`) and at a word boundary — a string like `"codegrep-ignore"`
  does not suppress.

Suppressions apply to cached scans too (comments are part of the file hash,
so edits invalidate the cache automatically).

## Design notes

- Suppression files are applied *after* the cache lookup: editing the file
  takes effect on the next scan without invalidating cached findings.
- The count of suppressed findings is always reported (stderr note +
  `--metrics` + `ScanReport.suppressed`) — nothing is hidden without a trace.
- Inline comments change file content, so removing one triggers a full
  rescan of that file (content-hash cache key).
