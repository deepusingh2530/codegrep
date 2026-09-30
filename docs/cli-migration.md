# Migrating to codegrep
- Rule header: `rules:` list → single-doc YAML per rule (`id, languages, severity, message, fix, pattern|pattern-either|taint`).
- Operators: `pattern, pattern-either, patterns, pattern-not, metavariable-regex, metavariable-comparison` supported; `pattern-inside` partial (file-level containment); `pattern-not-inside` roadmap.
- Metavars: `$VAR`, `$...ARGS`, `...` supported.
- Taint: `taint: {sources:[{patterns}], sinks:[{patterns}], sanitizers:[{patterns}]}` intra-procedural v0.1.
- Output: `--json` / `--sarif` (GitHub code scanning) / `--junit` (CI test tabs).

## CLI flag mapping

| Common SAST CLI convention | codegrep |
| --- | --- |
| `--config=<file-or-dir>` (repeatable) | `--config=<PATH>` (repeatable; supersedes `--rules`) |
| `--config=p/...`, `--config=auto`, git URLs | refused with a clear error (offline-first; point at local files) |
| `--exclude=<glob>` / `--include=<glob>` | `--exclude` / `--include` (repeatable; glob `*` `**` `?` or substring) |
| `--severity=ERROR` (floor) | `--min-severity error\|warning\|info` |
| `--error` (exit 1 on findings) | `--error` |
| `--json` / `--sarif` | `--json` / `--sarif` (SARIF includes `driver.rules` metadata + `security-severity`) / `--junit` (JUnit XML, one testsuite per file) |
| `--metrics=on/off` | `--metrics` (off by default) |
| `--baseline-commit` + diff scan | `--baseline <ref> --diff-only` |
| typical CI gate command | `codegrep scan --baseline <ref> --diff-only --sarif --error -o results.sarif` |
