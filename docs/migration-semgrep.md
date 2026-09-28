# Semgrep → codegrep migration
- Rule header: `rules:` list → single-doc YAML per rule (`id, languages, severity, message, fix, pattern|pattern-either|taint`).
- Operators: `pattern, pattern-either, patterns, pattern-not` supported in v0.1; `pattern-inside` partial; `pattern-not-inside`, `metavariable-comparison` roadmap.
- Metavars: `$VAR`, `$...ARGS`, `...` supported.
- Taint: `taint: {sources:[{patterns}], sinks:[{patterns}], sanitizers:[{patterns}]}` intra-procedural v0.1.
- Output: `--json` / `--sarif` compatible with GitHub code scanning.
- CI: replace `semgrep ci` with `codegrep scan --baseline <ref> --diff-only --sarif`.
