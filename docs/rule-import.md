# Importing rules from other scanners (portable pattern schema)

codegrep understands the **portable pattern-rule schema** — the YAML shape used
by common open-source static analyzers: `patterns:` conjunctions,
`pattern-either`, `pattern-not`, `metavariable-regex`,
`mode: taint` with `pattern-sources` / `pattern-sinks` / `pattern-sanitizers`,
and so on. Point `--config` (or `ScanOptions.rules`) at **your own local rule
files** and they load alongside codegrep's built-in MIT-licensed corpus.

```bash
# scan a repo with third-party rule files you already have locally
codegrep scan . --config ./my-rules/
```

Only files you pass in are ever parsed this way; codegrep ships none of their
content, and the translator is original MIT-licensed code.

## What translates

| Portable construct | codegrep equivalent |
|---|---|
| `pattern` | `pattern` |
| `pattern-either: [{pattern: ...}]` | `pattern-either` |
| `patterns:` with one positive + restrictions | `pattern` + `pattern-not` / `pattern-inside` |
| `metavariable-regex: {metavariable, regex}` | `metavariable-regex: {$VAR: regex}` |
| `metavariable-comparison: {metavariable, comparison}` | `metavariable-comparison: "$VAR op n"` |
| `mode: taint` + `pattern-sources/-sinks/-sanitizers` | native `taint:` block |
| `severity: CRITICAL/HIGH/MEDIUM/LOW` | `ERROR` / `WARNING` / `INFO` |
| `metadata` (scalars) | copied through (used by CVE-watch, reports) |

Unsupported languages are dropped from a rule's language list (e.g. COBOL in a
`[python, cobol]` rule keeps `python`); a rule with *no* supported language is
skipped. All 27 recognized languages import (including the text-scanned
ones: `rust`, `swift`, `dart`, `elixir`, `lua`, `powershell`, `sql`, …).

## What is refused (strictly)

We never weaken a rule to make it import. Any construct we cannot represent
with faithful semantics **skips that rule** and prints a warning naming the
rule and the construct:

- multiple AND-ed positive patterns (`patterns:` with two+ positives)
- `pattern-not-inside`, `pattern-regex`
- `focus-metavariable`, `requires`, `equivalences`
- bare (unquoted) numeric patterns — quote them (`"0o777"`)
- taint rules missing sources or sinks

Warnings appear on stderr from the CLI and in `ScanReport.warnings` /
`load_rule_set_report(...)` from the library. A skipped rule never blocks the
rest of the directory from loading.

## Known approximations

- **`pattern-not` is line-scoped** in codegrep's matcher; in the portable
  schema it is structural (enclosing-scope). Imported negations may fire in a
  few extra cases. Fix: tighten the positive pattern.
- **`pattern-inside` is coarse** (line-neighborhood check, not full AST
  containment).
- **Nested `pattern-either` inside `patterns:`** is not supported.
- Multiple `pattern-not`s per rule are not supported (keep the strongest one,
  or split the rule).

## Verifying what was imported

```bash
codegrep rule test ./my-rules/     # validity + skip reasons on stderr
codegrep scan . --config ./my-rules/ --metrics
```

`rule test` lists every translated rule id with its languages and severity, so
you can diff the import against your source set before gating CI on it.
