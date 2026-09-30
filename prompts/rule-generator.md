# Rule Generator — AI prompt pack for codegrep rules (original output)

> License safety (non-negotiable): the model must produce ORIGINAL patterns.
> Never reproduce any third-party registry rules or rule content.
> Input specs describe vulnerability CLASSES (facts: sink APIs, CWEs) — output
> patterns are written from scratch for the codegrep engine below.

## Engine contract (tell the model this)

codegrep patterns are code-shaped with three wildcards, compiled to regex
over file text (whitespace-insensitive, multi-line):

- `$VAR` — one code unit (greedy only if trailing, else lazy minimal)
- `$...ARGS` / `$...ANY` — variadic filler, prefer `...` for arg lists
- `...` — any text filler
- Everything else is literal (regex-escaped). No character classes, no
  alternation, no anchors. Keep patterns to ONE call/statement shape.
- A pattern with `, ...` (e.g. `f($VAR, ...)`) MISSES single-arg calls —
  always emit BOTH `f($VAR)` and `f($VAR, ...)` variants via `pattern-either`.
- `metavariable-regex: {VAR: <regex>}` constrains ONE capture (unanchored
  search). Use for secret formats only.
- Keep the dangerous-API literal in the pattern (it feeds the Aho-Corasick
  pre-filter; a pattern without literals scans everything).

## Required YAML schema (single doc per file)

```yaml
id: <lang>-<slug>            # e.g. py-subprocess-shell
languages: [<lang>]          # python|javascript|typescript|go|java|ruby|php|csharp|generic
severity: ERROR|WARNING
category: security:<slug>
message: <one-line, no unescaped ": " inside, quote if needed>
fix: <one-line remediation>
pattern: <shape>             # OR pattern-either: [{pattern: ...}, ...]
metadata: {owasp: ..., cwe: CWE-..., confidence: HIGH|MEDIUM|LOW}
```

## Generation prompt (copy/paste per rule, fill SPEC)

```
Write ONE codegrep detection rule as YAML (schema above) for this vulnerability
class. Output YAML only, no prose.

SPEC:
- language: {lang}   sink/API: {sink}   weakness: {cwe_text}   severity: {sev}
- vulnerable example (write the AROUND shape, model must generalize):
  {vuln_snippet}
- clean counterexample (must NOT match):
  {clean_snippet}

Constraints: original pattern from scratch; single call/statement shape;
both single-arg and multi-arg variants via pattern-either; keep the
dangerous-API literal; valid YAML (quote strings containing ": " or
leading "{", "-", "@").
```

## Validation loop (mechanical, no judgment)

1. `codegrep rule test <tmpdir>` — schema must load.
2. Fail-snippet must produce ≥1 finding with the new rule alone;
   clean-snippet must produce 0 (`findings_for_rule` semantics).
3. On failure: feed the failure back once ("pattern missed / false-positive
   because ..."), accept second-try output only if it passes, else escalate
   to a human-written pattern.
4. Accepted rules land in `rules/<lang>/<slug>.yaml` with fixtures at
   `rules/tests/<id>/{fail,pass}.*`.

## Coverage checklist (idea-level only — titles, never content)

Track per language x OWASP: sqli, cmdi, xss, ssrf, traversal, redirect,
deser, ssti, crypto-weak, secrets, misconfig, framework-specific sinks.
A checked box means "we wrote and tested an original rule", never "ported".
