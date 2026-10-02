# Architecture

How a scan actually flows through scanward, and the invariants that any change
must preserve. This is the reference for contributors; the rule format itself
lives in [`rule-authoring.md`](rule-authoring.md) and the CLI surface in the
[README](../README.md).

## Pipeline

```
scan(path, options)
  │
  ├─ discover_files           parallel walker (ignore crate) → .gitignore honoured,
  │                           hidden files included, every text file a candidate
  │
  ├─ language resolution      Language::from_path(ext) → 27 recognized languages,
  │                           else Language::Generic (fallback, 10 MB read cap)
  │
  ├─ cache lookup             content hash → skip unchanged files (--no-cache to disable)
  │
  ├─ literal pre-filter       rules whose extracted literals do not appear in the
  │                           file are never compiled or matched (Aho-Corasick)
  │
  ├─ parse (when needed)      tree-sitter CST for the 10 grammar-backed languages,
  │                           error-tolerant, lazy; text scan for the rest
  │
  ├─ match                    patterns compiled to regex over whole file text;
  │                           metavariable-regex / -comparison narrow the hit
  │                           taint rules: sources → propagators → sanitizers → sinks
  │
  ├─ dedup + filters          severity floor, --exclude/--include, suppressions,
  │                           --baseline/--diff-only, inline scanward-ignore
  │
  └─ emit                     human table | --json | --sarif 2.1.0 | --junit
```

Matching is deliberately **regex-over-text**, not AST-node matching. That is
what makes the engine language-agnostic, adds no per-language dependency, and
keeps results deterministic; tree-sitter is used for parsing/IR and for the
call summaries taint consumes, not to gate pattern hits.

## Crates

| Crate | Responsibility |
| --- | --- |
| [`scanward`](../crates/scanward) | Library API + CLI (`scan`, `rule test`, `autofix --verify`), walker, cache, SARIF/JSON/JUnit output |
| [`cg-parser`](../crates/cg-parser) | Language detection (27 languages), tree-sitter loading, error-tolerant parse, IR lowering |
| [`cg-ir`](../crates/cg-ir) | Shared node representation normalized across languages |
| [`cg-matcher`](../crates/cg-matcher) | Pattern → regex compilation and capture semantics, metavariable-regex/-comparison |
| [`cg-taint`](../crates/cg-taint) | Intra-procedural taint with function summaries |
| [`cg-rules`](../crates/cg-rules) | Rule loading/validation, literal extraction, portable-schema importer |

Dependencies flow one way: `cg-parser` → `cg-ir` → `cg-matcher` → `cg-taint` →
`cg-rules` → `scanward`. No crate depends on `scanward`.

## Invariants

These are not preferences; breaking one is a bug.

1. **The core scan is offline.** No network, no registry fetch, no telemetry, no
   API key. `--offline` additionally refuses sidecars. If a feature needs the
   network, it belongs in a side-plane (`ai-triage/`, `--only secrets|sca`),
   never in the scan path.
2. **Deterministic.** Same input, same output, same order. No clock-, locale-,
   or hash-order-dependent behaviour in findings.
3. **Never skip a file silently.** Unrecognized extensions fall back to
   `generic` rather than being ignored; if a file is not scanned (unreadable,
   binary, over the size cap) that is the only acceptable outcome, and it must
   not be reported as "clean".
4. **Never panic on user input.** Malformed code, malformed rule files, hostile
   archives, and syntax errors all degrade to warnings.
5. **Every rule ships a fail and a pass fixture.** `scanward rule test rules/`
   is a merge gate, not a suggestion.
6. **Original content only.** No third-party scanner code and no third-party
   rule text — see [`licensing.md`](licensing.md).
7. **Parallel by default, and optional.** `--jobs` bounds rayon; `--metrics`
   reports the split.

## Adding a language

1. Add the `Language` variant and its extensions in `crates/cg-parser/src/lib.rs`
   and register the name in `cg-parser`'s tests. Text-scanned languages need no
   grammar — that is the expected case.
2. Add the name to `map_languages` in `crates/cg-rules/src/portable.rs` so
   third-party rules for it import instead of being dropped.
3. Author the first pack in `scripts/specs/langpack-<lang>.json` and generate it
   (see [`rule-authoring.md`](rule-authoring.md)).
4. Update the language table in the README.
5. Run the gates in [`CONTRIBUTING.md`](../CONTRIBUTING.md) — `testdata/` and
   the self-scan baselines must not move.

## Deliberate limitations

Stated here so they read as decisions, not gaps. The reasoning behind each is
in [`coverage-policy.md`](coverage-policy.md).

- `pattern-inside` is coarse (call-site containment, not full block scoping).
- `pattern-not` is enforced per line.
- No cross-file or cross-function taint; taint is intra-procedural with call
  summaries.
- No lookahead in patterns — the regex engine has none.
- CWE classes that require block-range scoping or repeated metavariable equality
  (use-after-free, double free, OOB read, NULL deref, TOCTOU) are out of reach
  of the matcher and are not claimed.