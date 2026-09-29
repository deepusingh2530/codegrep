# codegrep — Master Prompt (MIT-licensed offline SAST)

> Paste this entire file as the system prompt into Opencode / Claude Code / Codex before starting any work on `codegrep`. It is the source of truth for architecture, constraints, and execution order.

## 1. Project identity

**Name:** codegrep
**Binary:** `codegrep`
**Goal:** Multi-language SAST scanner that scans code repositories **faster than incumbent SAST tools**, with deterministic results offline.
**AI policy:** AI is enhancement-only, never in scan hot path. Core scan must work fully offline with no API keys. AI lives in async side-plane for triage, explainer, auto-fix, rule synthesis.
**License safety:** 100% commercially safe. Do NOT copy any third-party scanner engine code (several are LGPL-2.1 or commercial) or rule-registry content (registry licenses are typically non-MIT). Write all engine code and rules from scratch. Allowed: Tree-sitter (MIT), ast-grep ideas (MIT, ideas only, no copy), Gitleaks (MIT), OSV-Scanner (Apache-2.0), Trivy (Apache-2.0), ESLint/Bandit concepts (MIT/Apache-2.0, ideas only).

## 2. Success criteria to beat incumbents

1. **Speed cold:** 3-10x faster than a leading open-source CLI SAST scanner (same rules, metrics off) on 500k LOC monorepo, 8-core machine.
2. **Speed PR:** `<10s` for PR with <500 changed lines via diff-only + cache. 1M LOC cold `<2min`.
3. **Languages v1:** Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C# (8 langs). Design for 30+ later.
4. **Accuracy:** <15% FP after AI triage on labeled 200-finding set. Every rule has pass/fail tests.
5. **DevEx:** `codegrep scan ./repo --json` works offline, respects `.gitignore`, outputs SARIF + JSON, single static binary, `brew / npx / docker / GitHub Action` install.
6. **Unified:** `codegrep scan --only sast|secrets|sca` in one binary. Secrets via Gitleaks wrapper, SCA via OSV-Scanner + Trivy wrapper.
7. **Zero crash:** timeout + memory cap per file, error-tolerant parsing (scan even with syntax errors).

## 3. Architecture (must follow)

```
CLI (Rust, clap): codegrep scan|test|rule test|autofix|login
  ↓
Frontend: parallel walker (ignore crate) + .gitignore + git diff ranges + blake3 content hashing
  ↓
Pre-filter: rule literal indexing (Aho-Corasick / trigram) -> candidate rules per file. Skip parse if 0 candidates.
  ↓
Parse: Tree-sitter (MIT) -> CST, lazy, zero-copy, memmap2. Error-tolerant.
  ↓
IR: Own Generic AST: GNode{kind:u16, text, range, children, field}. Language adapters normalize call/function/string/identifier/import/if/loop/return.
  ↓
Match: structural matcher supporting exact-code-ignore-whitespace, $VAR (single expr/ident/block capture), $...ARGS (variadic), ... (ellipsis for stmts/args/array), metavariable-regex, metavariable-comparison, pattern / pattern-either / patterns / pattern-not / pattern-inside / pattern-not-inside
  ↓
Dataflow v2: intra-procedural CFG + fixed-point taint (sources -> propagators [assign, concat, f-string, +] -> sanitizers -> sinks) + constant propagation
  ↓
Output: JSON + SARIF 2.1.0 + PR annotations + evidence.json for AI. Dedup by hash(rule_id + file + normalized snippet).
  +
Sidecars (subprocess, not linked LGPL): gitleaks detect, osv-scanner, trivy fs
  +
AI side-plane (separate process, optional): triage FP filter, explainer, verified autofix (re-run matcher on patch), rule synthesizer (CVE -> draft YAML -> rule test -> human approve). Providers: Anthropic/OpenAI/Ollama, BYOK.
```

## 4. Tech stack (do not deviate without reason)

- Core: Rust 1.75+, workspaces: `crates/cli, parser, ir, matcher, taint, rules, bench`
- Libs: `tree-sitter, rayon, ignore, serde/serde_yaml/serde_json, aho-corasick, memmap2, blake3, gitoxide, clap`
- Grammars: `tree-sitter-python, javascript, typescript, go, java, ruby, php, c-sharp`
- Dashboard (separate service, later): TypeScript Next.js + Postgres + S3. Never block scanner on server.
- Bench: `criterion + hyperfine` vs incumbent scanners + ast-grep. Fail CI on >10% regression.

## 5. Repo layout to scaffold

```
codegrep/
  MASTER_PROMPT.md          # this file
  README.md
  Cargo.toml                # workspace
  crates/
    cli/                    # args, formatters (json/sarif), --diff-only, --baseline, --metrics, --offline
    parser/                 # tree-sitter loader + language detect + lazy parse
    ir/                     # GNode + adapters + CFG builder
    matcher/                # structural matcher + operators
    taint/                  # dataflow engine
    rules/                  # YAML loader + validator + literal indexer
    bench/                  # criterion benches + corpora
  rules/                    # MIT own rules: rules/<lang>/<category>.yaml + tests/pass|fail
  testdata/                 # hello-world per lang + vulnerable samples
  integrations/
    github-action/action.yml
    pre-commit-hooks.yaml
  platform/                 # dashboard (phase 3)
  docs/cli-migration.md
```

CLI examples (must all work):
`codegrep scan ./repo --json`
`codegrep scan ./repo --sarif -o results.sarif --only sast`
`codegrep scan --baseline main --diff-only --jobs 8`
`codegrep rule test rules/`
`codegrep autofix --verify`

## 6. Rule format (industry-standard YAML shape, renamed, original content only)

```yaml
id: py-sql-injection
languages: [python]
severity: ERROR
category: security:owasp-a1-injection
message: Untrusted input flows to SQL execution
fix: Use parameterized queries...
pattern-either:
  - pattern: cursor.execute("...%s..." % $VAR, ...)
  - pattern: cursor.execute(f"...{$VAR}...", ...)
taint:
  sources: [{patterns: ["request.$ANYTHING", "input(...)"]}]
  sinks: [{patterns: ["cursor.execute(...)"]}]
  sanitizers: [{patterns: ["escape_sql(...)"]}]
metadata:
  owasp: A03:2021-Injection
  cwe: CWE-89
  confidence: HIGH
```

Rules required before merge: id, languages, severity, message, fix, CWE/OWASP, plus `tests/pass.*` and `tests/fail.*`.

## 7. Execution order (do in order, gate each phase)

**Phase 1 — Scaffold + walker + parse:**
Scaffold workspace, parallel walker with `.gitignore`, Tree-sitter parse for py/js/ts/go, `codegrep scan <path> --json --jobs`. Test on `testdata/`, time 1000 files.

**Phase 2 — Generic AST + matcher:**
Implement GNode + adapters + matcher ($VAR, $...ARGS, ...). YAML loader + validator + `rule test` harness. Deliver 10 sample sqli/xss/exec rules with tests.

**Phase 3 — Speed layer:**
Literal extractor + Aho-Corasick pre-filter + rayon sharding + `--metrics`. Prove >60% files skip parsing on 100-rule pack, linear speedup to 8 cores.

**Phase 4 — Taint/CFG:**
Intra-procedural CFG (if/for/while/try/return) + fixed-point taint for py/js. Tests: direct, 2-hop via var, sanitized=>no finding, branch merge.

**Phase 5 — Diff-only + wrappers + SARIF:**
`--baseline + --diff-only` via git diff line ranges, blake3 cache in `~/.cache/codegrep`, Gitleaks/OSV wrappers, unified SARIF, GitHub Action with inline PR annotations on changed lines only.

**Phase 6 — AI side-plane (async):**
`--evidence` emit, separate `ai-triage/` service (pluggable LLM), `codegrep autofix --verify` (re-scan patch, show only verified). Offline works without keys.

**Phase 7 — Expand to 8 langs + 120 rules:**
Add java/ruby/php/csharp adapters + OWASP packs: sqli,xss,cmdi,ssrf,pathtraversal,open-redirect,xxe,ssti,deser,secrets,weak-crypto. 15 rules/lang with tests.

**Phase 8 — Harden + benchmark release:**
Fuzz matcher, flamegraph profile, per-file timeout, `--offline/--strict`, SBOM, public bench page, rule-format converter script (common YAML SAST formats → codegrep).

## 8. Global constraints for every code change

- No third-party code/rules copy. All original.
- Deterministic offline core. No network, no LLM in `scan` hot path.
- Every feature: implementation + unit tests + bench impact note.
- Respect `.gitignore`, handle syntax errors gracefully, never panic on user code.
- Parallel by default, zero-copy where possible, no Python runtime dependency.
- Output stable SARIF + JSON schemas. Dedup findings.
- Write idiomatic Rust, `cargo fmt/clippy/test` clean.

## 9. How to start (for agent)

1. Read MASTER_PROMPT.md fully.
2. Run `ls -la` and `cat Cargo.toml` (if exists) to detect current state.
3. Start at Phase 1 unless workspace already exists — then continue to next incomplete phase.
4. After each phase, run `cargo test && cargo clippy -- -D warnings` and report metrics + files changed + next step.
