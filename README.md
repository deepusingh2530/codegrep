# codegrep — fast multi-language SAST (MIT)

Offline, deterministic scanner. Tree-sitter parsing (Python, JavaScript,
TypeScript, Go, Java, Ruby, PHP, C#), structural `$VAR` / `...` matching,
Aho-Corasick pre-filter + rayon parallelism, function-scope taint with call
summaries, 1183 MIT-original rules (OWASP + Django/Flask/Express/Spring/Rails/
Laravel + secrets — every language covered per `docs/coverage-policy.md`),
persistent content-hash cache (`~/.cache/codegrep`), SARIF+JSON output.

## Quickstart

```sh
cargo build --release -p codegrep
./target/release/codegrep scan ./testdata --metrics
./target/release/codegrep scan ./testdata --json --rules ./rules
./target/release/codegrep rule test rules/   # validates rules + runs fixtures
./target/release/codegrep scan --only secrets .
./target/release/codegrep scan --help
```

Cache is on by default (`--no-cache` to disable, `--cache-dir` to override).
`--offline` enforces no-network SAST (secrets/sca sidecars refused offline).
AI triage/autofix is a separate BYOK side-plane:
`python3 ai-triage/triage.py --mode triage --input findings.json`
(heuristic offline; Anthropic/OpenAI/Ollama with keys). New rules can be
synthesized with `python3 scripts/rule-gen.py` (Ollama-local, validated —
see `prompts/rule-generator.md`). Core scan never needs keys or network.

## Speed design

Rule literal index skips parsing non-candidate files; rayon scans files in parallel;
content-hash cache makes repeat scans incremental;
diff-only (`--baseline main --diff-only`) reports changed lines only.

## Layout

See `MASTER_PROMPT.md` (source of truth) + `crates/*`.
Rules live in `rules/<lang>/*.yaml` plus `rules/secrets/` (own MIT content,
fixtures under `rules/tests/<rule-id>/`).
AI triage/autofix lives in `ai-triage/` and never blocks `scan`.

## License safety

Engine and rules are original MIT code. Parsing via Tree-sitter (MIT).
Secrets/SCA delegate to external `gitleaks` (MIT) / `osv-scanner`
(Apache-2.0) processes — never linked. No Semgrep code or rules, no copyleft
or commercial-licensed dependencies.
