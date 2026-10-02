# Contributing to codegrep

Thanks for wanting to help. This document is the whole deal: how to get a
change in, what CI will check, and the two rules that are non-negotiable in
this project (original content only, offline by design).

## Ground rules

1. **Every change lands through a pull request.** `main` is protected: no
   direct pushes, no force pushes, no branch deletion, and linear history
   only. Even the maintainer works from a branch and a PR — that is deliberate,
   because it keeps the review trail intact.
2. **Original content only.** codegrep ships its own engine and its own rules.
   Do not copy third-party scanner code or rule-registry content (those
   registries are generally incompatible with this project's terms).
   Concepts from permissively licensed projects (Tree-sitter, Gitleaks,
   OSV-Scanner, Trivy, Bandit, ESLint) are
   fine to *learn from*; text is not fine to paste. Every rule must be written
   from scratch, even if it covers a well-known CVE class.
3. **Offline stays offline.** The scanner must never need the network: no
   remote rule registries, no telemetry, no phoning home, and no new runtime
   dependency that does. If your change needs the network at scan time, it
   belongs in a separate side-plane (see `ai-triage/`, `--only sca`).

## Workflow

```sh
git checkout -b my-change          # always a branch, never main
# ... edit, then run the local gates (below) ...
git push -u origin my-change
gh pr create --fill
```

If CI is green, the maintainer merges (squash or rebase — merge commits are
disabled) and the branch is deleted automatically. Review threads must be
resolved before merge.

**Forks:** this repository is the canonical source, and it is configured to
reject unreviewed writes to `main`, so a fork PR cannot land unattended.
Still, contributions are best sent from a branch in this repository: fork PRs
add review friction and we cannot guarantee timely attention to them. If you
opened a fork, please open a PR against `main` here and say so in the
description — it will be reviewed on its merits, not on where it came from.

## Local gates (run these before pushing)

```sh
cargo test --workspace                                    # unit + integration
cargo clippy --workspace --all-targets -- -D warnings     # zero warnings
cargo build --release -p codegrep
./target/release/codegrep rule test rules/                 # rule + fixture gate
./target/release/codegrep scan ./crates --min-severity warning --error   # self-scan
./target/release/codegrep scan ./testdata --rules ./rules --metrics     # demo scan
```

`cargo deny check` runs in CI (advisories, licenses, bans, sources). All six
commands above must be green locally first — CI is the referee, not the
first place you find out.

## Adding a rule (the common contribution)

Rules are authored as JSON specs and generated into YAML plus fixtures
(see [`docs/rule-authoring.md`](docs/rule-authoring.md)):

```sh
$EDITOR scripts/specs/my-rule.json     # id, languages, severity, message, fix, fixtures
python3 scripts/mkrules.py scripts/specs/my-rule.json
./target/release/codegrep rule test rules/
```

A spec must carry:

- `id` — unique, `kebab-case`, filesystem-safe (it becomes a directory name).
- `languages` — a recognized language name (see `Language::from_path` in
  `crates/cg-parser/src/lib.rs`) or `generic`.
- `severity`, `category`, `message`, and a `fix` that tells the reader what to
  do.
- A `fail` fixture that **must** trigger and a `pass` fixture that **must**
  stay clean. `rule test` enforces both; a rule without fixtures will fail CI.
- `metadata` with `owasp`, `cwe`, and `confidence`.

Severity discipline (from `docs/coverage-policy.md`): sink-presence rules are
WARNING unless the sink is rarely legitimate (`eval`, `unserialize`, `sh -c`
→ ERROR); a rule that narrows a sink with `metavariable-regex` on
user-controlled input may claim ERROR/HIGH. Do not ship INFO-band noise.

## Adding a language

1. Add the `Language` variant and its extensions in `crates/cg-parser/src/lib.rs`
   (text-scanned languages need no grammar — keep it that way unless AST
   fidelity is required).
2. Add the name to the portable-importer map in `crates/cg-rules/src/portable.rs`
   so third-party rules for it import instead of being dropped.
3. Author the first pack in `scripts/specs/langpack-<lang>.json` and generate it.
4. Update the language table in `README.md` and the counts you can verify with
   `codegrep rule test rules/`.

A new language must not regress the ones that exist: `testdata` and the
self-scan baselines are part of CI.

## Commit and PR conventions

- Conventional-Commit subjects, matching existing history: `feat(lang): …`,
  `fix(rules): …`, `docs: …`, `chore(deps): …`.
- Explain **why** in the body. A diff already says what changed; the body
  should say what problem it solves, what you measured, and what you decided
  against.
- One logical change per PR. Rule batches are fine; unrelated refactors are not.
- Update `CHANGELOG.md` under `## Unreleased` for user-visible changes.
- Keep marketing numbers out of the README — hard rule/fixture counts go stale
  on every batch and are not a quality signal.

## Security reports

Do **not** open a public issue for a vulnerability in codegrep itself or in
the rules it ships. Follow [`SECURITY.md`](SECURITY.md) (private disclosure,
acknowledgement targets, supported versions).

## Code of conduct

Be civil, assume good faith, and review the code rather than the contributor.
Unsolicited promotional or AI-generated bulk rule dumps that skip the fixture
gate will be closed.

## License and your contribution

codegrep is **not** MIT-licensed any more. The first release after `0.12.0`
is licensed under [PolyForm Noncommercial 1.0.0](LICENSE): free for personal,
research, educational, charity, public-sector and other noncommercial use;
**commercial use is not permitted** without a separate license from the
maintainer. See [`docs/licensing.md`](docs/licensing.md) for the full terms and
the version boundary (versions `0.12.0` and earlier remain MIT, permanently).

By opening a pull request you agree to these terms for your contribution:

1. You license your contribution to the project (the licensor), and you have
   the right to do so — no employer-owned code you cannot license, no code you
   did not write, nothing generated from a license you do not hold.
2. The project may distribute your contribution under these terms, and the
   maintainer may relicense the project as a whole, including to a permissive
   license, at their discretion.
3. Your contribution is provided "as is", without warranty.

Contributions merged before this change were accepted under MIT and stay MIT
for their authors. Nothing here revokes a license you already hold.
