<!-- Keep this short: it is a checklist, not a form. -->

## What

<!-- One or two sentences. What changes, and which user-visible problem it solves. -->

## Why

<!-- The motivation. What breaks (or stays broken) without this. Link the issue if there is one. -->

## How it was verified

<!-- Tick what you ran locally, and paste the numbers that matter. -->

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `codegrep rule test rules/` (required for any rule change)
- [ ] self-scan of `crates/` is still clean (required for engine changes)
- [ ] `testdata` finding count unchanged (required for rule changes)

## Checklist

- [ ] Comes from a branch, lands via PR (never a direct push to `main`)
- [ ] New rules are original, MIT-licensable, and ship `fail` + `pass` fixtures
- [ ] No new runtime network dependency; `--offline` still refuses everything
- [ ] `CHANGELOG.md` updated under `## Unreleased` if user-visible
- [ ] No third-party code, rule text, or registry content copied
