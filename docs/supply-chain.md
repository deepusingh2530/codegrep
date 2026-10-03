# Supply-chain checks

Three capabilities, deliberately split by what they can honestly know.

| Check | Command | Needs network | What it can tell you |
| --- | --- | --- | --- |
| Dependency inventory | `--only licenses` / `--only typosquat` | no | what your manifests declare, and which names look impersonated |
| CVE matching | `--only sca` | yes (osv-scanner) | whether a known CVE affects a resolved version |
| Secrets | `--only secrets` | no (gitleaks) | whether credentials are committed |

The inventory is native and offline because it is the part that can be done
without an external database. Anything that needs a vulnerability feed, a
registry, or a package index stays a sidecar, and scanward refuses to pretend
otherwise — a scanner that guesses is worse than one that says "I don't know".

## Inventory

[`crates/cg-deps`](../crates/cg-deps) parses what a repository actually
contains:

| Ecosystem | Files |
| --- | --- |
| Cargo | `Cargo.lock`, `Cargo.toml` |
| npm | `package-lock.json` (v1 tree and v2/v3 `packages`) |
| PyPI | `requirements.txt`, `pyproject.toml` (PEP 621 + Poetry), `poetry.lock` |
| Go | `go.mod` |
| Composer | `composer.lock` |
| RubyGems | `Gemfile.lock` |

Maven and MSBuild are declared gaps rather than approximations: a
half-correct inventory is worse than none when a policy decision depends on it.

Each record carries name, version, ecosystem, declared licence, directness, the
manifest it came from, and — importantly — `licence_availability`.

### Guarantees

- **Offline and deterministic.** Same tree, same output, every run.
- **Never panics.** A malformed manifest yields a warning and whatever could be
  read, not a crash.
- **Versions are verbatim.** `>=2.0` stays `>=2.0`; an exact pin `==2.31.0`
  becomes the version `2.31.0`. Nothing is normalized into a shape it did not
  have.
- **A range is not a version.** Records are marked `resolved` when they came
  from a lockfile and `direct` when a manifest declares them. A CVSS or policy
  decision made from a range is a decision made from nothing.

## Licence policy

```yaml
# .scanward-licences.yml at the scan root
allow: ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
deny: ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]
unlicensed: warn        # warn | ignore | error
scope: direct           # direct | all
```

```sh
scanward scan . --only licenses                    # uses .scanward-licences.yml
scanward scan . --only licenses --license-policy ci/policy.yml
scanward scan . --only licenses --json             # machine-readable
scanward scan . --only licenses --error            # exit 1 on anything needing a decision
```

### Verdict meanings

| Verdict | Meaning | Fails `--error` |
| --- | --- | --- |
| `allowed` | declared, on the allow list | no |
| `unlisted` | declared, known, not on the allow list | yes |
| `denied` | explicitly denied | yes |
| `unknown` | declared, but we cannot map it to a known licence | yes |
| `unlicensed` | the format records licences and this entry had none | yes |
| `unavailable` | the format carries no licence metadata at all | **no** |

Three of those deserve a note, because they are where an honest tool differs
from a convenient one:

- **Absent is not free.** A package with no licence declaration is reported, not
  waved through. "Nobody claimed a licence" is a legal question, not an
  engineering one, and the answer is not "public domain".
- **Unrecognised is not allowed.** A custom licence, a typo, or an expression
  we do not model comes back `unknown`. It might be perfectly fine; we do not
  know, and a policy gate that assumes fine is a policy gate that never fires.
- **Unknowable is not the same as absent.** `Cargo.lock`, `go.mod`,
  `Gemfile.lock` and `requirements.txt` have no licence field. Those entries are
  `unavailable` and never fail a gate, because failing every Rust project over
  metadata the scanner never had access to is noise, not signal.

`OR` expressions (`MIT OR Apache-2.0`) are split and judged side by side: one
acceptable licence is enough, since the consumer may choose it.

### Practical notes

- For Cargo and Go, licence data is mostly unavailable offline. Use
  `scope: direct` and `unlicensed: ignore`, and treat
  [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny) as the
  authoritative source for published crate licences — it reads the registry
  index, which scanward deliberately does not.
- npm v2/v3 lockfiles and `composer.lock`/`poetry.lock` do record licences, so
  `scope: all` is useful there.
- Unknown keys in the policy are ignored, so a policy written for a newer version
  still works. An **unparseable** policy fails closed: nothing is allowed, and
  unlicensed packages are still reported.

## Typosquatting

```sh
scanward scan . --only typosquat
scanward scan . --only typosquat --json
scanward scan . --only typosquat --error
```

Names are compared against a curated list of widely used packages per ecosystem,
normalized (case, separators) and scored by:

| Signal | Example | Why |
| --- | --- | --- |
| suffix on a real name | `requests-secure` | deliberate impersonation |
| homoglyph substitution | `serd3` for `serde` | a typo does not turn `e` into `3` |
| separator-only variant | `crossenv` for `cross-env` | registries differ, humans do not |
| Damerau-Levenshtein ≤ 1 (≤ 2 for longer names) | `lodahs`, `reqeusts` | transpositions are one keystroke, not two edits |

Ranking prefers the most deliberate signal, then the more popular package.
Generic wrapper suffixes (`-js`, `-cli`, `-utils`) are matched only in their
dashed form: `momentjs` and `expressjs` are real packages, and flagging every
honest wrapper would bury the signal. A misspelling of them still trips
(`expressj`).

**Every result is a suspect.** Without registry access we cannot know whether a
name is taken, whether it was registered maliciously, or whether it is your own
internal package. So the output names the package it resembles, the signal that
fired, and stops at `warning`. Treat it as a review queue, not a verdict.

## API security

OpenAPI and Swagger documents are scanned as source (YAML and JSON): plaintext
server URLs, credentials embedded in a URL, API keys in query strings, HTTP
Basic auth, deprecated OAuth2 password/implicit flows, remote `$ref` over http,
external `$ref` dependencies, published debug surfaces, and Swagger 2.0. See
[`rule-authoring.md`](rule-authoring.md) for how to add to the pack.

## Deliberate limitations

- **No vulnerability matching.** Versions and ranges are inventoried; CVE
  matching is `--only sca` (osv-scanner). Inventing a CVSS score offline is not
  possible and is not attempted.
- **No container image inspection.** Dockerfile rules are static. OS package
  CVEs inside an image need a scanner with a vulnerability database.
- **No registry reputation.** We do not know download counts, maintainer
  history, or whether a name is claimed. Typosquat output is a review queue.
- **No licence text analysis.** A `LICENSE` file is not parsed and matched
  against a package. Only declared metadata is used.
- **Maven/MSBuild not parsed.** Declared as gaps rather than approximated.
