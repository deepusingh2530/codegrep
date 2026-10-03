//! Typosquat / dependency-confusion heuristics over the inventory.
//!
//! What this can and cannot do — worth being blunt about, because "typosquat
//! detection" is usually sold as more than it is:
//!
//! - **It can** notice that a package name is one or two characters away from a
//!   name thousands of developers depend on. That is worth a human look.
//! - **It cannot** tell you the package is malicious. A similar name may be a
//!   legitimate fork, an internal package, or an unpublished local module. We
//!   have no registry access by design, so we never claim a name is "taken".
//!
//! So every result is a *suspect*, reported with the signal that fired, and the
//! severity stays at `warning`. Anything stronger would be a lie.

use std::collections::BTreeMap;

use cg_deps::{Dependency, Ecosystem};

/// A suspected impersonation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Suspect {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    /// The popular name it appears to imitate.
    pub impersonates: String,
    /// Why we flagged it, e.g. `edit-distance 1`.
    pub signal: String,
    /// Lower is more suspicious.
    pub score: u8,
}

impl Suspect {
    pub fn describe(&self) -> String {
        format!(
            "{} {} looks like {} ({})",
            self.package,
            if self.version.is_empty() {
                "-"
            } else {
                &self.version
            },
            self.impersonates,
            self.signal
        )
    }
}

/// Popular package names per ecosystem, most-downloaded first (order is the
/// popularity signal: impersonating `react` matters more than the 400th name).
/// Facts about which packages are popular, not creative content.
fn popular(eco: Ecosystem) -> &'static [&'static str] {
    match eco {
        Ecosystem::Npm => &[
            "react", "react-dom", "lodash", "axios", "express", "chalk", "commander",
            "debug", "moment", "request", "async", "lodash.merge", "vue", "webpack",
            "babel-core", "eslint", "prettier", "typescript", "jest", "mocha", "chai",
            "sinon", "dotenv", "uuid", "glob", "rimraf", "mkdirp", "minimist", "yargs",
            "left-pad", "cross-env", "colors", "inquirer", "body-parser", "cors",
            "mongoose", "socket.io", "next", "nuxt", "svelte", "redux", "rxjs",
            "graphql", "apollo-client", "tailwindcss", "postcss", "vite", "rollup",
            "esbuild", "typescript-eslint", "core-js", "regenerator-runtime", "jquery",
            "bootstrap", "material-ui", "styled-components", "immer", "zod", "yup",
            "dayjs", "luxon", "ramda", "underscore", "bluebird", "qs", "form-data",
        ],
        Ecosystem::PyPi => &[
            "requests", "urllib3", "numpy", "pandas", "flask", "django", "scipy",
            "matplotlib", "pytest", "setuptools", "pip", "wheel", "six", "python-dateutil",
            "pyyaml", "certifi", "idna", "charset-normalizer", "urllib", "click",
            "jinja2", "markupsafe", "werkzeug", "itsdangerous", "sqlalchemy", "psycopg2",
            "boto3", "botocore", "s3transfer", "pydantic", "attrs", "colorama",
            "tqdm", "rich", "typer", "httpx", "aiohttp", "fastapi", "uvicorn", "gunicorn",
            "celery", "redis", "pymongo", "cryptography", "pillow", "scikit-learn",
            "tensorflow", "torch", "transformers", "openai", "anthropic", "black",
            "flake8", "mypy", "isort", "poetry", "virtualenv", "typing-extensions",
            "protobuf", "grpcio", "kubernetes", "docker", "boto", "faker", "freezegun",
        ],
        Ecosystem::Cargo => &[
            "serde", "serde_json", "tokio", "rand", "regex", "log", "libc", "clap",
            "syn", "quote", "proc-macro2", "lazy_static", "chrono", "itertools",
            "anyhow", "thiserror", "reqwest", "hyper", "bytes", "futures", "cfg-if",
            "once_cell", "bitflags", "num-traits", "smallvec", "indexmap", "hashbrown",
            "tracing", "tracing-subscriber", "axum", "tower", "http", "url", "uuid",
            "toml", "serde_yaml", "rayon", "crossbeam", "parking_lot", "dashmap",
            "nom", "winnow", "regex-syntax", "memchr", "aho-corasick", "unicode-ident",
            "proc-macro2", "pin-project", "socket2", "mio", "signal-hook", "parking_lot_core",
        ],
        Ecosystem::Go => &[
            "github.com/gin-gonic/gin", "github.com/stretchr/testify", "golang.org/x/crypto",
            "golang.org/x/net", "golang.org/x/sys", "golang.org/x/text", "google.golang.org/grpc",
            "google.golang.org/protobuf", "github.com/spf13/cobra", "github.com/spf13/viper",
            "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/pkg/errors",
            "github.com/google/uuid", "github.com/gorilla/mux", "github.com/gorilla/websocket",
            "gorm.io/gorm", "github.com/lib/pq", "github.com/go-sql-driver/mysql",
            "github.com/redis/go-redis", "go.mongodb.org/mongo-driver", "github.com/prometheus/client_golang",
        ],
        Ecosystem::Composer => &[
            "phpunit/phpunit", "symfony/console", "symfony/http-foundation", "monolog/monolog",
            "guzzlehttp/guzzle", "laravel/framework", "illuminate/support", "psr/log",
            "nikic/php-parser", "phpstan/phpstan", "squizlabs/php_codesniffer", "doctrine/orm",
            "twig/twig", "league/flysystem", "ramsey/uuid", "nesbot/carbon",
        ],
        Ecosystem::Ruby => &[
            "rails", "rake", "bundler", "rspec", "rspec-core", "activesupport", "activerecord",
            "actionpack", "minitest", "nokogiri", "faraday", "json", "puma", "devise",
            "sidekiq", "pg", "mysql2", "redis", "dotenv", "pry", "rubocop", "simplecov",
        ],
    }
}

/// Characters people swap when hand-typing a name.
/// Substitutions that collapse to one canonical form. One-directional on
/// purpose: digits and digraphs fold to letters, never the reverse. A two-way
/// table made `serd3` fold to `s3rde`, because the `e` it produced was folded
/// straight back.
const HOMOGLYPHS: &[(&str, char)] = &[
    ("0", 'o'), ("1", 'l'), ("1", 'i'), ("3", 'e'), ("4", 'a'), ("5", 's'),
    ("7", 't'), ("8", 'b'), ("rn", 'm'), ("cl", 'd'),
];

/// Normalise a name for comparison: lowercase, and fold the separators that
/// registries treat as distinct but humans do not (`cross-env` ≈ `crossenv`).
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Damerau-Levenshtein distance (optimal string alignment), bounded: returns
/// `None` once every cell in a row exceeds the limit.
///
/// The transposition case is why this is not plain Levenshtein. `lodahs` vs
/// `lodash` is one keystroke for a human — two swaps on a keyboard — but plain
/// Levenshtein calls it 2, which pushes every transposition out of the window.
/// Typos are overwhelmingly transpositions, insertions and deletions, so
/// counting a swap as one edit is what makes this check useful.
fn distance_within(a: &str, b: &str, limit: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > limit {
        return None;
    }
    let n = b.len();
    let mut prev2: Vec<usize> = vec![0; n + 1];
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut cur = vec![0usize; n + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            // prev = row i-1, cur = row i.
            let mut d = (prev[j - 1] + cost).min(prev[j] + 1).min(cur[j - 1] + 1);
            // transposition: a[i-2]==b[j-1] && a[i-1]==b[j-2]
            if i > 1 && j > 1 && a[i - 2] == b[j - 1] && a[i - 1] == b[j - 2] {
                d = d.min(prev2[j - 2] + 1);
            }
            cur[j] = d;
            row_min = row_min.min(d);
        }
        if row_min > limit {
            return None;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    let d = prev[n];
    (d <= limit).then_some(d)
}

/// Suspicion scores: lower is worse. Deliberate impersonation beats a near-miss.
const SUFFIX_SCORE: u8 = 1;
const SUBSTITUTION_SCORE: u8 = 2;
const SEPARATOR_SCORE: u8 = 3;
const EDIT_BASE_SCORE: u8 = 4;

/// A common impersonation suffix/prefix bolted onto a real name.
const AFFIXES: &[&str] = &[
    "-copy", "-fork", "-fake", "-malware", "-backdoor", "-free", "-py", "-rs",
    "-go", "-node", "-helper", "-patched", "-mod", "-updated", "-new", "-old",
    "-secure", "-pro", "-js", "-ts", "-cli", "-util", "-utils", "-2", "-3",
];

/// Suffixes also matched without the leading dash. Deliberately a short list:
/// `-js`/`-cli`/`-utils` are how honest wrapper packages are named
/// (`expressjs`, `momentjs`), so only clearly malicious ones get the loose form.
const AFFIXES_BARE: &[&str] = &[
    "copy", "fork", "fake", "malware", "backdoor", "secure", "patched", "pro",
];

/// Compare one name against the popular list. Returns the closest match and why.
fn nearest(name: &str, candidates: &[&str]) -> Option<(String, String, u8)> {
    let n_norm = normalize(name);
    if n_norm.is_empty() {
        return None;
    }
    let mut best: Option<(String, String, u8)> = None;
    let mut best_key = (u8::MAX, usize::MAX);
    for (rank, cand) in candidates.iter().enumerate() {
        let c_norm = normalize(cand);
        if c_norm == n_norm {
            // Separator-only difference, or the name itself.
            if cand.eq_ignore_ascii_case(name) {
                return None;
            }
            let score = SEPARATOR_SCORE;
            let key = (score, rank);
            if key < best_key {
                best_key = key;
                best = Some((cand.to_string(), "separator-only variant".to_string(), score));
            }
            continue;
        }
        // Length-aware edit distance. Short names are held to distance 1:
        // `reqeusts` yes, `requests-utils` no.
        let limit = if c_norm.chars().count() >= 8 { 2 } else { 1 };
        if let Some(d) = distance_within(&n_norm, &c_norm, limit) {
            // A near-miss is the weakest signal: plenty of packages differ by a
            // character without any intent to impersonate.
            let score = EDIT_BASE_SCORE + d as u8;
            let key = (score, rank);
            if key < best_key {
                best_key = key;
                best = Some((cand.to_string(), format!("edit-distance {d}"), score));
            }
        }
        // Homoglyph substitution: `requsts` vs `requests` is distance 1, but
        // `pyt hon` style swaps on longer names are worth naming explicitly.
        let folded = fold_homoglyphs(&n_norm);
        if folded == c_norm && c_norm.len() >= 4 {
            // Substituting digits for letters (`serd3`) is not something a
            // typo produces, so it outranks a plain near-miss.
            let score = SUBSTITUTION_SCORE;
            let key = (score, rank);
            if key < best_key {
                best_key = key;
                best = Some((cand.to_string(), "character substitution".to_string(), score));
            }
        }
        // Suffixed real name: `requests-secure`, `lodash-copy`.
        let affixes = AFFIXES
            .iter()
            .chain(AFFIXES_BARE.iter());
        for affix in affixes {
            if let Some(stem) = n_norm.strip_suffix(affix) {
                if stem == c_norm && c_norm.len() >= 4 {
                    let score = SUFFIX_SCORE;
                    let key = (score, rank);
                    if key < best_key {
                        best_key = key;
                        best = Some((
                            cand.to_string(),
                            format!("real name plus '{affix}'"),
                            score,
                        ));
                    }
                }
            }
            if let Some(stem) = c_norm.strip_suffix(affix) {
                if stem == n_norm && c_norm.len() >= 4 {
                    let score = SUFFIX_SCORE;
                    let key = (score, rank);
                    if key < best_key {
                        best_key = key;
                        best = Some((
                            cand.to_string(),
                            format!("popular name plus '{affix}'"),
                            score,
                        ));
                    }
                }
            }
        }
    }
    best
}

/// Replace characters that are visually near-identical.
fn fold_homoglyphs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for (from, to) in HOMOGLYPHS {
            if let Some(tail) = rest.strip_prefix(*from) {
                out.push(*to);
                rest = tail;
                continue 'outer;
            }
        }
        let mut it = rest.chars();
        if let Some(c) = it.next() {
            out.push(c);
        }
        rest = it.as_str();
    }
    out
}

/// Inspect an inventory and return suspects, worst first.
pub fn check(deps: &[Dependency]) -> Vec<Suspect> {
    let mut out: Vec<Suspect> = vec![];
    for dep in deps {
        let list = popular(dep.ecosystem);
        if list.is_empty() {
            continue;
        }
        let Some((impersonates, signal, score)) = nearest(&dep.name, list) else {
            continue;
        };
        out.push(Suspect {
            package: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: dep.ecosystem,
            impersonates,
            signal,
            score,
        });
    }
    out.sort_by(|a, b| {
        a.score
            .cmp(&b.score)
            .then_with(|| a.ecosystem.cmp(&b.ecosystem))
            .then_with(|| a.package.cmp(&b.package))
    });
    out.dedup_by(|a, b| a.ecosystem == b.ecosystem && a.package == b.package);
    out
}

/// Popular-name table, for `--only typosquat --explain`.
pub fn popular_names(eco: Ecosystem) -> &'static [&'static str] {
    popular(eco)
}

/// Group suspects by ecosystem for reporting.
pub fn by_ecosystem(suspects: &[Suspect]) -> BTreeMap<&'static str, Vec<&Suspect>> {
    let mut m: BTreeMap<&'static str, Vec<&Suspect>> = BTreeMap::new();
    for s in suspects {
        m.entry(s.ecosystem.as_str()).or_default().push(s);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, eco: Ecosystem) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.2.3".into(),
            ecosystem: eco,
            license: Some("MIT".into()),
            licence_availability: cg_deps::LicenceAvailability::Declared,
            manifest: "package-lock.json".into(),
            direct: true,
            resolved: true,
        }
    }

    #[test]
    fn the_real_name_is_never_a_suspect() {
        assert!(nearest("requests", popular(Ecosystem::PyPi)).is_none());
        assert!(nearest("lodash", popular(Ecosystem::Npm)).is_none());
        assert!(nearest("serde", popular(Ecosystem::Cargo)).is_none());
    }

    /// Single-edit typos, the commonest shape by far. Two-edit names shorter
    /// than eight characters are deliberately out of scope: at that length the
    /// false-positive rate climbs faster than the catch rate.
    #[test]
    fn classic_typos_are_caught() {
        for (eco, bad, good) in [
            (Ecosystem::PyPi, "reqeusts", "requests"),
            (Ecosystem::PyPi, "requsts", "requests"),
            (Ecosystem::Npm, "lodahs", "lodash"),
            (Ecosystem::Npm, "reacct", "react"),
            (Ecosystem::Cargo, "tokioo", "tokio"),
            (Ecosystem::PyPi, "nubpy", "numpy"),
            (Ecosystem::Npm, "axois", "axios"),
        ] {
            let hit = nearest(bad, popular(eco)).unwrap_or_else(|| panic!("{bad} not flagged"));
            assert_eq!(hit.0, good, "{bad} should point at {good}");
        }
    }

    #[test]
    fn homoglyph_and_case_spoofs_are_caught() {
        // digit-for-letter swap
        assert_eq!(nearest("serd3", popular(Ecosystem::Cargo)).unwrap().0, "serde");
        assert_eq!(nearest("serd3_json", popular(Ecosystem::Cargo)).unwrap().0, "serde_json");
        // `reqwestt` is one edit from `reqwest`, so flagging it is correct —
        // recorded here because the first version of this test asserted the
        // opposite and was wrong.
        assert_eq!(nearest("reqwestt", popular(Ecosystem::Cargo)).unwrap().0, "reqwest");
        // Normalisation strips separators before comparison.
        assert_eq!(nearest("pyt hon", popular(Ecosystem::PyPi)), None);
    }

    #[test]
    fn homoglyph_folding_handles_digit_and_digraph_swaps() {
        assert_eq!(fold_homoglyphs("serd3"), "serde");
        assert_eq!(fold_homoglyphs("1odash"), "lodash");
        assert_eq!(fold_homoglyphs("modern"), "modem", "rn reads as m");
        assert_eq!(fold_homoglyphs("l0dash"), "lodash");
    }

    #[test]
    fn suffixed_variants_are_caught() {
        assert_eq!(nearest("requests-secure", popular(Ecosystem::PyPi)).unwrap().0, "requests");
        assert_eq!(nearest("lodash-copy", popular(Ecosystem::Npm)).unwrap().0, "lodash");
        assert_eq!(nearest("requests-backdoor", popular(Ecosystem::PyPi)).unwrap().0, "requests");
    }

    #[test]
    fn separator_only_variants_are_caught_but_real_names_are_not() {
        let hit = nearest("cross-env", popular(Ecosystem::Npm));
        // `cross-env` is itself in the list, so it is not a suspect.
        assert!(hit.is_none());
        let hit = nearest("crossenv", popular(Ecosystem::Npm)).unwrap();
        assert_eq!(hit.0, "cross-env");
        assert_eq!(hit.1, "separator-only variant");
    }

    #[test]
    fn unrelated_names_are_left_alone() {
        for name in [
            "totally-unique-internal-service",
            "acme-corp-design-system",
            "my-company-utils-2024",
        ] {
            assert!(nearest(name, popular(Ecosystem::Npm)).is_none(), "{name} flagged");
            assert!(nearest(name, popular(Ecosystem::PyPi)).is_none(), "{name} flagged");
        }
    }

    #[test]
    fn go_module_paths_are_handled() {
        let hit = nearest("github.com/gin-gonic/ginx", popular(Ecosystem::Go)).unwrap();
        assert_eq!(hit.0, "github.com/gin-gonic/gin");
    }

    #[test]
    fn short_names_are_held_to_distance_one() {
        assert_eq!(nearest("chalkk", popular(Ecosystem::Npm)).unwrap().0, "chalk");
        assert_eq!(nearest("chalx", popular(Ecosystem::Npm)).unwrap().0, "chalk");
    }

    #[test]
    fn generic_wrapper_suffixes_are_not_treated_as_typosquats() {
        // `momentjs` and `expressjs` are real (deprecated or wrapper) packages.
        // Flagging every `-js`/`-cli`-style name would bury the real signal, so
        // the bare form of those suffixes is deliberately not matched. A
        // misspelling of them still is: `expressj` is one edit away.
        assert!(nearest("momentjs", popular(Ecosystem::Npm)).is_none());
        assert!(nearest("expressjs", popular(Ecosystem::Npm)).is_none());
        assert!(nearest("lodashx-cli", popular(Ecosystem::Npm)).is_none());
        assert_eq!(nearest("expressj", popular(Ecosystem::Npm)).unwrap().0, "express");
    }

    #[test]
    fn check_is_deterministic_and_sorted() {
        let deps = vec![
            dep("requests-secure", Ecosystem::PyPi),
            dep("reqeusts", Ecosystem::PyPi),
            dep("lodash", Ecosystem::Npm),
        ];
        let a = check(&deps);
        let b = check(&deps);
        assert_eq!(a, b, "same input, same output");
        assert_eq!(a.len(), 2, "the real name is not reported");
        assert!(a[0].score <= a[1].score, "worst first");
        assert!(a.iter().all(|s| s.ecosystem == Ecosystem::PyPi));
    }

    #[test]
    fn the_most_deliberate_signal_wins() {
        // `serd3` is both one edit from `serde` and an exact homoglyph match.
        // Substituting a digit for a letter is not a typo, so that signal must
        // outrank the generic near-miss.
        let s = nearest("serd3", popular(Ecosystem::Cargo)).unwrap();
        assert_eq!(s.0, "serde");
        assert_eq!(s.1, "character substitution");
        assert_eq!(s.2, SUBSTITUTION_SCORE);
        // A real name is never a suspect.
        assert!(nearest("serde", popular(Ecosystem::Cargo)).is_none());
    }

    #[test]
    fn scores_are_ordered_by_how_deliberate_the_signal_is() {
        // Bound to locals: clippy rightly rejects asserting on constants, and a
        // scoring table that silently reorders is a scoring table nobody checks.
        let (suffix, substitution, separator, edit_base) =
            (SUFFIX_SCORE, SUBSTITUTION_SCORE, SEPARATOR_SCORE, EDIT_BASE_SCORE);
        assert!(suffix < substitution, "suffixing a real name is deliberate");
        assert!(substitution < separator);
        assert!(separator < edit_base, "a near-miss is the weakest signal");
        // A closer near-miss outranks a further one.
        let one = nearest("reqeusts", popular(Ecosystem::PyPi)).unwrap();
        let two = nearest("requetss", popular(Ecosystem::PyPi)).unwrap();
        assert_eq!(one.2, EDIT_BASE_SCORE + 1);
        assert!(two.2 >= one.2, "further match ranks no better");
    }
}
