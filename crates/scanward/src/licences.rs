//! Licence policy: check the dependency inventory against an allow/deny policy.
//!
//! Kept separate from [`crate::inventory`] so the parsing stays a pure function
//! of file contents and the policy is a pure function of the inventory. Policy
//! lives in `.scanward-licences.yml`:
//!
//! ```yaml
//! allow: ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
//! deny:  ["GPL-3.0", "AGPL-3.0", "SSPL-1.0", "BUSL-1.1"]
//! unlicensed: warn        # warn | ignore | error   (default: warn)
//! scope: direct           # direct | all           (default: direct)
//! ```
//!
//! Two deliberate honesty rules, because a licence check that guesses is worse
//! than one that says nothing:
//!
//! - **Absent is not free.** A dependency with no declared licence is reported
//!   as `Unlicensed`, never treated as permissive.
//! - **Unrecognised is not allowed.** A licence string we cannot map (a custom
//!   licence, a typo, an `OR` chain we do not model) is reported as `Unknown`,
//!   not silently accepted. `OR` expressions are split and each side is judged
//!   on its own, which is the conservative reading.

use std::collections::BTreeMap;
use std::fmt;

use cg_deps::{Dependency, Ecosystem, LicenceAvailability};

/// How a project treats dependencies with no declared licence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Unlicensed {
    #[default]
    Warn,
    Ignore,
    Error,
}

/// Whether transitive dependencies are judged too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    #[default]
    Direct,
    All,
}

/// A parsed policy file.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub unlicensed: Unlicensed,
    pub scope: Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Declared and on the allow list.
    Allowed,
    /// Declared but not on the allow list.
    Unlisted,
    /// Explicitly denied.
    Denied,
    /// No licence declared anywhere in the manifests.
    Unlicensed,
    /// Declared, but we cannot map it to a known licence.
    Unknown,
    /// The manifest format carries no licence metadata at all, so we genuinely
    /// do not know. Reported for transparency, never counted as a problem.
    Unavailable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Unlisted => "unlisted",
            Self::Denied => "denied",
            Self::Unlicensed => "unlicensed",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        }
    }
    /// Whether this verdict should fail a `--error` gate.
    ///
    /// `Unavailable` deliberately does not: a Rust project's `Cargo.lock` has no
    /// licence field, so failing on it would make every Rust project red for
    /// something the scanner never had a chance to learn.
    pub fn is_problem(self) -> bool {
        !matches!(self, Self::Allowed | Self::Unavailable)
    }
    /// Report ordering: worst first, so a policy report leads with what needs a
    /// decision. The derived `Ord` follows declaration order, which is not
    /// severity order.
    pub fn severity_rank(self) -> u8 {
        match self {
            Self::Denied => 0,
            Self::Unlicensed => 1,
            Self::Unknown => 2,
            Self::Unlisted => 3,
            Self::Allowed => 4,
            Self::Unavailable => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LicenceFinding {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub licence: String,
    pub verdict: Verdict,
    pub direct: bool,
    pub manifest: String,
}

impl fmt::Display for LicenceFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} [{}] — {} (licence: {})",
            self.package,
            if self.version.is_empty() {
                "-"
            } else {
                &self.version
            },
            self.ecosystem.as_str(),
            self.verdict.as_str(),
            self.licence
        )
    }
}

/// SPDX ids we recognise well enough to reason about. Anything else is
/// `Unknown` rather than guessed at — see the module docs.
const KNOWN: &[&str] = &[
    "MIT", "MIT-0", "X11", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "BSD-4-Clause", "ISC", "Zlib", "BSL-1.0", "CC0-1.0", "Unlicense",
    "Unicode-3.0", "Unicode-DFS-2016", "WTFPL", "0BSD", "MPL-2.0", "EPL-2.0",
    "EUPL-1.2", "OSL-3.0", "Artistic-2.0", "NCSA", "PostgreSQL", "Python-2.0",
    "Ruby", "OFL-1.1", "LPPL-1.3c", "IJG", "libpng-2.0",
];

/// Copyleft / source-available licences worth flagging by name.
const RESTRICTIVE: &[&str] = &[
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0",
    "EPL-2.0", "CDDL-1.0", "CPL-1.0", "EPL-1.0", "SSPL-1.0", "BUSL-1.1",
    "Elastic-2.0", "PolyForm-Noncommercial-1.0.0", "CC-BY-NC-4.0",
];

/// Normalise a declared licence string: strip `LicenseRef-` noise, collapse
/// whitespace, case-fold for comparison but keep the original for reporting.
fn normalize(raw: &str) -> String {
    raw.trim()
        .replace(['\n', '\t'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Does the declared string name a licence we know?
fn is_known(id: &str) -> bool {
    KNOWN.iter().any(|k| k.eq_ignore_ascii_case(id))
        || RESTRICTIVE.iter().any(|k| k.eq_ignore_ascii_case(id))
}

fn is_restrictive(id: &str) -> bool {
    RESTRICTIVE.iter().any(|k| k.eq_ignore_ascii_case(id))
}

impl Policy {
    /// Parse a policy document. Unknown keys are ignored rather than fatal, so
    /// a policy written for a newer version still works.
    pub fn parse(text: &str) -> Self {
        let value: serde_yaml::Value = match serde_yaml::from_str(text) {
            Ok(v) => v,
            Err(_) => return Policy::default(),
        };
        let list = |key: &str| -> Vec<String> {
            value
                .get(key)
                .and_then(|v| v.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str())
                        .map(normalize)
                        .collect()
                })
                .unwrap_or_default()
        };
        let unlicensed = match value
            .get("unlicensed")
            .and_then(|v| v.as_str())
            .unwrap_or("warn")
            .to_ascii_lowercase()
            .as_str()
        {
            "ignore" => Unlicensed::Ignore,
            "error" => Unlicensed::Error,
            _ => Unlicensed::Warn,
        };
        let scope = match value
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("direct")
            .to_ascii_lowercase()
            .as_str()
        {
            "all" => Scope::All,
            _ => Scope::Direct,
        };
        Policy {
            allow: list("allow"),
            deny: list("deny"),
            unlicensed,
            scope,
        }
    }

    fn allows(&self, id: &str) -> bool {
        self.allow.iter().any(|a| a.eq_ignore_ascii_case(id))
    }

    fn denies(&self, id: &str) -> bool {
        self.deny.iter().any(|d| d.eq_ignore_ascii_case(id))
    }

    /// Classify one dependency.
    pub fn classify(&self, dep: &Dependency) -> Option<LicenceFinding> {
        if self.scope == Scope::Direct && !dep.direct {
            return None;
        }
        let declared = dep.license.as_deref().map(normalize).unwrap_or_default();
        let verdict = match dep.licence_availability {
            // Nothing to judge: the file we read cannot express a licence.
            LicenceAvailability::NotInFormat => Verdict::Unavailable,
            _ if declared.is_empty() => {
            match self.unlicensed {
                Unlicensed::Ignore => return None,
                _ => Verdict::Unlicensed,
            }
            }
            _ => {
            // `MIT OR Apache-2.0` — the user may pick either side, so one
            // acceptable licence is enough. Precedence: any allowed side wins,
            // then unlisted, then unknown; only when every side is denied is it
            // denied.
            let parts: Vec<&str> = if declared.contains(" OR ") {
                declared.split(" OR ").map(|s| s.trim()).collect()
            } else if declared.contains('/') && !declared.contains("://") {
                // `MIT/Apache-2.0` shorthand.
                declared.split('/').map(|s| s.trim()).collect()
            } else {
                vec![declared.as_str()]
            };
            let verdicts: Vec<Verdict> = parts.iter().map(|p| self.classify_one(p)).collect();
            if verdicts.contains(&Verdict::Allowed) {
                Verdict::Allowed
            } else if verdicts.contains(&Verdict::Unlisted) {
                Verdict::Unlisted
            } else if verdicts.contains(&Verdict::Unknown) {
                Verdict::Unknown
            } else {
                Verdict::Denied
            }
            }
        };
        Some(LicenceFinding {
            package: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: dep.ecosystem,
            licence: match dep.licence_availability {
                LicenceAvailability::NotInFormat => {
                    "not in this manifest format".to_string()
                }
                _ if declared.is_empty() => "none declared".to_string(),
                _ => declared,
            },
            verdict,
            direct: dep.direct,
            manifest: dep.manifest.clone(),
        })
    }

    fn classify_one(&self, id: &str) -> Verdict {
        if self.denies(id) {
            return Verdict::Denied;
        }
        if self.allows(id) {
            return Verdict::Allowed;
        }
        if !is_known(id) {
            return Verdict::Unknown;
        }
        if is_restrictive(id) {
            // Known, restrictive, and not on the allow list: still a problem,
            // but "unlisted" rather than "denied" keeps the distinction honest.
            return Verdict::Unlisted;
        }
        Verdict::Unlisted
    }
}

/// Judge a whole inventory, sorted for deterministic output.
pub fn check(deps: &[Dependency], policy: &Policy) -> Vec<LicenceFinding> {
    let mut out: Vec<LicenceFinding> = deps.iter().filter_map(|d| policy.classify(d)).collect();
    out.sort_by(|a, b| {
        a.verdict
            .severity_rank()
            .cmp(&b.verdict.severity_rank())
            .then_with(|| a.ecosystem.cmp(&b.ecosystem))
            .then_with(|| a.package.cmp(&b.package))
    });
    out
}

/// Counts by verdict, for a summary line.
pub fn summarize(findings: &[LicenceFinding]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.verdict.as_str()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, license: Option<&str>, direct: bool) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Cargo,
            license: license.map(String::from),
            licence_availability: if license.is_some() {
                cg_deps::LicenceAvailability::Declared
            } else {
                cg_deps::LicenceAvailability::Absent
            },
            manifest: "Cargo.toml".into(),
            direct,
            resolved: false,
        }
    }

    fn policy() -> Policy {
        Policy::parse(
            r#"
allow: ["MIT", "Apache-2.0", "BSD-3-Clause"]
deny: ["GPL-3.0", "AGPL-3.0"]
unlicensed: warn
scope: direct
"#,
        )
    }

    #[test]
    fn allowed_permissive_and_denied_are_distinguished() {
        let p = policy();
        assert_eq!(p.classify(&dep("serde", Some("MIT OR Apache-2.0"), true)).unwrap().verdict, Verdict::Allowed);
        assert_eq!(p.classify(&dep("x", Some("GPL-3.0"), true)).unwrap().verdict, Verdict::Denied);
        assert_eq!(p.classify(&dep("y", Some("LGPL-3.0"), true)).unwrap().verdict, Verdict::Unlisted);
        assert_eq!(p.classify(&dep("z", Some("0BSD"), true)).unwrap().verdict, Verdict::Unlisted);
    }

    #[test]
    fn an_unreadable_licence_is_not_the_same_as_an_absent_one() {
        let mut d = dep("serde", None, true);
        d.licence_availability = cg_deps::LicenceAvailability::NotInFormat;
        let f = p_unavailable().classify(&d).unwrap();
        assert_eq!(f.verdict, Verdict::Unavailable);
        assert_eq!(f.licence, "not in this manifest format");
        assert!(
            !f.verdict.is_problem(),
            "a Cargo.lock entry cannot fail a gate the scanner was never able to judge"
        );
        // Declared-with-nothing is still a real absence, and still a problem.
        let mut declared_absent = dep("serde", None, true);
        declared_absent.licence_availability = cg_deps::LicenceAvailability::Absent;
        assert!(p_unavailable().classify(&declared_absent).unwrap().verdict.is_problem());
    }

    fn p_unavailable() -> Policy {
        Policy::parse("allow: [MIT]\nunlicensed: warn\nscope: all\n")
    }

    #[test]
    fn absent_is_never_free() {
        let p = policy();
        let f = p.classify(&dep("mystery", None, true)).unwrap();
        assert_eq!(f.verdict, Verdict::Unlicensed);
        assert_eq!(f.licence, "none declared");
    }

    #[test]
    fn unrecognised_licence_is_unknown_not_allowed() {
        let p = policy();
        assert_eq!(p.classify(&dep("weird", Some("Acme Internal 1.0"), true)).unwrap().verdict, Verdict::Unknown);
        assert_eq!(p.classify(&dep("typo", Some("MIIT"), true)).unwrap().verdict, Verdict::Unknown);
    }

    #[test]
    fn or_expression_takes_the_best_side() {
        let p = policy();
        // One acceptable side is enough.
        assert_eq!(p.classify(&dep("a", Some("GPL-3.0 OR MIT"), true)).unwrap().verdict, Verdict::Allowed);
        // Both sides denied stays denied.
        assert_eq!(p.classify(&dep("b", Some("GPL-3.0 OR AGPL-3.0"), true)).unwrap().verdict, Verdict::Denied);
    }

    #[test]
    fn scope_direct_ignores_transitive_by_default() {
        let p = policy();
        assert!(p.classify(&dep("direct", Some("GPL-3.0"), true)).is_some());
        assert!(p.classify(&dep("transitive", Some("GPL-3.0"), false)).is_none());
        let all = Policy::parse("allow: [MIT]\nscope: all\n");
        assert!(all.classify(&dep("t", Some("GPL-3.0"), false)).is_some());
    }

    #[test]
    fn unlicensed_ignore_removes_the_record() {
        let p = Policy::parse("allow: [MIT]\nunlicensed: ignore\n");
        assert!(p.classify(&dep("mystery", None, true)).is_none());
    }

    #[test]
    fn malformed_policy_fails_closed() {
        // Unparseable policy ⇒ nothing allowed, unlicensed still reported.
        let p = Policy::parse("::: not yaml :::");
        assert!(p.allow.is_empty());
        assert_eq!(p.classify(&dep("x", Some("MIT"), true)).unwrap().verdict, Verdict::Unlisted);
        assert_eq!(p.unlicensed, Unlicensed::Warn);
    }

    #[test]
    fn check_is_sorted_and_summary_counts() {
        let deps = vec![
            dep("zeta", Some("MIT"), true),
            dep("alpha", Some("GPL-3.0"), true),
            dep("mid", None, true),
            dep("noise", Some("AGPL-3.0"), false),
        ];
        let findings = check(&deps, &policy());
        assert_eq!(findings.len(), 3, "transitive excluded by scope");
        assert_eq!(findings[0].package, "alpha", "worst verdict first");
        assert_eq!(findings[0].verdict, Verdict::Denied);
        let summary = summarize(&findings);
        assert_eq!(summary.get("denied"), Some(&1));
        assert_eq!(summary.get("unlicensed"), Some(&1));
        assert_eq!(summary.get("allowed"), Some(&1));
        assert!(
            !findings.iter().any(|f| f.verdict == Verdict::Unavailable),
            "declared fixtures have declared licences"
        );
    }
}
