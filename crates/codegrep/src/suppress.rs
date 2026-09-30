//! False-positive suppression: auditable YAML entries (rule/path/line +
//! required reason, optional expiry) and inline `codegrep-ignore` comments.
//!
//! Suppression files are checked into the repo so every silenced finding has
//! a reviewable reason; expired entries stop applying and warn loudly.

use crate::{glob_match, path_candidates, pattern_hits, Finding};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// One suppression entry. Unknown fields are rejected so typos (`exires:`)
/// fail the scan instead of silently keeping a finding visible (or hidden).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    /// Rule id (exact) or glob (`py-*`) when it contains `*`/`?`.
    pub rule: String,
    /// Optional path glob/substring — same semantics as `--exclude`.
    pub path: Option<String>,
    /// Optional exact 1-based line number.
    pub line: Option<usize>,
    /// Why this finding is acceptable (required; reviewed in PRs).
    pub reason: String,
    /// Optional informational owner (`platform-team`).
    pub owner: Option<String>,
    /// Optional `YYYY-MM-DD`: entry stops applying after this date.
    pub expires: Option<String>,
}

impl Suppression {
    /// Validate format-level requirements (called at load time).
    pub fn check(&self) -> Result<()> {
        if self.rule.trim().is_empty() {
            anyhow::bail!("suppression `rule` must not be empty");
        }
        if self.reason.trim().is_empty() {
            anyhow::bail!("suppression for rule {} has no `reason`", self.rule);
        }
        if let Some(e) = &self.expires {
            parse_date(e)
                .with_context(|| format!("suppression for rule {}: bad `expires`", self.rule))?;
        }
        Ok(())
    }

    /// True when `today` is after `expires` (entry no longer applies).
    pub fn is_expired(&self, today: (i64, u32, u32)) -> bool {
        match self.expires.as_deref().and_then(|e| parse_date(e).ok()) {
            Some(exp) => today > exp,
            None => false,
        }
    }

    /// All specified fields must match (AND).
    pub fn applies(&self, f: &Finding, root: &str) -> bool {
        if self.rule.contains('*') || self.rule.contains('?') {
            if !glob_match(&self.rule, &f.rule_id) {
                return false;
            }
        } else if self.rule != f.rule_id {
            return false;
        }
        if let Some(p) = &self.path {
            let cands = path_candidates(&f.path, root);
            if !pattern_hits(p, &cands) {
                return false;
            }
        }
        if let Some(l) = self.line {
            if l != f.line {
                return false;
            }
        }
        true
    }
}

/// Parse a suppression file (YAML list, or a single entry).
pub fn parse_suppressions(text: &str, src: &str) -> Result<Vec<Suppression>> {
    let list: Vec<Suppression> = match serde_yaml::from_str::<Vec<Suppression>>(text) {
        Ok(l) => l,
        Err(vec_err) => match serde_yaml::from_str::<Suppression>(text) {
            Ok(one) => vec![one],
            // Prefer the list-level error: it names the actual field problem.
            Err(_) => return Err(vec_err).with_context(|| format!("parsing suppressions {src}")),
        },
    };
    for s in &list {
        s.check()
            .with_context(|| format!("{src}: invalid suppression entry"))?;
    }
    Ok(list)
}

/// Load a suppression file from disk.
pub fn load_suppressions(path: &str) -> Result<Vec<Suppression>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading suppressions {path}"))?;
    parse_suppressions(&text, path)
}

/// Today as (year, month, day) in UTC, for `expires` comparisons.
pub fn today_ymd() -> (i64, u32, u32) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil_from_days((secs / 86_400) as i64)
}

/// Howard Hinnant's `civil_from_days` (public domain algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Strict `YYYY-MM-DD` parse → comparable (y, m, d).
pub fn parse_date(s: &str) -> Result<(i64, u32, u32)> {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let t = s.get(r)?;
        if t.len() != 4 && t.len() != 2 {
            return None;
        }
        t.parse().ok()
    };
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        anyhow::bail!("expected YYYY-MM-DD, got {s:?}");
    }
    let y = digits(0..4).context("bad year")?;
    let m = digits(5..7).context("bad month")?;
    let d = digits(8..10).context("bad day")?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        anyhow::bail!("month/day out of range in {s:?}");
    }
    Ok((y as i64, m, d))
}

/// Markers that must precede `codegrep-ignore` on the same line for it to
/// count (so the text inside string literals rarely triggers by accident).
const MARKERS: &[&str] = &["#", "//", "<!--", "/*"];

/// An ignore comment found on a line: `next` means `codegrep-ignore-next-line`
/// (applies to the following line); ids = `codegrep-ignore(a, b)` scope,
/// `None` = all rules.
struct InlineIgnore {
    next: bool,
    ids: Option<Vec<String>>,
}

/// Collect ignore comments on one source line (word-boundary + comment
/// marker required).
fn ignores_on(line: &str) -> Vec<InlineIgnore> {
    const TOKEN: &str = "codegrep-ignore";
    const NEXT: &str = "codegrep-ignore-next-line";
    let mut out = vec![];
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(TOKEN) {
        let idx = from + rel;
        from = idx + TOKEN.len();
        let before = &line[..idx];
        // Word boundary: `xcodegrep-ignore` does not count.
        if before
            .chars()
            .next_back()
            .map(|c| c.is_alphanumeric() || c == '_' || c == '-')
            .unwrap_or(false)
        {
            continue;
        }
        if !MARKERS.iter().any(|m| before.contains(m)) {
            continue; // not in a comment
        }
        let after = &line[from..];
        let next = after.starts_with("-next-line");
        let rest = if next { &after[NEXT.len() - TOKEN.len()..] } else { after };
        let rest = rest.trim_start();
        let ids = if let Some(inner) = rest.strip_prefix('(') {
            match inner.find(')') {
                Some(end) => {
                    let ids: Vec<String> = inner[..end]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    Some(ids)
                }
                None => continue, // unterminated: ignore comment
            }
        } else {
            None // bare: all rules
        };
        out.push(InlineIgnore { next, ids });
    }
    out
}

/// Drop findings suppressed by an inline comment on their own line
/// (`# codegrep-ignore[...]`) or by a `# codegrep-ignore-next-line` comment
/// on the line directly above. Returns (kept, suppressed_count).
pub fn apply_inline(text: &str, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    let lines: Vec<&str> = text.lines().collect();
    let mut suppressed = 0usize;
    let kept = findings
        .into_iter()
        .filter(|f| {
            let hit = |ig: &InlineIgnore| match &ig.ids {
                None => true,
                Some(ids) => ids.iter().any(|id| id == &f.rule_id),
            };
            let same = f.line.checked_sub(1).and_then(|i| lines.get(i));
            let above = f.line.checked_sub(2).and_then(|i| lines.get(i));
            for ig in same.into_iter().flat_map(|l| ignores_on(l)) {
                if !ig.next && hit(&ig) {
                    suppressed += 1;
                    return false;
                }
            }
            for ig in above.into_iter().flat_map(|l| ignores_on(l)) {
                if ig.next && hit(&ig) {
                    suppressed += 1;
                    return false;
                }
            }
            true
        })
        .collect();
    (kept, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity: "ERROR".into(),
            message: "m".into(),
            fix: None,
            path: "testdata/go/vuln.go".into(),
            language: "python".into(),
            line,
            col: 0,
            snippet: "code".into(),
        }
    }

    #[test]
    fn suppression_file_parses_and_requires_reason() {
        let ok = "
- rule: py-hardcoded-secret
  path: \"testdata/**\"
  line: 3
  reason: fixture, not shipped
  owner: security
  expires: 2030-01-01
";
        let list = parse_suppressions(ok, "t").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].rule, "py-hardcoded-secret");

        let no_reason = "- rule: x\n  path: a\n";
        let err = parse_suppressions(no_reason, "t").unwrap_err();
        assert!(
            format!("{err:#}").contains("reason"),
            "error should name the missing reason: {err:#}"
        );

        let typo = "- rule: x\n  reason: ok\n  exires: 2030-01-01\n";
        assert!(parse_suppressions(typo, "t").is_err(), "unknown fields rejected");
    }

    #[test]
    fn applies_ands_all_specified_fields() {
        let s = Suppression {
            rule: "go-command-injection".into(),
            path: Some("testdata/**".into()),
            line: Some(4),
            reason: "r".into(),
            owner: None,
            expires: None,
        };
        let f = finding("go-command-injection", 4);
        assert!(s.applies(&f, "."));
        assert!(!s.applies(&finding("other", 4), "."));
        assert!(!s.applies(&finding("go-command-injection", 5), "."));

        let glob = Suppression { rule: "go-*".into(), ..s.clone() };
        assert!(glob.applies(&f, "."));

        let wrong_path = Suppression {
            path: Some("vendor/**".into()),
            ..s.clone()
        };
        assert!(!wrong_path.applies(&f, "."));
    }

    #[test]
    fn expiry_stops_apply_after_date() {
        assert!(parse_date("2030-12-31").unwrap() > (2030, 12, 31 - 1));
        let s = Suppression {
            rule: "r".into(),
            path: None,
            line: None,
            reason: "x".into(),
            owner: None,
            expires: Some("2020-01-01".into()),
        };
        assert!(s.is_expired((2026, 9, 30)));
        assert!(!s.is_expired((2019, 12, 31)));
        assert!(parse_date("2020-1-01").is_err(), "zero-padded required");
        assert!(parse_date("not-a-date").is_err());
    }

    #[test]
    fn inline_same_line_and_next_line() {
        let text = "os.system(cmd)  # codegrep-ignore\n\
                    foo()\n\
                    bar()  # codegrep-ignore-next-line\n\
                    baz()\n\
                    qux()  # codegrep-ignore(pyrce-exec)\n\
                    zap()\n\
                    y = \"codegrep-ignore\"\n";
        // line 1: bare same-line ignore
        let (kept, n) = apply_inline(text, vec![finding("any-rule", 1)]);
        assert_eq!((kept.len(), n), (0, 1));
        // line 2: line 1's same-line ignore must NOT leak downward
        let (kept, n) = apply_inline(text, vec![finding("any-rule", 2)]);
        assert_eq!((kept.len(), n), (1, 0));
        // line 4: suppressed by next-line marker on line 3
        let (kept, n) = apply_inline(text, vec![finding("any-rule", 4)]);
        assert_eq!((kept.len(), n), (0, 1));
        // line 5: rule-scoped same-line ignore
        let (kept, n) = apply_inline(text, vec![finding("pyrce-exec", 5)]);
        assert_eq!((kept.len(), n), (0, 1));
        let (kept, n) = apply_inline(text, vec![finding("other-rule", 5)]);
        assert_eq!((kept.len(), n), (1, 0));
        // line 6: scoped same-line ignore on line 5 does not propagate
        let (kept, n) = apply_inline(text, vec![finding("other-rule", 6)]);
        assert_eq!((kept.len(), n), (1, 0));
        // line 7: no comment marker -> no suppression
        let (kept, n) = apply_inline(text, vec![finding("any", 7)]);
        assert_eq!((kept.len(), n), (1, 0));
    }

    #[test]
    fn inline_requires_comment_marker_and_boundary() {
        // Inside plain text (no comment marker) must not suppress.
        let text = "x = \"codegrep-ignore\"";
        let (kept, n) = apply_inline(text, vec![finding("r", 1)]);
        assert_eq!((kept.len(), n), (1, 0));
        // Not at a word boundary.
        let text = "# xcodegrep-ignore";
        let (kept, n) = apply_inline(text, vec![finding("r", 1)]);
        assert_eq!((kept.len(), n), (1, 0));
        // C-style comment works too.
        let text = "os.system(c);  // codegrep-ignore";
        let (kept, n) = apply_inline(text, vec![finding("r", 1)]);
        assert_eq!((kept.len(), n), (0, 1));
    }
}
