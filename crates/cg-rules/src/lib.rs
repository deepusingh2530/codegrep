//! scanward rules: YAML loader + validator + literal indexer (Aho-Corasick).
//! Single-doc YAML rule format of our own design; content is MIT-licensed own rules.
//! User-supplied portable-schema rule files are detected and translated on load
//! (see [`portable`]); only files passed in by the user are ever parsed this way.

use anyhow::{anyhow, Context, Result};

pub mod portable;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSpec {
    #[serde(default)]
    pub sources: Vec<TaintPart>,
    #[serde(default)]
    pub sinks: Vec<TaintPart>,
    #[serde(default)]
    pub sanitizers: Vec<TaintPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPart {
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub languages: Vec<String>,
    pub severity: String,
    pub category: Option<String>,
    pub message: String,
    pub fix: Option<String>,
    // pattern operators (subset in v0.1, full set roadmap)
    pub pattern: Option<String>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternChoice>>,
    pub patterns: Option<Vec<PatternChoice>>,
    #[serde(rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    #[serde(rename = "metavariable-regex")]
    pub metavariable_regex: Option<HashMap<String, String>>,
    #[serde(rename = "metavariable-comparison")]
    pub metavariable_comparison: Option<String>,
    pub taint: Option<TaintSpec>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PatternChoice {
    Simple { pattern: String },
}

impl PatternChoice {
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple { pattern } => pattern,
        }
    }
}

impl Rule {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(anyhow!("rule id empty"));
        }
        if self.languages.is_empty() {
            return Err(anyhow!("rule {} has no languages", self.id));
        }
        let has_pattern = self.pattern.is_some()
            || self.pattern_either.is_some()
            || self.patterns.is_some()
            || self.taint.is_some();
        if !has_pattern {
            return Err(anyhow!("rule {} has no pattern/taint", self.id));
        }
        Ok(())
    }

    /// All positive pattern strings (for indexing + matching).
    pub fn positive_patterns(&self) -> Vec<String> {
        if let Some(p) = &self.pattern {
            return vec![p.clone()];
        }
        if let Some(e) = &self.pattern_either {
            return e.iter().map(|c| c.pattern().to_string()).collect();
        }
        if let Some(ps) = &self.patterns {
            return ps.iter().map(|c| c.pattern().to_string()).collect();
        }
        if let Some(t) = &self.taint {
            return t.sinks.iter().flat_map(|s| s.patterns.clone()).collect();
        }
        vec![]
    }

    pub fn applies_to(&self, lang: &str) -> bool {
        self.languages.iter().any(|l| l == lang || l == "generic")
    }
}

/// Extract indexable literals from a pattern: longest alphanumeric tokens >= 3 chars,
/// skipping metavariables ($VAR) and ellipsis. Used to build Aho-Corasick filter.
pub fn extract_literals(pattern: &str) -> Vec<String> {
    let mut lits = vec![];
    // Remove metavariables first.
    let mut cleaned = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b')' && bytes[j] != b'('
                && bytes[j] != b',' && bytes[j] != b' ' && bytes[j] != b'"'
                && bytes[j] != b'\''
            {
                // consume $...ARGS dots too
                if bytes[j] == b'.' && !(j > i + 1 && bytes[j - 1] == b'.') {
                    break;
                }
                j += 1;
                if j - i > 32 {
                    break;
                }
            }
            i = j;
        } else if pattern[i..].starts_with("...") {
            i += 3;
        } else {
            let ch = pattern[i..].chars().next().unwrap();
            cleaned.push(ch);
            i += ch.len_utf8();
        }
    }
    for tok in cleaned
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.' && c != '-')
        {
        // Keep dotted callees like cursor.execute, and dashed secrets like
        // `sk-`. Emit each part *and* the whole token: the whole token is a
        // strictly more specific literal, while the parts keep every previously
        // working case working. Both are safe because whitespace splits tokens,
        // so a literal can never contain a space that the whitespace-insensitive
        // matcher would have collapsed -- and '-' and '.' are literal in a
        // pattern, so a match implies the token is present verbatim.
        for part in tok.split('.') {
            if part.len() >= 3 {
                lits.push(part.to_lowercase());
            }
        }
        if tok.len() >= 3 {
            lits.push(tok.to_lowercase());
        }
    }
    lits
}

/// Load a single rule file (native schema or portable schema).
pub fn load_rules_file(path: &str) -> Result<Vec<Rule>> {
    Ok(load_rules_file_report(path)?.0)
}

/// Like [`load_rules_file`] but also returns human-readable warnings for
/// portable-schema rules that were skipped (unsupported construct / no
/// supported languages) or adjusted (dropped language, ignored fix-regex).
pub fn load_rules_file_report(path: &str) -> Result<(Vec<Rule>, Vec<String>)> {
    let text = std::fs::read_to_string(path)?;
    load_rules_str_report(&text, path)
}

/// Parse rule YAML text (single rule, list of rules) into rules + warnings.
/// `src` is used only for warning/error context (typically the file path).
///
/// Strategy: when no portable-schema markers are present, use the typed
/// native parse (preserves raw scalar text for patterns like `0o777`,
/// which a `Value` round-trip would turn into an integer). Documents that
/// *do* carry portable markers are handled item-by-item: portable items are
/// translated, native-shaped items are still parsed as `Rule`.
pub fn load_rules_str_report(text: &str, src: &str) -> Result<(Vec<Rule>, Vec<String>)> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).with_context(|| format!("parsing {src}"))?;
    let items: Vec<serde_yaml::Value> = match &value {
        serde_yaml::Value::Sequence(s) => s.clone(),
        other => vec![other.clone()],
    };
    let portable_any = items.iter().any(portable::looks_portable);

    if !portable_any {
        // Preserve the exact native behavior (single-rule, then list).
        if let Ok(rule) = serde_yaml::from_str::<Rule>(text) {
            rule.validate().with_context(|| src.to_string())?;
            return Ok((vec![rule], vec![]));
        }
        let rules: Vec<Rule> =
            serde_yaml::from_str(text).with_context(|| format!("loading {src}"))?;
        for r in &rules {
            r.validate().with_context(|| src.to_string())?;
        }
        return Ok((rules, vec![]));
    }

    let mut out = vec![];
    let mut warnings = vec![];
    for (i, item) in items.iter().enumerate() {
        let item_id = item
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("<item {}>", i + 1));
        if portable::looks_portable(item) {
            match portable::translate(item) {
                Ok((rule, w)) => {
                    out.push(rule);
                    warnings.extend(w.into_iter().map(|x| format!("{src}: {x}")));
                }
                Err(reason) => {
                    // translate() errors usually begin with "rule {id}: ...";
                    // avoid repeating the id in the warning line.
                    let reason = reason
                        .strip_prefix(&format!("rule {item_id}: "))
                        .unwrap_or(&reason);
                    warnings.push(format!("{src}: rule {item_id} skipped: {reason}"));
                }
            }
        } else {
            match serde_yaml::from_value::<Rule>(item.clone()) {
                Ok(rule) => {
                    rule.validate()
                        .with_context(|| format!("rule {item_id} in {src}"))?;
                    out.push(rule);
                }
                Err(e) => {
                    warnings.push(format!("{src}: rule {item_id} skipped: {e}"));
                }
            }
        }
    }
    Ok((out, warnings))
}

/// Load every `.yaml`/`.yml` rule file under `dir` (recursively).
pub fn load_rules_dir(dir: &str) -> Result<Vec<Rule>> {
    Ok(load_rules_dir_report(dir)?.0)
}

/// Like [`load_rules_dir`], surfacing per-rule skip/adjust warnings.
pub fn load_rules_dir_report(dir: &str) -> Result<(Vec<Rule>, Vec<String>)> {
    let mut out = vec![];
    let mut warnings = vec![];
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        let rd = std::fs::read_dir(&d)?;
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let p = entry.path();
            if p.is_dir() {
                // Fixtures live under rules/tests/ — never load them as rules.
                if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                    continue;
                }
                stack.push(p);
            } else if p.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                let (rules, w) = load_rules_file_report(p.to_str().unwrap())
                    .with_context(|| format!("loading {}", p.display()))?;
                out.extend(rules);
                warnings.extend(w);
            }
        }
    }
    Ok((out, warnings))
}

/// Rule index for speed: literal -> rule ids. Matcher consults per-file lowercase text.
///
/// Rules whose patterns yield no indexable literal (`"iv = \""`, `$VAR = "SK$REST"`)
/// are collected in `always` and returned for **every** file. Without that, the
/// prefilter would silently disable them: they load, validate, and pass their
/// own fixtures, yet never fire in a real scan.
pub struct RuleIndex {
    pub literals: HashSet<String>,
    pub literal_to_rules: HashMap<String, Vec<usize>>,
    /// Rules with no indexable literal; always candidates.
    pub always: Vec<usize>,
}

impl RuleIndex {
    pub fn build(rules: &[Rule]) -> Self {
        let mut literals = HashSet::new();
        let mut literal_to_rules: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always = Vec::new();
        for (idx, r) in rules.iter().enumerate() {
            let mut any = false;
            for p in r.positive_patterns() {
                for lit in extract_literals(&p) {
                    literals.insert(lit.clone());
                    literal_to_rules.entry(lit).or_default().push(idx);
                    any = true;
                }
            }
            if !any {
                always.push(idx);
            }
        }
        Self { literals, literal_to_rules, always }
    }

    /// Candidate rule indices for a file's text (lowercased once by caller ideally).
    pub fn candidates(&self, file_text_lower: &str) -> Vec<usize> {
        let mut hits: HashSet<usize> = self.always.iter().copied().collect();
        for (lit, rules) in &self.literal_to_rules {
            if file_text_lower.contains(lit.as_str()) {
                for r in rules {
                    hits.insert(*r);
                }
            }
        }
        let mut v: Vec<_> = hits.into_iter().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_execute() {
        let l = extract_literals("cursor.execute($VAR, ...)");
        assert!(l.contains(&"cursor".to_string()));
        assert!(l.contains(&"execute".to_string()));
    }

    #[test]
    fn extracts_whole_token_for_secret_patterns() {
        // Regression: `sk-$REST` / `"SG.$REST"` produced no indexable literal
        // before, so the prefilter never ran the rule at all.
        assert!(extract_literals("\"sk-$REST\"").contains(&"sk-".to_string()));
        assert!(extract_literals("$VAR = \"SG.$REST\"").contains(&"sg.".to_string()));
        // Short tokens still yield nothing; those rules rely on `always`.
        assert!(extract_literals("iv = \"").is_empty());
    }

    #[test]
    fn rule_without_literals_is_always_a_candidate() {
        // A valid rule whose pattern yields no literal must still be offered to
        // the matcher for every file, instead of being silently dropped.
        let r = Rule {
            id: "no-lit".into(),
            languages: vec!["python".into()],
            severity: "ERROR".into(),
            category: None,
            message: "m".into(),
            fix: None,
            pattern: Some("$A".into()),
            pattern_either: None,
            patterns: None,
            pattern_not: None,
            pattern_inside: None,
            metavariable_regex: None,
            metavariable_comparison: None,
            taint: None,
            metadata: None,
        };
        let idx = RuleIndex::build(std::slice::from_ref(&r));
        assert_eq!(idx.always, vec![0], "rule must be always-candidate");
        // Even for text containing none of its (non-existent) literals.
        assert_eq!(idx.candidates("totally unrelated text"), vec![0]);
    }

    #[test]
    fn index_candidates() {
        let r = Rule {
            id: "x".into(),
            languages: vec!["python".into()],
            severity: "ERROR".into(),
            category: None,
            message: "m".into(),
            fix: None,
            pattern: Some("cursor.execute($VAR)".into()),
            pattern_either: None,
            patterns: None,
            pattern_not: None,
            pattern_inside: None,
            metavariable_regex: None,
            metavariable_comparison: None,
            taint: None,
            metadata: None,
        };
        let idx = RuleIndex::build(&[r]);
        assert!(!idx.candidates("cursor.execute(q)").is_empty());
        assert!(idx.candidates("print('hello')").is_empty());
    }
}
