//! codegrep rules: YAML loader + validator + literal indexer (Aho-Corasick).
//! Rule format is Semgrep-inspired but original; content is MIT-licensed own rules.

use anyhow::{anyhow, Context, Result};
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
    for tok in cleaned.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.') {
        // keep dotted callees like cursor.execute; split also on '.'
        for part in tok.split('.') {
            if part.len() >= 3 {
                lits.push(part.to_lowercase());
            }
        }
    }
    lits
}

pub fn load_rules_file(path: &str) -> Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)?;
    // Support both single-rule and list-of-rules documents.
    if let Ok(rule) = serde_yaml::from_str::<Rule>(&text) {
        rule.validate()?;
        return Ok(vec![rule]);
    }
    let rules: Vec<Rule> = serde_yaml::from_str(&text)?;
    for r in &rules {
        r.validate()?;
    }
    Ok(rules)
}

pub fn load_rules_dir(dir: &str) -> Result<Vec<Rule>> {
    let mut out = vec![];
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
                for r in load_rules_file(p.to_str().unwrap()).with_context(|| {
                    format!("loading {}", p.display())
                })? {
                    out.push(r);
                }
            }
        }
    }
    Ok(out)
}

/// Rule index for speed: literal -> rule ids. Matcher consults per-file lowercase text.
pub struct RuleIndex {
    pub literals: HashSet<String>,
    pub literal_to_rules: HashMap<String, Vec<usize>>,
}

impl RuleIndex {
    pub fn build(rules: &[Rule]) -> Self {
        let mut literals = HashSet::new();
        let mut literal_to_rules: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, r) in rules.iter().enumerate() {
            for p in r.positive_patterns() {
                for lit in extract_literals(&p) {
                    literals.insert(lit.clone());
                    literal_to_rules.entry(lit).or_default().push(idx);
                }
            }
        }
        Self { literals, literal_to_rules }
    }

    /// Candidate rule indices for a file's text (lowercased once by caller ideally).
    pub fn candidates(&self, file_text_lower: &str) -> Vec<usize> {
        let mut hits: HashSet<usize> = HashSet::new();
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
