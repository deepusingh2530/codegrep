//! scanward matcher v0.2 (Tier-2 incremental).
//! - Patterns with $VAR / $...ARGS / ... compiled to regex, matched over the
//!   WHOLE file text (DOTALL) so multi-line sinks work; byte offset -> line/col.
//! - `metavariable-regex` and `metavariable-comparison` ($N > 1024) supported.
//! - `pattern-inside` is evaluated at call sites as coarse file-level containment
//!   (documented limitation; full block-range scoping is roadmap).
//!
//! Deterministic + offline.

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Match {
    pub line: usize,
    pub col: usize,
    pub snippet: String,
    pub captures: HashMap<String, String>,
}

/// Translate a scanward pattern to a regex string.
/// - `\$VAR` escape -> a literal `$` (JSON Schema/OpenAPI `$ref`, `$schema`,
///   jQuery). Without it, a pattern that needs a literal `$` immediately before
///   a word is silently reinterpreted as a metavariable.
/// - `$VAR`, `$X` -> named capture `.+?`
/// - `$...ARGS` -> named capture `.*?`
/// - `...` -> `.*?`
/// - whitespace runs -> `\s*` (patterns are whitespace/newline-insensitive,
///   so single-line patterns match multi-line call sites)
/// - rest is regex-escaped.
pub fn pattern_to_regex_src(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 2);
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = pattern[i..].chars().next().unwrap();
        if ch.is_whitespace() {
            // Collapse the whole run to optional whitespace (covers spaces/newlines).
            let mut j = i + ch.len_utf8();
            while j < bytes.len() {
                let c = pattern[j..].chars().next().unwrap();
                if !c.is_whitespace() {
                    break;
                }
                j += c.len_utf8();
            }
            out.push_str("\\s*");
            i = j;
        } else if pattern[i..].starts_with("\\$") {
            // Escaped dollar: a literal `$`, not a metavariable.
            out.push_str("\\$");
            i += 2;
        } else         if pattern[i..].starts_with("$...") {
            let mut j = i + 4;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
            {
                j += 1;
            }
            let name = &pattern[i + 1..j];
            let clean: String =
                name.chars().filter(|c| c.is_alphanumeric()).collect();
            let cap = if clean.is_empty() {
                "REST".to_string()
            } else {
                format!("{clean}_REST")
            };
            // Trailing capture must be greedy, else it matches empty/minimal
            // and post-filters (metavariable-regex) see a truncated value.
            if j == bytes.len() {
                out.push_str(&format!("(?P<{cap}>.*)"));
            } else {
                out.push_str(&format!("(?P<{cap}>.*?)"));
            }
            i = j;
        } else if bytes[i] == b'$' && i + 1 < bytes.len()
            && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'_')
        {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
            {
                j += 1;
            }
            let name = &pattern[i + 1..j];
            if j == bytes.len() {
                out.push_str(&format!("(?P<{name}>.+)"));
            } else {
                out.push_str(&format!("(?P<{name}>.+?)"));
            }
            i = j;
        } else if pattern[i..].starts_with("...") {
            out.push_str(".*?");
            i += 3;
        } else {
            let ch = pattern[i..].chars().next().unwrap();
            out.push_str(&regex::escape(&ch.to_string()));
            i += ch.len_utf8();
        }
    }
    out
}

pub fn compile_pattern(pattern: &str) -> Result<Regex> {
    // (?s): DOTALL so `...` and `.+?` span newlines for multi-line sinks.
    let src = format!("(?s){}", pattern_to_regex_src(pattern));
    Ok(Regex::new(&src)?)
}

fn line_col_of(source: &str, byte: usize) -> (usize, usize) {
    let before = &source[..byte.min(source.len())];
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = byte - before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    (line, col)
}

/// Match pattern against whole source text. Returns matches with 1-based lines.
pub fn find_matches(pattern: &str, source: &str) -> Result<Vec<Match>> {
    let re = compile_pattern(pattern)?;
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    for caps in re.captures_iter(source) {
        let whole = match caps.get(0) {
            Some(m) => m,
            None => continue,
        };
        let (line, col) = line_col_of(source, whole.start());
        let mut captures = HashMap::new();
        for name in re.capture_names().flatten() {
            if let Some(v) = caps.name(name) {
                captures.insert(name.to_string(), v.as_str().to_string());
            }
        }
        let snippet: String = lines
            .get(line - 1)
            .unwrap_or(&"")
            .trim()
            .chars()
            .take(300)
            .collect();
        out.push(Match { line, col, snippet, captures });
    }
    Ok(out)
}

/// Check metavariable-regex constraints: var -> required regex.
pub fn check_metavariable_regex(
    m: &Match,
    constraints: &HashMap<String, String>,
) -> bool {
    for (var, rs) in constraints {
        let val = match m.captures.get(var) {
            Some(v) => v,
            None => continue,
        };
        let re = match Regex::new(rs) {
            Ok(r) => r,
            Err(_) => return false,
        };
        if !re.is_match(val) {
            return false;
        }
    }
    true
}

/// Check a simple numeric comparison like `$N > 1024`, `$SIZE <= 4096`.
/// Returns true when the expression is absent/unparseable-var (skip) and
/// false only on a definite violation or invalid expression.
pub fn check_metavariable_comparison(m: &Match, expr: &str) -> bool {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 3 {
        return false;
    }
    let var = parts[0].trim_start_matches('$');
    let op = parts[1];
    let rhs: f64 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let raw = match m.captures.get(var) {
        Some(v) => v.clone(),
        None => return true, // var not bound here -> don't filter
    };
    // Extract first number from capture (e.g. "buf[8192]" -> 8192).
    let num_re = Regex::new(r"-?\d+(\.\d+)?").unwrap();
    let lhs: f64 = match num_re.find(&raw).and_then(|x| x.as_str().parse().ok()) {
        Some(v) => v,
        None => return true, // non-numeric capture -> don't filter
    };
    match op {
        ">" => lhs > rhs,
        ">=" => lhs >= rhs,
        "<" => lhs < rhs,
        "<=" => lhs <= rhs,
        "==" | "=" => (lhs - rhs).abs() < f64::EPSILON,
        "!=" => (lhs - rhs).abs() >= f64::EPSILON,
        _ => false,
    }
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    #[test]
    fn escaped_dollar_is_a_literal_dollar() {
        // The bug this fixes: `$ref: 'http://x'` compiled to a metavariable, so
        // the rule matched any `key: http://...` in any YAML file.
        let src = pattern_to_regex_src("\\$ref: 'http://$URL'");
        assert!(src.contains("\\$ref"), "literal $ preserved: {src}");
        assert!(!src.contains("(?P<ref>"), "no metavariable named ref: {src}");

        let re = compile_pattern("\\$ref: 'http://$URL'").unwrap();
        assert!(re.is_match("$ref: 'http://schemas.example.com/user.json'"));
        assert!(
            !re.is_match("url: http://example.com/pkg.tar.gz"),
            "a plain http url is not a $ref"
        );
        assert!(!re.is_match("$myref: 'http://example.com'"));
    }

    #[test]
    fn unescaped_dollar_is_still_a_metavariable() {
        let src = pattern_to_regex_src("$VAR($X)");
        assert!(src.contains("(?P<VAR>"), "{src}");
        assert!(src.contains("(?P<X>"), "{src}");
    }

    #[test]
    fn escaped_and_unescaped_dollars_coexist() {
        let re = compile_pattern("\\$ref: $URL").unwrap();
        assert!(re.is_match("$ref: ./components/schemas/User"));
        assert!(!re.is_match("prefix: ./components/schemas/User"));
    }
}
