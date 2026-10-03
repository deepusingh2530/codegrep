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

/// Byte offset of the first non-whitespace character at or after `from`.
fn skip_ws(pattern: &str, from: usize) -> usize {
    let bytes = pattern.as_bytes();
    let mut j = from;
    while j < bytes.len() && (bytes[j] as char).is_whitespace() {
        j += 1;
    }
    j
}

/// True when an ellipsis follows `from`, ignoring whitespace. Lets `f($X, ...)`,
/// `f($X,... )` and `f($X,  ...)` all compile the same way.
fn ellipsis_follows(pattern: &str, from: usize) -> bool {
    let j = skip_ws(pattern, from);
    pattern[j..].starts_with("...")
}

/// Translate a scanward pattern to a regex string.
/// - `\$VAR` escape -> a literal `$` (JSON Schema/OpenAPI `$ref`, `$schema`,
///   jQuery). Without it, a pattern that needs a literal `$` immediately before
///   a word is silently reinterpreted as a metavariable.
/// - `$VAR`, `$X` -> named capture `.+?`
/// - `$...ARGS` -> named capture `.*?`
/// - `...` -> `.*?`
/// - `f($X, ...)` -> $X plus **zero or more** further arguments
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
        } else if ch == ',' && ellipsis_follows(pattern, i + 1) {
            // `f($X, ...)` means "$X, then any number of further arguments --
            // including none". Compiling the comma as a literal made the trailing
            // arguments MANDATORY, so every single-argument call was missed:
            // `exec(req.query.cmd)` never matched `exec($VAR, ...)`.
            //
            // Because matching is DOTALL, that same mandatory comma was satisfied
            // by any comma appearing later in the file, so the finding was
            // attributed to the wrong line. That is why the rule appeared to fire
            // only when unrelated code happened to contain a comma.
            out.push_str("(?:,\\s*.*?)?");
            i = skip_ws(pattern, i + 1) + 3;
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

#[cfg(test)]
mod trailing_ellipsis_tests {
    use super::*;

    /// Regression: `exec($VAR, ...)` compiled the comma as a literal, so the
    /// trailing arguments were MANDATORY. Every single-argument call was missed,
    /// which is the overwhelmingly common shape for a command-injection sink.
    /// Because matching is DOTALL, the same mandatory comma was then satisfied by
    /// any comma appearing later in the file, so the rule only fired when the file
    /// happened to contain an unrelated comma -- and reported the wrong line.
    #[test]
    fn single_argument_call_matches() {
        let re = compile_pattern("exec($VAR, ...)").unwrap();
        assert!(
            re.is_match("return exec(req.query.cmd);"),
            "a one-argument call is the common sink and must match"
        );
    }

    #[test]
    fn multi_argument_call_still_matches() {
        let re = compile_pattern("exec($VAR, ...)").unwrap();
        assert!(re.is_match("return exec(req.query.cmd, { shell: true });"));
    }

    #[test]
    fn unrelated_later_comma_does_not_change_the_match() {
        // Before the fix this returned true only because the regex could span
        // lines to reach the comma in `db, id`.
        let re = compile_pattern("exec($VAR, ...)").unwrap();
        let src = "function run(req) { return exec(req.query.cmd); }\n\
                   function q(db, id) { return db.query(1); }";
        let caps = re.captures(src).expect("the sink still matches");
        let var = caps.name("VAR").unwrap().as_str();
        assert_eq!(var, "req.query.cmd", "capture must not run past the call");
    }

    #[test]
    fn spacing_variants_behave_identically() {
        for pattern in ["exec($VAR, ...)", "exec($VAR,...)", "exec($VAR,  ...)"] {
            let re = compile_pattern(pattern).unwrap();
            assert!(
                re.is_match("exec(a)"),
                "{pattern} should match a one-argument call"
            );
        }
    }

    #[test]
    fn ellipsis_after_a_comma_is_optional_but_a_bare_comma_is_not() {
        // `f($A, $B, ...)` still requires both named arguments.
        let re = compile_pattern("f($A, $B, ...)").unwrap();
        assert!(!re.is_match("f(1)"), "one argument is not enough");
        assert!(re.is_match("f(1, 2)"));
    }

    /// Regression for the rule-authoring half of the fix: a pattern that stops at
    /// `...` without a closing paren can end mid-token, truncating the final
    /// capture so a `metavariable-regex` post-filter inspects a shorter value.
    /// Terminating the pattern is what makes the capture stable.
    #[test]
    fn unterminated_pattern_can_truncate_the_last_capture() {
        let terminated = compile_pattern("pbkdf2($PW, $ITER, ...)").unwrap();
        let caps = terminated
            .captures("pbkdf2(password, 600000, 32, \"sha256\")")
            .unwrap();
        assert_eq!(caps.name("ITER").unwrap().as_str(), "600000");
    }
}

#[cfg(test)]
mod regex_receiver_tests {
    use super::*;

    /// `pattern-not` on the command-injection rule relies on this shape: a
    /// regex-literal receiver (`/[a-z]+/.exec(line)`) must be recognisable so it
    /// can be excluded from `exec($VAR, ...)`.
    #[test]
    fn regex_literal_receiver_is_recognisable() {
        let neg = compile_pattern("/$RE/.exec(...)").unwrap();
        assert!(
            neg.is_match("const m = /[a-z]+/.exec(line);"),
            "a regex-literal .exec() call must match the negative pattern"
        );
        assert!(
            !neg.is_match("const cp = require('child_process');"),
            "ordinary code must not match the negative pattern"
        );
    }
}
