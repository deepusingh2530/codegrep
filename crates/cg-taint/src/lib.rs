//! scanward taint v0.3: intra-file flow with function summaries.
//! - Line-level propagation (assign, concat, call args) as before.
//! - Function definitions are extracted per language family (indent vs braces).
//!   Parameters are treated as untrusted (standard SAST over-approximation).
//! - One-level call summaries: a function that returns tainted data taints its
//!   callers' receiving variables (fixpoint over two phases, monotone).
//!
//! Coarse on purpose: same-short-name methods share summaries, no cross-file
//! analysis yet.
//!
//! Deterministic, offline, no new dependencies.

use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Translate a taint sub-pattern like `request.$ANYTHING` / `cursor.execute(...)`
/// to a regex over source lines.
fn taint_pat_to_regex(pat: &str) -> Option<Regex> {
    let mut out = String::new();
    let bytes = pat.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if pat[i..].starts_with("$") {
            // wildcard for property / args
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric()
                    || bytes[j] == b'_'
                    || bytes[j] == b'.')
            {
                j += 1;
            }
            out.push_str(".*?");
            i = j.max(i + 1);
        } else if pat[i..].starts_with("...") {
            out.push_str(".*?");
            i += 3;
        } else {
            let ch = pat[i..].chars().next().unwrap();
            out.push_str(&regex::escape(&ch.to_string()));
            i += ch.len_utf8();
        }
    }
    Regex::new(&out).ok()
}

pub struct TaintRule {
    pub sources: Vec<Regex>,
    pub sinks: Vec<Regex>,
    pub sanitizers: Vec<Regex>,
}

impl TaintRule {
    pub fn compile(sources: &[String], sinks: &[String], sanitizers: &[String]) -> Self {
        Self {
            sources: sources.iter().filter_map(|s| taint_pat_to_regex(s)).collect(),
            sinks: sinks.iter().filter_map(|s| taint_pat_to_regex(s)).collect(),
            sanitizers: sanitizers.iter().filter_map(|s| taint_pat_to_regex(s)).collect(),
        }
    }

    /// Scan lines; return sink line numbers where tainted var reaches sink.
    pub fn scan(&self, source: &str) -> Vec<usize> {
        let assign_re = Regex::new(r"^[\w\s,]+\s*=\s*(.+)$").unwrap();
        let ident_re = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap();
        let mut tainted: HashSet<String> = HashSet::new();
        let mut hits = vec![];
        for (idx, raw) in source.lines().enumerate() {
            let line = raw.trim();
            let lineno = idx + 1;
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            // sanitizer defines clean var
            if self.sanitizers.iter().any(|r| r.is_match(line)) {
                for _m in ident_re.find_iter(line) {
                    // conservative: clean LHS var if line is assignment with sanitizer RHS
                    if let Some(cap) = assign_re.captures(line) {
                        let lhs = line.split('=').next().unwrap_or("");
                        for id in ident_re.find_iter(lhs) {
                            let _ = &cap;
                            tainted.remove(id.as_str());
                        }
                    }
                }
                continue;
            }
            // source marks taint: either direct source line assigns var, or source appears inline
            let has_source = self.sources.iter().any(|r| r.is_match(line));
            if has_source {
                if let Some(eq) = line.find('=') {
                    let lhs = &line[..eq];
                    for id in ident_re.find_iter(lhs) {
                        // skip keywords
                        let w = id.as_str();
                        if !["if", "for", "while", "return", "import", "from"].contains(&w) {
                            tainted.insert(w.to_string());
                        }
                    }
                } else {
                    tainted.insert(format!("__line{l}__", l = lineno));
                }
            }
            // propagate: x = tainted_var (+ concat etc.)
            if line.contains('=') && !has_source {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let rhs = parts[1];
                    let uses_tainted = tainted.iter().any(|t| {
                        rhs.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|tok| tok == t)
                    });
                    if uses_tainted {
                        for id in ident_re.find_iter(parts[0]) {
                            tainted.insert(id.as_str().to_string());
                        }
                    }
                }
            }
            // sink with tainted var or direct source inline
            let has_sink = self.sinks.iter().any(|r| r.is_match(line));
            if has_sink {
                let uses_tainted = tainted.iter().any(|t| {
                    line.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
                        .any(|tok| tok == t || tok.ends_with(t.as_str()))
                });
                if uses_tainted || has_source {
                    hits.push(lineno);
                }
            }
        }
        hits
    }
}

use std::sync::LazyLock;

static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap());
static CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z_][A-Za-z0-9_\.]*)\s*\(").unwrap());
static DEF_PY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)").unwrap()
});

fn tokens(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .collect()
}

fn parse_params(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|p| {
            let p = p.trim().trim_start_matches('*');
            let name: String = p
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty()
                || ["self", "cls", "this"].contains(&name.as_str())
            {
                None
            } else {
                Some(name)
            }
        })
        .collect()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

struct FnDef {
    name: String,
    params: Vec<String>,
    /// 0-based global line indices covered by this function (def line + body).
    span: Vec<usize>,
    /// Body lines with their 1-based global line numbers.
    body: Vec<(usize, String)>,
}

/// Indent-family extraction (Python, Ruby): `def name(params)` + deeper-indented body.
fn extract_indent(lines: &[&str]) -> Vec<FnDef> {
    let mut out = vec![];
    let mut i = 0;
    while i < lines.len() {
        if let Some(cap) = DEF_PY_RE.captures(lines[i]) {
            let base = indent_of(lines[i]);
            let name = cap[1].to_string();
            let params = parse_params(&cap[2]);
            let mut j = i + 1;
            while j < lines.len()
                && (lines[j].trim().is_empty() || indent_of(lines[j]) > base)
            {
                j += 1;
            }
            out.push(FnDef {
                name,
                params,
                span: (i..j).collect(),
                body: ((i + 1)..j).map(|k| (k + 1, lines[k].to_string())).collect(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Brace-family extraction (JS/TS/Go/Java/PHP/C#): def-ish line with `{` + brace matching.
/// Skips control keywords so `if (...) {` is not treated as a function.
fn extract_braces(lines: &[&str]) -> Vec<FnDef> {
    const KEYWORDS: [&str; 9] = [
        "if", "for", "while", "switch", "catch", "return", "elif", "else", "do",
    ];
    let name_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$").unwrap();
    let mut out = vec![];
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let first = t.split([' ', '\t', '(']).next().unwrap_or("");
        let looks_def = t.contains('(')
            && t.contains('{')
            && !t.ends_with(';')
            && !KEYWORDS.contains(&first)
            && name_re.is_match(t);
        if looks_def {
            let name = name_re
                .captures(t)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            // params: text between first '(' and matching ')' on the def line(s).
            let lp = t.find('(').unwrap_or(0);
            let rp = t.rfind(')').unwrap_or(t.len());
            let params = if rp > lp {
                parse_params(&t[lp + 1..rp])
            } else {
                vec![]
            };
            let mut depth = 0i32;
            let mut j = i;
            while j < lines.len() {
                depth += lines[j].bytes().filter(|&b| b == b'{').count() as i32;
                depth -= lines[j].bytes().filter(|&b| b == b'}').count() as i32;
                j += 1;
                if depth <= 0 {
                    break;
                }
            }
            if name.is_empty() {
                i += 1;
                continue;
            }
            out.push(FnDef {
                name,
                params,
                span: (i..j).collect(),
                body: ((i + 1)..j).map(|k| (k + 1, lines[k].to_string())).collect(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn extract_functions(source: &str, lang: &str) -> Vec<FnDef> {
    let lines: Vec<&str> = source.lines().collect();
    match lang {
        "python" | "ruby" => extract_indent(&lines),
        "generic" => {
            let mut both = extract_indent(&lines);
            both.extend(extract_braces(&lines));
            both
        }
        _ => extract_braces(&lines),
    }
}

/// Short callee name: `obj.get` -> `get`, `f` -> `f`.
fn short_callee(full: &str) -> &str {
    full.rsplit('.').next().unwrap_or(full)
}

impl TaintRule {
    /// Analyze one scope. `seed` vars start tainted (e.g. function params).
    /// Returns (0-based local hit indices, whether a `return` leaks taint).
    fn analyze(
        &self,
        body: &[(usize, String)],
        seed: &HashSet<String>,
        summaries: &HashMap<String, bool>,
    ) -> (Vec<usize>, bool) {
        let mut tainted: HashSet<String> = seed.clone();
        let mut hits = vec![];
        let mut returns_tainted = false;
        for (local_idx, (lineno, raw)) in body.iter().enumerate() {
            let _ = lineno;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let has_source = self.sources.iter().any(|r| r.is_match(line));
            if self.sanitizers.iter().any(|r| r.is_match(line)) {
                if let Some(eq) = line.find('=') {
                    let lhs = &line[..eq];
                    for id in IDENT_RE.find_iter(lhs) {
                        tainted.remove(id.as_str());
                    }
                }
                continue;
            }
            if has_source {
                if let Some(eq) = line.find('=') {
                    let lhs = &line[..eq];
                    for id in IDENT_RE.find_iter(lhs) {
                        let w = id.as_str();
                        if !["if", "for", "while", "return", "import", "from"]
                            .contains(&w)
                        {
                            tainted.insert(w.to_string());
                        }
                    }
                } else {
                    tainted.insert(format!("__line{local_idx}__"));
                }
            }
            // Calls to tainted-returning functions: taint LHS, hit on sink lines.
            let mut call_taints_lhs = false;
            let mut call_hits_sink = false;
            for cap in CALL_RE.captures_iter(line) {
                let short = short_callee(&cap[1]).to_string();
                if summaries.get(&short) != Some(&true) {
                    continue;
                }
                // Arguments text: crude slice from '(' to end.
                let after = &line[cap.get(0).unwrap().end()..];
                let arg_tainted = tokens(after).iter().any(|t| tainted.contains(*t));
                let no_args = tokens(after).is_empty();
                if arg_tainted || no_args || has_source {
                    call_taints_lhs = true;
                    call_hits_sink = true;
                }
            }
            if line.contains('=') && !has_source {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let rhs = parts[1];
                    let uses_tainted =
                        tokens(rhs).iter().any(|t| tainted.contains(*t));
                    if uses_tainted || call_taints_lhs {
                        for id in IDENT_RE.find_iter(parts[0]) {
                            tainted.insert(id.as_str().to_string());
                        }
                    }
                }
            } else if call_taints_lhs && !line.contains('=') {
                tainted.insert(format!("__line{local_idx}__"));
            }
            let has_sink = self.sinks.iter().any(|r| r.is_match(line));
            if has_sink {
                let uses_tainted = tokens(line)
                    .iter()
                    .any(|t| tainted.contains(*t) || {
                        tainted.iter().any(|tt| t.ends_with(tt.as_str()))
                    });
                if uses_tainted || has_source || call_hits_sink {
                    hits.push(local_idx);
                }
            }
            if line.starts_with("return") {
                let uses_tainted = tokens(line).iter().any(|t| tainted.contains(*t));
                if uses_tainted || has_source || call_hits_sink {
                    returns_tainted = true;
                }
            }
        }
        (hits, returns_tainted)
    }

    /// Scope-aware scan: function summaries + two-phase fixpoint, global 1-based lines.
    /// Falls back to flat scan when no functions are found.
    pub fn scan_scoped(&self, source: &str, lang: &str) -> Vec<usize> {
        let fns = extract_functions(source, lang);
        if fns.is_empty() {
            return self.scan(source);
        }
        // Phase 1: summaries (params seeded as tainted).
        let mut summaries: HashMap<String, bool> = HashMap::new();
        for f in &fns {
            let seed: HashSet<String> = f.params.iter().cloned().collect();
            let (_, ret) = self.analyze(&f.body, &seed, &HashMap::new());
            summaries
                .entry(f.name.clone())
                .and_modify(|v| *v = *v || ret)
                .or_insert(ret);
        }
        // Phase 2: full scan with summaries; top-level = lines outside all spans.
        let covered: HashSet<usize> = fns.iter().flat_map(|f| f.span.clone()).collect();
        let all: Vec<(usize, String)> = source
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l.to_string()))
            .collect();
        let top: Vec<(usize, String)> = all
            .iter()
            .enumerate()
            .filter(|(i, _)| !covered.contains(i))
            .map(|(_, (n, l))| (*n, l.clone()))
            .collect();
        let mut hits = vec![];
        let (h, _) = self.analyze(&top, &HashSet::new(), &summaries);
        hits.extend(h.iter().map(|i| top[*i].0));
        for f in &fns {
            let seed: HashSet<String> = f.params.iter().cloned().collect();
            let (h, _) = self.analyze(&f.body, &seed, &summaries);
            hits.extend(h.iter().map(|i| f.body[*i].0));
        }
        hits.sort_unstable();
        hits.dedup();
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_flow() {
        let r = TaintRule::compile(
            &["request.args".to_string()],
            &["cursor.execute(...)".to_string()],
            &[],
        );
        let src = "q = request.args.get('q')\ncursor.execute(q)\n";
        assert_eq!(r.scan(src), vec![2]);
    }

    #[test]
    fn sanitized_no_finding() {
        let r = TaintRule::compile(
            &["request.args".to_string()],
            &["cursor.execute(...)".to_string()],
            &["escape_sql(...)".to_string()],
        );
        let src = "q = request.args.get('q')\nq = escape_sql(q)\ncursor.execute(q)\n";
        assert!(r.scan(src).is_empty());
    }

    #[test]
    fn scoped_matches_flat_when_no_functions() {
        let r = TaintRule::compile(
            &["request.args".to_string()],
            &["cursor.execute(...)".to_string()],
            &[],
        );
        let src = "q = request.args.get('q')\ncursor.execute(q)\n";
        assert_eq!(r.scan_scoped(src, "python"), vec![2]);
    }

    #[test]
    fn through_function_summary() {
        let r = TaintRule::compile(
            &["request.args".to_string()],
            &["cursor.execute(...)".to_string()],
            &[],
        );
        let src = "def get_q():\n  return request.args.get('q')\nq = get_q()\ncursor.execute(q)\n";
        assert_eq!(r.scan_scoped(src, "python"), vec![4]);
    }

    #[test]
    fn param_sink_inside_function() {
        let r = TaintRule::compile(
            &["request.args".to_string()],
            &["cursor.execute(...)".to_string()],
            &[],
        );
        let src = "def run(q):\n  cursor.execute(q)\n";
        assert_eq!(r.scan_scoped(src, "python"), vec![2]);
    }

    #[test]
    fn js_function_scope() {
        let r = TaintRule::compile(
            &["req.query".to_string()],
            &["eval(...)".to_string()],
            &[],
        );
        let src = "function h(q) {\n  eval(q);\n}\n";
        assert_eq!(r.scan_scoped(src, "javascript"), vec![2]);
    }
}
