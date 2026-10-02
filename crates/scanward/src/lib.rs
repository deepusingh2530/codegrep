//! scanward library: embeddable offline SAST scanning.
//!
//! The CLI (`src/main.rs`) is a thin wrapper over this API:
//!
//! ```no_run
//! let report = scanward::scan(&scanward::ScanOptions {
//!     path: "src".into(),
//!     rules: "rules".into(),
//!     ..Default::default()
//! })?;
//! for f in &report.findings {
//!     println!("{}:{} [{}] {}", f.path, f.line, f.severity, f.rule_id);
//! }
//! # anyhow::Ok(())
//! ```
//!
//! Rules ship as YAML in this repository's `rules/` directory — point
//! `ScanOptions::rules` (or `config`) at a local checkout of the repo
//! (git submodule, clone, or vendored copy).

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

// Re-exports so embedders only need the `scanward` crate.
pub use cg_matcher;
pub use cg_parser;
pub use cg_rules::{self, Rule};
pub use cg_taint;
pub mod suppress;
pub use suppress::Suppression;

/// A single scan finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub fix: Option<String>,
    pub path: String,
    pub language: String,
    pub line: usize,
    pub col: usize,
    pub snippet: String,
}

/// Input options for [`scan`]. `Default` = scan `.` with `rules/`,
/// cache on, no filters.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Directory (or file) to scan. Respects `.gitignore`.
    pub path: String,
    /// Rules directory (used when `config` is empty).
    pub rules: String,
    /// Rule files/directories (repeatable; supersedes `rules`).
    /// Remote/registry URLs are refused — the scanner is offline-first.
    pub config: Vec<String>,
    /// Only report paths matching any of these globs/substrings.
    pub include: Vec<String>,
    /// Drop paths matching any of these globs/substrings.
    pub exclude: Vec<String>,
    /// Severity floor: `error` | `warning` | `info`.
    pub min_severity: Option<String>,
    /// Git ref for diff-only scans (requires `diff_only`).
    pub baseline: Option<String>,
    /// Only report findings on lines changed vs `baseline`.
    pub diff_only: bool,
    /// Disable the persistent content-hash cache.
    pub no_cache: bool,
    /// Override cache directory (default: platform cache dir/scanward).
    pub cache_dir: Option<String>,
    /// Rayon worker threads (0 = auto).
    pub jobs: usize,
    /// Suppression files (repeatable). When empty, the scan root is
    /// auto-checked for `.scanward-suppressions.yml`/`.yaml`.
    pub suppress: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            path: ".".into(),
            rules: "rules".into(),
            config: vec![],
            include: vec![],
            exclude: vec![],
            min_severity: None,
            baseline: None,
            diff_only: false,
            no_cache: false,
            cache_dir: None,
            jobs: 0,
            suppress: vec![],
        }
    }
}

/// Result of [`scan`].
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Deduplicated, sorted findings (after filters).
    pub findings: Vec<Finding>,
    /// Files considered (after path filters).
    pub files_scanned: usize,
    /// Rules loaded from `rules`/`config`.
    pub rules_loaded: usize,
    /// Wall time in milliseconds.
    pub elapsed_ms: u128,
    /// Cache hits during this scan.
    pub cache_hits: usize,
    /// Whether the persistent cache was enabled.
    pub cache_on: bool,
    /// Warnings from loading user-supplied rules (portable-schema skips,
    /// dropped languages, ignored fixes). Empty for scanward's own rules.
    pub warnings: Vec<String>,
    /// Findings dropped by suppression files or inline `scanward-ignore`
    /// comments during this scan.
    pub suppressed: usize,
}

/// SARIF 2.1.0 document for the given findings (GitHub code scanning
/// compatible: includes `driver.rules` metadata + `security-severity`).
pub fn sarif_from(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": sarif_level(&f.severity),
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line, "startColumn": f.col + 1}
                }}]
            })
        })
        .collect();
    let mut rules: Vec<serde_json::Value> = vec![];
    let mut seen: HashSet<&str> = HashSet::new();
    for f in findings {
        if seen.insert(f.rule_id.as_str()) {
            rules.push(serde_json::json!({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message},
                "defaultConfiguration": {"level": sarif_level(&f.severity)},
                "properties": {
                    "security-severity": match f.severity.as_str() {
                        "ERROR" => "8.0",
                        "WARNING" => "5.0",
                        _ => "3.0",
                    }
                }
            }));
        }
    }
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {
            "name": "scanward",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules
        }}, "results": results}]
    })
}

fn sarif_level(sev: &str) -> &'static str {
    match sev {
        "ERROR" => "error",
        "WARNING" => "warning",
        _ => "note",
    }
}

/// Escape text for XML element content and attribute values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// JUnit XML report for the given findings: one `<testsuite>` per file,
/// one failed `<testcase>` per finding (severity in `type`, message in
/// `message`, snippet + fix in the element body). An empty scan emits a
/// single passing placeholder testcase so strict JUnit consumers
/// (Jenkins, GitLab test tabs) still receive a valid document.
pub fn junit_from(findings: &[Finding]) -> String {
    use std::fmt::Write;
    // Group by path, first-seen order (findings arrive sorted by path/line).
    let mut groups: Vec<(String, Vec<&Finding>)> = Vec::new();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        match seen.get(f.path.as_str()) {
            Some(&i) => groups[i].1.push(f),
            None => {
                seen.insert(&f.path, groups.len());
                groups.push((f.path.clone(), vec![f]));
            }
        }
    }
    let placeholder = findings.is_empty();
    let total = if placeholder { 1 } else { findings.len() };
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<testsuites name=\"scanward\" tests=\"{total}\" failures=\"{}\" errors=\"0\" time=\"0\">",
        if placeholder { 0 } else { findings.len() }
    );
    if placeholder {
        out.push_str("  <testsuite name=\"scanward\" tests=\"1\" failures=\"0\" errors=\"0\" time=\"0\">\n");
        out.push_str("    <testcase classname=\"scanward\" name=\"no findings\" time=\"0\"/>\n");
        out.push_str("  </testsuite>\n");
    } else {
        for (path, fs) in &groups {
            let _ = writeln!(
                out,
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0\">",
                xml_escape(path),
                fs.len(),
                fs.len()
            );
            for f in fs {
                let _ = writeln!(
                    out,
                    "    <testcase classname=\"{}\" name=\"{}:{}\" time=\"0\">",
                    xml_escape(path),
                    xml_escape(&f.rule_id),
                    f.line
                );
                let mut body = String::new();
                let _ = writeln!(body, "{}", xml_escape(&f.message));
                let _ = writeln!(body, "{}", xml_escape(&f.snippet));
                if let Some(fix) = &f.fix {
                    let _ = writeln!(body, "fix: {}", xml_escape(fix));
                }
                let _ = writeln!(
                    out,
                    "      <failure type=\"{}\" message=\"{}\">{}</failure>",
                    xml_escape(&f.severity),
                    xml_escape(&f.message),
                    body
                );
                out.push_str("    </testcase>\n");
            }
            out.push_str("  </testsuite>\n");
        }
    }
    out.push_str("</testsuites>\n");
    out
}

/// Load rules from `config` entries (files or dirs) or, when empty,
/// from the `rules_dir`. Remote/registry locations are refused.
pub fn load_rule_set(rules_dir: &str, config: &[String]) -> Result<Vec<Rule>> {
    Ok(load_rule_set_report(rules_dir, config)?.0)
}

/// Like [`load_rule_set`], additionally returning warnings about
/// user-supplied portable-schema rules that were skipped or adjusted on load.
pub fn load_rule_set_report(rules_dir: &str, config: &[String]) -> Result<(Vec<Rule>, Vec<String>)> {
    if !config.is_empty() {
        let mut out: Vec<Rule> = vec![];
        let mut warnings: Vec<String> = vec![];
        for c in config {
            if c.starts_with("http://")
                || c.starts_with("https://")
                || c.starts_with("git@")
                || c.starts_with("p/")
                || c.ends_with(".git")
                || c == "auto"
            {
                anyhow::bail!(
                    "scanward: remote/registry configs are not supported (--config {c}). \
                     scanward is offline-first: point --config at a local rule file or directory."
                );
            }
            let p = std::path::Path::new(c);
            if p.is_file() {
                let (rules, w) = cg_rules::load_rules_file_report(c)
                    .with_context(|| format!("loading {c}"))?;
                out.extend(rules);
                warnings.extend(w);
            } else if p.is_dir() {
                let (rules, w) = cg_rules::load_rules_dir_report(c)
                    .with_context(|| format!("loading {c}"))?;
                out.extend(rules);
                warnings.extend(w);
            } else {
                anyhow::bail!("scanward: --config {c}: no such file or directory");
            }
        }
        return Ok((out, warnings));
    }
    if std::path::Path::new(rules_dir).exists() {
        cg_rules::load_rules_dir_report(rules_dir)
            .with_context(|| format!("loading rules from {rules_dir}"))
    } else {
        Ok((vec![], vec![]))
    }
}

/// Scan `opts.path` with the configured rules. Fully offline, parallel,
/// cache-backed. Returns deduplicated findings after filters.
pub fn scan(opts: &ScanOptions) -> Result<ScanReport> {
    let t0 = Instant::now();
    if let Some(ms) = opts.min_severity.as_deref() {
        parse_min_severity(ms)?;
    }
    if opts.jobs > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(opts.jobs)
            .build_global()
            .ok();
    }
    let (rules, mut warnings) = load_rule_set_report(&opts.rules, &opts.config)?;
    let index = cg_rules::RuleIndex::build(&rules);

    // Suppression files: explicit list wins; otherwise auto-discover the
    // conventional file at the scan root (directories only). The legacy
    // `.codegrep-suppressions.*` names are still honored, checked after the
    // current ones, so repositories written before the rename keep working.
    let mut suppressions: Vec<Suppression> = Vec::new();
    if opts.suppress.is_empty() {
        let root = std::path::Path::new(&opts.path);
        if root.is_dir() {
            let candidates = [
                ".scanward-suppressions.yml",
                ".scanward-suppressions.yaml",
                ".codegrep-suppressions.yml",
                ".codegrep-suppressions.yaml",
            ];
            for name in candidates {
                let p = root.join(name);
                if p.is_file() {
                    suppressions = suppress::load_suppressions(&p.to_string_lossy())?;
                    break;
                }
            }
        }
    } else {
        for s in &opts.suppress {
            suppressions.extend(suppress::load_suppressions(s)?);
        }
    }
    let today = suppress::today_ymd();
    suppressions.retain(|s| {
        if s.is_expired(today) {
            warnings.push(format!(
                "suppression for rule {} expired {} — no longer applies",
                s.rule,
                s.expires.as_deref().unwrap_or("?")
            ));
            false
        } else {
            true
        }
    });

    let diff_map = if opts.diff_only {
        opts.baseline
            .as_deref()
            .map(diff_changed_lines)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let diff_active = opts.diff_only && opts.baseline.is_some();

    let rhash = rules_hash(&rules);
    let cache_dir: PathBuf = opts
        .cache_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_dir);
    let cache: CacheFile = if opts.no_cache {
        CacheFile::default()
    } else {
        load_cache(&cache_dir)
    };
    let cache_hits = std::sync::atomic::AtomicUsize::new(0);
    let inline_suppressed = std::sync::atomic::AtomicUsize::new(0);

    let files: Vec<PathBuf> = discover_files(&opts.path)
        .into_iter()
        .filter(|p| path_allowed(&p.to_string_lossy(), &opts.path, &opts.include, &opts.exclude))
        .collect();
    let scanned = files.len();

    // Per-file result carries (path, content_hash, findings, was_cached) for cache write-back.
    let per_file: Vec<(String, u64, Vec<Finding>, bool)> = files
        .par_iter()
        .filter_map(|path| {
            let path_s = path.to_string_lossy().to_string();
            // Unknown extension → generic: `generic`-language rules (secrets,
            // polyglot patterns) still apply instead of skipping the file.
            let lang = cg_parser::Language::from_path(&path_s)
                .unwrap_or(cg_parser::Language::Generic);
            if lang == cg_parser::Language::Generic {
                // Unrecognized extensions can be large data files; bound the
                // read so a stray .log/.csv cannot blow up the scan.
                if let Ok(m) = path.metadata() {
                    if m.len() > 10_000_000 {
                        return None;
                    }
                }
            }
            let text = std::fs::read_to_string(path).ok()?;
            let chash = hash_str(&text);
            if !opts.no_cache {
                if let Some(e) = cache.entries.get(&path_s) {
                    if e.content_hash == chash && e.rules_hash == rhash {
                        cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // diff-only still applies on cached findings
                        let mut out = e.findings.clone();
                        if diff_active {
                            out.retain(|f| {
                                diff_map.iter().any(|(df, set)| {
                                    (f.path.ends_with(df.as_str()) || df.ends_with(f.path.as_str()))
                                        && set.contains(&f.line)
                                })
                            });
                        }
                        let (out, n) = suppress::apply_inline(&text, out);
                        if n > 0 {
                            inline_suppressed.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                        }
                        return Some((path_s, chash, out, true));
                    }
                }
            }
            let lower = text.to_lowercase();
            let cands = index.candidates(&lower);
            if cands.is_empty() {
                // Cache negatives too: clean files skip matching on repeat scans.
                return Some((path_s, chash, vec![], false));
            }
            let mut local = vec![];
            for ci in cands {
                let rule = &rules[ci];
                if !rule.applies_to(lang.name()) {
                    continue;
                }
                // pattern-inside (coarse: file-level containment; block scoping roadmap).
                if let Some(inside) = &rule.pattern_inside {
                    let has_inside = cg_matcher::find_matches(inside, &text)
                        .map(|v| !v.is_empty())
                        .unwrap_or(false);
                    if !has_inside {
                        continue;
                    }
                }
                // Taint rules: scope-aware driver (function summaries + fixpoint)
                if let Some(t) = &rule.taint {
                    let srcs: Vec<String> =
                        t.sources.iter().flat_map(|s| s.patterns.clone()).collect();
                    let snks: Vec<String> =
                        t.sinks.iter().flat_map(|s| s.patterns.clone()).collect();
                    let sans: Vec<String> =
                        t.sanitizers.iter().flat_map(|s| s.patterns.clone()).collect();
                    let tr = cg_taint::TaintRule::compile(&srcs, &snks, &sans);
                    for ln in tr.scan_scoped(&text, lang.name()) {
                        let line_text: String =
                            text.lines().nth(ln - 1).unwrap_or("").chars().take(300).collect();
                        local.push((rule, ln, 0usize, line_text));
                    }
                    continue;
                }
                for pat in rule.positive_patterns() {
                    let ms = cg_matcher::find_matches(&pat, &text).ok()?;
                    // pattern-not: drop matches sharing a line with a neg hit
                    let neg_lines: HashSet<usize> = rule
                        .pattern_not
                        .as_ref()
                        .map(|np| {
                            cg_matcher::find_matches(np, &text)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|m| m.line)
                                .collect()
                        })
                        .unwrap_or_default();
                    for m in ms {
                        if neg_lines.contains(&m.line) {
                            continue;
                        }
                        if let Some(mvr) = &rule.metavariable_regex {
                            if !cg_matcher::check_metavariable_regex(&m, mvr) {
                                continue;
                            }
                        }
                        if let Some(mvc) = &rule.metavariable_comparison {
                            if !cg_matcher::check_metavariable_comparison(&m, mvc) {
                                continue;
                            }
                        }
                        local.push((rule, m.line, m.col, m.snippet.clone()));
                    }
                }
            }
            // diff-only filter + map to findings
            let mut out = vec![];
            for (rule, line, col, snippet) in local {
                if diff_active {
                    // diff map keys are repo-relative; path_s may be absolute or prefixed — try suffix match
                    let hit = diff_map.iter().any(|(f, set)| {
                        (path_s.ends_with(f.as_str()) || f.ends_with(path_s.as_str()))
                            && set.contains(&line)
                    });
                    if !hit {
                        continue;
                    }
                }
                out.push(Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    message: rule.message.clone(),
                    fix: rule.fix.clone(),
                    path: path_s.clone(),
                    language: lang.name().to_string(),
                    line,
                    col,
                    snippet,
                });
            }
            let (out, n) = suppress::apply_inline(&text, out);
            if n > 0 {
                inline_suppressed.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            }
            if out.is_empty() {
                Some((path_s, chash, vec![], false))
            } else {
                Some((path_s, chash, out, false))
            }
        })
        .collect();

    // Cache write-back (skip diff-only runs: cached full findings stay authoritative).
    if !opts.no_cache && !diff_active {
        let mut cache = cache;
        for (path_s, chash, findings, was_cached) in &per_file {
            if *was_cached {
                continue;
            }
            cache.entries.insert(
                path_s.clone(),
                CacheEntry {
                    content_hash: *chash,
                    rules_hash: rhash,
                    findings: findings.clone(),
                },
            );
        }
        // Bound cache size (LRU-ish: truncate arbitrarily at 20k entries).
        if cache.entries.len() > 20_000 {
            let keys: Vec<String> = cache
                .entries
                .keys()
                .take(cache.entries.len() - 20_000)
                .cloned()
                .collect();
            for k in keys {
                cache.entries.remove(&k);
            }
        }
        save_cache(&cache_dir, &cache);
    }

    let findings: Vec<Finding> = per_file.into_iter().flat_map(|(_, _, f, _)| f).collect();

    // Dedup by rule+path+line+snippet
    let mut seen = HashSet::new();
    let mut uniq = vec![];
    for f in findings {
        let k = format!("{}:{}:{}:{}", f.rule_id, f.path, f.line, f.snippet);
        if seen.insert(k) {
            uniq.push(f);
        }
    }
    uniq.sort_by_key(|a| (a.path.clone(), a.line));
    if let Some(ms) = opts.min_severity.as_deref() {
        let min = parse_min_severity(ms)?;
        uniq.retain(|f| severity_rank(&f.severity) >= min);
    }
    // Suppression files: every specified field must match (AND).
    let mut suppressed_files = 0usize;
    if !suppressions.is_empty() {
        uniq.retain(|f| {
            if suppressions.iter().any(|s| s.applies(f, &opts.path)) {
                suppressed_files += 1;
                false
            } else {
                true
            }
        });
    }

    Ok(ScanReport {
        findings: uniq,
        files_scanned: scanned,
        rules_loaded: rules.len(),
        elapsed_ms: t0.elapsed().as_millis(),
        cache_hits: cache_hits.load(std::sync::atomic::Ordering::Relaxed),
        cache_on: !opts.no_cache,
        warnings,
        suppressed: suppressed_files
            + inline_suppressed.load(std::sync::atomic::Ordering::Relaxed),
    })
}

/// Single-rule scan of in-memory text (used by `rule test` fixtures).
/// Mirrors [`scan`] matching incl. taint, pattern-not, metavar checks,
/// pattern-inside (coarse). Returns (line, col, snippet) hits.
pub fn findings_for_rule(
    rule: &cg_rules::Rule,
    text: &str,
    lang: &str,
) -> Vec<(usize, usize, String)> {
    let mut local: Vec<(usize, usize, String)> = vec![];
    if let Some(t) = &rule.taint {
        let srcs: Vec<String> = t.sources.iter().flat_map(|s| s.patterns.clone()).collect();
        let snks: Vec<String> = t.sinks.iter().flat_map(|s| s.patterns.clone()).collect();
        let sans: Vec<String> = t.sanitizers.iter().flat_map(|s| s.patterns.clone()).collect();
        let tr = cg_taint::TaintRule::compile(&srcs, &snks, &sans);
        for ln in tr.scan_scoped(text, lang) {
            let line_text: String = text.lines().nth(ln - 1).unwrap_or("").chars().take(300).collect();
            local.push((ln, 0, line_text));
        }
        return local;
    }
    if let Some(inside) = &rule.pattern_inside {
        let has = cg_matcher::find_matches(inside, text)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if !has {
            return local;
        }
    }
    for pat in rule.positive_patterns() {
        let ms = cg_matcher::find_matches(&pat, text).unwrap_or_default();
        let neg: HashSet<usize> = rule
            .pattern_not
            .as_ref()
            .map(|np| {
                cg_matcher::find_matches(np, text)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|m| m.line)
                    .collect()
            })
            .unwrap_or_default();
        for m in ms {
            if neg.contains(&m.line) {
                continue;
            }
            if let Some(mvr) = &rule.metavariable_regex {
                if !cg_matcher::check_metavariable_regex(&m, mvr) {
                    continue;
                }
            }
            if let Some(mvc) = &rule.metavariable_comparison {
                if !cg_matcher::check_metavariable_comparison(&m, mvc) {
                    continue;
                }
            }
            local.push((m.line, m.col, m.snippet.clone()));
        }
    }
    local
}

/// Severity ranking for `--min-severity`. Rules use ERROR | WARNING | INFO.
pub fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_uppercase().as_str() {
        "ERROR" | "HIGH" | "CRITICAL" => 3,
        "WARNING" | "WARN" | "MEDIUM" => 2,
        _ => 1, // INFO / NOTE / LOW
    }
}

/// Parse a severity floor; errors on unknown levels.
pub fn parse_min_severity(s: &str) -> Result<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "error" | "high" | "critical" => Ok(3),
        "warning" | "warn" | "medium" => Ok(2),
        "info" | "note" | "low" => Ok(1),
        other => anyhow::bail!(
            "scanward: unknown severity level {other:?} (expected error|warning|info)"
        ),
    }
}

/// Glob match with `*` (within a path segment), `**` (any incl. `/`),
/// `?` (one char, no `/`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, 0, &t, 0)
}

fn glob_rec(p: &[char], pi: usize, t: &[char], ti: usize) -> bool {
    let mut pi = pi;
    let mut ti = ti;
    while pi < p.len() {
        match p[pi] {
            '*' if pi + 1 < p.len() && p[pi + 1] == '*' => {
                // `**` consumes anything (incl. `/`). `**/` may also match zero dirs.
                let rest = pi + 2;
                if rest < p.len() && p[rest] == '/' && glob_rec(p, rest + 1, t, ti) {
                    return true;
                }
                if rest >= p.len() {
                    return true;
                }
                let mut k = ti;
                loop {
                    if glob_rec(p, rest, t, k) {
                        return true;
                    }
                    if k >= t.len() {
                        return false;
                    }
                    k += 1;
                }
            }
            '*' => {
                let rest = pi + 1;
                if rest >= p.len() {
                    // Trailing `*`: rest of this segment (never crosses `/`).
                    return !t[ti..].contains(&'/');
                }
                let mut k = ti;
                loop {
                    if glob_rec(p, rest, t, k) {
                        return true;
                    }
                    if k >= t.len() || t[k] == '/' {
                        return false;
                    }
                    k += 1;
                }
            }
            '?' => {
                if ti >= t.len() || t[ti] == '/' {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            c => {
                if ti >= t.len() || t[ti] != c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
    ti == t.len()
}

/// Candidate spellings a path filter is matched against (absolute + root-relative).
pub fn path_candidates<'a>(path_s: &'a str, root: &str) -> Vec<&'a str> {
    let mut v = vec![path_s];
    let rel = path_s
        .strip_prefix(root)
        .or_else(|| {
            if root == "." {
                path_s.strip_prefix("./")
            } else {
                None
            }
        })
        .map(|r| r.trim_start_matches('/'));
    if let Some(r) = rel {
        if r != path_s && !r.is_empty() {
            v.push(r);
        }
    }
    v
}

/// True when `pattern` (glob or substring) matches any candidate.
pub fn pattern_hits(pattern: &str, candidates: &[&str]) -> bool {
    let is_glob = pattern.contains('*') || pattern.contains('?');
    if !is_glob {
        return candidates.iter().any(|c| c.contains(pattern));
    }
    if candidates.iter().any(|c| glob_match(pattern, c)) {
        return true;
    }
    // Globs also match at any directory suffix: `vendor/**` hits `src/vendor/x`.
    candidates.iter().any(|c| {
        let mut s = *c;
        while let Some(idx) = s.find('/') {
            s = &s[idx + 1..];
            if glob_match(pattern, s) {
                return true;
            }
        }
        false
    })
}

/// Path filters: any `exclude` match drops; with `include` given, at
/// least one match is required to keep.
pub fn path_allowed(path_s: &str, root: &str, include: &[String], exclude: &[String]) -> bool {
    let cands = path_candidates(path_s, root);
    if exclude.iter().any(|p| pattern_hits(p, &cands)) {
        return false;
    }
    if !include.is_empty() && !include.iter().any(|p| pattern_hits(p, &cands)) {
        return false;
    }
    true
}

/// Changed lines per file from `git diff -U0 baseline...HEAD`.
/// Best-effort: empty map on failure means "report everything".
pub fn diff_changed_lines(baseline: &str) -> HashMap<String, HashSet<usize>> {
    let out = std::process::Command::new("git")
        .args(["diff", "-U0", &format!("{baseline}...HEAD"), "--"])
        .output();
    let mut map: HashMap<String, HashSet<usize>> = HashMap::new();
    let Ok(o) = out else { return map };
    if !o.status.success() {
        return map;
    }
    let text = String::from_utf8_lossy(&o.stdout);
    let mut cur = String::new();
    for line in text.lines() {
        if let Some(stripped) = line.strip_prefix("+++ b/") {
            cur = stripped.to_string();
        } else if line.starts_with("@@") {
            // @@ -a,b +c,d @@
            if let Some(plus) = line.split('+').nth(1) {
                let nums: Vec<&str> = plus.split([' ', ',', '@']).collect();
                if nums.len() >= 2 {
                    if let (Ok(start), Ok(count)) =
                        (nums[0].parse::<usize>(), nums[1].parse::<usize>())
                    {
                        let entry = map.entry(cur.clone()).or_default();
                        let count = count.max(1);
                        for l in start..start + count {
                            entry.insert(l);
                        }
                    }
                }
            }
        }
    }
    map
}

/// Discover scannable files under `root` (respects .gitignore, hidden
/// files included). Every text file is a candidate — language resolution
/// happens per-file at scan time, and unrecognized extensions are scanned
/// as the `generic` pseudolanguage so generic rules (secrets, polyglot
/// patterns) never silently miss a file.
pub fn discover_files(root: &str) -> Vec<PathBuf> {
    let mut b = ignore::WalkBuilder::new(root);
    b.hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true);
    b.build()
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .filter(|p| p.is_file())
        .collect()
}

// --- Persistent cache (content-hash, offline, no new deps) ---
use std::hash::{Hash, Hasher};

fn hash_str(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn rules_hash(rules: &[cg_rules::Rule]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for r in rules {
        r.id.hash(&mut h);
        for p in r.positive_patterns() {
            p.hash(&mut h);
        }
    }
    h.finish()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheFile {
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    content_hash: u64,
    rules_hash: u64,
    findings: Vec<Finding>,
}

fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("scanward")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("scanward")
    } else {
        PathBuf::from("/tmp/scanward-cache")
    }
}

fn load_cache(dir: &std::path::Path) -> CacheFile {
    let p = dir.join("cache.json");
    std::fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_cache(dir: &std::path::Path, cache: &CacheFile) {
    let _ = std::fs::create_dir_all(dir);
    if let Ok(t) = serde_json::to_string(cache) {
        let _ = std::fs::write(dir.join("cache.json"), t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_segment_rules() {
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(!glob_match("src/*.rs", "src/a/main.rs"));
        assert!(glob_match("vendor/**", "vendor/a/b.js"));
        assert!(glob_match("**/*.min.js", "src/app.min.js"));
        assert!(glob_match("a/**/b", "a/b"));
        assert!(glob_match("a/**/b", "a/x/y/b"));
        assert!(glob_match("*", "foo"));
        assert!(!glob_match("*", "foo/bar"));
        assert!(glob_match("run?.py", "run1.py"));
        assert!(!glob_match("run?.py", "run12.py"));
        assert!(glob_match("**/node_modules/**", "app/node_modules/x.js"));
    }

    #[test]
    fn path_filter_exclude_include() {
        let ex = vec!["vendor/**".to_string(), ".min.js".to_string()];
        assert!(!path_allowed("./src/vendor/x.js", ".", &[], &ex));
        assert!(!path_allowed("src/app.min.js", ".", &[], &ex));
        assert!(path_allowed("src/app.js", ".", &[], &ex));

        let ex_sub = vec!["tests".to_string()];
        assert!(!path_allowed("pkg/tests/fixture.py", ".", &[], &ex_sub));
        assert!(path_allowed("pkg/src/fixture.py", ".", &[], &ex_sub));

        let inc = vec!["src/**".to_string()];
        assert!(path_allowed("src/app.js", ".", &inc, &[]));
        assert!(!path_allowed("lib/app.js", ".", &inc, &[]));

        // root-relative candidates
        assert!(path_allowed(
            "testdata/py/vuln.py",
            "testdata",
            &["py/**".to_string()],
            &[]
        ));
        assert!(!path_allowed(
            "testdata/ruby/vuln.rb",
            "testdata",
            &[],
            &["ruby/**".to_string()]
        ));
    }

    #[test]
    fn severity_ordering() {
        assert!(severity_rank("ERROR") > severity_rank("WARNING"));
        assert!(severity_rank("WARNING") > severity_rank("INFO"));
        assert_eq!(parse_min_severity("error").unwrap(), 3);
        assert_eq!(parse_min_severity("info").unwrap(), 1);
        assert!(parse_min_severity("bogus").is_err());
    }

    #[test]
    fn sarif_has_rule_metadata() {
        let f = Finding {
            rule_id: "t-rule".into(),
            severity: "ERROR".into(),
            message: "m".into(),
            fix: None,
            path: "a.py".into(),
            language: "python".into(),
            line: 1,
            col: 0,
            snippet: "s".into(),
        };
        let doc = sarif_from(&[f]);
        let run = &doc["runs"][0];
        assert_eq!(run["results"][0]["ruleId"], "t-rule");
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "t-rule");
        assert_eq!(run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"], "error");
    }

    fn sample(path: &str, rule: &str, line: usize, snippet: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity: "ERROR".into(),
            message: format!("msg <x> & \"y\" for {rule}"),
            fix: Some("use safe(&v)".into()),
            path: path.into(),
            language: "python".into(),
            line,
            col: 0,
            snippet: snippet.into(),
        }
    }

    #[test]
    fn junit_groups_by_file_and_escapes_xml() {
        let xml = junit_from(&[
            sample("a.py", "r1", 1, "x < 2"),
            sample("a.py", "r2", 5, "y & z"),
            sample("b.js", "r1", 9, "console.log('hi')"),
        ]);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("tests=\"3\" failures=\"3\""));
        // two testsuites (a.py, b.js), three testcases
        assert_eq!(xml.matches("<testsuite ").count(), 2);
        assert_eq!(xml.matches("<testcase ").count(), 3);
        assert_eq!(xml.matches("<failure ").count(), 3);
        // raw XML metacharacters from findings must be escaped
        assert!(!xml.contains("x < 2"));
        assert!(xml.contains("x &lt; 2"));
        assert!(xml.contains("y &amp; z"));
        assert!(xml.contains("msg &lt;x&gt; &amp; &quot;y&quot;"));
        // severity lands in type=, message in message=
        assert!(xml.contains("type=\"ERROR\""));
        assert!(xml.contains("name=\"a.py:r1\"") || xml.contains("classname=\"a.py\""));
        assert!(xml.contains("fix: use safe(&amp;v)"));
        assert!(xml.ends_with("</testsuites>\n"));
    }

    #[test]
    fn junit_empty_scan_is_valid_placeholder() {
        let xml = junit_from(&[]);
        assert!(xml.contains("tests=\"1\" failures=\"0\""));
        assert_eq!(xml.matches("<testsuite ").count(), 1);
        assert_eq!(xml.matches("<testcase ").count(), 1);
        assert_eq!(xml.matches("<failure ").count(), 0);
        assert!(xml.contains("no findings"));
        assert!(xml.contains("</testsuites>"));
    }
}
