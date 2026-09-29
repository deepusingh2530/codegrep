//! codegrep CLI: `scan`, `rule test`, `autofix --verify`.
//! Deterministic + offline. Parallel with rayon. Respects .gitignore.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "codegrep", version, about = "Fast multi-language SAST scanner (MIT)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a path for findings
    Scan(Box<ScanArgs>),
    /// Rule utilities
    Rule {
        #[command(subcommand)]
        cmd: RuleCmd,
    },
    /// AI-assisted autofix (verified; optional, offline-safe stub)
    Autofix {
        /// Verify fix by re-running matcher
        #[arg(long, default_value_t = false)]
        verify: bool,
        #[arg(long, default_value = ".")]
        path: String,
    },
}

#[derive(Subcommand, Debug)]
enum RuleCmd {
    /// Validate rules + report count (`codegrep rule test rules/`)
    Test { path: String },
}

#[derive(Parser, Debug)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: String,
    /// Emit JSON findings to stdout (default human table otherwise)
    #[arg(long, default_value_t = false)]
    json: bool,
    /// Emit SARIF 2.1.0 to stdout
    #[arg(long, default_value_t = false)]
    sarif: bool,
    /// Write output to file instead of stdout
    #[arg(short, long)]
    output: Option<String>,
    /// Worker threads (0 = auto)
    #[arg(long, default_value_t = 0)]
    jobs: usize,
    /// Limit: sast|secrets|sca (wrappers for secrets/sca call external tools if present)
    #[arg(long, default_value = "sast")]
    only: String,
    /// Rules directory
    #[arg(long, default_value = "rules")]
    rules: String,
    /// Git baseline ref for diff-only
    #[arg(long)]
    baseline: Option<String>,
    /// Only report findings intersecting git diff lines
    #[arg(long, default_value_t = false)]
    diff_only: bool,
    /// Print scan metrics to stderr
    #[arg(long, default_value_t = false)]
    metrics: bool,
    /// Emit evidence.json lines for AI side-plane
    #[arg(long, default_value_t = false)]
    evidence: bool,
    /// Disable persistent content-hash cache (cache is on by default)
    #[arg(long, default_value_t = false)]
    no_cache: bool,
    /// Override cache directory (default ~/.cache/codegrep)
    #[arg(long)]
    cache_dir: Option<String>,
    /// Strict offline: no network, no external sidecars (secrets/sca wrappers refused)
    #[arg(long, default_value_t = false)]
    offline: bool,
    /// Rule file or directory (repeatable, semgrep-style; supersedes --rules)
    #[arg(long = "config", value_name = "PATH")]
    config: Vec<String>,
    /// Drop paths matching this glob or substring (repeatable): `vendor/**`, `tests`
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Only report paths matching this glob or substring (repeatable)
    #[arg(long = "include", value_name = "GLOB")]
    include: Vec<String>,
    /// Only report findings at or above this severity: error|warning|info
    #[arg(long, value_name = "LEVEL")]
    min_severity: Option<String>,
    /// Exit 1 when findings remain (CI gating, semgrep --error)
    #[arg(long, default_value_t = false)]
    error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    rule_id: String,
    severity: String,
    message: String,
    fix: Option<String>,
    path: String,
    language: String,
    line: usize,
    col: usize,
    snippet: String,
}

fn sarif_level(sev: &str) -> &'static str {
    match sev {
        "ERROR" => "error",
        "WARNING" => "warning",
        _ => "note",
    }
}

fn sarif_from(findings: &[Finding]) -> serde_json::Value {
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
    // driver.rules metadata: required by GitHub code scanning for rule display
    // and used by other SARIF consumers to map levels/tags.
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
            "name": "codegrep",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules
        }}, "results": results}]
    })
}

fn diff_changed_lines(baseline: &str) -> HashMap<String, HashSet<usize>> {
    // Best-effort `git diff -U0 baseline...HEAD -- <files>` parsing. Empty map on failure = report all.
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

/// Severity ranking for `--min-severity`. Rules use ERROR | WARNING | INFO.
fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_uppercase().as_str() {
        "ERROR" | "HIGH" | "CRITICAL" => 3,
        "WARNING" | "WARN" | "MEDIUM" => 2,
        _ => 1, // INFO / NOTE / LOW
    }
}

fn parse_min_severity(s: &str) -> Result<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "error" | "high" | "critical" => Ok(3),
        "warning" | "warn" | "medium" => Ok(2),
        "info" | "note" | "low" => Ok(1),
        other => anyhow::bail!(
            "codegrep: unknown --min-severity {other:?} (expected error|warning|info)"
        ),
    }
}

/// Glob match with `*` (within a path segment), `**` (any incl. `/`), `?` (one char, no `/`).
fn glob_match(pattern: &str, text: &str) -> bool {
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
fn path_candidates<'a>(path_s: &'a str, root: &str) -> Vec<&'a str> {
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

fn pattern_hits(pattern: &str, candidates: &[&str]) -> bool {
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

/// Semgrep-style path filters: any `--exclude` match drops; with `--include`
/// given, at least one match is required to keep.
fn path_allowed(path_s: &str, root: &str, include: &[String], exclude: &[String]) -> bool {
    let cands = path_candidates(path_s, root);
    if exclude.iter().any(|p| pattern_hits(p, &cands)) {
        return false;
    }
    if !include.is_empty() && !include.iter().any(|p| pattern_hits(p, &cands)) {
        return false;
    }
    true
}

fn discover_files(root: &str) -> Vec<PathBuf> {
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
        .filter(|p| cg_parser::Language::from_path(&p.to_string_lossy()).is_some())
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
        PathBuf::from(xdg).join("codegrep")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("codegrep")
    } else {
        PathBuf::from("/tmp/codegrep-cache")
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

/// License-safe sidecars: entirely separate processes (never linked).
/// gitleaks is MIT, osv-scanner is Apache-2.0. Best-effort: clear message when absent.
fn run_secrets(path: &str) -> Result<()> {
    // Exit code 1 from gitleaks means "leaks found", not failure: keep stdout.
    let attempt = std::process::Command::new("gitleaks")
        .args(["detect", "--source", path, "--no-git", "--format", "json"])
        .output();
    let out = match attempt {
        Err(e) => anyhow::bail!(
            "codegrep: `gitleaks` not found ({e}). Install gitleaks (MIT) for `--only secrets` or run `--only sast`."
        ),
        Ok(o) => o,
    };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let count = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    if text.trim().is_empty() {
        println!("codegrep secrets: no leaks reported ✅");
    } else {
        println!("{text}");
        eprintln!("codegrep secrets: {count} finding(s) via gitleaks");
    }
    Ok(())
}

fn run_sca(path: &str) -> Result<()> {
    // Newer osv-scanner uses `scan -r`; older takes bare flags. Try both.
    let tries: &[&[&str]] = &[
        &["scan", "--recursive", "--format", "json", path],
        &["--recursive", "--format", "json", path],
    ];
    let mut last_err = String::new();
    for args in tries {
        match std::process::Command::new("osv-scanner").args(*args).output() {
            Err(e) => {
                last_err = format!(
                    "codegrep: `osv-scanner` not found ({e}). Install osv-scanner (Apache-2.0) for `--only sca` or run `--only sast`."
                );
                break;
            }
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                if !text.trim().is_empty() && serde_json::from_str::<serde_json::Value>(&text).is_ok() {
                    println!("{text}");
                    return Ok(());
                }
                last_err = format!(
                    "codegrep: osv-scanner produced no JSON (stderr: {})",
                    String::from_utf8_lossy(&o.stderr).chars().take(300).collect::<String>()
                );
            }
        }
    }
    anyhow::bail!("{last_err}")
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let t0 = Instant::now();
    // Strict offline policy: SAST core is always offline; external sidecars are refused.
    if args.offline && args.only != "sast" && args.only != "all" {
        anyhow::bail!(
            "codegrep --offline: --only {} refused (secrets/sca wrappers shell out to gitleaks/osv-scanner which may fetch DBs). Use --only sast offline.",
            args.only
        );
    }
    if let Some(ms) = args.min_severity.as_deref() {
        parse_min_severity(ms)?;
    }
    if args.jobs > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.jobs)
            .build_global()
            .ok();
    }
    match args.only.as_str() {
        "sast" | "all" => {}
        "secrets" => return run_secrets(&args.path),
        "sca" => return run_sca(&args.path),
        other => anyhow::bail!("codegrep: unknown --only {other} (expected sast|secrets|sca|all)"),
    }
    let rules: Vec<cg_rules::Rule> = if !args.config.is_empty() {
        let mut out: Vec<cg_rules::Rule> = vec![];
        for c in &args.config {
            if c.starts_with("http://")
                || c.starts_with("https://")
                || c.starts_with("git@")
                || c.starts_with("p/")
                || c.ends_with(".git")
                || c == "auto"
            {
                anyhow::bail!(
                    "codegrep: remote/registry configs are not supported (--config {c}). \
                     codegrep is offline-first: point --config at a local rule file or directory."
                );
            }
            let p = std::path::Path::new(c);
            if p.is_file() {
                out.extend(cg_rules::load_rules_file(c).with_context(|| format!("loading {c}"))?);
            } else if p.is_dir() {
                out.extend(cg_rules::load_rules_dir(c).with_context(|| format!("loading {c}"))?);
            } else {
                anyhow::bail!("codegrep: --config {c}: no such file or directory");
            }
        }
        out
    } else if std::path::Path::new(&args.rules).exists() {
        cg_rules::load_rules_dir(&args.rules)
            .with_context(|| format!("loading rules from {}", args.rules))?
    } else {
        vec![]
    };
    if rules.is_empty() {
        eprintln!(
            "codegrep: no rules found in '{}' — scanning with 0 rules",
            args.rules
        );
    }
    let index = cg_rules::RuleIndex::build(&rules);

    let diff_map = if args.diff_only {
        args.baseline
            .as_deref()
            .map(diff_changed_lines)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let diff_active = args.diff_only && args.baseline.is_some();

    let rhash = rules_hash(&rules);
    let cache_dir: PathBuf = args
        .cache_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_dir);
    let cache: CacheFile = if args.no_cache {
        CacheFile::default()
    } else {
        load_cache(&cache_dir)
    };
    let cache_hits = std::sync::atomic::AtomicUsize::new(0);

    let files: Vec<PathBuf> = discover_files(&args.path)
        .into_iter()
        .filter(|p| path_allowed(&p.to_string_lossy(), &args.path, &args.include, &args.exclude))
        .collect();
    let scanned = files.len();

    // Per-file result carries (path, content_hash, findings, was_cached) for cache write-back.
    let per_file: Vec<(String, u64, Vec<Finding>, bool)> = files
        .par_iter()
        .filter_map(|path| {
            let path_s = path.to_string_lossy().to_string();
            let lang = cg_parser::Language::from_path(&path_s)?;
            let text = std::fs::read_to_string(path).ok()?;
            let chash = hash_str(&text);
            if !args.no_cache {
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
                // pattern-inside (coarse v0.2: file-level containment; block scoping roadmap).
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
                    let srcs: Vec<String> = t.sources.iter().flat_map(|s| s.patterns.clone()).collect();
                    let snks: Vec<String> = t.sinks.iter().flat_map(|s| s.patterns.clone()).collect();
                    let sans: Vec<String> = t.sanitizers.iter().flat_map(|s| s.patterns.clone()).collect();
                    let tr = cg_taint::TaintRule::compile(&srcs, &snks, &sans);
                    for ln in tr.scan_scoped(&text, lang.name()) {
                        let line_text: String = text.lines().nth(ln - 1).unwrap_or("").chars().take(300).collect();
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
                        (path_s.ends_with(f.as_str()) || f.ends_with(path_s.as_str())) && set.contains(&line)
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
            if out.is_empty() {
                Some((path_s, chash, vec![], false))
            } else {
                Some((path_s, chash, out, false))
            }
        })
        .collect();

    // Cache write-back (skip diff-only runs: cached full findings stay authoritative).
    if !args.no_cache && !diff_active {
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
            let keys: Vec<String> = cache.entries.keys().take(cache.entries.len() - 20_000).cloned().collect();
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
    if let Some(ms) = args.min_severity.as_deref() {
        let min = parse_min_severity(ms)?;
        uniq.retain(|f| severity_rank(&f.severity) >= min);
    }

    let elapsed = t0.elapsed();
    if args.metrics {
        eprintln!(
            "codegrep metrics: files={} rules={} findings={} elapsed_ms={} cache_hits={} cache={}",
            scanned,
            rules.len(),
            uniq.len(),
            elapsed.as_millis(),
            cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            if args.no_cache { "off" } else { "on" },
        );
    }

    // `--only all`: SAST above plus best-effort sidecars (warn, don't fail).
    if args.only == "all" && !args.offline {
        if let Err(e) = run_secrets(&args.path) {
            eprintln!("codegrep: secrets sidecar skipped: {e}");
        }
        if let Err(e) = run_sca(&args.path) {
            eprintln!("codegrep: sca sidecar skipped: {e}");
        }
    }

    let body = if args.sarif {
        serde_json::to_string_pretty(&sarif_from(&uniq))?
    } else if args.json || args.output.is_some() {
        serde_json::to_string_pretty(&uniq)?
    } else {
        if uniq.is_empty() {
            "codegrep: no findings ✅".to_string()
        } else {
            let mut s = format!("codegrep: {} finding(s)\n", uniq.len());
            for f in &uniq {
                s.push_str(&format!(
                    "{}:{} [{}] {} — {}\n",
                    f.path, f.line, f.severity, f.rule_id, f.snippet
                ));
            }
            s
        }
    };

    if args.evidence {
        for f in &uniq {
            eprintln!(
                "evidence: {}",
                serde_json::json!({"rule": f.rule_id, "path": f.path, "line": f.line, "snippet": f.snippet})
            );
        }
    }

    if let Some(o) = &args.output {
        std::fs::write(o, body).with_context(|| format!("writing {o}"))?;
        eprintln!("codegrep: wrote {} finding(s) to {o}", uniq.len());
    } else {
        println!("{body}");
    }
    if args.error && !uniq.is_empty() {
        if !args.json && !args.sarif && args.output.is_none() {
            eprintln!("codegrep: exiting 1 (--error, {} finding(s))", uniq.len());
        }
        std::process::exit(1);
    }
    Ok(())
}

/// Single-rule scan of in-memory text (used by `rule test` fixtures).
/// Mirrors run_scan matching incl. taint, pattern-not, metavar checks, pattern-inside (coarse).
fn findings_for_rule(rule: &cg_rules::Rule, text: &str, lang: &str) -> Vec<(usize, usize, String)> {
    let mut local: Vec<(usize, usize, String)> = vec![];
    if let Some(t) = &rule.taint {
        let srcs: Vec<String> = t.sources.iter().flat_map(|s| s.patterns.clone()).collect();
        let snks: Vec<String> = t.sinks.iter().flat_map(|s| s.patterns.clone()).collect();
        let sans: Vec<String> = t.sanitizers.iter().flat_map(|s| s.patterns.clone()).collect();
        let tr = cg_taint::TaintRule::compile(&srcs, &snks, &sans);
        for ln in tr.scan_scoped(text, lang) {
            let line_text: String =
                text.lines().nth(ln - 1).unwrap_or("").chars().take(300).collect();
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Scan(a) => run_scan(*a),
        Commands::Rule { cmd } => match cmd {
            RuleCmd::Test { path } => {
                let rules = cg_rules::load_rules_dir(&path)
                    .with_context(|| format!("loading rules from {path}"))?;
                println!("codegrep: {} rule(s) valid in {}", rules.len(), path);
                for r in &rules {
                    println!("  ✓ {} [{}] langs={:?}", r.id, r.severity, r.languages);
                }
                // Accuracy fixtures: rules/tests/<rule-id>/{fail*,pass*}.
                let fixture_root = std::path::Path::new(&path).join("tests");
                if fixture_root.is_dir() {
                    let by_id: HashMap<&str, &cg_rules::Rule> =
                        rules.iter().map(|r| (r.id.as_str(), r)).collect();
                    let mut tested = 0usize;
                    let mut failed = 0usize;
                    let mut entries: Vec<_> = std::fs::read_dir(&fixture_root)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .collect();
                    entries.sort_by_key(|e| e.file_name());
                    for dir in entries {
                        let id = dir.file_name().to_string_lossy().to_string();
                        let Some(rule) = by_id.get(id.as_str()) else {
                            println!("  ! fixtures/{id}: no such rule id (skipped)");
                            continue;
                        };
                        let mut files: Vec<_> = std::fs::read_dir(dir.path())
                            .unwrap()
                            .filter_map(|e| e.ok())
                            .filter(|e| e.path().is_file())
                            .collect();
                        files.sort_by_key(|e| e.file_name());
                        for f in files {
                            let name =
                                f.file_name().to_string_lossy().to_string();
                            let text = std::fs::read_to_string(f.path())
                                .unwrap_or_default();
                            let hits = findings_for_rule(rule, &text, "generic");
                            tested += 1;
                            if name.starts_with("fail") {
                                if hits.is_empty() {
                                    failed += 1;
                                    println!("  ✗ {id}/{name}: expected ≥1 finding, got 0");
                                } else {
                                    println!(
                                        "  ✓ {id}/{name}: fail-fixture triggers ({} hit(s))",
                                        hits.len()
                                    );
                                }
                            } else if name.starts_with("pass") {
                                if hits.is_empty() {
                                    println!("  ✓ {id}/{name}: pass-fixture clean");
                                } else {
                                    failed += 1;
                                    println!(
                                        "  ✗ {id}/{name}: expected 0 findings, got {}",
                                        hits.len()
                                    );
                                }
                            }
                        }
                    }
                    println!(
                        "codegrep: fixtures: {tested} checked, {} failed",
                        failed
                    );
                    if failed > 0 {
                        anyhow::bail!("rule test: {failed} fixture(s) failed");
                    }
                    if tested == 0 {
                        println!("codegrep: no fixtures found under rules/tests/ (add fail*/pass* files)");
                    }
                } else {
                    println!("codegrep: no fixtures dir at rules/tests/ (skipped)");
                }
                Ok(())
            }
        },
        Commands::Autofix { verify, path } => {
            println!(
                "codegrep autofix: path={path} verify={verify}\n\
                 AI autofix is an async side-plane (see ai-triage/, BYOK). \
                 No patch is shown unless re-scan verification passes. \
                 Offline scan results are unaffected."
            );
            Ok(())
        }
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
}
