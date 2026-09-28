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
    Scan(ScanArgs),
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

fn sarif_from(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": match f.severity.as_str() { "ERROR" => "error", "WARNING" => "warning", _ => "note" },
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line, "startColumn": f.col + 1}
                }}]
            })
        })
        .collect();
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "codegrep", "version": env!("CARGO_PKG_VERSION")}}, "results": results}]
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
    let rules: Vec<cg_rules::Rule> = if std::path::Path::new(&args.rules).exists() {
        cg_rules::load_rules_dir(&args.rules)
            .with_context(|| format!("loading rules from {}", args.rules))?
    } else {
        vec![]
    };
    if rules.is_empty() {
        eprintln!("codegrep: no rules found in '{}' — scanning with 0 rules", args.rules);
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

    let files = discover_files(&args.path);
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

    if let Some(o) = args.output {
        std::fs::write(&o, body).with_context(|| format!("writing {o}"))?;
        eprintln!("codegrep: wrote {} finding(s) to {o}", uniq.len());
    } else {
        println!("{body}");
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
        Commands::Scan(a) => run_scan(a),
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
