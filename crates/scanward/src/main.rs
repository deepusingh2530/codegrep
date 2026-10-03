//! scanward CLI: `scan`, `rule test`, `autofix --verify`.
//! Deterministic + offline. Parallel with rayon. Respects .gitignore.
//! Library API (scan, sarif, filters) lives in `src/lib.rs`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use scanward::{findings_for_rule, parse_min_severity, sarif_from, ScanOptions};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "scanward", version, about = "Fast multi-language SAST scanner (noncommercial license)")]
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
    /// Validate rules + report count (`scanward rule test rules/`)
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
    /// Emit JUnit XML to stdout (CI test-report ingestion)
    #[arg(long, default_value_t = false)]
    junit: bool,
    /// Write output to file instead of stdout
    #[arg(short, long)]
    output: Option<String>,
    /// Worker threads (0 = auto)
    #[arg(long, default_value_t = 0)]
    jobs: usize,
    /// Limit: sast|secrets|sca|platform (the sidecars call external tools if present)
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
    /// Override cache directory (default ~/.cache/scanward)
    #[arg(long)]
    cache_dir: Option<String>,
    /// Strict offline: no network, no external sidecars (secrets/sca wrappers refused)
    #[arg(long, default_value_t = false)]
    offline: bool,
    /// Rule file or directory (repeatable; supersedes --rules)
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
    /// Suppression file (repeatable; replaces auto-discovered
    /// .scanward-suppressions.yml at the scan root)
    #[arg(long = "suppress", value_name = "FILE")]
    suppress: Vec<String>,
    /// Exit 1 when findings remain (CI gating)
    #[arg(long, default_value_t = false)]
    error: bool,
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
            "scanward: `gitleaks` not found ({e}). Install gitleaks (MIT) for `--only secrets` or run `--only sast`."
        ),
        Ok(o) => o,
    };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let count = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    if text.trim().is_empty() {
        println!("scanward secrets: no leaks reported ✅");
    } else {
        println!("{text}");
        eprintln!("scanward secrets: {count} finding(s) via gitleaks");
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
                    "scanward: `osv-scanner` not found ({e}). Install osv-scanner (Apache-2.0) for `--only sca` or run `--only sast`."
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
                    "scanward: osv-scanner produced no JSON (stderr: {})",
                    String::from_utf8_lossy(&o.stderr).chars().take(300).collect::<String>()
                );
            }
        }
    }
    anyhow::bail!("{last_err}")
}

fn run_platform(path: &str) -> Result<()> {
    // Hosted security platform as an opt-in sidecar: separate process, never
    // linked, credentials come from the environment. Refused under --offline.
    let token = std::env::var("AIKIDO_API_KEY")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "scanward: AIKIDO_API_KEY is not set. The platform sidecar needs a key; \
                 unset it and use `--only sast` (no account, no network) instead."
            )
        })?;
    let endpoint = std::env::var("AIKIDO_ENDPOINT")
        .unwrap_or_else(|_| "https://app.aikido.dev".to_string());

    let payload = serde_json::json!({
        "repository": { "path": path },
        "checks": ["sast", "secrets", "dependency_vulnerability", "iac_misconfiguration"],
    });
    let url = format!("{}/api/v1/scans", endpoint.trim_end_matches('/'));

    // Minimal HTTPS POST. Kept dependency-free: SAST offline policy means no
    // HTTP client crate in the binary, and this path is opt-in only.
    let out = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            "120",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            &url,
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(payload.to_string().as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| anyhow::anyhow!("scanward: `curl` not found or failed ({e}). Install curl, or use `--only sca` (osv-scanner, Apache-2.0)."))?;

    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| body.chars().take(300).collect());
        anyhow::bail!("scanward: platform sidecar failed ({}): {detail}", out.status)
    }
    println!("{body}");
    eprintln!(
        "scanward platform: results submitted for {path} — poll the dashboard for triage (results are not merged into --json/--sarif output)"
    );
    Ok(())
}

fn run_scan(args: ScanArgs) -> Result<()> {
    // Strict offline policy: SAST core is always offline; external sidecars are refused.
    if args.offline && args.only != "sast" && args.only != "all" {
        anyhow::bail!(
            "scanward --offline: --only {} refused (sidecars shell out to gitleaks/osv-scanner/the platform API, which need network). Use --only sast offline.",
            args.only
        );
    }
    if let Some(ms) = args.min_severity.as_deref() {
        parse_min_severity(ms)?;
    }
    match args.only.as_str() {
        "sast" | "all" => {}
        "secrets" => return run_secrets(&args.path),
        "sca" => return run_sca(&args.path),
        "platform" => return run_platform(&args.path),
        other => anyhow::bail!(
            "scanward: unknown --only {other} (expected sast|secrets|sca|platform|all)"
        ),
    }

    let scan_path = args.path.clone();
    let report = scanward::scan(&ScanOptions {
        path: args.path.clone(),
        rules: args.rules.clone(),
        config: args.config.clone(),
        include: args.include.clone(),
        exclude: args.exclude.clone(),
        min_severity: args.min_severity.clone(),
        baseline: args.baseline.clone(),
        diff_only: args.diff_only,
        no_cache: args.no_cache,
        cache_dir: args.cache_dir.clone(),
        jobs: args.jobs,
        suppress: args.suppress.clone(),
    })?;
    if report.rules_loaded == 0 {
        eprintln!(
            "scanward: no rules found in '{}' — scanning with 0 rules",
            args.rules
        );
    }
    for w in &report.warnings {
        eprintln!("scanward: {w}");
    }
    if report.suppressed > 0 {
        eprintln!(
            "scanward: {} finding(s) suppressed (see --suppress / inline scanward-ignore)",
            report.suppressed
        );
    }
    let uniq = &report.findings;

    if args.metrics {
        eprintln!(
            "scanward metrics: files={} rules={} findings={} suppressed={} elapsed_ms={} cache_hits={} cache={}",
            report.files_scanned,
            report.rules_loaded,
            uniq.len(),
            report.suppressed,
            report.elapsed_ms,
            report.cache_hits,
            if args.no_cache { "off" } else { "on" },
        );
    }

    // `--only all`: SAST above plus best-effort sidecars (warn, don't fail).
    if args.only == "all" && !args.offline {
        if let Err(e) = run_secrets(&scan_path) {
            eprintln!("scanward: secrets sidecar skipped: {e}");
        }
        if let Err(e) = run_sca(&scan_path) {
            eprintln!("scanward: sca sidecar skipped: {e}");
        }
    }

    let body = if args.sarif {
        serde_json::to_string_pretty(&sarif_from(uniq))?
    } else if args.junit {
        scanward::junit_from(uniq)
    } else if args.json || args.output.is_some() {
        serde_json::to_string_pretty(uniq)?
    } else {
        if uniq.is_empty() {
            "scanward: no findings ✅".to_string()
        } else {
            let mut s = format!("scanward: {} finding(s)\n", uniq.len());
            for f in uniq {
                s.push_str(&format!(
                    "{}:{} [{}] {} — {}\n",
                    f.path, f.line, f.severity, f.rule_id, f.snippet
                ));
            }
            s
        }
    };

    if args.evidence {
        for f in uniq {
            eprintln!(
                "evidence: {}",
                serde_json::json!({"rule": f.rule_id, "path": f.path, "line": f.line, "snippet": f.snippet})
            );
        }
    }

    if let Some(o) = &args.output {
        std::fs::write(o, body).with_context(|| format!("writing {o}"))?;
        eprintln!("scanward: wrote {} finding(s) to {o}", uniq.len());
    } else {
        println!("{body}");
    }
    if args.error && !uniq.is_empty() {
        if !args.json && !args.sarif && !args.junit && args.output.is_none() {
            eprintln!("scanward: exiting 1 (--error, {} finding(s))", uniq.len());
        }
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Scan(a) => run_scan(*a),
        Commands::Rule { cmd } => match cmd {
            RuleCmd::Test { path } => {
                let (rules, warnings) = cg_rules::load_rules_dir_report(&path)
                    .with_context(|| format!("loading rules from {path}"))?;
                for w in &warnings {
                    eprintln!("scanward: {w}");
                }
                println!("scanward: {} rule(s) valid in {}", rules.len(), path);
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
                        "scanward: fixtures: {tested} checked, {} failed",
                        failed
                    );
                    if failed > 0 {
                        anyhow::bail!("rule test: {failed} fixture(s) failed");
                    }
                    if tested == 0 {
                        println!("scanward: no fixtures found under rules/tests/ (add fail*/pass* files)");
                    }
                } else {
                    println!("scanward: no fixtures dir at rules/tests/ (skipped)");
                }
                Ok(())
            }
        },
        Commands::Autofix { verify, path } => {
            println!(
                "scanward autofix: path={path} verify={verify}\n\
                 AI autofix is an async side-plane (see ai-triage/, BYOK). \
                 No patch is shown unless re-scan verification passes. \
                 Offline scan results are unaffected."
            );
            Ok(())
        }
    }
}
