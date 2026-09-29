//! Minimal embedding example: scan a path and print SARIF to stdout.
//!
//! ```sh
//! cargo run -p codegrep --example scan -- ./testdata ./rules
//! ```
use codegrep::{scan, ScanOptions};

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let rules = std::env::args().nth(2).unwrap_or_else(|| "rules".into());
    let report = scan(&ScanOptions {
        path,
        rules,
        no_cache: true,
        ..Default::default()
    })?;
    eprintln!(
        "codegrep: files={} rules={} findings={} in {}ms",
        report.files_scanned,
        report.rules_loaded,
        report.findings.len(),
        report.elapsed_ms
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&codegrep::sarif_from(&report.findings))?
    );
    Ok(())
}
