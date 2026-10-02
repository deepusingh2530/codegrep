//! End-to-end FP management: suppression files (explicit + auto-discovered),
//! inline `scanward-ignore` comments, expiry warnings, and strict validation.

use scanward::{scan, ScanOptions};

const PY: &str = r#"import subprocess, os, pickle
user = "x"
os.system("ls " + user)
subprocess.run(user, shell=True)
eval(user)
pickle.loads(user)
"#;

fn scan_dir(dir: &std::path::Path, suppress: Vec<String>) -> scanward::ScanReport {
    scan(&ScanOptions {
        path: dir.to_str().unwrap().into(),
        rules: "../../rules".into(),
        no_cache: true,
        suppress,
        ..Default::default()
    })
    .expect("scan")
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cg-fp-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn explicit_suppression_file_filters_findings() {
    let dir = temp_dir("explicit");
    std::fs::write(dir.join("app.py"), PY).unwrap();
    let sup = dir.join("suppressions.yml");
    std::fs::write(
        &sup,
        "- rule: py-eval-exec\n  path: \"app.py\"\n  reason: sandboxed eval in test harness\n  expires: 2030-01-01\n",
    )
    .unwrap();

    let base = scan_dir(&dir, vec![]);
    assert_eq!(base.findings.len(), 5, "baseline");

    let report = scan_dir(&dir, vec![sup.to_str().unwrap().into()]);
    assert_eq!(report.findings.len(), 4, "one finding suppressed");
    assert_eq!(report.suppressed, 1);
    assert!(
        !report.findings.iter().any(|f| f.rule_id == "py-eval-exec"),
        "py-eval-exec must be gone"
    );
    assert!(report.warnings.is_empty(), "warnings: {:?}", report.warnings);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn auto_discovery_at_scan_root() {
    let dir = temp_dir("auto");
    std::fs::write(dir.join("app.py"), PY).unwrap();
    std::fs::write(
        dir.join(".scanward-suppressions.yml"),
        "- rule: \"py-*\"\n  reason: bulk-triaged as test code\n",
    )
    .unwrap();

    let report = scan_dir(&dir, vec![]);
    assert_eq!(report.suppressed, 5, "all five findings match py-*");
    assert!(
        report.findings.iter().all(|f| !f.rule_id.starts_with("py-")),
        "no py-* finding may survive: {:?}",
        report.findings
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn expired_suppression_warns_and_stops_applying() {
    let dir = temp_dir("expired");
    std::fs::write(dir.join("app.py"), PY).unwrap();
    let sup = dir.join("suppressions.yml");
    std::fs::write(
        &sup,
        "- rule: py-eval-exec\n  reason: was triaged long ago\n  expires: 2020-01-01\n",
    )
    .unwrap();

    let report = scan_dir(&dir, vec![sup.to_str().unwrap().into()]);
    assert_eq!(report.findings.len(), 5, "expired suppression must not apply");
    assert_eq!(report.suppressed, 0);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("expired") && w.contains("py-eval-exec")),
        "expiry warning expected: {:?}",
        report.warnings
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inline_ignore_comments_suppress() {
    let dir = temp_dir("inline");
    // line 3: rule-scoped same-line; line 4: bare same-line (2 findings);
    // line 5: next-line marker on line 4 would NOT apply (same-line token wins
    // for line 4 only) — put next-line on its own target instead.
    std::fs::write(
        dir.join("app.py"),
        "import subprocess, os, pickle\n\
         user = \"x\"\n\
         os.system(\"ls \" + user)  # scanward-ignore(py-command-injection)\n\
         subprocess.run(user, shell=True)  # scanward-ignore\n\
         eval(user)  # innocuous\n\
         pickle.loads(user)\n",
    )
    .unwrap();

    let report = scan_dir(&dir, vec![]);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !ids.contains(&"py-command-injection"),
        "scoped inline ignore must fire: {ids:?}"
    );
    assert!(
        !ids.contains(&"py-subprocess-input-shell") && !ids.contains(&"py-subprocess-shell"),
        "bare inline ignore drops both line-4 findings: {ids:?}"
    );
    assert!(ids.contains(&"py-eval-exec"), "untagged line stays: {ids:?}");
    assert!(ids.contains(&"py-deserialization"), "untagged line stays: {ids:?}");
    assert_eq!(report.suppressed, 3, "1 scoped + 2 bare");
    assert_eq!(report.findings.len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn next_line_ignore_and_validation() {
    let dir = temp_dir("nextline");
    std::fs::write(
        dir.join("app.py"),
        "import os\n\
         user = \"x\"\n\
         # scanward-ignore-next-line\n\
         os.system(\"ls \" + user)\n",
    )
    .unwrap();
    let report = scan_dir(&dir, vec![]);
    assert!(
        !report.findings.iter().any(|f| f.rule_id == "py-command-injection"),
        "next-line marker must suppress: {:?}",
        report.findings
    );
    assert_eq!(report.suppressed, 1);

    // Unknown keys (typos like `exires:`) fail loudly instead of silently
    // keeping a suppression inactive.
    let sup = dir.join("bad.yml");
    std::fs::write(&sup, "- rule: x\n  reason: ok\n  exires: 2030-01-01\n").unwrap();
    let err = scan_dir_err(&dir, vec![sup.to_str().unwrap().into()]);
    assert!(err.contains("exires"), "typo must be rejected: {err}");

    // Missing reason is rejected too.
    let sup2 = dir.join("noreason.yml");
    std::fs::write(&sup2, "- rule: x\n  path: a\n").unwrap();
    let err = scan_dir_err(&dir, vec![sup2.to_str().unwrap().into()]);
    assert!(err.contains("reason"), "reason required: {err}");

    std::fs::remove_dir_all(&dir).ok();
}

fn scan_dir_err(dir: &std::path::Path, suppress: Vec<String>) -> String {
    let err = scan(&ScanOptions {
        path: dir.to_str().unwrap().into(),
        rules: "../../rules".into(),
        no_cache: true,
        suppress,
        ..Default::default()
    })
    .unwrap_err();
    format!("{err:#}") // full anyhow chain: context + serde source
}
