//! End-to-end: user-supplied portable-schema rule files load, translate,
//! and fire against a target through the public `scan()` API.

use scanward::{load_rule_set_report, scan, ScanOptions};

const PORTABLE_RULE: &str = r#"
id: portable-import-example
mode: taint
languages: [python]
severity: ERROR
message: untrusted input reaches execution sink
pattern-sources:
  - pattern: request.args.get($KEY)
pattern-sinks:
  - pattern: subprocess.run($CMD, ...)
"#;

#[test]
fn portable_rule_translates_and_fires() {
    let dir = std::env::temp_dir().join(format!("cg-portable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rule_path = dir.join("imported.yaml");
    std::fs::write(&rule_path, PORTABLE_RULE).unwrap();
    let target = dir.join("app.py");
    std::fs::write(
        &target,
        "import subprocess\ncmd = request.args.get('q')\nsubprocess.run(cmd, shell=True)\n",
    )
    .unwrap();

    let rules_dir = dir.to_str().unwrap();
    let (rules, warnings) = load_rule_set_report(rules_dir, &[]).expect("load portable rules");
    assert_eq!(rules.len(), 1, "translated rule loaded; warnings={warnings:?}");
    assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    assert_eq!(rules[0].taint.as_ref().unwrap().sources[0].patterns.len(), 1);

    let report = scan(&ScanOptions {
        path: rules_dir.to_string(),
        rules: rules_dir.to_string(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan");
    assert!(report.warnings.is_empty(), "warnings: {:?}", report.warnings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "portable-import-example"),
        "portable taint rule must fire: {:?}",
        report.findings
    );

    std::fs::remove_dir_all(&dir).ok();
}

const UNSUPPORTED_RULE: &str = r#"
id: portable-unsupported-example
languages: [python]
severity: ERROR
message: m
patterns:
  - pattern: os.system($CMD)
  - pattern-not-inside: "with safe_mode: ..."
"#;

const OK_RULE: &str = r#"
id: portable-ok-example
languages: [python]
severity: WARNING
message: m
pattern: pickle.loads($X)
"#;

#[test]
fn unsupported_portable_rule_skips_with_warning_but_others_load() {
    let dir = std::env::temp_dir().join(format!("cg-portable-skip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("unsupported.yaml"), UNSUPPORTED_RULE).unwrap();
    std::fs::write(dir.join("ok.yaml"), OK_RULE).unwrap();

    let rules_dir = dir.to_str().unwrap();
    let (rules, warnings) = load_rule_set_report(rules_dir, &[]).expect("load");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "portable-ok-example");
    assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    assert!(
        warnings[0].contains("portable-unsupported-example")
            && warnings[0].contains("pattern-not-inside"),
        "skip reason must name rule + construct: {warnings:?}"
    );

    // scan() surfaces the same warning.
    let report = scan(&ScanOptions {
        path: rules_dir.to_string(),
        rules: rules_dir.to_string(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan");
    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.rules_loaded, 1);

    std::fs::remove_dir_all(&dir).ok();
}
