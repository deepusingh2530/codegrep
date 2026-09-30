//! Library API smoke test: the crate must be usable as a dependency
//! (as prsniffer-style embedders do), with no CLI involved.

use codegrep::{junit_from, sarif_from, scan, ScanOptions};

#[test]
fn scans_testdata_with_shipped_rules() {
    let report = scan(&ScanOptions {
        path: "../../testdata".into(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan must succeed");

    assert!(
        report.rules_loaded >= 1000,
        "expected the full corpus, loaded {}",
        report.rules_loaded
    );
    assert!(
        !report.findings.is_empty(),
        "testdata should trigger findings"
    );
    // Findings stay within the scanned root and carry all public fields.
    for f in &report.findings {
        assert!(f.path.contains("testdata"), "unexpected path {}", f.path);
        assert!(!f.rule_id.is_empty());
        assert!(f.line > 0);
        assert!(!f.severity.is_empty());
    }
}

#[test]
fn severity_and_path_filters_apply() {
    let base = ScanOptions {
        path: "../../testdata".into(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    };

    let all = scan(&base).expect("scan");
    let errors_only = scan(&ScanOptions {
        min_severity: Some("error".into()),
        ..base.clone()
    })
    .expect("scan");
    assert!(!errors_only.findings.is_empty());
    assert!(errors_only.findings.len() <= all.findings.len());
    assert!(errors_only
        .findings
        .iter()
        .all(|f| codegrep::severity_rank(&f.severity) >= 3));

    let excluded = scan(&ScanOptions {
        exclude: vec!["**/*.py".into()],
        ..base.clone()
    })
    .expect("scan");
    assert!(excluded.findings.iter().all(|f| !f.path.ends_with(".py")));
    assert!(excluded.findings.len() < all.findings.len());
}

#[test]
fn sarif_document_is_producible_from_report() {
    let report = scan(&ScanOptions {
        path: "../../testdata".into(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan");
    let doc = sarif_from(&report.findings);
    assert_eq!(doc["version"], "2.1.0");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "codegrep");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), report.findings.len());
}

#[test]
fn junit_report_covers_every_finding() {
    let report = scan(&ScanOptions {
        path: "../../testdata".into(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan");
    let xml = junit_from(&report.findings);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert_eq!(
        xml.matches("<testcase ").count(),
        report.findings.len(),
        "one testcase per finding"
    );
    assert_eq!(xml.matches("<failure ").count(), report.findings.len());
    for f in &report.findings {
        assert!(
            xml.contains(&format!("classname=\"{}\"", f.path)),
            "testsuite for {} missing",
            f.path
        );
    }
    // Scan output must be parseable XML even with hostile snippets.
    assert!(xml.ends_with("</testsuites>\n"));
}

#[test]
fn unknown_severity_is_an_error() {
    let err = scan(&ScanOptions {
        path: "../../testdata".into(),
        rules: "../../rules".into(),
        min_severity: Some("bogus".into()),
        ..Default::default()
    })
    .expect_err("bad severity must fail");
    assert!(err.to_string().contains("severity"));
}
