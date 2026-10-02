//! End-to-end: files with unrecognized extensions are scanned as the
//! `generic` pseudolanguage instead of being silently skipped, and
//! `generic` rules apply to recognized files too.

use scanward::{scan, ScanOptions};

#[test]
fn unknown_extension_scanned_as_generic() {
    let dir = std::env::temp_dir().join(format!("cg-generic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("notes.xyz"), "password=\"hunter2xyz\"\n").unwrap();
    std::fs::write(dir.join("main.rs"), "const P: &str = password=\"hunter2rust\";\n").unwrap();

    let report = scan(&ScanOptions {
        path: dir.to_str().unwrap().to_string(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan must succeed");

    assert_eq!(report.files_scanned, 2, "both files discovered");

    let unknown = report
        .findings
        .iter()
        .find(|f| f.path.ends_with("notes.xyz"))
        .expect("unknown extension must still be scanned");
    assert_eq!(unknown.language, "generic");
    assert_eq!(unknown.rule_id, "secret-password-assign");

    // Generic rules also apply to recognized languages (here: new rust).
    let rust = report
        .findings
        .iter()
        .find(|f| f.path.ends_with("main.rs"))
        .expect("recognized file must be scanned");
    assert_eq!(rust.language, "rust");
    assert_eq!(rust.rule_id, "secret-password-assign");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn oversized_generic_files_are_skipped() {
    let dir = std::env::temp_dir().join(format!("cg-generic-big-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // >10MB unknown-extension file must not be read (bound memory).
    let big = "password=\"x\"\n".repeat(800_000); // ~12MB
    std::fs::write(dir.join("huge.log"), big).unwrap();

    let report = scan(&ScanOptions {
        path: dir.to_str().unwrap().to_string(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan must succeed");

    assert_eq!(report.files_scanned, 1, "file considered but capped");
    assert!(
        report.findings.is_empty(),
        "oversized generic file skipped: {:?}",
        report.findings
    );

    std::fs::remove_dir_all(&dir).ok();
}
