//! Regression tests for the literal prefilter.
//!
//! `RuleIndex` maps rule -> extracted literals so the scanner can skip rules
//! that cannot match a file. A rule whose patterns yield no indexable literal
//! used to be dropped from *every* scan: it loaded, validated, and passed its
//! own fixtures (the fixture harness calls `findings_for_rule` directly and
//! never touches the index), so nothing noticed it could never fire.
//!
//! Ten shipped hardcoded-secret rules were in exactly that state — including
//! `js-hardcoded-sendgrid-key`, whose patterns are all `$VAR = "SG.$REST"`.
//! These tests guard both the engine fix and that real rule.

use std::fs;
use std::path::{Path, PathBuf};

use scanward::{scan, ScanOptions};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scanward-prefilter-{}-{}",
        tag,
        std::process::id()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

fn scan_dir(dir: &Path, rules: &str) -> Vec<String> {
    let report = scan(&ScanOptions {
        path: dir.to_string_lossy().to_string(),
        rules: rules.to_string(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan must succeed");
    report.findings.into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn shipped_secret_rule_fires_in_a_real_scan() {
    let dir = tmpdir("secret");
    fs::write(
        dir.join("mailer.js"),
        "const key = \"SG.abc123def456ghi789jkl0.abc-defghi1234567890abc1234567890abc-defghi\";\n",
    )
    .unwrap();

    let ids = scan_dir(&dir, "../../rules");
    assert!(
        ids.iter().any(|r| r == "js-hardcoded-sendgrid-key"),
        "js-hardcoded-sendgrid-key must fire in a real scan; got {ids:?}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn rule_without_extractable_literal_still_matches() {
    // `pattern: $A` and `pattern: ...` extract no literal at all. They must be
    // offered to the matcher for every file rather than silently skipped.
    let dir = tmpdir("nolit");
    let rules = dir.join("rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("only-metavar.yaml"),
        "id: t-only-metavar\nlanguages: [python]\nseverity: ERROR\nmessage: m\npattern: $A\n",
    )
    .unwrap();
    fs::write(
        rules.join("only-ellipsis.yaml"),
        "id: t-only-ellipsis\nlanguages: [python]\nseverity: ERROR\nmessage: m\npattern: ...\n",
    )
    .unwrap();
    fs::write(dir.join("target.py"), "anything at all\n").unwrap();

    let ids = scan_dir(&dir, rules.to_str().unwrap());
    assert!(
        ids.iter().any(|r| r == "t-only-metavar"),
        "a rule whose pattern is only a metavariable must still match; got {ids:?}"
    );
    assert!(
        ids.iter().any(|r| r == "t-only-ellipsis"),
        "a rule whose pattern is only an ellipsis must still match; got {ids:?}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn literal_rule_is_still_skipped_when_absent() {
    // The optimization itself must survive the fix: a rule with a literal is
    // still not offered for a file that cannot contain it.
    let dir = tmpdir("skip");
    let rules = dir.join("rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("p.yaml"),
        "id: t-needs-literal\nlanguages: [python]\nseverity: ERROR\nmessage: m\npattern: distinctive_literal_token($X)\n",
    )
    .unwrap();
    fs::write(dir.join("target.py"), "unrelated content\n").unwrap();

    let ids = scan_dir(&dir, rules.to_str().unwrap());
    assert!(
        ids.is_empty(),
        "prefilter should skip a rule whose literal is absent; got {ids:?}"
    );

    // ...and it does fire when the literal is present.
    fs::write(
        dir.join("target.py"),
        "distinctive_literal_token(value)\n",
    )
    .unwrap();
    let ids = scan_dir(&dir, rules.to_str().unwrap());
    assert!(
        ids.iter().any(|r| r == "t-needs-literal"),
        "rule must fire when its literal appears; got {ids:?}"
    );

    fs::remove_dir_all(&dir).ok();
}