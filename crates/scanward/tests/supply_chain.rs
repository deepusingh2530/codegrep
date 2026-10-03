//! End-to-end tests for the native supply-chain checks (`--only licenses`,
//! `--only typosquat`). These run the real binary, because the contract that
//! matters is the exit code and the printed report, not the library types.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_scanward")
}

struct Project(PathBuf);

impl Project {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "scanward-supply-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create project");
        Self(dir)
    }

    fn write(&self, name: &str, body: &str) -> &Self {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, body).expect("write file");
        self
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str]) -> Output {
    let out = Command::new(bin()).args(args).output().expect("run scanward");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

const LOCK_WITH_TYPO: &str = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0",
          "dependencies": { "lodahs": "^4", "internal-billing-sdk": "^1" } },
    "node_modules/lodahs": { "version": "4.17.21", "license": "MIT" },
    "node_modules/lodash": { "version": "4.17.20", "license": "MIT" },
    "node_modules/internal-billing-sdk": { "version": "1.0.0" }
  }
}"#;

const POLICY: &str = r#"allow: ["MIT", "Apache-2.0"]
deny: ["GPL-3.0"]
unlicensed: warn
scope: all
"#;

#[test]
fn typosquat_flags_a_transposed_name_and_spells_out_why() {
    let p = Project::new("typo");
    p.write("package-lock.json", LOCK_WITH_TYPO);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "typosquat",
    ]);
    assert_eq!(out.code, 0, "no --error, so no failure: {}", out.stderr);
    assert!(
        out.stdout.contains("lodahs") && out.stdout.contains("lodash"),
        "names both the suspect and the package it imitates: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("review, not proof"),
        "the report must not claim certainty: {}",
        out.stdout
    );
    // The genuine package and the internal name are not suspects.
    assert!(!out.stdout.contains("lodash 4.17.20"), "{}", out.stdout);
    assert!(
        !out.stdout.contains("internal-billing-sdk"),
        "an internal package is not a typosquat: {}",
        out.stdout
    );
}

#[test]
fn typosquat_error_gate_fails_the_build() {
    let p = Project::new("typo-error");
    p.write("package-lock.json", LOCK_WITH_TYPO);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "typosquat",
        "--error",
    ]);
    assert_eq!(out.code, 1, "a suspect must fail --error: {}", out.stdout);
}

#[test]
fn clean_dependency_set_passes_the_typosquat_gate() {
    let p = Project::new("typo-clean");
    p.write(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{
            "node_modules/lodash":{"version":"4.17.21","license":"MIT"},
            "node_modules/express":{"version":"4.19.2","license":"MIT"}}}"#,
    );
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "typosquat",
        "--error",
    ]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("no names resembling"), "{}", out.stdout);
}

#[test]
fn licence_check_separates_declared_absent_and_unknown() {
    let p = Project::new("lic");
    p.write("package-lock.json", LOCK_WITH_TYPO);
    p.write("requirements.txt", "requests==2.31.0\n");
    p.write(".scanward-licences.yml", POLICY);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "licenses",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    // lodahs declares MIT (allowed); internal-billing-sdk declares nothing (a
    // real absence); requests comes from requirements.txt, a format with no
    // licence field at all (unknowable).
    assert!(out.stdout.contains("allowed=2"), "{}", out.stdout);
    assert!(out.stdout.contains("unlicensed=1"), "{}", out.stdout);
    assert!(
        out.stdout.contains("unavailable=1"),
        "an unknowable licence must not be reported as unlicensed: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("not in this manifest format"),
        "{}",
        out.stdout
    );
}

#[test]
fn licence_check_fails_the_gate_on_a_denial() {
    let p = Project::new("lic-deny");
    p.write(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{
            "node_modules/copyleft-lib":{"version":"1.0.0","license":"GPL-3.0"}}}"#,
    );
    p.write(".scanward-licences.yml", POLICY);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "licenses",
        "--error",
    ]);
    assert_eq!(out.code, 1, "a denied licence must fail: {}", out.stdout);
    assert!(out.stdout.contains("denied"), "{}", out.stdout);
}

#[test]
fn an_explicit_policy_path_that_does_not_exist_is_an_error() {
    let p = Project::new("lic-missing");
    p.write("package-lock.json", LOCK_WITH_TYPO);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "licenses",
        "--license-policy",
        "no/such/policy.yml",
    ]);
    assert_ne!(out.code, 0, "naming a missing policy is a mistake: {}", out.stdout);
    assert!(
        out.stderr.contains("cannot read licence policy"),
        "the error must say what is wrong: {}",
        out.stderr
    );
}

#[test]
fn json_output_is_machine_readable() {
    let p = Project::new("json");
    p.write("package-lock.json", LOCK_WITH_TYPO);
    p.write(".scanward-licences.yml", POLICY);
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "licenses",
        "--json",
    ]);
    let parsed: serde_json::Value =
        serde_json::from_str(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", out.stdout));
    let arr = parsed.as_array().expect("array");
    assert!(!arr.is_empty());
    let first = &arr[0];
    assert!(first.get("package").and_then(|v| v.as_str()).is_some());
    assert_eq!(
        first.get("ecosystem").and_then(|v| v.as_str()),
        Some("npm"),
        "ecosystem must be the wire name, not the Rust variant"
    );
    assert!(first.get("verdict").and_then(|v| v.as_str()).is_some());
}

#[test]
fn a_tree_without_manifests_says_so_instead_of_pretending_to_pass() {
    let p = Project::new("empty");
    p.write("main.py", "print('hi')\n");
    let out = run(&[
        "scan",
        p.path().to_str().unwrap(),
        "--only",
        "licenses",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stderr.contains("no dependency manifests found"),
        "an empty inventory must not read as 'all clear': {}",
        out.stderr
    );
}
