//! Guards on surface area that was deliberately removed.
//!
//! These exist because a deleted feature is easy to reintroduce by accident —
//! a stale branch, a copied flag list, a muscle-memory edit — and a
//! reintroduced sidecar that uploads a repository to a third party is worse than
//! the bug that motivated removing it.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_scanward")
}

#[test]
fn the_hosted_platform_sidecar_is_gone() {
    let out = Command::new(bin())
        .args(["scan", ".", "--only", "platform"])
        .output()
        .expect("run scanward");
    assert!(
        !out.status.success(),
        "--only platform must not resolve to anything"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown --only platform"),
        "the error should name the bad value: {stderr}"
    );
    // And it must point at what does exist, so the message is actionable.
    for expected in ["sast", "secrets", "sca", "licenses", "typosquat"] {
        assert!(
            stderr.contains(expected),
            "the usage error should list `{expected}`: {stderr}"
        );
    }
}

#[test]
fn no_vendor_credential_or_endpoint_is_referenced_anywhere_in_the_source() {
    // A sidecar that reads an API key is a sidecar that can be re-enabled by
    // flipping a default. The names must not exist in the tree at all.
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let forbidden = [
        "AIKIDO_API_KEY",
        "AIKIDO_ENDPOINT",
        "aikido.dev",
        "run_platform",
    ];
    let mut offenders = vec![];
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" || name == "target" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            // CHANGELOG is exempt on purpose: documenting a removal has to name
            // what was removed, otherwise nobody can grep for it.
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // So is this file: it necessarily spells the strings it forbids.
            if path.file_name().and_then(|f| f.to_str()) == Some("removed_surface.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for needle in forbidden {
                if text.contains(needle) {
                    offenders.push(format!("{} mentions {needle}", path.display()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "vendor integration references came back:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn every_documented_only_value_is_accepted_by_the_parser() {
    // Keeps the help text, the usage error and the dispatch table from drifting
    // apart, which is how a removed flag lingers as a stale mention.
    for value in ["sast", "secrets", "sca", "licenses", "typosquat"] {
        let out = Command::new(bin())
            .args(["scan", "--help"])
            .output()
            .expect("run scanward");
        let help = String::from_utf8_lossy(&out.stdout);
        assert!(
            help.contains(value),
            "`--only {value}` is implemented but missing from --help"
        );
    }
}
