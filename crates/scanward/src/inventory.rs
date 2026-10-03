//! Dependency inventory: walk a tree, parse the manifests, merge the records.
//!
//! Thin by design — all format knowledge lives in [`cg_deps`]. This module only
//! decides *which* files to read and hands back one deduplicated list.

use std::path::{Path, PathBuf};

use cg_deps::{self, Dependency};

/// Manifest files worth reading, longest/most-specific names first so that a
/// directory containing both `Cargo.toml` and `Cargo.lock` yields both.
const CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile.lock",
    "composer.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "go.mod",
];

/// Collect every dependency declared under `root`.
///
/// Results are merged across manifests (a lockfile's resolved version wins over
/// a manifest's range, a declared licence fills a lockfile that lacks one) and
/// sorted for deterministic output.
pub fn collect(root: &str) -> Vec<Dependency> {
    let root_path = Path::new(root);
    let mut out: Vec<Dependency> = vec![];

    for name in CANDIDATE_FILES {
        // Case-sensitive on purpose: a file called `CARGO.TOML` is not a manifest
        // cargo itself would read.
        let matches: Vec<PathBuf> = if root_path.is_file() {
            if root_path
                .file_name()
                .map(|f| f.to_string_lossy() == *name)
                .unwrap_or(false)
            {
                vec![root_path.to_path_buf()]
            } else {
                vec![]
            }
        } else {
            walk(root_path)
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .map(|f| f.to_string_lossy() == *name)
                        .unwrap_or(false)
                })
                .collect()
        };
        for path in matches {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue; // unreadable or binary: skip, never invent
            };
            let path_s = path.to_string_lossy().to_string();
            if let Some(mut deps) = cg_deps::parse_manifest(&path_s, &text) {
                for d in &mut deps {
                    d.manifest = display_path(root_path, &path);
                }
                out.extend(deps);
            }
        }
    }
    cg_deps::merge(out)
}

/// Directory walk that skips the usual noise directories. Uses the same
/// ignore-aware walker as the scanner when possible so `.gitignore` is honoured
/// (a vendored `target/` should not contribute dependencies).
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder.hidden(false).git_ignore(true).git_global(false);
    builder
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

/// Paths are reported relative to the scan root when possible, so reports do not
/// leak the absolute path of the machine that ran the scan.
fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scanward-inv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn collects_across_ecosystems_and_merges() {
        let dir = tmpdir("mixed");
        write(
            &dir,
            "Cargo.toml",
            "[package]\nname='x'\n\n[dependencies]\nserde = { version = \"1\", license = \"MIT OR Apache-2.0\" }\n",
        );
        write(
            &dir,
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n",
        );
        write(&dir, "requirements.txt", "requests==2.31.0\nflask>=3\n");
        write(&dir, "go.mod", "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.0\n)\n");
        write(&dir, "sub/nested/package.json", "{}\n");

        let deps = collect(dir.to_str().unwrap());
        let by_name = |n: &str| deps.iter().find(|d| d.name == n).cloned();

        let serde = by_name("serde").expect("serde present");
        assert_eq!(serde.version, "1.0.210", "resolved version wins over range");
        assert_eq!(
            serde.license.as_deref(),
            Some("MIT OR Apache-2.0"),
            "declared licence survives the merge"
        );
        assert!(serde.direct);

        assert!(by_name("requests").is_some(), "pypi inventoried");
        assert!(by_name("flask").is_some());
        assert!(
            by_name("github.com/spf13/cobra").is_some(),
            "go requirement inventoried"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reports_paths_relative_to_root() {
        let dir = tmpdir("rel");
        write(&dir, "svc/requirements.txt", "httpx==0.27.0\n");
        let deps = collect(dir.to_str().unwrap());
        let d = deps.iter().find(|d| d.name == "httpx").unwrap();
        assert_eq!(d.manifest, "svc/requirements.txt");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scanning_this_repository_lists_its_own_dependencies() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let deps = collect(root);
        assert!(deps.iter().any(|d| d.name == "serde"), "workspace deps found");
        assert!(
            deps.iter().any(|d| d.name == "toml"),
            "the new toml dependency shows up"
        );
        assert!(
            deps.iter().all(|d| !d.manifest.starts_with('/')),
            "no absolute paths leak into records"
        );
    }

    #[test]
    fn a_single_manifest_file_can_be_scanned() {
        let dir = tmpdir("single");
        write(&dir, "Cargo.toml", "[package]\nname='x'\n\n[dependencies]\nanyhow = \"1\"\n");
        let deps = collect(dir.join("Cargo.toml").to_str().unwrap());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "anyhow");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tree_without_manifests_yields_nothing() {
        let dir = tmpdir("empty");
        write(&dir, "main.py", "print('hi')\n");
        assert!(collect(dir.to_str().unwrap()).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
