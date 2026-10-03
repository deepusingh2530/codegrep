//! cg-deps: dependency manifest inventory.
//!
//! Parses the lockfiles and manifests a repository actually contains into a
//! flat, deterministic list of [`Dependency`] records. This is the spine for
//! three checks that all need the same data — supply-chain inventory (and SBOM
//! export), licence policy, and typosquat name analysis — so they are computed
//! once, here, rather than re-parsing manifests three times.
//!
//! Design constraints (inherited from the engine):
//! - **Offline and deterministic.** Everything is derived from file contents;
//!   no registry lookup, no network, no ordering surprises.
//! - **Original, dependency-light.** Only a TOML and a JSON parser; XML
//!   (Maven `pom.xml`) and MSBuild lockfiles are deliberately not handled yet
//!   and say so rather than guessing.
//! - **Never panic.** A malformed manifest yields an empty list, not an error
//!   the scanner would have to survive.
//!
//! Directness matters: "did you choose this dependency, or did it arrive
//! transitively?" is what makes a licence or typosquat finding actionable, so
//! each format uses its own signal for it (`go.mod`'s `// indirect`, npm's root
//! package, Cargo's dependency graph, Ruby's DEPENDENCIES section).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Package ecosystem, inferred from the manifest filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPi,
    Go,
    Composer,
    Ruby,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::PyPi => "pypi",
            Self::Go => "go",
            Self::Composer => "composer",
            Self::Ruby => "rubygems",
        }
    }
}

/// One resolved (or declared) dependency.
/// Whether licence metadata is knowable from what we read.
///
/// This exists because "we cannot see it" and "it is not there" are different
/// facts, and reporting them the same way is a lie. `Cargo.lock` has no licence
/// field at all, so every transitive crate in a Rust project would otherwise be
/// reported as unlicensed — when in fact the crate is usually MIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenceAvailability {
    /// The format records licences and this entry had one.
    Declared,
    /// The format records licences and this entry had none.
    Absent,
    /// The format carries no licence metadata whatsoever (Cargo.lock, go.mod,
    /// Gemfile.lock, requirements.txt, npm v1 lockfiles).
    NotInFormat,
}

impl LicenceAvailability {
    /// Best of two observations: a real declaration always wins, then an
    /// observed absence, then "this format cannot say".
    pub fn best(self, other: Self) -> Self {
        match (self, other) {
            (Self::Declared, _) | (_, Self::Declared) => Self::Declared,
            (Self::Absent, _) | (_, Self::Absent) => Self::Absent,
            _ => Self::NotInFormat,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Dependency {
    pub name: String,
    /// Version exactly as written in the file. Requirements-style ranges are
    /// kept verbatim (`>=2.0`) rather than normalized, so nothing is invented.
    pub version: String,
    pub ecosystem: Ecosystem,
    /// Declared license, when the manifest carries one. Lockfiles usually do
    /// not; manifests often do. `None` means "not declared here" — not "free".
    pub license: Option<String>,
    /// Whether `license` could have been present in the file this came from.
    pub licence_availability: LicenceAvailability,
    /// Manifest the record came from, relative to the scan root when possible.
    pub manifest: String,
    /// True when the project asked for this dependency directly.
    pub direct: bool,
    /// True when the record came from a lockfile (a resolved version) rather
    /// than a manifest (a declared requirement).
    pub resolved: bool,
}

/// Manifest filename → parser. Ordered longest-first where names overlap.
pub const MANIFEST_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
];

/// Which ecosystem a manifest filename belongs to, if any.
pub fn ecosystem_for(file_name: &str) -> Option<Ecosystem> {
    match file_name {
        "Cargo.lock" | "Cargo.toml" => Some(Ecosystem::Cargo),
        "package-lock.json" | "npm-shrinkwrap.json" => Some(Ecosystem::Npm),
        "requirements.txt" | "requirements-dev.txt" | "pyproject.toml" | "poetry.lock" => {
            Some(Ecosystem::PyPi)
        }
        "go.mod" | "go.sum" => Some(Ecosystem::Go),
        "composer.lock" => Some(Ecosystem::Composer),
        "Gemfile.lock" => Some(Ecosystem::Ruby),
        _ => None,
    }
}

/// Parse one manifest. Returns `None` for a filename we do not handle, and an
/// empty vector for a file we handle but cannot make sense of.
pub fn parse_manifest(path: &str, text: &str) -> Option<Vec<Dependency>> {
    let file = Path::new(path).file_name()?.to_string_lossy().to_string();
    let eco = ecosystem_for(&file)?;
    let manifest = Path::new(path).to_string_lossy().to_string();
    let mut deps = match file.as_str() {
        "Cargo.lock" => cargo_lock(text, &manifest),
        "Cargo.toml" => cargo_toml(text, &manifest),
        "package-lock.json" | "npm-shrinkwrap.json" => npm_lock(text, &manifest),
        "requirements.txt" | "requirements-dev.txt" => requirements_txt(text, &manifest),
        "pyproject.toml" => pyproject_toml(text, &manifest),
        "poetry.lock" => poetry_lock(text, &manifest),
        "go.mod" => go_mod(text, &manifest),
        "go.sum" => go_sum(text, &manifest),
        "composer.lock" => composer_lock(text, &manifest),
        "Gemfile.lock" => gemfile_lock(text, &manifest),
        _ => vec![],
    };
    for d in &mut deps {
        d.manifest = manifest.clone();
        d.ecosystem = eco;
    }
    Some(deps)
}

// ---------------------------------------------------------------- Cargo

/// `Cargo.lock`: `[[package]]` blocks. A package with no `source` is a local
/// workspace member, which is not a dependency at all.
fn cargo_lock(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return vec![];
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return vec![];
    };
    // Directness: in a workspace the packages *without* a `source` are the local
    // members, and their dependency lists are exactly the direct dependencies.
    // Everything else arrived transitively.
    let mut direct: BTreeSet<String> = BTreeSet::new();
    for pkg in packages {
        if pkg.get("source").is_some() {
            continue; // not a local member
        }
        if let Some(list) = pkg.get("dependencies").and_then(|d| d.as_array()) {
            for item in list {
                if let Some(s) = item.as_str() {
                    direct.insert(split_version(s));
                }
            }
        }
    }
    let mut out = vec![];
    for pkg in packages {
        let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        // No `source` ⇒ path/workspace member: our own code, not a dependency.
        if pkg.get("source").is_none() {
            continue;
        }
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: Ecosystem::Cargo,
            license: None,
            licence_availability: LicenceAvailability::NotInFormat,
            manifest: manifest.to_string(),
            direct: direct.contains(name),
            resolved: true,
        });
    }
    out
}

/// `Cargo.toml`: declared dependencies, which do carry a `license` field.
fn cargo_toml(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return vec![];
    };
    let mut out = vec![];
    let push_table = |tbl: &toml::Value, out: &mut Vec<Dependency>| {
        let Some(tbl) = tbl.as_table() else { return };
        for (name, spec) in tbl {
            let (version, license) = match spec {
                toml::Value::String(v) => (v.clone(), None),
                toml::Value::Table(t) => (
                    t.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    t.get("license").and_then(|v| v.as_str()).map(String::from),
                ),
                _ => (String::new(), None),
            };
            if name.starts_with('.') {
                continue; // [workspace.dependencies] is not a package
            }
                let licence_availability = if license.is_some() {
                    LicenceAvailability::Declared
                } else {
                    LicenceAvailability::Absent
                };
            out.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: Ecosystem::Cargo,
                license,
                licence_availability,
                manifest: manifest.to_string(),
                direct: true,
                resolved: false,
            });
        }
    };
    for key in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
    ] {
        if let Some(tbl) = value.get(key) {
            push_table(tbl, &mut out);
        }
    }
    // `[target.'cfg(...)'.dependencies]`
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for (_platform, spec) in targets {
            if let Some(tbl) = spec.as_table() {
                for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(t) = tbl.get(key) {
                        push_table(t, &mut out);
                    }
                }
            }
        }
    }
    dedupe_by_name(out)
}

/// `"serde 1.0.1 (registry+...)"` → name.
fn split_version(spec: &str) -> String {
    spec.split_whitespace().next().unwrap_or(spec).to_string()
}

// ------------------------------------------------------------------- npm

/// `package-lock.json` (v1 dependency tree, and v2/v3 `packages` map).
fn npm_lock(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return vec![];
    };
    let mut out = vec![];

    // v2/v3: "packages" keyed by path, "" is the project root.
    if let Some(packages) = root.get("packages").and_then(|p| p.as_object()) {
        let root_deps: BTreeSet<String> = root
            .get("packages")
            .and_then(|p| p.get(""))
            .and_then(|r| r.get("dependencies"))
            .and_then(|d| d.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        for (path, meta) in packages {
            if path.is_empty() {
                continue;
            }
            let Some(name) = path.rsplit("node_modules/").next() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let version = meta
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let license = meta.get("license").and_then(|v| v.as_str()).map(String::from);
            // Only a direct dependency of the root is direct; a nested path
            // (…/node_modules/a/node_modules/b) never is.
            let direct = path.matches("node_modules/").count() == 1
                && root_deps.contains(name);
                let licence_availability = if license.is_some() {
                    LicenceAvailability::Declared
                } else {
                    LicenceAvailability::Absent
                };
            out.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Npm,
                license,
                licence_availability,
                manifest: manifest.to_string(),
                direct,
                resolved: true,
            });
        }
        return dedupe_by_name(out);
    }

    // v1: nested "dependencies" tree; top level = direct.
    if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
        fn walk(
            deps: &serde_json::Map<String, serde_json::Value>,
            direct: bool,
            eco: Ecosystem,
            manifest: &str,
            out: &mut Vec<Dependency>,
        ) {
            for (name, meta) in deps {
                let version = meta
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let license = meta.get("license").and_then(|v| v.as_str()).map(String::from);
                    let licence_availability = if license.is_some() {
                        LicenceAvailability::Declared
                    } else {
                        LicenceAvailability::Absent
                    };
                out.push(Dependency {
                    name: name.clone(),
                    version,
                    ecosystem: eco,
                    license,
                    licence_availability,
                    manifest: manifest.to_string(),
                    direct,
                    resolved: true,
                });
                if let Some(nested) = meta.get("dependencies").and_then(|d| d.as_object()) {
                    walk(nested, false, eco, manifest, out);
                }
            }
        }
        walk(deps, true, Ecosystem::Npm, manifest, &mut out);
    }
    dedupe_by_name(out)
}

// ------------------------------------------------------------------ PyPI

/// `requirements.txt`: tolerate comments, options, continuations and URLs.
fn requirements_txt(text: &str, manifest: &str) -> Vec<Dependency> {
    let mut out = vec![];
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        if line.is_empty() || line.starts_with('-') {
            continue; // blank, --index-url, --hash, -r other.txt, -e .
        }
        // Environment markers and hashes after the requirement.
        let line = line.split(';').next().unwrap_or(line).trim();
        let line = line.split(" --hash").next().unwrap_or(line).trim();
        if line.contains("://") {
            continue; // direct URL/VCS requirement: no resolvable version
        }
        let spec = split_requirement(line);
        let Some((name, version)) = spec else {
            continue;
        };
        out.push(Dependency {
            name,
            version,
            ecosystem: Ecosystem::PyPi,
            license: None,
            licence_availability: LicenceAvailability::NotInFormat,
            manifest: manifest.to_string(),
            direct: true,
            resolved: false,
        });
    }
    dedupe_by_name(out)
}

/// `"requests[security]>=2.31 ; python_version>'3'"` → `("requests", ">=2.31")`.
fn split_requirement(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let idx = line
        .char_indices()
        .find(|(_, c)| matches!(c, '=' | '<' | '>' | '!' | '~'))
        .map(|(i, _)| i);
    match idx {
        Some(i) => {
            let name = line[..i].trim();
            // Drop extras: `requests[security]`
            let name = name.split('[').next().unwrap_or(name).trim();
            let raw_version = line[i..].trim();
            // `==2.31.0` is a pin: the operator is not part of the version.
            // Anything else (`>=2.0`, `~=1.4`) keeps its operator verbatim, since
            // rewriting a range would misreport what the manifest asked for.
            let version = raw_version
                .strip_prefix("==")
                .unwrap_or(raw_version)
                .trim()
                .to_string();
            if name.is_empty() {
                None
            } else {
                Some((name.to_string(), version))
            }
        }
        None => {
            let name = line.split('[').next().unwrap_or(line).trim();
            if name.is_empty() {
                None
            } else {
                Some((name.to_string(), String::new()))
            }
        }
    }
}

/// `pyproject.toml`: PEP 621 `[project] dependencies` and Poetry's
/// `[tool.poetry.dependencies]` (the latter may carry `license`).
fn pyproject_toml(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return vec![];
    };
    let mut out = vec![];

    if let Some(list) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for item in list {
            if let Some(s) = item.as_str() {
                if let Some((name, version)) = split_requirement(s) {
                    out.push(Dependency {
                        name,
                        version,
                        ecosystem: Ecosystem::PyPi,
                        license: None,
                        licence_availability: LicenceAvailability::NotInFormat,
                        manifest: manifest.to_string(),
                        direct: true,
                        resolved: false,
                    });
                }
            }
        }
    }

    if let Some(deps) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, spec) in deps {
            if name.eq_ignore_ascii_case("python") {
                continue; // the interpreter constraint, not a package
            }
            let (version, license) = match spec {
                toml::Value::String(v) => (v.clone(), None),
                toml::Value::Table(t) => (
                    t.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    t.get("license").and_then(|v| v.as_str()).map(String::from),
                ),
                _ => (String::new(), None),
            };
                let licence_availability = if license.is_some() {
                    LicenceAvailability::Declared
                } else {
                    LicenceAvailability::Absent
                };
            out.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: Ecosystem::PyPi,
                license,
                licence_availability,
                manifest: manifest.to_string(),
                direct: true,
                resolved: false,
            });
        }
    }
    dedupe_by_name(out)
}

/// `poetry.lock`: `[[package]]` with an explicit `category`.
fn poetry_lock(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return vec![];
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return vec![];
    };
    let mut out = vec![];
    for pkg in packages {
        let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dev = pkg
            .get("category")
            .and_then(|c| c.as_str())
            .map(|c| c.eq_ignore_ascii_case("dev"))
            .unwrap_or(false);
        let license = pkg.get("license").and_then(|v| v.as_str()).map(String::from);
        let licence_availability = if license.is_some() {
            LicenceAvailability::Declared
        } else {
            LicenceAvailability::Absent
        };
        out.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: Ecosystem::PyPi,
            license,
            licence_availability,
            manifest: manifest.to_string(),
            direct: !dev,
            resolved: true,
        });
    }
    out
}

// -------------------------------------------------------------------- Go

/// `go.mod`: `require` blocks, honouring the `// indirect` marker.
fn go_mod(text: &str, manifest: &str) -> Vec<Dependency> {
    let mut out = vec![];
    let mut in_require = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or(raw).trim(); // drop comments
        let indirect = raw.contains("// indirect");
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require") {
            let rest = line.trim_start_matches("require").trim();
            // `require (` opens a block; `require` alone opens one too.
            if rest.is_empty() || rest == "(" {
                in_require = true;
                continue;
            }
            let mut parts = rest.split_whitespace();
            if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
                out.push(go_dep(name, version, indirect, manifest));
            }
            continue;
        }
        if line == ")" {
            in_require = false;
            continue;
        }
        if in_require {
            let mut parts = line.split_whitespace();
            if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
                out.push(go_dep(name, version, indirect, manifest));
            }
        }
    }
    dedupe_by_name(out)
}

fn go_dep(name: &str, version: &str, indirect: bool, manifest: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Go,
        license: None,
        licence_availability: LicenceAvailability::NotInFormat,
        manifest: manifest.to_string(),
        direct: !indirect,
        resolved: false,
    }
}

/// `go.sum` gives resolved versions but no names/versions worth pairing here;
/// it is listed as a supported file so discovery does not flag it, but the
/// `go.mod` requirements are the useful record.
fn go_sum(_text: &str, _manifest: &str) -> Vec<Dependency> {
    vec![]
}

// --------------------------------------------------------------- Composer

/// `composer.lock`: `packages` and `packages-dev`; licence is an array.
fn composer_lock(text: &str, manifest: &str) -> Vec<Dependency> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return vec![];
    };
    let mut out = vec![];
    for (key, direct) in [("packages", true), ("packages-dev", false)] {
        let Some(list) = root.get(key).and_then(|p| p.as_array()) else {
            continue;
        };
        for pkg in list {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let license = pkg.get("license").and_then(|l| match l {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Array(a) => a
                    .first()
                    .and_then(|v| v.as_str())
                    .map(String::from),
                _ => None,
            });
                let licence_availability = if license.is_some() {
                    LicenceAvailability::Declared
                } else {
                    LicenceAvailability::Absent
                };
            out.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: Ecosystem::Composer,
                license,
                licence_availability,
                manifest: manifest.to_string(),
                direct,
                resolved: true,
            });
        }
    }
    dedupe_by_name(out)
}

// ------------------------------------------------------------------ Ruby

/// `Gemfile.lock`: the `specs:` block lists resolved gems, `DEPENDENCIES`
/// marks the direct ones. Platform suffixes are dropped.
fn gemfile_lock(text: &str, manifest: &str) -> Vec<Dependency> {
    let mut specs: Vec<(String, String)> = vec![];
    let mut direct: BTreeSet<String> = BTreeSet::new();
    // Sections are at column 0; their keys (`specs:`) are indented; entries are
    // indented further. Gemfile.lock is indentation-significant, so track all three.
    let mut section = String::new();
    let mut in_specs = false;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            section = trimmed.to_string();
            in_specs = false;
            continue;
        }
        if indent <= 2 && trimmed.ends_with(':') {
            in_specs = trimmed == "specs:";
            continue;
        }
        if in_specs && section == "GEM" {
            if let Some(spec) = parse_gem_spec(trimmed) {
                specs.push(spec);
            }
        } else if section == "DEPENDENCIES" && !trimmed.starts_with('!') {
            if let Some(spec) = parse_gem_spec(trimmed) {
                direct.insert(spec.0);
            }
        }
    }

    specs
        .into_iter()
        .map(|(name, version)| Dependency {
            direct: direct.contains(&name),
            name,
            version,
            ecosystem: Ecosystem::Ruby,
            license: None,
            licence_availability: LicenceAvailability::NotInFormat,
            manifest: manifest.to_string(),
            resolved: true,
        })
        .collect()
}

/// `"rails (7.1.2)"` / `"nokogiri (1.16.0-x86_64-linux)"` → `(name, version)`.
fn parse_gem_spec(line: &str) -> Option<(String, String)> {
    let line = line.trim().trim_end_matches('!').trim();
    if line.is_empty() {
        return None;
    }
    // `name (1.2.3)` — read the version out of the parenthetical. Splitting on
    // " (" first would throw the version away entirely.
    let (name, raw_version) = match line.rfind('(') {
        Some(i) if line.ends_with(')') => (
            line[..i].trim(),
            line[i + 1..line.len() - 1].trim().to_string(),
        ),
        _ => (line, String::new()),
    };
    let name = name.trim();
    if name.is_empty() || name.ends_with(':') {
        return None;
    }
    Some((name.to_string(), strip_ruby_platform(&raw_version)))
}

/// RubyGems appends a platform to the version in the lockfile. Only *known*
/// platform suffixes are stripped: a pre-release such as `1.0.0-beta.1` is real
/// version information and must survive.
const RUBY_PLATFORM_SUFFIXES: &[&str] = &[
    "x86_64-linux",
    "x86_64-linux-musl",
    "x86_64-darwin",
    "aarch64-linux",
    "aarch64-darwin",
    "arm64-darwin",
    "arm-linux",
    "x64-mingw-ucrt",
    "x64-mingw32",
    "x86-mingw32",
    "java",
    "universal-darwin",
    "sparc",
];

fn strip_ruby_platform(version: &str) -> String {
    for suffix in RUBY_PLATFORM_SUFFIXES {
        if let Some(base) = version.strip_suffix(&format!("-{suffix}")) {
            return base.to_string();
        }
    }
    version.to_string()
}

// ------------------------------------------------------------------ util

/// Keep the first record per name (manifests list a package once; when a lock
/// and a manifest are both scanned the caller keeps both anyway).
fn dedupe_by_name(deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut seen = BTreeSet::new();
    deps.into_iter()
        .filter(|d| seen.insert(d.name.clone()))
        .collect()
}

/// Merge inventories from several manifests, keyed by ecosystem+name, keeping
/// the richest record: a resolved version beats a range, a declared license
/// beats none.
pub fn merge(mut all: Vec<Dependency>) -> Vec<Dependency> {
    let mut by_key: BTreeMap<(Ecosystem, String), Dependency> = BTreeMap::new();
    for dep in all.drain(..) {
        let key = (dep.ecosystem, dep.name.clone());
        match by_key.get_mut(&key) {
            Some(existing) => {
                if dep.resolved && !existing.resolved {
                    existing.version = dep.version;
                    existing.resolved = true;
                } else if !existing.resolved && existing.version.is_empty() {
                    existing.version = dep.version;
                }
                if existing.license.is_none() {
                    existing.license = dep.license;
                }
                // A lockfile may not know the licence while the manifest does,
                // or vice versa; keep whichever observation is strongest.
                existing.licence_availability =
                    existing.licence_availability.best(dep.licence_availability);
                existing.direct = existing.direct || dep.direct;
            }
            None => {
                by_key.insert(key, dep);
            }
        }
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(name: &str, text: &str) -> Vec<Dependency> {
        parse_manifest(name, text).unwrap_or_default()
    }

    #[test]
    fn cargo_lock_directness() {
        let text = r#"
[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "scanward"
version = "0.13.2"
dependencies = ["serde"]

[[package]]
name = "scanward"
version = "0.13.2"
"#;
        let deps = parse("Cargo.lock", text);
        // Workspace member (no `source`) is excluded from the inventory, and a
        // crate listed in a member's dependencies is a direct dependency.
        assert!(!deps.iter().any(|d| d.name == "scanward"), "member excluded");
        let serde = deps.iter().find(|d| d.name == "serde").expect("serde");
        assert!(serde.direct, "listed by the workspace member ⇒ direct");
        assert_eq!(serde.version, "1.0.210");
        assert_eq!(serde.ecosystem, Ecosystem::Cargo);
    }

    #[test]
    fn cargo_toml_keeps_declared_license() {
        let text = r#"
[package]
name = "x"

[dependencies]
serde = { version = "1", license = "MIT OR Apache-2.0" }
anyhow = "1"
rayon = { version = "1", git = "https://example/x" }

[dev-dependencies]
tempfile = "3"

[target.'cfg(unix)'.dependencies]
nix = "0.27"
"#;
        let deps = parse("Cargo.toml", text);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert!(!serde.resolved, "a manifest declares, it does not resolve");
        for n in ["anyhow", "rayon", "tempfile", "nix"] {
            assert!(deps.iter().any(|d| d.name == n), "{n} should be present");
        }
    }

    #[test]
    fn npm_lock_v3_root_directness() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "dependencies": { "express": "^4" } },
            "node_modules/express": { "version": "4.19.2", "license": "MIT" },
            "node_modules/body-parser": { "version": "1.20.2" },
            "node_modules/express/node_modules/debug": { "version": "2.6.9" }
          }
        }"#;
        let deps = parse("package-lock.json", text);
        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert!(express.direct, "declared by the root package");
        assert_eq!(express.license.as_deref(), Some("MIT"));
        let body = deps.iter().find(|d| d.name == "body-parser").unwrap();
        assert!(!body.direct, "not in the root's dependency list");
        let debug_nested = deps
            .iter()
            .find(|d| d.name == "debug")
            .expect("nested package is still inventoried");
        assert!(!debug_nested.direct, "nested path is never direct");
    }

    #[test]
    fn npm_lock_v1_tree() {
        let text = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "express": { "version": "4.18.2", "dependencies": { "qs": { "version": "6.11.0" } } }
          }
        }"#;
        let deps = parse("package-lock.json", text);
        assert!(deps.iter().any(|d| d.name == "express" && d.direct));
        assert!(deps.iter().any(|d| d.name == "qs" && !d.direct));
    }

    #[test]
    fn requirements_txt_shapes() {
        let text = "# comment\n\nrequests==2.31.0\nurllib3>=2.0  # pinned\nflask[async]==3.0.0\n-r other.txt\n--index-url https://x\ndjango\npkg @ https://example/pkg.whl\nnumpy==1.26.4 ; python_version > '3.9'\n";
        let deps = parse("requirements.txt", text);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["requests", "urllib3", "flask", "django", "numpy"],
            "URL/options/includes must be skipped, markers dropped"
        );
        // Pins lose the `==`; ranges keep their operator.
        assert_eq!(
            deps.iter().find(|d| d.name == "requests").unwrap().version,
            "2.31.0",
            "an exact pin is a version, not a version plus an operator"
        );
        assert_eq!(
            deps.iter().find(|d| d.name == "numpy").unwrap().version,
            "1.26.4"
        );
        let urllib = deps.iter().find(|d| d.name == "urllib3").unwrap();
        assert_eq!(urllib.version, ">=2.0");
        let django = deps.iter().find(|d| d.name == "django").unwrap();
        assert_eq!(django.version, "", "bare requirement has no version");
    }

    #[test]
    fn pyproject_poetry_and_pep621() {
        let text = r#"
[project]
name = "x"
dependencies = ["httpx>=0.27", "pydantic==2.9.2"]

[tool.poetry.dependencies]
python = "^3.11"
requests = { version = "^2.31", license = "Apache-2.0" }
"#;
        let deps = parse("pyproject.toml", text);
        let req = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(req.license.as_deref(), Some("Apache-2.0"));
        assert!(!deps.iter().any(|d| d.name == "python"), "python constraint is not a package");
        assert!(deps.iter().any(|d| d.name == "httpx"));
    }

    #[test]
    fn poetry_lock_categories() {
        let text = r#"
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "8.3.3"
category = "dev"
"#;
        let deps = parse("poetry.lock", text);
        assert!(deps.iter().find(|d| d.name == "requests").unwrap().direct);
        assert!(!deps.iter().find(|d| d.name == "pytest").unwrap().direct);
    }

    #[test]
    fn go_mod_indirect_marker() {
        let text = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.0\n\tgolang.org/x/sys v0.15.0 // indirect\n)\n\nrequire github.com/stretchr/testify v1.8.4\n";
        let deps = parse("go.mod", text);
        let cobra = deps.iter().find(|d| d.name == "github.com/spf13/cobra").unwrap();
        assert!(cobra.direct && cobra.version == "v1.8.0");
        let sys = deps
            .iter()
            .find(|d| d.name == "golang.org/x/sys")
            .unwrap();
        assert!(!sys.direct, "// indirect must be honoured");
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/stretchr/testify" && d.direct));
    }

    #[test]
    fn composer_lock_license_array() {
        let text = r#"{
          "packages": [
            { "name": "monolog/monolog", "version": "3.5.0", "license": ["MIT"] },
            { "name": "acme/closed", "version": "1.0.0", "license": ["proprietary"] }
          ],
          "packages-dev": [ { "name": "phpunit/phpunit", "version": "10.5.0" } ]
        }"#;
        let deps = parse("composer.lock", text);
        let monolog = deps.iter().find(|d| d.name == "monolog/monolog").unwrap();
        assert_eq!(monolog.license.as_deref(), Some("MIT"));
        assert!(monolog.direct);
        assert!(!deps
            .iter()
            .find(|d| d.name == "phpunit/phpunit")
            .unwrap()
            .direct);
    }

    #[test]
    fn gemfile_lock_directs() {
        let text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.1.2)\n    rack (3.0.8)\n    nokogiri (1.16.0-x86_64-darwin)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  actionpack (~> 7.1)\n  rack\n\nBUNDLED WITH\n   2.4.22\n";
        let deps = parse("Gemfile.lock", text);
        assert_eq!(deps.len(), 3, "one record per gem spec");
        let rack = deps.iter().find(|d| d.name == "rack").unwrap();
        assert!(rack.direct && rack.version == "3.0.8");
        let nokogiri = deps.iter().find(|d| d.name == "nokogiri").unwrap();
        assert_eq!(nokogiri.version, "1.16.0", "platform suffix dropped");
        assert!(!nokogiri.direct);
    }

    #[test]
    fn ruby_platform_suffix_stripped_but_prerelease_kept() {
        // `nokogiri (1.16.0-x86_64-darwin)` → platform dropped.
        assert_eq!(
            parse_gem_spec("nokogiri (1.16.0-x86_64-darwin)").unwrap(),
            ("nokogiri".to_string(), "1.16.0".to_string())
        );
        // A pre-release is version information, not a platform.
        assert_eq!(
            parse_gem_spec("rails (7.1.0-beta.1)").unwrap(),
            ("rails".to_string(), "7.1.0-beta.1".to_string())
        );
        assert_eq!(
            parse_gem_spec("rack").unwrap(),
            ("rack".to_string(), String::new())
        );
    }

    #[test]
    fn malformed_input_yields_nothing() {
        for (name, text) in [
            ("Cargo.lock", "this is not toml {{{"),
            ("package-lock.json", "{not json"),
            ("pyproject.toml", "<<<>>>"),
            ("Gemfile.lock", "\0\0\0"),
        ] {
            let deps = parse(name, text);
            assert!(deps.is_empty(), "{name} must not panic or invent data");
        }
    }

    #[test]
    fn unknown_manifest_is_not_claimed() {
        assert!(parse_manifest("go.sum", "x v1.0.0 h1:abc\n").is_some());
        assert!(parse_manifest("build.gradle", "dependencies { }").is_none());
        assert!(parse_manifest("random.txt", "hello").is_none());
    }

    #[test]
    fn licence_availability_distinguishes_unknown_from_absent() {
        // Cargo.lock has no licence field: we cannot know, which is not the
        // same as "not licensed".
        let lock = parse(
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://x\"",
        );
        assert_eq!(lock[0].license, None);
        assert_eq!(
            lock[0].licence_availability,
            LicenceAvailability::NotInFormat,
            "claiming a Cargo.lock entry is unlicensed would be a lie"
        );

        // A manifest with no `license` key is a real observation of absence.
        let manifest = parse("Cargo.toml", "[package]\nname='x'\n\n[dependencies]\nfoo = '1'\n");
        assert_eq!(
            manifest[0].licence_availability,
            LicenceAvailability::Absent
        );

        let declared = parse(
            "Cargo.toml",
            "[package]\nname='x'\n\n[dependencies]\nserde = { version = '1', license = 'MIT' }\n",
        );
        assert_eq!(declared[0].licence_availability, LicenceAvailability::Declared);

        // npm v3 lockfiles do record it.
        let npm = parse(
            "package-lock.json",
            r#"{"packages":{"node_modules/x":{"version":"1.0.0","license":"MIT"}}}"#,
        );
        assert_eq!(npm[0].licence_availability, LicenceAvailability::Declared);

        // poetry.lock records it too, and the parser now reads it.
        let poetry = parse(
            "poetry.lock",
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nlicense = \"Apache-2.0\"\n",
        );
        assert_eq!(poetry[0].license.as_deref(), Some("Apache-2.0"));
        assert_eq!(poetry[0].licence_availability, LicenceAvailability::Declared);
    }

    #[test]
    fn merge_keeps_the_strongest_licence_observation() {
        assert_eq!(LicenceAvailability::Declared.best(LicenceAvailability::NotInFormat), LicenceAvailability::Declared);
        assert_eq!(LicenceAvailability::Absent.best(LicenceAvailability::NotInFormat), LicenceAvailability::Absent);
        assert_eq!(LicenceAvailability::NotInFormat.best(LicenceAvailability::NotInFormat), LicenceAvailability::NotInFormat);
    }

    #[test]
    fn merge_prefers_resolved_and_license() {
        let all = vec![
            Dependency {
                name: "serde".into(),
                version: "1".into(),
                ecosystem: Ecosystem::Cargo,
                license: None,
                licence_availability: LicenceAvailability::Absent,
                manifest: "Cargo.toml".into(),
                direct: true,
                resolved: false,
            },
            Dependency {
                name: "serde".into(),
                version: "1.0.210".into(),
                ecosystem: Ecosystem::Cargo,
                license: Some("MIT OR Apache-2.0".into()),
                licence_availability: LicenceAvailability::Declared,
                manifest: "Cargo.lock".into(),
                direct: false,
                resolved: true,
            },
        ];
        let merged = merge(all);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].version, "1.0.210", "resolved version wins");
        assert_eq!(merged[0].license.as_deref(), Some("MIT OR Apache-2.0"));
    }

    #[test]
    fn real_cargo_lock_of_this_repository() {
        // The repo's own lockfile must parse and contain known crates.
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
            .expect("Cargo.lock is readable");
        let deps = parse("Cargo.lock", &text);
        assert!(deps.iter().any(|d| d.name == "rayon" && d.direct));
        assert!(
            deps.iter().any(|d| d.name == "tree-sitter"),
            "tree-sitter must be inventoried"
        );
        assert!(
            deps.iter().all(|d| !d.version.is_empty()),
            "every lockfile entry has a resolved version"
        );
    }
}
