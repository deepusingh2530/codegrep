//! Translator for the portable pattern-rule schema — the common open-source
//! YAML rule format used by third-party scanners (keys like `patterns:`,
//! `pattern-not-inside`, `mode: taint`, `pattern-sources`).
//!
//! Only *user-supplied* rule files are translated at runtime; codegrep ships
//! none of their content. Translation is strict: any construct we cannot
//! represent with faithful semantics skips that rule with a reported reason
//! instead of silently weakening it.
//!
//! Known approximations (documented in docs/rule-import.md):
//! - `pattern-not` is enforced line-scoped by our matcher (their scope is
//!   structural); imported negations may therefore fire in a few extra cases.
//! - Multiple AND-ed positive patterns / `pattern-not-inside` /
//!   `pattern-regex` are not supported yet and skip the rule.

use crate::{PatternChoice, Rule, TaintPart, TaintSpec};
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;

/// Top-level keys that only exist in the portable schema.
const MARKERS: &[&str] = &[
    "mode",
    "pattern-sources",
    "pattern-sinks",
    "pattern-sanitizers",
    "fix-regex",
    "pattern-not-inside",
    "pattern-regex",
    "pattern-propagate",
    "focus-metavariable",
    "requires",
    "equivalences",
];

/// True when a rule document belongs to the portable schema (and native
/// loading would mis-parse or reject it).
pub fn looks_portable(v: &Value) -> bool {
    let Some(m) = v.as_mapping() else { return false };
    for (k, val) in m {
        let Some(ks) = k.as_str() else { continue };
        if MARKERS.contains(&ks) {
            return true;
        }
        if ks == "metavariable-regex" || ks == "metavariable-comparison" {
            // Portable form is a single {metavariable, regex} object; the
            // native form is a metavariable -> regex map.
            if val.get("metavariable").is_some() {
                return true;
            }
        }
        if ks == "patterns" {
            // Native `patterns` items are {pattern}; portable conjunctions
            // carry negative/restriction keys too.
            let Some(seq) = val.as_sequence() else { continue };
            for item in seq {
                match item.as_mapping() {
                    Some(im) => {
                        let only_pattern = im.keys().all(|ik| ik.as_str() == Some("pattern"));
                        if !only_pattern {
                            return true;
                        }
                    }
                    None => return true,
                }
            }
        }
    }
    false
}

fn s(m: &Mapping, key: &str) -> Option<String> {
    m.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

/// A pattern must be a quoted YAML string: bare scalars like `0o777` parse
/// as integers once routed through `Value`, silently corrupting the text.
fn pat_str(v: &Value, what: &str) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Err(format!(
            "{what} is the bare number {n} — quote patterns containing digits (e.g. \"0o777\")"
        )),
        Value::Bool(b) => Err(format!("{what} is the bare boolean {b} — quote it")),
        _ => Err(format!("{what} must be a string")),
    }
}

fn seq_str(v: &Value) -> Option<Vec<String>> {
    v.as_sequence()
        .map(|items| items.iter().filter_map(|i| i.as_str()).map(str::to_string).collect())
}

/// Map portable language names onto codegrep languages; drop unsupported.
fn map_languages(list: &[String]) -> (Vec<String>, Vec<String>) {
    let mapped: HashMap<&str, &str> = HashMap::from([
        ("python", "python"),
        ("javascript", "javascript"),
        ("js", "javascript"),
        ("typescript", "typescript"),
        ("ts", "typescript"),
        ("tsx", "typescript"),
        ("go", "go"),
        ("golang", "go"),
        ("java", "java"),
        ("ruby", "ruby"),
        ("rb", "ruby"),
        ("php", "php"),
        ("csharp", "csharp"),
        ("c#", "csharp"),
        ("c", "c"),
        ("cpp", "cpp"),
        ("c++", "cpp"),
        ("kotlin", "kotlin"),
        ("scala", "scala"),
        ("ocaml", "ocaml"),
        ("bash", "bash"),
        ("sh", "bash"),
        ("shell", "bash"),
        ("yaml", "yaml"),
        ("json", "json"),
        ("terraform", "terraform"),
        ("hcl", "terraform"),
        ("dockerfile", "dockerfile"),
        ("docker", "dockerfile"),
        ("html", "html"),
        ("generic", "generic"),
    ]);
    let mut out = vec![];
    let mut dropped = vec![];
    for l in list {
        match mapped.get(l.to_ascii_lowercase().as_str()) {
            Some(t) => {
                let t = (*t).to_string();
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            None => dropped.push(l.clone()),
        }
    }
    (out, dropped)
}

fn map_severity(s: Option<&str>) -> Result<String, String> {
    match s.map(|x| x.to_ascii_uppercase()).as_deref() {
        None => Err("missing severity".into()),
        Some("ERROR") | Some("CRITICAL") | Some("HIGH") => Ok("ERROR".into()),
        Some("WARNING") | Some("WARN") | Some("MEDIUM") => Ok("WARNING".into()),
        Some("INFO") | Some("LOW") | Some("NOTE") => Ok("INFO".into()),
        Some(other) => Err(format!("unknown severity {other:?}")),
    }
}

/// Flatten portable pattern lists: `{pattern: s}` / `{patterns: [...]}` /
/// `{pattern-either: [...]}` entries, as alternatives (sources/sinks/sanitizers
/// are unions by design, so OR is semantically right here).
fn gather_patterns(m: &Mapping, key: &str) -> Result<Vec<String>, String> {
    let Some(val) = m.get(key) else { return Ok(vec![]) };
    let Some(seq) = val.as_sequence() else {
        return Err(format!("{key} must be a list"));
    };
    let mut out = vec![];
    for (i, item) in seq.iter().enumerate() {
        if let Some(p) = item.as_str() {
            out.push(p.to_string());
            continue;
        }
        let Some(im) = item.as_mapping() else {
            return Err(format!("{key}[{i}] is not a pattern object"));
        };
        if let Some(pv) = im.get("pattern") {
            out.push(pat_str(pv, &format!("{key}[{i}].pattern"))?);
        } else if let Some(ps) = im.get("patterns").and_then(seq_str) {
            out.extend(ps);
        } else if let Some(pe) = im.get("pattern-either") {
            let Some(pes) = pe.as_sequence() else {
                return Err(format!("{key}[{i}].pattern-either must be a list"));
            };
            for (j, e) in pes.iter().enumerate() {
                match e.as_str() {
                    Some(p) => out.push(p.to_string()),
                    None => {
                        let em = e.as_mapping().ok_or_else(|| {
                            format!("{key}[{i}].pattern-either[{j}] unsupported")
                        })?;
                        let pv = em.get("pattern").ok_or_else(|| {
                            format!("{key}[{i}].pattern-either[{j}] unsupported")
                        })?;
                        out.push(pat_str(
                            pv,
                            &format!("{key}[{i}].pattern-either[{j}].pattern"),
                        )?);
                    }
                }
            }
        } else {
            let keys: Vec<&str> = im.keys().filter_map(|k| k.as_str()).collect();
            return Err(format!(
                "{key}[{i}] unsupported construct ({})",
                keys.join(", ")
            ));
        }
    }
    Ok(out)
}

fn mvr_pairs(v: &Value) -> Result<Vec<(String, String)>, String> {
    let Some(m) = v.as_mapping() else {
        return Err("metavariable-regex must be an object".into());
    };
    if let Some(mv) = s(m, "metavariable") {
        // Portable single-constraint form {metavariable, regex}.
        let re = s(m, "regex").ok_or("metavariable-regex missing regex")?;
        return Ok(vec![(mv, re)]);
    }
    // Already a var -> regex map.
    let mut out = vec![];
    for (k, val) in m {
        let (Some(k), Some(re)) = (k.as_str(), val.as_str()) else {
            return Err("malformed metavariable-regex".into());
        };
        out.push((k.to_string(), re.to_string()));
    }
    Ok(out)
}

fn comparison_expr(v: &Value) -> Result<String, String> {
    let Some(m) = v.as_mapping() else {
        return Err("metavariable-comparison must be an object".into());
    };
    let mv = s(m, "metavariable").ok_or("metavariable-comparison missing metavariable")?;
    let cmp = s(m, "comparison").ok_or("metavariable-comparison missing comparison")?;
    Ok(format!("{mv} {cmp}"))
}

/// Translate one portable rule mapping into a native [`Rule`].
/// Returns the rule plus human-readable warnings (dropped languages,
/// ignored fix-regex, non-scalar metadata...).
pub fn translate(v: &Value) -> Result<(Rule, Vec<String>), String> {
    let m = v
        .as_mapping()
        .ok_or_else(|| "rule is not a mapping".to_string())?;
    let mut warnings = vec![];

    let id = s(m, "id").ok_or_else(|| "missing id".to_string())?;
    let message = s(m, "message").ok_or_else(|| format!("rule {id}: missing message"))?;
    let severity = map_severity(m.get("severity").and_then(|x| x.as_str()))
        .map_err(|e| format!("rule {id}: {e}"))?;

    let langs_raw = m
        .get("languages")
        .and_then(seq_str)
        .ok_or_else(|| format!("rule {id}: missing languages"))?;
    let (languages, dropped) = map_languages(&langs_raw);
    if !dropped.is_empty() {
        warnings.push(format!(
            "rule {id}: unsupported language(s) dropped: {}",
            dropped.join(", ")
        ));
    }
    if languages.is_empty() {
        return Err(format!(
            "rule {id}: no supported languages (wanted: {})",
            langs_raw.join(", ")
        ));
    }

    let mut metadata: HashMap<String, String> = HashMap::new();
    if let Some(md) = m.get("metadata").and_then(|x| x.as_mapping()) {
        for (k, val) in md {
            let Some(ks) = k.as_str() else { continue };
            let text = match val {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Sequence(seq) => {
                    let parts: Vec<&str> =
                        seq.iter().filter_map(|x| x.as_str()).collect();
                    if parts.is_empty() {
                        warnings.push(format!("rule {id}: metadata.{ks} dropped (non-scalar)"));
                        continue;
                    }
                    parts.join(", ")
                }
                _ => {
                    warnings.push(format!("rule {id}: metadata.{ks} dropped (non-scalar)"));
                    continue;
                }
            };
            metadata.insert(ks.to_string(), text);
        }
    }
    let fix = s(m, "fix");
    if m.get("fix-regex").is_some() && fix.is_none() {
        warnings.push(format!("rule {id}: fix-regex ignored (no portable equivalent yet)"));
    }

    // --- Taint mode ---------------------------------------------------
    let taint_mode = m.get("mode").and_then(|x| x.as_str()) == Some("taint")
        || m.get("pattern-sources").is_some()
        || m.get("pattern-sinks").is_some();
    let taint = if taint_mode {
        let sources = gather_patterns(m, "pattern-sources")
            .map_err(|e| format!("rule {id}: {e}"))?;
        let sinks =
            gather_patterns(m, "pattern-sinks").map_err(|e| format!("rule {id}: {e}"))?;
        let sanitizers = gather_patterns(m, "pattern-sanitizers")
            .map_err(|e| format!("rule {id}: {e}"))?;
        if sources.is_empty() {
            return Err(format!("rule {id}: taint rule without pattern-sources"));
        }
        if sinks.is_empty() {
            return Err(format!("rule {id}: taint rule without pattern-sinks"));
        }
        Some(TaintSpec {
            sources: vec![TaintPart { patterns: sources }],
            sinks: vec![TaintPart { patterns: sinks }],
            sanitizers: vec![TaintPart { patterns: sanitizers }],
        })
    } else {
        None
    };

    // --- Scan mode ----------------------------------------------------
    let mut pattern: Option<String> = None;
    let mut pattern_either: Option<Vec<PatternChoice>> = None;
    let mut pattern_not: Option<String> = None;
    let mut pattern_inside: Option<String> = None;
    let mut mvr: HashMap<String, String> = HashMap::new();
    let mut comparison: Option<String> = None;

    let set_slot = |slot: &mut Option<String>, val: String, what: &str| -> Result<(), String> {
        if slot.is_some() {
            return Err(format!("rule {id}: multiple {what} not supported"));
        }
        *slot = Some(val);
        Ok(())
    };

    if taint.is_none() {
        if let Some(pv) = m.get("pattern") {
            pattern = Some(pat_str(pv, &format!("rule {id}: pattern"))?);
        } else if let Some(pe) = m.get("pattern-either") {
            let Some(seq) = pe.as_sequence() else {
                return Err(format!("rule {id}: pattern-either must be a list"));
            };
            if seq.is_empty() {
                return Err(format!("rule {id}: empty pattern-either"));
            }
            let mut choices = vec![];
            for (i, e) in seq.iter().enumerate() {
                let p = match e.as_str() {
                    Some(p) => p.to_string(),
                    None => {
                        let em = e
                            .as_mapping()
                            .ok_or_else(|| format!("rule {id}: pattern-either[{i}] unsupported"))?;
                        let pv = em
                            .get("pattern")
                            .ok_or_else(|| format!("rule {id}: pattern-either[{i}] unsupported"))?;
                        pat_str(pv, &format!("rule {id}: pattern-either[{i}].pattern"))?
                    }
                };
                choices.push(PatternChoice::Simple { pattern: p });
            }
            pattern_either = Some(choices);
        } else if let Some(ps) = m.get("patterns") {
            // Portable AND-list.
            let Some(seq) = ps.as_sequence() else {
                return Err(format!("rule {id}: patterns must be a list"));
            };
            let mut positives = vec![];
            for (i, item) in seq.iter().enumerate() {
                let Some(im) = item.as_mapping() else {
                    return Err(format!("rule {id}: patterns[{i}] is not an object"));
                };
                for (k, val) in im {
                    let ks = k.as_str().unwrap_or("");
                    match ks {
                        "pattern" => {
                            positives.push(pat_str(
                                val,
                                &format!("rule {id}: patterns[{i}].pattern"),
                            )?);
                        }
                        "pattern-not" => {
                            let p = pat_str(val, &format!("rule {id}: patterns[{i}].pattern-not"))?;
                            set_slot(&mut pattern_not, p, "pattern-not")?;
                        }
                        "pattern-inside" => {
                            let p = pat_str(
                                val,
                                &format!("rule {id}: patterns[{i}].pattern-inside"),
                            )?;
                            set_slot(&mut pattern_inside, p, "pattern-inside")?;
                        }
                        "metavariable-regex" => {
                            for (mv, re) in mvr_pairs(val).map_err(|e| {
                                format!("rule {id}: patterns[{i}].{e}")
                            })? {
                                mvr.insert(mv, re);
                            }
                        }
                        "metavariable-comparison" => {
                            let e = comparison_expr(val)
                                .map_err(|e| format!("rule {id}: patterns[{i}]: {e}"))?;
                            set_slot(&mut comparison, e, "metavariable-comparison")?;
                        }
                        "pattern-not-inside" | "pattern-regex" => {
                            return Err(format!(
                                "rule {id}: patterns[{i}].{ks} not supported yet"
                            ));
                        }
                        other => {
                            return Err(format!(
                                "rule {id}: patterns[{i}].{other} not supported yet"
                            ));
                        }
                    }
                }
            }
            match positives.len() {
                0 => return Err(format!("rule {id}: no positive pattern in patterns: list")),
                1 => pattern = Some(positives.swap_remove(0)),
                n => {
                    return Err(format!(
                        "rule {id}: {n} AND-ed positive patterns not supported yet \
                         (split the rule or use pattern-either)"
                    ))
                }
            }
        } else {
            return Err(format!(
                "rule {id}: no pattern / pattern-either / patterns / taint construct"
            ));
        }

        // Top-level restrictions (shared key names).
        if let Some(pv) = m.get("pattern-not") {
            set_slot(
                &mut pattern_not,
                pat_str(pv, &format!("rule {id}: pattern-not"))?,
                "pattern-not",
            )?;
        }
        if let Some(pv) = m.get("pattern-inside") {
            set_slot(
                &mut pattern_inside,
                pat_str(pv, &format!("rule {id}: pattern-inside"))?,
                "pattern-inside",
            )?;
        }
        if let Some(v) = m.get("metavariable-regex") {
            for (mv, re) in mvr_pairs(v).map_err(|e| format!("rule {id}: {e}"))? {
                mvr.insert(mv, re);
            }
        }
        if let Some(v) = m.get("metavariable-comparison") {
            let e = comparison_expr(v).map_err(|e| format!("rule {id}: {e}"))?;
            set_slot(&mut comparison, e, "metavariable-comparison")?;
        }
    }

    let rule = Rule {
        id,
        languages,
        severity,
        category: None,
        message,
        fix,
        pattern,
        pattern_either,
        patterns: None,
        pattern_not,
        pattern_inside,
        metavariable_regex: if mvr.is_empty() { None } else { Some(mvr) },
        metavariable_comparison: comparison,
        taint,
        metadata: if metadata.is_empty() { None } else { Some(metadata) },
    };
    rule.validate().map_err(|e| e.to_string())?;
    Ok((rule, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(y: &str) -> Value {
        serde_yaml::from_str(y).expect("valid yaml")
    }

    #[test]
    fn detects_portable_and_translates_conjunction() {
        let v = parse(
            r#"
id: portable-and-example
message: unsafe eval-like call with dynamic code
languages: [python]
severity: ERROR
patterns:
  - pattern: exec($CMD, ...)
  - pattern-not: exec("static", ...)
  - metavariable-regex:
      metavariable: $CMD
      regex: "^\\w+\\("
metadata:
  cwe: CWE-94
"#,
        );
        assert!(looks_portable(&v));
        let (r, warnings) = translate(&v).expect("translates");
        assert_eq!(r.id, "portable-and-example");
        assert_eq!(r.pattern.as_deref(), Some("exec($CMD, ...)"));
        assert_eq!(r.pattern_not.as_deref(), Some(r#"exec("static", ...)"#));
        assert_eq!(
            r.metavariable_regex.as_ref().unwrap().get("$CMD").unwrap(),
            "^\\w+\\("
        );
        assert_eq!(r.metadata.as_ref().unwrap().get("cwe").unwrap(), "CWE-94");
        assert!(warnings.is_empty());
    }

    #[test]
    fn native_schema_not_flagged_portable() {
        let v = parse(
            r#"
id: native-example
languages: [python]
severity: ERROR
message: native
pattern-either:
  - pattern: pickle.loads($X)
  - pattern: yaml.load($X)
"#,
        );
        assert!(!looks_portable(&v));
    }

    #[test]
    fn either_and_comparison() {
        let v = parse(
            r#"
id: portable-either
languages: [go]
severity: WARNING
message: oversized buffer
pattern-either:
  - pattern: make([]byte, $N)
  - pattern: make([]byte, $N, ...)
metavariable-comparison:
  metavariable: $N
  comparison: "> 1024"
"#,
        );
        assert!(looks_portable(&v));
        let (r, _) = translate(&v).unwrap();
        assert_eq!(r.pattern_either.as_ref().unwrap().len(), 2);
        assert_eq!(r.metavariable_comparison.as_deref(), Some("$N > 1024"));
    }

    #[test]
    fn taint_mode_translates() {
        let v = parse(
            r#"
id: portable-taint
mode: taint
languages: [python]
severity: ERROR
message: request data reaches sink
pattern-sources:
  - pattern: request.args.get($K)
pattern-sinks:
  - pattern: cursor.execute($S)
pattern-sanitizers:
  - pattern: escape($V)
"#,
        );
        assert!(looks_portable(&v));
        let (r, _) = translate(&v).unwrap();
        let t = r.taint.as_ref().unwrap();
        assert_eq!(t.sources[0].patterns, vec!["request.args.get($K)"]);
        assert_eq!(t.sinks[0].patterns, vec!["cursor.execute($S)"]);
        assert_eq!(t.sanitizers[0].patterns, vec!["escape($V)"]);
    }

    #[test]
    fn unsupported_construct_skips_with_reason() {
        let v = parse(
            r#"
id: portable-unsupported
languages: [python]
severity: ERROR
message: m
patterns:
  - pattern: os.system($X)
  - pattern-not-inside: "with safe_mode: ..."
"#,
        );
        let err = translate(&v).unwrap_err();
        assert!(err.contains("pattern-not-inside"), "{err}");
    }

    #[test]
    fn unsupported_languages_dropped_or_skip() {
        let v = parse(
            r#"
id: portable-langs
languages: [python, elixir]
severity: ERROR
message: m
pattern: eval($X)
"#,
        );
        // elixir-only would fail; python+elixir keeps python with a warning.
        let (r, warnings) = translate(&v).unwrap();
        assert_eq!(r.languages, vec!["python"]);
        assert!(warnings[0].contains("elixir"));

        let v2 = parse(
            r#"
id: portable-langs2
languages: [rust]
severity: ERROR
message: m
pattern: eval($X)
"#,
        );
        assert!(translate(&v2).unwrap_err().contains("no supported languages"));
    }

    #[test]
    fn cpp_language_mapped() {
        let v = parse(
            r#"
id: portable-cpp
languages: [cpp]
severity: ERROR
message: m
pattern: eval($X)
"#,
        );
        let (r, warnings) = translate(&v).unwrap();
        assert_eq!(r.languages, vec!["cpp"]);
        assert!(warnings.is_empty());

        let v2 = parse(
            r#"
id: portable-cpp-alt
languages: [c++]
severity: ERROR
message: m
pattern: eval($X)
"#,
        );
        let (r2, warnings2) = translate(&v2).unwrap();
        assert_eq!(r2.languages, vec!["cpp"]);
        assert!(warnings2.is_empty());
    }

    #[test]
    fn multi_positive_and_rejected() {
        let v = parse(
            r#"
id: portable-multi
languages: [python]
severity: ERROR
message: m
patterns:
  - pattern: a($X)
  - pattern: b($Y)
"#,
        );
        let err = translate(&v).unwrap_err();
        assert!(err.contains("AND-ed"), "{err}");
    }
}
