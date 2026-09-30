#!/usr/bin/env python3
"""Generate codegrep rules + pass/fail fixtures from a compact JSON spec table.

This is original tooling for writing project-licensed rules from scratch. It does NOT
read or copy any third-party rule content.

Usage:
    python3 scripts/mkrules.py <specs.json>

specs.json = [ {spec}, ... ] where each spec has:
    id          unique, filesystem-safe (no slashes), required
    languages   list of language names, required (first = directory)
    severity    ERROR | WARNING | INFO
    category    e.g. "security:code-execution"
    message     human message
    fix         remediation string (optional)
    pattern     single pattern string            (XOR)
    either      list of pattern strings          (XOR)
    taint       {sources:[{patterns:[..]}], sinks:[...], sanitizers:[...]}  (XOR)
    not         optional pattern-not string
    inside      optional pattern-inside string
    mvr         optional {metavariable: regex}
    metadata    optional {owasp, cwe, confidence, ...}
    fail        fail-fixture source (must trigger)
    pass        pass-fixture source (must stay clean)
    ext         optional fixture extension override
    group       optional rule-file basename (default: id) to batch rules together

Writes rules/<lang>/<group>.yaml and rules/tests/<id>/fail.<ext>, pass.<ext>.
"""
import json
import os
import re
import sys

RULES_ROOT = "rules"
TESTS_ROOT = os.path.join("rules", "tests")

LANG_EXT = {
    "python": "py", "javascript": "js", "typescript": "ts", "go": "go",
    "java": "java", "ruby": "rb", "php": "php", "csharp": "cs",
    "terraform": "tf", "yaml": "yaml", "dockerfile": "Dockerfile",
    "scala": "scala", "c": "c", "ocaml": "ml", "kotlin": "kt",
    "bash": "sh", "json": "json", "html": "html", "generic": "txt",
    "rust": "rs", "swift": "swift", "dart": "dart", "elixir": "ex",
    "lua": "lua", "powershell": "ps1", "sql": "sql",
}


def q(s: str) -> str:
    """Double-quoted YAML scalar."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def emit_yaml(spec: dict) -> str:
    langs = spec["languages"]
    out = []
    out.append(f"id: {q(spec['id'])}")
    out.append("languages: [" + ", ".join(q(l) for l in langs) + "]")
    out.append(f"severity: {q(spec['severity'])}")
    if spec.get("category"):
        out.append(f"category: {q(spec['category'])}")
    out.append(f"message: {q(spec['message'])}")
    if spec.get("fix"):
        out.append(f"fix: {q(spec['fix'])}")

    if spec.get("pattern") is not None:
        out.append(f"pattern: {q(spec['pattern'])}")
    elif spec.get("either"):
        out.append("pattern-either:")
        for p in spec["either"]:
            out.append(f"  - pattern: {q(p)}")
    elif spec.get("taint"):
        t = spec["taint"]
        out.append("taint:")
        for part in ("sources", "sinks", "sanitizers"):
            if t.get(part):
                out.append(f"  {part}:")
                for grp in t[part]:
                    out.append("    - patterns: [" +
                               ", ".join(q(x) for x in grp["patterns"]) + "]")
    else:
        raise SystemExit(f"{spec['id']}: spec needs pattern / either / taint")

    if spec.get("not"):
        out.append(f"pattern-not: {q(spec['not'])}")
    if spec.get("inside"):
        out.append(f"pattern-inside: {q(spec['inside'])}")
    if spec.get("mvr"):
        out.append("metavariable-regex:")
        for k, v in spec["mvr"].items():
            out.append(f"  {q(k)}: {q(v)}")
    if spec.get("metadata"):
        out.append("metadata:")
        for k, v in spec["metadata"].items():
            out.append(f"  {q(k)}: {q(v)}")
    return "\n".join(out) + "\n"


def run(specs: list) -> None:
    # Group rules by target file so we can batch multiple rules per YAML file.
    by_file = {}
    for spec in specs:
        for req in ("id", "languages", "severity", "message", "fail", "pass"):
            if not spec.get(req):
                raise SystemExit(f"spec missing {req}: {spec.get('id')}")
        lang = spec["languages"][0]
        group = spec.get("group") or spec["id"]
        by_file.setdefault((lang, group), []).append(spec)

    n_rules = 0
    for (lang, group), group_specs in sorted(by_file.items()):
        lang_dir = os.path.join(RULES_ROOT, lang)
        os.makedirs(lang_dir, exist_ok=True)
        docs = [emit_yaml(s).rstrip("\n") for s in group_specs]
        path = os.path.join(lang_dir, f"{group}.yaml")
        if os.path.exists(path):
            # Never silently clobber a pre-existing group file: all spec ids
            # must already be present (idempotent regen), otherwise abort and
            # ask for a fresh group name. (A missing guard here wiped 9 rules.)
            with open(path) as f:
                existing = set(re.findall(r'^-?\s*id:\s*"?([^"\n]+)"?\s*$', f.read(), re.M))
            missing = [s["id"] for s in group_specs if s["id"] not in existing]
            if missing:
                raise SystemExit(
                    f"{path} exists but lacks {missing}; "
                    f"use a new group name (would overwrite {len(existing)} rules)"
                )
        if len(docs) == 1:
            content = docs[0] + "\n"
        else:
            # Serialize as a YAML sequence: each rule is a "- " list item.
            items = []
            for d in docs:
                lines = d.split("\n")
                head = "- " + lines[0]
                tail = "\n".join(("  " + l) if l else l for l in lines[1:])
                items.append(head + ("\n" + tail if tail else ""))
            content = "\n".join(items) + "\n"
        with open(path, "w") as f:
            f.write(content)

        for s in group_specs:
            ext = s.get("ext") or LANG_EXT.get(lang, "txt")
            tdir = os.path.join(TESTS_ROOT, s["id"])
            os.makedirs(tdir, exist_ok=True)
            with open(os.path.join(tdir, f"fail.{ext}"), "w") as f:
                f.write(s["fail"] if s["fail"].endswith("\n") else s["fail"] + "\n")
            with open(os.path.join(tdir, f"pass.{ext}"), "w") as f:
                f.write(s["pass"] if s["pass"].endswith("\n") else s["pass"] + "\n")
            n_rules += 1
    print(f"wrote {n_rules} rules in {len(by_file)} file(s)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    with open(sys.argv[1]) as f:
        run(json.load(f))
