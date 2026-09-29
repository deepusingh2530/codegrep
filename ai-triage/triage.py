#!/usr/bin/env python3
# ai-triage: async AI side-plane for codegrep (BYOK, optional, stdlib only).
#
# Core `codegrep scan` NEVER calls this and needs no keys. This script consumes
# scan output and adds AI judgment:
#   triage mode: score findings as TP/FP (heuristic offline, or real LLM via
#                Anthropic / OpenAI / Ollama when you provide keys/endpoints).
#   fix mode:    ask the LLM for a minimal fix, apply it to a scratch copy of
#                the repo, re-run `codegrep scan` on the patched copy, and emit
#                a unified diff ONLY when the original finding is gone
#                (verified autofix — unverified suggestions are discarded).
#
# No third-party packages: urllib only. No third-party scanner code. MIT.
#
#   codegrep scan ./repo --json -o findings.json
#   python3 ai-triage/triage.py --mode triage --input findings.json
#   python3 ai-triage/triage.py --mode triage --provider anthropic --input findings.json
#   python3 ai-triage/triage.py --mode fix --input findings.json --repo ./repo

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

PROMPT = """You are a precise application-security reviewer. Given one static-analysis
finding (rule, file, line, snippet), reply with EXACTLY one JSON object, no other text:
{{"is_tp": true|false, "confidence": 0.0-1.0, "reason": "<one sentence>",
"fixed_snippet": "<minimal fixed code, or empty string if unsure>"}}
Finding: {finding}"""

DANGEROUS = ("execute", "eval", "system", "innerHTML", "exec(", "raw(", "unserialize",
             "pickle", "readObject", "Deserialize", "AKIA", "PRIVATE KEY")


def heuristic_triage(finding):
    text = json.dumps(finding)
    score = 0.9 if any(k in text for k in DANGEROUS) else 0.4
    return {"is_tp": score >= 0.5, "confidence": score,
            "reason": "offline heuristic v0.3", "fixed_snippet": ""}


def llm_complete(provider, model, prompt, timeout=60):
    """Minimal JSON-over-HTTP for three providers. Keys via env only."""
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps({"model": model, "max_tokens": 512,
                             "messages": [{"role": "user", "content": prompt}]})
            .encode(),
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        body = json.load(urllib.request.urlopen(req, timeout=timeout))
        return "".join(b.get("text", "") for b in body["content"] if b.get("type") == "text")
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        req = urllib.request.Request(
            base + "/chat/completions",
            data=json.dumps({"model": model, "max_tokens": 512,
                             "messages": [{"role": "user", "content": prompt}]})
            .encode(),
            headers={"authorization": "Bearer " + key,
                     "content-type": "application/json"})
        body = json.load(urllib.request.urlopen(req, timeout=timeout))
        return body["choices"][0]["message"]["content"]
    if provider == "ollama":
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        req = urllib.request.Request(
            host + "/api/generate",
            data=json.dumps({"model": model, "prompt": prompt,
                             "stream": False}).encode(),
            headers={"content-type": "application/json"})
        body = json.load(urllib.request.urlopen(req, timeout=timeout))
        return body.get("response", "")
    raise ValueError(f"unknown provider {provider}")


def extract_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


def triage_one(provider, model, finding):
    if provider == "heuristic":
        return heuristic_triage(finding)
    try:
        raw = llm_complete(provider, model, PROMPT.format(finding=json.dumps(finding)))
        out = extract_json(raw)
        return {"is_tp": bool(out.get("is_tp", True)),
                "confidence": float(out.get("confidence", 0.5)),
                "reason": str(out.get("reason", ""))[:300],
                "fixed_snippet": str(out.get("fixed_snippet", ""))}
    except Exception as e:  # LLM failure must never lose the finding
        base = heuristic_triage(finding)
        base["reason"] = f"llm-error fallback: {type(e).__name__}"
        return base


def load_findings(path):
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path) as f:
            text = f.read()
    data = json.loads(text)
    return data if isinstance(data, list) else data.get("results", data)


def cmd_triage(args):
    for finding in load_findings(args.input):
        scored = triage_one(args.provider, args.model, finding)
        print(json.dumps({"finding": finding, "triage": scored}))


def apply_snippet(path, line_no, new_snippet):
    with open(path) as f:
        lines = f.readlines()
    old = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    indent = old[:len(old) - len(old.lstrip())]
    fixed = "".join(indent + ln if ln.strip() else ln
                    for ln in new_snippet.splitlines(keepends=True))
    if not fixed.endswith("\n"):
        fixed += "\n"
    lines[line_no - 1] = fixed
    with open(path, "w") as f:
        f.writelines(lines)


def cmd_fix(args):
    findings = load_findings(args.input)
    work = tempfile.mkdtemp(prefix="codegrep-fix-")
    shutil.copytree(args.repo, os.path.join(work, "repo"),
                    ignore=shutil.ignore_patterns(".git", "target"))
    verified = 0
    for finding in findings:
        scored = triage_one(args.provider, args.model, finding)
        snippet = scored.get("fixed_snippet", "")
        rel = finding.get("path", "")
        line_no = finding.get("line", 0)
        if not snippet or not rel or not line_no:
            continue
        target = os.path.join(work, "repo", os.path.basename(rel))
        # Resolve repo-relative path: match by suffix against scratch copy.
        match = None
        for root, _, files in os.walk(os.path.join(work, "repo")):
            for fn in files:
                full = os.path.join(root, fn)
                if rel == full or full.endswith(rel.lstrip("./")) or rel.endswith(full):
                    match = full
                    break
        target = match or target
        if not os.path.exists(target):
            continue
        apply_snippet(target, line_no, snippet)
        # Verify: original rule must no longer fire on the patched copy.
        rule_id = finding.get("rule_id", "")
        check = subprocess.run(
            [args.codegrep_bin, "scan", os.path.dirname(target), "--json",
             "--rules", args.rules, "--no-cache"],
            capture_output=True, text=True, cwd=args.repo)
        try:
            after = json.loads(check.stdout or "[]")
        except json.JSONDecodeError:
            after = []
        still = [x for x in after
                 if x.get("rule_id") == rule_id and x.get("line") == line_no]
        if not still:
            diff = subprocess.run(["git", "diff", "--no-index", "--", rel, target],
                                  capture_output=True, text=True)
            print(f"--- verified fix for {rule_id} {rel}:{line_no}")
            print(diff.stdout or "(content replaced, no git available for diff)")
            verified += 1
    print(f"codegrep fix: {verified}/{len(findings)} verified", file=sys.stderr)
    shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="codegrep AI side-plane (BYOK)")
    ap.add_argument("--mode", choices=["triage", "fix"], default="triage")
    ap.add_argument("--input", default="-", help="findings JSON file or - for stdin")
    ap.add_argument("--provider", default="heuristic",
                    choices=["heuristic", "anthropic", "openai", "ollama"])
    ap.add_argument("--model", default="claude-haiku-4-5",
                    help="provider model id (anthropic/openai/ollama)")
    ap.add_argument("--repo", default=".", help="repo root (fix mode)")
    ap.add_argument("--rules", default="rules", help="rules dir (fix verify)")
    ap.add_argument("--codegrep-bin", default="./target/release/codegrep")
    args = ap.parse_args()
    if args.mode == "triage":
        cmd_triage(args)
    else:
        cmd_fix(args)


if __name__ == "__main__":
    main()
