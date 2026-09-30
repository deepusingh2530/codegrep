#!/usr/bin/env python3
"""Weekly CVE watch for codegrep.

Fetches recent CRITICAL/HIGH CVEs from the NVD 2.0 API, maps their CWEs
against the codegrep rule corpus, and writes a markdown coverage report.

This does NOT feed vulnerability data into the scanner: codegrep stays fully
offline. The report drives *rule authoring* — new patterns for vulnerability
classes that recent CVEs exercise but no rule covers yet. Dependency CVEs in
scanned projects are handled by the SCA sidecar (osv-scanner); CVEs in
codegrep's own Rust dependencies are handled by `cargo audit`.

Usage:
    python3 scripts/cve_watch.py --days 7 --out docs/cve-coverage.md
    python3 scripts/cve_watch.py --json /tmp/watch.json --top 0   # full list
    NVD_API_KEY=... python3 scripts/cve_watch.py                  # optional

Exit codes: 0 on success (report-only; gaps never fail the run),
1 on usage errors. NVD unreachable -> warning report, exit 0, so the
release cadence is never blocked by a third-party outage.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("need pyyaml: python3 -m pip install pyyaml")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "codegrep-cve-watch (weekly coverage report; offline SAST)"
CWE_RE = re.compile(r"CWE-\d+")


def iso(d: dt.datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_severity(severity: str, start: dt.datetime, end: dt.datetime,
                   api_key: str | None) -> dict:
    params = urllib.parse.urlencode({
        "pubStartDate": iso(start),
        "pubEndDate": iso(end),
        "cvssV3Severity": severity,
        "resultsPerPage": "2000",
    })
    headers = {"User-Agent": UA}
    if api_key:
        headers["apiKey"] = api_key
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(f"{NVD_URL}?{params}", headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except Exception as e:  # noqa: BLE001 — report-only tool: degrade gracefully
            last_err = e
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(str(last_err))


def parse_cve(vuln: dict) -> dict:
    c = vuln["cve"]
    score, sev = 0.0, ""
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = float(data.get("baseScore") or 0)
            sev = (m.get("baseSeverity") or data.get("baseSeverity") or "").upper()
            break
    desc = ""
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cwes: set[str] = set()
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            cwes.update(CWE_RE.findall(d.get("value", "")))
    return {
        "id": c["id"],
        "published": c.get("published", "")[:10],
        "score": score,
        "severity": sev,
        "cwes": sorted(cwes),
        "desc": desc.strip().split(". ")[0][:160],
    }


def load_corpus(rules_dir: str) -> tuple[dict[str, set[str]], int, int]:
    """Return (cwe -> rule ids, total rules, rules carrying CWE metadata)."""
    by_cwe: dict[str, set[str]] = defaultdict(set)
    total = 0
    with_cwe = 0
    for f in sorted(Path(rules_dir).rglob("*.yaml")):
        if "tests" in f.parts:
            continue
        try:
            data = yaml.safe_load(f.read_text())
        except Exception as e:  # noqa: BLE001
            print(f"warning: cannot parse {f}: {e}", file=sys.stderr)
            continue
        docs = data if isinstance(data, list) else [data]
        for rule in docs:
            if not isinstance(rule, dict) or "id" not in rule:
                continue
            total += 1
            meta = rule.get("metadata") or {}
            raw = meta.get("cwe", "") or rule.get("cwe", "")
            found = set(CWE_RE.findall(str(raw)))
            if found:
                with_cwe += 1
            for cwe in found:
                by_cwe[cwe].add(rule["id"])
    return by_cwe, total, with_cwe


def build_report(cves: list[dict], by_cwe: dict[str, set[str]], total: int,
                 with_cwe: int, start: dt.datetime, end: dt.datetime,
                 note: str, top_n: int = 40) -> str:
    crit = sum(1 for c in cves if c["severity"] == "CRITICAL")
    high = sum(1 for c in cves if c["severity"] == "HIGH")
    observed = sorted({w for c in cves for w in c["cwes"]})
    covered = [w for w in observed if w in by_cwe]
    gaps = [w for w in observed if w not in by_cwe]
    gap_counts = {w: sum(1 for c in cves if w in c["cwes"]) for w in gaps}
    gap_examples = {
        w: [c["id"] for c in sorted(cves, key=lambda x: -x["score"]) if w in c["cwes"]][:3]
        for w in gaps
    }
    top = sorted(cves, key=lambda c: (-c["score"], c["id"]))

    L = [
        "# CVE watch — weekly coverage report",
        "",
        f"- Generated: {end.date()} (UTC) | Window: {start.date()} → {end.date()} "
        f"(last {(end - start).days} days)",
        "- Source: NVD 2.0 API (CRITICAL + HIGH, published in window)",
        f"{note}",
        "",
        "> codegrep is pattern-based SAST: it flags vulnerability *classes* in code,",
        "> not per-product advisories. **Gap** below = a CWE exercised by recent CVEs",
        "> with no matching rule yet → candidate for `scripts/specs/` + `mkrules.py`.",
        "> Dependency advisories for scanned projects: `codegrep scan --only sca`",
        "> (osv-scanner). codegrep's own deps: `cargo audit` in the weekly run.",
        "",
        "## Window summary",
        "",
        f"| Metric | Value |",
        f"| --- | --- |",
        f"| New CVEs in window | **{len(cves)}** ({crit} critical / {high} high) |",
        f"| Distinct CWEs observed | {len(observed)} |",
        f"| Covered by ≥1 rule | {len(covered)} |",
        f"| **Coverage gaps** | **{len(gaps)}** |",
        f"| Rule corpus | {total} rules, {with_cwe} carrying CWE metadata |",
        "",
    ]
    if gaps:
        L += [
            "## Coverage gaps (candidate new rules)",
            "",
            "| CWE | Recent CVEs using it | Example CVEs |",
            "| --- | --- | --- |",
        ]
        for w in sorted(gaps, key=lambda x: (-gap_counts[x], x)):
            L.append(f"| {w} | {gap_counts[w]} | {', '.join(gap_examples[w])} |")
        L += [
            "",
            "To close a gap: write an original spec at `scripts/specs/gap-sec-*.json`,",
            "run `python3 scripts/mkrules.py <spec>` (generates rule + fail/pass",
            "fixtures), then `codegrep rule test rules/` — CI requires fixtures for",
            "every rule.",
            "",
        ]
    if covered:
        L += ["## Covered CWEs (recent CVEs already matched by rules)", ""]
        L += [f"- **{w}** → {', '.join(sorted(by_cwe[w])[:4])}"
              f"{' …' if len(by_cwe[w]) > 4 else ''}" for w in covered]
        L.append("")
    cap = min(top_n, len(top)) if top_n else len(top)
    L += [f"## Recent CVEs by score ({cap} of {len(top)})", "",
          "| CVE | Score | Severity | CWEs | Coverage | Description |",
          "| --- | --- | --- | --- | --- | --- |"]
    for c in top[:cap]:
        cov = ("covered" if any(w in by_cwe for w in c["cwes"])
               else "GAP" if c["cwes"] else "n/a")
        L.append(f"| {c['id']} | {c['score']} | {c['severity']} | "
                 f"{', '.join(c['cwes']) or '—'} | {cov} | {c['desc']} |")
    L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=7, help="look-back window (max 120)")
    ap.add_argument("--rules", default="rules", help="rule corpus directory")
    ap.add_argument("--out", default=None, help="write markdown report here")
    ap.add_argument("--json", default=None, help="write machine-readable results here")
    ap.add_argument("--top", type=int, default=40, help="0 = full CVE list in report")
    args = ap.parse_args()
    if not 1 <= args.days <= 120:
        ap.error("--days must be 1..120 (NVD window limit)")

    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=args.days)
    by_cwe, total, with_cwe = load_corpus(args.rules)

    cves: list[dict] = []
    error_note = ""
    try:
        for sev in ("CRITICAL", "HIGH"):
            data = fetch_severity(sev, start, now,
                                  os.environ.get("NVD_API_KEY"))
            cves.extend(parse_cve(v) for v in data.get("vulnerabilities", []))
            time.sleep(6 if not os.environ.get("NVD_API_KEY") else 1)
    except Exception as e:  # noqa: BLE001 — outage must not block cadence
        error_note = f"- **NVD fetch failed** ({e}) — report may be incomplete."
        print(f"warning: {error_note}", file=sys.stderr)

    seen: set[str] = set()
    uniq = [c for c in cves if not (c["id"] in seen or seen.add(c["id"]))]
    report = build_report(uniq, by_cwe, total, with_cwe, start, now,
                          error_note, args.top)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report)
        print(f"wrote {args.out} ({len(uniq)} CVEs)", file=sys.stderr)
    else:
        print(report)
    if args.json:
        Path(args.json).write_text(json.dumps({
            "window": {"start": start.isoformat(), "end": now.isoformat(),
                       "days": args.days},
            "cves": uniq,
            "corpus": {"rules": total, "with_cwe": with_cwe},
            "coverage": {
                "observed_cwes": sorted({w for c in uniq for w in c["cwes"]}),
                "gaps": sorted({w for c in uniq for w in c["cwes"]} - set(by_cwe)),
            },
            "error": error_note or None,
        }, indent=2))
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
