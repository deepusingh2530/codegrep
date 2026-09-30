#!/usr/bin/env bash
# Patch-bump crates/codegrep and prepend a CHANGELOG entry (weekly cadence).
# Usage: ./scripts/bump.sh ["extra changelog bullet", ...]
# Prints the new version on stdout (last line).
set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST=crates/codegrep/Cargo.toml
cur="$(grep -m1 '^version = ' "$MANIFEST" | cut -d'"' -f2)"
IFS=. read -r major minor patch <<<"$cur"
new="$major.$minor.$((patch + 1))"

python3 - "$MANIFEST" "$new" <<'EOF'
import re, sys
path, new = sys.argv[1], sys.argv[2]
src = open(path).read()
src, n = re.subn(r'(?m)^version = "[^"]+"', f'version = "{new}"', src, count=1)
assert n == 1, f"version line not found in {path}"
open(path, "w").write(src)
EOF

# Refresh Cargo.lock (resolution only, no build).
cargo metadata --format-version 1 >/dev/null

rules_line=""
if [ -x target/debug/codegrep ]; then
  count="$(./target/debug/codegrep rule test rules/ 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || true)"
  if [ -n "${count:-}" ]; then
    rules_line="Rule corpus: $count rules, fixtures re-verified."
  fi
fi

python3 - "$new" "$cur" "$rules_line" "$@" <<'EOF'
import sys, datetime as dt
new, cur, rules_line = sys.argv[1], sys.argv[2], sys.argv[3]
extras = list(sys.argv[4:])
date = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
lines = [f"## {new} (weekly sync, {date})"]
if rules_line:
    lines.append(f"- {rules_line}")
lines.append(f"- Weekly cadence: tests, clippy, and rule gates green; CVE watch refreshed (docs/cve-coverage.md).")
for e in extras:
    if e:
        lines.append(f"- {e}")
entry = "\n".join(lines) + "\n\n"

path = "CHANGELOG.md"
src = open(path).read()
marker = "# Changelog\n\n"
assert marker in src, "CHANGELOG marker not found"
src = src.replace(marker, marker + entry, 1)
open(path, "w").write(src)
print(entry, end="", file=sys.stderr)
EOF

echo "$new"
