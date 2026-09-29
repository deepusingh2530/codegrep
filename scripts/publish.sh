#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order.
# Requires: cargo login (or CARGO_REGISTRY_TOKEN in env).
# Safe to re-run: already-published versions are skipped.
set -euo pipefail
cd "$(dirname "$0")/.."

order=(cg-parser cg-rules cg-ir cg-taint cg-matcher codegrep)

crate_version() {
  grep -m1 '^version = ' "crates/$1/Cargo.toml" | cut -d'"' -f2
}

# Ask the registry (not the local workspace) whether the version is live.
published() {
  cargo search "$1" 2>/dev/null | grep -q "^$1 = \"$2\""
}

wait_indexed() {
  local c="$1" v="$2"
  for _ in $(seq 1 30); do
    if published "$c" "$v"; then
      return 0
    fi
    sleep 10
  done
  echo "error: $c $v did not appear in the crates.io index" >&2
  return 1
}

for c in "${order[@]}"; do
  v="$(crate_version "$c")"
  if published "$c" "$v"; then
    echo "==> $c $v already published, skipping"
    continue
  fi
  echo "==> publishing $c $v"
  cargo publish -p "$c"
  if [ "$c" != "codegrep" ]; then
    wait_indexed "$c" "$v"
  fi
done

echo "all crates published"
