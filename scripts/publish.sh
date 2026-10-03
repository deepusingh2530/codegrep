#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order.
# Requires: cargo login (or CARGO_REGISTRY_TOKEN in env).
# Safe to re-run: already-published versions are skipped.
set -euo pipefail
cd "$(dirname "$0")/.."

order=(cg-parser cg-deps cg-rules cg-ir cg-taint cg-matcher scanward)

crate_version() {
  grep -m1 '^version = ' "crates/$1/Cargo.toml" | cut -d'"' -f2
}

# Ask the registry (not the local workspace) whether the version is live.
# Uses the sparse index CDN: `cargo search` gets rate-limited from cloud
# runner IPs, which previously caused "already exists" publish failures.
# (Note: never name a local `path` — it clobbers PATH in zsh/ksh.)
published() {
  local c="$1" v="$2" idx
  case "${#c}" in
    1) idx="1/$c" ;;
    2) idx="2/$c" ;;
    3) idx="3/${c:0:1}/$c" ;;
    *) idx="${c:0:2}/${c:2:2}/$c" ;;
  esac
  curl -fsS "https://index.crates.io/$idx" 2>/dev/null | grep -q "\"vers\":\"$v\""
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
  # Tolerate the index-lag race: if the upload says it already exists,
  # another run beat us — that is success, not failure.
  if ! pub_out="$(cargo publish -p "$c" 2>&1)"; then
    if printf '%s\n' "$pub_out" | grep -q "already exists"; then
      echo "==> $c $v is already on the index, continuing"
    else
      printf '%s\n' "$pub_out" >&2
      exit 1
    fi
  else
    printf '%s\n' "$pub_out"
  fi
  if [ "$c" != "scanward" ]; then
    wait_indexed "$c" "$v"
  fi
done

echo "all crates published"
