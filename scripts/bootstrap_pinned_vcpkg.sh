#!/usr/bin/env bash
# Bootstrap the exact vcpkg revision named by the Agent dependency authority.
# Production Linux matcher builds call this before the isolated PCRE2 producer;
# a moving vcpkg clone is not acceptable input for release provenance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
VCPKG_ROOT=""

usage() {
  echo "usage: $0 [--vcpkg-root PATH]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vcpkg-root)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      VCPKG_ROOT="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

command -v git >/dev/null 2>&1 || { echo "missing git" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing python3" >&2; exit 2; }

if [[ -z "$VCPKG_ROOT" ]]; then
  VCPKG_ROOT="$ROOT/vcpkg"
fi
mkdir -p "$VCPKG_ROOT"
VCPKG_ROOT="$(cd "$VCPKG_ROOT" && pwd -P)"

BASELINE="$(python3 - "$ROOT/dependencies.lock.json" "$ROOT/vcpkg.json" <<'PY'
import json
import re
import sys

lock_path, manifest_path = sys.argv[1:]
with open(lock_path, encoding="utf-8") as handle:
    lock = json.load(handle)
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)
baseline = lock.get("vcpkg", {}).get("builtin_baseline")
if (lock.get("schema") != "edr.native-dependencies.lock.v1" or
        not isinstance(baseline, str) or
        re.fullmatch(r"[0-9a-f]{40}", baseline) is None or
        manifest.get("builtin-baseline") != baseline):
    raise SystemExit("Agent dependency authority has no matching vcpkg baseline")
print(baseline)
PY
)"

if [[ ! -d "$VCPKG_ROOT/.git" ]]; then
  if [[ -n "$(find "$VCPKG_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "vcpkg root exists but is not a Git checkout: $VCPKG_ROOT" >&2
    exit 2
  fi
  git -C "$VCPKG_ROOT" init --quiet
  git -C "$VCPKG_ROOT" remote add origin https://github.com/microsoft/vcpkg.git
fi

if ! ORIGIN="$(git -C "$VCPKG_ROOT" remote get-url origin 2>/dev/null)"; then
  git -C "$VCPKG_ROOT" remote add origin https://github.com/microsoft/vcpkg.git
  ORIGIN="https://github.com/microsoft/vcpkg.git"
fi
case "${ORIGIN%/}" in
  https://github.com/microsoft/vcpkg|https://github.com/microsoft/vcpkg.git|git@github.com:microsoft/vcpkg.git|ssh://git@github.com:microsoft/vcpkg.git) ;;
  *)
    echo "vcpkg origin is not official microsoft/vcpkg: $ORIGIN" >&2
    exit 2
    ;;
esac

git -C "$VCPKG_ROOT" fetch --depth 1 origin "$BASELINE"
git -C "$VCPKG_ROOT" checkout --detach --force FETCH_HEAD
ACTUAL="$(git -C "$VCPKG_ROOT" rev-parse HEAD)"
if [[ "$ACTUAL" != "$BASELINE" ]]; then
  echo "vcpkg checkout mismatch: expected=$BASELINE actual=$ACTUAL" >&2
  exit 2
fi
if [[ -n "$(git -C "$VCPKG_ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo "vcpkg checkout has tracked or untracked modifications: $VCPKG_ROOT" >&2
  exit 2
fi
if [[ ! -x "$VCPKG_ROOT/bootstrap-vcpkg.sh" ]]; then
  echo "pinned vcpkg checkout lacks bootstrap-vcpkg.sh" >&2
  exit 2
fi
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
echo "Pinned vcpkg ready: commit=$BASELINE root=$VCPKG_ROOT"
