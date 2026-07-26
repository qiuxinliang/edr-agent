#!/usr/bin/env bash
# Copy listed source files under edr-agent/tmp/backup-<timestamp>/ preserving tree layout.
# Usage (from edr-agent repo root):
#   ./scripts/backup_sources_to_tmp.sh src/foo.c src/bar.c
# Paths are relative to edr-agent root. /tmp is gitignored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="${ROOT}/tmp/backup-${STAMP}"
mkdir -p "${DEST}"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <path> [path...]  (each path relative to edr-agent root)" >&2
  exit 1
fi

for rel in "$@"; do
  rel="${rel#./}"
  src="${ROOT}/${rel}"
  if [[ ! -f "${src}" ]]; then
    echo "backup_sources_to_tmp: skip (not a file): ${rel}" >&2
    continue
  fi
  case "${src}" in
    "${ROOT}"/*) ;;
    *)
      echo "backup_sources_to_tmp: skip (outside edr-agent): ${rel}" >&2
      continue
      ;;
  esac
  d="${DEST}/$(dirname "${rel}")"
  mkdir -p "${d}"
  cp -p "${src}" "${DEST}/${rel}"
  echo "backed up: ${rel}"
done

echo "Backup directory: ${DEST}"
