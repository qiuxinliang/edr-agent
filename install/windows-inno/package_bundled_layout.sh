#!/usr/bin/env bash
# Full Windows endpoint payload (zip) — matches EDRAgentSetup.bundled.iss [Files] under {app}.
# See bundle_extra/BUNDLE_README.txt for what this bundle covers vs platform-only artifacts.
#
# Usage:
#   ./package_bundled_layout.sh
#   EDR_BIN_DIR=/path/to/stage EDR_BUNDLE_STRICT=1 ./package_bundled_layout.sh
# EDR_BUNDLE_STRICT=1: fail if models miss behavior.onnx or if no static-capable .onnx is present
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_DIR="${EDR_BIN_DIR:-"$REPO_ROOT/edr-agent-win_2-2"}"
EDR_AGENT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_NAME="${EDR_BUNDLE_ZIP_NAME:-EDRAgent-bundled-payload-win-amd64}"
OUT_DIR="$SCRIPT_DIR/Output/${OUT_NAME}"
ZIP_PATH="$SCRIPT_DIR/Output/${OUT_NAME}.zip"
STRICT="${EDR_BUNDLE_STRICT:-0}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/models" "$OUT_DIR/data"

if [[ ! -d "$STAGE_DIR" ]]; then
  echo "Error: STAGE_DIR not found: $STAGE_DIR" >&2
  echo "Set EDR_BIN_DIR to your folder with edr_agent.exe and .dll" >&2
  exit 1
fi
if [[ ! -f "$STAGE_DIR/edr_agent.exe" ]]; then
  echo "Error: missing: $STAGE_DIR/edr_agent.exe" >&2
  exit 1
fi

# --- Binaries (Inno EDR_BIN_DIR) ---
cp -a "$STAGE_DIR/edr_agent.exe" "$OUT_DIR/"
if [[ -f "$STAGE_DIR/edr_monitor.exe" ]]; then
  cp -a "$STAGE_DIR/edr_monitor.exe" "$OUT_DIR/"
fi
shopt -s nullglob
DLL_COUNT=0
for f in "$STAGE_DIR"/*.dll; do
  cp -a "$f" "$OUT_DIR/"
  DLL_COUNT=$((DLL_COUNT + 1))
done
shopt -u nullglob
if [[ "$DLL_COUNT" -lt 1 ]]; then
  echo "Warning: no .dll next to edr_agent.exe; Windows runtime will not start." >&2
fi

# models: recursive (onnx, pca_*.npy, etc.)
if [[ -d "$EDR_AGENT_DIR/models" ]]; then
  cp -a "$EDR_AGENT_DIR/models/." "$OUT_DIR/models/"
fi

PREP_TOML="$REPO_ROOT/edr-backend/platform/config/agent_preprocess_rules_v1.toml"
if [[ -f "$PREP_TOML" ]]; then
  cp -a "$PREP_TOML" "$OUT_DIR/agent_preprocess_rules_v1.toml"
else
  echo "Error: missing preprocess rules: $PREP_TOML" >&2
  exit 1
fi

if [[ -f "$EDR_AGENT_DIR/agent.toml.example" ]]; then
  cp -a "$EDR_AGENT_DIR/agent.toml.example" "$OUT_DIR/"
fi
if [[ -f "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" ]]; then
  cp -a "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" "$OUT_DIR/"
fi
for n in "edr_install_wizard_enroll.ps1" "edr_windows_autorun.ps1"; do
  if [[ -f "$SCRIPT_DIR/$n" ]]; then
    cp -a "$SCRIPT_DIR/$n" "$OUT_DIR/"
  fi
done
if [[ -f "$SCRIPT_DIR/bundle_extra/README_OPTIONAL_DBS.txt" ]]; then
  cp -a "$SCRIPT_DIR/bundle_extra/README_OPTIONAL_DBS.txt" "$OUT_DIR/data/"
fi
if [[ -f "$SCRIPT_DIR/bundle_extra/BUNDLE_README.txt" ]]; then
  cp -a "$SCRIPT_DIR/bundle_extra/BUNDLE_README.txt" "$OUT_DIR/BUNDLE_README.txt"
fi

# --- Full-stack checks (ONNX + rules) ---
ONNX_LIST=0
HAS_BEHAVIOR=0
STATIC_CAND=0
shopt -s nullglob
for f in "$OUT_DIR/models"/*.onnx; do
  [[ -f "$f" ]] || continue
  ONNX_LIST=$((ONNX_LIST + 1))
  b=$(basename "$f")
  if [[ "$b" == "behavior.onnx" ]]; then
    HAS_BEHAVIOR=1
  else
    STATIC_CAND=1
  fi
done
shopt -u nullglob

check_fail() {
  if [[ "$STRICT" == "1" ]]; then
    echo "Error: $1" >&2
    exit 1
  fi
  echo "Warning: $1" >&2
}

if [[ "$ONNX_LIST" -eq 0 ]]; then
  check_fail "models/ has no .onnx — AVE static/behavior will not run; not a full detection stack."
else
  if [[ "$HAS_BEHAVIOR" -ne 1 ]]; then
    check_fail "models/behavior.onnx missing — behavior pipeline disabled."
  fi
  if [[ "$STATIC_CAND" -ne 1 ]]; then
    check_fail "no second .onnx besides behavior — static engine needs a non-behavior .onnx (e.g. static.onnx)."
  fi
fi

# Drop macOS junk from payload
find "$OUT_DIR" -name '.DS_Store' -delete 2>/dev/null || true

# manifest (file list; no secrets)
{
  echo "# EDRAgent bundled payload manifest"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  ( cd "$OUT_DIR" && find . -type f | sort )
} > "$OUT_DIR/MANIFEST.txt"

mkdir -p "$SCRIPT_DIR/Output"
( cd "$SCRIPT_DIR/Output" && rm -f "${OUT_NAME}.zip" && zip -r -q "${OUT_NAME}.zip" "$OUT_NAME" )
echo "OK: $ZIP_PATH"
echo "Read BUNDLE_README inside the zip for full terminal feature coverage and out-of-band items."
echo "Optional: EDR_BUNDLE_STRICT=1 to require models/behavior.onnx + a static .onnx before zipping."
