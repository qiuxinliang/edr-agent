#!/usr/bin/env bash
# Full Windows endpoint payload (zip) — matches EDRAgentSetup.bundled.iss [Files] under {app}.
# See bundle_extra/BUNDLE_README.txt for what this bundle covers vs platform-only artifacts.
#
# Usage:
#   ./package_bundled_layout.sh
#   EDR_BIN_DIR=/path/to/stage EDR_BUNDLE_STRICT=1 ./package_bundled_layout.sh
# EDR_BUNDLE_STRICT=1: fail if no static-capable .onnx is present
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
# 目标架构(amd64|arm64):决定 STAGE 默认目录、Go 适配器/velo 取哪一份、输出 zip 名。
ARCH="${EDR_BUNDLE_ARCH:-amd64}"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "Error: EDR_BUNDLE_ARCH must be amd64 or arm64 (got: $ARCH)" >&2; exit 1 ;;
esac
STAGE_DIR="${EDR_BIN_DIR:-"$REPO_ROOT/edr-agent-win_2-2"}"
EDR_AGENT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_NAME="${EDR_BUNDLE_ZIP_NAME:-EDRAgent-bundled-payload-win-${ARCH}}"
OUT_DIR="$SCRIPT_DIR/Output/${OUT_NAME}"
ZIP_PATH="$SCRIPT_DIR/Output/${OUT_NAME}.zip"
STRICT="${EDR_BUNDLE_STRICT:-0}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/models" "$OUT_DIR/data"

if [[ ! -d "$STAGE_DIR" ]]; then
  echo "Error: STAGE_DIR not found: $STAGE_DIR" >&2
  echo "Set EDR_BIN_DIR to your folder with FDSensor.exe and .dll" >&2
  exit 1
fi
if [[ -f "$STAGE_DIR/FDSensor.exe" ]]; then
  AGENT_EXE="$STAGE_DIR/FDSensor.exe"
elif [[ -f "$STAGE_DIR/edr_agent.exe" ]]; then
  AGENT_EXE="$STAGE_DIR/edr_agent.exe"
else
  echo "Error: missing: $STAGE_DIR/FDSensor.exe" >&2
  exit 1
fi

# --- Binaries (Inno EDR_BIN_DIR) ---
cp -a "$AGENT_EXE" "$OUT_DIR/FDSensor.exe"
if [[ -f "$STAGE_DIR/FDSecurityInstallerWorker.exe" ]]; then
  cp -a "$STAGE_DIR/FDSecurityInstallerWorker.exe" "$OUT_DIR/"
else
  echo "Warning: missing FDSecurityInstallerWorker.exe; installer will fall back to script stages." >&2
fi
shopt -s nullglob
DLL_COUNT=0
for f in "$STAGE_DIR"/*.dll; do
  cp -a "$f" "$OUT_DIR/"
  DLL_COUNT=$((DLL_COUNT + 1))
done
shopt -u nullglob
if [[ "$DLL_COUNT" -lt 1 ]]; then
  echo "Warning: no .dll next to FDSensor.exe; Windows runtime will not start." >&2
fi

# models: recursive (onnx, pca_*.npy, etc.)
if [[ -d "$EDR_AGENT_DIR/models" ]]; then
  cp -a "$EDR_AGENT_DIR/models/." "$OUT_DIR/models/"
  find "$OUT_DIR/models" -type f -name 'behavior.onnx' -delete 2>/dev/null || true
fi

PREP_TOML="$REPO_ROOT/edr-backend/platform/config/agent_preprocess_rules_v1.toml"
if [[ -f "$PREP_TOML" ]]; then
  cp -a "$PREP_TOML" "$OUT_DIR/agent_preprocess_rules_v1.toml"
else
  echo "Error: missing preprocess rules: $PREP_TOML" >&2
  exit 1
fi

# detection rule sets (shellcode / webshell YARA + builtin fallback)
if [[ -d "$EDR_AGENT_DIR/src/shellcode_detector/rules" ]]; then
  mkdir -p "$OUT_DIR/rules/shellcode"
  cp -a "$EDR_AGENT_DIR/src/shellcode_detector/rules/." "$OUT_DIR/rules/shellcode/"
fi
if [[ -d "$EDR_AGENT_DIR/src/webshell_detector/rules" ]]; then
  mkdir -p "$OUT_DIR/rules/webshell"
  cp -a "$EDR_AGENT_DIR/src/webshell_detector/rules/." "$OUT_DIR/rules/webshell/"
fi

if [[ -f "$EDR_AGENT_DIR/agent.toml.example" ]]; then
  cp -a "$EDR_AGENT_DIR/agent.toml.example" "$OUT_DIR/"
fi
if [[ -f "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" ]]; then
  cp -a "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" "$OUT_DIR/"
fi
for n in "edr_agent_preflight.ps1" "windows_service_install.ps1" "windows_isolate_host.ps1"; do
  if [[ -f "$EDR_AGENT_DIR/scripts/$n" ]]; then
    cp -a "$EDR_AGENT_DIR/scripts/$n" "$OUT_DIR/"
  fi
done
if [[ -f "$EDR_AGENT_DIR/config/agent_windows_production.example.toml" ]]; then
  mkdir -p "$OUT_DIR/config"
  cp -a "$EDR_AGENT_DIR/config/agent_windows_production.example.toml" "$OUT_DIR/config/"
fi
mkdir -p "$OUT_DIR/edr_config"
for n in "p0_rule_bundle_ir_v1.json.enc" "sensor_interest_manifest.json"; do
  if [[ -f "$EDR_AGENT_DIR/config/$n" ]]; then
    cp -a "$EDR_AGENT_DIR/config/$n" "$OUT_DIR/edr_config/"
  fi
done
if [[ -f "$OUT_DIR/edr_config/p0_rule_bundle_ir_v1.json" ]]; then
  echo "Error: plaintext p0_rule_bundle_ir_v1.json must not be packaged" >&2
  exit 1
fi
if [[ -f "$OUT_DIR/edr_config/p0_rule_bundle_manifest.json" ]]; then
  echo "Error: plaintext p0_rule_bundle_manifest.json must not be packaged" >&2
  exit 1
fi
if [[ ! -f "$OUT_DIR/edr_config/p0_rule_bundle_ir_v1.json.enc" ]]; then
  echo "Error: missing encrypted p0_rule_bundle_ir_v1.json.enc" >&2
  exit 1
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

# --- 取证采集器 collector/ (装到 {app}\collector\ = C:\Program Files\FDSecurity\collector\) ---
# 按架构(ARCH=amd64|arm64)取件:
#   forensic_collector.exe          ← Go 适配器:forensic-collector/build.sh (dist/win-<ARCH>/)
#   forensic_collector_builtin.exe  ← CMake target(C baseline);从 STAGE_DIR 取(发布 CI 同 FDSensor 一起 stage)
#   velociraptor.exe + LICENSE/SOURCE ← fetch_velociraptor.sh (collector_stage/<ARCH>/)
# velo 体积大:**默认不内置**(平台自托管 + agent 按需下载是主路径);
# 仅 EDR_BUNDLE_VELO=1 时才内置(离线/无平台连通场景)。adapter+builtin 始终内置(小)。
# 任一缺失仅 Warning(非 strict):agent 三层兜底(velo→builtin→in-process)。
BUNDLE_VELO="${EDR_BUNDLE_VELO:-0}"
COLLECTOR_OUT="$OUT_DIR/collector"
mkdir -p "$COLLECTOR_OUT"
GO_FC="${EDR_FORENSIC_COLLECTOR_BIN:-$EDR_AGENT_DIR/../forensic-collector/dist/win-${ARCH}/forensic_collector.exe}"
VELO_STAGE="${EDR_VELO_OUT:-$SCRIPT_DIR/collector_stage}/${ARCH}"
if [[ "$BUNDLE_VELO" != "1" && -f "$STAGE_DIR/collector/velociraptor.exe" ]]; then
  echo "Error: standard installer staging contains collector/velociraptor.exe. Remove it or build an explicit offline package with EDR_BUNDLE_VELO=1." >&2
  exit 1
fi
if [[ "${EDR_SKIP_FORENSIC_COLLECTOR_BUILD:-0}" != "1" && -d "$EDR_AGENT_DIR/../forensic-collector" ]]; then
  if command -v go >/dev/null 2>&1; then
    echo "==> [$ARCH] rebuilding Go forensic_collector.exe from current source"
    ( cd "$EDR_AGENT_DIR/../forensic-collector" && EDR_FC_OUT="$EDR_AGENT_DIR/../forensic-collector/dist/win-${ARCH}" ./build.sh "$ARCH" )
  else
    echo "Warning: [$ARCH] go not found; using existing forensic_collector.exe if present." >&2
  fi
fi
if [[ -f "$GO_FC" ]]; then
  cp -a "$GO_FC" "$COLLECTOR_OUT/forensic_collector.exe"
else
  echo "Warning: [$ARCH] missing Go forensic_collector.exe ($GO_FC); run forensic-collector/build.sh ${ARCH}. Agent falls back to builtin/in-process." >&2
fi
if [[ -f "$STAGE_DIR/forensic_collector_builtin.exe" ]]; then
  cp -a "$STAGE_DIR/forensic_collector_builtin.exe" "$COLLECTOR_OUT/"
else
  echo "Warning: [$ARCH] missing forensic_collector_builtin.exe in STAGE_DIR; C-baseline fallback unavailable." >&2
fi
if [[ "$BUNDLE_VELO" == "1" ]]; then
  if [[ -f "$VELO_STAGE/velociraptor.exe" ]]; then
    cp -a "$VELO_STAGE/velociraptor.exe" "$COLLECTOR_OUT/"
    # AGPL 合规件必须随 velociraptor.exe 一起分发;有 velo 无许可即视为打包错误。
    if [[ -f "$VELO_STAGE/velociraptor.LICENSE.txt" && -f "$VELO_STAGE/velociraptor.SOURCE.txt" ]]; then
      cp -a "$VELO_STAGE/velociraptor.LICENSE.txt" "$VELO_STAGE/velociraptor.SOURCE.txt" "$COLLECTOR_OUT/"
    else
      echo "Error: [$ARCH] EDR_BUNDLE_VELO=1 but AGPL LICENSE/SOURCE missing in $VELO_STAGE (run fetch_velociraptor.sh)" >&2
      exit 1
    fi
  else
    echo "Error: [$ARCH] EDR_BUNDLE_VELO=1 but velociraptor.exe missing ($VELO_STAGE/velociraptor.exe); run fetch_velociraptor.sh EDR_VELO_ARCHES=$ARCH" >&2
    exit 1
  fi
else
  echo "Info: [$ARCH] velociraptor 未内置(默认按需下载);如需内置离线包设 EDR_BUNDLE_VELO=1。" >&2
fi
# collector 目录若为空则移除,避免空目录入包
rmdir "$COLLECTOR_OUT" 2>/dev/null || true

# --- Full-stack checks (ONNX + rules) ---
ONNX_LIST=0
STATIC_CAND=0
shopt -s nullglob
for f in "$OUT_DIR/models"/*.onnx; do
  [[ -f "$f" ]] || continue
  ONNX_LIST=$((ONNX_LIST + 1))
  b=$(basename "$f")
  if [[ "$b" != "behavior.onnx" ]]; then
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
  check_fail "models/ has no .onnx — AVE static EPP will not run; not a full endpoint protection stack."
else
  if [[ "$STATIC_CAND" -ne 1 ]]; then
    check_fail "static engine needs a non-behavior .onnx (e.g. static.onnx)."
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
if unzip -Z1 "$ZIP_PATH" | grep -E '(^|/)(p0_rule_bundle_ir_v1\.json|p0_rule_bundle_manifest\.json)$' >/dev/null; then
  echo "Error: plaintext P0 rules were found in $ZIP_PATH" >&2
  exit 1
fi
echo "OK: $ZIP_PATH"
echo "Read BUNDLE_README inside the zip for full terminal feature coverage and out-of-band items."
echo "Optional: EDR_BUNDLE_STRICT=1 to require a static .onnx before zipping."
