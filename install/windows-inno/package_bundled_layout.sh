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

require_yara_runtime_dlls_in_dir() {
  local dir="$1"
  local context="$2"
  if ! find "$dir" -maxdepth 1 -type f -iname '*yara*.dll' | grep -q .; then
    echo "Error: YARA runtime DLL missing from ${context}: $dir" >&2
    echo "Windows endpoint bundles require vcpkg libyara runtime DLLs staged next to FDSensor.exe." >&2
    exit 1
  fi
}

require_windivert_runtime() {
  local runtime_dir="$EDR_AGENT_DIR/third_party/windivert/runtime/amd64"
  local dll="$runtime_dir/WinDivert.dll"
  local sys="$runtime_dir/WinDivert64.sys"
  local license="$EDR_AGENT_DIR/third_party/windivert/LICENSE"
  local source="$EDR_AGENT_DIR/third_party/windivert/SOURCE.json"
  [[ -f "$dll" && -f "$sys" && -f "$license" && -f "$source" ]] || {
    echo "Error: pinned WinDivert runtime/legal assets are missing" >&2
    exit 1
  }
  local dll_hash sys_hash
  dll_hash="$(shasum -a 256 "$dll" | awk '{print $1}')"
  sys_hash="$(shasum -a 256 "$sys" | awk '{print $1}')"
  [[ "$dll_hash" == "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2" ]] || {
    echo "Error: WinDivert.dll SHA-256 mismatch" >&2; exit 1;
  }
  [[ "$sys_hash" == "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2" ]] || {
    echo "Error: WinDivert64.sys SHA-256 mismatch" >&2; exit 1;
  }
}

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
if command -v file >/dev/null 2>&1; then
  PE_DESC="$(file -b "$AGENT_EXE")"
  case "$ARCH" in
    amd64) [[ "$PE_DESC" == *"x86-64"* ]] || { echo "Error: target amd64 but Agent PE is: $PE_DESC" >&2; exit 1; } ;;
    arm64) [[ "$PE_DESC" == *"Aarch64"* || "$PE_DESC" == *"ARM64"* ]] || { echo "Error: target arm64 but Agent PE is: $PE_DESC" >&2; exit 1; } ;;
  esac
fi
require_yara_runtime_dlls_in_dir "$STAGE_DIR" "STAGE_DIR"

# --- Binaries (Inno EDR_BIN_DIR) ---
cp -a "$AGENT_EXE" "$OUT_DIR/FDSensor.exe"
if [[ -f "$STAGE_DIR/FDSecurityInstallerWorker.exe" ]]; then
  cp -a "$STAGE_DIR/FDSecurityInstallerWorker.exe" "$OUT_DIR/"
else
  echo "Warning: missing FDSecurityInstallerWorker.exe; installer will fall back to script stages." >&2
fi
if [[ -f "$STAGE_DIR/uninstall.exe" ]]; then
  cp -a "$STAGE_DIR/uninstall.exe" "$OUT_DIR/"
else
  echo "Error: missing headless uninstaller: $STAGE_DIR/uninstall.exe" >&2
  exit 1
fi
shopt -s nullglob
DLL_COUNT=0
BUNDLE_ONNX_RUNTIME="${EDR_BUNDLE_ONNX_RUNTIME:-0}"
DLL_DENY_REGEX="${EDR_BUNDLE_DLL_DENY_REGEX:-(^|/)(onnxruntime.*|.*\\.(pdb|ilk|exp|lib|xml))$}"
for f in "$STAGE_DIR"/*.dll; do
  name="$(basename "$f")"
  if [[ "$BUNDLE_ONNX_RUNTIME" != "1" && "$name" =~ ^onnxruntime.*\.dll$ ]]; then
    echo "Info: skip large optional ONNX Runtime DLL from standard package: $name (set EDR_BUNDLE_ONNX_RUNTIME=1 to include)." >&2
    continue
  fi
  if [[ "$name" =~ $DLL_DENY_REGEX ]]; then
    echo "Info: skip denied runtime file: $name" >&2
    continue
  fi
  cp -a "$f" "$OUT_DIR/"
  DLL_COUNT=$((DLL_COUNT + 1))
done
shopt -u nullglob
if [[ "$DLL_COUNT" -lt 1 ]]; then
  echo "Warning: no .dll next to FDSensor.exe; Windows runtime will not start if FDSensor.exe is dynamically linked." >&2
fi
require_yara_runtime_dlls_in_dir "$OUT_DIR" "bundled payload output"
mkdir -p "$OUT_DIR/licenses" "$OUT_DIR/capabilities"
if [[ "$ARCH" == "amd64" ]]; then
  require_windivert_runtime
  cp -a "$EDR_AGENT_DIR/third_party/windivert/runtime/amd64/WinDivert.dll" "$OUT_DIR/WinDivert.dll"
  cp -a "$EDR_AGENT_DIR/third_party/windivert/runtime/amd64/WinDivert64.sys" "$OUT_DIR/WinDivert64.sys"
  cp -a "$EDR_AGENT_DIR/third_party/windivert/LICENSE" "$OUT_DIR/licenses/WinDivert-LICENSE.txt"
  cp -a "$EDR_AGENT_DIR/third_party/windivert/SOURCE.json" "$OUT_DIR/licenses/WinDivert-SOURCE.json"
  printf '%s\n' '{"target_arch":"amd64","windivert":true,"network_packet_capture":true,"arm64_emulation_supported":false,"arm64_emulation_network_packet_capture":false,"windows_firewall_isolation":true,"reason":"AMD64-on-ARM64 is blocked until the full package passes a native ARM64 E2E gate"}' > "$OUT_DIR/capabilities/package.json"
else
  printf '%s\n' '{"target_arch":"arm64","windivert":false,"network_packet_capture":false,"arm64_emulation_supported":false,"arm64_emulation_network_packet_capture":false,"windows_firewall_isolation":true,"reason":"WinDivert 2.2.2 has no ARM64 kernel driver; Windows Firewall host isolation remains available"}' > "$OUT_DIR/capabilities/package.json"
fi
printf '%s\n' "$ARCH" > "$OUT_DIR/ARCH"

# models: whitelist production-ready compact model artifacts only.
if [[ -d "$EDR_AGENT_DIR/models" ]]; then
  shopt -s nullglob
  for f in "$EDR_AGENT_DIR/models"/README* "$EDR_AGENT_DIR/models"/pca_*.npy "$EDR_AGENT_DIR/models"/static.onnx "$EDR_AGENT_DIR/models"/static_quant*.onnx; do
    [[ -f "$f" ]] && cp -a "$f" "$OUT_DIR/models/"
  done
  shopt -u nullglob
fi

PREP_TOML="$REPO_ROOT/edr-backend/platform/config/agent_preprocess_rules_v1.toml"
if [[ -f "$PREP_TOML" ]]; then
  cp -a "$PREP_TOML" "$OUT_DIR/agent_preprocess_rules_v1.toml"
else
  echo "Error: missing preprocess rules: $PREP_TOML" >&2
  exit 1
fi

# detection rule sets (forensic / shellcode / webshell YARA + builtin fallback)
if [[ -d "$EDR_AGENT_DIR/rules/forensic" ]]; then
  mkdir -p "$OUT_DIR/rules/forensic"
  cp -a "$EDR_AGENT_DIR/rules/forensic/." "$OUT_DIR/rules/forensic/"
fi
if [[ -d "$EDR_AGENT_DIR/src/shellcode_detector/rules" ]]; then
  mkdir -p "$OUT_DIR/rules/shellcode"
  cp -a "$EDR_AGENT_DIR/src/shellcode_detector/rules/." "$OUT_DIR/rules/shellcode/"
fi
if [[ -d "$EDR_AGENT_DIR/src/webshell_detector/rules" ]]; then
  mkdir -p "$OUT_DIR/rules/webshell"
  cp -a "$EDR_AGENT_DIR/src/webshell_detector/rules/." "$OUT_DIR/rules/webshell/"
fi
for required_rule in \
  "rules/forensic/VERSION" \
  "rules/forensic/credential_theft.yar" \
  "rules/forensic/lateral_movement.yar" \
  "rules/forensic/privilege_escalation.yar"; do
  if [[ ! -f "$OUT_DIR/$required_rule" ]]; then
    echo "Error: missing bundled forensic YARA rule asset: $required_rule" >&2
    exit 1
  fi
done
if ! find "$OUT_DIR/rules/forensic" -maxdepth 1 -type f \( -name '*.yar' -o -name '*.yara' \) | grep -q .; then
  echo "Error: rules/forensic has no .yar/.yara files" >&2
  exit 1
fi

if [[ -f "$EDR_AGENT_DIR/agent.toml.example" ]]; then
  cp -a "$EDR_AGENT_DIR/agent.toml.example" "$OUT_DIR/"
fi
if [[ -f "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" ]]; then
  cp -a "$EDR_AGENT_DIR/scripts/edr_agent_install.ps1" "$OUT_DIR/"
fi
if [[ -f "$EDR_AGENT_DIR/scripts/edr_agent_uninstall.ps1" ]]; then
  cp -a "$EDR_AGENT_DIR/scripts/edr_agent_uninstall.ps1" "$OUT_DIR/uninstall.ps1"
else
  echo "Error: missing headless uninstall script: $EDR_AGENT_DIR/scripts/edr_agent_uninstall.ps1" >&2
  exit 1
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
if ! grep -Ei '(^|/)(lib)?yara.*\.dll$' "$OUT_DIR/MANIFEST.txt" >/dev/null; then
  echo "Error: MANIFEST.txt does not include a YARA runtime DLL" >&2
  exit 1
fi
if ! grep -E '^\./rules/forensic/.+\.yar(a)?$' "$OUT_DIR/MANIFEST.txt" >/dev/null; then
  echo "Error: MANIFEST.txt does not include forensic YARA rules" >&2
  exit 1
fi
for required in "WinDivert.dll" "WinDivert64.sys" "licenses/WinDivert-LICENSE.txt" "licenses/WinDivert-SOURCE.json"; do
  if ! grep -Fqx "./$required" "$OUT_DIR/MANIFEST.txt"; then
    echo "Error: MANIFEST.txt does not include $required" >&2
    exit 1
  fi
done

mkdir -p "$SCRIPT_DIR/Output"
( cd "$SCRIPT_DIR/Output" && rm -f "${OUT_NAME}.zip" && zip -r -q "${OUT_NAME}.zip" "$OUT_NAME" )
if unzip -Z1 "$ZIP_PATH" | grep -E '(^|/)(p0_rule_bundle_ir_v1\.json|p0_rule_bundle_manifest\.json)$' >/dev/null; then
  echo "Error: plaintext P0 rules were found in $ZIP_PATH" >&2
  exit 1
fi
if ! unzip -Z1 "$ZIP_PATH" | grep -Ei '(^|/)(lib)?yara.*\.dll$' >/dev/null; then
  echo "Error: YARA runtime DLL missing from $ZIP_PATH" >&2
  exit 1
fi
if ! unzip -Z1 "$ZIP_PATH" | grep -E '(^|/)rules/forensic/.+\.yar(a)?$' >/dev/null; then
  echo "Error: forensic YARA rules missing from $ZIP_PATH" >&2
  exit 1
fi
for required in "WinDivert.dll" "WinDivert64.sys" "licenses/WinDivert-LICENSE.txt" "licenses/WinDivert-SOURCE.json"; do
  if ! unzip -Z1 "$ZIP_PATH" | grep -Fq "/$required"; then
    echo "Error: $required missing from $ZIP_PATH" >&2
    exit 1
  fi
done
echo "OK: $ZIP_PATH"
echo "Read BUNDLE_README inside the zip for full terminal feature coverage and out-of-band items."
echo "Optional: EDR_BUNDLE_STRICT=1 to require a static .onnx before zipping."
