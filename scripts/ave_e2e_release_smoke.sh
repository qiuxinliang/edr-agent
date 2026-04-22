#!/usr/bin/env bash
# AVE 全流程：model_dir 下 static.onnx + behavior.onnx → AVE_ScanFile + edr_onnx_behavior_infer
#
# 用法（在 edr-agent 目录）：
#   export MODEL_DIR=/abs/path/to/model/releases/<id>
#   bash ./scripts/ave_e2e_release_smoke.sh
# 或把 model_dir 作为第一个参数：
#   bash ./scripts/ave_e2e_release_smoke.sh /abs/path/to/model/releases/<id>
# 可选第二个参数：待扫描文件（默认 /bin/ls）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -n "${1:-}" ]]; then
  MODEL_DIR="$1"
fi
MODEL_DIR="${MODEL_DIR:-}"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
if [[ -z "${MODEL_DIR}" && -f "${REPO_ROOT}/model/releases/current.json" ]]; then
  RID="$(sed -n 's/.*"release_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${REPO_ROOT}/model/releases/current.json" | head -1)"
  if [[ -n "${RID}" ]]; then
    MODEL_DIR="${REPO_ROOT}/model/releases/${RID}"
  fi
fi
if [[ -z "${MODEL_DIR}" || ! -d "${MODEL_DIR}" ]]; then
  echo "usage: MODEL_DIR=/path/to/release bash $0   OR   $0 /path/to/release [file_to_scan]" >&2
  exit 1
fi

BUILD_DIR="${BUILD_DIR:-build-ort-e2e}"
if [[ -n "${ONNXRUNTIME_ROOT:-}" ]]; then
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}" \
    -DEDR_WITH_ONNXRUNTIME=ON "-DONNXRUNTIME_ROOT=${ONNXRUNTIME_ROOT}"
else
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}" -DEDR_WITH_ONNXRUNTIME=ON
fi
cmake --build "$BUILD_DIR" -j"${NPROC:-4}" --target test_ave_e2e_full

unset EDR_AVE_INFER_DRY_RUN || true
export EDR_AVE_INFER_DRY_RUN=

SCAN_TARGET="${2:-/bin/ls}"

echo "[ave_e2e_release_smoke] MODEL_DIR=$MODEL_DIR scan=$SCAN_TARGET"
exec "${BUILD_DIR}/test_ave_e2e_full" "$MODEL_DIR" "$SCAN_TARGET"
