#!/usr/bin/env bash
# P4：与 model/releases 对齐的热更冒烟 — `AVE_ApplyHotfix` → 重载 ORT → `AVE_GetStatus` 可见模型版本串。
#
# 用法（在 edr-agent 目录）：
#   export MODEL_DIR=/abs/path/to/model/releases/<id>
#   export HOTFIX_DIR=/abs/path/to/another/release_or_hotfix_dir   # 须含 static.onnx 和/或 behavior.onnx
#   bash ./scripts/ave_hotfix_release_smoke.sh
# 或：
#   bash ./scripts/ave_hotfix_release_smoke.sh /path/to/model_dir /path/to/hotfix_dir
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -n "${1:-}" ]]; then
  MODEL_DIR="$1"
fi
if [[ -n "${2:-}" ]]; then
  HOTFIX_DIR="$2"
fi
MODEL_DIR="${MODEL_DIR:-}"
HOTFIX_DIR="${HOTFIX_DIR:-}"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
if [[ -z "${MODEL_DIR}" && -f "${REPO_ROOT}/model/releases/current.json" ]]; then
  RID="$(sed -n 's/.*"release_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${REPO_ROOT}/model/releases/current.json" | head -1)"
  if [[ -n "${RID}" ]]; then
    MODEL_DIR="${REPO_ROOT}/model/releases/${RID}"
  fi
fi
if [[ -z "${HOTFIX_DIR}" ]]; then
  HOTFIX_DIR="${MODEL_DIR:-}"
fi
if [[ -z "${MODEL_DIR}" || ! -d "${MODEL_DIR}" || -z "${HOTFIX_DIR}" || ! -d "${HOTFIX_DIR}" ]]; then
  echo "usage: MODEL_DIR=... HOTFIX_DIR=... bash $0   OR   $0 <model_dir> <hotfix_dir>" >&2
  exit 1
fi

BUILD_DIR="${BUILD_DIR:-build-ort-e2e}"
if [[ -n "${ONNXRUNTIME_ROOT:-}" ]]; then
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}" \
    -DEDR_WITH_ONNXRUNTIME=ON "-DONNXRUNTIME_ROOT=${ONNXRUNTIME_ROOT}"
else
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}" -DEDR_WITH_ONNXRUNTIME=ON
fi
cmake --build "$BUILD_DIR" -j"${NPROC:-4}" --target test_ave_hotfix_smoke

unset EDR_AVE_INFER_DRY_RUN || true
export EDR_AVE_INFER_DRY_RUN=

export EDR_AVE_TEST_MODEL_DIR="${MODEL_DIR}"
export EDR_AVE_HOTFIX_DIR="${HOTFIX_DIR}"

echo "[ave_hotfix_release_smoke] MODEL_DIR=$MODEL_DIR HOTFIX_DIR=$HOTFIX_DIR"
exec "${BUILD_DIR}/test_ave_hotfix_smoke"
