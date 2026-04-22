#!/usr/bin/env bash
# AVE / ONNX 本地冒烟：构建（若已配置 ORT）并运行 test_ave_infer。
# 用法：在 edr-agent 仓库根目录执行 bash ./scripts/onnx_local_stack_smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="${BUILD_DIR:-build}"
if [[ -n "${ONNXRUNTIME_ROOT:-}" ]]; then
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}" \
    -DEDR_WITH_ONNXRUNTIME=ON "-DONNXRUNTIME_ROOT=${ONNXRUNTIME_ROOT}"
else
  cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Debug}"
fi
cmake --build "$BUILD_DIR" -j"${NPROC:-4}" --target test_ave_infer

echo "[onnx_local_stack_smoke] running test_ave_infer (default dry-run unless EDR_AVE_INFER_DRY_RUN set)"
"$BUILD_DIR/test_ave_infer"
echo "[onnx_local_stack_smoke] ok"
