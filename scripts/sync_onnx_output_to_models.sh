#!/usr/bin/env bash
# 将训练产物目录 onnx-output/*.onnx 复制到 models/，供 Inno / 便携 zip / Linux 发行包打包。
# 仓库约定：onnx-output 与 scripts/ 同级（见 install_static_onnx.sh）。
# EDR_BUNDLE_ONNX_REQUIRED=1 且无 .onnx 时失败（发布 CI 使用）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/onnx-output"
DST="$ROOT/models"
mkdir -p "$DST"
if [[ ! -d "$SRC" ]]; then
  if [[ "${EDR_BUNDLE_ONNX_REQUIRED:-}" == "1" ]]; then
    echo "::error::sync_onnx_output_to_models: missing directory $SRC" >&2
    exit 1
  fi
  echo "sync_onnx_output_to_models: warning: missing $SRC" >&2
  exit 0
fi
shopt -s nullglob
files=("$SRC"/*.onnx)
if ((${#files[@]} == 0)); then
  if [[ "${EDR_BUNDLE_ONNX_REQUIRED:-}" == "1" ]]; then
    echo "::error::sync_onnx_output_to_models: no *.onnx under $SRC — add static.onnx / behavior.onnx (or train export) and commit for release bundle." >&2
    exit 1
  fi
  echo "sync_onnx_output_to_models: warning: no *.onnx in $SRC; leaving models/ as-is (README only is ok for dev)." >&2
  exit 0
fi
cp -f "${files[@]}" "$DST/"
echo "sync_onnx_output_to_models: copied ${#files[@]} file(s) to $DST"
