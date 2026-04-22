#!/usr/bin/env bash
# 将训练产物 static.onnx 安装到 Agent 读取的目录（默认与 [ave].model_dir 一致：/opt/edr/models）。
# 加载链：edr_ave_init → model_dir 下首个非 behavior.onnx 的 .onnx → edr_onnx_runtime_load（需 EDR_WITH_ONNXRUNTIME=ON）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC="${EDR_STATIC_ONNX_SRC:-$REPO_ROOT/onnx-output/static.onnx}"
DEST_DIR="${EDR_MODEL_DIR:-/opt/edr/models}"
DEST_NAME="static.onnx"

usage() {
  cat <<'EOF'
Usage: install_static_onnx.sh [options]

  --source PATH     源文件（默认: <repo>/onnx-output/static.onnx）
  --dest-dir DIR    目标目录（默认: /opt/edr/models；与 agent.toml [ave] model_dir 一致）
  --name NAME       目标文件名（默认: static.onnx；可为任意 .onnx，勿与 behavior.onnx 冲突用途）
  -h, --help        本说明

环境变量（与命令行等价）:
  EDR_STATIC_ONNX_SRC   覆盖默认源路径
  EDR_MODEL_DIR         覆盖默认目标目录

安装后请在 agent.toml 中设置:
  [ave]
  model_dir = "<同上 --dest-dir>"

CMake 真推理需: -DEDR_WITH_ONNXRUNTIME=ON，且本机可找到 ONNX Runtime。
EOF
}

DEST_BASENAME="$DEST_NAME"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SRC="$2"
      shift 2
      ;;
    --dest-dir)
      DEST_DIR="$2"
      shift 2
      ;;
    --name)
      DEST_BASENAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$SRC" ]]; then
  echo "install_static_onnx: source not found: $SRC" >&2
  echo "  Train/export static.onnx into onnx-output/ or set --source / EDR_STATIC_ONNX_SRC." >&2
  exit 1
fi

case "$DEST_BASENAME" in
  *.onnx|*.ONNX) ;;
  *)
    echo "install_static_onnx: --name should end with .onnx" >&2
    exit 1
    ;;
esac

mkdir -p "$DEST_DIR"
DEST="$DEST_DIR/$DEST_BASENAME"
cp -f "$SRC" "$DEST"
BYTES=$(wc -c <"$DEST" | tr -d ' ')
echo "Installed: $DEST ($BYTES bytes)"
echo ""
echo "Next:"
echo "  1. agent.toml  [ave] model_dir = \"$DEST_DIR\""
echo "  2. cmake -DEDR_WITH_ONNXRUNTIME=ON ... && build edr_agent"
echo "  3. Run agent; stderr should contain: [ave/onnx] static 已加载 ..."
