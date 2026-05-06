#!/bin/bash
# 一键部署：复制所有 backend 变更文件到 edr-backend 目录
set -e

BACKEND_ROOT="/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-backend/platform"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Step 1: Copy modified shell.go ==="
cp "$SCRIPT_DIR/shell.go" "$BACKEND_ROOT/internal/handler/shell.go"
echo "  ✓ shell.go"

echo "=== Step 2: Copy new test files ==="
cp "$SCRIPT_DIR/shell_test.go" "$BACKEND_ROOT/internal/handler/shell_test.go"
cp "$SCRIPT_DIR/forensic_p2_test.go" "$BACKEND_ROOT/internal/handler/forensic_p2_test.go"
echo "  ✓ shell_test.go"
echo "  ✓ forensic_p2_test.go"

echo "=== Step 3: Apply forensic_p2.go patch ==="
cd "$BACKEND_ROOT"
bash "$SCRIPT_DIR/patch_forensic_p2.sh"
echo "  ✓ forensic_p2.go"

echo "=== Step 4: Apply build.go patch ==="
bash "$SCRIPT_DIR/patch_build.sh"
echo "  ✓ build.go"

echo ""
echo "=== All done! ==="
echo ""
echo "Next steps:"
echo "  1. cd $BACKEND_ROOT"
echo "  2. go test ./internal/handler/ -run 'TestPostShell|TestPostDeep' -v"
echo ""
