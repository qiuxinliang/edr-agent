#!/usr/bin/env bash
# 本地/CI：产品主线构建。gRPC 客户端已从 Agent 产品构建移除，当前仅验证 HTTP ingest/control 路径。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

print_build_fingerprint() {
  local bin_path="$1"
  local git_short git_dirty bin_sha bin_mtime
  git_short="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  git_dirty="$(git -C "$ROOT" diff --quiet 2>/dev/null; rc=$?; [[ $rc -eq 0 ]] && echo clean || echo dirty)"
  if command -v shasum >/dev/null 2>&1; then
    bin_sha="$(shasum -a 256 "$bin_path" 2>/dev/null | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    bin_sha="$(sha256sum "$bin_path" 2>/dev/null | awk '{print $1}')"
  else
    bin_sha="unknown"
  fi
  bin_mtime="$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%S%z" "$bin_path" 2>/dev/null || stat -c "%y" "$bin_path" 2>/dev/null || echo unknown)"
  echo "=== build fingerprint: git=${git_short}(${git_dirty}) sha256=${bin_sha} mtime=${bin_mtime} bin=${bin_path}"
}

BUILD_DIR="$ROOT/build-product"

echo "=== CMake: product build (HTTP ingest/control, no gRPC) ==="
cmake -B "$BUILD_DIR" -DEDR_WITH_GRPC=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
if [[ -f "$BUILD_DIR/FDSensor.exe" ]]; then
  print_build_fingerprint "$BUILD_DIR/FDSensor.exe"
elif [[ -f "$BUILD_DIR/edr_agent" ]]; then
  print_build_fingerprint "$BUILD_DIR/edr_agent"
elif [[ -f "$BUILD_DIR/edr_agent.exe" ]]; then
  print_build_fingerprint "$BUILD_DIR/edr_agent.exe"
fi
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "ci_build.sh 完成"
