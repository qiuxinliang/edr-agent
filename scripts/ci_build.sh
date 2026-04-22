#!/usr/bin/env bash
# 本地/CI：无 gRPC 与有 gRPC 两种配置各构建一次（第二段在已安装 grpc 的机器上可选）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== CMake: EDR_WITH_GRPC=OFF ==="
cmake -B build-nogrpc -DEDR_WITH_GRPC=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-nogrpc -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
ctest --test-dir build-nogrpc --output-on-failure

if cmake -B build-grpc -DCMAKE_BUILD_TYPE=Release 2>/dev/null; then
  echo "=== CMake: default (gRPC if found) ==="
  cmake --build build-grpc -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  ctest --test-dir build-grpc --output-on-failure || true
fi

echo "ci_build.sh 完成"
