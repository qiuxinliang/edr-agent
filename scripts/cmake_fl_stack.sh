#!/usr/bin/env bash
# 可复现配置：FL + gRPC（+ OpenSSL HTTPS）。用法：
#   ./scripts/cmake_fl_stack.sh [build-dir]
# 环境：
#   CMAKE_BUILD_TYPE   默认 Release
#   CMAKE_EXTRA_ARGS   附加传给 cmake 的参数（引号包裹）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-${ROOT}/build-fl-stack}"
BT="${CMAKE_BUILD_TYPE:-Release}"

EXTRA=()
if [[ -n "${CMAKE_EXTRA_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  EXTRA=(${CMAKE_EXTRA_ARGS})
fi

PREFIX_PATHS=()
if [[ -d /usr/lib/x86_64-linux-gnu/cmake ]]; then
  PREFIX_PATHS+=("/usr/lib/x86_64-linux-gnu/cmake")
fi
if command -v brew >/dev/null 2>&1; then
  if brew --prefix grpc &>/dev/null; then
    PREFIX_PATHS+=("$(brew --prefix grpc)")
  fi
  if brew --prefix openssl &>/dev/null; then
    PREFIX_PATHS+=("$(brew --prefix openssl)")
  fi
fi

PP=""
for p in "${PREFIX_PATHS[@]}"; do
  if [[ -n "$PP" ]]; then
    PP="${PP};${p}"
  else
    PP="${p}"
  fi
done

CMAKE_ARGS=(
  -S "$ROOT"
  -B "$BUILD"
  "-DCMAKE_BUILD_TYPE=$BT"
  -DEDR_WITH_GRPC=ON
  -DEDR_WITH_FL_TRAINER=ON
)
if [[ -n "$PP" ]]; then
  CMAKE_ARGS+=("-DCMAKE_PREFIX_PATH=$PP")
fi
CMAKE_ARGS+=("${EXTRA[@]}")

echo "cmake ${CMAKE_ARGS[*]}"
cmake "${CMAKE_ARGS[@]}"
NJ="${FL_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)}"
cmake --build "$BUILD" -j"${NJ}"
