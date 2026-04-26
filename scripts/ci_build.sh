#!/usr/bin/env bash
# 本地/CI：无 gRPC 与有 gRPC 两种配置各构建一次（第二段在已安装 grpc 的机器上可选）
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

echo "=== CMake: EDR_WITH_GRPC=OFF ==="
cmake -B build-nogrpc -DEDR_WITH_GRPC=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-nogrpc -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
if [[ -f "$ROOT/build-nogrpc/edr_agent" ]]; then
  print_build_fingerprint "$ROOT/build-nogrpc/edr_agent"
elif [[ -f "$ROOT/build-nogrpc/edr_agent.exe" ]]; then
  print_build_fingerprint "$ROOT/build-nogrpc/edr_agent.exe"
fi
ctest --test-dir build-nogrpc --output-on-failure

if cmake -B build-grpc -DCMAKE_BUILD_TYPE=Release 2>/dev/null; then
  echo "=== CMake: default (gRPC if found) ==="
  cmake --build build-grpc -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  if [[ -f "$ROOT/build-grpc/edr_agent" ]]; then
    print_build_fingerprint "$ROOT/build-grpc/edr_agent"
  elif [[ -f "$ROOT/build-grpc/edr_agent.exe" ]]; then
    print_build_fingerprint "$ROOT/build-grpc/edr_agent.exe"
  fi
  ctest --test-dir build-grpc --output-on-failure || true
fi

echo "ci_build.sh 完成"
