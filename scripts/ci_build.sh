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
VCPKG_ROOT="${EDR_PCRE2_VCPKG_ROOT:-}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: ci_build.sh is a native Linux production path. Use scripts/build_linux_native_docker.sh outside Linux." >&2
  exit 2
fi
if [[ -z "$VCPKG_ROOT" || ! -d "$VCPKG_ROOT/.git" ]]; then
  echo "ERROR: set EDR_PCRE2_VCPKG_ROOT to a clean vcpkg checkout pinned by dependencies.lock.json." >&2
  exit 2
fi
case "$(uname -m)" in
  x86_64|amd64)
    PCRE2_TARGET="linux/amd64"
    ;;
  aarch64|arm64)
    PCRE2_TARGET="linux/arm64"
    ;;
  *)
    echo "ERROR: unsupported native Linux CPU for the production matcher: $(uname -m)" >&2
    exit 2
    ;;
esac
mkdir -p "$BUILD_DIR"

echo "=== CMake: product build (HTTP ingest/control, no gRPC) ==="
cmake -B "$BUILD_DIR" -DEDR_REQUIRE_PCRE2=ON \
  -DEDR_WITH_INGEST_HTTPS_OPENSSL=ON -DEDR_REQUIRE_HTTPS_REST=ON \
  -DCMAKE_BUILD_TYPE=Release \
  "-DEDR_PCRE2_PRODUCER_TARGET=$PCRE2_TARGET" \
  "-DEDR_PCRE2_VCPKG_ROOT=$VCPKG_ROOT"
cmake --build "$BUILD_DIR" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
if [[ -f "$BUILD_DIR/FDSensor.exe" ]]; then
  print_build_fingerprint "$BUILD_DIR/FDSensor.exe"
elif [[ -f "$BUILD_DIR/edr_agent" ]]; then
  print_build_fingerprint "$BUILD_DIR/edr_agent"
elif [[ -f "$BUILD_DIR/edr_agent.exe" ]]; then
  print_build_fingerprint "$BUILD_DIR/edr_agent.exe"
fi
ctest --test-dir "$BUILD_DIR" --output-on-failure

PCRE2_CONTRACT="$(sed -n 's/^EDR_PCRE2_MATCHER_CONTRACT_AUDIT_PATH:INTERNAL=//p' "$BUILD_DIR/CMakeCache.txt")"
echo "ci_build.sh 完成（CMake build-owned PCRE2 matcher contract: ${PCRE2_CONTRACT:-unavailable}）"
