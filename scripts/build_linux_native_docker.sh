#!/usr/bin/env bash
# 在 Linux 容器（Docker / Podman）内用 apt 安装 CMake、Ninja 与依赖，编译 **本机 Linux** 版 edr_agent。
# 适用于：本机未装 CMake、CI、或 IDE 沙箱等隔离环境，与 Trae/云端沙箱「干净环境装依赖再编」同一思路。
#
# 用法（在 edr-agent 仓库根）：
#   chmod +x scripts/build_linux_native_docker.sh
#   ./scripts/build_linux_native_docker.sh
#
# 可选环境变量：
#   EDR_CONTAINER           容器 CLI，默认自动探测 docker → podman（与 build_windows_mingw_docker.sh 一致）
#   EDR_LINUX_DOCKER_IMAGE  默认 ubuntu:22.04
#   EDR_LINUX_DOCKER_EXTRA  附加 docker run 参数，如 '--network host'
#   EDR_LINUX_BUILD_DIR     必须为空的绝对构建目录；用于从只读源码快照实建
#   EDR_PCRE2_VCPKG_ROOT    Agent 锁定 baseline 的干净 vcpkg checkout；生产
#                           matcher 仅从该源码构建，不能使用 apt 的 PCRE2
#   EDR_RUN_CTEST           设为 1 时在构建后执行 ctest；测试失败会使构建失败
#   http_proxy / https_proxy  传入容器（宿主机已设时自动 -e）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD_DIR="${EDR_LINUX_BUILD_DIR:-$ROOT/build-linux}"
IMAGE="${EDR_LINUX_DOCKER_IMAGE:-ubuntu:22.04}"
EXTRA="${EDR_LINUX_DOCKER_EXTRA:-}"
VCPKG_ROOT="${EDR_PCRE2_VCPKG_ROOT:-}"
if [[ "$BUILD_DIR" != /* ]]; then
  echo "ERROR: EDR_LINUX_BUILD_DIR must be an absolute path" >&2
  exit 2
fi
if [[ -e "$BUILD_DIR" && ! -d "$BUILD_DIR" ]]; then
  echo "ERROR: EDR_LINUX_BUILD_DIR is not a directory: $BUILD_DIR" >&2
  exit 2
fi
mkdir -p "$BUILD_DIR"
BUILD_DIR="$(cd "$BUILD_DIR" && pwd -P)"
if [[ -n "$(find "$BUILD_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "ERROR: EDR_LINUX_BUILD_DIR must be empty for a fresh production build: $BUILD_DIR" >&2
  exit 2
fi
if [[ -z "$VCPKG_ROOT" || ! -d "$VCPKG_ROOT/.git" ]]; then
  echo "ERROR: production Linux matcher build requires EDR_PCRE2_VCPKG_ROOT to name a clean pinned vcpkg checkout." >&2
  exit 2
fi
VCPKG_ROOT="$(cd "$VCPKG_ROOT" && pwd -P)"

ENGINE="${EDR_CONTAINER:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ENGINE=docker
  elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    ENGINE=podman
  fi
fi

if [[ -z "$ENGINE" ]]; then
  echo "未检测到可用的容器引擎（docker / podman）。请先安装并启动，参见 docs/WINDOWS_CROSS_COMPILE.md §0。"
  exit 1
fi

PROXY_ARGS=()
if [[ -n "${http_proxy:-}" ]]; then PROXY_ARGS+=(-e "http_proxy=${http_proxy}"); fi
if [[ -n "${https_proxy:-}" ]]; then PROXY_ARGS+=(-e "https_proxy=${https_proxy}"); fi
if [[ -n "${HTTP_PROXY:-}" ]]; then PROXY_ARGS+=(-e "HTTP_PROXY=${HTTP_PROXY}"); fi
if [[ -n "${HTTPS_PROXY:-}" ]]; then PROXY_ARGS+=(-e "HTTPS_PROXY=${HTTPS_PROXY}"); fi

# shellcheck disable=SC2086
"$ENGINE" run --rm \
  ${PROXY_ARGS[@]+"${PROXY_ARGS[@]}"} \
  -e "EDR_RUN_CTEST=${EDR_RUN_CTEST:-0}" \
  ${EXTRA} \
  -v "$ROOT:/work:ro" \
  -v "$BUILD_DIR:/build" \
  -v "$VCPKG_ROOT:/vcpkg-source:ro" \
  -w /work \
  "$IMAGE" \
  bash -ec '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
for attempt in 1 2 3 4 5; do
  if apt-get update -qq; then break; fi
  echo "[container] apt-get update failed, retry ${attempt}/5 in 8s..."
  sleep 8
done

BASE_PKGS="build-essential cmake ninja-build pkg-config ca-certificates curl git python3 libsqlite3-dev libssl-dev tar unzip zip"
apt-get install -y -qq --no-install-recommends ${BASE_PKGS}

case "$(uname -m)" in
  x86_64|amd64)
    PCRE2_TARGET="linux/amd64"
    ;;
  aarch64|arm64)
    PCRE2_TARGET="linux/arm64"
    ;;
  *)
    echo "unsupported container CPU for native production matcher: $(uname -m)" >&2
    exit 2
    ;;
esac

# The mounted checkout remains read-only. vcpkg writes buildtrees/downloads
# beside its checkout, so make a disposable clean copy before bootstrapping.
cp -a /vcpkg-source /tmp/edr-pcre2-vcpkg
rm -f /tmp/edr-pcre2-vcpkg/vcpkg /tmp/edr-pcre2-vcpkg/vcpkg.exe
/tmp/edr-pcre2-vcpkg/bootstrap-vcpkg.sh -disableMetrics

BUILD_TESTS=OFF
if [[ "${EDR_RUN_CTEST:-0}" == "1" ]]; then
  BUILD_TESTS=ON
fi

cmake -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DEDR_REQUIRE_PCRE2=ON \
  -DEDR_WITH_INGEST_HTTPS_OPENSSL=ON \
  -DEDR_REQUIRE_HTTPS_REST=ON \
  "-DEDR_BUILD_TESTS=$BUILD_TESTS" \
  "-DEDR_PCRE2_PRODUCER_TARGET=$PCRE2_TARGET" \
  "-DEDR_PCRE2_VCPKG_ROOT=/tmp/edr-pcre2-vcpkg" \
  -S /work 2>&1 | tee /build/configure.log
if [[ "${EDR_RUN_CTEST:-0}" == "1" ]]; then
  # Build the default target graph so every registered CTest executable exists.
  cmake --build /build -j"$(nproc 2>/dev/null || echo 4)" 2>&1 | tee /build/build.log
  ctest --test-dir /build --output-on-failure -j"$(nproc 2>/dev/null || echo 4)" 2>&1 | tee /build/ctest.log
else
  cmake --build /build --target edr_agent -j"$(nproc 2>/dev/null || echo 4)" 2>&1 | tee /build/build.log
fi
'

echo "OK: 本机 Linux 产物与已验证 matcher contract 见 ${BUILD_DIR}/（容器内原生目标）"
ls -la "${BUILD_DIR}/edr_agent" 2>/dev/null || true
