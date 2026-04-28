#!/usr/bin/env bash
# 在 Linux 容器（Docker / Podman）内用 apt 安装 CMake、Ninja 与依赖，编译 **本机 Linux** 版 edr_agent。
# 适用于：本机未装 CMake/gRPC、CI、或 IDE 沙箱等隔离环境，与 Trae/云端沙箱「干净环境装依赖再编」同一思路。
#
# 用法（在 edr-agent 仓库根）：
#   chmod +x scripts/build_linux_native_docker.sh
#   ./scripts/build_linux_native_docker.sh
#
# 可选环境变量：
#   EDR_CONTAINER           容器 CLI，默认自动探测 docker → podman（与 build_windows_mingw_docker.sh 一致）
#   EDR_LINUX_DOCKER_IMAGE  默认 ubuntu:22.04
#   EDR_LINUX_DOCKER_EXTRA  附加 docker run 参数，如 '--network host'
#   EDR_WITH_GRPC           默认 OFF；设为 ON 则 apt 装 gRPC 并链接真实客户端
#   EDR_RUN_CTEST           设为 1 时在构建后执行 ctest（部分测试依赖环境，失败时可关）
#   http_proxy / https_proxy  传入容器（宿主机已设时自动 -e）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUTDIR="build-linux"
IMAGE="${EDR_LINUX_DOCKER_IMAGE:-ubuntu:22.04}"
EXTRA="${EDR_LINUX_DOCKER_EXTRA:-}"
REQUIRE_GRPC="${EDR_WITH_GRPC:-OFF}"

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
  "${PROXY_ARGS[@]}" \
  -e "EDR_WITH_GRPC=${REQUIRE_GRPC}" \
  -e "EDR_RUN_CTEST=${EDR_RUN_CTEST:-0}" \
  ${EXTRA} \
  -v "$ROOT:/work" \
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

BASE_PKGS="build-essential cmake ninja-build pkg-config ca-certificates libsqlite3-dev"
if [[ "${EDR_WITH_GRPC}" == "ON" ]] || [[ "${EDR_WITH_GRPC}" == "1" ]] || [[ "${EDR_WITH_GRPC}" == "on" ]]; then
  apt-get install -y -qq --no-install-recommends ${BASE_PKGS} \
    libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc libssl-dev
else
  apt-get install -y -qq --no-install-recommends ${BASE_PKGS}
fi

rm -rf build-linux
cmake -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DEDR_WITH_GRPC="$(
    if [[ "${EDR_WITH_GRPC}" == "OFF" ]] || [[ "${EDR_WITH_GRPC}" == "0" ]] || [[ "${EDR_WITH_GRPC}" == "off" ]]; then echo OFF; else echo ON; fi
  )" \
  -S .
cmake --build build-linux --target edr_agent -j"$(nproc 2>/dev/null || echo 4)"

if [[ "${EDR_RUN_CTEST:-0}" == "1" ]]; then
  cd build-linux && ctest --output-on-failure -j"$(nproc 2>/dev/null || echo 4)" || true
fi
'

echo "OK: 本机 Linux 产物见 ${ROOT}/${OUTDIR}/edr_agent（容器内编译，ELF x86_64）"
ls -la "${ROOT}/${OUTDIR}/edr_agent" 2>/dev/null || true
