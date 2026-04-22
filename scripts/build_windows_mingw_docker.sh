#!/usr/bin/env bash
# 用容器（Docker / Podman 等）交叉编译 Windows 版 edr_agent（不依赖 Homebrew ghcr / 本机 MinGW）。
# 在 ubuntu 镜像内用 apt 安装 mingw-w64 + cmake + ninja，与 ghcr.io 无关。
#
# 用法：
#   chmod +x scripts/build_windows_mingw_docker.sh
#   ./scripts/build_windows_mingw_docker.sh
#
# 可选环境变量：
#   EDR_CONTAINER            容器 CLI，默认自动：先试 docker，再试 podman（Docker Desktop 不可用时可用 Colima+Docker CLI 或 Podman）
#   EDR_MINGW_DOCKER_IMAGE   默认 ubuntu:22.04（可改为 ubuntu:24.04 等）
#   EDR_MINGW_DOCKER_EXTRA   附加 docker run 参数，例如 '--network host'（部分网络环境 apt 更稳）
#   http_proxy / https_proxy  传入容器（若宿主机已设，会自动 -e 传入）
# 终端编译注意：宿主机侧 build-mingw/ 与容器内产物宜保留以便后查，勿习惯性全删（见 docs/WINDOWS_CROSS_COMPILE.md「终端编译注意要点」）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TOOLCHAIN="cmake/mingw-w64-x86_64.cmake"
OUTDIR="build-mingw"
IMAGE="${EDR_MINGW_DOCKER_IMAGE:-ubuntu:22.04}"
EXTRA="${EDR_MINGW_DOCKER_EXTRA:-}"
REQUIRE_GRPC="${EDR_REQUIRE_GRPC:-1}"

ENGINE="${EDR_CONTAINER:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ENGINE=docker
  elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    ENGINE=podman
  fi
fi

if [[ -z "$ENGINE" ]]; then
  echo "未检测到可用的容器引擎（docker / podman 均未就绪）。"
  echo "  Docker Desktop 异常时，可任选其一："
  echo "    - Colima + Docker CLI：brew install colima docker && colima start"
  echo "    - Podman：brew install podman && podman machine init && podman machine start"
  echo "    - OrbStack 等替代 Docker Desktop 的发行版"
  echo "  或完全不用容器：见 docs/WINDOWS_CROSS_COMPILE.md（MacPorts / MINGW_PREFIX）"
  exit 1
fi

PROXY_ARGS=()
if [[ -n "${http_proxy:-}" ]]; then
  PROXY_ARGS+=(-e "http_proxy=${http_proxy}")
fi
if [[ -n "${https_proxy:-}" ]]; then
  PROXY_ARGS+=(-e "https_proxy=${https_proxy}")
fi
if [[ -n "${HTTP_PROXY:-}" ]]; then
  PROXY_ARGS+=(-e "HTTP_PROXY=${HTTP_PROXY}")
fi
if [[ -n "${HTTPS_PROXY:-}" ]]; then
  PROXY_ARGS+=(-e "HTTPS_PROXY=${HTTPS_PROXY}")
fi

# shellcheck disable=SC2086
"$ENGINE" run --rm \
  "${PROXY_ARGS[@]}" \
  -e "EDR_REQUIRE_GRPC=${REQUIRE_GRPC}" \
  ${EXTRA} \
  -v "$ROOT:/work" \
  -w /work \
  "$IMAGE" \
  bash -ec '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
for attempt in 1 2 3 4 5; do
  if apt-get update -qq; then
    break
  fi
  echo "[container] apt-get update failed, retry ${attempt}/5 in 8s..."
  sleep 8
done
apt-get install -y -qq --no-install-recommends \
  mingw-w64 cmake ninja-build ca-certificates
rm -rf build-mingw
cmake -B build-mingw -G Ninja -DCMAKE_TOOLCHAIN_FILE='"$TOOLCHAIN"' -DEDR_WITH_GRPC=ON -S .
if [[ "${EDR_REQUIRE_GRPC:-1}" == "1" ]]; then
  if ! awk '"'"'BEGIN{ok=0} $0=="EDR_GRPC_CLIENT_AVAILABLE:INTERNAL=1"{ok=1} END{exit(ok?0:1)}'"'"' build-mingw/CMakeCache.txt; then
    echo "ERROR: container MinGW toolchain missing gRPC/protobuf for Windows target (stub would be used)."
    echo "Set EDR_REQUIRE_GRPC=0 only if you intentionally want stub transport."
    exit 2
  fi
fi
cmake --build build-mingw --target edr_agent -j4
'

echo "OK: ${ROOT}/${OUTDIR}/ 下生成 Windows 目标（见 edr_agent.exe 或构建日志）"
ls -la "${ROOT}/${OUTDIR}/"edr_agent.exe 2>/dev/null || ls -la "${ROOT}/${OUTDIR}/"edr_agent 2>/dev/null || true
