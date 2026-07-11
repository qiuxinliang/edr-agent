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
#   EDR_MINGW_DEPS_PREFIX     Windows 目标依赖前缀，需指向 vcpkg MinGW 动态 triplet（如 x64-mingw-dynamic），且含 curl+nghttp2+unofficial-libyara config+YARA DLL/静态库
#   EDR_MINGW_GRPC_PREFIX     兼容旧变量名，等同于 EDR_MINGW_DEPS_PREFIX
# 终端编译注意：宿主机侧 build-mingw/ 与容器内产物宜保留以便后查，勿习惯性全删（见 docs/WINDOWS_CROSS_COMPILE.md「终端编译注意要点」）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TOOLCHAIN="cmake/mingw-w64-x86_64.cmake"
OUTDIR="build-mingw"
IMAGE="${EDR_MINGW_DOCKER_IMAGE:-ubuntu:22.04}"
EXTRA="${EDR_MINGW_DOCKER_EXTRA:-}"
DEPS_PREFIX="${EDR_MINGW_DEPS_PREFIX:-${EDR_MINGW_GRPC_PREFIX:-}}"

if [[ -z "$DEPS_PREFIX" || ! -d "$DEPS_PREFIX" ]]; then
  echo "ERROR: EDR_MINGW_DEPS_PREFIX must reference an existing vcpkg MinGW dependency prefix." >&2
  exit 2
fi

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
  -e "EDR_MINGW_DEPS_PREFIX=${DEPS_PREFIX}" \
  ${EXTRA} \
  -v "$ROOT:/work" \
  -v "$DEPS_PREFIX:$DEPS_PREFIX:ro" \
  -w /work \
  "$IMAGE" \
  bash -ec '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PKG_CONFIG_LIBDIR="${EDR_MINGW_DEPS_PREFIX}/lib/pkgconfig"
for attempt in 1 2 3 4 5; do
  if apt-get update -qq; then
    break
  fi
  echo "[container] apt-get update failed, retry ${attempt}/5 in 8s..."
  sleep 8
done
apt-get install -y -qq --no-install-recommends \
  mingw-w64 cmake ninja-build ca-certificates
if [[ -z "${EDR_MINGW_DEPS_PREFIX:-}" ]]; then
  echo "ERROR: EDR_MINGW_DEPS_PREFIX is required for Windows MinGW package builds."
  echo "Set it to a vcpkg MinGW dynamic triplet prefix, e.g. installed/x64-mingw-dynamic; do not use MSVC x64-windows."
  exit 2
fi
if [[ ! -f "${EDR_MINGW_DEPS_PREFIX}/include/curl/curl.h" ]]; then
  echo "ERROR: EDR_WITH_HTTP2_CURL=ON requires a Windows-target dependency prefix with curl/nghttp2."
  echo "Set EDR_MINGW_DEPS_PREFIX to vcpkg installed/<triplet> containing include/curl/curl.h and libcurl."
  exit 2
fi
if [[ ! -f "${EDR_MINGW_DEPS_PREFIX}/include/yara.h" && ! -f "${EDR_MINGW_DEPS_PREFIX}/include/yara/yara.h" ]]; then
  echo "ERROR: EDR_REQUIRE_YARA=ON requires YARA headers under ${EDR_MINGW_DEPS_PREFIX}/include."
  echo "Install the vcpkg yara feature for a MinGW dynamic triplet such as x64-mingw-dynamic."
  exit 2
fi
if [[ ! -f "${EDR_MINGW_DEPS_PREFIX}/share/unofficial-libyara/unofficial-libyara-config.cmake" ]]; then
  echo "ERROR: vcpkg unofficial-libyara config package missing under ${EDR_MINGW_DEPS_PREFIX}/share/unofficial-libyara."
  echo "Windows MinGW YARA builds must use vcpkg libyara, not a manual YARA_ROOT fallback."
  exit 2
fi
shopt -s nullglob
yara_dlls=("${EDR_MINGW_DEPS_PREFIX}"/bin/*yara*.dll "${EDR_MINGW_DEPS_PREFIX}"/bin/*YARA*.dll "${EDR_MINGW_DEPS_PREFIX}"/bin/libyara*.dll "${EDR_MINGW_DEPS_PREFIX}"/bin/libYARA*.dll)
yara_static=("${EDR_MINGW_DEPS_PREFIX}"/lib/libyara*.a "${EDR_MINGW_DEPS_PREFIX}"/lib/libYARA*.a "${EDR_MINGW_DEPS_PREFIX}"/lib/liblibyara*.a)
shopt -u nullglob
if [[ ${#yara_dlls[@]} -lt 1 && ${#yara_static[@]} -lt 1 ]]; then
  echo "ERROR: vcpkg YARA library missing (expected runtime DLL or static archive)."
  echo "Install the vcpkg yara feature for x64-mingw-dynamic; manual YARA_ROOT fallback is not accepted."
  exit 2
fi
rm -rf build-mingw
cmake -B build-mingw -G Ninja -DCMAKE_TOOLCHAIN_FILE='"$TOOLCHAIN"' -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="${EDR_MINGW_DEPS_PREFIX}" -DOPENSSL_ROOT_DIR="${EDR_MINGW_DEPS_PREFIX}" -DOPENSSL_USE_STATIC_LIBS=OFF -DOPENSSL_SSL_LIBRARY="${EDR_MINGW_DEPS_PREFIX}/lib/libssl.dll.a" -DOPENSSL_CRYPTO_LIBRARY="${EDR_MINGW_DEPS_PREFIX}/lib/libcrypto.dll.a" -DSSL_EAY="${EDR_MINGW_DEPS_PREFIX}/lib/libssl.dll.a" -DLIB_EAY="${EDR_MINGW_DEPS_PREFIX}/lib/libcrypto.dll.a" -DPCRE2_DIR="${EDR_MINGW_DEPS_PREFIX}/share/pcre2" -Dzstd_DIR="${EDR_MINGW_DEPS_PREFIX}/share/zstd" -DEDR_WITH_GRPC=OFF -DEDR_WITH_FL_TRAINER=OFF -DEDR_WITH_FL_KAFKA=OFF -DEDR_WITH_HTTP2_CURL=ON -DEDR_REQUIRE_CURL_HTTP2=ON -DEDR_WITH_YARA=ON -DEDR_REQUIRE_YARA=ON -DVCPKG_MANIFEST_FEATURES=yara -S .
cmake --build build-mingw --target edr_agent -j4
bash scripts/stage_mingw_runtime_dlls.sh build-mingw/FDSensor.exe "${EDR_MINGW_DEPS_PREFIX}" x86_64-w64-mingw32-gcc x86_64-w64-mingw32-objdump
'

echo "OK: ${ROOT}/${OUTDIR}/ 下生成 Windows 目标（见 FDSensor.exe 或构建日志）"
ls -la "${ROOT}/${OUTDIR}/"FDSensor.exe 2>/dev/null || ls -la "${ROOT}/${OUTDIR}/"edr_agent.exe 2>/dev/null || ls -la "${ROOT}/${OUTDIR}/"edr_agent 2>/dev/null || true
