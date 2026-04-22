#!/usr/bin/env bash
# 无 MSVC 时用 MinGW-w64 交叉编译 Windows 版 edr_agent，验证 iphlpapi / MIB_TCP6* 等能否通过编译。
# 依赖（任选其一）：
#   - 本机 PATH 中有 x86_64-w64-mingw32-gcc（如 brew / MacPorts 等）
#   - 环境变量 MINGW_PREFIX 指向工具链根目录（其下须有 bin/x86_64-w64-mingw32-gcc），可不依赖 Homebrew
#   - 容器：docker 或 podman 就绪 → **scripts/build_windows_mingw_docker.sh**（apt，不经 ghcr；可不依赖 Docker Desktop）
# Homebrew 安装 mingw-w64 若遇 ghcr 超时，见 docs/WINDOWS_CROSS_COMPILE.md
# 终端编译注意：勿随意 rm -rf 构建目录；保留 CMakeCache、ninja、*.obj 等便于排错（见同文档「终端编译注意要点」）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$ROOT/cmake/mingw-w64-x86_64.cmake"
OUTDIR="${ROOT}/build-mingw"
REQUIRE_GRPC="${EDR_REQUIRE_GRPC:-1}"
GRPC_PREFIX="${EDR_MINGW_GRPC_PREFIX:-}"

mingw_gcc_path() {
  if [[ -n "${MINGW_PREFIX:-}" ]]; then
    echo "${MINGW_PREFIX%/}/bin/x86_64-w64-mingw32-gcc"
  else
    command -v x86_64-w64-mingw32-gcc 2>/dev/null || true
  fi
}

build_local() {
  cmake_args=(
    -B "$OUTDIR"
    -G Ninja
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN"
    -DEDR_WITH_GRPC=ON
    -S "$ROOT"
  )
  if [[ -n "$GRPC_PREFIX" ]]; then
    export EDR_MINGW_GRPC_PREFIX="$GRPC_PREFIX"
    cmake_args+=("-DCMAKE_PREFIX_PATH=$GRPC_PREFIX")
  fi
  cmake "${cmake_args[@]}"
  if [[ "$REQUIRE_GRPC" == "1" ]]; then
    if ! awk 'BEGIN{ok=0} $0=="EDR_GRPC_CLIENT_AVAILABLE:INTERNAL=1"{ok=1} END{exit(ok?0:1)}' "$OUTDIR/CMakeCache.txt"; then
      echo "ERROR: configure succeeded but gRPC client is unavailable (would fall back to stub)."
      echo "Hint:"
      echo "  - provide MinGW-targeted grpc/protobuf via EDR_MINGW_GRPC_PREFIX"
      echo "  - verify gRPC CMake package: <prefix>/share/grpc/gRPCConfig.cmake (vcpkg layout)"
      echo "  - verify protobuf CMake package: <prefix>/share/protobuf/protobuf-config.cmake"
      echo "  - to bypass check temporarily: EDR_REQUIRE_GRPC=0 $0"
      exit 2
    fi
  fi
  cmake --build "$OUTDIR" --target edr_agent -j"${NPROC:-4}"
  echo "OK: $OUTDIR/edr_agent.exe (MinGW)"
  ls -la "$OUTDIR"/edr_agent.exe 2>/dev/null || ls -la "$OUTDIR"/edr_agent 2>/dev/null || true
}

if [[ -n "${MINGW_PREFIX:-}" ]]; then
  _gcc="$(mingw_gcc_path)"
  if [[ -x "$_gcc" ]]; then
    export MINGW_PREFIX
    export PATH="${MINGW_PREFIX%/}/bin:${PATH}"
    NPROC="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
    build_local
    exit 0
  fi
  echo "MINGW_PREFIX 已设置但不可执行: $_gcc"
  exit 1
fi

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  NPROC="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
  build_local
  exit 0
fi

if (command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1) ||
   (command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1); then
  exec bash "$ROOT/scripts/build_windows_mingw_docker.sh"
fi

echo "未找到 x86_64-w64-mingw32-gcc，且本机无可用容器引擎（docker / podman 均未就绪）。"
echo "  可选："
echo "    ./scripts/build_windows_mingw_docker.sh   # Colima/Podman/Docker 任一可用即可，不经 Homebrew ghcr"
echo "    文档: docs/WINDOWS_CROSS_COMPILE.md"
echo "    export MINGW_PREFIX=/path/to/mingw-root   # 须含 bin/x86_64-w64-mingw32-gcc，再运行 $0"
echo "    或: sudo port install mingw-w64          # MacPorts"
echo "  Docker Desktop 异常时：brew install colima docker && colima start 后重试；或 Podman Machine。"
echo "  Homebrew ghcr 超时：勿依赖 brew bottle；用容器路径或 MINGW_PREFIX / MacPorts。"
exit 1
