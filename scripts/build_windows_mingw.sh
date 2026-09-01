#!/usr/bin/env bash
# 无 MSVC 时用 MinGW-w64 交叉编译 Windows 版 FDSensor，验证 iphlpapi / MIB_TCP6* 等能否通过编译。
# 这是显式非生产 source-only 检查：MSVC 生产/Release 必须由锁定 vcpkg
# producer 生成静态 PCRE2 contract，不能把该 MinGW 产物用于发布。
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
DEPS_PREFIX="${EDR_MINGW_DEPS_PREFIX:-${EDR_MINGW_GRPC_PREFIX:-}}"

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
  echo "OK: build fingerprint git=${git_short}(${git_dirty}) sha256=${bin_sha} mtime=${bin_mtime} bin=${bin_path}"
}

mingw_gcc_path() {
  if [[ -n "${MINGW_PREFIX:-}" ]]; then
    echo "${MINGW_PREFIX%/}/bin/x86_64-w64-mingw32-gcc"
  else
    command -v x86_64-w64-mingw32-gcc 2>/dev/null || true
  fi
}

require_mingw_vcpkg_yara_deps() {
  if [[ -z "$DEPS_PREFIX" ]]; then
    echo "ERROR: Windows MinGW package builds require EDR_MINGW_DEPS_PREFIX." >&2
    echo "Set EDR_MINGW_DEPS_PREFIX to a vcpkg MinGW dynamic triplet prefix, e.g. installed/x64-mingw-dynamic." >&2
    echo "Do not point it at an MSVC x64-windows prefix." >&2
    exit 2
  fi
  if [[ ! -f "$DEPS_PREFIX/include/curl/curl.h" ]]; then
    echo "ERROR: EDR_WITH_HTTP2_CURL=ON requires $DEPS_PREFIX/include/curl/curl.h." >&2
    echo "Set EDR_MINGW_DEPS_PREFIX to vcpkg installed/<triplet> containing curl/nghttp2 for MinGW." >&2
    exit 2
  fi
  if [[ ! -f "$DEPS_PREFIX/include/yara.h" && ! -f "$DEPS_PREFIX/include/yara/yara.h" ]]; then
    echo "ERROR: EDR_REQUIRE_YARA=ON requires YARA headers under $DEPS_PREFIX/include." >&2
    echo "Install the vcpkg yara feature for a MinGW dynamic triplet such as x64-mingw-dynamic." >&2
    exit 2
  fi
  if [[ ! -f "$DEPS_PREFIX/share/unofficial-libyara/unofficial-libyara-config.cmake" ]]; then
    echo "ERROR: vcpkg unofficial-libyara config package missing under $DEPS_PREFIX/share/unofficial-libyara." >&2
    echo "Windows MinGW YARA builds must use vcpkg libyara, not a manual YARA_ROOT fallback." >&2
    exit 2
  fi
  shopt -s nullglob
  local yara_dlls=("$DEPS_PREFIX"/bin/*yara*.dll "$DEPS_PREFIX"/bin/*YARA*.dll "$DEPS_PREFIX"/bin/libyara*.dll "$DEPS_PREFIX"/bin/libYARA*.dll)
  local yara_static=("$DEPS_PREFIX"/lib/libyara*.a "$DEPS_PREFIX"/lib/libYARA*.a "$DEPS_PREFIX"/lib/liblibyara*.a)
  shopt -u nullglob
  if [[ ${#yara_dlls[@]} -lt 1 && ${#yara_static[@]} -lt 1 ]]; then
    echo "ERROR: vcpkg YARA library missing (expected runtime DLL or static archive)." >&2
    echo "Install the vcpkg yara feature for x64-mingw-dynamic; manual YARA_ROOT fallback is not accepted." >&2
    exit 2
  fi
}

build_local() {
  local bin_path gcc_path objdump_path
  require_mingw_vcpkg_yara_deps
  cmake_args=(
    -B "$OUTDIR"
    -G Ninja
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN"
    -DCMAKE_BUILD_TYPE=Debug
    -DEDR_BUILD_TESTS=ON
    -DEDR_REQUIRE_PCRE2=OFF
    -DEDR_P0_RULE_IR_ALLOW_TEST_STUB=ON
    -DEDR_WITH_HTTP2_CURL=ON
    -DEDR_REQUIRE_CURL_HTTP2=ON
    -DEDR_WITH_YARA=ON
    -DEDR_REQUIRE_YARA=ON
    -DVCPKG_MANIFEST_FEATURES=yara
    -S "$ROOT"
  )
  export EDR_MINGW_DEPS_PREFIX="$DEPS_PREFIX"
  export PKG_CONFIG_LIBDIR="$DEPS_PREFIX/lib/pkgconfig"
  cmake_args+=("-UOPENSSL_*")
  cmake_args+=("-ULIB_EAY" "-USSL_EAY")
  cmake_args+=("-UEDR_PCRE2_*" "-UPCRE2_*")
  cmake_args+=("-UProtobuf_DIR" "-Uabsl_DIR" "-Uc-ares_DIR" "-Ure2_DIR" "-Uutf8_range_DIR")
  cmake_args+=("-DOPENSSL_ROOT_DIR=$DEPS_PREFIX")
  cmake_args+=("-DOPENSSL_USE_STATIC_LIBS=OFF")
  cmake_args+=("-DOPENSSL_SSL_LIBRARY=$DEPS_PREFIX/lib/libssl.dll.a")
  cmake_args+=("-DOPENSSL_CRYPTO_LIBRARY=$DEPS_PREFIX/lib/libcrypto.dll.a")
  cmake_args+=("-DSSL_EAY=$DEPS_PREFIX/lib/libssl.dll.a")
  cmake_args+=("-DLIB_EAY=$DEPS_PREFIX/lib/libcrypto.dll.a")
  cmake_args+=("-DCMAKE_PREFIX_PATH=$DEPS_PREFIX")
  cmake_args+=("-DPCRE2_DIR=$DEPS_PREFIX/share/pcre2")
  cmake_args+=("-Dzstd_DIR=$DEPS_PREFIX/share/zstd")
  cmake "${cmake_args[@]}"
  cmake --build "$OUTDIR" --target edr_agent -j"${NPROC:-4}"
  echo "OK: $OUTDIR/FDSensor.exe (MinGW explicit non-production P0 source-only build)"
  ls -la "$OUTDIR"/FDSensor.exe 2>/dev/null || ls -la "$OUTDIR"/edr_agent.exe 2>/dev/null || ls -la "$OUTDIR"/edr_agent 2>/dev/null || true
  if [[ -f "$OUTDIR/FDSensor.exe" ]]; then
    bin_path="$OUTDIR/FDSensor.exe"
  elif [[ -f "$OUTDIR/edr_agent.exe" ]]; then
    bin_path="$OUTDIR/edr_agent.exe"
  elif [[ -f "$OUTDIR/edr_agent" ]]; then
    bin_path="$OUTDIR/edr_agent"
  else
    echo "ERROR: MinGW build completed without an Agent executable." >&2
    exit 3
  fi
  gcc_path="$(mingw_gcc_path)"
  objdump_path="${gcc_path%gcc}objdump"
  bash "$ROOT/scripts/stage_mingw_runtime_dlls.sh" "$bin_path" "$DEPS_PREFIX" "$gcc_path" "$objdump_path"
  print_build_fingerprint "$bin_path"
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
echo "    export EDR_MINGW_DEPS_PREFIX=/path/to/vcpkg/installed/x64-mingw-dynamic  # 须含 curl + unofficial-libyara config + YARA DLL/静态库"
echo "    或: sudo port install mingw-w64          # MacPorts"
echo "  Docker Desktop 异常时：brew install colima docker && colima start 后重试；或 Podman Machine。"
echo "  Homebrew ghcr 超时：勿依赖 brew bottle；用容器路径或 MINGW_PREFIX / MacPorts。"
exit 1
