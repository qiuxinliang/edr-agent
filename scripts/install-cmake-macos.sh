#!/usr/bin/env bash
# 在 macOS 上安装 CMake，供 edr-agent 等客户端用 CMake 构建。
# 优先使用 Homebrew；若无 brew，则下载 Kitware 官方 macOS universal 压缩包到 ~/.local/share/edr/cmake/<version>/
#
# 用法：
#   ./scripts/install-cmake-macos.sh
#   CMAKE_VERSION=3.31.6 ./scripts/install-cmake-macos.sh

set -euo pipefail

VERSION="${CMAKE_VERSION:-3.31.6}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is for macOS only." >&2
  exit 1
fi

if command -v brew >/dev/null 2>&1; then
  echo "Found Homebrew; installing CMake via brew."
  brew install cmake
  echo
  cmake --version
  exit 0
fi

BASE_URL="https://github.com/Kitware/CMake/releases/download/v${VERSION}"
ARCHIVE="cmake-${VERSION}-macos-universal.tar.gz"
ROOT="${CMAKE_HOME:-$HOME/.local/share/edr/cmake/${VERSION}}"
TOP="${ROOT}/cmake-${VERSION}-macos-universal"
BIN="${TOP}/CMake.app/Contents/bin"

if [[ -x "${BIN}/cmake" ]]; then
  echo "CMake ${VERSION} already installed at:"
  echo "  ${BIN}"
else
  mkdir -p "${ROOT}"
  TMP="${ROOT}/${ARCHIVE}.part"
  echo "Downloading ${ARCHIVE} (may take a few minutes) ..."
  curl -fSL --silent --show-error --retry 3 --retry-delay 2 "${BASE_URL}/${ARCHIVE}" -o "${TMP}"
  echo "Extracting to ${ROOT} ..."
  tar -xzf "${TMP}" -C "${ROOT}"
  rm -f "${TMP}"
fi

echo
"${BIN}/cmake" --version
echo
echo "Add CMake to your PATH (e.g. in ~/.zshrc):"
echo "  export PATH=\"${BIN}:\$PATH\""
