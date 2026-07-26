#!/usr/bin/env bash
# A4.1：本地复现事件总线 MPMC 压测；与 `ctest -R test_event_bus_mpmc_stress` 同二进制。
# 用法：
#   ./scripts/run_event_bus_mpmc_stress.sh
#   ./scripts/run_event_bus_mpmc_stress.sh /path/to/cmake-build-dir
#   ./scripts/run_event_bus_mpmc_stress.sh /path/to/build 30000 8 256
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BDIR="${ROOT}/out/build/any-ninja-fast-dev"
if [[ $# -ge 1 && -d "$1" ]]; then
  BDIR="$1"
  shift
fi
BIN="${BDIR}/test_event_bus_mpmc_stress"
if [[ ! -e "$BIN" ]]; then
  echo "缺少: $BIN" >&2
  echo "请先: cmake -S \"${ROOT}\" -B \"${BDIR}\" -G Ninja -DEDR_WITH_GRPC=OFF && cmake --build \"${BDIR}\" --target test_event_bus_mpmc_stress" >&2
  exit 1
fi
if [[ $# -eq 0 ]]; then
  set -- 250 4 64
fi
exec "$BIN" "$@"
