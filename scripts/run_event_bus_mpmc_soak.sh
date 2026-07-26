#!/usr/bin/env bash
# A4.1 P2：事件总线 MPMC 长 soak 包装；与 `scripts/run_event_bus_mpmc_stress.sh` 同参序。
# 与 `ctest -R test_event_bus_mpmc_stress` / `build/test_event_bus_mpmc_stress` 一致：参数为
#   <总时长_ms> <生产线程数> <队列槽深>（见 tests/test_event_bus_mpmc_stress.c）
#
# 环境变量:
#   DURATION_MS  总运行毫秒（默认 3600000 = 1h）；也可直接传为第一个**数值**给底层 stress
#
# 用法:
#   ./scripts/run_event_bus_mpmc_soak.sh
#   ./scripts/run_event_bus_mpmc_soak.sh /path/build 600000 8 256
#   DURATION_MS=7200000 ./scripts/run_event_bus_mpmc_soak.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BDIR="${ROOT}/out/build/any-ninja-fast-dev"
DURATION_MS="${DURATION_MS:-3600000}"
if [[ $# -ge 1 && -d "$1" ]]; then
  BDIR="$1"
  shift
fi
if [[ $# -eq 0 ]]; then
  set -- "$DURATION_MS" 4 64
fi
STRESS="${ROOT}/scripts/run_event_bus_mpmc_stress.sh"
echo "A4.1 soak: 调用 ${STRESS} ${BDIR} $*" >&2
exec "$STRESS" "$BDIR" "$@"
