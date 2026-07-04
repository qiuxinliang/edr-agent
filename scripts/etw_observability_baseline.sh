#!/usr/bin/env bash
# A1.2：ETW 可观测基线实验说明（10+ 分钟、同机同负载前后对比用）。
# 与 `EDR_ETW_OBS` / `[etw_obs]` 行及 `edr_agent` console heartbeat 同周期，见 README 环境变量表。
# 用法：bash edr-agent/scripts/etw_observability_baseline.sh
#       PRINT_ONLY=1 bash …   # 只打印要设置的环境变量，不启动 Agent
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== A1.2 ETW 可观测基线（与任务包 A1.1 输出同口径）"
echo "仓库 edr-agent: $ROOT"
echo ""
echo "1) 在**管理员** PowerShell 或 cmd 中设置（示例：60s 打一行 [heartbeat] + [etw_obs]）："
echo "   set EDR_ETW_OBS=1"
echo "   set EDR_CONSOLE_HEARTBEAT_SEC=60"
echo "2) 启动 edr_agent（工作目录、agent.toml 按你环境）："
echo "   Windows 例: <build>/Release/edr_agent.exe ； macOS/Linux: <build>/edr_agent"
echo "3) 保持**同一负载**（同场景/同压测脚本）跑 **≥10 分钟**；将 stderr 重定向到文件便于 diff："
echo "   edr_agent.exe 2> etw_baseline_pre.log"
echo "   P2：也可设 EDR_ETW_OBS_EXPORT_PATH=C:\\edr\\etw_obs.log（与 EDR_ETW_OBS=1 同用），[etw_obs] 会追加到该文件，便于 log shipper/集中检索。"
echo "4) 改代码/调参后重复步骤 3，对两份 log 中的 [etw_obs] 行做对比（etw_cb、tag 分桶、pl0、bus push/drop、tdh err%）。"
echo ""
if [[ "${PRINT_ONLY:-0}" == "1" ]]; then
  echo "export EDR_ETW_OBS=1"
  echo "export EDR_CONSOLE_HEARTBEAT_SEC=60"
  exit 0
fi
echo "（本脚本不自动启动 Agent；上为检查清单。POSIX 可改用: export EDR_ETW_OBS=1 EDR_CONSOLE_HEARTBEAT_SEC=60）"
exit 0
