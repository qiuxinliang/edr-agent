#!/usr/bin/env bash
# 集成冒烟：启动 edr_agent，短暂存活后 SIGINT 退出（需 bash；用于 ctest）
set -eu
AGENT="${1:?usage: agent_smoke.sh /path/to/edr_agent}"
test -x "$AGENT" || {
  echo "not executable: $AGENT" >&2
  exit 1
}

"$AGENT" &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  echo "edr_agent exited before smoke signal" >&2
  exit 1
fi
kill -INT "$pid" 2>/dev/null || true
wait "$pid" || true
exit 0
