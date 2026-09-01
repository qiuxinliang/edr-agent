#!/usr/bin/env bash
# 集成冒烟：启动 edr_agent，短暂存活后 SIGINT 退出（需 bash；用于 ctest）
set -eu
AGENT="${1:?usage: agent_smoke.sh /path/to/edr_agent}"
test -x "$AGENT" || {
  echo "not executable: $AGENT" >&2
  exit 1
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/edr-agent-smoke.XXXXXX")
pid=""
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" || true
  fi
  rm -rf -- "$work_dir"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

# Smoke instances must never share the build-directory default databases: a
# concurrent CTest can otherwise inherit a source-only recovery latch or queue
# lock from another agent. Both persistent stores live under one owned temp
# directory and are removed only after the child has exited.
EDR_QUEUE_PATH="$work_dir/queue.db" \
EDR_EVIDENCE_CACHE_PATH="$work_dir/evidence.db" \
  "$AGENT" &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  echo "edr_agent exited before smoke signal" >&2
  exit 1
fi
kill -INT "$pid" 2>/dev/null || true
wait "$pid" || true
pid=""
exit 0
