#!/usr/bin/env bash
# §B2 伴生 watchdog 端到端冒烟（POSIX）：
#   1) 启用 watchdog_process 启动 agent，确认伴生 watchdog 进程出现；
#   2) kill -9 主 agent，确认被 watchdog 重新拉起（新 pid）；
#   3) kill 伴生 watchdog，确认被 agent 重新拉起；
#   4) 干净退出（SIGINT）后写 stop stamp，watchdog 不再重启并退出。
#
# 用法：AGENT_BIN=./build_wd/edr_agent CONFIG=/tmp/wd_agent.toml bash scripts/watchdog_smoke.sh
set -u

AGENT_BIN="${AGENT_BIN:-./build_wd/edr_agent}"
WORK="$(mktemp -d)"
# 自带配置：关闭采集/网络，并把 watchdog 心跳间隔调小以加快冒烟。
CONFIG="${CONFIG:-$WORK/agent.toml}"
if [ ! -f "$CONFIG" ]; then
  cat > "$CONFIG" <<EOF
[server]
address = ""
[agent]
endpoint_id = "smoke-ep"
tenant_id = "smoke-tn"
[collection]
etw_enabled = false
[platform]
rest_base_url = ""
[self_protect]
watchdog_process = true
watchdog_heartbeat_interval_s = 2
watchdog_stale_timeout_s = 6
EOF
fi
PIDFILE="$WORK/agent.pid"
HB="$WORK/agent.hb"
STOP="$HB.stop"
LOG="$WORK/agent.log"

export EDR_SELF_PROTECT_WATCHDOG_PROCESS=1
export EDR_SELF_PROTECT_PIDFILE="$PIDFILE"
export EDR_SELF_PROTECT_HEARTBEAT="$HB"
export EDR_WATCHDOG_MAX_RESTARTS_PER_MIN=20

PASS=0
FAIL=0
note() { echo "[smoke] $*"; }
ok() { echo "[smoke][PASS] $*"; PASS=$((PASS + 1)); }
bad() { echo "[smoke][FAIL] $*"; FAIL=$((FAIL + 1)); }

# 按角色列出本次冒烟的进程 pid（用唯一的 --config 路径过滤，避免误伤机器上其它 edr_agent；
# 重启后的 agent 可能用绝对 exe 路径，故不按 exe 路径匹配）。
list_role() { # $1 = watchdog|agent
  ps -eo pid,args 2>/dev/null | grep -- "$CONFIG" | grep -v grep | \
  while read -r pid args; do
    case "$args" in
      *--watchdog*) [ "$1" = watchdog ] && echo "$pid" ;;
      *) [ "$1" = agent ] && echo "$pid" ;;
    esac
  done | tr '\n' ' '
}
all_pids() { list_role agent; list_role watchdog; }
watchdog_pids() { list_role watchdog; }
# 当前主 agent pid（来自 pidfile）。
agent_pid() { [ -f "$PIDFILE" ] && head -n1 "$PIDFILE" 2>/dev/null | tr -d '[:space:]'; }

cleanup() {
  : > "$STOP" 2>/dev/null || true
  for p in $(all_pids); do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

note "starting agent ($AGENT_BIN) with watchdog enabled; work=$WORK"
"$AGENT_BIN" --config "$CONFIG" > "$LOG" 2>&1 &
sleep 4

A1="$(agent_pid)"
WD="$(watchdog_pids)"
[ -n "$A1" ] && ok "agent up pid=$A1" || bad "agent pidfile missing"
[ -n "$WD" ] && ok "companion watchdog up pid=$WD" || bad "no watchdog companion spawned"

# 2) kill 主 agent，watchdog 应重启出新 agent
note "kill -9 agent pid=$A1"
[ -n "$A1" ] && kill -9 "$A1" 2>/dev/null
RESTARTED=""
for _ in $(seq 1 20); do
  sleep 1
  A2="$(agent_pid)"
  if [ -n "$A2" ] && [ "$A2" != "$A1" ] && kill -0 "$A2" 2>/dev/null; then RESTARTED="$A2"; break; fi
done
[ -n "$RESTARTED" ] && ok "agent restarted by watchdog new_pid=$RESTARTED" || bad "agent not restarted after kill"

# 3) kill watchdog，agent 应重新 spawn 一个
WD1="$(watchdog_pids)"
note "kill watchdog pid=$WD1"
for p in $WD1; do kill -9 "$p" 2>/dev/null; done
RESPAWNED=""
for _ in $(seq 1 15); do
  sleep 1
  WD2="$(watchdog_pids)"
  if [ -n "$WD2" ]; then
    for p in $WD2; do
      case " $WD1 " in *" $p "*) ;; *) RESPAWNED="$p";; esac
    done
    [ -n "$RESPAWNED" ] && break
  fi
done
[ -n "$RESPAWNED" ] && ok "watchdog respawned by agent new_pid=$RESPAWNED" || bad "watchdog not respawned after kill"

# 4) 干净退出：SIGINT agent，应写 stop stamp，watchdog 退出且不再重启
A3="$(agent_pid)"
note "SIGINT agent pid=$A3 for clean shutdown"
[ -n "$A3" ] && kill -INT "$A3" 2>/dev/null
LEFT="x"
for _ in $(seq 1 15); do
  sleep 1
  LEFT="$(all_pids)"
  [ -z "$(echo "$LEFT" | tr -d '[:space:]')" ] && break
done
if [ -z "$(echo "$LEFT" | tr -d '[:space:]')" ]; then
  ok "clean shutdown: no agent/watchdog left (stop stamp honored)"
else
  bad "processes still alive after clean shutdown: $LEFT"
fi

echo "[smoke] result: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
