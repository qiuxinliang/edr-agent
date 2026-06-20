#!/bin/bash
set -euo pipefail
# ============================================================================
# EDR RTR 统一部署脚本
# 用法: bash deploy_all.sh
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$(cd "${EDR_AGENT_DIR:-$SCRIPT_DIR}" && pwd)"
BACKEND_DIR="${EDR_BACKEND_DIR:-$(cd "$AGENT_DIR/../edr-backend/platform" 2>/dev/null || echo "")}"
FRONTEND_DIR="${EDR_FRONTEND_DIR:-$(cd "$AGENT_DIR/../edr-frontend" 2>/dev/null || echo "")}"

TS=$(date +%Y%m%d_%H%M%S)
echo "============================================================"
echo "  EDR RTR 全栈部署脚本"
echo "  时间: $(date)"
echo "============================================================"

# ============================================================================
# Part A: Agent (编译)
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████"
echo "  Part A: Agent 编译"
echo "████████████████████████████████████████████████████████████"

cd "$AGENT_DIR/build"
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -2
make -j$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4) 2>&1 | tail -3

# 部署采集器
cp "$AGENT_DIR/scripts/forensic_collector" ./forensic_collector
chmod +x ./forensic_collector
echo "  + Agent 编译完成"
echo "  + forensic_collector 已部署到 build/"

# ============================================================================
# Part B: Backend (WS Relay)
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████"
echo "  Part B: Backend WebSocket Relay"
echo "████████████████████████████████████████████████████████████"

if [[ -d "$BACKEND_DIR" ]]; then
  # 备份
  cp "$BACKEND_DIR/internal/realtime/hub.go"     "$BACKEND_DIR/internal/realtime/hub.go.bak.$TS"
  cp "$BACKEND_DIR/internal/handler/ingest.go"   "$BACKEND_DIR/internal/handler/ingest.go.bak.$TS"
  cp "$BACKEND_DIR/internal/server/build.go"     "$BACKEND_DIR/internal/server/build.go.bak.$TS"

  # hub.go
  cp "$AGENT_DIR/backend_changes/hub_new.go" "$BACKEND_DIR/internal/realtime/hub.go"
  echo "  + hub.go 已替换 (含 BroadcastShellOutput)"

  # ingest.go: import
  INGEST="$BACKEND_DIR/internal/handler/ingest.go"
  if ! grep -q '"edr-backend/platform/internal/realtime"' "$INGEST"; then
    awk '/"edr-backend\/platform\/internal\/ingestcommand"/ { print; print "\t\"edr-backend/platform/internal/realtime\""; next } { print }' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
    echo "  + ingest.go: 添加 realtime import"
  fi

  # ingest.go: RealtimeHub 字段
  if ! grep -q 'RealtimeHub' "$INGEST"; then
    awk '/CommandHTTPOutbox \*ingestcommand\.HTTPOutbox/ { print; print "\tRealtimeHub       \*realtime.Hub"; next } { print }' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
    echo "  + ingest.go: 添加 RealtimeHub 字段"
  fi

  # ingest.go: WS broadcast
  if ! grep -q 'BroadcastShellOutput' "$INGEST"; then
    awk '/SyncResponseTaskFromCommandIngest\(ep, cmdID, st, 0, detail, fin\)/ { print; print ""; print "\tif h.RealtimeHub != nil && detail != \"\" {"; print "\t\th.RealtimeHub.BroadcastShellOutput(ep, detail, false)"; print "\t}"; next } { print }' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
    echo "  + ingest.go: 添加 WS 广播调用"
  fi

  # build.go: wire hub
  BUILD="$BACKEND_DIR/internal/server/build.go"
  if ! grep -q 'RealtimeHub: hub' "$BUILD"; then
    perl -0pe 's/CommandHTTPOutbox: cmdHTTPOB}/CommandHTTPOutbox: cmdHTTPOB, RealtimeHub: hub}/' "$BUILD" > "$BUILD.tmp"
    mv "$BUILD.tmp" "$BUILD"
    if ! grep -q 'RealtimeHub: hub' "$BUILD"; then
      echo "  ! build.go: failed to inject RealtimeHub wiring" >&2
      exit 1
    fi
    echo "  + build.go: IngestHandler 注入 RealtimeHub"
  fi

  # 测试
  cp "$AGENT_DIR/backend_changes/realtime_hub_test.go" "$BACKEND_DIR/internal/realtime/hub_test.go"
  cd "$BACKEND_DIR"
  go test ./internal/realtime/ -run TestBroadcastShellOutput -v -timeout 10s 2>&1 | tail -5
  echo "  + 后端 WS Relay 测试通过"
else
  echo "  ! 后端目录不存在: $BACKEND_DIR"
  echo "  ! 请手动执行 backend_changes/deploy_ws_relay.sh"
fi

# ============================================================================
# Part C: Frontend
# ============================================================================
echo ""
echo "████████████████████████████████████████████████████████████"
echo "  Part C: Frontend 组件"
echo "████████████████████████████████████████████████████████████"

if [[ -d "$FRONTEND_DIR" ]]; then
  cd "$AGENT_DIR"
  bash "$AGENT_DIR/frontend_changes/deploy_frontend.sh"
  echo "  + 前端部署完成"
else
  echo "  ! 前端目录不存在: $FRONTEND_DIR"
  echo "  ! 请手动执行 frontend_changes/deploy_frontend.sh"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================================"
echo "  全部部署完成！"
echo ""
echo "  验证步骤:"
echo "  1. cd $AGENT_DIR/build && EDR_CMD_ENABLED=1 EDR_CMD_HTTP_POLL=1 ./edr_agent --config ../agent.toml"
echo "  2. cd $BACKEND_DIR && go build ./cmd/server"
echo "  3. cd $FRONTEND_DIR && npm run dev"
echo ""
echo "  测试命令:"
echo "  curl -X POST http://127.0.0.1:9090/dev/commands ..."
echo "============================================================"
