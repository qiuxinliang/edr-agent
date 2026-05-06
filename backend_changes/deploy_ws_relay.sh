#!/bin/bash
set -euo pipefail
# ============================================================================
# 部署 WebSocket Shell Relay + 测试
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$(cd "$AGENT_DIR/../edr-backend/platform" && pwd)"

echo "=== 后端路径: $BACKEND_DIR ==="

echo ""
echo "=== step 1/4: 备份原文件 ==="
TS=$(date +%Y%m%d_%H%M%S)
cp "$BACKEND_DIR/internal/realtime/hub.go"     "$BACKEND_DIR/internal/realtime/hub.go.bak.$TS"
cp "$BACKEND_DIR/internal/handler/ingest.go"   "$BACKEND_DIR/internal/handler/ingest.go.bak.$TS"
echo "备份完成"

echo ""
echo "=== step 2/4: 替换 realtime/hub.go ==="
cp "$AGENT_DIR/backend_changes/hub_new.go" "$BACKEND_DIR/internal/realtime/hub.go"
echo "hub.go 已替换"

echo ""
echo "=== step 3/4: patch handler/ingest.go ==="
INGEST="$BACKEND_DIR/internal/handler/ingest.go"

# 3a: 添加 realtime import
if ! grep -q '"edr-backend/platform/internal/realtime"' "$INGEST"; then
	awk '
	/\"edr-backend\/platform\/internal\/ingestcommand\"/ {
		print
		print "\t\"edr-backend/platform/internal/realtime\""
		next
	}
	{ print }
	' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
	echo "  + 添加 realtime import"
else
	echo "  (realtime import 已存在，跳过)"
fi

# 3b: 添加 RealtimeHub 字段
if ! grep -q 'RealtimeHub' "$INGEST"; then
	awk '
	/CommandHTTPOutbox \*ingestcommand\.HTTPOutbox/ {
		print
		print "\tRealtimeHub       \*realtime.Hub"
		next
	}
	{ print }
	' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
	echo "  + 添加 RealtimeHub 字段"
else
	echo "  (RealtimeHub 字段已存在，跳过)"
fi

# 3c: 添加 WS broadcast 调用
if ! grep -q 'BroadcastShellOutput' "$INGEST"; then
	awk '
	/SyncResponseTaskFromCommandIngest\(ep, cmdID, st, 0, detail, fin\)/ {
		print
		print ""
		print "\tif h.RealtimeHub != nil && detail != \"\" {"
		print "\t\th.RealtimeHub.BroadcastShellOutput(ep, detail, false)"
		print "\t}"
		next
	}
	{ print }
	' "$INGEST" > "$INGEST.tmp" && mv "$INGEST.tmp" "$INGEST"
	echo "  + 添加 WS broadcast 调用"
else
	echo "  (WS broadcast 已存在，跳过)"
fi

echo ""
echo "=== step 5/5: patch server/build.go (注入 hub) ==="
BUILD="$BACKEND_DIR/internal/server/build.go"

if ! grep -q 'RealtimeHub: hub' "$BUILD"; then
	sed -i '' 's/CommandHTTPOutbox: cmdHTTPOB}/CommandHTTPOutbox: cmdHTTPOB, RealtimeHub: hub}/' "$BUILD"
	echo "  + IngestHandler 已注入 RealtimeHub: hub"
else
	echo "  (RealtimeHub 已注入，跳过)"
fi

echo ""
echo "=== 拷贝测试并运行 ==="
cp "$AGENT_DIR/backend_changes/realtime_hub_test.go" "$BACKEND_DIR/internal/realtime/hub_test.go"

cd "$BACKEND_DIR"
echo "--- 运行 WS Relay 测试 ---"
go test ./internal/realtime/ -run TestBroadcastShellOutput -v -timeout 10s

echo ""
echo "============================================================"
echo "  部署完成！请手动编译: cd $BACKEND_DIR && go build ./cmd/server"
echo "============================================================"
