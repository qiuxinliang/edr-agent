#!/bin/bash
set -euo pipefail
# ============================================================================
# 部署前端 RTR 变更 (Shell Panel + Forensic Modal)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND_DIR="$(cd "$AGENT_DIR/../edr-frontend" && pwd)"

echo "=== 前端路径: $FRONTEND_DIR ==="

echo ""
echo "=== step 1/6: 备份原文件 ==="
TS=$(date +%Y%m%d_%H%M%S)
cp "$FRONTEND_DIR/src/api/shell.ts"                       "$FRONTEND_DIR/src/api/shell.ts.bak.$TS" 2>/dev/null || true
cp "$FRONTEND_DIR/src/components/shared/RtrShellPanel.tsx" "$FRONTEND_DIR/src/components/shared/RtrShellPanel.tsx.bak.$TS" 2>/dev/null || true
echo "备份完成"

echo ""
echo "=== step 2/6: 部署 API 扩展 (shell_api.ts) ==="
cp "$SCRIPT_DIR/shell_api.ts" "$FRONTEND_DIR/src/api/shell_ext.ts"
echo "  + 创建 src/api/shell_ext.ts"

echo ""
echo "=== step 3/6: 部署 WebSocket Hook (useShellWs.ts) ==="
mkdir -p "$FRONTEND_DIR/src/hooks"
cp "$SCRIPT_DIR/useShellWs.ts" "$FRONTEND_DIR/src/hooks/useShellWs.ts"
echo "  + 创建 src/hooks/useShellWs.ts"

echo ""
echo "=== step 4/6: 替换 RtrShellPanel.tsx ==="
cp "$SCRIPT_DIR/RtrShellPanel_new.tsx" "$FRONTEND_DIR/src/components/shared/RtrShellPanel.tsx"
echo "  + 替换 src/components/shared/RtrShellPanel.tsx"

echo ""
echo "=== step 5/6: 部署 ForensicModal.tsx ==="
cp "$SCRIPT_DIR/ForensicModal.tsx" "$FRONTEND_DIR/src/components/shared/ForensicModal.tsx"
echo "  + 创建 src/components/shared/ForensicModal.tsx"

echo ""
echo "=== step 6/6: patch AlertDetailPage.tsx ==="
DETAIL_PAGE="$FRONTEND_DIR/src/pages/alerts/AlertDetailPage.tsx"

# 添加 ForensicModal import
if ! grep -q 'import ForensicModal from' "$DETAIL_PAGE"; then
	awk '/import RtrShellPanel from/ { print; print "import ForensicModal from '\''@/components/shared/ForensicModal'\'';"; next } { print }' "$DETAIL_PAGE" > "$DETAIL_PAGE.tmp" && mv "$DETAIL_PAGE.tmp" "$DETAIL_PAGE"
	echo "  + 添加 ForensicModal import"
else
	echo "  (ForensicModal import 已存在)"
fi

# 添加 showForensicModal state
if ! grep -q 'showForensicModal' "$DETAIL_PAGE"; then
	awk '/const \[showPEAnalysis/ { print; print "  const [showForensicModal, setShowForensicModal] = useState(false);"; next } { print }' "$DETAIL_PAGE" > "$DETAIL_PAGE.tmp" && mv "$DETAIL_PAGE.tmp" "$DETAIL_PAGE"
	echo "  + 添加 showForensicModal state"
else
	echo "  (showForensicModal state 已存在)"
fi

# 在"取证时间线"按钮后添加"深度取证采集"按钮
if ! grep -q '深度取证采集' "$DETAIL_PAGE"; then
	awk '
	/取证时间线/ { found=1 }
	found && /\}/ {
		print "              <Button"
		print "                variant=\"primary\""
		print "                className=\"w-full\""
		print "                type=\"button\""
		print "                disabled={!canForensic || actionLoading !== null}"
		print "                onClick={() => setShowForensicModal(true)}"
		print "              >"
		print "                深度取证采集"
		print "              </Button>"
		found=0
	}
	{ print }
	' "$DETAIL_PAGE" > "$DETAIL_PAGE.tmp" && mv "$DETAIL_PAGE.tmp" "$DETAIL_PAGE"
	echo "  + 添加深度取证采集按钮"
else
	echo "  (深度取证采集按钮已存在)"
fi

# 添加 ForensicModal 组件
if ! grep -q '<ForensicModal' "$DETAIL_PAGE"; then
	awk '
	/<RtrShellPanel/ { found=1 }
	found && /\/>/ {
		print $0
		print "                {showForensicModal && <ForensicModal endpointId={endpointId} endpointName={detail?.endpointName} isOpen={showForensicModal} onClose={() => setShowForensicModal(false)} />}"
		found=0
		next
	}
	{ print }
	' "$DETAIL_PAGE" > "$DETAIL_PAGE.tmp" && mv "$DETAIL_PAGE.tmp" "$DETAIL_PAGE"
	echo "  + 添加 ForensicModal 组件"
else
	echo "  (ForensicModal 组件已存在)"
fi

echo ""
echo "============================================================"
echo "  前端部署完成！"
echo "  启动: cd $FRONTEND_DIR && npm run dev"
echo "============================================================"
