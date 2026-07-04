#!/usr/bin/env bash
# 从本机发一条与 edr_agent「HTTP ingest」同路径、同头的 POST /ingest/report-events，用于排查联通性。
#
# 用法（需安装 go；默认在 monorepo 下使用 sibling ../edr-backend/platform，否则设 EDR_PLATFORM_ROOT）：
#   export EDR_SMOKE_BASE="http://192.168.1.35:8080/api/v1"
#   export EDR_SMOKE_BEARER="eyJ..."    # 与 agent.toml [platform].rest_bearer_token 一致
#   export EDR_SMOKE_ENDPOINT="<注册得到的 endpoint_id>"
#   export EDR_SMOKE_TENANT="demo-tenant"   # 可选，默认 demo-tenant
#   ./scripts/smoke_http_ingest.sh
#
# 若 curl 成功而 Agent 仍无数据：查 agent 的 endpoint_id/token、PATH 是否有 curl、stderr 是否 [ingest-http] curl failed。
# 若 curl 失败：查平台防火墙、JWT 权限、endpoint 是否存在于库。
set -euo pipefail

: "${EDR_SMOKE_BASE:?export EDR_SMOKE_BASE e.g. http://192.168.1.35:8080/api/v1}"
: "${EDR_SMOKE_BEARER:?export EDR_SMOKE_BEARER (JWT)}"
: "${EDR_SMOKE_ENDPOINT:?export EDR_SMOKE_ENDPOINT}"
TENANT="${EDR_SMOKE_TENANT:-demo-tenant}"
USER="${EDR_SMOKE_USER:-edr-agent}"

AGENT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLATFORM_ROOT="${EDR_PLATFORM_ROOT:-$AGENT_ROOT/../edr-backend/platform}"
if [[ ! -f "$PLATFORM_ROOT/go.mod" ]]; then
  echo "platform go module not found at $PLATFORM_ROOT — set EDR_PLATFORM_ROOT (default: <monorepo>/edr-backend/platform)" >&2
  exit 1
fi

JSON="$(cd "$PLATFORM_ROOT" && go run ./cmd/edr-ingest-sample -endpoint "$EDR_SMOKE_ENDPOINT" -tenant "$TENANT")"
echo "POST ${EDR_SMOKE_BASE}/ingest/report-events ..."
curl -sS -w "\nHTTP %{http_code}\n" -X POST "${EDR_SMOKE_BASE}/ingest/report-events" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT}" \
  -H "X-User-ID: ${USER}" \
  -H "X-Permission-Set: telemetry:write" \
  -H "Authorization: Bearer ${EDR_SMOKE_BEARER}" \
  -d "${JSON}"
echo ""
