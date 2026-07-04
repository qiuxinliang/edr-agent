#!/usr/bin/env bash
# Export qa_smoke_stats_by_10m_ip.sql to scripts/exports/*.txt
#
# 必须「同一行」把环境变量和脚本写在一起，否则换行后变量不会传给下一条命令，例如:
#   MYSQL_HOST=192.168.1.35 MYSQL_USER=root MYSQL_PWD=secret MYSQL_PORT=3306 \
#   ENDPOINT_IP=192.168.64.2 HOURS_AGO=2 \
#   ./qa_smoke_stats_export.sh
#
# ERROR 2003 / 系统错误 61: 本机到 MySQL 的 TCP 连不上。常见原因:
#   1) 服务只监听 127.0.0.1 (my.cnf bind-address) — 需在 192.168.1.35 上开远程或走 SSH 隧道
#   2) 防火墙/安全组未放行 3306
#   3) 端口不是 3306 — 用 MYSQL_PORT= 指定
# SSH 隧道示例(在本机开 13306 连到服务器本机 MySQL):
#   ssh -N -L 13306:127.0.0.1:3306 user@192.168.1.35
#   然后: MYSQL_HOST=127.0.0.1 MYSQL_PORT=13306 ... ./qa_smoke_stats_export.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SQL="${HERE}/qa_smoke_stats_by_10m_ip.sql"
OUTDIR="${HERE}/exports"
mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
IP="${ENDPOINT_IP:-192.168.64.2}"
HOURS="${HOURS_AGO:-4}"
SAFE_IP="${IP//./_}"
OUT="${OUTDIR}/smoke_stats_by10m_${SAFE_IP}_${TS}.txt"

: "${MYSQL_HOST:=192.168.1.35}"
: "${MYSQL_USER:=root}"
: "${MYSQL_DB:=edr}"
: "${MYSQL_PORT:=3306}"
mysql_cli=(mysql -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" --default-character-set=utf8mb4)

if [[ ! -f "$SQL" ]]; then
  echo "Missing: $SQL" >&2
  exit 1
fi

TMP="${OUTDIR}/._export_$$.sql"
trap 'rm -f "$TMP"' EXIT
{
  echo "SET NAMES utf8mb4;"
  echo "SET @ip = '$IP';"
  echo "SET @hours_ago = ${HOURS};"
  sed -e '/^SET @ip = /d' -e '/^SET @hours_ago = /d' "$SQL"
} >"$TMP"

if [[ -n "${MYSQL_PWD-}" ]]; then
  MYSQL_PWD="${MYSQL_PWD}" "${mysql_cli[@]}" -p"$MYSQL_PWD" "$MYSQL_DB" <"$TMP" >"$OUT"
else
  "${mysql_cli[@]}" "$MYSQL_DB" <"$TMP" >"$OUT"
fi

echo "Wrote: $OUT"
