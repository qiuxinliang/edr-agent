#!/usr/bin/env bash
# 与 GitHub Release 中 linux_* zip 同目录放置；一键安装二进制与默认配置占位。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${ROOT}/edr_agent"
EXAMPLE="${ROOT}/agent.toml.example"
INSTALL_BIN="/usr/local/bin/edr_agent"
ETC_DIR="/etc/edr-agent"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 或 sudo 运行，例如: sudo \"$0\"" >&2
  exit 1
fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "未找到 ${BIN_SRC}。请在解压后的发布包目录内执行本脚本。" >&2
  exit 1
fi

install -m 0755 -d "$(dirname "$INSTALL_BIN")"
install -m 0755 "$BIN_SRC" "$INSTALL_BIN"

install -m 0755 -d "$ETC_DIR"
if [[ ! -f "${ETC_DIR}/agent.toml" ]]; then
  if [[ -f "$EXAMPLE" ]]; then
    install -m 0644 "$EXAMPLE" "${ETC_DIR}/agent.toml"
    echo "已安装默认配置: ${ETC_DIR}/agent.toml"
  else
    echo "警告: 未找到 agent.toml.example，未创建 ${ETC_DIR}/agent.toml" >&2
  fi
else
  echo "已存在 ${ETC_DIR}/agent.toml，未覆盖。"
fi

echo "安装完成: ${INSTALL_BIN}"
echo "注册/写全 agent.toml 见仓库 docs/AGENT_INSTALLER.md；启动示例: ${INSTALL_BIN} --config ${ETC_DIR}/agent.toml"
