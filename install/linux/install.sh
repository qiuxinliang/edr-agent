#!/usr/bin/env bash
# 与 GitHub Release 中 linux_* zip 同目录放置；一键安装二进制与默认配置占位。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${ROOT}/edr_agent"
EXAMPLE="${ROOT}/agent.toml.example"
INSTALL_BIN="/usr/local/bin/edr_agent"
ETC_DIR="/etc/edr-agent"
LIB_DIR="/usr/local/lib/edr-agent"
STRONG_PROFILE="${ROOT}/linux_detection_strong.toml"
if [[ ! -f "$STRONG_PROFILE" && -f "${ROOT}/../../config/profiles/linux_detection_strong.toml" ]]; then
  STRONG_PROFILE="${ROOT}/../../config/profiles/linux_detection_strong.toml"
fi

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

install -m 0755 -d "$LIB_DIR"
for asset in edr-ebpf-trace.sh edr-linux.bt; do
  if [[ -f "${ROOT}/${asset}" ]]; then
    install -m 0755 "${ROOT}/${asset}" "${LIB_DIR}/${asset}"
  fi
done
if [[ -f "${ROOT}/edr-linux.bt" ]]; then
  chmod 0644 "${LIB_DIR}/edr-linux.bt"
fi
if [[ -f "${ROOT}/edr-agent-ebpf.service" ]]; then
  install -m 0644 "${ROOT}/edr-agent-ebpf.service" /etc/systemd/system/edr-agent-ebpf.service
fi
if [[ -f "${ROOT}/edr-agent.rules" ]]; then
  install -m 0755 -d /etc/audit/rules.d
  install -m 0640 "${ROOT}/edr-agent.rules" /etc/audit/rules.d/edr-agent.rules
fi
if [[ -f "$STRONG_PROFILE" ]]; then
  install -m 0755 -d "${ETC_DIR}/profiles"
  install -m 0644 "$STRONG_PROFILE" "${ETC_DIR}/profiles/linux_detection_strong.toml"
fi

if [[ "${EDR_ENABLE_STRONG_LINUX:-0}" == "1" ]]; then
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
  else
    echo "警告: augenrules 不可用，auditd 规则已安装但尚未加载。" >&2
  fi
  if command -v systemctl >/dev/null 2>&1 && command -v bpftrace >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now edr-agent-ebpf.service
  else
    echo "警告: systemd 或 bpftrace 不可用，eBPF 数据源未自动启用。" >&2
  fi
fi

echo "安装完成: ${INSTALL_BIN}"
echo "注册/写全 agent.toml 见仓库 docs/AGENT_INSTALLER.md；启动示例: ${INSTALL_BIN} --config ${ETC_DIR}/agent.toml"
echo "Linux 强检测资产已安装；设置 EDR_ENABLE_STRONG_LINUX=1 重新执行可加载 auditd 规则并启用 eBPF 数据源。"
