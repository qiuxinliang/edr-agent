#!/usr/bin/env bash
# 薄封装：调用同目录 edr_agent_install.py（需 python3）。
# 用法见 edr_agent_install.py 或 docs/AGENT_INSTALLER.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec python3 "${ROOT}/edr_agent_install.py" "$@"
