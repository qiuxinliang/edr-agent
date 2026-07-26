#!/bin/bash
# EDR 前端守护启动脚本
# 用法: bash start_frontend_daemon.sh

set -e

FRONTEND_DIR="/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-frontend"
PORT=5173

echo "=== EDR 前端守护启动 ==="
echo "目录: ${FRONTEND_DIR}"
echo "端口: ${PORT}"

# macOS 提高文件监听限制（Vite HMR 需要大量文件描述符）
if [[ "$(uname)" == "Darwin" ]]; then
    echo "提高文件描述符限制: 256 -> 8192"
    ulimit -n 8192 2>/dev/null || echo "WARNING: 无法提高 ulimit"
fi

# 清理旧进程
OLD_PIDS=$(lsof -i :${PORT} -t 2>/dev/null || true)
if [ -n "$OLD_PIDS" ]; then
    echo "清理旧进程: $OLD_PIDS"
    kill $OLD_PIDS 2>/dev/null || true
    sleep 2
fi

# 检查 backend 是否可达
echo -n "检查 backend 连通性... "
if curl -s -o /dev/null -w "%{http_code}" "http://192.168.1.10:8080/healthz" 2>/dev/null | grep -q "200"; then
    echo "OK"
else
    echo "WARNING: backend (192.168.1.10:8080) 不可达"
fi

cd "${FRONTEND_DIR}"

echo "启动 Vite 开发服务器..."
npx vite --host 0.0.0.0 --port ${PORT} --strictPort

echo "Vite 已退出"
