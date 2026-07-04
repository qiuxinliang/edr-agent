#!/bin/bash
# EDR Agent 配置验证脚本
# 用法: ./check_edr_config.sh

echo "=========================================="
echo "EDR Agent 配置验证"
echo "=========================================="
echo ""

# 检查函数
check_env() {
    local var_name="$1"
    local var_value="${!var_name}"
    local description="$2"

    if [ -n "$var_value" ]; then
        echo "✅ $var_name = $var_value"
    else
        echo "❌ $var_name = (未设置)"
    fi
}

check_env "EDR_P0_DIRECT_EMIT" "P0引擎开关 (1=启用, 0=禁用)"
check_env "EDR_P0_DEBUG" "P0调试模式"
check_env "EDR_P0_DEDUP_SEC" "P0去重窗口(秒)"
check_env "EDR_P0_MAX_EMITS_PER_MIN" "P0全局速率限制"
check_env "EDR_PROCNAME_GATE_ENABLED" "procname_gate开关"
check_env "EDR_PROCNAME_GATE_WHITELIST" "procname_gate白名单"
check_env "EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE" "非白名单保留比例"
check_env "EDR_DEDUP_WINDOW_SECONDS" "去重窗口(秒)"
check_env "EDR_RATE_LIMIT_PER_SEC" "速率限制"
check_env "EDR_BEHAVIOR_ENCODING" "事件编码格式"
check_env "EDR_LZ4_COMPRESSION_LEVEL" "LZ4压缩级别"
check_env "EDR_A44_ENABLED" "A44开关"
check_env "EDR_A44_NUM_THREADS" "A44线程数"

echo ""
echo "=========================================="
echo "配置合理性检查"
echo "=========================================="
echo ""

# P0引擎检查
if [ "$EDR_P0_DIRECT_EMIT" = "1" ]; then
    echo "✅ P0引擎已启用"

    # 检查是否启用了调试模式
    if [ "$EDR_P0_DEBUG" = "1" ]; then
        echo "⚠️  警告: P0调试模式已启用，生产环境建议禁用"
    fi

    # 检查去重窗口
    if [ -n "$EDR_P0_DEDUP_SEC" ]; then
        if [ "$EDR_P0_DEDUP_SEC" -lt 5 ]; then
            echo "⚠️  警告: P0去重窗口(${EDR_P0_DEDUP_SEC}s)较短，可能产生大量告警"
        elif [ "$EDR_P0_DEDUP_SEC" -gt 60 ]; then
            echo "⚠️  警告: P0去重窗口(${EDR_P0_DEDUP_SEC}s)较长，可能漏报"
        else
            echo "✅ P0去重窗口(${EDR_P0_DEDUP_SEC}s)合理"
        fi
    fi
else
    echo "❌ P0引擎已禁用"
fi

echo ""

# 预处理检查
if [ "$EDR_PROCNAME_GATE_ENABLED" = "1" ]; then
    echo "✅ procname_gate已启用"

    if [ -n "$EDR_PROCNAME_GATE_WHITELIST" ]; then
        count=$(echo "$EDR_PROCNAME_GATE_WHITELIST" | tr ',' '\n' | wc -l)
        echo "   白名单进程数: $count"
        if [ "$count" -gt 20 ]; then
            echo "⚠️  警告: 白名单进程数较多，可能产生较多无用事件"
        fi
    fi

    if [ -n "$EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE" ]; then
        if [ "$EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE" -gt 10 ]; then
            echo "⚠️  警告: 非白名单保留比例较高"
        fi
    fi
else
    echo "❌ procname_gate已禁用，可能产生大量无用事件"
fi

echo ""

# 速率限制检查
if [ -n "$EDR_RATE_LIMIT_PER_SEC" ]; then
    if [ "$EDR_RATE_LIMIT_PER_SEC" -lt 10 ]; then
        echo "⚠️  警告: 速率限制(${EDR_RATE_LIMIT_PER_SEC}/s)较低，可能漏报"
    elif [ "$EDR_RATE_LIMIT_PER_SEC" -gt 200 ]; then
        echo "⚠️  警告: 速率限制(${EDR_RATE_LIMIT_PER_SEC}/s)较高，可能产生大量事件"
    else
        echo "✅ 速率限制(${EDR_RATE_LIMIT_PER_SEC}/s)合理"
    fi
fi

echo ""

# 编码格式检查
case "$EDR_BEHAVIOR_ENCODING" in
    wire)
        echo "✅ 使用wire编码（低延迟）"
        ;;
    protobuf|protobuf_c)
        echo "✅ 使用protobuf编码（高压缩）"
        ;;
    *)
        echo "❌ 未知编码格式: $EDR_BEHAVIOR_ENCODING"
        ;;
esac

echo ""
echo "=========================================="
echo "快速命令参考"
echo "=========================================="
echo ""

# 生成快速配置命令
echo "# 启用P0调试模式:"
echo "export EDR_P0_DEBUG=1"
echo ""

echo "# 禁用P0调试模式:"
echo "export EDR_P0_DEBUG=0"
echo ""

echo "# 查看P0统计:"
echo 'grep "\[p0\]" logs/*.log'
echo ""

echo "# 查看P0调试日志:"
echo 'grep "\[P0 DEBUG\]" logs/*.log'
echo ""

echo "# 查看当前所有EDR配置:"
echo 'env | grep EDR_'
echo ""

echo "=========================================="