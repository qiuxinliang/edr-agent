# EDR Agent 配置参数参考指南

**版本**：2.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 概述

本文档汇总 EDR Agent 所有可配置的参数，按照功能模块分类，提供默认值、说明和推荐值。

---

## 2. P0 动态行为引擎

### 2.1 核心参数

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_P0_DIRECT_EMIT` | `1` (启用) | `1` | P0引擎开关。设为`0`禁用 |
| `EDR_P0_DEBUG` | `0` (禁用) | `0` | 调试日志开关。设为`1`启用 |

### 2.2 限流参数

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_P0_DEDUP_SEC` | `10` | `10` | 去重窗口（秒）。同规则+同PID在窗口内只告警一次 |
| `EDR_P0_MAX_EMITS_PER_MIN` | `0` (不限) | `0` | 全局每分钟最大告警数。`0`表示不限 |
| `EDR_P0_TENANT_RATE` | `0` (不限) | `0` | 每租户每分钟最大告警数 |
| `EDR_P0_MAX_EMITS_PER_MIN_PER_ENDPOINT` | `0` (不限) | `0` | 每端点每分钟最大告警数 |

### 2.3 快速配置

```bash
# 开发/测试环境 - 宽松模式
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=1
export EDR_P0_DEDUP_SEC=60  # 较长去重窗口

# 生产环境 - 标准模式
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=0
export EDR_P0_DEDUP_SEC=10

# 生产环境 - 严格模式（减少告警）
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=0
export EDR_P0_DEDUP_SEC=5
export EDR_P0_MAX_EMITS_PER_MIN=100
```

---

## 3. 预处理模块

### 3.1 procname_gate 白名单

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_PROCNAME_GATE_WHITELIST` | 见下方 | `powershell.exe,pwsh.exe,cmd.exe,mshta.exe` | 白名单进程名，逗号分隔 |
| `EDR_PROCNAME_GATE_ENABLED` | `1` | `1` | procname_gate开关 |
| `EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE` | `1` | `1` | 非白名单进程保留比例（1/1000） |

**默认白名单进程**：
```
powershell.exe, pwsh.exe,                     # 脚本引擎
cmd.exe,                                    # 命令行
mshta.exe, rundll32.exe, regsvr32.exe,    # LOLBAS
certutil.exe, cmstp.exe,                   # LOLBAS
mimikatz.exe, psexec.exe,                  # 攻击工具
javaw.exe, java.exe                         # Java进程
```

### 3.2 去重和限流

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_DEDUP_WINDOW_SECONDS` | `10` | `10` | 去重窗口（秒） |
| `EDR_RATE_LIMIT_PER_SEC` | `50` | `50` | 每PID每秒最大事件数 |

### 3.3 L2 Split

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_PREPROCESS_L2_SPLIT` | `0` | `0` | L2 split开关 |

### 3.4 快速配置

```bash
# 开发/测试环境 - 宽松模式
export EDR_PROCNAME_GATE_ENABLED=1
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe,mshta.exe,rundll32.exe,regsvr32.exe,certutil.exe,cmstp.exe,mimikatz.exe,psexec.exe,net.exe,net1.exe,curl.exe,wget.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=100  # 10%保留
export EDR_DEDUP_WINDOW_SECONDS=60
export EDR_RATE_LIMIT_PER_SEC=200

# 生产环境 - 标准模式
export EDR_PROCNAME_GATE_ENABLED=1
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe,mshta.exe,rundll32.exe,regsvr32.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=1
export EDR_DEDUP_WINDOW_SECONDS=10
export EDR_RATE_LIMIT_PER_SEC=50

# 生产环境 - 严格模式
export EDR_PROCNAME_GATE_ENABLED=1
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=1
export EDR_DEDUP_WINDOW_SECONDS=5
export EDR_RATE_LIMIT_PER_SEC=20
```

---

## 4. A44 分叉路径

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_A44_ENABLED` | `1` | `1` | A44分叉开关 |
| `EDR_A44_NUM_THREADS` | `4` | `4` | A44线程数 |
| `EDR_A44_LOCKFREE_ENABLED` | `0` | `0` | 无锁队列开关 |
| `EDR_A44_LOCKFREE_CAP` | 队列大小/2 | `4096` | 无锁队列容量 |

### 快速配置

```bash
# 高性能环境
export EDR_A44_NUM_THREADS=8
export EDR_A44_LOCKFREE_ENABLED=1
export EDR_A44_LOCKFREE_CAP=8192

# 标准环境
export EDR_A44_NUM_THREADS=4
export EDR_A44_LOCKFREE_ENABLED=0
```

---

## 5. 事件编码和传输

| 环境变量 | 默认值 | 推荐值 | 说明 |
|----------|--------|--------|------|
| `EDR_BEHAVIOR_ENCODING` | `wire` | `protobuf` | 事件编码格式。可选：`wire`, `protobuf`, `protobuf_c` |
| `EDR_LZ4_COMPRESSION_LEVEL` | `6` | `6` | LZ4压缩级别（1-12） |
| `EDR_BATCH_FLUSH_TIMEOUT_S` | `5` | `5` | 批量刷新超时（秒） |

### 快速配置

```bash
# 高压缩环境
export EDR_BEHAVIOR_ENCODING=protobuf_c
export EDR_LZ4_COMPRESSION_LEVEL=12

# 低延迟环境
export EDR_BEHAVIOR_ENCODING=wire
export EDR_LZ4_COMPRESSION_LEVEL=1
```

---

## 6. 完整配置模板

### 6.1 开发/测试环境

```bash
#!/bin/bash
# EDR Agent - 开发/测试环境配置

# P0引擎
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=1
export EDR_P0_DEDUP_SEC=60

# 预处理 - 宽松
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe,mshta.exe,rundll32.exe,regsvr32.exe,certutil.exe,cmstp.exe,net.exe,net1.exe,curl.exe,wget.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=100
export EDR_DEDUP_WINDOW_SECONDS=60
export EDR_RATE_LIMIT_PER_SEC=200

# A44
export EDR_A44_NUM_THREADS=4

# 编码
export EDR_BEHAVIOR_ENCODING=wire
```

### 6.2 生产环境

```bash
#!/bin/bash
# EDR Agent - 生产环境配置

# P0引擎
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=0
export EDR_P0_DEDUP_SEC=10

# 预处理 - 标准
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe,mshta.exe,rundll32.exe,regsvr32.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=1
export EDR_DEDUP_WINDOW_SECONDS=10
export EDR_RATE_LIMIT_PER_SEC=50

# A44
export EDR_A44_NUM_THREADS=4

# 编码
export EDR_BEHAVIOR_ENCODING=protobuf_c
export EDR_LZ4_COMPRESSION_LEVEL=6
```

### 6.3 高安全环境

```bash
#!/bin/bash
# EDR Agent - 高安全环境配置

# P0引擎 - 严格
export EDR_P0_DIRECT_EMIT=1
export EDR_P0_DEBUG=0
export EDR_P0_DEDUP_SEC=5
export EDR_P0_MAX_EMITS_PER_MIN=100

# 预处理 - 严格
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe"
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=1
export EDR_DEDUP_WINDOW_SECONDS=5
export EDR_RATE_LIMIT_PER_SEC=20

# A44
export EDR_A44_NUM_THREADS=8
export EDR_A44_LOCKFREE_ENABLED=1

# 编码
export EDR_BEHAVIOR_ENCODING=protobuf_c
export EDR_LZ4_COMPRESSION_LEVEL=12
```

---

## 7. 配置验证

### 7.1 检查当前配置

```bash
# 查看所有 EDR 相关环境变量
env | grep EDR_

# 验证 P0 引擎状态
./edr_agent --version
```

### 7.2 配置检查清单

- [ ] `EDR_P0_DIRECT_EMIT=1`（如果需要P0告警）
- [ ] `EDR_BEHAVIOR_ENCODING=protobuf`（如果后端需要protobuf）
- [ ] 白名单包含需要监控的进程
- [ ] 速率限制适合当前环境

---

## 8. 故障排查

### 8.1 P0引擎不产生告警

1. 检查环境变量：`EDR_P0_DIRECT_EMIT=1`
2. 启用调试：`EDR_P0_DEBUG=1`
3. 检查日志：`grep "\[P0\]" logs/*.log`

### 8.2 事件量过大

1. 检查 procname_gate 白名单
2. 降低 `RATE_LIMIT_PER_SEC`
3. 缩短 `DEDUP_WINDOW_SECONDS`

### 8.3 告警被去重丢弃

1. 检查 `EDR_P0_DEDUP_SEC` 设置
2. 如果需要更多告警，增大该值

---

*文档生成时间：2026-04-28*