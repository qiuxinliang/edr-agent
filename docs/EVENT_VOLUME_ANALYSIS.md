# EDR Agent 事件量过大问题分析

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. 问题描述

几分钟内产生上万条事件，说明事件过滤机制没有正常工作。

---

## 2. EDR 支持的事件类型

EDR Agent 支持以下事件类型（按类别分组）：

### 2.1 进程事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 1 | PROCESS_CREATE | 进程创建 |
| 2 | PROCESS_TERMINATE | 进程终止 |
| 3 | PROCESS_INJECT | 进程注入 |
| 4 | DLL_LOAD | DLL加载 |

### 2.2 文件事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 6 | FILE_READ | 文件读取 |
| 10 | FILE_CREATE | 文件创建 |
| 11 | FILE_WRITE | 文件写入 |
| 12 | FILE_DELETE | 文件删除 |
| 13 | FILE_RENAME | 文件重命名 |
| 14 | FILE_PERMISSION_CHANGE | 文件权限变更 |

### 2.3 网络事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 20 | NET_CONNECT | 网络连接 |
| 21 | NET_LISTEN | 网络监听 |
| 22 | NET_DNS_QUERY | DNS查询 |
| 23 | NET_TLS_HANDSHAKE | TLS握手 |

### 2.4 注册表事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 30 | REG_CREATE_KEY | 注册表创建 |
| 31 | REG_SET_VALUE | 注册表设置值 |
| 32 | REG_DELETE_KEY | 注册表删除 |

### 2.5 脚本事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 40 | SCRIPT_POWERSHELL | PowerShell脚本 |
| 41 | SCRIPT_BASH | Bash脚本 |
| 42 | SCRIPT_PYTHON | Python脚本 |
| 43 | SCRIPT_WMI | WMI脚本 |

### 2.6 认证事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 50 | AUTH_LOGIN | 登录 |
| 51 | AUTH_LOGOUT | 登出 |
| 52 | AUTH_FAILED | 认证失败 |
| 53 | AUTH_PRIVILEGE_ESC | 权限提升 |

### 2.7 其他事件
| 事件ID | 名称 | 说明 |
|--------|------|------|
| 60 | SERVICE_CREATE | 服务创建 |
| 61 | SCHEDULED_TASK_CREATE | 计划任务创建 |
| 62 | DRIVER_LOAD | 驱动加载 |
| 63 | PROTOCOL_SHELLCODE | Shellcode检测 |
| 65 | WEBSHELL_DETECTED | Webshell检测 |
| 66 | PMFE_SCAN_RESULT | PMFE扫描结果 |

---

## 3. 事件量大的可能原因

### 3.1 emit_rules 未配置

**代码位置**：`src/preprocess/emit_rules.c:73-80`

```c
void edr_emit_rules_configure(const EdrConfig *cfg) {
    if (!cfg || !cfg->preprocessing.rules || cfg->preprocessing.rules_count == 0u) {
        return;  // 没有配置规则，所有事件都通过！
    }
}
```

**影响**：如果 `emit_rules` 未配置，`edr_emit_rules_evaluate()` 返回1，所有事件都会被发送！

### 3.2 procname_gate 白名单过宽

**当前配置**：36个进程

```c
static const char *const kHotProcNames[] = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    ...
};
```

**问题**：白名单进程越多，进入预处理的事件越多

### 3.3 去重窗口过长

**默认值**：30秒

**问题**：如果用户在30秒内执行了略有不同的命令，每个都会被发送

### 3.4 速率限制过高

**默认值**：100/秒/PID

**问题**：对于高频进程（如系统进程），每秒可能产生100个事件

---

## 4. 排查步骤

### 4.1 检查 emit_rules 配置

```powershell
# 查看配置文件中的 emit_rules 配置
# 位置：edr_config/agent.toml 或注册表

[preprocessing]
[[preprocessing.rules]]
event_type = 1  # PROCESS_CREATE
exe_path_contains = "powershell.exe"
```

### 4.2 检查 procname_gate 白名单

```bash
# 查看当前白名单
grep -r "kHotProcNames" src/

# 默认白名单进程数
# 优化前：36个
# 优化后：9个
```

### 4.3 检查统计信息

```bash
# 查看 dedup 统计
# [dedup] total=xxx dropped_dedup=xxx dropped_rate=xxx

# 查看 procname_gate 丢弃
# [procname] drops=xxx

# 查看 P0 统计
# [p0] total=xxx r_exec=xxx r_cred=xxx r_filess=xxx
```

---

## 5. 解决方案

### 5.1 立即实施

```bash
# 1. 设置严格的白名单
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe"

# 2. 缩短去重窗口
export EDR_DEDUP_WINDOW_SECONDS=5

# 3. 降低速率限制
export EDR_RATE_LIMIT_PER_SEC=20

# 4. 配置 emit_rules
# 在 agent.toml 中添加：
# [[preprocessing.rules]]
# event_type = 1  # PROCESS_CREATE
# exe_path_contains = "powershell.exe"
```

### 5.2 配置 emit_rules 建议

```toml
# agent.toml

[preprocessing]

# 只发送高风险事件
[[preprocessing.rules]]
event_type = 1  # PROCESS_CREATE
exe_path_contains = "powershell.exe,pwsh.exe,cmd.exe"

[[preprocessing.rules]]
event_type = 40  # SCRIPT_POWERSHELL

[[preprocessing.rules]]
event_type = 11  # FILE_WRITE
file_path_contains = ".ps1,.vbs,.js"
```

---

## 6. 事件量评估

### 6.1 正常事件量

| 环境 | 每分钟事件数 | 每小时事件数 |
|------|-------------|-------------|
| 桌面用户 | 100-500 | 6,000-30,000 |
| 开发人员 | 500-2000 | 30,000-120,000 |
| 服务器 | 200-1000 | 12,000-60,000 |

### 6.2 异常事件量（几分钟上万）

| 可能原因 | 估计增加量 |
|----------|-----------|
| emit_rules未配置 | 10-50倍 |
| procname_gate白名单过宽 | 3-10倍 |
| 去重窗口过长 | 2-5倍 |
| 速率限制过高 | 2-10倍 |

---

## 7. 推荐配置

```bash
# 生产环境 - 严格模式
export EDR_PROCNAME_GATE_WHITELIST="powershell.exe,pwsh.exe,cmd.exe"
export EDR_DEDUP_WINDOW_SECONDS=5
export EDR_RATE_LIMIT_PER_SEC=20
export EDR_PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE=1
```

---

*文档生成时间：2026-04-28*