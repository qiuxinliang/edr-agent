# P0 规则与 Smoke Test 验证指南

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. Smoke Test 脚本分析

### 1.1 测试用例与 P0 规则对应关系

| Smoke Test 用例 | 规则ID | P0 规则 | 预期结果 | 说明 |
|-----------------|--------|---------|----------|------|
| R-EXEC-001: powershell -encodedcommand | R-EXEC-001 | ✅ 应该匹配 | ALERT | Base64编码命令 |
| R-EXEC-001: frombase64string | R-EXEC-001 | ✅ 应该匹配 | ALERT | Base64字符串解码 |
| R-FILELESS-001: IEX | R-FILELESS-001 | ✅ 应该匹配 | ALERT | IEX远程下载执行 |
| R-FILELESS-001: Invoke-Expression | R-FILELESS-001 | ✅ 应该匹配 | ALERT | Invoke-Expression执行 |
| R-EXEC-002: -WindowStyle hidden | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-EXEC-005: IWR/IRM+URL | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-DISC-001: discovery via cmd | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-003: certutil -urlcache | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-004: mshta | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-002: rundll32 + https | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-001: regsvr32 /i:https | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-005: wmic /node | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-009: bitsadmin /transfer | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LOLBIN-006: msiexec+https | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-CRED-005: cmdkey /list | - | ❌ 不匹配 | 无告警 | 未实现该规则 |
| R-LMOVE-004/005: admin$ echo | - | ❌ 不匹配 | 无告警 | 未实现该规则 |

### 1.2 P0 规则支持状态

| 规则ID | 描述 | 支持状态 | 测试用例 |
|--------|------|----------|----------|
| **R-EXEC-001** | PowerShell编码命令 | ✅ 已实现 | 4个测试用例 |
| **R-CRED-001** | 注册表凭证导出 | ✅ 已实现 | 0个测试用例 |
| **R-FILELESS-001** | 无文件攻击 | ✅ 已实现 | 2个测试用例 |
| R-EXEC-002 | PowerShell隐藏窗口 | ❌ 未实现 | 1个测试用例 |
| R-EXEC-005 | Web请求+URL | ❌ 未实现 | 2个测试用例 |
| R-DISC-001 | 系统发现命令 | ❌ 未实现 | 1个测试用例 |
| R-LOLBIN-001~009 | LOLBAS攻击 | ❌ 未实现 | 7个测试用例 |

---

## 2. 验证环境准备

### 2.1 前置条件

```powershell
# 1. 确保 EDR Agent 已安装并运行
# 2. 设置环境变量
$env:EDR_P0_DIRECT_EMIT = "1"
$env:EDR_BEHAVIOR_ENCODING = "protobuf"

# 3. 检查 Agent 状态
Get-Service | Where-Object { $_.Name -like "*edr*" }
```

### 2.2 验证配置

```powershell
# 推荐配置
$env:EDR_PROCNAME_GATE_WHITELIST = "powershell.exe,pwsh.exe,cmd.exe"
$env:EDR_DEDUP_WINDOW_SECONDS = "10"
$env:EDR_RATE_LIMIT_PER_SEC = "50"
```

---

## 3. 执行验证

### 3.1 运行 Smoke Test

```powershell
# 方式1：使用 DryRun 模式（不实际执行）
.\edr_platform_stack_smoke.ps1 -DryRun

# 方式2：正常运行（5次迭代）
.\edr_platform_stack_smoke.ps1

# 方式3：自定义迭代次数
.\edr_platform_stack_smoke.ps1 -Iterations 3 -StaggerMs 200
```

### 3.2 查看日志输出

```powershell
# 查看 Agent 日志
# 位置：安装目录/logs/

# 搜索 P0 相关日志
Select-String -Path ".\logs\*.log" -Pattern "\[P0\]"

# 搜索告警日志
Select-String -Path ".\logs\*.log" -Pattern "edr_dynamic_rule"
```

### 3.3 查看 Heartbeat 统计

```powershell
# P0 统计输出格式
# [p0] total=12345 env_skip=0 ir_match=5 fb_match=10 r_exec=3 r_cred=2 r_filess=0

# 检查统计
Get-Content .\logs\agent.log | Select-String "\[p0\]"
```

---

## 4. 预期结果

### 4.1 应该产生告警的用例

| 用例 | 预期告警数 | 规则ID |
|------|------------|--------|
| R-EXEC-001: powershell -encodedcommand | 1/迭代 | R-EXEC-001 |
| R-EXEC-001: frombase64string | 1/迭代 | R-EXEC-001 |
| R-FILELESS-001: IEX | 1/迭代 | R-FILELESS-001 |
| R-FILELESS-001: Invoke-Expression | 1/迭代 | R-FILELESS-001 |

### 4.2 预期统计变化

```
执行前：
[p0] total=1000 env_skip=0 ir_match=5 fb_match=10 r_exec=3 r_cred=2 r_filess=0

执行后（5次迭代）：
[p0] total=1024 env_skip=0 ir_match=5 fb_match=15 r_exec=8 r_cred=2 r_filess=4
                                    ↑           ↑           ↑           ↑
                                 无变化      +5          +5          +4
```

### 4.3 验证检查清单

- [ ] Agent 日志中有 `[P0]` 相关输出
- [ ] `r_exec` 计数增加
- [ ] `r_filess` 计数增加
- [ ] 后端平台出现 `edr_dynamic_rule` 类型的告警
- [ ] 告警的 `Title` 包含 `R-EXEC-001` 或 `R-FILELESS-001`

---

## 5. 故障排查

### 5.1 无告警产生

**检查1：环境变量是否设置正确**

```powershell
$env:EDR_P0_DIRECT_EMIT  # 应该输出 "1"
$env:EDR_BEHAVIOR_ENCODING  # 应该输出 "protobuf"
```

**检查2：P0 引擎是否启用**

```powershell
# 查看 Agent 日志中的 P0 初始化信息
Select-String -Path ".\logs\agent.log" -Pattern "\[P0\]"
```

**检查3：事件是否到达 Agent**

```powershell
# 查看原始事件日志
Select-String -Path ".\logs\agent.log" -Pattern "PROCESS_CREATE"
```

### 5.2 告警格式验证

**检查后端告警格式**

```json
{
  "user_subject_json": {
    "subject_type": "edr_dynamic_rule"
  },
  "title": "[规则] R-EXEC-001: PowerShell Encoded Command",
  "alert_type": "behavior",
  "source": "edr_agent"
}
```

---

## 6. 扩展 P0 规则建议

### 6.1 高优先级新增规则

| 规则ID | 描述 | 匹配条件 |
|--------|------|----------|
| R-EXEC-002 | PowerShell隐藏窗口 | `-WindowStyle hidden` + `-NoProfile` |
| R-EXEC-005 | Web请求+URL | `Invoke-WebRequest` / `Invoke-RestMethod` + URL |
| R-LOLBIN-003 | CertUtil下载 | `certutil.exe` + `-urlcache` |
| R-LOLBIN-004 | Mshta执行 | `mshta.exe` + URL 或 `.hta` |

### 6.2 规则实现示例

```c
// R-EXEC-002: PowerShell隐藏窗口
static int match_r_exec_002(const char *cmd) {
    if (!cmd) return 0;
    // -WindowStyle hidden + -NoProfile 组合
    if (cistr_find(cmd, "-windowstyle") && cistr_find(cmd, "hidden") &&
        cistr_find(cmd, "-noprofile")) {
        return 1;
    }
    return 0;
}
```

---

*文档生成时间：2026-04-28*