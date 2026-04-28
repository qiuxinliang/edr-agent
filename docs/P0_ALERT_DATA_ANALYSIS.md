# P0 规则命中后发送的数据分析

**版本**：1.0
**日期**：2026-04-28
**状态**：已完成

---

## 1. P0 告警数据结构

### 1.1 AVEBehaviorAlert 结构

```c
typedef struct AVEBehaviorAlert {
  uint32_t pid;                      // ✅ 进程ID
  char process_name[256];           // ✅ 进程名
  char process_path[512];            // ✅ 进程路径
  float anomaly_score;                // ✅ 异常分数
  float tactic_probs[14];           // ❌ 未设置
  char triggered_tactics[512];      // ✅ Mitre战术
  AVEBehaviorFlags behavior_flags;   // ❌ 未设置
  bool skip_ai_analysis;            // ✅ 设置为true
  bool needs_l2_review;             // ✅ 设置为false
  int64_t timestamp_ns;             // ✅ 时间戳
  char related_iocs_json[4090];    // ❌ 未设置（留空）
  char user_subject_json[1024];     // ✅ 规则元数据
} AVEBehaviorAlert;
```

### 1.2 user_subject_json 内容

```json
{
  "subject_type": "edr_dynamic_rule",
  "rule_id": "R-EXEC-001",
  "rules_bundle_version": "1.0.0",
  "display_title": "PowerShell Encoded Command"
}
```

---

## 2. EdrBehaviorRecord 完整上下文

P0规则检测函数接收的 `EdrBehaviorRecord` 包含以下数据：

```c
typedef struct {
  // 进程信息
  uint32_t pid;                      // 进程ID
  uint32_t ppid;                     // 父进程ID
  char process_name[256];            // 进程名
  char cmdline[1024];                // 命令行
  char exe_hash[65];                // 可执行文件哈希
  char exe_path[1024];               // 可执行文件路径
  char username[256];               // 用户名

  // 父子进程
  char parent_name[256];             // 父进程名
  char parent_path[512];            // 父进程路径

  // 文件操作
  char file_op[32];                 // 文件操作类型
  char file_path[1024];             // 文件路径

  // 网络信息
  char net_src[64];                 // 源地址
  char net_dst[64];                 // 目标地址
  uint32_t net_sport;               // 源端口
  uint32_t net_dport;               // 目标端口
  char net_proto[16];               // 协议
  char dns_query[512];              // DNS查询

  // 注册表
  char reg_key_path[1024];          // 注册表键路径
  char reg_value_name[512];         // 值名称
  char reg_value_data[8192];        // 值数据

  // 脚本
  char script_snippet[1024];        // 脚本片段

  // 进程链
  uint32_t process_chain_depth;     // 进程链深度
} EdrBehaviorRecord;
```

---

## 3. 当前 P0 告警实际发送的内容

### ✅ 已发送的数据

| 字段 | 来源 | 示例 |
|------|------|------|
| `pid` | `br->pid` | 1234 |
| `timestamp_ns` | `br->event_time_ns` | 1714300000000000000 |
| `process_name` | `br->process_name` | "powershell.exe" |
| `process_path` | `br->exe_path` | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" |
| `anomaly_score` | 固定值 0.70 | 0.70 |
| `triggered_tactics` | 规则元数据 | "T1059.003" |
| `user_subject_json` | 规则元数据 | 见上方 |

### ❌ 未发送的数据（缺失）

| 字段 | 说明 | 影响 |
|------|------|------|
| `ppid` | 父进程ID | 无法看到父进程 |
| `parent_name` | 父进程名 | 无法看到父进程 |
| `parent_path` | 父进程路径 | 无法看到父进程链 |
| `cmdline` | 命令行参数 | **重要**：无法看到完整命令 |
| `exe_hash` | 文件哈希 | 无法验证文件 |
| `username` | 用户名 | 无法知道谁执行的 |
| `process_chain_depth` | 进程链深度 | 无法知道攻击链深度 |
| `file_path` | 文件路径 | 无文件上下文 |
| `net_*` | 网络信息 | 无网络上下文 |
| `dns_query` | DNS查询 | 无DNS上下文 |
| `reg_*` | 注册表信息 | 无注册表上下文 |
| `script_snippet` | 脚本内容 | 无脚本上下文 |
| `pmfe_snapshot` | PMFE摘要 | 无高级威胁上下文 |

---

## 4. 问题分析

### 4.1 主要问题

**P0告警只发送了进程基本信息，缺失大量上下文！**

当前P0告警只有：
```
- pid: 1234
- process_name: powershell.exe
- process_path: C:\Windows\System32\...
- anomaly_score: 0.70
- Mitre: T1059.003
```

**缺少的上下文信息：**
```
- 父进程是谁？（cmd.exe? explorer.exe?）
- 命令行参数是什么？（-EncodedCommand xxx?）
- 用户是谁？（管理员? 普通用户?）
- 进程链有多深？（1层？5层？）
```

### 4.2 为什么会这样？

查看 `emit_for_rule` 函数：

```c
static int emit_for_rule(const EdrBehaviorRecord *br, const char *rule_id,
                        const char *title, const char *mitre_comma) {
  AVEBehaviorAlert a;
  memset(&a, 0, sizeof(a));
  a.pid = br->pid;                              // ✅ 发送
  a.timestamp_ns = br->event_time_ns;         // ✅ 发送
  snprintf(a.process_name, ..., br->process_name);    // ✅ 发送
  snprintf(a.process_path, ..., br->exe_path);        // ✅ 发送
  a.anomaly_score = sev3_anomaly();            // ✅ 发送
  snprintf(a.triggered_tactics, ..., mitre_comma);     // ✅ 发送
  a.skip_ai_analysis = true;                   // ✅ 发送
  a.needs_l2_review = false;                  // ✅ 发送

  // ❌ 下面这些都没有填充！
  // a.ppid, a.parent_name, a.cmdline, a.exe_hash, etc.
}
```

---

## 5. 建议改进

### 5.1 方案1：增强 AVEBehaviorAlert 结构

```c
typedef struct AVEBehaviorAlert {
  // ... 现有字段 ...

  // 新增字段
  uint32_t ppid;                     // 父进程ID
  char parent_name[256];             // 父进程名
  char parent_path[512];              // 父进程路径
  char cmdline[1024];                // 命令行
  char exe_hash[65];                 // 文件哈希
  char username[256];                // 用户名
  uint32_t process_chain_depth;      // 进程链深度

  // 如果是网络相关事件
  char net_src[64];
  char net_dst[64];
  uint32_t net_sport;
  uint32_t net_dport;
  char dns_query[512];

  // 如果是注册表相关事件
  char reg_key_path[1024];
  char reg_value_name[512];
} AVEBehaviorAlert;
```

### 5.2 方案2：将完整上下文放入 user_subject_json

```c
// 在 emit_for_rule 中
{
  int n = snprintf(
      a.user_subject_json, sizeof(a.user_subject_json),
      "{"
      "\"subject_type\":\"edr_dynamic_rule\","
      "\"rule_id\":\"%s\","
      "\"rules_bundle_version\":\"%s\","
      "\"display_title\":\"%s\","
      "\"context\":{"
        "\"ppid\":%u,"
        "\"parent_name\":\"%s\","
        "\"cmdline\":\"%s\","
        "\"username\":\"%s\","
        "\"process_chain_depth\":%u"
      "}"
      "}",
      rule_id, EDR_P0_RULES_BUNDLE_VERSION, title,
      br->ppid,
      br->parent_name[0] ? br->parent_name : "",
      br->cmdline[0] ? br->cmdline : "",
      br->username[0] ? br->username : "",
      br->process_chain_depth);
}
```

### 5.3 方案3：创建一个新的 P0Alert 结构体

```c
typedef struct P0Alert {
  uint32_t pid;
  uint32_t ppid;
  char process_name[256];
  char process_path[512];
  char cmdline[1024];
  char parent_name[256];
  char parent_path[512];
  char exe_hash[65];
  char username[256];
  uint32_t process_chain_depth;
  char rule_id[64];
  char title[256];
  char mitre_tactics[512];
  int64_t timestamp_ns;
  float anomaly_score;
  char related_iocs_json[4090];
} P0Alert;
```

---

## 6. 实施建议

### 6.1 优先级1：添加命令行和父进程信息

```c
// 修改 emit_for_rule
snprintf(a.process_name, sizeof(a.process_name), "%s", br->process_name);
snprintf(a.process_path, sizeof(a.process_path), "%s", br->exe_path);
snprintf(a.cmdline, sizeof(a.cmdline), "%s", br->cmdline);  // 新增
snprintf(a.parent_name, sizeof(a.parent_name), "%s", br->parent_name);  // 新增
a.ppid = br->ppid;  // 新增
```

### 6.2 优先级2：添加用户和进程链信息

```c
snprintf(a.username, sizeof(a.username), "%s", br->username);  // 新增
a.process_chain_depth = br->process_chain_depth;  // 新增
```

### 6.3 优先级3：根据事件类型添加上下文

```c
// 网络事件
if (br->type == EDR_EVENT_NET_CONNECT || br->type == EDR_EVENT_NET_DNS_QUERY) {
  snprintf(a.dns_query, sizeof(a.dns_query), "%s", br->dns_query);
  snprintf(a.net_dst, sizeof(a.net_dst), "%s", br->net_dst);
  a.net_dport = br->net_dport;
}
```

---

## 7. 总结

### 7.1 当前状态

| 数据类型 | 状态 | 说明 |
|----------|------|------|
| 进程基本信息 | ✅ 已发送 | pid, process_name, process_path |
| 时间戳 | ✅ 已发送 | timestamp_ns |
| Mitre战术 | ✅ 已发送 | triggered_tactics |
| 规则元数据 | ✅ 已发送 | user_subject_json |
| 父进程信息 | ❌ 未发送 | ppid, parent_name |
| 命令行参数 | ❌ 未发送 | cmdline |
| 用户信息 | ❌ 未发送 | username |
| 进程链深度 | ❌ 未发送 | process_chain_depth |
| 网络上下文 | ❌ 未发送 | dns_query, net_dst |
| 文件上下文 | ❌ 未发送 | file_path |
| 注册表上下文 | ❌ 未发送 | reg_key_path |

### 7.2 影响

**当前P0告警对安全分析师来说信息量不足**，需要：
1. 关联多个数据源才能还原完整攻击链
2. 无法直接看到命令参数
3. 无法直接看到父进程
4. 无法直接看到用户

### 7.3 建议

**建议增强 P0 告警的上下文信息**，至少包含：
- 命令行参数（cmdline）
- 父进程信息（parent_name, ppid）
- 用户信息（username）
- 进程链深度（process_chain_depth）

---

*文档生成时间：2026-04-28*