# PMFE 空闲扫描器设计文档

> PMFE Idle Scanner — 针对系统服务进程的 APT 内存木马低频检测  
> 版本: v1.0 | 日期: 2026-05-04 | 作者: Agent Architecture

---

## 1. 背景与威胁模型

国家背景的 APT 组织（如 APT29/APT41/Hafnium）常用技术：

| TTP | MITRE | 注入目标 | 内存特征 |
|-----|-------|----------|----------|
| Process Injection | T1055 | svchost / lsass / spoolsv | 私有 MEM_PRIVATE + PAGE_EXECUTE_READWRITE |
| Reflective DLL Loading | T1620 | services / winlogon | 无磁盘映射的 RX 区域 + MZ 头 |
| Process Hollowing | T1055.012 | explorer / w3wp | 模块 stomp（磁盘 hash ≠ 内存在页 hash） |
| CobaltStrike Beacon | S0154 | 任何系统进程 | RWE 内存 + 规律性出站心跳 |

**核心假设**：攻击者注入系统服务进程后，该进程必然产生非预期的 C2 通信。

---

## 2. 三层过滤漏斗

```
系统全量进程 (~200)
  │
  ├── 过滤 1: 系统服务进程筛选 (~30)
  │   条件: PID > 100
  │        + 非交互用户会话启动
  │        + process_name ∈ SYSTEM_SERVICE_SET
  │        + 签名者为 Microsoft
  │
  ├── 过滤 2: 活跃网络连接筛选 (~5-10)
  │   条件: GetExtendedTcpTable 存在 ESTABLISHED 连接
  │        + 排除标准端口 (80/443) 且进程名为 w3wp.exe 或 MsMpEng.exe
  │
  └── 过滤 3: PMFE VAD 深度扫描 (命中 0-1)
      条件: MEM_PRIVATE + PAGE_EXECUTE_READWRITE
          + 内存头含 MZ/PE 签名
          + Shannon 熵 > 6.0
          + 无磁盘文件映射或模块 stomp
```

### 2.1 系统进程白名单 (SYSTEM_SERVICE_SET)

```c
static const char *g_system_services[] = {
  "svchost.exe",    // 服务宿主 — 注入首选
  "lsass.exe",      // 本地安全认证
  "spoolsv.exe",    // 打印服务
  "services.exe",   // SCM
  "winlogon.exe",   // 登录管理
  "csrss.exe",      // Windows 子系统
  "dwm.exe",        // 桌面窗口合成
  "taskhostw.exe",  // 任务宿主
  "wlms.exe",       // Windows 许可证
  "fontdrvhost.exe",
  "wininit.exe",
  "WmiPrvSE.exe",   // WMI — 频繁成为注入目标
  "msdtc.exe",      // 分布式事务
  "VSSVC.exe",      // 卷影复制
  NULL
};
```

### 2.2 TCP 连接获取

```c
#define PMFE_TCP_TABLE_ROW_COUNT 2000
MIB_TCPTABLE_OWNER_PID *t = malloc(sizeof(*t) + sizeof(t->table[0]) * PMFE_TCP_TABLE_ROW_COUNT);
t->dwNumEntries = PMFE_TCP_TABLE_ROW_COUNT;
GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

// 拉取一次全量，内存检索
for (DWORD i = 0; i < t->dwNumEntries; i++) {
  if (t->table[i].dwState == MIB_TCP_STATE_ESTAB) {
    tcp_pids[t->table[i].dwOwningPid] = 1;
  }
}
```

---

## 3. 架构

```
┌─────────────────────────────────────────────────┐
│            pmfe_listen_poll_main (60s 周期)      │
│                                                   │
│  if (!idle_scanner_enabled) return;               │
│  if (!cpu_idle_60s()) return;                     │
│                                                   │
│  ┌─ 过滤1: enum_processes_system_services() ──┐   │
│  ├─ 过滤2: filter_by_tcp_table(pids)          │   │
│  ├─ 过滤3: pmfe_submit_scan(pids[], "idle")   │   │
│  └─ 结果: 上报异常命中                          │   │
└─────────────────────────────────────────────────┘
```

- **线程**：复用现有 `pmfe_listen_poll_main` 的 60 秒 tick，不新增线程
- **任务队列**：复用现有 `PMFE_TASK_CAP(64)` 和 2 个 worker
- **优先级**：worker 在空闲扫描期间自动切换到 `THREAD_MODE_BACKGROUND_BEGIN`
- **配置**：`[pmfe] idle_scan_enabled = false`（默认关闭）

---

## 4. 空闲判定

```c
static int cpu_idle_60s(void) {
  // 1. 检查过去 60s 平均 CPU 使用率
  //    GetSystemTimes + 60s 差值计算
  //    阈值: < 15% (用户态 + 内核态)
  //
  // 2. 全屏检测
  //    GetForegroundWindow + GetWindowPlacement
  //    若全屏且持续 60s → 跳过
  //
  // 3. 电池检测（笔记本）
  //    GetSystemPowerStatus
  //    BatteryFlag & 4 → AC 供电 或 电量 > 50%
  return 1;
}
```

---

## 5. 配置项

```toml
[pmfe]
# 默认 0（关闭），1 开启
enabled = 0

# 空闲扫描
idle_scan_enabled      = false
idle_scan_interval_min = 15     # 扫描间隔（分钟）
idle_scan_max_procs    = 8      # 单轮最大扫描进程数
idle_cpu_threshold     = 15.0   # CPU 阈值 (%)，低于此值启用
```

---

## 6. 结果上报

仅上报异常命中（减少噪音）：

```json
{
  "event": "PMFE_IDLE_SCAN_ANOMALY",
  "pid": 1234,
  "process_name": "svchost.exe",
  "findings": {
    "private_rwx_mz": 2,
    "max_entropy": 6.82,
    "stomp_suspicious": 1,
    "private_exec_regions": 3,
    "tcp_dest": ["185.130.5.253:443"]
  }
}
```

通过行为告警批（`ave_behavior_alert_emit_to_batch`）上报到后端，与其他行为告警统一展示。

---

## 7. 实现清单

| # | 文件 | 改动 | 行数估计 |
|---|------|------|---------|
| 1 | `src/pmfe/pmfe_idle_scanner.c` | 新建 — 三层过滤 + 空闲判定 + TCP 枚举 | ~250 |
| 2 | `src/pmfe/pmfe_idle_scanner.h` | 新建 — 接口声明 | ~20 |
| 3 | `src/pmfe/pmfe_engine.c` | `pmfe_listen_poll_main` 60s tick 中调用 | ~8 |
| 4 | `include/edr/config.h` | 加 `pmfe` 配置 struct | ~6 |
| 5 | `src/config/config.c` | TOML 解析 + 默认值 | ~20 |
| 6 | `agent.toml.example` | 加 `[pmfe]` 段说明 | ~10 |
| **合计** | | | **~314 行** |

---

## 8. 风险与边界

| 场景 | 处理 |
|------|------|
| `GetExtendedTcpTable` 失败 | 跳过本轮，不阻塞 |
| 扫描时进程退出 | `OpenProcess` 失败直接 continue |
| w3wp.exe（正常 IIS 网络+内存分配） | 过滤1 排除非系统服务，或过滤2 排除 standard port |
| VM 环境 `ReadProcessMemory` 慢 10x | 单进程上限 500ms 超时，超时 skip |
| 同一进程多轮重复扫描 | `last_scan_ns` 去重，间隔 < interval 跳过 |
