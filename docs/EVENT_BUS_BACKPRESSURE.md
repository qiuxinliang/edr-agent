# 事件总线背压与丢弃行为（P2-PERF-3）

本文描述 **`edr_event_bus_try_push`** 在**队列满**或**非法参数**时的语义，以及各采集线程的**可观测性**差异；与当前实现一致（**无**「满则只丢低优」「降采样」等可选开关 — 属后续产品项）。

**实现**：`src/core/event_bus.c`、`include/edr/event_bus.h`  
**容量配置**：`[collection].max_event_queue_size`（`src/config/config.c` 默认 **4096**，夹紧 **256～65536**）→ `edr_agent_init` 中 **`edr_event_bus_create`**（`src/core/agent.c`）。  
**产品 SLO（总线类指标占位）**：**`docs/SHELLCODE_AGENT_SLO.md`**。

---

## 1. 环形队列与「满」的判定

- 总线为**互斥保护的环形缓冲区**（设计目标见 **`event_bus.h`** 头注释：长期可无锁环，当前为便于联调的互斥实现）。
- 槽位数组长度为 **`cap = max_event_queue_size`**。满条件为 **`(tail + 1) % cap == head`**，因此**同时在队列中的事件条数最多为 `cap - 1`**（保留一格区分空/满）。
- **`edr_event_bus_try_push(bus, slot)`**：
  - **`bus` 或 `slot` 为空**：返回 **`false`**，**不**增加 `dropped` 计数（调用方视为无效入队）。
  - **队列已满**：**复制不发生**；**`dropped++`**；返回 **`false`**（**非阻塞**，无重试、无阻塞等待）。

---

## 2. 推送失败时的业务含义

**满队列时当前策略：该条事件丢弃**，不进入预处理线程、不产生批次上报、不落地磁盘队列。各生产者**不**共享「阻塞直到有空间」的语义。

**高水位计数 `high_water_hits`（stderr 汇总字段 `bus_hw80`）**：在**本次推送成功**且当前占用 **`used * 100 >= cap * 80`** 时，**`high_water_hits++`**（`event_bus.c`）。用于观测「总线长期贴近满载」的频率，与 **`dropped`** 配合看背压。

---

## 3. 各调用方对 `try_push` 失败的处理

| 调用方 | 文件 | 失败时 |
|--------|------|--------|
| Windows ETW 采集 | `src/collector/collector_win.c` | 失败时 **`dropped` 仍累计**；stderr **`[collector_win] event bus full…`** 至多约 **每 5s** 一行（节流），并带本窗口内丢弃约计数 |
| Linux inotify 采集 | `src/collector/collector_linux.c` | 同上 |
| WinDivert shellcode 告警 | `src/shellcode_detector/windivert_capture.c` | **`fprintf`**：`[shellcode_detector] event bus full, drop shellcode alert`；**`s_wd_stat_bus_drops++`**（**`EDR_SHELLCODE_WD_STATS=1`** 停止时可见） |
| Webshell（Windows） | `src/webshell_detector/webshell_detector_win.c` | 失败时 **`fprintf`**：`[webshell_detector] event bus full, drop alert: <path>`（与 Linux 对齐） |
| Webshell（Linux） | `src/webshell_detector/webshell_detector_linux.c` | **`fprintf`**：`[webshell_detector] event bus full, drop alert: <path>` |
| PMFE 扫描结果 | `src/pmfe/pmfe_engine.c` | 失败时 stderr **`[pmfe] event bus full…`** 至多约 **每 5s** 一行（节流） |

结论：**丢弃与计数以总线为准**；**即时**一行 stderr：**shellcode（WinDivert）**、**webshell（Linux/Windows）**；**节流** stderr：**Windows ETW**、**PMFE**；其余路径仍主要依赖进程退出汇总与自保护轮询。

---

## 4. 运维可观测性

1. **进程退出**（`src/main.c`）：**`[preprocess]`** 行中的 **`bus_hw80`**、**`bus_dropped`** 分别对应 **`edr_event_bus_high_water_hits`**、**`edr_event_bus_dropped_total`**。
2. **自保护**（`src/self_protect/self_protect.c`）：
   - **`edr_self_protect_format_status`**：含 **`bus_pct`**（近似占用百分比）、**`hw_hits`**、**`dropped`**。
   - **`edr_self_protect_poll`**：当占用 ≥ **`[self_protect].event_bus_pressure_warn_pct`**（默认 **90**，**0** 表示关闭）时，**每 25 次轮询最多打 1 行** stderr，打印占用比例、阈值、**`hw_hits`**、**`dropped`**。

配置示例见 **`agent.toml.example`**（**`max_event_queue_size`**、**`event_bus_pressure_warn_pct`**）。

---

## 5. 与 WinDivert / §17 的关系

Shellcode 路径在总线满时**丢弃整条 shellcode 告警事件**（见上表）；本地 PCAP / 环形取证等**不依赖**总线是否成功入队，但**平台侧不可见**该条告警。调大 **`max_event_queue_size`**、降低上游事件速率、或优化预处理/上报吞吐，可减少丢弃；**P2-PERF-4** 压测可结合 **`wd_stats`** 与退出 **`bus_dropped`** 做报告。

---

## 6. 明确非目标（后续）

- **总线满时按 `priority` 选择性丢弃**（例如仅丢 `priority != 0`）：**未实现**。
- **降采样 / 合并**：**未实现**。
- 若产品需要上述策略，需在 **`event_bus` 或各 producer** 层新增设计与开关，并更新本文与 **`WINDOWS_SHELLCODE_FORENSIC_TODO.md`**。
