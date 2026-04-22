# 剩余工作汇总（Shellcode / 取证 / 控制台）

本文是 **`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 中未完成项的**一页摘要**，便于排期；**若与主清档不一致，以主清档中的 `[ ]` / `[x]` 为准**。

---

## Agent（`edr-agent`）

| ID | 内容 | 详情 |
|----|------|------|
| **P1（余量）** | **`forensic` JSON**：**`paths[]`**；**Windows** 下 **`registry_keys` / `memory_regions`** 在 **`EDR_FORENSIC_REGISTRY_DUMP` / `EDR_FORENSIC_MEMORY_DUMP`** 开启时落盘 | **`FORENSIC_STRUCTURED_PAYLOAD.md`**、**`WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P1** |
| **P1 清单** | **`manifest.txt`**：**用户 / 卷序列号**（Windows）已写；其余扩展字段随产品再定 | 同上 §P1、`command_stub.c` |
| **P2-PERF-4** | 合规环境下合成流量压测 + 报告（参数表、CPU、**`wd_stats`**） | **`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`** 已填框架与 §4 格式示例；**客户级**验收另存 **`P2_PERF4_RUN_*`** 并粘贴真实 §4；**`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 主清档已 **`[x]`** |
| **P2c（余量）** | **S1** 已实现 **`--service`**；可选 **Prometheus 进程内 `/metrics`** 仍排期；**S2–S4** 见专文 | **`WINDOWS_SERVICE_SHUTDOWN.md`**、**`WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P2c** |

**已完成（本线摘要中不重复展开）**：例如 **P2-PERF-1**（SLO 框架 — **`docs/SHELLCODE_AGENT_SLO.md`**）、**P2-PERF-2**、**P2-PERF-3**、**C1**–**C3**、**C4**（**`AGT009` §2.1** + **`WINDOWS_DEPLOY`** 预检）、取证打包去 `system`、`UploadFile` 客户端调用与 **`forensic-<command_id>`** 等 — 见主清档 **[x]** 行。

---

## 平台 / 前端 / 文档（多仓库）

（**C2–C3** 已关：**`GET /alerts/:id`** 合并 **`UploadFile`** 键；**`AlertDetailPage`** 展示与复制。）

---

## 全链路联调（不限于 Shellcode）

**`docs/CLIENT_IMPROVEMENT_TASKS.md`** 中「联调前检查清单」等 **`[ ]`**（平台栈、enroll、**`ReportEvents`**、注册表验收、SOAR、**`Subscribe`**、AVE/ONNX、Windows 部署等）仍适用。

---

## 实现状态快照（README 交叉引用）

**`README.md`**「实现状态快照」中 **P1 §8 / P2 §9** 已链至 **`FORENSIC_STRUCTURED_PAYLOAD`** 与 **§P2c** 专文；**仍排期** 项（进程内 **`/metrics`**、**P3 §12**、**P4 §5** 等）以 **`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 与 **`REMAINING.md`** 表为准；总线满丢弃细节以 **`docs/EVENT_BUS_BACKPRESSURE.md`** 为准。
