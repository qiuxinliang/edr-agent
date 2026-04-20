# AGT-012：Linux 内核态采集（P7）— 技术选型与分阶段计划

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-012](CLIENT_IMPROVEMENT_TASKS.md)、设计 **§3.2**、[README.md](../README.md) 路线图  

当前 Linux 主路径为 **inotify 文件事件（M1）**（`collector_linux.c`），与 Windows **ETW** 在进程/网络等维度 **不对等**。本文给出 **P7** 阶段目标、选型约束与 **PR 分期**，供评审与排期。

---

## 1. 目标

- 以 **eBPF CO-RE**（或等价可移植方案）补充 **进程 / 网络 / 文件** 等内核态遥测，并与现有 **总线 + 预处理** 对齐（`ETW1` 文本槽或后续结构化字段）。
- 与 **设计 §3.2** 一致：优先 **可维护、可灰度、可降级**（内核版本不足时回退 **inotify-only**）。

---

## 2. 技术选型（草案）

| 方向 | 说明 |
|------|------|
| **CO-RE + libbpf** | 主流路线；需 **BTF**、内核版本下限与发行版矩阵。 |
| **bcc / bpftrace** | 原型快，**不适合** 常驻 Agent 主路径依赖。 |
| **auditd / perf** | 备选补充，与 eBPF 关系需在集成时统一。 |

**构建**：`EDR_WITH_LINUX_COLLECTOR` 与 **`EDR_WITH_EBPF`**（拟新增）分层；**默认 OFF**，避免无 eBPF 环境编不过。

---

## 3. 分阶段 PR 计划（建议）

| 阶段 | 内容 | 产出 |
|------|------|------|
| **P7.0** | 仓库内 **vmlinux/BTF 探测**、**noop 探针**、CMake 可选链接 | 可编过、默认不启用 |
| **P7.1** | **进程 exec/exit** 映射到现有 `EdrEventSlot` 类型或 ETW1 兼容行 | 与 PMFE/预处理可对齐的最小集 |
| **P7.2** | **网络**（connect/accept 级）与 **§3.2** 字段表对齐 | 与设计映射表更新 |
| **P7.3** | 性能、**ring buffer** 背压、与 **resource / 预处理降载** 协同 | 生产可开 |

---

## 4. 与 Windows ETW 的映射表（初稿，随 P7.2 细化）

| 能力 | Windows（ETW） | Linux P7（目标） |
|------|----------------|------------------|
| 进程创建/退出 | Kernel-Process | eBPF `sched_process_exec` / `...` |
| 网络连接 | Kernel-Network / TCPIP Provider | eBPF tracepoint/sock |
| 文件写 | Kernel-File / inotify | inotify + eBPF 可选叠加 |

---

## 5. 非目标（本文不展开）

- 替换 **inotify M1** 为唯一文件路径前，需单独评审 **行为兼容性**。
- **Windows** 路径不变。

---

**状态**：**AGT-012** 以本文为 **技术选型笔记 + 分阶段计划**；**实现** 按 P7.x 在后续 PR 落地。
