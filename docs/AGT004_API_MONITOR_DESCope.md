# AGT-004：API / IAT 监控层 — 本期范围说明（正式 descope）

**关联**：[CLIENT_IMPROVEMENT_TASKS.md §AGT-004](CLIENT_IMPROVEMENT_TASKS.md)  
**设计对照**：[Cauld Design/EDR_端点详细设计_v1.0.md](../Cauld%20Design/EDR_端点详细设计_v1.0.md) **§1.2**（API 监控层 / IAT Hook 意图）

---

## 决策

本仓库 **当前版本不实现** 用户态 **IAT Hook / inline hook / 第三方 Detours 类 API 监控层**。

## 原因（摘要）

1. **采集主路径已确立**：Windows 以 **ETW 实时会话**（`collector_win.c`，Kernel-Process / Kernel-File / Kernel-Network 及扩展 Provider）将事件送入 **`EdrEventBus`**，经 **预处理** 产出行为记录；与 §1.2 图中「API 监控层」在**进程内挂钩**的形态不同，但在**终端行为可见性**上由 **内核态 + 总线** 覆盖主要威胁面。
2. **稳定性与兼容性**：用户态全局/按进程 API Hook 易与 **反病毒、其他 EDR、加固软件** 冲突，且需长期维护 **OS 版本 / 补丁** 差异；与当前「先跑通 ETW → 预处理 → 上报」的里程碑优先级不一致。
3. **取证与扩展能力**：内存/模块相关能力由 **PMFE**、**AVE**、**指令 forensic** 等路径补充，不依赖通用 IAT 层。

## 与设计文档的关系（避免静默缺口）

- **§1.2 仍可作为架构意图**；本仓库在 README **能力矩阵**中显式标注 **「本期不做 IAT Hook」**，并指向本文。
- 若产品后续强制要求「用户态 API 调用序列」类遥测，再单独立项：**PoC 分支**（限定进程/限定 API）或 **驱动/回调** 方案评审，并与 **Cauld Design** 同步修订 §1.2 的落地形态。

## 后续研发（非承诺排期）

| 方向 | 说明 |
|------|------|
| 定向 PoC | 仅对 **单进程 / 少数量 API** 做 Hook 验证，评估误报与性能 |
| Linux 对齐 | 与 **§3.2 eBPF**（AGT-012）协同，而非在 Linux 上引入 IAT |
| 文档 | 更新 Cauld Design §1.2 脚注：「edr-agent 实现以 ETW+总线 为主路径」 |

---

**状态**：作为 **AGT-004** 的 **正式 descope** 交付物；关闭该子任务以「文档决策记录」为准，**无** PoC 代码分支。
