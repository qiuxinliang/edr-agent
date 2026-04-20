# PMFE Linux 后续开发清单（Backlog）

本文档单独记录 **Linux 端 PMFE** 的**已实现基线**与**后续需求（留存待办）**。

**策略（与评审对齐）：**

- **交付与验收优先 Windows**：见 **`PMFE_WINDOWS_COMPLETENESS.md`**（§0 进度检查）。
- **Linux 不阻塞 Windows 里程碑**；下列需求为 **后续迭代 / 产品选型** 时启用，**不在当前 Windows 主线的必达范围**。

Linux 运行时能力以 `edr-agent/src/pmfe/pmfe_engine.c` 中 `#elif defined(__linux__)` 为准。

设计对照：**`Cauld Design/07_进程内存取证引擎PMFE设计.md` 第 9 章 Linux 适配**。

---

## 1. 已实现（基线，便于与 backlog 区分）

- 读取 **`/proc/<pid>/maps`**，解析行、对私有可执行等映射打分，候选池排序后 **`peek`**（解析/打分见 **`pmfe_linux_scan_util.c`**，可单测）。
- 读内存：**`process_vm_readv`**，失败时 **`/proc/<pid>/mem` + `pread`**；详情 **`vm_read_failures=`** 聚合双路径均失败次数。
- 魔数：**ELF**（`\x7FELF`）计入详情 **`elf_hits=`**；熵 **`ent_max`**。
- 可选 **DNS ASCII** 分块扫描（与 Windows 同类的简化 ASCII 规则）；`dns_utf16` / `dns_wire` 在 Linux 上为 0；受 **`EDR_PMFE_DNS_DISABLED`** 等影响。
- **`module_integrity` 档位**：文件路径私有可执行映射上 **ELF 头与磁盘前缀比对**（stomp）、**磁盘 SHA256 前缀**（`disk_hash_ok`），与 Windows 共用 **`EDR_PMFE_STOMP_BYTES`** / **`EDR_PMFE_DISK_HASH_MAX`**。
- **`EDR_PMFE_LINUX_ANON_EXEC_ONLY=1`**：候选池仅 **匿名 / `[vdso]`** 类可执行段（与设计 §9.1 「仅匿名」对齐）。
- 宿主：**`pmfe_host_policy_linux.c`**（`ss -ltnp` + `/proc`）；**`edr_pmfe_init`** 起 **60s + 去抖** 监听表刷新（与 Windows 同语义）；**`EDR_PMFE_LISTEN_REFRESH_ON_PROCESS=0`** 可关生命周期去抖。
- 任务字段：**`EdrPmfeTask`** 全量传入（`peek_cap`、`full_vad`、`dns_path`、`priority`、`band`）。
- 下游：**`pid_history_pmfe`** 解析 `elf_hits` → JSON **`"elf"`**；事件 **`EDR_PMFE_EMIT_ELF`** 与 **`EDR_PMFE_EMIT_MZ`** 分离；**`maps_open_failed`** 与 **`open_process=failed`** 一致降噪。

---

## 2. 与 Windows 对比：仍弱或未对等的部分（事实描述）

### 2.1 宿主 / 入队

| 项目 | 现状 | 备注 |
|------|------|------|
| 优先级 / 监听表 | **`pmfe_host_policy_linux.c`** + **`edr_pmfe_listen_table_refresh`** | 已落地；**无** Windows **规则 3（Win32 服务 PID + 监听）** 的 systemd 等价（可选后续）。 |
| 进程生命周期 → 监听刷新 | **`EDR_LINUX_PROC_CONNECTOR=1`**、预处理对 **`PROCESS_CREATE`/`TERMINATE`** | 与 ETW 全量进程事件仍有差距。 |
| 预处理自动入队 | **`EDR_PMFE_ETW_AUTO` + webshell**（**`pmfe_etw_preprocess.c`**） | **无** Windows 侧 **`EDR_EVENT_PROTOCOL_SHELLCODE`** 全量 ETW1 能力；扩展依赖 **`11_behavior.onnx详细设计.md`** 与流水线。 |

### 2.2 扫描与 §9

| 项目 | 现状 | 备注 |
|------|------|------|
| 高价值映射 | **`EDR_PMFE_LINUX_ANON_EXEC_ONLY`** | 策略开关已有。 |
| **`module_integrity`** | ELF 头 stomp + 磁盘 SHA256 前缀（maps 路径） | 与 Windows **EnumProcessModules** 语义近似，非 100% 对齐。 |
| **路径 A（ELF 重建/上传）** | **未实现** | 与 MinIO/gRPC/控制台约定，**独立大项**。 |
| **AVE 落盘扫描** | **未接** | Windows 有 **`EDR_PMFE_AVE_TEMPFILE`**；Linux 需单独方案。 |

### 2.3 可观测 / 测试

| 项目 | 现状 |
|------|------|
| **`maps_open_failed` 降噪** | 已与 **`open_process=failed`** 一致。 |
| **`vm_read_failures=`** | 已在 detail；**未**写入 **`pid_history` JSON**（可选增强）。 |
| 自动化测试 | **`test_pmfe_linux_maps`**（纯逻辑）；**无** 与 ptrace/权限相关的 E2E。 |

---

## 3. Linux 后续需求清单（留存待办 · 不阻塞 Windows）

以下条目供 **Linux 专项排期** 使用；**不**作为当前 Windows 交付的依赖。

| 优先级 | 需求 | 说明 |
|--------|------|------|
| **P0** | **ELF 路径 A（样本重建/上传）** | 对齐设计 §9 / MinIO / gRPC；与 Webshell/平台模块衔接。 |
| **P0** | **Linux AVE（或等价）与 `EDR_PMFE_AVE_*` 对齐** | 与 Windows tempfile 扫描路径一致化，需 **`edr_pmfe_bind_config`** + AVE 初始化。 |
| **P1** | **预处理扩展** | `EDR_PMFE_ETW_AUTO` 下增加 **`behavior.onnx` 高置信类型**、脚本/shellcode 等（见 **`11_behavior.onnx详细设计.md`**）。 |
| **P1** | **宿主：systemd 运行单元 → PID**（可选） | 近似 Windows **规则 3**；与 `pmfe_host_policy_linux.c` 组合策略。 |
| **P1** | **可观测性** | `vm_read` **errno 分桶**或 **`pid_history` 增加 `vm_read_failures`**：注意 detail 长度与下游解析。 |
| **P2** | **工程** | Linux **CI 全量编译**（含 `collector_linux` + netlink 头）、**集成测试**（需 Linux Runner）。 |
| **P2** | **运维说明** | **`EDR_LINUX_PROC_CONNECTOR`**、Yama **`ptrace_scope`**、内核头依赖：可写在 `docs/` 或运维手册，**不**强制写入安装器主流程（`AGENT_INSTALLER.md` 以注册为主）。 |

**历史说明：** 原 §3「建议实施顺序」中 **宿主监听表 / module_integrity / 匿名段 / 预处理 / vm_read_failures 基线** 等已在代码中落地；上表仅保留 **后续仍可做的增量**。

---

## 4. 主要代码索引

| 路径 | 说明 |
|------|------|
| `edr-agent/src/pmfe/pmfe_engine.c` | Linux：`pmfe_scan_linux`；Windows：`pmfe_scan_windows`。 |
| `edr-agent/src/pmfe/pmfe_host_policy_win.c` | Windows 监听表 + `edr_pmfe_compute_priority`。 |
| `edr-agent/src/pmfe/pmfe_host_policy_stub.c` | 非 Windows、非 Linux 占位优先级。 |
| `edr-agent/src/pmfe/pmfe_host_policy_linux.c` | Linux 监听表 + `edr_pmfe_compute_priority`。 |
| `edr-agent/src/pmfe/pmfe_linux_scan_util.c` | Linux maps 解析与候选打分（可测）。 |
| `edr-agent/src/pmfe/pmfe_etw_preprocess.c` | Windows：shellcode；Linux：webshell 自动入队（`EDR_PMFE_ETW_AUTO`）。 |
| `edr-agent/src/pmfe/pid_history_pmfe.c` | `pmfe_snapshot` JSON 与 ingest。 |
| `edr-agent/include/edr/pmfe.h` | 对外 API 与环境变量说明。 |

---

## 5. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-04-18 | 初稿：从当前实现与设计对照整理 Linux backlog，Windows 为交付重点。 |
| 2026-04-18 | 补充：预处理进程事件 → PMFE hint；可选 **`EDR_LINUX_PROC_CONNECTOR`**（collector）。 |
| 2026-04-18 | **优先 Windows**：重写 **§3** 为「Linux 需求留存」；**§2** 改为与 Windows 对比的事实描述；旧排期表作废。 |
