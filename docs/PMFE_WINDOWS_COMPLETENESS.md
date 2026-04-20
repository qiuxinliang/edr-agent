# PMFE Windows 研发完成度（对照设计）

本文档说明 **Windows 端 PMFE**（`edr-agent/src/pmfe/`，主实现 `pmfe_engine.c` + `pmfe_host_policy_win.c`）相对 **`Cauld Design/07_进程内存取证引擎PMFE设计.md`** 的落地程度，供评审与排期。

**验收优先级：** **Windows 为设计与交付主平台**；Linux 能力见 **`PMFE_LINUX_BACKLOG.md`**（需求留存，不阻塞 Windows 验收）。

---

## 0. 进度检查（优先 Windows）

| 维度 | 状态 | 说明 |
|------|------|------|
| **核心闭环** | **已贯通** | 监听表 + 服务 PID 表 + 宿主优先级 → 队列 → 模块基线 / VAD / peek / DNS / 可选 AVE → 详情与 `pid_history` / 可选上报。 |
| **设计 §2.2.4** | **已落地** | 含 **规则 3**（`EDR_PMFE_SERVICE_PRIORITY=0` 可关）、**`edr_pmfe_submit_etw_scan_ex`**、**VAD hint ±64MB**、预处理 **`va=`/`hint=`**。 |
| **与设计仍有差距** | **见下 §2** | **PE 重建 + MinIO**、采集侧默认 **`va=`**、宿主策略 **E2E 单测** 等 — 多为跨模块或环境依赖，**不视为 PMFE 核心阻塞**。 |
| **轻量回归** | **具备** | **`test_pmfe_detail`**（详情串 token）；完整 SCM/监听联调需 Windows 环境或集成测试。 |

**结论（摘要）：** 核心链路 **「监听表 → 宿主档位 → 任务队列 → 模块基线 + VAD 粗筛 + 高分区 peek + 可选 DNS + 可选 AVE 落盘扫描 + 摘要/事件」** 已贯通；**§2.2.4 规则 3（服务 + 监听）**、**ETW 档位 / VAD hint 精扫** 已在代码中补齐。**PE 重建 + MinIO 上传** 仍属独立产品链路，不在 `pmfe` 单模块闭环。

---

## 1. 已较完整实现（与设计意图一致）

| 设计/能力 | 实现位置 | 说明 |
|-----------|----------|------|
| 双扫描线程 + 任务队列 | `pmfe_engine.c` | `PMFE_NUM_WORKERS`、`PMFE_TASK_CAP`，`edr_pmfe_init` / `shutdown`。 |
| 监听进程表（与 §19 同源） | `pmfe_host_policy_win.c` + `listen_table_win.c` | `edr_win_listen_collect_rows` 聚合 TCP/UDP；**截断**时 stderr 告警，可用 **`EDR_PMFE_LISTEN_TRUNC_QUIET=1`** 关闭。 |
| **Win32 服务 PID 表** | `pmfe_host_policy_win.c` | 与监听表**同周期刷新**：`EnumServicesStatusExW`（`SC_ENUM_PROCESS_INFO`）收集 **SERVICE_RUNNING** 的 PID，排序去重；**`EDR_PMFE_SERVICE_PRIORITY=0`** 关闭规则 3。 |
| 宿主优先级 §2.2.4 | `pmfe_host_policy_win.c` | 规则 1–2、**规则 3（服务 + 监听 → HIGH）**、0.0.0.0→MED、仅回环→LOW、关键进程名补集等。 |
| 定时 + 生命周期去抖刷新 | `pmfe_engine.c` | 约 **60s** 周期刷新；**`edr_pmfe_on_process_lifecycle_hint`** 约 **1s** 后刷新；**`EDR_PMFE_LISTEN_REFRESH_ON_PROCESS=0`** 可关。 |
| 服务端扫描 / ETW 入队 | `pmfe_engine.c` | **`edr_pmfe_submit_server_scan`**（`force_deep`）；**`edr_pmfe_submit_etw_scan`** / **`edr_pmfe_submit_etw_scan_ex`**（冷却 **`EDR_PMFE_ETW_COOLDOWN_MS`**）。 |
| **`band` + `vad_hint`** | `pmfe_engine.c`、`pmfe.h` | **`EdrPmfeTask.vad_hint_va`**：`full_vad=0` 时仅保留 **hint±64MB** 窗口内 VAD 候选，空池则 **VirtualQuery** hint 单区兜底；详情含 **`vad_hint=`**。 |
| `ScanScope` / `pmfe_task_fill_scope` | `pmfe_engine.c` | 按 **`EdrPmfeScanPriority`** + **`EdrPmfeTriggerBand`** 设置 **`full_vad`、`module_integrity`、`dns_path`、`peek_cap`**。 |
| 模块基线 + stomp + 磁盘哈希 | `pmfe_engine.c`（`#ifdef _WIN32`） | **`EnumProcessModulesEx`** + **`ReadProcessMemory`** 与磁盘前缀对比；**`EDR_PMFE_STOMP_BYTES`**、**`EDR_PMFE_DISK_HASH_MAX`**。 |
| VAD 粗筛统计 | `pmfe_coarse_vad_windows_handle` | **`VirtualQueryEx`**，输出 regions / private_exec 等。 |
| VAD 深扫 | `pmfe_win_vad_deep_scan` | 候选池打分、**`full_vad`** 控制池大小与步数上限；**`EDR_PMFE_VAD_PEEK`** 可上限 peek 数。 |
| Peek：MZ、熵 | 同上 | 首段读取；**`mz_hits`、`ent_max`**。 |
| 可选 AVE | 同上 | **`EDR_PMFE_AVE_TEMPFILE=1`** 且已 **`edr_pmfe_bind_config`** 时对 MZ 区落盘并 **`AVE_ScanFile`**（最多 3 次）；**`ave_max_score`**。 |
| DNS 路径（ASCII/UTF-16/Wire） | 同上 + `pmfe_dns_region_scan` | 模块区间反查 **`dns_owner`**；**`EDR_PMFE_DNS_*`** 系列。 |
| 扫描详情与下游 | `pmfe_engine.c`、`pid_history_pmfe.c` | **`stomp_suspicious`、`mz_hits`**、DNS 字段；**`open_process=failed err=`**；**`EDR_PMFE_PID_HISTORY`**；**`EDR_PMFE_EMIT_*`**。 |
| 预处理自动入队（ETW） | `pmfe_etw_preprocess.c` | **`EDR_PMFE_ETW_AUTO=1`** 且 **`EDR_EVENT_PROTOCOL_SHELLCODE`**；**`edr_pmfe_submit_etw_scan_ex`**：`slot.priority==0`→**P0** 否则 **P1**；ETW1 可选 **`va=` / `hint=`**（十六进制）→ **VAD hint**。 |
| 轻量测试 | `tests/test_pmfe_detail.c` | 详情串 token 存在性（CMake **`pmfe_scan_detail_format`**）。 |

---

## 2. 仍不在本模块范围或未单独落地

| 项 | 说明 |
|----|------|
| **PE 重建 + MinIO 上传** | 设计第 5 章等长链路；PMFE 仍为 **peek + 可选 tempfile + AVE**；与 Webshell/平台上传的衔接见其它模块。 |
| **监听表条目内 `is_windows_service` 布尔** | 规则 3 已用 **全局服务 PID 表**实现；聚合结构未再冗余该字段。 |
| **WinDivert 等采集侧默认写入 `va=`** | 预处理已解析；采集器可在 ETW1 中增加 **`va=`** 以触发 hint（当前 WinDivert 载荷以网络证据为主，未强绑远端进程 VA）。 |
| **端到端 PMFE 宿主策略单测（需 Windows API）** | 现有 **`test_pmfe_detail`** 为纯字符串；完整 SCM/监听联调依赖环境或集成测试。 |

---

## 3. 运维与依赖（避免「代码已写但未生效」）

- **`EDR_PMFE_DISABLED=1`**：跳过初始化（无扫描线程）。
- **AVE 探针**：**`EDR_PMFE_AVE_TEMPFILE=1`** 且 **`edr_pmfe_bind_config`** 已设置（`s_pmfe_cfg` 非空），否则不走落盘扫描分支。
- **`AVE_ScanFile`** 需进程内 **AVE 已初始化**（通常 **`AVE_InitFromEdrConfig`**，见 `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`）。
- **`EDR_PMFE_ETW_AUTO`**：仅影响 **Shellcode 协议事件** 自动入队，不覆盖所有 ETW 类型。

---

## 4. 与 Linux 文档的关系

- **Linux 后续需求（留存，不阻塞 Windows）**：**`PMFE_LINUX_BACKLOG.md`** §3。
- **Windows 为设计主平台**；跨平台共享的 **pid_history JSON、`EDR_PMFE_EMIT_*` 语义** 以头文件与两份文档为准。

---

## 5. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-04-18 | 初稿：基于当前代码与《07》对照整理 Windows 完成度。 |
| 2026-04-18 | 补充：服务 PID 规则 3、`edr_pmfe_submit_etw_scan_ex`、VAD hint 窗口、`test_pmfe_detail`。 |
| 2026-04-18 | 增加 **§0 进度检查**；明确 **优先 Windows** 与 Linux 文档分工。 |
