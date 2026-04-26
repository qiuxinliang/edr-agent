# 客户端 AVEngine（AI 引擎）实施计划

本文档对照《09_AVEngine开发需求文档.md》（EDR-DEV-AVE-001 v1.0）与当前 `edr-agent` 实现，说明**差距**、**分阶段交付**与 **已落地范围**。

**behavior.onnx 专项（设计 § 全量、里程碑、服务端对照）**：见同目录 **`BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`**（与《Cauld Design/11_behavior.onnx详细设计.md》双向引用）。

## 1. 需求摘要（来自 09 文档）

- **交付形态**：独立 `AVEngine.dll` / `libavengine.so`，对外单一 C 头文件 `ave_sdk.h`（与仓库中 `include/edr/ave_sdk.h` 对齐），导出 `AVE_*` 生命周期、扫描、行为、热更新等接口。
- **子系统**：静态 ONNX（EMBER+PCA）、行为 ONNX + PidHistory、四层误报抑制（签名 → 白名单 → IOC → 不可豁免行为）、证书白名单（WinVerifyTrust + DB + 热更新）、YARA、联邦学习、热修复/模型更新。
- **不在本文档范围**（09 文档说明）：WinDivert webshell 目录、PMFE VAD、服务端 L2/L3、gRPC（另项）。

## 2. 当前代码基线

| 能力 | 现状 |
|------|------|
| 模型目录扫描、**首个非 `behavior.onnx` 的 `.onnx`**（静态）+ 可选 **`behavior.onnx`**、ONNX Runtime | `src/ave/ave_engine.c`、`src/ave/ave_onnx_infer.c`（共享 `OrtEnv`） |
| Agent 配置 | `EdrConfig.ave`（`model_dir`、`scan_threads`、`max_file_size_mb`、证书与抑制库路径等） |
| 对外 SDK | `include/edr/ave_sdk.h` + `src/ave/ave_sdk.c`：`AVE_Init` / `AVE_InitFromEdrConfig`、`AVE_ScanFile`、`AVEScanResult`（`raw_*` / `final_*`、`verification_layer`） |
| **L1** 证书签名 Stage0（Windows） | `src/ave/ave_sign_whitelist_win.c`：见第 7 节 |
| **L2** 文件哈希白名单、**L3** 文件 IOC | `src/ave/ave_suppression.c`：SQLite 表 `file_hash_whitelist`、`ioc_file_hash`；需 **`EDR_HAVE_SQLITE`** 且配置非空路径 |
| **L3 后检** | ONNX 成功后再次查询 `ioc_file_hash`；命中则 **`edr_ave_overlay_ioc_post_ai`**（`rule_name=ioc_file_hash_post`），**保留** `raw_ai_*` |
| **L4** 不可豁免哈希 | 表 **`file_behavior_non_exempt`**（库路径 **`behavior_policy_db_path`**）；在 ONNX **之后**应用，设置 `sig_behavior_override` / `needs_l2_review`，并按 `escalate` 抬升 `final_*`（若已为 `VERDICT_IOC_CONFIRMED` 则不改 verdict，仅可带行为标志） |
| **规则元数据** | `src/ave/ave_rules_meta.c`：表 **`ave_db_meta`**（键 **`rules_version`** 等）；**`AVE_GetStatus`** 填充 `ioc_rules_version`、白名单/证书库版本字符串、`ioc_entry_count` |
| **单元测试** | `tests/test_ave_suppression.c`（IOC/L4/meta）、`tests/test_ave_pipeline.c`（`ioc_precheck_enabled=false` + 后检 IOC） |

## 3. 差距分析

1. **四层抑制**：L1–L4 已在 `AVE_ScanFile` 内落地；**L4** 含文件哈希库 **`file_behavior_non_exempt`**；**实时行为联动**：`AVE_ScanFileWithSubject` + `[ave] l4_realtime_behavior_link` + 行为异常分阈值（与 `AVE_GetProcessAnomalyScore` 同源）。**吊销**：`cert_revocation_check` / `EDR_AVE_CERT_REVOCATION=1` 时 `WinVerifyTrust` 使用 `WTD_REVOKE_WHOLECHAIN`。
2. **IOC / 白名单形态**：当前为**端上本地 SQLite**；**平台热更新**通过替换库文件 + TOML 路径（及既有 **`EDR_REMOTE_CONFIG_URL`** 拉取配置）完成；**`ave_db_meta.rules_version`** 供观测与对齐。
3. **行为与 PidHistory**：`AVE_FeedEvent`、**Vyukov MPMC**（无 C11 原子时 Win32 临界区 / pthread 环）、监控线程与 PID 槽位已在 `ave_behavior_pipeline.c` / `ave_lf_mpmc.c` 落地；**`model_dir/behavior.onnx`** 就绪时工作线程用 **ONNX 特征向量**替代启发式 bump；Windows ETW 在 `collector_win.c` 经 **`edr_ave_etw_feed_from_event`** 调用 **`AVE_FeedEvent`** / **`AVE_NotifyProcessExit`**（可用 **`EDR_AVE_ETW_FEED=0`** 关闭）。与 PMFE **`pid_history`** 仍为并行演进（字段对齐 **`AVEBehaviorEvent`** / **`EdrEventType`**）。
4. **证书吊销 / 多内置根**：Stage0 仍为 `WTD_REVOKE_NONE` 等策略；扩展根与吊销策略见 `08_签名白名单机制设计.md` 后续迭代。
5. **独立 DLL/SO、热修复、联邦学习**：仍按第 4 节阶段推进。

## 4. 分阶段路线

| 阶段 | 目标 | 说明 |
|------|------|------|
| **P0 / Phase 1** | `ave_sdk.h` + `ave_sdk.c`：生命周期、`AVE_GetVersion`/`AVE_GetStatus`、`AVE_ScanFile` → 经 L1–L3 后调用 `edr_ave_infer_file`，填充 `AVEScanResult` | **已落地** |
| **P1（进行中）** | 四层抑制：**L2/L3** SQLite 闭环；字段与 `verification_layer` 一致；**L4** 行为层 | 本文档第 2、7 节 |
| **P2** | 行为：MPMC + 单线程消费 + PID 状态；**behavior.onnx** + ETW 注入 | **已接线**（见 `ave_behavior_pipeline.c`、`ave_etw_feed_win.c`） |
| **P3** | 热修复 `AVE_ApplyHotfix`、`AVE_UpdateModel`、公钥验签 | 与平台下发协议对齐 |
| **P4** | 独立 DLL/SO 打包、ABI 与版本策略、与 Agent 主进程集成方式 | 构建与安装器 |

## 5. Phase 1 行为约定

- **`AVE_Init`**：内部 `edr_config_load(NULL, cfg)` 应用默认配置，再写入 `model_dir`、`scan_threads` 等；可将 `AVEConfig.whitelist_db_path` / `ioc_db_path` 映射到 `EdrConfig.ave.file_whitelist_db_path` / `ioc_db_path`。调用 `edr_ave_init`，并**拥有**内部 `EdrConfig`（`AVE_Shutdown` 时 `edr_config_free_heap`）。
- **`AVE_InitFromEdrConfig`**：`edr_agent_init` 在 TOML 已加载后调用，传入 **`&agent->cfg`**；`[ave] file_whitelist_db_path` / `ioc_db_path` 由 TOML 提供。`AVE_Shutdown` 仅 `edr_ave_shutdown()`，**不释放** Agent 的 `EdrConfig`。与 `AVE_Init` **二选一**。
- **SOAR `ave_infer` / PMFE（`EDR_PMFE_AVE_TEMPFILE`）/ Webshell 扫描**：均已走 **`AVE_ScanFile`**（与 **`AVE_InitFromEdrConfig`** 同一 ONNX 会话；PMFE/Webshell 侧取 **`final_confidence`** 等参与原有加权/摘要）。底层实现仍见 `edr_ave_infer_file`（仅 `ave_sdk.c` 内部）。
- **`AVE_ScanFile`**：在 L1–L3 任一层决定 **跳过 ONNX** 时，`final_verdict` / `verification_layer` 由该层填充；否则映射 `edr_ave_infer_file` 结果；`raw_confidence` 对非 \([0,1]\) 的 logit 做简单 sigmoid 映射（校准与 softmax 属 P1+）。
- **未实现接口**：**`AVE_ScanFileAsync` / `AVE_ScanMemory` / `AVE_CancelScan`** 仍为占位。`AVE_UpdateWhitelist` / `AVE_UpdateIOC`：最小 SQLite `INSERT OR REPLACE`（见 `src/ave/ave_db_update.c`，JSON 字符串数组或裸 64hex 列表）。`AVE_StartBehaviorMonitor`：在 **`[ave] behavior_monitor_enabled=true`** 且已注册 `on_behavior_alert` 时拉起消费线程（见 §7.5）。

## 6. 版本号

- 头文件 `AVE_SDK_VERSION_*` 与 `AVE_GetVersion()` 须一致（当前 **2.5.0**）。实现演进时同步递增 **Patch**。
- ONNX 目标接口与现状见 **`docs/AVE_ONNX_CONTRACT.md`**；研发顺序见 **`docs/AVE_RD_ROADMAP.md`**。

## 7. 扫描管线与 §08 签名白名单（Stage0）

### 7.1 `AVE_ScanFile` 顺序（摘要）

1. **L1（Windows，证书）**：`enable_cert_whitelist` / `[ave] cert_whitelist_enabled` 时调用 `edr_ave_sign_stage0`。  
   - 叶子证书 SHA256、`WinVerifyTrust`（无吊销轮询）、可选 **`cert_whitelist_db_path`** 上 **`sign_blacklist`** / **`sign_whitelist`** / **`sign_cache`**（见 Windows 实现）。  
   - **`sign_blacklist`** 命中：不跳过 ONNX，对 ONNX 输出置信度 **+0.30**（`onnx_boost`）。  
   - **内置链 / SQL 白名单 / 厂商启发式** 等通过 `WinVerifyTrust` 后可 **`VERDICT_TRUSTED_CERT`**，`verification_layer=L1`，**跳过 ONNX**。
2. **L3（文件 IOC，预检）**：当 **`ioc_precheck_enabled=true`**（默认）且 **`ioc_db_path`** 中 **`ioc_file_hash`** 命中 → **`VERDICT_IOC_CONFIRMED`**，`verification_layer=L3`，**跳过 ONNX**。  
   - 设为 **`ioc_precheck_enabled=false`** 时**不**在此阶段拦截，以便**始终先跑 ONNX**（例如与模型并行部署或仅依赖后检）。
   - **与 L2 同哈希冲突时**：端上 **先 IOC 预检再 L2 白名单**，避免误放行。
3. **L2（文件哈希白名单）**：若 **`file_whitelist_db_path`** / **`file_hash_whitelist`** 命中 → **`VERDICT_WHITELISTED`**，`verification_layer=L2`，**跳过 ONNX**。
4. **AI**：否则 **ONNX**；`verification_layer=AI`；L1 **`onnx_boost`** 在 AI 结果上加分。
5. **L3（后检）**：再次查询 **`ioc_file_hash`**；命中则 **`ioc_file_hash_post`**，**仅改** `final_*` / `verification_layer` / `rule_name`，**保留** ONNX 写入的 **`raw_ai_*`**。
6. **L4**：查询 **`behavior_policy_db_path`** / **`file_behavior_non_exempt`**；命中则 `verification_layer=L4`，`rule_name=behavior_non_exempt`，并置 **`sig_behavior_override`**；若 **`final_verdict`** 已为 **`VERDICT_IOC_CONFIRMED`** 则**不覆盖** IOC 结论。

**非 Windows**：`ave_sign_whitelist_stub.c` 无 L1 证书逻辑；L2–L4 仍可用（SQLite + 路径配置）。

### 7.2 SQLite 表（P1 最小）

| 表名 | 用途 | 主要列 |
|------|------|--------|
| `file_hash_whitelist` | L2 | `sha256` TEXT（64 字符小写十六进制，与 Agent 计算一致）、`is_active` INTEGER 默认 1 |
| `ioc_file_hash` | L3 | `sha256` TEXT、`is_active` INTEGER 默认 1、可选 `severity` INTEGER 1–3（默认 3） |
| `file_behavior_non_exempt` | L4 | `sha256` TEXT、`is_active` INTEGER 默认 1、`escalate` INTEGER 默认 1（1=按恶意抬升，0=至少可疑带） |
| `ave_db_meta` | 版本观测 | `key` TEXT PK、`value` TEXT；推荐写入 **`rules_version`**（与平台包版本对齐） |

证书相关表（`sign_blacklist`、`sign_whitelist`、`sign_cache` 等）见 **`08_签名白名单机制设计.md`** 与 Windows 源码注释。

### 7.3 平台热更新与 DB 版本（当前约定）

- **热更新**：将新 SQLite 文件下发到可写目录，更新 **`edr.toml`** 中 `[ave]` 各 `*_db_path`（或通过 **`EDR_REMOTE_CONFIG_URL`** 拉取的新 TOML），**重启 Agent** 或依赖配置热载路径使进程重新打开库文件（本实现每次查询 **open/read/close**，同路径替换文件后**下一轮扫描**即见新数据）。
- **版本**：在各库中维护 **`ave_db_meta`**；**`AVE_GetStatus`** 读取 IOC / 文件白名单 / 证书库上的 **`rules_version`**（及 IOC 行数）。

### 7.4 仍待增强（后续迭代）

- 平台侧 **增量下发**、原子替换与回滚协议。
- **吊销** 联网策略（OCSP/CRL）与性能评估。
- **L4** 与 **`AVE_FeedEvent`** / 进程上下文、行为 ONNX 的联合策略。
- 独立 **`AVEngine.dll`** 与 ABI 冻结（P4）。

### 7.5 P2 行为管线（已实现基线）

- **源码**：`src/ave/ave_behavior_pipeline.c` + `src/ave/ave_lf_mpmc.c` — 有界 MPMC（C11 原子优先）、PID 表仍用互斥；单后台线程消费（约 20ms 空转休眠）；每 PID 槽位累积 `behavior_flags` 与 **`anomaly`**（0–1）。**behavior.onnx** 加载成功时以模型输出（经 sigmoid 映射）替代启发式 **bump**；特征默认与输入维一致（`EDR_AVE_BEH_IN_LEN` 用于动态轴，默认 64）。
- **API**：`AVE_FeedEvent` 在监控线程**已启动**时 **try_push**（满则同步 `process_one_event` 防背压丢语义）；**未启动**时**同步**更新 PID 状态。`AVE_RegisterCallbacks` / `AVE_StartBehaviorMonitor` 约定同前。
- **ETW**：`src/collector/ave_etw_feed_win.c` — `EdrEventType` → `AVEEventType`，进程退出走 **`AVE_NotifyProcessExit`**。
- **`AVE_GetStatus`**：`behavior_event_queue_size` 为 MPMC **近似深度**，与 **`behavior_queue_capacity`**（4096）对照；另含 **`behavior_feed_total`**、**`behavior_queue_enqueued`**、**`behavior_queue_full_sync_fallback`**（队列满同步降级）、**`behavior_feed_sync_bypass`**、**`behavior_worker_dequeued`**、**`behavior_infer_ok` / `behavior_infer_fail`**（`AVE_SDK_VERSION_PATCH` 见 `ave_sdk.h`）。`behavior_model_version` 在行为 ONNX 就绪时为 **`onnx:behavior.onnx`**（短名），否则 **`heuristic_v1`**。

## 8. 相关文档

- `Cauld Design/09_AVEngine开发需求文档.md`
- `Cauld Design/08_签名白名单机制设计.md`（证书与 L1）
- `Cauld Design/static_onnx_设计规范_v1.0.md`（静态 ONNX 特征与任务）
- `docs/AVE_ONNX_CONTRACT.md`（static/behavior ONNX 目标与当前契约）
- `docs/STATIC_ONNX_SPEC_GAP.md`（static 与规范 v1.0 差距）
- `docs/AVE_RD_ROADMAP.md`（研发阶段与第一阶段状态）
