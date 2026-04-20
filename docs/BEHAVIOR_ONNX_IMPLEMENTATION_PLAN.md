# behavior.onnx 功能落地与文档对照（仓库跟踪）

> **设计权威**：《Cauld Design/11_behavior.onnx详细设计.md》（EDR-DEV-BEHAVIOR-001 v1.0）  
> **联邦学习**：行为侧联邦导出默认维数与 §6.1 **CLS（256 维）** 一致，见 `include/edr/ave_sdk.h` 中 `AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT`、`docs/FL_SAMPLES_SCHEMA.md`。  
> **本文作用**：把设计章节映射到 **edr-agent / edr-backend / edr-frontend** 路径，标 **已具备 / 缺口 / 待对齐**，便于分客户端与服务端迭代。  
> **详细任务清单（跨仓库、可勾选）**：**`edr-agent/docs/DETAILED_TASK_CHECKLIST.md`**（含 AG/PL/FE/REL 编号与粗估）。

### I3 行为闭环 — 设计 ↔ Proto ↔ 代码（文档入口）

| 文档 | 对应任务 |
|------|-----------|
| **`BEHAVIOR_PROTO_DESIGN_MAPPING.md`** | DOC-001 |
| **`BEHAVIOR_DIM_BCD_AUDIT_AG012.md`** | AG-012（B/C/D 8–43 审计表） |
| **`BEHAVIOR_GATES_AG013.md`** | AG-013（§7 宏与 `bp_infer_immediate`） |
| **`BEHAVIOR_E_GROUP_FEED_AG020.md`** | AG-020（`AVE_FeedEvent` → E 组） |

---

## 0. 交付顺序（已锁定）

**原则：先 Proto + 平台 API，再端侧闭环。** 契约与路由稳定后，Agent 再填字段、接 `on_behavior_alert` → gRPC，避免双端反复改二进制与批次格式。

### 阶段 A — Proto + 平台 API（优先）

| # | 交付项 | 说明 |
|---|--------|------|
| A1 | **`edr-agent/proto/edr/v1/event.proto`** | **已完成**：**`BehaviorAlert`** + **`behavior_alert=40`**；**《11》§4.1**：**`AveBehaviorEventFeed`** + **`optional ave_behavior_feed=41`**；nanopb **`event.pb.*`** 手调（本机 **protobuf≥7** 可再跑 **`scripts/regen_event_proto.sh`**）。 |
| A2 | **批次语义文档** | **已完成**：**`edr-backend/docs/BAT1_EVENT_INGEST.md`**；平台 **`README`** 可链到该文。 |
| A3 | **平台 REST** | **已完成**：**`GET /api/v1/endpoints/:id/processes/:pid/events`**（limit≤512）；**`openapi/main.yaml`** 已补路径。 |
| A4 | **ingest → 告警** | **已完成（HTTP）**：**`POST /api/v1/ingest/report-events`**（`payload` Base64 = gRPC 同一段 wire）；解析 **BAT1** 帧 + **`pbwire`** 解码 **`behavior_alert`** → **`endpoint_events` + `alerts`**（**`000020` 迁移**）。**`tactic_probs` / `triggered_tactics`**：`event.proto` 字段 **2** 显式 **`packed=true`**（与 nanopb 默认 packed 一致）；**`pbwire`** 校验 packed 长度、解析侧 **最多 14 维**；ingest **`NormalizeTacticProbs14` + `SanitizeTriggeredTactics`** 再写 **`tactic_probs_json` / `triggered_tactics` / `mitre_ttps`**。**BLZ4** 批次已 **LZ4 block 解压**（`bat1` + `pierrec/lz4/v4`）。**gRPC unary** 可与 `Makefile proto` 同路径生成 `edrv1` 后另挂服务。 |
| A5 | **（可选同迭代）** L2 占位 | 队列 + `needs_l2_review` 状态机可先 **不写 LLM**，仅 **入队/标记**（**`needs_l2_review` 已落库**；占位 Worker 见 **§10 T12**）。 |

**阶段 A 完成标准**：前端或 curl 可调通 **进程历史 API**；mock/合成一条 **带 §12.4 字段** 的告警可在控制台看到；**proto 已合并且 nanopb 已重生成**（若 Agent 仓库为单一 proto 源）。

### 0.1 联调闭环（E2E）与 gRPC 说明（优先 2）

| 步骤 | 动作 | 验收 |
|------|------|------|
| E1 | 平台 DB 含 **`000020`**，起 **`edr-api`** | **`GET /ready`** 200 |
| E2 | **`./edr-backend/scripts/smoke_i1_demo_ready.sh`**（或 **`smoke_behavior_ingest.sh`**；可设 **`API_ROOT`/`BASE`/`EP`/`PID`**） | **`/healthz`**、**`/ready`**；**`POST .../ingest/report-events`** `accepted`；**`GET .../processes/:pid/events`** 非空；**`GET .../alerts`** 含行为列 |
| E3 | 真 Agent：设置 **`EDR_BEHAVIOR_ENCODING=protobuf`**，触发行为告警后 flush | 控制台或 DB 可见 **`tactic_probs_json` / `triggered_tactics`**（与 **A4** 一致） |
| G1 | **gRPC**：本仓库 **platform** 仅实现 **HTTP** **`POST /api/v1/ingest/report-events`**；**`ReportEventsRequest.payload` 与 HTTP `payload`（Base64 解码后）须为同一 BAT1 体**（见 **`edr-backend/docs/BAT1_EVENT_INGEST.md`** §gRPC 与 HTTP）。若生产单独起 gRPC ingest，须 **复用 `bat1` + `pbwire` + `InsertBehavior`**，与 HTTP 行为一致。 |

### 阶段 B — 端侧闭环（随后）

| # | 交付项 | 说明 |
|---|--------|------|
| B1 | **Agent 编码** | **已完成**：`edr_behavior_alert_encode_protobuf` + **`edr_behavior_alert_emit_to_batch`**（`behavior_alert_emit.c`）；`ave_behavior_pipeline.c` 在触发告警时 **先入 EventBatch** 再调用户 **`on_behavior_alert`**；事件类型 **`EDR_EVENT_BEHAVIOR_ONNX_ALERT=70`**。全批次与平台 ingest 一致时请设 **`EDR_BEHAVIOR_ENCODING=protobuf`**（或 **`protobuf_c`**），否则会 stderr 提示与 wire 帧混编。 |
| B2 | **联调** | **已完成（交付物）**：平台 **BAT1 + protobuf ingest**、**BLZ4 解压**、**`GET .../processes/:pid/events`**；工具 **`smoke_behavior_ingest.sh`**、**`edr-ingest-sample`**、**`000020`**。**真机 E2E**（behavior.onnx → 批次上报 → DB/API/可选前端）为环境验收项：按 **`edr-agent/docs/REAL_DEVICE_BEHAVIOR_E2E.md`** 执行与勾选；实验室可用 **`smoke_behavior_ingest.sh`** 仅验证平台链路。 |
| B3 | **E 组 / PMFE / FL** | **B3a** 已完成。**B3b（进行中）**：**`EdrPidHistory`**（`include/edr/pid_history.h`）含 **ppid / ave_static_max_conf / ave_verdict** 与 **128×64 特征序列**；特征 **§5.5 维 44–52**；**`edr_ave_bp_merge_static_scan`** 由 **`AVE_ScanFile*`** 写入静态结论。**IOC**：`ioc_db` 扩展表 **`ioc_ip` / `ioc_domain`**（与 **`ioc_file_hash`** 同库）；**`AVE_FeedEvent`** 内 **`edr_ave_behavior_event_apply_ioc`**；ETW 经 **`edr_tdh_extract_ave_net_fields`** 填 **`target_ip`/`target_domain`** 后 Feed；**`file_sha256_hex`** 供预处理填后走哈希 IOC。**B3c（未开始）**：与《11》**§5.0 M3b** 对齐 — **完整 B/C/D（维 8–43）** 按设计逐维落地 + **§7 触发/阈值门禁** + **§8 训练/导出口径**（与 **T16 golden 扩充**、**§6 性能验收**联动）。**注**：源码中 **`edr_onnx_behavior_export_weights`** 旁注释「联邦 B3c」指 **联邦整包导出 behavior.onnx 字节**（**P3 T10/T11** / **`AVE_ExportModelWeights("behavior")`**），**不是**本表 **B3c**。 |

---

## 1. 设计文档章节 → 仓库映射总表

| 设计 § | 主题 | 客户端（edr-agent / AVEngine） | 服务端（edr-backend platform） | 备注 |
|--------|------|----------------------------------|----------------------------------|------|
| 一、二 | 定位、数据流、输出去向 | `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md` §2–3 已描述行为管线；`src/ave/ave_behavior_pipeline.c` 等 | 告警入库、SOAR 与现有 `alerts` 流水线对齐 | 设计文 §2.2 **L2 LLM** 属平台能力 |
| 三 | `PidHistory` | 实现随 `ave_behavior` / 管线演进；与 `include/edr/pmfe.h` **pid_history** 并行对齐 | 无 | 以 **C 结构体**为单一事实源 |
| 四 | `AVEBehaviorEvent` | ETW：`collector_win.c` → `edr_ave_etw_feed_from_event`；与 `EdrEventType`、`event.proto` 对齐 | — | **`BehaviorEvent.ave_behavior_feed`**（字段 **41**）承载 §4.1 强类型子集；**`EdrBehaviorRecord`→proto** 见 **`behavior_proto.c`**（可继续补全标量） |
| 五 | 64 维特征 | `ave_behavior_pipeline.c` / 编码逻辑 | 无（端侧推理） | **E 组**依赖 static/PMFE/WinDivert 等，可分期 |
| 六–八 | 模型、ONNX I/O、`behavior.onnx` | `src/ave/ave_onnx_infer.c`、`model_dir/behavior.onnx` | 可选 **`behavior_server.onnx`**（§8.1 服务端 batch） | 服务端版 **未强制与端侧同 PR** |
| 七 | 触发与决策、`on_behavior_alert` | 管线 + 回调注册（与 09 / AVE 计划一致） | 接收侧见 §3 | **阈值 0.40 / 0.65** 与 PMFE 优先级与设计一致 |
| 九–十 | 训练、性能、线程安全 | 训练流水线见 `10_联邦学习` 与 FL proto；P99 压测 | FL 聚合、模型下发 | **§9.4** FL 约束与 `proto/edr/v1/fl.proto` 对齐 |
| 十二 | 接口汇总 | **§12.4 gRPC 字段** → 见下文「契约缺口」 | ingest、进程历史 API | **关键联调面** |
| 十三 | 里程碑 M1–M9 | 作为 Agent 侧 WBS 参考 | 平台独立排期 | 工期以人天校准 |

---

## 2. 客户端（edr-agent）

### 2.1 已具备（与 11 文档对齐的基线）

| 项 | 代码 / 文档位置 |
|----|-----------------|
| 静态 + 行为 ONNX 加载、ORT | `src/ave/ave_engine.c`、`src/ave/ave_onnx_infer.c` |
| 行为管线、ETW 注入 `AVE_FeedEvent` | `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md` §3；`ave_behavior_pipeline.c`、`ave_etw_feed_win.c`（见该文档路径） |
| 行为事件 wire / proto | `proto/edr/v1/event.proto` → `BehaviorEvent`；nanopb 生成 `src/proto/edr/v1/event.pb.*` |
| gRPC 上报批次 | `proto/edr/v1/ingest.proto` → `ReportEventsRequest.payload`（**BAT1 批次体**） |

### 2.2 缺口与动作（相对 §12.4）— **阶段 B 执行**

> **阶段 A** 应先完成 **§0 之 A1–A4**；本节为 Agent 侧后续闭环任务。

1. **`AVEBehaviorAlert` 显式字段**  
   - **状态**：**B1 已编码**：`edr_behavior_alert_encode_protobuf` + `behavior_alert_emit.c` → `edr_event_batch_push`。

2. **`on_behavior_alert` → 批次 / gRPC**  
   - **状态**：管线在 **`cb()` 前** `emit_to_batch`；gRPC 仍走既有 flush（`ReportEvents` payload = BAT1）；联调平台 HTTP 时设 **`EDR_BEHAVIOR_ENCODING=protobuf`**。

3. **PMFE / WinDivert / Webshell / Pid 槽 → E 组**（§12.2 / §5.5）  
   - **状态**：**B3a**：跨引擎标量字段 + 特征槽。**B3b**：**`EdrPidHistory`** 跟踪 **ppid**、**128×64 序列** 与 **static 扫描结论**（**`edr_ave_bp_merge_static_scan`**，由 **`AVE_ScanFileWithSubject`** 等触发）；特征维 **48–52** 含 **`ioc_*_hit`**、**51** 父进程静态置信度、**52** 兄弟 **`anomaly` 均值**。**仍待**：各子系统稳定 **`AVE_FeedEvent`** 填 E 组标量；**维 56**（证书吊销祖先）等与设计逐维对齐；**§5.3 维 35（MOTW）** 等 C 组细项。

4. **联邦学习 `AVE_ExportModelWeights`（§9.4 / M8）**  
   - **动作**：与 `proto/edr/v1/fl.proto`、平台 FL 任务对齐；当前 API 见 **`AVE_ExportModelWeights`**（`ave_sdk.c`），**behavior** 目标仍为占位。

---

## 3. 服务端（edr-backend platform）

### 3.1 已具备

| 项 | 位置 |
|----|------|
| gRPC `EventIngest.ReportEvents` 消费 | 需对接实际 **ingest 服务**（若合在单进程则见各模板 handler） |
| 终端事件列表（占位/实现） | `GET /api/v1/endpoints/:id/events` — `internal/handler/endpoints.go` `GetEvents`；`internal/stubs/endpoints.go` 有占位说明 |
| 告警、终端、攻击链等 | `build.go` 挂载的 alerts/endpoints 路由 |

### 3.2 缺口与动作（相对 §12.4）

1. **进程级事件 API**（§12.4，L2 拉历史）  
   - **状态**：**已交付**（**§0 A3**、**§5 表**）。若 L2 需 **>512** 步或额外过滤，在平台侧单独开需求。

2. **ingest 解析（A4）**  
   - **状态**：HTTP **已交付**（**§0 A4**）。**gRPC unary** 若独立部署，须满足 **§0.1 G1** 与 **`BAT1_EVENT_INGEST.md`**。

3. **L2 LLM 复核**（§2.2、§7.3）  
   - **状态**：占位 Worker + 落库见 **§10 T12**；真 LLM 见 **§9 B3 产品项**。

---

## 4. 前端（edr-frontend）

| 项 | 动作 |
|----|------|
| 告警详情展示 **行为分、战术、L2 状态** | `EDR_前端详细设计` 与告警 DTO 对齐；依赖平台 API 字段 |
| 攻击链 / MITRE | 使用 `tactic_probs` / `triggered_tactics` 展示（设计 §6.3 十四战术） |

---

## 5. 与《11_behavior.onnx详细设计》的逐项查验摘要

| 设计章节 | 结论 |
|----------|------|
| §1–2 定位与数据流 | 与 `AVE_ENGINE_IMPLEMENTATION_PLAN`、平台告警流 **无冲突**；L2 为 **服务端**职责。 |
| §3 `PidHistory` | 仓库内 **分散在 AVE/PMFE**，需持续 **字段对齐** 设计 §3.1。 |
| §4 `AVEBehaviorEvent` | **`AveBehaviorEventFeed`** 与 §4.1 表对齐（含 **`optional ave_event_type`**=`AVEEventType`）；**`behavior_proto.c`** 从 **`EdrBehaviorRecord`** 填路径/网络/DNS 与类型映射；**`severity_hint`/熵/GeoIP** 等待预处理写 **`EdrBehaviorRecord`** 或扩展编码。 |
| §5 64 维 | 实现以代码为准；设计为 **规格书**。 |
| §6–8 模型 | 端侧 **`behavior.onnx`**；**`behavior_server.onnx`** 为 **可选** 平台组件。 |
| §7 阈值与回调 | **`edr/ave_behavior_gates.h`**：**`EDR_AVE_BEH_SCORE_MEDIUM_LOW` / `EDR_AVE_BEH_SCORE_HIGH`**（**0.40 / 0.65**）— 命名与《11》**§7.0** 对照表一致；默认推理触发见 **`ave_behavior_pipeline.c`**（§7.1）；**`[ave] l4_realtime_anomaly_threshold`** 默认与 **HIGH** 对齐（`config.h`）。**PMFE** 等仍以各模块为准。 |
| §12.4 gRPC / 告警载荷 | 设计侧 **`AVEBehaviorAlert`** 在实现中映射为 **`edr.v1.BehaviorEvent.behavior_alert`（字段 40）**；HTTP **`POST .../ingest/report-events`** 已解码入库。单独 gRPC 服务须与 **§0.1 G1** 同逻辑。 |
| §12.4 进程历史 API | **已交付**：**`GET /api/v1/endpoints/:id/processes/:pid/events`**（`limit≤512`）；《11》§12.4 中 **`/v1/...`** 为抽象路径，**以 OpenAPI / 本仓库路由为准**。若需 **>512** 或过滤，另开平台需求。 |
| §十三 里程碑 | Agent 侧 **M1–M6** 与仓库 **P2 行为** 已部分重叠；**M7–M9** 仍有效。 |

---

## 6. 性能与容错（后续开发基线）

与《11》**§9**（性能/线程）及端侧资源约束对齐，建议在实现 **C 组全量、序列推理常态开启** 时一并落地；以下为 **验收口径**而非一次性 PR 清单。

| 主题 | 目标 / 做法 |
|------|-------------|
| **热路径分配** | **已落地**：**`s_bp_ort_scratch[8192]`** 在持锁推理路径复用；**`need > 8192`** 时仍 **`malloc`**。 |
| **推理节流** | **已落地**：《11》**§7.1** 为默认：**立即触发**（注入/LSASS/IOC/跨引擎信号/不可豁免 flags 等）或 **步长 16**（连续 **≥3** 次 **[0.40,0.65)** 模型分后步长 **8**）。设置 **`EDR_AVE_BEH_INFER_MIN_EVENTS`** 时走 **legacy**：仅 **`events_since_last_inference >= N`**；特征仍每事件 **append**。 |
| **序列截断** | `EDR_AVE_BEH_SEQ_LEN` 与 **`EDR_PID_HISTORY_MAX_SEQ`**、`refine_behavior_input_dims` 解析结果 **必须一致**；环境变量越界时在 **`ave_onnx_infer.c`** 打日志并 **回退默认 128**。 |
| **ORT 失败** | **已部分落地**：**`s_bp_beh_infer_fail`** + 限频 **stderr**；非 **EDR_OK** 时 **不**重置 **`events_since_last_inference`**、**不**覆盖 **`last_anomaly_score`**；对外 metrics 仍待接。 |
| **队列反压** | `ave_mpmc_try_push` 失败时 **同步降级** `process_one_event` 已在管线中；**可观测**：**`AVE_GetStatus`** 填 **`behavior_queue_enqueued` / `behavior_queue_full_sync_fallback` / `behavior_feed_sync_bypass` / `behavior_worker_dequeued`** 与 **`behavior_event_queue_size` / `behavior_queue_capacity`**；进程退出时 **`edr_agent`** 在 stderr 打 **`[ave/behavior]`** 一行汇总。 |
| **Pid 槽 / GC** | **已部分落地**：**`notify_exit`** 软删除 + **300s** 后 **`pid_find_slot` 回收**；**LRU** 不驱逐已退出未过期槽；**`create_time_ns`** 与 **PROCESS_CREATE** 复用见 P0 T03。 |

---

## 7. C 组（§5.3）契约与训练对齐

**代码事实源**：`src/ave/ave_behavior_features.c` 中 **`encode_c_group`**（维 **24–35**）。当前实现为 **启发式**（路径熵、系统/临时/UNC 目录、扩展名风险、公网 IP、端口/注册表/DNS 等）；**`feat[35]`** 由 **`AVEBehaviorEvent.target_has_motw`** 填写；平台 **`FileDetail.target_has_motw`**（`event.proto`）与 **`EdrBehaviorRecord.file_target_has_motw`** 对齐上报。

| 契约项 | 说明 |
|--------|------|
| **与设计逐维表** | 《11》**§5.3** 表中 **字段名 ↔ 维下标** 为训练与端侧 **唯一契约**；代码中每一处归一化（如 `/16`、`/8`）须在 **`encode_c_group` 上方注释** 或 **本文件** 记一笔，避免「文档一套、训练脚本一套、端上一套」。 |
| **不适用事件填 0** | 与 §5.3 注一致：非路径/非网络/非 DNS 等事件，对应维 **0.0**；门禁可通过 **单元测试向量** 固定若干 `AVEBehaviorEvent` + 期望 `feat[24..35]`。 |
| **训练导出** | 联邦/离线训练管线导出 **64 维步特征**时，须 **同一 `edr_ave_behavior_encode_m3b` 语义**（或 Python 参考实现与 **golden 向量** 对拍）。**§5.6**：真实步 **`feat[57]=is_real_event=1.0`**（`encode_e_group`）；左 PAD 步为 **`memset` 整步 64 维 0**（**`feat[57]=0`**，`ph_build_ort_input`）。**`test_ave_behavior_features_m3b`** 断言真实步与 PAD 零步；**`check_behavior_onnx_contract.sh`** 校验 `feat[57]=1.f` 与 pipeline 内 §5.6 注释。 |
| **扩展字段** | 若 **`AVEBehaviorEvent`** 增加 `target_path_entropy`（预计算）、`target_has_motw`、**GeoIP** 等，须 **先改 SDK 头文件 + 设计 §4 表**，再改 **`encode_c_group`**，最后 **补 golden 测试**。 |

---

## 8. 文实一致验收门禁（CI / 本地）

| 门禁 | 作用 | 位置 |
|------|------|------|
| **头文件常量** | `EDR_PID_HISTORY_MAX_SEQ == 128`、`EDR_PID_HISTORY_FEAT_DIM == 64` 与《11》§6.1 **(1,128,64)** 一致；**`ave_behavior_gates.h`** 与 **§8.1** 形状及 **§7** 阈值/步长；**§5.6** 真实/PAD 维 57 约定（脚本 + 注释） | `scripts/check_behavior_onnx_contract.sh` |
| **编译 + 单测** | `test_ave_behavior_features_m3a/m3b`、`test_ave_behavior_gates`、`test_ave_pipeline`、`test_ave_fl_abi`；启用 ORT 时 **`test_ave_behavior_onnx_integration`** | CMake `add_test` |
| **维 8–43 回归** | **M3b** 任意改动必须 **不静默改变** golden 或容差断言（见《11》§5 **M3b 任务清单** 第 4 点） | `tests/test_ave_behavior_features_m3b.c`（扩展用例） |
| **文档索引** | 本文件 **§0–§5** 与《11》章节映射；**大改特征时** 更新 **§7** 与 **§5 查验表** | 代码评审 checklist |

**本地/CI 一键契约检查（无编译）：**

```bash
./scripts/check_behavior_onnx_contract.sh
```

建议在 **PR 模板** 或 **`.github/workflows`** 中在 **Linux 构建** 后调用上述脚本（`bash` 即可）。

---

## 9. 建议的下一提交

- [x] 本文件：`edr-agent/docs/BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`  
- [x] `Cauld Design/11_behavior.onnx详细设计.md` **关联文档** 指向本文  
- [x] **阶段 A**：A1–A4（见 **§0**）  
- [x] **阶段 B**：B1、B2 交付物（见 **§0**）；B3 分期进行中  
- [x] **B3a / B3b（代码侧）**：见 **§0 B3**、**§10 P0–P3**（E 组/IOC 等仍可按《11》逐维收紧）  
- [ ] **B3c（M3b + §7/§8）**：《11》**§5.0** 全量 **B/C/D（8–43）** + 触发/训练导出口径；与 **T16**、性能验收联动  
- [ ] **B3 产品项（与代码解耦）**：真 **L2 LLM** 替换占位 Worker、**`behavior_server.onnx`** 是否立项（**T14**）— 与产品确认迭代  

---

## 10. 可推进任务单（按优先级）

> **用法**：按 **P0 → P1 → …** 拉迭代；每条含 **验收** 便于关单。路径默认 **`edr-agent/`** 下。

### P0 — 训练 / 契约对齐（与设计 §5 差距最大处）

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T01** | **C 组维 35 `target_has_motw`** | **已完成**：`AVEBehaviorEvent.target_has_motw`（`ave_sdk.h`）；`encode_c_group` 路径事件填 **feat[35]**；**`AVE_SDK_VERSION_PATCH` 3**；**proto §4**：**`AveBehaviorEventFeed`** + **`behavior_proto.c` 填充** | **`test_ave_behavior_features_m3b`**；**`check_behavior_onnx_contract.sh`** |
| **T02** | **E 组维 56 `cert_revoked_ancestor`** | **已完成**：`EdrPidHistory.sticky_cert_revoked_ancestor` + **`edr_ave_bp_merge_static_scan`** 遇 **`VERDICT_CERT_REVOKED`** 置位；**`EdrAveBehaviorFeatExtra.cert_revoked_ancestor`** → **`encode_e_group` feat[56]** | **m3b** 断言；**后续**：独立「祖先链吊销」信号若与主模块判决分离再接线 |
| **T03** | **`create_time_ns` 语义** | **已完成**：新槽 **`create_time_ns`** 取自 **`timestamp_ns`**（有则）否则 **now**；**`fill_pid_snapshot`** 维 21 用 **`now - create_time_ns`**（无则回退 **first_seen**）；**`AVE_EVT_PROCESS_CREATE` 同 PID** 时 **`ph_reset_lifecycle_for_pid_reuse`** | 管线逻辑见 **`ave_behavior_pipeline.c`**；**可选后续**：`pid_find_slot` 按 **(pid, create_time_ns)** 严格去重 |

### P1 — 性能与容错（§6 基线落地）

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T04** | **去掉热路径 per-event `malloc`** | **已完成**：**`s_bp_ort_scratch[8192]`**（`AVE_BP_ORT_NELEM_MAX`）；**`need` 更大时仍 `malloc`** | 契约脚本 **`s_bp_ort_scratch`**；高 `need` 回退路径保留 |
| **T05** | **ORT 推理可观测** | **已完成**：**`s_bp_beh_infer_ok` / `s_bp_beh_infer_fail`**；失败 **每 64 次** `stderr` 一行 | 失败不更新 **`last_anomaly_score`**（与既有语义一致） |
| **T06** | **推理节流（§7）** | **已完成**：默认 **《11》§7.1**（**`bp_infer_immediate`** + **16/8** 步长）；**`EDR_AVE_BEH_INFER_MIN_EVENTS`** 显式设置时 **legacy** 覆盖；阈值宏 **`ave_behavior_gates.h`** | 契约脚本；**`test_ave_behavior_gates`**；回归 **`test_ave_pipeline`** |

### P2 — `PidHistory` 与设计 §3.1 收敛

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T07** | **结构体字段缺口清单** | **已完成**：**`pid_history.h`** 顶部 **§3.1 对照**注释块 | 评审对照《11》§3.1 |
| **T08** | **进程退出与 GC** | **已完成**：**`notify_exit`** 置 **`is_active=0`** + **`exit_ts_ns`**；**`pid_find_slot`** 对 **退出满 300s** 槽 **`memset` 回收**；**`pid_evict_lru`** 跳过非活跃槽 | 与设计 §3.2「保留再 GC」一致；**可选**：可配置 **300s** |
| **T09** | **E 组跨引擎写回** | **已完成**：预处理 **`edr_ave_cross_engine_feed_from_record` → `AVE_FeedEvent`**（`ave_cross_engine_feed.c` / `ave_cross_engine_parse.c`）；从 **`script_snippet`/`cmdline` 的 `score=`** 与 **`pmfe_snapshot` JSON** 填 **`shellcode_score`/`webshell_score`/`pmfe_confidence`/`pmfe_pe_found`**；**`pmfe.h` / `pid_history.h`** 职责边界已注；**`test_ave_cross_engine_parse`** | E 组 46–47、53–54 随跨引擎事件入 `feat_chrono`；`EDR_AVE_CROSS_ENGINE_FEED=0` 可关 |

### P3 — 联邦与静态导出

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T10** | **`AVE_ExportModelWeights("static", …)`** | **已完成**：**`g_static_model_path`** + **`edr_onnx_static_export_weights`**（与 behavior 同文件读字节） | **`test_ave_fl_abi`**：`static` 导出 **OK 或 NOT_IMPL**（无模型路径时） |
| **T11** | **行为 FL 语义澄清 + 张量级导出** | **整包**：**`AVE_ExportModelWeights("behavior")`** → **`edr_onnx_behavior_export_weights`**（磁盘字节）。**张量**：**`AVE_ExportBehaviorFlTrainableTensors`** / **`edr_onnx_behavior_export_fl_trainable_floats`**（解析 **Graph.initializer** FP32，排除名称含 **tactic**/**head_b**；《11》§9.4）。**平台**：**`UploadGradientsRequest.sealed_gradient`** 可与 manifest JSON 分帧约定；勿与整包字节混用。 | **`test_ave_fl_abi`**；**`check_behavior_onnx_contract.sh`** |

### P4 — 平台与产品（非 Agent 独占）

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T12** | **L2 LLM Worker** | **已完成**：**`internal/l2review`** 轮询 **`needs_l2_review=1`**，拉进程历史，写 **`l2_*`**。**占位**：未配 **`EDR_L2_LLM_BASE_URL`** 时仍为摘要 Markdown。**真 LLM**：配置 **`EDR_L2_LLM_*`**（OpenAI 兼容 **`/v1/chat/completions`**）后 **`l2_status=llm_completed`**；见 **`edr-backend/docs/L2_LLM_AND_BEHAVIOR_SERVER.md`** §1。启用 **`EDR_L2_REVIEW_INTERVAL_SEC`**；迁移 **`000021_behavior_l2_review`**。 | 配 LLM 后重启 **`edr-api`**，中危告警得到模型段落而非仅「占位」提示 |
| **T13** | **前端行为告警详情** | **已完成**：**`BehaviorAlertDetailPanel`** + **`alertDetailMap`** / **`AlertDetail`** 对齐 **`anomaly_score` / `tactic_probs` / `triggered_tactics` / `needs_l2_review` / `l2_*` / `behavior_pid`** | 告警详情页展示行为块与 L2 摘要 |
| **T14** | **`behavior_server.onnx`（可选）** | **参考实现**：**`edr-backend/scripts/behavior_server_infer.py`**（`onnxruntime` + **`POST /infer`**，与设计 §8.1 I/O 名一致）；说明见 **`edr-backend/docs/L2_LLM_AND_BEHAVIOR_SERVER.md`** §2。**产品化**（接入 **`edr-api`**、鉴权、队列、模型版本）仍与产品共判 | 本地导出 **`behavior_server.onnx`** 后 `python3 ... --listen` 可对 **`/infer`** 跑通批形状 |

### P5 — 门禁与 golden

| ID | 任务 | 主要改动 | 验收 |
|----|------|----------|------|
| **T15** | **扩展 `check_behavior_onnx_contract.sh`** | **已完成**：**P1/P3/proto** 关键符号 grep（**`EDR_AVE_BEH_INFER_MIN_EVENTS`**、**`s_bp_ort_scratch`**、**`edr_onnx_static_export_weights`**、**`FileDetail.target_has_motw`**） | **`./scripts/check_behavior_onnx_contract.sh`** |
| **T16** | **C/D 组 golden 扩充** | **推进中**：**m3b** 已含 B/D/E57/C35/E56 及 **C25–C34** 路径/注册表/DNS 启发式断言；可按《11》§5.3 继续加边界（如 **C24** 高熵路径数值对拍） | **`tests/test_ave_behavior_features_m3b.c`** + **`scripts/behavior_encode_m3b.py`** `self_test` |
| **T17** | **Python 参考编码器（可选）** | **已完成**：**`scripts/behavior_encode_m3b.py`** — **`encode_m3b(e, ex, snap, n=64)`** 与 **`edr_ave_behavior_encode_m3b`** 同语义；**`python3 scripts/behavior_encode_m3b.py`** 自测对齐 **`test_ave_behavior_features_m3b.c`**；CMake **`ave_behavior_m3b_python_parity`**（有 **`python3`** 时注册） | 训练/离线生成 64 维步特征时与端侧对拍 |

---

*维护：任务关单时在对应 **ID** 旁标注 PR 与日期；每季度回顾 **P0** 是否清空。*
