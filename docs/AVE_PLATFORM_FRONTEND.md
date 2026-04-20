# AVE 与平台（服务端）· 控制台（前端）

本文说明 **AVE 在终端之外** 的协作边界：管控如何下发与回收结果，控制台如何呈现；**实现以各仓库为准**，此处为架构级约定与联调入口。

---

## 1. 终端侧已冻结的对外语义

- **进程内 API**：`include/edr/ave_sdk.h`（`AVE_ScanFile`、`AVE_GetStatus`、`AVE_ApplyHotfix` 等）。
- **远端指令**：经 **gRPC `Subscribe` → `CommandEnvelope`** 到达 Agent，由 **`command_stub.c`** 解析 `command_type` 并调用 `edr_ave_*` / `AVE_*`。**字段与 payload** 见 **`docs/SOAR_CONTRACT.md`**（AVE 小节：`ave_status`、`ave_fingerprint`、`ave_infer`；PMFE 可选联动 **`AVE_ScanFile`**）。
- **结果回传**：**`ReportCommandResult`**，`detail_utf8` 携带短说明（如 `ave_infer` 的 `final=... sha256=...`）。编排联调见 **`SOAR_CONTRACT` §3**（`EDR_SOAR_REPORT_ALWAYS` 等）。

---

## 2. 仓库实现核查（edr-backend / edr-frontend）

以下为 **本工作区当前代码** 与 **§1 终端契约** 的对照，用于排查「AVE 数据是否已在服务端落库、并在控制台展示」。

### 2.1 服务端（`edr-backend/platform`）

| 路径 | 结论 |
|------|------|
| **`internal/edrpb/ingestv1/.../ingest_grpc.pb.go`** | 含 **`EventIngest` / `ReportCommandResult`** 的 **gRPC 生成代码**（客户端与服务端接口）。 |
| **`EventIngest` 服务端实现** | 在本仓库 **未检索到** `RegisterEventIngestServer` 的 **业务实现**；ingest 若由独立进程/网关承载，需在该组件内 **接收 `ReportCommandResult`** 并落库或转发。 |
| **`GET /endpoints/:id/response-tasks`**（`internal/handler/endpoints.go`） | **已扩展**：内存占位（取证 / 杀进程）与表 **`endpoint_command_results`**（ingest 落库，含 **`ave_status` 结构化列**）合并返回。落库与 proto 差异见 **`edr-backend/platform/docs/COMMAND_RESULTS.md`**。 |
| **联邦学习 / 模型运维**（如 `fl_rounds`、`model_versions`） | **`base_model_version` / `derived_model_version`** 等字段属于 **FL 聚合与模型版本表**，与终端 **`AVE_GetStatus` → `static_model_version` / `behavior_model_version`** **不是同一条数据链**。 |

### 2.2 前端（`edr-frontend`）

| 路径 | 结论 |
|------|------|
| **`api/endpoints.ts` → `EndpointResponseTask`** | `action` 以 **`forensic` / `terminate_process`** 为主；**无**专用 `ave_infer` / `ave_status` 类型定义（`string` 可透传但未在 UI 约定）。 |
| **`EndpointResponseTaskListCard`** | 文案与字段展示面向 **取证 / 杀进程**；**未**解析 `detail_utf8` 中的 AVE 扫描结论。 |
| **管理端 `ModelManagement` / `FederatedSection`** | 展示 **FL 轮次**的 `base_model_version` / `derived_model_version`，**不是**终端侧 ONNX 热更版本串。 |
| **`api/behaviorServer.ts` → `POST .../behavior-server/infer`** | **平台代理上游行为推理**（运维/联调），与 Agent 本机 **`AVE_ScanFile` / `ave_infer` 指令** 是 **不同入口**。 |
| **告警详情 `AlertAiInsightSection` 等** | 通用 **L2 AI 分析**展示；**未**与 **`ave_infer` 回包** 做专门字段绑定（除非后端在告警 payload 中自行写入）。 |

### 2.3 小结：缺口与建议

- **缺口**：终端 **`ReportCommandResult(detail_utf8)`** 中的 AVE 结果 **→** 平台 **REST/DB** **→** 控制台 **可检索 UI**，在本 monorepo **尚未闭合**。  
- **建议**：在 **ingest 实现侧** 持久化 `command_type` + `detail_utf8`（或结构化 JSON），并扩展 **`response-tasks` 或新资源**（如 `command-results`）供 **`edr-frontend`** 列表与详情展示；终端 **`AVE_GetStatus`** 若需列表「模型版本」列，需 **库存 API** 或 **周期性事件** 上报，与 **§3–§4** 目标态一致。

---

## 3. 服务端（edr-backend / 管控）开发要点（目标态）

| 主题 | 说明 |
|------|------|
| **指令下发** | 对指定 `endpoint_id` 构造 **`command_type`**（如 `ave_status` / `ave_infer`）与 **UTF-8 JSON `payload`**（`ave_infer` 需 `{"path":"/abs/path"}`），经与 **`ingest.proto`** 一致的 **`CommandEnvelope`** 写入 **`Subscribe`** 流。 |
| **结果消费** | 持久化或透传 **`ReportCommandResult`**，按 **`command_id`** 与 SOAR 元数据（`soar_correlation_id` / `playbook_run_id`）闭合 playbook / 工单。 |
| **模型与发布** | 训练产物布局见仓库根 **`model/README.md`**；**平台负责**将 release 产物同步到终端可访问路径（或下发裸 ONNX），**不在本文重复** P4 打包语义（见 **`docs/AVE_PACKAGING_P4.md`**）。 |
| **可选增强** | 周期性或在 heartbeat/库存扩展中上报 **`AVE_GetStatus`** 风格字段（如 `static_model_version` / `behavior_model_version`）需 **ingest / 库存 API** 与前端列对齐；当前以 **指令 `ave_status`**（`edr_ave_get_scan_counts` 摘要）为基线联调路径。 |

---

## 4. 前端（控制台）开发要点（目标态）

| 主题 | 说明 |
|------|------|
| **指令入口** | 在终端详情 / 响应动作中提供「下发 SOAR 指令」能力时，**`command_type` 与 JSON payload** 必须与 **`SOAR_CONTRACT`** 一致；高危策略（`EDR_CMD_ENABLED` 等）以产品安全策略为准。 |
| **`ave_infer` 展示** | 成功时解析或展示 **`detail_utf8`** 中的 `final=`、`sha256=`、`dur_ms=` 等（具体格式以 `command_stub.c` / SDK 实现为准）；失败时展示 **`exit_code`** 与 **`detail_utf8`**，便于区分 **NOT_IMPL**（未接 ONNX / dry-run 策略）与路径错误。 |
| **`ave_status` 展示** | 将 **`model_files` / `non_dir_files` / `ready`** 类摘要以只读面板展示即可（来源为指令回包 `detail`）。 |
| **设计稿交叉引用** | 终端列表「模型版本」等列为 **产品化展示** 目标，需与 **库存 / 上报字段** 一致；参见 **`Cauld Design/EDR_前端详细设计_v1.0.md`** 中与终端详情、批量操作、狩猎相关的章节，随 **edr-backend** 接口落地迭代。 |

---

## 5. 联调验证（终端仓库）

在 **`edr-agent`** 配置 **`-DEDR_WITH_ONNXRUNTIME=ON`** 并完成构建后：

```bash
ctest -R 'ave_' --output-on-failure
```

应包含 **`ave_e2e_full_smoke`**、**`ave_hotfix_smoke`**、集成与单元测试等（以 **`CMakeLists.txt`** 中 `add_test(NAME ave_* ...)` 为准）。全流程脚本见 **`docs/AVE_COMPLETENESS_TASKS.md`** §5。

---

*文档随平台 API 与控制台实现增量更新；契约变更请先改 **`SOAR_CONTRACT`** 再同步本节。*
