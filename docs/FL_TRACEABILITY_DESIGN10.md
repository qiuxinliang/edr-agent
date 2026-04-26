# 《10_联邦学习FL组件详细设计》对照表与执行 backlog

**设计来源**：`Cauld Design/10_联邦学习FL组件详细设计.md`（下称《10》）  
**实现分散在**：`edr-agent/`（端侧）、`edr-backend/platform/cmd/fl-coordinator` + `internal/flcoord/`、`edr-backend/platform`（edr-api / model-ops）、`onnxtraining/claude/edr-models/`（训练与 QC 上报）
**端侧载荷与 proto**：**`docs/FL_GRADIENT_PROTO_CONTRACT_AG031.md`**（AG-031）。

**读表约定**

| 列 | 含义 |
|----|------|
| **现状** | 已实现 / 部分 / 未做 |
| **与《10》差异** | 有意简化或与文档字段、算法不一致处 |

---

## 一、逐项对照表（按《10》章节）

### §1 定位与边界

| 《10》要点 | 现状 | 与《10》差异 / 备注 |
|-----------|------|---------------------|
| FL 为跨层协议链，非独立产品线 | **已对齐**（工程组织上） | — |
| 端侧 `fl_trainer/` 独立编译、不污染 AVEngine | **已对齐**（CMake 可选 LibTorch） | — |

### §2 端侧 FL Trainer

| 《10》小节 | 设计要求（摘要） | 现状 | 与《10》差异 |
|-----------|------------------|------|--------------|
| **2.1** 线程模型 | FL 协议线程 + FLLocalTrainer，优先级 BELOW/IDLE | **部分** | 线程在 `fl_trainer.c`/`fl_round.c`；命名与端点文档可对齐 |
| **2.2** 目录结构 | `round_state_machine.c`、`fllocal_trainer.c` 等拆分 | **部分** | 逻辑在 `fl_round.c`、`local_train_core.*` 等，非逐文件同名 |
| **2.3** `FLT_*` / `FLTConfig` | 生命周期、状态枚举 | **部分** | `FLT_*` 与 `FLTConfig` 已有；枚举与《10》命名不完全一致 |
| **2.4** Round 状态机 | IDLE→ANNOUNCED→TRAINING→… | **部分** | `FLRoundPhase` 覆盖主路径；无独立 `round_state_machine.c` |
| **2.5** 本地训练 | LibTorch、按样本训练 | **部分** | 可选 LibTorch；否则均值特征差分占位路径 |
| **2.6** DP | L2 裁剪 + Laplace 等 | **已实现** | 见 `fl_dp.c` |
| **2.7** 隐私预算 | 本地 SQLite 持久化 | **已实现** | `fl_privacy_budget`；与《10》服务端汇总表是两条线 |
| **2.8** 分块上传 | 分块 HTTP/gRPC | **已实现** | `fl_gradient_upload` / assembler |
| **2.9** AVE 导出/导入 | `AVE_ExportFeatureVector*`、权重导出导入 | **已实现** | 见 `ave_sdk` + `test_ave_fl_abi` |

### §3 服务端 fl_coordinator

| 《10》小节 | 设计要求（摘要） | 现状 | 与《10》差异 |
|-----------|------------------|------|--------------|
| **3.1.1** Round 广播 | Kafka JSON，含 `base_model_version`、`server_pubkey_b64`、`tenant_scope` 等 | **已对齐核心字段** | `RoundAnnounceV1` 含 `v`、`tenant_scope`、`base_model_version`、`server_pubkey_b64` 等（T-008）；Agent 仍应以 `v` 做版本门控 |
| **3.1.2** 库表 | `fl_rounds` / `fl_participants` / `fl_privacy_budget` 及扩展字段 | **部分** | MySQL 版为 **bigint `round_id` + tenant**，非 UUID；无 `output_model_version`、统计计数、服务端私钥轮转等《10》全文段 |
| **3.1.2+** 扩展 | 聚合快照、QC 表、唯一约束、窗口 | **已实现** | `fl_aggregate_runs`、`fl_qc_*`、`MigrateP2/3`、`EDR_FL_AGG_WINDOW` |
| **3.1.3** gRPC FLService | `GetRoundInfo`、`ReportClientStatus`、`TriggerRound`、`CancelRound` | **部分** | 已实现 **UploadGradients**（含 `sample_count`）、**GetRoundInfo**（含 `round_status`）、**ReportClientStatus**、**TriggerRound**、**CancelRound** |
| **3.1.4** REST（edr-api 域） | `/v1/model/fl/rounds...` 等管理面 API | **部分** | `GET /api/v1/admin/model/fl/rounds/current`、**`GET .../rounds?limit=&offset=`**（列表，按 `round_id` 降序）与 **`GET .../rounds/:round_id`** 读 MySQL（T-007）；与《10》路径前缀略有差异 |
| **3.1.5** 聚合流程 | ECDH 解密、2.5σ 拜占庭、**样本加权 FedAvg+**、销毁私钥、QC、灰度发布 | **部分** | **FL3** + **L2/trim/median/krum** + **`EDR_FL_BYZ_ZSIGMA_MAX`** 坐标 Z-score 剔除 + **`sample_count` 加权 FedAvg**（T-003/T-004）；**协调器内不自动灰度**；T-009/ADR 已提供 **DB manifest + 可选 staging + HTTP notify + `/metrics`（S5）**；**全自动** `apply_gradients`→生产灰度仍属 train_svc（见 **`FL_S5_MODEL_VERSION_OBSERVABILITY.md`**） |
| **3.2** Prometheus | FL Round/QC 等指标 | **已实现 / 部分** | **已实现**：协调器 **`GET /metrics`**、命名空间 **`edr_fl_*`**（含 T-009 / S5 等，见 `internal/flcoord/prom_fl.go`）；运维说明见 **`edr-backend/platform/docs/FL_COORDINATOR_P1.md`**，最小入口见 **`FL_COORDINATOR_MINIMAL.md`** §P1。**部分**：**Grafana 仪表盘 JSON** 仍**不在**仓库内，由运维自建；**Prometheus 告警**提供**可导入示例** **`edr-backend/platform/docs/prometheus_fl_rules.example.yml`**（含抓取缺失、梯度错误率、S5 notify/staging 等），**非**生产级唯一策略，部署前须调阈值与标签；T-010 亦不以大盘/告警为关闭条件。 |

### §4 前端

| 《10》要点 | 现状 | 与《10》差异 |
|-----------|------|--------------|
| 管理后台联邦 **只读** Round | **部分** | **`/admin/ops/model/federated`**（模型管理 → 联邦）：已接 **`GET .../rounds/current`**、**`GET .../rounds?limit=50`**（历史下拉 + 表格）、**`GET .../rounds/:round_id`** 与 **`?round=<id>`**（单轮详情 + 参与者表，T-012）。**模型运维 → 联邦学习架构**：架构图为 **model-ops 面板** 占位 + 顶部 **当前 Round** 卡片（**`fetchCurrentFLRound`**）；实时字段以模型管理页为准。 |
| `/admin/model/federated-learning`（旧路径名） | **不适用** | 路由以 **`routes.tsx`** 中 **`ops/model/federated`** 为准；不要求单独 `/admin/model/federated-learning` 页。 |
| WebSocket FL 消息类型 | **部分→已闭环（聚合事件）** | **`model.fl.round.status`**：前端 **`useModelManagementData`** / **ModelOpsPage** invalidate；后端由协调器聚合完成回调 edr-api 内部广播（T-013，见 **`FL_COORDINATOR_P1.md`**）。更细粒度（每路上传即推）仍可选增强。 |

### §5 TOML `[fl]`

| 《10》要点 | 现状 | 与《10》差异 |
|-----------|------|--------------|
| 独立 `[fl]`、`[fl.frozen_layers]` 等 | **已实现（T-015）** | `agent.toml` / `config.c` 解析 `[fl.frozen_layers]`；HTTP 梯度 JSON 附带 `frozen_layer_names`；特征均值路径不切片嵌入（见 `FL_ROUND_TRAINING_SEMANTICS.md`） |

### §6 改造影响汇总（与实现对读）

| 《10》6.x 表项 | 现状摘要 |
|----------------|----------|
| 6.1 AVEngine 删 DLL 内训练 | **依赖 AVE 侧实际发布物**；Agent 侧已通过 SDK 导出接口解耦训练 |
| 6.2 协调器 Kafka + gRPC + DB + REST + Prom | **Kafka/DB/聚合/QC/读模型 FL REST + `/metrics`（`edr_fl_*`）+ gRPC `TriggerRound`/`Cancel` 等已完成**；**Grafana 大盘仍属运维自建**；Prometheus **告警示例**见 **`prometheus_fl_rules.example.yml`**（与 §3.2「部分」一致） |
| 6.3 前端三处 | **部分**：模型管理联邦 + **当前 / 列表 / 单轮 `?round=`**；模型运维联邦 Tab 顶栏 + 示意架构图 |
| 6.4 agent.toml + compose | **部分**（compose 变量名与《10》示例可能不一致，以 `FL_COORDINATOR_P1.md` 为准） |

### §7 明确不改造模块

| 《10》声明 | 现状 | 备注 |
|-----------|------|------|
| train_svc / 灰度 / CMD_UPDATE_MODEL 等不改 | **未在本文档追踪** | 联邦产出模型自动走灰度仍属**产品后续** |

---

## 二、执行 backlog（可排序、可验收）

> **优先级**：P0 阻塞联调 / P1 产品最小闭环 / P2 对齐《10》全文 / P3 观测与运维

| ID | 优先级 | 任务 | 依赖 | 建议验收标准 |
|----|--------|------|------|--------------|
| **T-001** | P1 | fl-coordinator：**deadline 窗口后无新梯度时的定时 finalize**（扫描 `fl_rounds`+`fl_participants`，幂等写聚合） | 现有 `FinalizeRoundIfReady` | **已实现**：`EDR_FL_FINALIZE_POLL_SECONDS`（默认 10s，`≤0` 关闭）+ `StartDeadlineFinalizeTicker`；截止后无请求仍幂等 finalize |
| **T-002** | P1 | 协调器：**鉴权或部署文档**（反向代理、mTLS、内网 IP 限制） | — | **已实现**：`FL_COORDINATOR_P1.md` 部署/安全节 + 可选 **`EDR_FL_COORDINATOR_HTTP_API_KEY`**（HTTP+gRPC，`X-API-Key` / `Authorization: Bearer`） |
| **T-003** | P1 | **样本加权 FedAvg**（`fl_participants` 存 `sample_count` 或从明文维数推断权重） | DB 迁移 | **已实现**：`MigrateP4` + `sample_count`；HTTP/gRPC 上传；`FedAvgWeighted`；单测见 `aggregate_test` |
| **T-004** | P2 | **2.5σ（或可配置 Z-score）拜占庭过滤**（与现有 L2/trim/krum 可组合开关） | T-003 可选 | **已实现**：`EDR_FL_BYZ_ZSIGMA_MAX` + `ApplyZScoreIterative`（与 trim/median/krum 组合时先剔除再鲁棒聚合）；单测 `byzantine_test` |
| **T-005** | P2 | gRPC：**GetRoundInfo**（返回当前 round、deadline、min_clients、model_target） | fl-coordinator proto | **已实现**：`FLRoundRequest` 含 `tenant_id`/`round_id`（0=最新）；响应含 `tenant_scope`、`base_model_version`、`server_pubkey` 等 |
| **T-006** | P2 | gRPC：**ReportClientStatus**（可选，供前端展示） | T-005 | **已实现**：`fl_client_round_status` + gRPC `ReportClientStatus` |
| **T-007** | P2 | edr-api：**读模型 FL REST**（至少 `GET .../rounds/current`、`GET .../rounds/{id}` 只读转发或读 MySQL） | `DATABASE_DSN` 与 fl 表 | **已实现**：`GET /api/v1/admin/model/fl/rounds/current` 与 **`GET /api/v1/admin/model/fl/rounds/:round_id`**（并保留 `GET /admin/fl/rounds/current`） |
| **T-008** | P2 | **Round 公告 JSON 与《10》对齐**（`base_model_version`、`tenant_scope`、可选 `server_pubkey` 策略） | Kafka 消费者兼容 | **已实现**：`RoundAnnounceV1` 扩展 + announce HTTP 字段；兼容字段 `v` |
| **T-009** | P2 | **聚合后模型应用 / 版本产出**（与 ModelVersion / 对象存储衔接，或明确「仅导出 mean_blob」产品边界） | train_svc 决策 | **ADR + 实现**：[`ADR-0009-T-009-fl-aggregate-to-model-version.md`](./ADR-0009-T-009-fl-aggregate-to-model-version.md) §7 — **`fl_aggregate_runs.mean_blob_sha256` / `derived_model_version`**（`MigrateT009`）；可选 **`EDR_FL_MODEL_VERSION_AUTO_LINK`** → **`model_versions` staging**；可选 **`EDR_FL_AGGREGATE_NOTIFY_URL`** manifest POST；`GET /admin/model/fl/rounds/*` 暴露摘要字段 |
| **T-010** | P3 | **Prometheus**：`edr_fl_*` 指标（《10》§3.2） | fl-coordinator 暴露 `/metrics` | **已实现**。**建议验收（= 本项唯一关闭条件，已写死）**：(1) `GET /metrics` 返回 Prometheus 文本；(2) 至少暴露 `edr_fl_http_requests_total`、`edr_fl_gradient_uploads_total`、`edr_fl_round_announces_total`、`edr_fl_qc_metrics_posts_total`、`edr_fl_finalize_rounds_total`、`edr_fl_grpc_unary_requests_total`、`edr_fl_coordinator_info`（实现见 `internal/flcoord/prom_fl.go`；另有 T-009 / S5 扩展指标如 **`edr_fl_model_version_staging_registered_total`**、**`edr_fl_aggregate_notify_http_total`** 等）；(3) **`edr-backend/platform/docs/FL_COORDINATOR_P1.md`** 已说明 `GET /metrics`、指标列表及与 **T-002**（`/metrics` 免 API Key）的关系。**本迭代 / 本 backlog 明确不包含**：**Grafana 仪表盘 JSON**、**生产环境最终告警策略与大盘截图**、录制演示——**不作为** T-010 是否完成的依据；仓库内 **`prometheus_fl_rules.example.yml`** 仅为**示例**，便于运维导入后自行调整。**不得**用 Grafana 缺失阻塞将 T-010 视为未完成。 |
| **T-011** | P3 | 前端：联邦 **只读 API**（T-007） | T-007 | **已实现（模型管理联邦 Tab + 模型运维联邦 Tab 顶栏）**；**`GET .../rounds` 列表**已在联邦 Tab 接下拉/表（与 S6）；model-ops 架构图仍为示意面板 |
| **T-012** | P3 | 前端：**指定 round 详情** + **参与者只读表** | T-007 | **已实现**：**`/admin/ops/model/federated?round=<id>`**；**`GET .../rounds/:id/participants`**（P1）+ 控制台表格；见 **`FL_P1_CONSOLE_AND_RUNBOOK.md`** |
| **T-013** | P3 | WebSocket：**FL round 状态推送**（与《10》§4.2.3） | hub + 协调器事件源 | **已实现（二次迭代）**：聚合后协调器可选 **`EDR_FL_PLATFORM_WS_NOTIFY_*`** → edr-api **`POST /api/v1/internal/fl/broadcast-round-status`**（**`EDR_INTERNAL_FL_WS_KEY`**）→ Hub 广播 **`model.fl.round.status`**；前端 **`useModelManagementData`** 与 **ModelOpsPage** 失效相关 query；见 **`FL_COORDINATOR_P1.md`** §控制台 WebSocket |
| **T-014** | P1 | **端到端脚本**：1 协调器 + N 端上传 + 断言聚合与 QC | 现有栈 | **已实现**：`edr-backend/platform/scripts/fl_p1_e2e.sh` + `cmd/fl-p1-e2e`（FL3 密封串与 DB 断言） |
| **T-015** | P2 | agent.toml：**`[fl.frozen_layers]` 与训练冻结行为** 对齐《10》§5 | LibTorch 路径 | **已实现**：TOML 解析 + `FLTConfig`；HTTP 上传 JSON 带 `frozen_layer_names`；`fl_frozen_layers_apply_feature_delta` 占位（特征均值路径不切片）；LibTorch `reduce_mean` 见 `local_train_torch.cpp` 注释；语义见 `FL_ROUND_TRAINING_SEMANTICS.md` §frozen_layers |

---

## 三、建议执行顺序（迭代计划）

1. **Sprint A（闭环）**：T-014 → T-001 → T-002  
2. **Sprint B（对齐《10》聚合语义）**：T-003 → T-004  
3. **Sprint C（可观测 + 管理面）**：T-005 → T-007 → **T-010**（以协调器可 scrape 为完成；**Grafana 不属 T-010**）  
4. **Sprint D（前端）**：T-011 → T-012 → T-013  
5. **Sprint E（产品化）**：T-008 → T-009 → T-015  

---

## 四、维护

- 本文件随实现更新：**改代码时同步改对应行「现状」**（避免对照表腐烂）。  
- 设计变更以《10》改版为准，在此表增加「版本」脚注列（可选）。
- **最后同步（代码）**：`edr_fl_*` 与 §3.2 / T-010 对齐至 `edr-backend/platform/internal/flcoord/prom_fl.go` + `cmd/fl-coordinator/main.go`（`/metrics`、HTTP 与 gRPC 埋点；T-009 扩展指标见同文件）。
