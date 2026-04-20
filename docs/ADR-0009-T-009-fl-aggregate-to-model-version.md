# ADR-0009：T-009 聚合结果如何进入模型版本管线（P2 产品边界）

| 字段 | 内容 |
|------|------|
| **状态** | 已采纳（产品边界）；实现分阶段 |
| **任务** | T-009（P2） |
| **关联** | `FL_TRACEABILITY_DESIGN10.md`；《10_联邦学习FL组件详细设计》§3.1.5；`Cauld Design/三个板块的逻辑关系.md` §「服务端聚合后如何复用已有发布机制」 |
| **日期** | 2026-04-18 |

---

## 1. 背景与问题

### 1.1 设计意图（《10》与板块关系文档）

- 协调器在完成 **FedAvg+ / QC** 等步骤后，理想路径是复用既有 **模型版本与灰度发布**（如 `ModelVersionManager.publish`、MinIO `models/ave/{version}/`、`model.global.update` 等），使联邦产出与集中训练产出对 Agent **下载与热更新路径一致**。
- 版本号上可通过后缀区分来源（例如 `v2.4.1+fl.<round>`）。

### 1.2 当前实现缺口（事实）

- `fl-coordinator` 已能将聚合结果写入 **`fl_aggregate_runs`**（及关联 QC/元数据），但 **未** 与 **ONNX 构建、`train_svc`、MinIO 上传、`ModelVersion` 元数据、灰度 Kafka** 形成自动化闭环。
- 《10》中的 **`apply_gradients` / ModelVersionManager 联动** 在工程上仍属**未接线**。

### 1.3 需裁决的产品问题

**聚合结果（mean blob / 聚合张量摘要）以何种契约进入「模型版本管线」？**  
若不裁决，会出现：协调器是否应直接发版、谁负责把向量变成 ONNX、安全与审计边界落在哪一层等歧义。

---

## 2. 决策（P2 产品边界）

### 2.1 总原则：**协调器不直接调用「发版 / 灰度」**

- **`fl-coordinator`（及同进程的聚合逻辑）** 的职责 **止于**：解密与校验、鲁棒聚合、QC 门禁、**持久化聚合产物与可追溯元数据**（含 `round_id`、`model_target`、checksum、参与方摘要等）。
- **模型版本管线**（ONNX 导出、签名、上传对象存储、写入 `ModelVersion`、灰度与回滚）**仍由既有 `train_svc` / model-ops 域**完成，或通过其 **稳定 API / 作业** 触发。

**理由**：发版涉及密钥、合规、容量与回滚策略；与「梯度聚合」生命周期分离，符合现有《10》§7「train_svc / 灰度 / CMD_UPDATE_MODEL 等不改」的演进节奏，并降低协调器与训练服务的循环依赖。

### 2.2 P2 采纳的衔接形态：**「聚合产物 = 可消费工件」+ 显式下游**

在 T-009 的实现边界内，**至少满足其一**（可并行存在）：

| 形态 | 说明 | 验收指向 |
|------|------|----------|
| **A. 导出型 API / 作业输入** | 提供**受控**方式拉取或导出某轮 **`aggregate` 工件**（例如聚合向量 blob、或约定格式的 manifest + SHA256）。调用方可为 **运维脚本、`train_svc` 批处理、或安全审计流水线**。 | 可调用的导出路径 + 鉴权/审计要求见部署文档 |
| **B. 文档化「仅 DB 落地」** | 在特定部署中明确 **不** 接对象存储，聚合结果 **仅** 存于 `fl_aggregate_runs`（及备份策略），**不承诺**自动进 ModelVersion。 | 产品说明与运维手册一致，避免误期望「自动发版」 |

**不推荐**在 P2 把下列能力作为 **T-009 必选项**（可作为后续 ADR）：

- 协调器进程内直接 **`publish()`** 或写 MinIO「可下发 ONNX」；
- 无人工/无策略门控的 **全自动** 联邦 round → 生产灰度。

---

## 3. 推荐实现路径（与 backlog 对齐）

1. **短期（闭环数据）**  
   - 保证 `fl_aggregate_runs`（及关联表）字段足以支撑 **导出 manifest**（版本、算法、QC 结果引用、`mean_blob` 或外部指针）。  
   - 若已有 **只读管理 API**（如 T-007 的 round 详情），扩展 **聚合摘要** 的只读展示，避免运营「黑盒」。

2. **T-009 核心交付（二选一或组合）**  
   - **最小实现**：实现 **「导出聚合向量 / manifest」** 的 API 或异步导出任务（对应 `FL_TRACEABILITY` 表中「最小导出聚合向量 API」）。  
   - **边界声明**：在 **同一 ADR 族或部署说明** 中写明：若不做导出 API，则 P2 边界为 **「仅 DB 中 mean_blob，由运维/ETL 自行接 train_svc」**，并在对外文档中显著标注。

3. **下游对接（train_svc）**  
   - 由 **train_svc 或独立 job** 读取导出工件 → 负责 **向量 → ONNX（或目标格式）→ 既有 publish 管线**。  
   - 版本命名、灰度策略 **复用** 集中训练规则；联邦来源仅通过 **元数据字段**（如 `source=fl`, `fl_round_id`）区分。

---

## 4. 备选方案与未采纳原因

| 方案 | 说明 | 未采纳为 P2 默认 |
|------|------|------------------|
| **协调器内一键发版** | 聚合完成即调用 ModelVersion / 上传 MinIO | 耦合过重、安全与发布职责混在数据面；与现有「train_svc 决策」分工冲突 |
| **仅文档声明、零接口** | 不写任何导出 API | 可接受为 **B**，但需在 T-009 验收中明确「无 API」带来的运维成本；与「可产品化」目标略弱 |
| **Agent 侧直接应用 mean blob** | 不下发 ONNX，端上自行 merge | 与当前 Agent/AVE 更新模型路径不一致，长期维护成本高，不作为 P2 主路径 |

---

## 5. 后果

- **正面**：职责清晰；协调器可独立扩缩与部署；发版规则单点演进（train_svc / model-ops）。  
- **负面**：联邦 round 完成到「可灰度版本」**非零延迟**，依赖下游作业或人工；需 **监控与告警** 覆盖「聚合完成但未生成版本」类场景（可与 T-010 指标配合）。  
- **后续 ADR 触发条件**：若产品要求 **亚分钟级** 联邦发版、或协调器必须 **内联 ONNX**，应新开 ADR 修订本决策。

---

## 6. 参考与追踪

- 执行 backlog：`edr-agent/docs/FL_TRACEABILITY_DESIGN10.md` → **T-009**  
- 协调器行为：`edr-backend/platform/docs/FL_COORDINATOR_P1.md`  
- 本 ADR 修订应同步更新 `FL_TRACEABILITY_DESIGN10.md` 中 T-009 行「现状 / 备注」。

---

## 7. 工程实现（与 ADR §2.1 一致：协调器不直接灰度发版）

| 能力 | 说明 |
|------|------|
| **DB manifest** | `fl_aggregate_runs` 增加 **`mean_blob_sha256`**（SHA-256 hex）与 **`derived_model_version`**（`{base_model_version}+fl.{round_id}`，无 base 时为 `fl.{tenant}.{round}`）。迁移：**`MigrateT009`**（与 `migrations/004_fl_t009_aggregate_manifest.sql` 对齐）。 |
| **可选 → `model_versions`** | 当库内存在 **`model_versions`** 表且设置 **`EDR_FL_MODEL_VERSION_AUTO_LINK=1`** 时，聚合成功后 **upsert**（`stage=staging`）一行，**id** 为确定性 `fl_<sha256>`，**version** 为 `derived_model_version`，供 Model Ops 列表与 train_svc 下游衔接（仍非灰度/发布）。指标 **`edr_fl_model_version_staging_registered_total`**。 |
| **可选 HTTP 通知** | 设置 **`EDR_FL_AGGREGATE_NOTIFY_URL`** 时，聚合成功后 **异步 POST** JSON **`AggregateArtifactManifestV1`**（manifest）；鉴权可选 **`EDR_FL_AGGREGATE_NOTIFY_API_KEY`**，否则回退 **`EDR_FL_COORDINATOR_HTTP_API_KEY`**。 |
| **管理面只读** | `GET .../admin/model/fl/rounds/*` 响应增加 **`mean_blob_sha256`**、**`derived_model_version`**（T-007 扩展）。 |
| **edr-api 可选接收** | 设置 **`EDR_INTERNAL_FL_AGGREGATE_MANIFEST_KEY`** 时注册 **`POST /api/v1/internal/fl/aggregate-manifest`**，可与 **`EDR_FL_AGGREGATE_NOTIFY_URL`** 指向同一进程，便于内网消费 manifest（S5，见 **`edr-backend/platform/docs/FL_S5_MODEL_VERSION_OBSERVABILITY.md`**）。 |
