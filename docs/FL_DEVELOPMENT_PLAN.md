# 联邦学习（FL）开发计划

> 依据：`Cauld Design/10_联邦学习FL组件详细设计.md`、`09_AVEngine开发需求文档.md`、`联邦学习训练框架实现规范_v1.0..md`、`EDR_端点详细设计_v1.0.md`（§1.2 / §2.1 / §5.6）。  
> 代码仓库：`edr-agent`（端侧）、`edr-backend/platform`（服务端 `fl_coordinator` 等）。

**《10》逐项对照与可执行 backlog（含任务 ID T-001…）**：见同目录 **[`FL_TRACEABILITY_DESIGN10.md`](./FL_TRACEABILITY_DESIGN10.md)**，便于排期与验收。

---

## 1. 目标与原则

| 项 | 说明 |
|----|------|
| **端侧** | 新增 **`src/fl_trainer/`**（对应设计中的 `Agent/fl_trainer/`），**`FLLocalTrainer`** 与 **`fl_protocol_thread`** 在 Agent 进程内；**LibTorch 等训练依赖仅链接本模块**；通过 **`AVE_ExportFeatureVector` / `AVE_ExportModelWeights` / `AVE_ImportModelWeights`** 与 AVEngine 交互。 |
| **服务端** | **`fl_coordinator`** 独立容器：Round 生命周期、收梯度、聚合、质量门禁、与 ModelVersion / train_svc 协调（见设计 §20.7 与实现规范）。 |
| **优先级** | **P0**：可联调闭环（最小 fake / 真实 stub）；**P1**：完整训练与上传；**P2**：生产级运维、监控与前端。 |

---

## 2. 端侧开发计划（`edr-agent`）

### 2.1 优先级总览

| 阶段 | 优先级 | 内容 | 产出（验收） |
|------|--------|------|----------------|
| **C0** | **P0** | AVEngine 三条 ABI 桩实现 + 头文件声明 | **已完成（2026-04）**：`include/edr/ave_sdk.h` + `ave_sdk.c`；`ctest -R ave_fl_abi_c0` / `test_ave_fl_abi` |
| **C1** | **P0** | **`fl_trainer` 模块骨架**：`FLT_Init` / `FLT_Start` / `FLT_Shutdown`、配置 `[fl]`、`CMake` 选项 `EDR_WITH_FL_TRAINER`（默认 OFF） | **已完成（2026-04）**：`include/edr/fl_trainer.h` + `src/fl_trainer/fl_trainer.c`；`[fl]` TOML；`ctest -R fl_trainer_c1`（需 `-DEDR_WITH_FL_TRAINER=ON`） |
| **C2** | **P0** | **Round 协议线程**：先接本地/内存队列或轮询 **stub**；预留 Kafka 消费者接口 | **已完成（2026-04）**：`fl_round.c`（`FLRoundPhase` / 协议+训练线程协作）、`fl_kafka_stub.c`（注册回调）+ **`fl_kafka_poll_round_stub`**（`-DEDR_WITH_FL_KAFKA=ON` 时 **librdkafka** 实现，否则 noop）；`[fl] mock_round_interval_s` 周期性假 Round；`FLT_GetStatus` 对齐状态 |
| **C3** | **P1** | `fl_samples.db` 只读枚举 + `AVE_ExportFeatureVector` 联调；**static 512 维** 路径打通 | **已完成**：`docs/FL_SAMPLES_SCHEMA.md` + `fl_samples_db.c`；`edr_fl_register_feature_lookup`；`[fl] fl_samples_db_path` + SQLite 命中时导出 BLOB |
| **C4** | **P1** | **LibTorch + `local_train_core`**：权重差、冻结头（与设计一致）、**仅 static** 先跑通 | **已完成（可选）**：`EDR_WITH_LIBTORCH` + `TORCH_ROOT` / `find_package(Torch)` 时 `local_train_torch.cpp` 求行均值；否则 C 循环 |
| **C5** | **P1** | DP（裁剪 + Laplace）+ **gRPC 梯度上传**（对齐现有 `FLService` / proto，或临时 sidecar） | **已完成**：`fl_dp.c`；`coordinator_http_url` 走 `fl_http_upload`（JSON+Base64）；`coordinator_grpc_addr` 在 `EDR_HAVE_GRPC_FL`（`find_package(gRPC)` 且 `EDR_WITH_FL_TRAINER`）时用 `fl_grpc_upload.cpp`（`fl_pb_wire` + `GenericStub`/`ByteBuffer`，不检入 `fl.pb` 以免与 ingest 的 protobuf 主版本冲突） |
| **C6** | **P2** | ECDH + AES-GCM、分块上传、隐私预算 SQLite、`Import` 验证路径 | **部分完成**：`fl_privacy_budget.c`；**FL3**；**分块上传**：`gradient_chunk_size_kb` → `fl_gradient_upload_bytes` / `UploadGradientsRequest.gradient_upload_id` + `chunk_*`；**协调端最小接收**：`edr-backend/platform/cmd/fl-coordinator`（HTTP JSON + 分块 + FL3 解密，见 `platform/docs/FL_COORDINATOR_MINIMAL.md`）；`AVE_ImportModelWeights` 对 **FL3** 返回 `AVE_ERR_NOT_SUPPORTED`；`[fl] model_target` + `docs/FL_ROUND_TRAINING_SEMANTICS.md` |
| **C7** | **P2** | **behavior** 特征维度扩展（若与 512 不一致）：`ExportFeatureVectorEx` 或第二套缓冲约定 | **已完成**：`AVE_ExportFeatureVectorEx`；`AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT` **256**（与《11》§6.1 CLS 表征一致）；`AVE_FL_BEHAVIOR_SEQ_LEN` **128**（输入 `seq_len`）；见 `FL_SAMPLES_SCHEMA.md`、`docs/FL_BUILD_AND_CI.md` |

**建议顺序**：**C0 → C1 → C2** 保证结构可编译与可测；**C3–C4** 可部分并行（C3 偏数据面，C4 偏训练）；**C5** 依赖服务端最小接收端（见 §3.1）。

### 2.2 与现有代码的衔接点

- **AVE**：在 `include/edr/ave_sdk.h`（或现有 `ave` 头文件）声明三接口；在 `src/ave/` 实现（或 `ave_engine.c` 转发至 ONNX 权重导出与特征缓存）。
- **Agent 主流程**：`src/core/agent.c`（或 `main` 路径）在 `AVE_Init` 之后、按配置调用 `FLT_Init` / `FLT_Start`；关闭顺序与 **10 号文** 一致。
- **CMake**：`fl_trainer` 为独立 target，`edr_agent` 可选链接；LibTorch 通过 `find_package(Torch)` 或预编译包路径，**勿**加入 `ave` 静态库依赖链若当前为单库——设计要求是 **训练不污染 AVEngine**，故 **动态链接 fl_trainer 或独立 object 库** 更清晰。

### 2.3 端侧风险与前置

| 风险 | 缓解 |
|------|------|
| LibTorch 体积与 Windows 交叉编译 | P1 前做 **PoC**；或先 **C4 用最小自定义张量步进**（仅矩阵差）再换 LibTorch。 |
| `fl_samples.db` schema 与实现不一致 | C0 在 **09** 与 **10** 对齐一张 **最小 schema** 文档，并在 `tests/` 建库。 |
| gRPC `FLService` 未在平台侧就绪 | C5 先用 **独立测试 harness** 或 **最小 gRPC server** 在 `edr-backend` 侧 stub（见 §3.1）。 |

---

## 3. 服务端开发计划（`edr-backend/platform`）

### 3.1 优先级总览

| 阶段 | 优先级 | 内容 | 产出（验收） |
|------|--------|------|----------------|
| **S0** | **P0** | **Proto / OpenAPI**：`UploadGradients`、`GetRoundInfo`、Round 状态查询与现有 **ingest** 命名空间并存 | `buf` 可生成 Go / C++ stub |
| **S1** | **P0** | **`fl_coordinator` 最小进程**：HTTP/gRPC **health** + **接收梯度**（内存聚合或落临时文件）+ **假 Round**（固定 `round_id`） | **HTTP + gRPC**：`cmd/fl-coordinator`（`/health`、`/v1/fl/gradient`、`EDR_FL_COORDINATOR_GRPC_LISTEN` → `edr.v1.FLService/UploadGradients`；分块重组、FL3 解密；见 `platform/docs/FL_COORDINATOR_MINIMAL.md`） |
| **S2** | **P1** | **DB 迁移**：`fl_rounds` / `fl_participants` / `fl_privacy_budget`（与设计一致或子集） | **最小可用**：`migrations/001_fl_p1.sql` + `EDR_FL_AUTO_MIGRATE=1`；`fl_aggregate_runs` 存 FedAvg 快照；与现有 MySQL 共存 |
| **S3** | **P1** | **Round 广播**：Kafka `edr.fl_round_announce`（或等价 topic）+ 消费者文档 | **生产者**：`POST /v1/fl/round/announce` + `EDR_FL_KAFKA_BROKERS`；**消费者**：Agent 可选 **`EDR_WITH_FL_KAFKA`** + `fl_kafka_rdkafka.c`（`RoundAnnounceV1` JSON、`EDR_FL_KAFKA_*` 见 `docs/FL_BUILD_AND_CI.md`） |
| **S4** | **P1** | **FedAvg+**、拜占庭过滤、**质量门禁**（TPR/FPR 阈值可配置） | **已增强**：`EDR_FL_BYZ_MODE`（mean/trim/median/krum）+ L2；`EDR_FL_QC_*` + `fl_qc_*` + `POST /v1/fl/qc/metrics`；`RecoverAggregationState` 跨重启重放/补写聚合；见 `edr-backend/platform/docs/FL_COORDINATOR_P1.md` |
| **S5** | **P2** | **ModelVersion / train_svc 衔接 + 观测**：ADR-0009（staging、**`EDR_FL_AGGREGATE_NOTIFY_URL`** manifest）；协调器 **`edr_fl_aggregate_notify_http_total`** / **`edr_fl_model_version_staging_failures_total`**；可选 **`POST /api/v1/internal/fl/aggregate-manifest`**（**`EDR_INTERNAL_FL_AGGREGATE_MANIFEST_KEY`**）；说明 **`platform/docs/FL_S5_MODEL_VERSION_OBSERVABILITY.md`**、**`prometheus_fl_rules.example.yml`** | 与 T-010 `/metrics` 同抓取面 |
| **S6** | **P2** | **管理端 REST**：**`GET /api/v1/admin/model/fl/rounds`**（分页列表）+ 已有 **`.../rounds/current`**、**`.../:round_id`**、**`.../:round_id/participants`**；隐私预算只读仍属后续 | 列表可对接控制台历史下拉；参与列表已覆盖 |

**建议顺序**：**S0 → S1** 解锁端侧联调；**S2–S4** 与端侧 **C5–C6** 并行；**S5–S6** 偏上线前。

### 3.2 服务端依赖

- **数据库**：与现有 `DATABASE_DSN` 同一实例；新表前缀 `fl_`。
- **消息**：Kafka 与现有平台一致；无 Kafka 时 **S3** 提供 **REST 轮询 Round** 作为开发降级（设计可选，需文档一句话）。
- **容器**：`docker-compose` 中 **§20.7** `fl_coordinator` 服务块与卷。

---

## 4. 联合里程碑（建议）

| 里程碑 | 端侧 | 服务端 | 可演示内容 |
|--------|------|--------|------------|
| **M-α** | C0–C2 | — | Agent 启用 FL 线程不崩溃 |
| **M-β** | C3 | S0–S1 | 假 Round + 上传一包梯度到测试 coordinator |
| **M-γ** | C4–C5 | S2–S3 | 真本地训练一步 + 真 Round 广播（或轮询） |
| **M-δ** | C6 | S4–S5 | DP + 加密 + 聚合门禁 |
| **M-ε** | C7 | S6 | behavior 扩展 + 管理端 |

（与 **10 号文** 中原 M1–M9 对应关系：M1≈C0+AVE、M2≈C1–C2、M3≈C4、M4≈C5–C6、M6≈S1–S4。）

---

## 5. 建议的「第一步」编码任务（本周可执行）

1. **AVE**：在 `include/edr/ave_sdk.h` 增加三函数声明；`src/ave/` 实现 **stub**（`ExportFeatureVector` 可返回全零或从内部缓存查找）。  
2. **CMake**：`option(EDR_WITH_FL_TRAINER OFF)`，空目录 `src/fl_trainer/` + `fl_trainer_stub.c` 导出 `flt_init` 等弱符号或 `FLT_*`。  
3. **文档**：本文件已在 `edr-agent/docs/`；变更记录在 PR 描述中引用 **10/09** 章节。

---

## 6. 参考索引

| 文档 | 用途 |
|------|------|
| `Cauld Design/10_联邦学习FL组件详细设计.md` | 线程、接口、状态机、里程碑 |
| `Cauld Design/09_AVEngine开发需求文档.md` §2.6 | C ABI |
| `Cauld Design/联邦学习训练框架实现规范_v1.0..md` | DP、MIN_CLIENTS、协议时序 |
| `Cauld Design/EDR_端点详细设计_v1.0.md` §1.2 §2.1 §5.6 | 进程与组件图 |
| `Cauld Design/EDR_服务端详细设计_v1.0.md` §20.7 | 容器与部署 |
| `edr-agent/docs/FL_BUILD_AND_CI.md` | gRPC/OpenSSL/HTTPS 可复现构建与 CI 环境变量 |

---

*版本：2026-04 · 随实现可迭代修订（勿与《10》正文冲突；冲突以《10》为准）。*
