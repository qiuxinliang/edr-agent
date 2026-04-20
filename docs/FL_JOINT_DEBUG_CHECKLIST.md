# 联邦学习联调前检查清单（P0）

与 **`FL_TRACEABILITY_DESIGN10.md`**、**`FL_GRADIENT_PROTO_CONTRACT_AG031.md`** 配合使用。控制台 P1 能力见 **`FL_P1_CONSOLE_AND_RUNBOOK.md`**。

---

## 0. P0 关闭标准（稳定性门禁）

| 项 | 要求 | 如何验证 |
|----|------|----------|
| **联调门禁** | MySQL + **`fl_p1_e2e.sh` 绿** | `cd edr-backend/platform && ./scripts/verify_fl_p0.sh`（或手动跑 **`scripts/fl_p1_e2e.sh`**）；环境变量以 **`FL_COORDINATOR_P1.md`** 为准 |
| **租户一致** | 协调器 `tenant_id`、Agent 配置、平台 JWT **tenant** 一致 | 联调/登录时核对同一租户 ID；否则控制台 **GET .../rounds/** 无数据 |
| **平台与协调器同库** | **edr-api** `DATABASE_DSN` 与 **fl-coordinator** 指向同一 MySQL（含 `fl_*` 表） | 协调器写入后，用同一库对 API 的 `GET .../model/fl/rounds/current` 应能看到摘要 |
| **生产安全** | 协调器对公网时至少 **API Key / 反向代理 / 内网** 其一 | 配置 **`EDR_FL_COORDINATOR_HTTP_API_KEY`** 或网关；**勿**将协调器 Key 打入 Agent 镜像 |

**自动化脚本**：`edr-backend/platform/scripts/verify_fl_p0.sh`（MySQL 探测 + E2E + `go build` fl-coordinator）。

### 0.1 手动 P0（脚本无法代劳）

按下面顺序勾选；任一项不满足时，控制台 **联邦学习** 页或只读 API 会表现为空数据、403 或误暴露协调器管理面。

**A. 租户一致（coordinator / Agent / edr-api JWT）**

1. 协调器侧：公告与梯度里的 `tenant_id` 记为 **T**（如 `e2e_tenant`、`demo-tenant`）。  
2. Agent：`agent.toml`（或等价配置）里 **`[fl]` / `tenant_id`**（及上报路径使用的租户）= **T**。  
3. 平台：登录用户 JWT 里 **`tid`（租户）** = **T**（演示模式则为请求头 **`X-Tenant-ID`**，与灌库/演示租户一致）。  
4. 验收：`GET /api/v1/admin/model/fl/rounds/current`（带合法 Bearer）返回的摘要与 **T** 下 `fl_rounds` 一致；若始终空，先对 MySQL 执行  
   `SELECT tenant_id, round_id FROM fl_rounds ORDER BY round_id DESC LIMIT 5;`  
   核对 **tenant_id** 是否就是你在控制台使用的 **T**。

**B. edr-api 与 fl-coordinator 同库**

1. 两边环境变量 **`DATABASE_DSN`**（或协调器专用 DSN）指向 **同一 MySQL 实例、同一 database 名**（通常含库名 **`edr`**），且账号对 `fl_*` 表可读（API 只读）、协调器侧可写。  
2. 验收：协调器完成一轮聚合后，**不重启 API**，直接调  
   `GET /api/v1/admin/model/fl/rounds/current`  
   应能看到 `round_id` / `has_aggregate` 等与 `fl_aggregate_runs` 一致（需 **A** 中租户一致）。

**C. 生产安全（协调器管理面）**

1. 协调器若可被非内网访问：配置 **`EDR_FL_COORDINATOR_HTTP_API_KEY`**（HTTP + gRPC 共用）**或** 前置网关鉴权 / 仅内网 SLB。  
2. **`GET /health`、`GET /metrics`** 可按文档免 Key（便于探活与 Prometheus）；**勿**把无防护的监听地址直接暴露公网。  
3. **Agent 镜像与配置**：**不得**写入协调器 API Key；运维仅通过密钥管理 / 网关注入调用 `POST /v1/fl/round/announce` 等。  
4. 抽查：`grep -r "COORDINATOR.*API_KEY\|X-API-Key" edr-agent/` 构建产物与发布物中不应出现生产协调器密钥（联调临时值除外）。

### 0.2 联调推荐默认（已定策略时可照此填）

| 维度 | 选择 | 落地要点 |
|------|------|----------|
| **租户 T** | 与**平台当前登录租户**一致 | 协调器 JSON / Agent `tenant_id` / JWT `tid`（或 demo 的 `X-Tenant-ID`）同一字符串；不要用与控制台无关的随机租户。 |
| **库** | **本机 MySQL**，库名 **`edr`**，**两边 DSN 对齐** | **edr-api** 与 **fl-coordinator** 使用同一 `DATABASE_DSN` 形态，例如 `USER:PWD@tcp(127.0.0.1:3306)/edr?parseTime=true`（密码与账号以环境为准）；先 `CREATE DATABASE IF NOT EXISTS edr;`。 |
| **暴露** | **仅内网** | 协调器监听 **`127.0.0.1:端口`** 或仅 VPC/内网网卡；防火墙不开放公网入站；**可不设** `EDR_FL_COORDINATOR_HTTP_API_KEY`（仍勿把进程暴露到公网）。Prometheus 若只在内网 scrape，与 **T-002** `/metrics` 例外一致。 |

---

## 1. 协调器（fl-coordinator）

| 检查项 | 说明 |
|--------|------|
| 配置权威 | 以 **`edr-backend/platform/docs/FL_COORDINATOR_P1.md`** 为准（环境变量名与《10》示例不一致时以本文档为准）。 |
| 数据库 | `DATABASE_DSN` 指向可写 MySQL；首次可 `EDR_FL_AUTO_MIGRATE=1`（需建表权限）。 |
| 安全 | 生产或跨团队联调建议 **`EDR_FL_COORDINATOR_HTTP_API_KEY`**；Agent **不得**把该 Key 打进镜像（仅运维/协调器侧）。 |
| 门禁脚本 | 在 **`edr-backend/platform`** 目录执行 **`scripts/fl_p1_e2e.sh`**（依赖本机 MySQL，见脚本头注释）；通过表示 **deadline 聚合 + FL3 上传** 链路可跑通。脚本在 deadline 后会 **sleep + 轮询 `has-aggregate`**，与协调器 **首轮立即 finalize 扫描**（`finalize_ticker.go`）对齐，避免竞态误报。 |

---

## 2. Agent（edr-agent）

| 检查项 | 说明 |
|--------|------|
| `[fl]` | `coordinator_http_url` 或 gRPC 地址与协调器监听一致；`tenant_id`、`agent_endpoint_id` 非空（按环境）。 |
| 梯度维 | 与 `fl_samples` / `model_target` 及 **`FL_SAMPLES_SCHEMA.md`** 维数一致。 |
| OpenSSL FL3 | 密封需要 **`EDR_HAVE_OPENSSL_FL`** 等构建选项时，以 **`FL_BUILD_AND_CI.md`** 为准。 |
| 与 proto 关系 | 上传载荷为 **FL3 密封梯度**，不是 **`AVE_ExportModelWeights`**（见 AG-031 文档）。 |

### 2.1 AVE 与 FL 接口（设计对齐与联调）

| 项 | 设计要求 / 代码事实 | 联调是否「顺」 |
|----|---------------------|----------------|
| **初始化顺序** | `agent.c` 先 **`AVE_InitFromEdrConfig`**，再 **`FLT_InitFromEdrConfig`**（`EDR_WITH_FL_TRAINER` 且 `[fl] enabled`） | 正确：AVE 就绪后注册 FL 样本桥 |
| **`AVE_ExportFeatureVector(Ex)`** | 经 **`edr_fl_feature_lookup_dispatch`** → **`fl_samples_db_register_ave_bridge`** 读 SQLite `feature_blob`；未命中 → `AVE_ERR_FL_SAMPLE_NOT_FOUND`（或 C0 全零回退路径） | 与 **`FL_SAMPLES_SCHEMA.md`**、**`ave_sdk.h`** 一致 |
| **训练线程数据路径** | `fl_round_trainer_thread_loop` 用 **`fl_samples_db_list_static_sha256`** + **`fl_local_train_mean_feature_delta`**，**不**在每样本上再调 `AVE_ExportFeatureVector` | 与 DB 内特征一致；与「通过 AVE 导出同 SHA」在**同一库**前提下等价 |
| **`model_target=behavior`** | 梯度维 **256**（`AVE_FL_FEATURE_DIM_BEHAVIOR_DEFAULT`）；枚举样本 SQL 仍为 **`model_target='static'`**（`fl_samples_db.c`） | **部分**：behavior 专用样本枚举与 `ExportFeatureVectorEx(...,BEHAVIOR)` 联调需单独灌库/扩 SQL（见 **`FL_ROUND_TRAINING_SEMANTICS.md`**） |
| **`fl_samples_lookup_bridge`** | 按 **sha256** 读 BLOB，**未**按 `target` 过滤；表 **PK=sha256** 时无冲突 | 与设计「一行一 SHA」一致；多 target 同行需不同 SHA |
| **`AVE_ImportModelWeights`** | **FL3** 密封梯度 **非** ONNX 权重：测试期望 **`AVE_ERR_NOT_SUPPORTED`**（`test_ave_fl_abi.c`） | **符合** ADR：联邦均值不直接当 ONNX 导入；下游 train_svc 转换 |
| **`[fl.frozen_layers]`** | 特征均值路径下 **`fl_frozen_layers_apply_feature_delta` 为占位** | 与 **T-015** / **`FL_ROUND_TRAINING_SEMANTICS.md`** 一致，非联调阻塞 |

**建议联调动作**：配置 **`[fl] fl_samples_db_path`** 与 **`EDR_HAVE_SQLITE`**；灌 **`fl_samples`** 后，进程内先 **`AVE_ExportFeatureVector(hex, buf)`** 与 **`fl_samples_db_read_feature`** 各抽一行比对 float；再跑一轮 Round 看 **`FL_ROUND_TRAINING`→上传** 是否成功。

**自动化（本机构建，含 macOS）**：在 **`edr-agent`** 构建目录执行 **`ctest -R fl_ave_samples_bridge --output-on-failure`**（需 CMake 找到 **SQLite**；测试名 **`fl_ave_samples_bridge`**，源文件 **`tests/test_fl_ave_samples_bridge.c`**：临时 **`fl_samples.db`**（**`tests/fixtures/fl_samples_schema.sql`** 与 **`FL_SAMPLES_SCHEMA.md`** 一致的全量 DDL）→ 桥接 → **`AVE_ExportFeatureVector` / Ex** 与 **`fl_samples_db_read_feature`** 一致性）。**`EDR_WITH_FL_TRAINER=ON`** 时 Round 线程若跳过训练，**stderr** 会出现 **`[fl] round skipped:`** 及原因（见 **`FL_P1_CONSOLE_AND_RUNBOOK.md` §4.5**）。

---

## 3. 平台 API（edr-api）

| 检查项 | 说明 |
|--------|------|
| FL 只读 | `GET /api/v1/admin/model/fl/rounds/current`、`GET .../rounds/:round_id` 需 **`FLRounds` 仓库** 已注入且租户有 `fl_*` 数据。 |
| QC 转发（可选） | 评测侧 **`POST .../admin/model/training/eval-report`** + **`EDR_FL_COORDINATOR_HTTP_URL`**（见 `platform/README.md`）。 |

---

## 4. 联调顺序建议

1. 启动 MySQL + fl-coordinator（见 **`FL_COORDINATOR_MINIMAL.md`**）。  
2. 跑通 **`fl_p1_e2e.sh`**。  
3. 起 edr-api，控制台打开 **模型管理 → 联邦学习**，确认 **当前 Round** 与 **`?round=<id>`** 单轮详情（前端 T-012）。  
4. 再接入真实 Agent 上传梯度，对照协调器 **`GET /metrics`**（`edr_fl_*`）与 DB **`fl_participants` / `fl_aggregate_runs`**。
