# 联邦学习 P1：控制台能力 + 真机联调提纲

**前置**：P0 文档 **`FL_GRADIENT_PROTO_CONTRACT_AG031.md`**、**`FL_JOINT_DEBUG_CHECKLIST.md`**；门禁脚本 **`edr-backend/platform/scripts/verify_fl_p0.sh`** / **`fl_p1_e2e.sh`** 跑通。

**开始 P1 工作**：代码侧 P1（协调器 + 只读 API + 控制台联邦 Tab）已具备；**P1 剩余是联调与验收**——按 **§4** 起 **edr-api + 协调器 + 控制台**（租户 **T**、库 **`edr`**、DSN 对齐，见 **`FL_JOINT_DEBUG_CHECKLIST.md` §0.2**）。

---

## 1. 平台 API（P1 新增 / 已有）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/admin/model/fl/rounds/current` | 当前租户最新 Round 摘要（已有，T-007） |
| GET | `/api/v1/admin/model/fl/rounds` | **P2**：租户 Round **列表**（`?limit=` 默认 20、最大 100，`?offset=`）；`items[]` 字段与下单轮摘要一致 |
| GET | `/api/v1/admin/model/fl/rounds/:round_id` | 指定 Round 摘要（已有） |
| GET | `/api/v1/admin/model/fl/rounds/:round_id/participants` | **P1**：`fl_participants` 只读列表（`endpoint_id`、`sample_count`、`received_at`），**不含梯度** |

---

## 2. 前端

- **模型管理 → 联邦学习**：`?round=<id>` 加载单轮摘要 + **参与者表**（调用上述 participants API）；**历史轮次**由 **`GET .../model/fl/rounds?limit=50&offset=…`** 驱动下拉与表格（`FederatedSection`），支持 **上一页 / 下一页 / 回到第一页**，与 **`?round=`** 联动。
- **模型运维 → 联邦学习架构**：顶部「当前 Round」卡片链到 **`/admin/ops/model/federated?round=<id>`**；架构图仍为示意，与 **`fetchModelOpsPanel('federated')`** 占位数据并存。

---

## 3. 真机联调提纲（环境就绪后逐项勾选）

1. 协调器 + MySQL + **`fl_p1_e2e.sh` 绿**。  
2. 至少 **2 台 Agent**（或 1 台 + 脚本模拟第二路梯度）向同一 `round_id` 上传 **FL3** 梯度，`tenant_id` / `endpoint_id` 与平台租户一致。  
3. **deadline** 后 DB **`fl_aggregate_runs`** 有行；控制台 **当前 Round** 与 **`?round=`** 摘要一致。  
4. **参与者表** 行数与 **`participant_count`** 一致。  
5. （可选）评测管线 **`POST /v1/fl/qc/metrics`** 或 **edr-api eval-report** 写入 QC，观察 **`qc_*` 字段**。

详细环境变量仍以 **`FL_COORDINATOR_P1.md`** 为准。

---

## 4. P1 工作启动（联调顺序）

> 目标：在 **与平台登录租户一致** 的 **T** 下，控制台能看到 **当前 Round**、**`?round=`** 单轮与 **参与者表**，并与 DB **`fl_*`** 一致。

### 4.1 环境

| 项 | 要求 |
|----|------|
| MySQL | 本机 **`edr`** 库已建；`verify_fl_p0.sh` 已绿则表与迁移可用 |
| **T** | 协调器 announce/梯度、Agent、JWT **`tid`**（或 demo **`X-Tenant-ID`**）同一租户；门禁脚本使用 **`e2e_tenant`**，控制台联调请改用你平台真实租户或向 **`fl_rounds`** 灌入 **T** 的轮次数据 |
| DSN | **fl-coordinator** 与 **edr-api** 使用同一 `DATABASE_DSN` 形态，例如 `USER:PWD@tcp(127.0.0.1:3306)/edr?parseTime=true` |
| 暴露 | 内网-only 时可不配置协调器 API Key（见 **`FL_JOINT_DEBUG_CHECKLIST.md` §0.2**） |

### 4.2 进程（示例端口）

**顺序**：先起 **fl-coordinator**（`:8081`），再起 **edr-api**（`:8080`），避免端口冲突；DSN 与 §4.1 一致。

1. **fl-coordinator**（与 `verify_fl_p0.sh` / **`FL_COORDINATOR_P1.md`** 一致）：  
   - **推荐**：`cd edr-backend/platform && ./scripts/start_fl_coordinator_p1.sh`  
     默认 `DATABASE_DSN` 与 **`edr-backend/scripts/restart_local_edr_api.sh`** 对齐；`EDR_FL_COORDINATOR_LISTEN=:8081`；`EDR_FL_AUTO_MIGRATE=1`、`EDR_FL_AGG_WINDOW=deadline`、`EDR_FL_FINALIZE_POLL_SECONDS=1`；未设置 `EDR_FL_COORDINATOR_SECP256R1_PRIV_HEX` 时脚本会生成临时 hex。  
     后台启动时：**日志** `/tmp/fl-coordinator-p1.log`，**pid** `/tmp/fl-coordinator-p1.pid`；就绪后脚本会 `curl` **`http://127.0.0.1:8081/health`**。  
     **前台**：`./scripts/start_fl_coordinator_p1.sh fg`（Ctrl+C 退出）。  
     **停止**：`kill "$(cat /tmp/fl-coordinator-p1.pid)"`（或按 pid 结束进程）。  
   - **手动**（等价）：`cd edr-backend/platform && go build -o fl-coordinator ./cmd/fl-coordinator && ./fl-coordinator`（环境变量同上）。
2. **edr-api**（与平台前端联调）：`DATABASE_DSN` 同上；`JWT_SECRET` 等与本地一致。  
   可用 **`edr-backend/scripts/restart_local_edr_api.sh`**（默认 `:8080`），或 `go run ./cmd/edr-api`（在 **`edr-backend/platform`** 下、且 `go.work` 正确）。联调前可 **`curl -fsS http://127.0.0.1:8080/healthz`**（以实际路由为准）。
3. **前端**：`VITE_*` 指向 **`http://127.0.0.1:8080`**（或你的 API 基址），登录租户 **T**。

### 4.3 验收勾选

**租户与 JWT**：库内轮次在 **`e2e_tenant`**（门禁）或你的 **T** 时，登录 **`POST /api/v1/auth/login`** 需带 **`X-Tenant-ID: <T>`**（与 **`FL_JOINT_DEBUG_CHECKLIST.md` §0.1-A** 一致），否则默认 JWT **`tid=demo-tenant`**，**`.../rounds/current`** 会对无数据租户返回 **404**（JSON：`no federated learning rounds for tenant`）。  

**API 快速验收**（本机 **`restart_local_edr_api.sh`** 后、`curl` 示例）：  
`TOKEN=$(curl -fsS -X POST http://127.0.0.1:8080/api/v1/auth/login -H 'Content-Type: application/json' -H 'X-Tenant-ID: <T>' -d '{"username":"admin","password":"admin123"}' | jq -r '.data.access_token')`  
→ **`GET /api/v1/admin/model/fl/rounds/current`**、**`GET .../rounds/<id>`**、**`GET .../rounds/<id>/participants`**（Bearer）。若 **`participants`** 为 Gin 纯文本 **`404 page not found`**，多为运行中 **`edr-api` 二进制过旧**，请重新执行 **`edr-backend/scripts/restart_local_edr_api.sh`** 再测。

- [ ] **`GET /api/v1/admin/model/fl/rounds/current`**（Bearer）返回与 **`fl_rounds`**（租户 **T**）最新一条一致。  
- [ ] **`GET .../rounds/:round_id`**、**`GET .../rounds/:round_id/participants`** 与 **`participant_count`** / 行数一致。  
- [ ] 浏览器：**模型管理 → 联邦学习**，**`?round=<id>`** 有单轮摘要 + 参与者表；**模型运维 → 联邦学习架构** 当前 Round 卡片可跳转。  
- [ ] （可选）≥2 Agent 或「1 真机 + 1 脚本」梯度上传，deadline 后 **`fl_aggregate_runs`** 有行；控制台 **has_aggregate** 等与 DB 一致。  
- [ ] （可选）聚合后 WS 刷新：配置 **`EDR_INTERNAL_FL_WS_KEY`** + **`EDR_FL_PLATFORM_WS_NOTIFY_*`**（见 **`FL_COORDINATOR_P1.md`** §控制台 WebSocket）。

### 4.4 与 P0 门禁的关系

| 维度 | **`verify_fl_p0.sh`（自动化 P0）** | **§4.3 控制台 / API 验收（P1）** |
|------|-----------------------------------|----------------------------------|
| 命令 | `cd edr-backend/platform && ./scripts/verify_fl_p0.sh` | §4.2 起 **edr-api + 协调器** + §4.3 **`curl`/浏览器** |
| 证明内容 | MySQL 可达；**`fl_p1_e2e.sh`** 在临时协调器上跑通 **FL 写库 + deadline 聚合**（租户固定 **`e2e_tenant`**）；**`go build ./cmd/fl-coordinator`** | 在**你选定的租户 T** 下，**只读 API** 与 **`fl_*`** 一致；前端页可见 |
| **不**覆盖 | 控制台登录、JWT **`tid`**、**`X-Tenant-ID`**、浏览器路由 | E2E 脚本是否绿、协调器能否从零编译（由 P0 脚本保证） |

- **`verify_fl_p0.sh`** **不替代** §4.3：门禁用 **`e2e_tenant`** 灌库，若控制台登录的是 **`demo-tenant`** 或其它 **T** 而未对齐，**`GET .../rounds/current`** 仍可能空或 404（见 §4.3）。  
- **P1 收口**：§4.3 勾选完成 **且** 手动 P0 **A/B/C**（**`FL_JOINT_DEBUG_CHECKLIST.md` §0.1**）——租户同库、生产面安全——与 **`verify_fl_p0.sh` 绿** 一并作为发布前检查；日常可 **`verify_fl_p0.sh`** 回归链路，**§4.3** 在发版或改联邦控制台前再跑一遍。

### 4.5 Agent 联邦侧（`model_target` / `frozen_layers` / `fl_samples.db`）

- **`[fl] model_target=behavior`**：本地 Round 训练向量维数为 **256**，但 **`fl_samples_db_list_*` 当前仍只枚举 `model_target='static'`**。若库里仅有 behavior 行而无 static 行，Round 会因 **`min_new_samples`** 不满足而跳过；属预期，**勿**与「协调器无公告」混淆。端侧跳过时会向 **stderr** 打 **`[fl] round skipped:`** 原因（样本不足 / 枚举失败 / 隐私预算 / `fl_local_train_mean_feature_delta` 失败）。
- **`[fl.frozen_layers]`**（T-015）：当前联邦路径使用 **特征向量均值作伪梯度**，**`fl_frozen_layers_apply_feature_delta` 不改变数值**；`frozen_layer_names` 仍随梯度上传 JSON 供协调端审计与后续张量联邦。控制台与验收**勿**按《10》理解为「已冻结 ONNX 某层参数」。
- **回归**：本仓库 **`ctest -R fl_ave_samples_bridge`**（需 SQLite）验证 **`fl_samples.db` 全量 schema** + AVE 桥接 + `AVE_ExportFeatureVector`；与 **`verify_fl_p0.sh`** 互补（后者不编译 edr-agent C 测试）。
