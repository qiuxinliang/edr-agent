# 真机行为管线 E2E 验收（Agent → platform → DB/API/可选前端）

目标：在**真实 Windows 终端**上跑 `edr_agent`，使 **behavior.onnx** 路径产生事件 → 批次上报 → 平台 **`ingest/report-events`** 落库 → **`GET .../processes/:pid/events`** 与告警列表可查到；与《11》及 **`BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`** §0.1 对齐。

实验室「无 ETW 真流量」时，用 **`edr-backend/scripts/smoke_i1_demo_ready.sh`**（内含 **`smoke_behavior_ingest.sh`**）做 **I1** 平台健康 + ingest + API 回归；或单独跑 **`smoke_behavior_ingest.sh`**（不等价于真机 ONNX 触发，见 §6）。

---

## 0. 与平台仓库联调顺序（建议）

1. **`edr-backend`**：`SKIP_LIVE=1 make dev-i1-execute`（嵌入 + 单测）  
2. 起 **`edr-api`** 后：`make smoke-i1-demo`  
3. 再按下文 **§1–§4** 配 Agent 与真机验收  

---

## 1. 平台与库（任意可达主机）

1. **MySQL**：执行 **`edr-backend/scripts/reset_local_edr_db.sh`**（含迁移 **`000020`** 与 demo 种子）。  
2. **platform**：按 **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`** §3 启动 **`edr-api`**（`DATABASE_DSN`、`DEMO_TENANT_ID`、`DEMO_USER_ID`）。  
3. **可选**：前端 **`edr-frontend`** + CORS；可选 **L2**（`EDR_L2_REVIEW_INTERVAL_SEC` 等）见 **`edr-backend/docs/L2_LLM_AND_BEHAVIOR_SERVER.md`**。  
4. **健康检查**：`curl -sS http://<api-host>:8080/healthz`（或文档中的 `/ready`）。

---

## 2. 真机 Agent 前置

| 项 | 说明 |
|----|------|
| **构建** | 目标机安装与 **`edr-agent`** 一致的产物（建议 **`-DEDR_WITH_ONNXRUNTIME=ON`**，并部署 **ONNX Runtime** 与 **`behavior.onnx`** 至 **`[ave].model_dir`**）。 |
| **身份** | **`[agent].tenant_id`** / **`endpoint_id`** 与种子一致（如 **`demo-tenant`** + **`ep-1`**）；勿用 `auto`，否则上报路径与控制台不一致。 |
| **平台上报** | **`[platform].rest_base_url`** 指向可达的 **`…/api/v1`**；若开 RBAC，配置 **`rest_bearer_token`** 或演示权限头（见 LOCAL_STACK §7）。 |
| **行为编码** | 联调平台 ingest 时设置 **`EDR_BEHAVIOR_ENCODING=protobuf`**（或 **`protobuf_c`**），避免批次内混 wire 导致 HTTP 解析失败（见 **`edr-backend/docs/BAT1_EVENT_INGEST.md`**）。 |
| **行为监控** | **`[ave] behavior_monitor_enabled = true`**，且进程内已 **`AVE_RegisterCallbacks`**（含 **`on_behavior_alert`**）；否则 **`AVE_StartBehaviorMonitor`** 不会起消费线程，事件仍同步处理但无 MPMC 背压形态。 |
| **联调模板** | 可复制 **`edr-agent/agent.integration.toml`** 为 **`agent.toml`**，改 **`endpoint_id`**、**`rest_base_url`** 为真机可达地址（内网联调可用 **`start_local_en0.sh all`** 模式，见 LOCAL_STACK §4 后「en0」节）。 |

---

## 3. Windows 真机上的推荐操作顺序

1. 以**管理员**或设计文档要求的权限运行 Agent（ETW/部分采集依赖）。  
2. 配置 **`[collection].etw_enabled=true`**（或与现场策略一致），确保有行为类事件进入预处理 → **`AVE_FeedEvent`**。  
3. 触发可产生 **文件/网络/注册表** 等行为的操作（或红队脚本），使 **`behavior.onnx`** 有机会推理并在超阈值时 **`on_behavior_alert`**。  
4. 等待 **gRPC 批次上报**或本地离线队列 **`[offline].queue_db_path`** 刷盘策略（视 `edr_agent` 实现与网络而定）。  
5. **停进程前**看 stderr：应出现 **`[ave/behavior] feed=… enq=… q_full_sync=…`** 等汇总行（见 **`AVE_GetStatus`** / **`main.c`**），用于判断队列背压与推理次数。

---

## 4. 验收用例（平台侧）

在 API 主机上（权限头与 LOCAL_STACK 一致）：

```bash
# 将 EP / PID 换成真机上报里出现的 endpoint 与进程号
curl -fsS -H "X-Tenant-ID: demo-tenant" -H "X-User-ID: demo-user" \
  "http://127.0.0.1:8080/api/v1/endpoints/ep-1/processes/<PID>/events?limit=20"

curl -fsS -H "X-Tenant-ID: demo-tenant" -H "X-User-ID: demo-user" \
  "http://127.0.0.1:8080/api/v1/alerts?limit=20"
```

- **成功**：`events` 返回中含 **`behavior_alert`** 相关字段或至少含该 **`pid`** 的 **`BehaviorEvent`** 轨迹；`alerts` 中可见行为告警行（迁移 **000020** 列）。  
- **失败**：先查 Agent 日志是否 **ingest 4xx**、是否未设 **`EDR_BEHAVIOR_ENCODING=protobuf`**、**`endpoint_id`** 是否与 DB 一致。

---

## 5. 前端（可选）

浏览器打开终端抽屉 → **行为告警 / 进程事件**（以当前前端路由为准）；需 **`VITE_DEMO_*`** 或 JWT 与租户一致。详见 **`edr-frontend/docs/STAGING_E2E_ACCEPTANCE_CHECKLIST.md`**（staging 全量时）。

---

## 6. 实验室替代（验证平台链路与 BAT1，非 ONNX 真触发）

在 **`edr-backend`** 目录、platform 已起、DB 已灌：

```bash
./edr-backend/scripts/smoke_behavior_ingest.sh
# 或：BASE=http://<api>:8080/api/v1 EP=ep-1 PID=4242 ./edr-backend/scripts/smoke_behavior_ingest.sh
```

该脚本用 **`edr-ingest-sample`** 生成 **BAT1 + protobuf** 负载，不经过真机 Agent ONNX。

---

## 7. 参考索引

| 文档 | 用途 |
|------|------|
| **`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`** | 灌库、起 API、前端、纯 HTTP 冒烟 |
| **`edr-backend/docs/BAT1_EVENT_INGEST.md`** | BAT1 头、protobuf、`behavior_alert` 字段 |
| **`edr-agent/docs/BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`** | 实施阶段与 B2 联调说明 |
| **`edr-agent/docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`** | AVE 生命周期、`AVE_GetStatus` 与队列 metrics |
