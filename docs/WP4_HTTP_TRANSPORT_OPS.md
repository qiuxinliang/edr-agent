# WP-4：HTTP / gRPC 传输可运营与排障

> **目标**：在**不读** `transport_stub.c` / `event_batch.c` 的前提下，能根据**启动几行**与**周期 `[heartbeat]`** 判断：当前是 **gRPC 为主**、**HTTP 为主** 还是 **INGEST 分流**；并知道常见失败应查 **WP-1（平台）**、**WP-2（总线/预处理）** 还是 **WP-3（身份/REST 根）**。

> **相关**：**WP-1**（`edr-backend/docs/WP1_ALERT_INGEST_E2E.md`）、**WP-2**（`docs/WP2_EVENT_BUS_PREPROCESS.md`）、**WP-3**（`docs/WP3_CONFIG_VALIDATION.md`）、**WP-5**（`docs/WP5_RULES_ENGINEERING.md`，规则/版本，非网络栈）、**WP-6**（`docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`，`[upload]`/**shutdown 指标**）、**WP-7**（`docs/WP7_OFFLINE_QUEUE_RETRY.md`，失败落盘/补传）、**WP-8**（`docs/WP8_ETW_COLLECTION_PROFILE.md`，无事件无 ingest）、**WP-9**（行为 protobuf 上送/编码 与 P0/静态 不混，见 `docs/WP9_BEHAVIOR_AVE.md`）。全 HTTP 化路线图见仓库根 **`docs/AGENT_HTTP_ONLY_INGEST_DESIGN.md`**。

## 1. 启动时最先看的三行

| 日志前缀 / 行 | 含义 |
|----------------|------|
| **`[config] WARN:`**（可能多条） | **WP-3**：REST 根、`endpoint_id`、`tenant_id` 与平台联调是否一致。 |
| **`[transport] HTTP ingest: <url>`** | 已解析出**有效**平台 REST 根（`EDR_PLATFORM_REST_BASE` 优先于 `[platform].rest_base_url`），HTTP 上送/轮询/部分回执会用它。 |
| **`[transport] EDR_EVENT_INGEST_SPLIT=on\|off`** | **`on`**：批次在 flush 时拆成**两路**（见 §2）；**`off`**：整批走 `edr_transport_on_event_batch` 的**单一路径**（见 `transport_stub.c`）。 |
| **`[preprocess/config] …`** | **WP-2**：L2/L3/门控等。 |
| **`[heartbeat] grpc=… http=… batches=…`** | **周期**（默认与 `[server].keepalive_interval_s` 相关）：`grpc` 是否**已就绪**；`http` 是否**已配置** ingest 基址；`batches` 为已尝试发送的批次数。`EDR_LOG_VERBOSE=1` 时字段更多。 |

## 2. `EDR_EVENT_INGEST_SPLIT`（分流）

- **条件**：环境变量**非** `0`/空，且 **HTTP ingest 已配置**（与 `ingest_split_enabled()` 一致）。  
- **行为**（`event_batch.c`）：对批次内**每一帧**用 nanopb 解 `BehaviorEvent`；**带 `behavior_alert` 的帧**进 **gRPC 通道**（`use_http=0`），**其余帧**进 **HTTP 通道**（`use_http=1`）。两路各自生成子 `batch_id` 后缀 `-g` / `-h`。  
- **gRPC 未就绪时**：`transport_stub` 对**本来走 gRPC 的那路**仍可能改走 **HTTP**（与 stub 里「gRPC 未建链则 HTTP」一致），故 **`SPLIT=on` 且 gRPC 未起** 时，**两路最终都可能表现为 HTTP 尝试** — 以 `[ingest-http]` 与 **WP-1 平台** 是否绿为准。  
- **`SPLIT=off`**：不拆批，**整批**走 `edr_transport_on_event_batch` → 发送线程里再决定 gRPC 或 HTTP（含 gRPC 失败回退 HTTP 等）。  

## 3. 与 gRPC 回退、SQLite 队列相关的环境变量

| 变量 | 作用（摘要） |
|------|----------------|
| `EDR_EVENT_GRPC_FALLBACK_HTTP` | 非 `0`/`false` 时，**gRPC `ReportEvents` 失败**后若已配 HTTP 根，则**再试 HTTP**；设为 `0` 则**不**回退。 |
| `EDR_TRANSPORT_LOG_EVERY_HTTP_FALLBACK` | 为真时，**gRPC 未就绪走 HTTP** 的日志可按批重复（否则多数路径只打一次/verbose）。 |
| `EDR_PERSIST_STRATEGY=on_fail` | 与 `queue_sqlite` 等配合时，**发送失败**才入队（见 `transport_stub` / 队列实现）。 |
| `EDR_PERSIST_QUEUE=1` | **每批**尽力落队（`event_batch.c` `maybe_persist`），与上不同，用于**审计/补传**场景。 |
| `EDR_TRANSPORT_SEND_QUEUE_CAP` | 发送侧异步队列深度（默认范围实现内 clamp）。 |
| `EDR_ALLOW_SHELL_CURL_FALLBACK` | 允许 **popen(curl)** 回退；默认关闭时见 **`[ingest-http] … curl fallback disabled`**。生产建议 **libcurl** 路径成功，勿依赖 shell。 |

**下行指令**（HTTP 长轮询）与 **`[ingest-http] GET … poll-commands`** 类日志：见 `ingest_http.c` 与 `docs/AGENT_HTTP_ONLY_INGEST_DESIGN.md` §3；若轮询失败，先确认 **平台可达** 与 **WP-3** 身份一致。

## 4. 常见现象 → 往哪查

| 现象 | 优先查 |
|------|--------|
| `Failed to connect` / 连接拒绝对 `<host:port>` | 平台未监听、防火墙、或 REST **根 URL 写错**（**WP-3** + `LOCAL_STACK`）。 |
| HTTP **403/404** 于 `report-events` / `poll-commands` | 租户/endpoint 与库不一致、路径非 `/api/v1/...`（**WP-3** WARN `/api/`，**WP-1** 脚本先验平台）。 |
| `grpc=0` 长期、`batches` 不增 + **总线/预处理无问题** | gRPC 未起或地址错；若已配 HTTP，流量可走 HTTP（看 **`[ingest-http]`**）。 |
| **WP-1 脚本草稿绿**、真机 **无** `alerts` | **WP-2**（L2/L3/门控/无 `BehaviorAlert` 帧）+ 本文 §2 是否**误以为走了 gRPC** 而实际全进 `endpoint_events`。 |
| 仅 healthz 通、业务 API 全挂 | 根 URL 只配到 `http://host:port` **无** `/api/`（**WP-3** 会 WARN）。 |

## 5. 完成标准（验收）

- [ ] 能口述：**`EDR_EVENT_INGEST_SPLIT=off`** 与 **`on`** 时，批次在传输层的**走法差异**（§2）。  
- [ ] 能在一次启动日志中指认：**`[transport] HTTP ingest`**、**`EDR_EVENT_INGEST_SPLIT`**、**`[heartbeat] grpc= http= batches=`** 三处。  
- [ ] 遇到 **`[ingest-http]` 连接错误** 时，能按 **WP-3 → LOCAL_STACK → WP-1** 顺序缩小范围。  
- [ ] 知悉 **`EDR_EVENT_GRPC_FALLBACK_HTTP=0`** 会关闭 gRPC 失败后的 HTTP 回退，用于**刻意隔离** gRPC 问题。  

## 6. 交叉参考

- `edr-agent/src/transport/transport_stub.c` — 发送、回退、异步队列。  
- `edr-agent/src/transport/event_batch.c` — `EDR_EVENT_INGEST_SPLIT`、BAT1 压缩。  
- `edr-agent/src/transport/ingest_http.c` — libcurl、POST/GET、multipart。  
- `edr-agent/src/core/agent.c` — `[heartbeat]` 详细字段（verbose）。  
- `edr-agent/docs/WP5_RULES_ENGINEERING.md` — 若 `batches>0` 仍无期望告警/规则，查规则包与 P0 版本。  
