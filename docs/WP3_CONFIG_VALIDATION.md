# WP-3：配置管理优化（启动语义类 WARN）

> **目标**：在**语法合法**的 TOML/环境变量下，对**易静默误配**的项在启动/重载时于 **stderr** 打 **`[config] WARN:`**，与 WP-1（平台先验）、WP-2（总线/预处理可运营）、**WP-4**（HTTP/gRPC 传输排障，见 `docs/WP4_HTTP_TRANSPORT_OPS.md`）、**WP-5**（规则包/版本，见 `docs/WP5_RULES_ENGINEERING.md`）、**WP-6**（`[upload]`/shutdown 指标，见 `docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`）、**WP-7**（`EDR_PERSIST_*` / `EDR_QUEUE_*` / `[offline].queue_db_path`，见 `docs/WP7_OFFLINE_QUEUE_RETRY.md`）、**WP-8**（`[collection]`/ETW 与 P0 底线，见 `docs/WP8_ETW_COLLECTION_PROFILE.md`）、**WP-9**（`[ave]` 与 `EDR_BEHAVIOR_*`，见 `docs/WP9_BEHAVIOR_AVE.md`）可对照排查。

## 1. 生效时机

- **`edr_config_load` 成功**、**`edr_config_clamp` 之后**调用 **`edr_config_log_semantic_warnings`**。  
- **`edr_config_reload_if_modified` 重载**走同一 `edr_config_load` 路径，**无需额外步骤**。  
- **无 TOML**（`--config` 未设）：仍应用 **defaults**；若设了 `EDR_PLATFORM_REST_BASE`，同样会校验。

## 2. 规则表（与实现一致）

| 条件 | 行为 |
|------|------|
| 有效 REST 根**非空** | `EDR_PLATFORM_REST_BASE` 优先，否则 TOML **`[platform].rest_base_url`** |
| 非空且**不以** `http://` / `https://` 开头 | **WARN**（scheme/拼写易错） |
| 以 `http`/`https` 开头但 URL 中**无**子串 `/api/` | **WARN**（多仅为 **healthz-only** 根时属预期，可忽略；ingest/攻击面需全 API 根，如 `http://host:8080/api/v1`） |
| 上述有效 REST 非空，且 **`[agent].endpoint_id`** 为 **空** 或 **`auto`** | **WARN**（与 `LOCAL_STACK` 种子、`POST …/attack-surface` 身份一致要求） |
| 上述有效 REST 非空，且 **`[agent].tenant_id`** 为 **空** 或仍为默认占位 **`tenant_default`** | **WARN** |

**未**配置平台 REST 时：本 WP **不**对 `endpoint_id` / `tenant_id` 发 WARN，避免纯离线/仅 gRPC 实验环境刷屏。

## 3. 与 `agent.toml.example` / 环境变量

- 示例中 **`[agent].endpoint_id = "auto"`**、**`tenant_id = "tenant_default"`** 在**启用** `[platform].rest_base_url` 或 `EDR_PLATFORM_REST_BASE` 时会在启动时触发 WARN — **联调/生产**请改为**库中已注册**的 `endpoint_id` 与真实 `tenant_id`。  
- 权威联调表：**`edr-backend/docs/LOCAL_STACK_INTEGRATION.md`**（同 WP-1 README 互链）。

## 4. 与 WP-1、WP-2 的分工

| WP | 关注点 |
|----|--------|
| WP-1 | 平台 `ingest` → `alerts` 最短验证（与 Agent 无关时亦可跑） |
| WP-2 | 总线背压、L2/L3/进程名门控、**实验室 vs 生产** profile |
| **WP-3**（本文）| **TOML + 环境** 与**平台联调**相关的**语义**提示（stderr） |
| **WP-4** | **传输层**：`[transport]` / `EDR_EVENT_INGEST_SPLIT`、`[ingest-http]`、与 gRPC 回退 |
| **WP-5** | **规则工程化**：`dynamic_rules_v1`、预处理 TOML、P0 IR、**版本对账** |
| **WP-6** | **批/传输调优**：先 **`EDR_AGENT_SHUTDOWN_LOG=1` 等** 采指标，再动 **`[upload]`** / 队列 cap |
| **WP-7** | **SQLite 离线队列入队/出队**：`EDR_PERSIST_STRATEGY` vs `EDR_PERSIST_QUEUE`、`EDR_QUEUE_*` |
| **WP-8** | **ETW/采集**、**P0 字段矩阵** 与 `[collection]` / `EDR_ETW_OBS` |

## 5. 完成标准（验收）

- [ ] 仅配 **`EDR_PLATFORM_REST_BASE=http://127.0.0.1:8080/api/v1`**（defaults 的 `auto` + `tenant_default`）时，启动可见 **至少两条** 与 `endpoint`/`tenant` 相关的 `[config] WARN`  
- [ ] 将 `endpoint_id` / `tenant_id` 改为与灌库一致后，上述 WARN **消失**（在 REST 根仍非空时）  
- [ ] 将 REST 根写成无 scheme 的 `127.0.0.1:8080/...` 时，**scheme** 相关 **WARN 出现**  
- [ ] `edr_config_reload_if_modified` 改配置并触发重载后，行为与首次加载一致

## 6. 交叉参考

- `edr-agent/include/edr/config.h` — `edr_config_log_semantic_warnings` 声明（工具进程亦可链接后复用，当前 **Agent 在 load 内调用** 即可）  
- `edr-agent/agent.toml.example` — `[agent]` / `[platform]` 注释  
- `edr-backend/docs/WP1_ALERT_INGEST_E2E.md`、`edr-agent/docs/WP2_EVENT_BUS_PREPROCESS.md`  
- `edr-agent/docs/WP4_HTTP_TRANSPORT_OPS.md`  
- `edr-agent/docs/WP5_RULES_ENGINEERING.md`  
- `edr-agent/docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`  
- `edr-agent/docs/WP7_OFFLINE_QUEUE_RETRY.md`  
- `edr-agent/docs/WP8_ETW_COLLECTION_PROFILE.md`  
- `edr-backend/docs/LOCAL_STACK_INTEGRATION.md`
