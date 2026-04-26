# WP-7：离线队列与重试策略统一

> **目标**：把 **SQLite 离线队列**、**何时落盘**、**出队补传** 与 **重试/退避** 的环境变量，收敛到**一张表、一套心智模型**，与 **WP-4**（gRPC/HTTP）、**WP-6**（批次/上送吞吐）**对照排障**。

> **相关**：`docs/AGENT_HTTP_ONLY_INGEST_DESIGN.md` §6（HTTP 与队列同构上送）、**WP-4**、**WP-6**、**WP-8**（`wire_events=0` 时队列为空属正常，见 `docs/WP8_ETW_COLLECTION_PROFILE.md`）、**WP-9**（`on_behavior_alert` 未注册/编码不对时行为帧缺失，与队列无关，见 `docs/WP9_BEHAVIOR_AVE.md`）。

## 1. 三件套

| 能力 | 说明 |
|------|------|
| **库** | 可选 `EDR_HAVE_SQLITE`；`edr_storage_queue_open` 打开 `[offline].queue_db_path` 或 **`EDR_QUEUE_PATH`** 覆盖（见 `main.c`） |
| **入队** | 两条**互斥语义**的触发（见 §2） |
| **出队** | `edr_storage_queue_poll_drain` 在预处理主循环中调用；gRPC 就绪则**先试 gRPC**，失败或未就绪再 **HTTP ingest**（`queue_sqlite.c` 与上送主路径**同一载荷**） |

## 2. 何时写入队列（`EDR_PERSIST_STRATEGY` vs `EDR_PERSIST_QUEUE`）

| 模式 | 环境变量 | 行为 |
|------|------------|------|
| **仅发送失败**（推荐缺省联调外） | **`EDR_PERSIST_STRATEGY=on_fail`** | 仅在 `transport_stub` 一次发送（gRPC+可选 HTTP 回退）**仍失败** 后 `enqueue`。**不**在「成功刷批」时落盘。 |
| **每批都落**（审计/强持久） | **`EDR_PERSIST_QUEUE=1`** 且 **未**设 `on_fail` 为**唯一**策略时 | 在 `event_batch.c` **flush 成功构建 wire 后** 仍尝试入队（与 `on_fail` **二选一**语义：`on_fail` 时 `maybe_persist` 直接**不**走「每批落盘」） |

- **同时想「失败才落盘」又记「每批双份」**在实现中**不成立**：`maybe_persist` 在 `on_fail` 时**整段 return**。  
- **无 SQLite 编译/未打开库**：`edr_storage_queue_is_open()` 为 0，**on_fail 路径也不会入队**；需确认构建带 SQLite 且路径可写。

## 3. 出队、节流与重试

| 变量 | 默认（实现内） | 含义 |
|------|----------------|------|
| **`EDR_QUEUE_MAX_RETRIES`** | 100 | `retry_count` 达上限则**删行**并打 `[queue] 达最大重试` |
| **`EDR_QUEUE_RETRY_BACKOFF_BASE_MS`** | 200 | 连续上传失败时指数退避的**基**（ms，clamp 10–5000） |
| **`EDR_QUEUE_RETRY_BACKOFF_MAX_MS`** | 5000 | 退避**上界**（ms，clamp 100–60000） |
| **`EDR_QUEUE_MAX_DB_MB`** | 未设=不检查 | 库文件大小超限时**拒绝新入队**（防磁盘打满） |

- **`poll_drain` 内**：两次调用至少间隔约 **200ms**；每轮最多连续处理 **32** 行；**单次发送失败**（`drain_one` 返回 2）时设置 `s_retry_not_before_ns` 为指数退避，**暂停**本轮回删。  
- **补传顺序**与现网主路径一致：**gRPC 可用 → 先发 gRPC**，否则/失败 → **HTTP**（与 `transport` 的 HTTP 回退**对齐**思想）。

## 4. 与其它 WP 的分工

| WP | 关系 |
|----|------|
| WP-2 | 总线满、L2/L3 丢是**上送前**；队列解决**上送后失败**的尾包。 |
| WP-4 | 若 `rpc_fail` 高且 **`queue_pending`** 长，应区分「平台问题」与「无 REST / 无队列」。 |
| WP-6 | `batches` 大但 `queue_pending` 不降 → 查 §2 是否 `on_fail`、**平台是否长期 5xx**、**退避是否打满**间隔。 |
| **WP-7**（本文）| **入队条件 + 出队重试** 的**统一**操作说明。 |

## 5. 完成标准（验收）

- [ ] 能说明 **`on_fail` 与 `EDR_PERSIST_QUEUE=1`** 谁**抑制**谁（§2）。  
- [ ] 能读出启动时一行 **`[queue] sqlite=…`** 中的 `on_fail_persist` / `persist_every_flush` / `max_retries` / `backoff_ms`（与当前环境一致）。  
- [ ] 排障时同时看 **shutdown 的 `queue_pending`（`main.c`）** 与 **WP-4 网络/ingest 日志**。

## 6. 参考

- `edr-agent/src/storage/queue_sqlite.c`  
- `edr-agent/src/transport/transport_stub.c`（`enqueue_wire_on_fail`）  
- `edr-agent/src/transport/event_batch.c`（`maybe_persist`）  
- `edr-agent/include/edr/storage_queue.h`  
