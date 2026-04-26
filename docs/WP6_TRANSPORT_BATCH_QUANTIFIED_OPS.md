# WP-6：传输与批处理「量化后」优化

> **「量化后」**指：在**已能读出或汇总**与传输/批次相关的**计数与比率**后，再改 **`[upload]`** 与 **传输环境变量**；避免仅凭主观「感觉慢/费 CPU」调参。  
> **相关**：**WP-2**（总线/预处理限载）、**WP-4**（gRPC/HTTP/回退）、**WP-5**（规则与批次内容量无直接关系，但**事件条数**影响批大小与压缩命中）、**WP-7**（`queue_pending` 与 `EDR_PERSIST_*` / 补传，见 `docs/WP7_OFFLINE_QUEUE_RETRY.md`）、**WP-8**（`wire_events=0` 时先查采集，见 `docs/WP8_ETW_COLLECTION_PROFILE.md`）、**WP-9**（行为 `BehaviorAlert` 帧进批/编码 前提，见 `docs/WP9_BEHAVIOR_AVE.md`）。

## 1. 先采什么（指标）

### 1.1 进程退出时汇总行（推荐）

设 **`EDR_AGENT_SHUTDOWN_LOG=1`** 或 **`EDR_AGENT_VERBOSE=1`**，正常停一次 `edr_agent` 后，stderr 会出现（见 `src/main.c`）：

| 字段 | 含义与粗看 |
|------|------------|
| `batches` | 已尝试发送的**批次数**（`edr_transport_batch_count`） |
| `batch_bytes` | 批总字节约量（**含** 12B 头与载荷） |
| `batch_lz4` | **BLZ4** 压缩批次数；长期为 0 且 `batch_bytes` 大时，可检查是否未过 LZ4 阈值（`event_batch.c` 中 `EDR_LZ4_MIN_IN` 等） |
| `batch_timeout_flushes` | **时间窗到点**而触发的刷批次数；相对 `batches` **过高** 常表示「事件稀疏但 `batch_timeout_s` 过短」或「单批很难攒满」 |
| `dedup_drops` / `rate_drops` | 预处理限流，与 **WP-2**、`[preprocessing]` 相关 |
| `queue_pending` | 离线队列积压（`queue_sqlite`） |
| `bus_dropped` / `bus_hw80` | 总线背压，**先**看 **WP-2** 再动 batch |

同次还会打 **`[grpc] rpc_ok/rpc_fail`**、**`[command]`** 等，与 **WP-4** 一起判断「上送是否健康」。

### 1.2 运行中

- 周期 **`[heartbeat]`**（`edr_agent`）：`batches` 是否随时间增长。  
- **`EDR_LOG_VERBOSE=1` 类**：`[transport]` 的 gRPC/HTTP 回退细节（见 **WP-4**）。

## 2. 调什么（与实现对齐）

| 配置 / 环境变量 | 作用 | 调优提示（在**有 §1 数据**后） |
|-----------------|------|----------------------------------|
| **`[upload] batch_max_size_mb`** | 单批缓冲**上限**（`edr_event_batch_init` 的 `max_bytes`） | 频繁触顶刷批、且 **latency 敏感** → 可略**降**以缩短单批等待（需结合 `batch_max_events`） |
| **`[upload] batch_max_events`** | 单批**最大帧数** | 高事件率且单帧小：可适当**加**，减少 `batches`/s；**反压**时先降总线/预处理，勿单加此项 |
| **`[upload] batch_timeout_s`** | 距**最后一次 push** 超过该秒数则**超时刷批**；`≤0` 行为以代码为准（见 `event_batch.c` / clamp） | **`batch_timeout_flushes` 占比高**、且希望**更合并** → 略**加**；希望**更快可见**上送 → 略**减**（可能增 QPS） |
| **`EDR_TRANSPORT_SEND_QUEUE_CAP`** | 异步发送队列深度（默认 **256**，范围 8–8192） | 上送线程追不上产生时，在确认**不是**平台持续 5xx 后，可**小步**加大；过大可能放大内存与尾延迟 |
| **LZ4** | 批原始体 ≥1KB 且压缩有效时用 **BLZ4** | 大批、可压缩内容多时 `batch_lz4` 应 >0；一直为 0 多为**未达阈值**或**载荷已极短**（非 bug） |

启动时现会打 **`[batch] batch_max_size_mb=… batch_max_events=… batch_timeout_s=…`** 与 **`[transport] send_queue_cap=…`**，便于与配置/文档对账（见下节「验收」）。

## 3. 与 WP-2 / WP-4 的分工

- **总线 `dropped` 高、预处理 L2/L3 大量丢**：先按 **WP-2** 缓载；**只**把 batch 调大**不能**从根上解决背压。  
- **`rpc_fail` 高、或 `[ingest-http]` 连不上**：**WP-4**；此时加大 `send_queue_cap` 只会**延长**失败重试前的排队。  
- **规则/直出**（P0、emit 量）：**WP-5**；若事件条数暴增，会间接推高对 `batch_max_events` / `batch_timeout_s` 的压力，指标上先看 **`batches` 与 `wire_events` 比**。

## 4. 完成标准（验收）

- [ ] 能说明 **`batch_timeout_flushes` 高** 与 **`batches` 多** 分别更可能对应 **哪一类** 调参（`batch_timeout_s` / `batch_max_events` 等）。  
- [ ] 改 `[upload]` 后，新启动日志中 **`[batch] …` 行** 与 TOML **一致**（重载若未重建 preprocess，须以**当前**实现为准：本仓库在 `edr_preprocess_start` 读配置）。  
- [ ] 至少用 **`EDR_AGENT_SHUTDOWN_LOG=1`** 采集过一次完整 shutdown 行，并保存为排障/灰度**前后对照**。  
- [ ] 在「平台侧延迟 / Agent CPU」目标下，有**可量化**的对比（如 shutdown 中 `batches`、或外部抓取的上送 QPS、P99），再冻结配置变更。

## 5. 交叉参考

- `edr-agent/include/edr/event_batch.h` — 批次与超时语义  
- `edr-agent/src/transport/transport_stub.c` — 异步队列、发送  
- `edr-agent/src/main.c` — shutdown 统计块（含 `queue_pending`；与 **WP-7** 对读）  
- `edr-agent/agent.toml.example` — `[upload]` 段  
