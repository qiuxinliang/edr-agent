# WP-2：事件总线背压与预处理策略（可运营）

> **相关**：**WP-1** 平台先验（`edr-backend/docs/WP1_ALERT_INGEST_E2E.md`）；**WP-3** 配置语义与启动 WARN（`docs/WP3_CONFIG_VALIDATION.md`）；**WP-4** HTTP/gRPC 传输与 `EDR_EVENT_INGEST_SPLIT`（`docs/WP4_HTTP_TRANSPORT_OPS.md`）；**WP-5** 规则工程化与 `[[preprocessing.rules]]` 语义（`docs/WP5_RULES_ENGINEERING.md`、`docs/PREPROCESS_RULES.md`）；**WP-6** 批/传输调优前先看 **shutdown 指标**（`docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`）；**WP-7** 离线 **SQLite** 队列/重试（`docs/WP7_OFFLINE_QUEUE_RETRY.md`）；**WP-8** **先** 采集合规/ETW（`docs/WP8_ETW_COLLECTION_PROFILE.md`）再动本 WP；**WP-9** 跨引擎喂入 → 行为管线/回调/批次（`docs/WP9_BEHAVIOR_AVE.md`）。  

> **目标**：让运维与研发在**不读 C 源码**的情况下，能根据**日志关键词**和**环境变量**选择「实验室易出数」与「生产更稳载」两档，并理解**丢事件**发生在哪一层。

## 1. 数据在端上的处理顺序（简图）

1. **采集（ETW 等）** → `edr_event_bus_try_push`  
   - 总线**满**时：`try_push` 失败，事件**丢弃**（`edr_event_bus_dropped_total` 累加；`[self_protect]` 周期性打 `[self_protect] 事件总线占用 … dropped=…`）。  
2. **预处理线程** 从总线 `pop` → 组 `EdrBehaviorRecord`  
3. **进程名门控**（`EDR_PREPROCESS_PROCNAME_GATE`）：未过门控的 `process_create` 可抽样丢弃。  
4. **L2 分流**（`EDR_PREPROCESS_L2_SPLIT=1` 时）：未命中 TOML `emit_always` 的**行为类进程事件**按比例丢弃（实现里 **L2_KEEP_RATIO 上限 0.10**）。  
5. **L3 高压**（`EDR_PREPROCESS_L3_PRESSURE=1` 时）：总线**使用率**超阈值时，对**非高价值** slot 按千分比随机丢弃。  
6. `edr_preprocess_should_emit`：TOML **drop/emit**、**dedup**、**限流**  
7. 编码进批次 → 传输

**产品含义**：总线满 = **以丢事件保 Agent 进程不拖死**；L2/L3 = **在预处理里再限载**。两者叠加时，**实验室「看不到告警」** 很常见，需**有意放松**本文件 §3 的 profile。

## 2. 日志里看什么

| 日志 | 含义 |
|------|------|
| `[preprocess/config] L2_SPLIT=… L2_KEEP_RATIO=… L3_PRESSURE=… … PROCNAME_GATE=…` | 当前预处理开关快照（**stderr 启动时一行**） |
| `[self_protect] 事件总线占用 N%（阈值 M%）… dropped=D` | 总线水位与**累计**丢弃；`D` 持续增长说明采集仍快于消费 |
| `[ave/bp]…` / ONNX 相关 | 行为模型链，**不是**本 WP 重点 |

**注意**：L2/L3/门控的**分计数**当前主要在实现内；排障时以**启动行 + self_protect 行**为主。若需 **Prometheus 化**，另立任务挂指标（不在 WP-2 文内假设施已完成）。

## 3. 两档环境变量（推荐）

> **使用方式**（Windows `cmd`）：`set` 各变量后**同一会话**再启动 `edr_agent.exe`；服务需把变量写进**服务环境**；Linux **export** 后启动。  
> **TOML**：`[collection] max_event_queue_size`、`[preprocessing] sampling_rate_whitelist` 与 L2 默认值相关，见下表。  
> 示例文件：`edr-agent/config/profiles/wp2_lab_e2e.env.example`、`wp2_prod_default.env.example`（**复制后按需改，勿提交带密钥的副本**）。

### 3.1 实验室 / E2E / 与 WP-1 对照（**易出数**）

| 变量 | 建议值 | 说明 |
|------|--------|------|
| `EDR_PREPROCESS_L2_SPLIT` | `0` | 关闭 L2 抽样，避免 **emit 未命中** 时大量掉事件 |
| `EDR_PREPROCESS_L3_PRESSURE` | `0` | 关闭 L3 高压丢载，便于对照「是否上送问题」 |
| `EDR_PREPROCESS_PROCNAME_GATE` | `0` | 关闭进程名门控，减少随机丢 |
| `EDR_BEHAVIOR_USER_SUBJECT_JSON` | 不设或调试短 JSON | 仅调试用，见 `agent.toml.example` 注释 |
| TOML `max_event_queue_size` | `8192`～`16384`（在合法上限内） | 高噪机降低总线 `dropped` 斜率，视内存调整 |

P0/告警与 **WP-1** 先验后，可再开 **`EDR_P0_DIRECT_EMIT=1`** 做真机 **P0 直出**（见 `EDR_P0_DIRECT_EMIT_E2E.md`）。

### 3.2 生产 / 高噪机（**更稳、更可能丢非关键**）

| 变量 | 建议 | 说明 |
|------|------|------|
| `EDR_PREPROCESS_L2_SPLIT` | `1` | 降低「未匹配 emit 规则」的流量；配合 **`EDR_PREPROCESS_L2_KEEP_RATIO`**（≤ **0.10** 硬上限） |
| `EDR_PREPROCESS_L3_PRESSURE` | 视情况 `1` | 总线长期高位时与 L2 **叠加**；`L3_HIGH_PCT` / `L3_RECOVER_PCT` / `L3_DROP_PERMILLE` 见 `agent.toml.example` |
| `EDR_PREPROCESS_PROCNAME_GATE` | `1` | 默认开；`PROCNAME_GATE_KEEP_UNKNOWN_PERMILLE` 控制**未知名**保留比例（默认实现里 **100**=10% 档，以启动日志为准） |
| TOML `max_event_queue_size` | 按机内存在 **4096**～**65536** 间调 | 大队列换内存，需压测 |
| `EDR_PREPROCESS_STRICT_BEHAVIOR_GATE` | 一般 `0` | 仅压测/验证时 `1`（**仅**少量事件类型进下游） |

**与 `sampling_rate_whitelist`**：`EDR_PREPROCESS_L2_KEEP_RATIO` 未设时，默认取 TOML **`preprocessing.sampling_rate_whitelist`**（见 `preprocess_init_l2_l3_controls`）。

## 4. 其它相关环境变量

| 变量 | 作用 |
|------|------|
| `EDR_PREPROCESS_THROTTLE` = `1` | **强制**预处理器节电模式（`edr_resource_preprocess_throttle`）；**POSIX** 上 CPU/内存紧急时也会置位 |
| `EDR_RESOURCE_STRICT` = `1` | 与 **低** `cpu_limit_percent` 联用才严格打 resource 日志（见 `resource.c`） |
| `EDR_CONFIG_RELOAD_S` | 正整数时周期性重载 **preprocessing** 等，**不**重连传输；调参可免重启（仍建议大改后重启） |

`[self_protect] event_bus_pressure_warn_pct`：仅**告警阈值**（何时打 `self_protect` 行），**不**改变丢弃逻辑。

## 5. 与 WP-1 的关系

- **WP-1 绿、真机仍无 `alerts`**：在排除「无 `BehaviorAlert` 帧」后，用 **§3.1 实验室档** 复测；若 `dropped` 仍暴长，**加大队列**、**关 L3/门控** 再试。  
- **WP-1 红**：先修平台/库，**不要**先用 WP-2 当主因。

## 6. WP-2 完成标准（验收）

- [ ] 团队能从本文 **§1～§3** 说清：**总线丢**、**L2 丢**、**L3 丢**、**门控** 的**至少一种**出现场景  
- [ ] 已在 **1 台** 高噪/实验室 机用 **`wp2_lab_e2e.env.example`** 思路跑通**与生产不同的**可预期行为（有日志对比即可）  
- [ ] 生产/灰度机有**书面**的 **`wp2_prod_default` + TOML** 组合（不必与示例逐字相同，但需**可追溯**）  
- [ ] `agent.toml.example` 与 `README` 中 **L2/L3 注释** 与本文**无矛盾**（版本迭代时以**代码** defaults 为准）

## 7. 交叉参考

- `agent.toml.example` — `[collection]`、`[preprocessing]`、`L2/L3` 注释  
- `docs/PREPROCESS_RULES.md` — TOML `emit_always` / `drop`  
- `edr-backend/docs/WP1_ALERT_INGEST_E2E.md` — 平台先验  
- `docs/WP3_CONFIG_VALIDATION.md` — WP-3 配置语义与 `[config] WARN`  
- `docs/WP4_HTTP_TRANSPORT_OPS.md` — WP-4 传输与 ingest 排障  
- `docs/WP5_RULES_ENGINEERING.md` / `docs/PREPROCESS_RULES.md` — WP-5 与 TOML 子串规则  
- `docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md` — WP-6 批/上送**量化后**再调参  
- `docs/WP7_OFFLINE_QUEUE_RETRY.md` — WP-7 发送失败/持久化与**出队**  
- `docs/WP8_ETW_COLLECTION_PROFILE.md` — WP-8 ETW/采集 与 P0 底线（与 L2/L3 **先后**）  
- `edr/include/edr/emit_rules.h` — 预处理规则与 dedup 顺序文字说明  
