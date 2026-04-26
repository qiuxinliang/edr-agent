# 预处理规则（`[[preprocessing.rules]]`）

> **范围**：TOML 可配的 **`drop` / `emit_always`** 子串规则，在 **dedup / 秒级限流之前** 参与决策（`edr_preprocess_should_emit` → `edr_emit_rules_evaluate`）。**不是** P0 条件全量 DSL（P0 见 `p0_rule_bundle_ir_v1.json` 与 `docs/WP5_RULES_ENGINEERING.md`）。

## 1. 配置段

`[preprocessing]` 中除规则外，常用键包括：

| 键 | 含义（摘要） |
|----|----------------|
| `dedup_window_s` | 去重窗口秒数，喂入 `edr_dedup_configure` |
| `high_freq_threshold` | 每 pid+type **每秒** 最大条数，超出则丢弃（限流） |
| `sampling_rate_whitelist` 等 | 见 `agent.toml.example` 与设计 §11 |
| `rules_version` | 人读/对账用字符串，常与平台 `dynamic_rules_v1.json` 根 `version` 对齐（见 **`sync_behavior_rules_bundle.py`**） |

## 2. 单条规则 `[[preprocessing.rules]]`

| 字段 | 必须 | 说明 |
|------|------|------|
| `name` | 否 | 缺省为 `rule_<index>` |
| `action` | 是 | **`drop`** 或 **`emit_always`** |
| `event_type` | 否 | 限制为某事件类型，如 `PROCESS_CREATE`；不填则不限类型（仍须满足下方至少一条子串/类型约束） |
| `exe_path_contains` / `cmdline_contains` / `file_path_contains` / `dns_query_contains` / `script_snippet_contains` | 与 `event_type` 二选一组合 | 非空时按字段做子串包含；`icase_*` 为 true 时大小写不敏感 |

实现结构体见 `edr/emit_rules.h`（`EdrEmitRule`）。

## 3. 求值顺序（与实现一致）

1. **`edr_emit_rules_evaluate` 按数组下标 0..N-1 扫描**，**第一条** 规则若字段与 `event_type` 全匹配，则：  
   - `drop` → 返回 `0`（`edr_preprocess_should_emit` 为 false，**不**进入批次）  
   - `emit_always` → 返回 `1`（**绕过** dedup 与限流，仍受更高层如总线/采集约束）  
2. 若**无一命中**，返回 `-1` → 继续 **dedup**，再 **限流**（`priority==0` 时直接放行，不跑规则、dedup、限流，见 `dedup.c`）。

> **L2 分流**（`EDR_PREPROCESS_L2_SPLIT=1`）在 `preprocess_pipeline.c` 中还会对「行为类」事件**额外**调用 `edr_emit_rules_evaluate` 判断是否视为「已命中 emit_always 类」以影响抽样；细节见 **`docs/WP2_EVENT_BUS_PREPROCESS.md`**。

## 4. 规则包自动加载

若主 `agent.toml` 的 `[preprocessing]` 下**没有**内嵌 `rules` 数组（`toml` 中未出现该数组，端上以此为准），`edr_config_load` 在解析结束后会按序尝试：

1. 环境变量 **`EDR_PREPROCESS_RULES_BUNDLE_PATH`** 指向的完整 TOML 文件；或  
2. 与主配置**同目录**的 **`agent_preprocess_rules_v1.toml`**

该文件应含 `[preprocessing]` 与可选多段 `[[preprocessing.rules]]`，以及（推荐）`rules_version`。**若**主文件已内嵌 `[[preprocessing.rules]]`，**不会**再自动合并同目录 bundle（见 `docs/EDR_AGENT_WAVE2_RUNBOOK.md`）。

**生成**：Conservative 子集由 `edr-backend/platform/config/generate_agent_preprocess_rules.py` 从 `dynamic_rules_v1.json` 生成；**整库版本**与 TOML 内 `rules_version` 的同步常由 `sync_behavior_rules_bundle.py` 一次写回多处。

## 5. 参考

- `edr/emit_rules.h` — 数据结构  
- `edr-agent/docs/WP5_RULES_ENGINEERING.md` — 与平台母版、P0 IR、发版对账的**工程化流程**（WP-5）  
- `edr/preprocess/p0_rule_match.h` — P0 直出/匹配，与本文 TOML **并列**，语义不同  
