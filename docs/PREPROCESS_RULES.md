# 预处理「是否上报」规则列表（`preprocessing.rules`）

在 **dedup 时间窗去重**与**秒级高频限流**之前，对每条 `EdrBehaviorRecord` 按配置顺序匹配 **第一条** 满足全部条件的规则，并执行其 **action**。

## 配置位置

写在 **`agent.toml`** 的 **`[preprocessing]`** 下，使用 TOML **数组表**：

```toml
[preprocessing]
dedup_window_s      = 30
high_freq_threshold = 100
rules_version       = "edr-dynamic-rules-v1"

[[preprocessing.rules]]
name               = "示例：丢弃临时目录噪声"
action             = "drop"
exe_path_contains  = "\\Windows\\Temp\\"
icase_exe_path     = true

[[preprocessing.rules]]
name               = "示例：编码 PowerShell 始终上报"
action             = "emit_always"
cmdline_contains   = "EncodedCommand"
icase_cmdline      = true
```

规则条数 **无固定上限**：解析时按条 **`realloc`** 存入 `EdrConfig.preprocessing.rules`；运行时 **`edr_emit_rules_configure`** 再 **`malloc`** 一份副本用于匹配。条数极多时请注意 **内存占用** 与 **每条事件上的线性扫描**（\(O(\text{规则数})\)）。运维侧可限制 TOML 体积；更细的工程化手段见下节 **「后续优化建议」**。

## 后续优化建议（保留立项，当前代码未实现）

以下为性能/运维向的**保留建议**，便于与《端点详细设计》迭代对齐，**尚未写入实现**：

1. **环境变量封顶**：支持 **`EDR_EMIT_RULES_MAX`**（或类似名），在加载 TOML 时若已解析条数超过该值则截断并打日志，防止误配置或恶意超大列表撑爆内存。
2. **按 `event_type` 分桶**：将规则按 `event_type`（及「未限定类型」桶）建索引，匹配时只扫描相关桶，把均摊复杂度从「全量规则线性」降为「与当前事件类型相关的子集」。
3. **海量子串模式**：当规则以「命令行/路径子串」为主且规模极大时，可考虑 **多模式匹配**（如 Aho-Corasick）或前缀树，避免对每条事件做朴素双重循环；需与规则语义（首条命中、AND 条件）统一设计。
4. **规则合并与离线编译**：运营侧将大量细粒度规则合并为更少条、或离线编译为中间表示，再下发终端，减少终端侧规则条数与热路径开销。

实现任一子项时，应更新本文件并补充基准数据（规则条数、事件 QPS、CPU/内存）。

## 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 可选；日志/排错用。 |
| `action` | string | **必填**。`drop`：命中则**不上报**；`emit_always`：命中则**直接上报**（**不**走 dedup 与按秒限流）。 |
| `event_type` | string | 可选。`ANY` 或省略表示不限制；否则为 `EdrEventType` 名，如 `PROCESS_CREATE`、`NET_DNS_QUERY`（与 `include/edr/types.h` 一致）。仅填此项时，表示「该类型的全部事件」都应用本规则（慎用 `drop`）。 |
| `rules_version` | string | 可选。规则包版本标识；默认内置为 `edr-dynamic-rules-v1`，用于与平台规则版本对齐。 |
| `exe_path_contains` | string | 可执行路径 **子串**匹配（`EdrBehaviorRecord.exe_path`）。 |
| `cmdline_contains` | string | 命令行 **子串**（`cmdline`）。 |
| `file_path_contains` | string | 文件路径 **子串**（`file_path`）。 |
| `dns_query_contains` | string | DNS 查询 **子串**（`dns_query`）。 |
| `script_snippet_contains` | string | 脚本片段 **子串**（`script_snippet`）。 |
| `icase_exe_path` 等 | bool | 可选，默认 `false`。为 `true` 时对应字段做 **ASCII 大小写不敏感**子串匹配。 |

**匹配逻辑**：已填写的条件之间为 **AND**。同一规则内未填写的维度不参与过滤。

**无效规则**：若既无 `event_type` 限定，又没有任何 `*_contains` 非空，加载时 **跳过** 并打日志。

## 与现有逻辑的顺序

1. 采集侧已置 **`priority == 0`**（如 ETW 载荷含 `EncodedCommand`）→ **始终上报**，不经过本规则表。  
2. **`edr_emit_rules_evaluate`**（本规则）。  
3. **dedup** + **高频限流**（`dedup_window_s` / `high_freq_threshold`）。

## 默认内置规则

- `edr_config_apply_defaults` 会内置一组 `emit_always` 动态规则（当前版本 `edr-dynamic-rules-v1`）。
- 若 TOML 中未提供 `[[preprocessing.rules]]`，将继续使用内置规则。
- 一旦在 TOML 明确提供 `[[preprocessing.rules]]`，则以 TOML 规则覆盖内置规则列表。

## 与 `sampling_rate_whitelist`

配置项 **`sampling_rate_whitelist`** 仍为预留；**白名单采样百分比**尚未与本规则表合并，后续可定义为：仅对未命中 `emit_always`/`drop` 的事件再抽样。

## 模式说明（v1）

当前仅支持 **子串包含**（含大小写可选），**不包含** 正则或 glob。若需通配路径，可拆成多条 `exe_path_contains` 规则，或后续版本扩展 `exe_path_glob`。
