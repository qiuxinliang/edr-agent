# B/C/D 维 8–43 实现审计（AG-012）

> **设计**：《11》§5.2 **B(8–23)**、§5.3 **C(24–35)**、§5.4 **D(36–43)**  
> **实现**：`src/ave/ave_behavior_features.c` — **`edr_ave_behavior_encode_m3b`**、**`encode_c_group`**  
> **验收**：本表为「评审签字」工作底稿；变更编码须同步 **`scripts/behavior_encode_m3b.py`** 与 **`test_ave_behavior_features_m3b`**。

| 维 | 分组 | 代码来源（摘要） | 状态 |
|----|------|-------------------|------|
| 8 | B | `snap->total_events_incl_current / 1000` → `clamp01` | 已实现 |
| 9 | B | `file_write_count / 100` | 已实现 |
| 10 | B | `net_connect_count / 100` | 已实现 |
| 11 | B | `reg_write_count / 100` | 已实现 |
| 12 | B | `dll_load_count / 50` | 已实现 |
| 13 | B | `has_injected_memory` | 已实现 |
| 14 | B | `has_accessed_lsass` | 已实现 |
| 15 | B | `has_loaded_suspicious_dll` | 已实现 |
| 16 | B | `has_ioc_connection` | 已实现 |
| 17 | B | `static_max_conf` / `ave_confidence` | 已实现 |
| 18 | B | `static_verdict_norm` | 已实现 |
| 19 | B | `parent_chain_depth_norm` | 已实现 |
| 20 | B | `is_system_account` | 已实现 |
| 21 | B | `time_since_birth_norm` | 已实现 |
| 22 | B | `unique_ip_count / 20` | 已实现 |
| 23 | B | `is_high_value_host` | 已实现 |
| 24 | C | 路径熵 `/16`（文件类事件） | 已实现 |
| 25–28 | C | 系统/临时/UNC/扩展名风险 | 已实现 |
| 29–31 | C | 公网 IP、启发式、端口风险 | 已实现 |
| 32 | C | 注册表键风险 | 已实现 |
| 33–34 | C | DNS 熵、IOC 域命中 | 已实现 |
| 35 | C | `target_has_motw` | 已实现 |
| 36–43 | D | 间隔 log、突发、sin/cos 时序、1/5 分钟计数、首事件、网连后事件数 | 已实现 |

**刻意简化 / 与设计细项差异**（需在评审会确认）：

- **C 组**：`feat[30]` 使用 `feat[29] > 0.5 ? 0.6 : 0.1` 的固定启发式，与设计文中「地理/信誉」可进一步细化时再迭代（见 AG-011）。
- **边界**：高熵路径、更多扩展名变体见 **AG-011** 专项。

**签字**：架构 □  安全 □  ML □  （日期：____）
