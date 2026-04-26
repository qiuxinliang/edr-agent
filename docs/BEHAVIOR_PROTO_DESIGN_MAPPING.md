# 《11》与 `BehaviorEvent` / `AveBehaviorEventFeed` 字段映射（DOC-001）

> **权威设计**：`Cauld Design/11_behavior.onnx详细设计.md`（下称《11》）  
> **Proto 源**：`edr-agent/proto/edr/v1/event.proto`  
> **C 侧载荷**：`include/edr/ave_sdk.h` 中 **`AVEBehaviorEvent`**、**`AVEBehaviorAlert`**（批次编码见 `behavior_proto.c`）

本文给出 **§4 / §12.4** 与 **proto 字段号** 的对照，供平台强类型入库、端侧编码与评审冻结同一套语义。

---

## 1. `AveBehaviorEventFeed`（`BehaviorEvent` 字段 **41**）↔ 《11》§4.1 / `AVEBehaviorEvent`

| proto 字段 | 编号 | C / 设计语义 |
|------------|------|----------------|
| `severity_hint` | 1 | `AVEBehaviorEvent.severity_hint` |
| `target_path` | 2 | `target_path` |
| `target_path_entropy` | 3 | 由路径计算的熵（特征 C 维与管线侧可再算，proto 便于平台落库） |
| `target_is_system_dir` | 4 | 对应路径启发式「系统目录」 |
| `target_is_temp_dir` | 5 | 对应「临时目录」 |
| `target_is_network_path` | 6 | UNC 等 |
| `target_file_ext_risk` | 7 | 与 `file_ext_risk_heuristic` 分级一致 |
| `target_has_motw` | 8 | 《11》§5.3 **维 35** |
| `target_ip` … `target_domain_entropy` | 9–15 | 网络 / DNS 目标 |
| `reg_key_risk` | 16 | 注册表风险启发式 |
| `shellcode_score` … `pmfe_dns_tunnel` | 17–21 | 《11》§5.5 **E 组** 跨引擎标量 |
| `ioc_*_hit` | 22–24 | TIP/IOC |
| `cert_revoked_ancestor` | 25 | §5.5 **维 56** 事件步信号 |
| `ave_confidence` | 26 | 静态/融合置信度 |
| `behavior_flags` | 27 | `AVEBehaviorFlags` 位域 |
| `file_sha256_hex` | 28 | IOC 文件哈希 |
| `ave_event_type` | 29 | `AVEEventType`，与 `BehaviorEvent.type`（`EdrEventType`）区分 |

**说明**：端侧若仅走 **BAT1 + `behavior_alert`**，可不填字段 41；完整重建特征或检索时建议填 **41**。

---

## 2. `BehaviorAlert`（`BehaviorEvent` 字段 **40**）↔ 《11》§6 / §12.4

| proto 字段 | 编号 | 语义 |
|------------|------|------|
| `anomaly_score` | 1 | ONNX 异常分 0–1 |
| `tactic_probs` | 2 | 固定 **14** 维（`packed`） |
| `triggered_tactics` | 3 | MITRE 战术 id 或展示名（平台归一） |
| `skip_ai_analysis` | 4 | 跳过附加 AI |
| `needs_l2_review` | 5 | L2 复核队列 |
| `timestamp_ns` | 6 | 事件时间 |
| `pid` … `process_path` | 7–9 | 进程上下文 |

C 侧 **`AVEBehaviorAlert`**：`include/edr/ave_sdk.h`，战术概率 **`tactic_probs[14]`**。

---

## 3. `BehaviorEvent` 信封字段 ↔ 通用遥测

| proto 字段 | 编号 | 备注 |
|------------|------|------|
| `event_id` … `session_id` | 1–13 | 与 `EdrEventType`、进程上下文一致 |
| `detail` oneof | 20–25 | `FileDetail.target_has_motw` 等可与 §5.3 对齐 |
| `ave_result_json` | 30 | 遗留 JSON；强类型优先 **40/41** |
| `mitre_ttps` | 31 | 与告警侧可重复，以产品为准 |
| `priority` | 32 | 优先级 |

---

## 4. 维护

- **变更 proto** 时同步更新本表与 **`BEHAVIOR_ONNX_IMPLEMENTATION_PLAN.md`**。  
- **关单**：在 **`edr-agent/docs/DETAILED_TASK_CHECKLIST.md`** 将 **DOC-001** 标为完成。
