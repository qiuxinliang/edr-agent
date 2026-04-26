# P3：行为管线、《09》策略与 Python 契约 — 可追溯矩阵

**目的**：关闭 **P3-1 / P3-2**（`AVE_COMPLETENESS_TASKS.md`）— 将《11》《09》、**`BEHAVIOR_ONNX_SPEC_GAP.md`**、**`T-integration-test/test_ave_pipeline.py`** 与 C 实现 **对上号**；标明 **刻意差异**（避免「以为一致」）。

**权威设计**（仓库外）：`Cauld Design/09_AVEngine开发需求文档.md`、`11_behavior.onnx详细设计.md`。

---

## 1. 《11》§7 推理触发 / 步长 / 立即推理（P3-1）

| 文档要点 | C 入口 | 常量 / 环境变量 |
|----------|--------|-----------------|
| §7.1 **立即**触发 ORT（与 `events_since_last_inference` 无关） | `ave_behavior_pipeline.c` → **`bp_infer_immediate()`** | 事件类型：`PROCESS_INJECT`、`MEM_ALLOC_EXEC`、`LSASS`、`SHELLCODE`、`PMFE_RESULT`、`WEBSHELL`；IOC 命中；**`behavior_flags`** 高危位（`AVE_BEH_*`） |
| §7.1 默认步长 **16**、连续中等分 ≥**3** 次后步长 **8** | **`bp_infer_events_threshold_design7()`** | **`EDR_AVE_BEH_INFER_STEP_DEFAULT`** (16)、**`EDR_AVE_BEH_INFER_STEP_TIGHT`** (8)、**`EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT`** (3)；与 **`test_ave_behavior_gates.c`** 门禁一致 |
| Legacy：仅「每 N 事件推理」 | **`env_infer_min_events_explicit()`** | **`EDR_AVE_BEH_INFER_MIN_EVENTS`** 设置时 **不**再走 §7.1 立即/16/8 分支（见源码注释） |
| §7.2–§7.3 分数带：中危下界 / 高危 | 告警与连续「中等」计数 | **`EDR_AVE_BEH_SCORE_MEDIUM_LOW`** (0.40)、**`EDR_AVE_BEH_SCORE_HIGH`** (0.65)（**`ave_behavior_gates.h`**） |
| §2.2 PMFE 建议线 **0.45** | Python **`should_trigger_pmfe`** / `BEHAVIOR_THRESHOLDS["pmfe_trigger"]` | C：**`EDR_AVE_PMFE_TRIGGER_SCORE`**；进程内对 PMFE 另以 **`AVE_EVT_PMFE_RESULT`** 走 **立即推理**（与纯 0.45 比较是 **并列**语义，见下节） |

**结论**：步长与立即触发在 **`ave_behavior_pipeline.c`** 可逐条对照 §7.1；若与设计仍有个案差异，在本文件追加一行「**gap**」即可版本化。

---

## 2. PMFE 与 Python `test_ave_pipeline`（P3-1）

| 位置 | 行为 |
|------|------|
| **Python** | **`ANOMALY_PMFE`** = `BEHAVIOR_THRESHOLDS["pmfe_trigger"]`（**0.45**）；**`should_trigger_pmfe(score, …)`** 用于场景脚本 |
| **C 行为管线** | 收到 **`AVE_EVT_PMFE_RESULT`** / 高危标志时 **`bp_infer_immediate`** 为真，**不依赖**单次 anomaly 与 0.45 比较 |
| **对齐方式** | 数值 **0.45** 与 C 宏 **`EDR_AVE_PMFE_TRIGGER_SCORE`**、训练 **`feature_config.py`** 一致；**`ctest -R ave_behavior_gates`** 校验宏与 0.40/0.65/0.45 |

---

## 3. 四层误报抑制 vs Python（P3-2）

| 层 | Python `apply_confidence_suppression`（`test_ave_pipeline.py`） | C 侧 |
|----|-------------------------------------------------------------------|------|
| **L4** 行为不可豁免 | `behavior_flags & NON_EXEMPTIBLE` → 不调证书衰减 | **`edr_ave_apply_l4_non_exempt`** / 行为标志与 SQLite 策略（见 **`ave_suppression`**、**`ave_sdk.c`**） |
| **L1–L3** 证书 | `cert_adj[trust]` 固定减量 + **floor = raw×0.20** | Windows：**`ave_sign_whitelist_win.c`** 等（如 MS **-0.55**）；非 Win：**stub** 路径 |
| **L2** 文件哈希白名单 | `final=0` | **`edr_ave_file_hash_whitelist_hit`** → **`fill_file_hash_whitelist`** |
| **L3** IOC | `conf += (1-conf)*0.20*ioc_confidence` | ONNX 后 **`edr_ave_overlay_ioc_post_ai`** 等（公式以 C 为准；与 Python **同一量级**即可联调） |
| **静态 verdict 阈值** | **`verdict_from_confidence`**：≥**0.80** MALWARE，≥**0.40** SUSPICIOUS（**09 §6.2 模拟**） | **`apply_infer_verdict`** 非三输出路径：**`s_l3_trigger` / `s_fp_floor`**（默认 **0.60**，可由 **`AVEConfig`** 覆盖） |

**重要**：**Python 脚本中的 0.80/0.40** 是 **09 文档式** 的展示矩阵；**C 进程内默认 0.60/0.60** 来自 **`AVE_Init`** 配置。对齐方式：产品在同一 **`AVEConfig`** 中写入 **`l3_trigger_threshold` / `fp_suppression_threshold`**，或接受「集成测试 = ORT+策略模拟，≠ edr_agent 默认阈值」。

---

## 4. 门禁与回归

| 项 | 路径 |
|----|------|
| 行为阈值 + 步长 + `EDR_AVE_PMFE_TRIGGER_SCORE` | **`tests/test_ave_behavior_gates.c`** |
| ONNX 行为双 fixture | **`ctest -R ave_behavior_onnx_dual_integration`** |
| Python ORT + 策略模拟 | 仓库根 **`T-integration-test/run.sh`**（依赖 **`feature_config.BEHAVIOR_THRESHOLDS`**） |

---

## 5. 版本

- 随 **P3** 首次写入；变更 **`ave_behavior_gates.h`** 或 **09/11** 阈值时，请同步更新本节表格。
