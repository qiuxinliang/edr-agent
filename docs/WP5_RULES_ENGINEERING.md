# WP-5：规则工程化

> **目标**：把 **平台动态规则母版**、**端上预处理 TOML**、**P0 IR 直出包** 与 **版本/CI 对账** 写成**可重复、可追溯**的闭环；避免「只改了一处 JSON、三端版本漂移」的静默错误。

> **相关**：**WP-2**（L2/L3/门控与 `emit_rules` 的交叠）、**WP-3**（`rules_version` / 路径与身份）、**WP-4**（上送与 ingest 日志）、**WP-6**（`[upload]`/批次与 **shutdown 量化**调优，见 `docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md`）、**WP-7**（上送失败后的**离线**路径，见 `docs/WP7_OFFLINE_QUEUE_RETRY.md`）、**WP-8**（P0/ETW 底线，见 `docs/WP8_ETW_COLLECTION_PROFILE.md`）。**P0/预处理 IR 直出** 与 **AVE 行为管线（WP-9）** 的边界见 `docs/WP9_BEHAVIOR_AVE.md`。设计背景见 `Cauld Design/EDR_ETW_optimization_and_behavior_rule_engine_master_plan.md`、`ADR_edr_agent_rule_engine_and_direct_BehaviorAlert.md`。

## 1. 三套路产物（别混用）

| 目的 | 载体 | 典型位置 | 平台侧/工具 |
|------|------|----------|-------------|
| **A. 全量母版**（供规则引擎/库表/富化） | `dynamic_rules_v1.json` | `edr-backend/platform/config/` | 人工或流水线编辑；`sync_behavior_rules_bundle.py` 会重写根 **`version`**（**SHA256(rules)** 派生短串，见该脚本 `compute_version`） |
| **B. 预处理 emit/drop（保守子集）** | `agent_preprocess_rules_v1.toml` | 同目录 + 可镜像到 Agent 发布 | **`generate_agent_preprocess_rules.py`** 从母版**抽取**高置信子集，生成 `[[preprocessing.rules]]` 与 `rules_version` 行；与 **A** 的 `version` 由 `sync_*.py` 绑定 |
| **C. P0 端上 IR**（`BehaviorAlert` 直出等，PCRE2/嵌入） | `p0_rule_bundle_ir_v1.json` + `p0_rule_bundle_manifest.json` | `edr-agent/config/` + platform 镜像 | **`export_p0_rule_manifest.py`**（`dynamic_rules_v1.json` + **`p0_rule_ids_v1.txt`**) |

**A** 是 **B、C 的上游**；B 是「限载/高置信放行」的**子串规则**（`docs/PREPROCESS_RULES.md`），**不**承担 P0 全条件；C 是 **B1.1** 的 IR，与 Go `dynamicrules` 同构的 `condition`。

## 2. 版本与对账

### 2.1 全库 `version`（dynamic_rules 根 + 预处理后缀）

- `sync_behavior_rules_bundle.py`：根据**规则数组内容**重算并写回 `dynamic_rules_v1.json` 的 **`version`**，并同步：  
  - 所有 `agent_preprocess_rules_v1*.toml` 的 `rules_version`、  
  - `edr-agent/src/config/config.c` 的 **`EDR_PREPROCESS_RULES_VERSION_DEFAULT`**、  
  - `edr-agent/agent.toml.example`、  
  - 若干 `p1_*.json` profile 的 `bundle_version` 等（以脚本为准）。

### 2.2 P0 包 `rules_bundle_version`（四处一致）

- **`verify_p0_bundle_version_alignment.sh`** 校验以下**字符串完全一致**：  
  `edr-backend/platform/config/dynamic_rules_v1.json` 的 **`version`**、  
  `p0_rule_bundle_manifest.json` 的 **`rules_bundle_version`**、  
  `edr-agent/config/p0_rule_bundle_ir_v1.json` 的 **`rules_bundle_version`**、  
  `edr-agent/CMakeLists.txt` 默认 **`EDR_P0_RULES_BUNDLE_VERSION`**.

- 修改 **P0 子集**或 **母版**后：应重新跑 **`export_p0_rule_manifest.py`** 生成/镜像 IR 与 manifest，使 **`rules_bundle_version` 与母版 `version` 一致**，再发 PR / 发版。

- **CMake** `EDR_P0_IR_EMBED`：构建时把 IR 编进可执行/嵌入 C；**运行期**优先外置 `EDR_P0_IR_PATH` / `edr_config/p0_rule_bundle_ir_v1.json`（见 `edr-agent/README`）。

## 3. 推荐工作流

### 3.1 全库规则/版本一次收敛（A+B+DB 片段+profile）

1. 编辑 `dynamic_rules_v1.json`（`rules` 数组）。  
2. 在 **`edr-backend/platform/config`** 执行：  
   `python3 sync_behavior_rules_bundle.py`  
3. 视需要重新生成 P0 产物：  
   `python3 export_p0_rule_manifest.py`（会镜像到 `edr-agent/config/`，除 `--no-agent-mirror`）。  
4. `bash edr-backend/scripts/verify_p0_bundle_version_alignment.sh`  
5. 本地构建 `edr-agent`（或 CI）确认 P0 嵌入/复制步骤无警告。

### 3.2 只调整「预处理保守 emit 表」（不动全库 hash）

- 改 **`generate_agent_preprocess_rules.py`** 中 `CURATED_EMIT_ALWAYS_RULES` 或母版中对应 `id` 的覆盖策略，再运行该脚本。  
- 若**未**动 `rules` 数组，可不必重跑 `sync_*.py`；若团队约定 **rules_version 必须与 `dynamic_rules_v1` 根 version 锁死**，则仍以 **`sync_behavior_rules_bundle.py`** 为权威一次写回（避免双源）。

### 3.3 P0 子集/清单变更

- 调 **`p0_rule_ids_v1.txt`** 或会签流 → **`export_p0_rule_manifest.py`** → 再跑 **`verify_p0_bundle_version_alignment.sh`** 与 `edr_p0_golden_test` / 记录中 golden。

## 4. 测试与金线

| 项 | 位置 / 命令 |
|----|-------------|
| P0 版四方对账 | `edr-backend/scripts/verify_p0_bundle_version_alignment.sh` |
| 进程+命令行金线（子集） | `edr_p0_golden_test`（CMake 目标，见 `p0_rule_golden_test.c`） |
| P0 直出 E2E 留证 | `edr-agent/docs/EDR_P0_DIRECT_EMIT_E2E.md` |
| Go/C 对拍 | 见 `Sprint-Backend-Tasks` / `internal/dynamicrules` 与 P0 清单 |

## 5. 与其它 WP 的分工

| WP | 与规则工程化的关系 |
|----|--------------------|
| WP-2 | L2 使用 `edr_emit_rules_evaluate` 的返回值区分「高价值/命中 emit_always 类」与**未命中**的抽样。 |
| WP-3 | `agent.toml` / `EDR_PREPROCESS_RULES_BUNDLE_PATH` 决定**哪一份** TOML 与平台身份一起生效。 |
| WP-4 | 上送与 ingest 可达；**规则再绿**送不出去仍无 `alerts`。 |
| **WP-5**（本文）| **产物的来源、版本、脚本** 与改母版时的**顺序**。 |

## 6. 完成标准（验收）

- [ ] 能说出 **A / B / C** 三份产物**各自**解决什么问题，**不**把 TOML `emit_always` 与 P0 IR 混为一谈。  
- [ ] 在修改 `dynamic_rules_v1.json` 后，团队约定跑 **`sync_behavior_rules_bundle.py`** 与（涉及 P0 时）**`export_p0_rule_manifest.py` + `verify_p0_bundle_version_alignment.sh`** 再合并。  
- [ ] 阅读 **`docs/PREPROCESS_RULES.md`** 能解释 `emit_always` 在 **dedup/限流** 前的短路语义。  
- [ ] 发版检查清单中 **P0/规则** 行可与 **`rules_bundle_version`** 或 `rules_version` 对得上。

## 7. 交叉参考

- `edr-agent/docs/PREPROCESS_RULES.md` — TOML 规则语法与加载顺序  
- `edr-backend/platform/config/generate_agent_preprocess_rules.py`  
- `edr-backend/platform/config/sync_behavior_rules_bundle.py`  
- `edr-backend/platform/config/export_p0_rule_manifest.py`  
- `edr-agent/include/edr/p0_rule_ir.h` — 运行期 API  
- `edr-agent/docs/WP6_TRANSPORT_BATCH_QUANTIFIED_OPS.md` — 规则**增多**上送量时的批次侧排查  

