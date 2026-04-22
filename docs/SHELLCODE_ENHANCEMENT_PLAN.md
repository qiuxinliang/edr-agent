# §17 Shellcode 检测 — 详细增强计划与可执行任务

**范围**：`proto_parse.c`、`shellcode_known.c` / `known_exploits.yar`、`windivert_capture.c`、语料 **`test_data/shellcode_corpus/`**、**`eval_shellcode_corpus`**、CI、性能（**`P2_PERF4`**）、与行为/平台侧**弱耦合**项。

**关联文档**：**`docs/SHELLCODE_EVALUATION_CORPUS.md`**（语料与评估矩阵）、**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md`**、**`docs/P2_PERF4_SYNTHETIC_TRAFFIC_REPORT.md`**。

**状态说明**：下表 **P0-已完成** 概括当前仓库已落地的阶段一/语料对齐；自 **P1** 起为建议迭代，**工作量**为粗略人日（1 人全职当量），便于排期。

---

## 1. 目标分层

| 层级 | 目标 | 成功判据（摘要） |
|------|------|------------------|
| **P0（已完成）** | 语料与 **manifest**、**pipeline**（`edr_proto_find_shellcode_region` + 子区间匹配）一致；EternalBlue 含 **NetBIOS 封装** 变体 | **`ctest -R shellcode`** 绿；**`eval_shellcode_corpus`** manifest/pipeline **`rule_ok_pct=100%`**（**43** 条 baselines） |
| **P1（检测正确性）** | 扩展协议解析与规则覆盖时 **不显著恶化 FP/性能**；YARA 与内置路径 **可验证一致** | 新增场景有 **单测 + 语料或隔离样本矩阵**；带 YARA 的 eval **有记录** |
| **P2（产品化）** | 告警可运营：分级、去重、与进程/会话上下文弱绑定 | 字段/schema 与 **`SOAR_CONTRACT`** / 预处理约定对齐（若适用） |
| **P3（架构）** | TLS 侧、解密旁路、网关明文等 **非单模块**方案 | 设计评审通过、与平台/网络团队边界清晰 |

---

## 2. 可执行任务清单

### 2.1 P0 — 维护与回归（持续）

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-000** | 变更 **`shellcode_known.c` / YARA / `proto_parse.c` / `emit_baseline_variants.py`** 后的标准回归 | **已实现**：① **`cmake --build <dir> --target shellcode_t_sc_000_verify`**（emit → **`ctest -R shellcode`** → **`eval_shellcode_corpus`** manifest + pipeline **`--strict`**）；或 ② **`bash scripts/shellcode_corpus/t_sc_000_verify.sh [CMAKE_BINARY_DIR]`**（默认 **`build`**）。通过后提交 **`test_data/shellcode_corpus/baselines/`** 与 **`manifest.tsv`** 的 diff | 无 | 每次变更后跑一次 |
| **T-SC-001** | **pipeline strict** 纳入 **`ctest`**，CI 与本地无需单独跑 eval | **已实现**：**`add_test(shellcode_corpus_pipeline_eval)`** 通过 **`cmake/run_shellcode_pipeline_eval.in.cmake`**（`cmake -P`）在 **`CMAKE_BINARY_DIR`** 下解析 **`eval_shellcode_corpus`**（Unix / MSVC 多配置路径）；**`ctest -R shellcode`** 即执行。**`.github/workflows/edr-agent-ci.yml`** 仅保留 **`ctest`**，已删除重复的 eval 步骤 | 无 | 已完成 |

---

### 2.2 P1 — 协议解析（SMB2 / SMB1 扩展）

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-010** | **SMB2**：梳理线上需覆盖的 **Command** 列表 | 从 WinDivert 端口集合 + 内部 PCAP/情报中归纳「出现过 exploit 相关载荷」的 command；输出 1 页设计说明（可放 **`docs/`** 或内网） | 流量样本或统计 | 0.5～1d |
| **T-SC-011** | **SMB2**：在 **`proto_parse.c`** 中按列表扩展 **OK 分支** | 每条新分支：**单测**（`test_shellcode.c` 或专用 `test_proto_parse.c`）+ **短合成 carrier**（可并入 **`emit_baseline_variants.py`** 或独立脚本）；**`NOT_INTERESTING`** 行为不变或可测 | T-SC-010 | 1～3d/命令族 |
| **T-SC-012** | **SMB1**：扩展 **Command** 白名单（若有明确需求） | 同 T-SC-011 模式；注意与 **EternalBlue** 检测的 **kind==SMB1** 门控一致 | 需求与 FP 评审 | 1～2d |
| **T-SC-013** | **性能回归**：扩解析后对 **`max_payload_inspect`** 路径计时或计数 | 在 **`P2_PERF4`** 或本仓库约定脚本中增加前后对比（例如处理 N MB 合成 SMB 的 CPU 时间或 **`wd_stats`**）；阈值由团队约定 | T-SC-011 或 012 | 0.5～1d |

---

### 2.3 P1 — YARA 与内置链

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-020** | **CI**：新增 **`libyara`** 可选 job（建议 Ubuntu） | Job：`apt install` 或静态链 yara（按项目策略）；**`cmake`** 打开 **`EDR_YARA_AVAILABLE`**；**`ctest -R shellcode`** + **`eval_shellcode_corpus --yara <内置 rules 目录> --mode manifest`**；产出 **`got_rule` vs `expected_rule`** 对照表为 artifact 或日志 | 包管理与 CMake 探测 | 1～2d |
| **T-SC-021** | **规则顺序**：文档化 YARA **首命中**与内置顺序的差异 | 更新 **`SHELLCODE_EVALUATION_CORPUS.md`** §1.1 或本文件附录；若需固定顺序，调整 **`known_exploits.yar`** 规则拆分/命名策略 | T-SC-020 | 0.25～0.5d |
| **T-SC-022** | **（可选）** `eval_shellcode_corpus` 增加 **`--expect-builtin`** | 强制跳过 YARA 仅测 C 链，便于同一语料在 **有/无 YARA** 下对比；验收：开关生效、文档更新 | 无 | 0.5d |

---

### 2.4 P1 — 语料与负样本

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-030** | **负样本**：合成「含 UUID 片段但非 PetitPotam 语义」等 **不应命中** 或 **应降置信度** 的 buffer | 不入库恶意二进制；仅 **合成** 字节；验收：单测或 eval 脚本断言 **`edr_shellcode_match_known_exploit`==0** 或告警字段符合策略（若已实现策略位） | 产品对 FP 的容忍度 | 1～2d |
| **T-SC-031** | **HTTP**：对 **Follina / Log4Shell** 增加 **边界变体**（大小写、分块、截断头等） | 扩展 **`emit_baseline_variants.py`** + manifest；**`pipeline`** 下 **`parse_ok`** 行为记录在 **`SHELLCODE_EVALUATION_CORPUS.md`** | 无 | 1～2d |
| **T-SC-032** | **实验室**：在 **`raw_private/`** 跑 **`apply_lab_variants.py`**（D2–D7）对情报片段做 **矩阵表**（**不提交 raw**） | 输出 TP/FP/FN 表到内网 wiki；仓库内仅保留 **统计结论** 或脱敏一行摘要（可选） | 合法样本来源 | 持续 |

---

### 2.5 P2 — 启发式与告警产品化

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-040** | **告警 JSON**：为 shellcode 事件增加 **detector 分层**（yara / known_exploit / heuristic）与 **rule 置信度占位** | 与 **`windivert_capture.c`** 推送字段及 **`SOAR_CONTRACT.md`** 对齐；验收：样例日志一条 + 预处理消费无回归 | 产品字段冻结 | 1～2d |
| **T-SC-041** | **去重**：同五元组 + 同 rule 在 **T 秒内** 合并或计数 | 策略写 TOML 或常量；单测或集成测；验收：风暴场景不撑爆总线 | T-SC-040 | 2～4d |
| **T-SC-042** | **与 PMFE/行为**：高危 shellcode 命中后 **hint_pid / 端口反查** 路径复核（已有变量则文档化） | 读 **`SOAR_CONTRACT`** § 相关段；补 **`WINDOWS_SHELLCODE_FORENSIC_TODO.md`** 勾选或新子项 | 无 | 0.5～1d |

---

### 2.6 P3 — TLS 与跨模块

| ID | 任务 | 说明与验收 | 依赖 | 估时 |
|----|------|------------|------|------|
| **T-SC-050** | **TLS  gap** 设计评审：仅端上 / 网关 / 解密镜像 三选一或组合 | 产出 ADR 或设计 1 页；明确 **不在 `proto_parse` 内解析 TLS** 的边界 | 架构 | 0.5～1d |
| **T-SC-051** | 若选 **进程关联**：shellcode 告警携带 **候选 PID** 的契约与后端展示 | proto / JSON 字段；与 **edr-backend** 联调清单 | T-SC-050 | 1～2 周级 |

---

## 3. 建议排期（里程碑）

| 里程碑 | 包含任务 | 周期（粗） |
|--------|----------|------------|
| **M1** | T-SC-000、~~T-SC-001~~（已接入 CI）、T-SC-020、T-SC-021 | **T-SC-020/021** 约 1 周内可并行准备 |
| **M2** | T-SC-010 → T-SC-011（+ T-SC-013） | 每增加一类 SMB2 场景约 1 周（含评审） |
| **M3** | T-SC-030、T-SC-031 | 1～2 周 |
| **M4** | T-SC-040 → T-SC-042 | 2～3 周 |
| **M5** | T-SC-050 → T-SC-051 | 按产品立项 |

---

## 4. 不在本计划内强行落地的项

- **完整恶意样本入库**：合规边界见 **`SHELLCODE_EVALUATION_CORPUS.md`** §2。  
- **未授权解密 TLS**：需法务/架构与部署模型一致后再进 **T-SC-050** 之后任务。

---

## 5. 修订记录

| 日期 | 变更 |
|------|------|
| 2026-04-20 | 初版：基于当前 **35** 条 baseline、**pipeline/manifest** 双绿、NetBIOS 变体已合入的前提整理 |
| 2026-04-20 | **T-SC-001**：**`add_test(shellcode_corpus_pipeline_eval)`** + 从 workflow 移除重复 eval 步骤 |
| 2026-04-20 | **T-SC-000**：**`shellcode_t_sc_000_verify`** CMake 目标 + **`scripts/shellcode_corpus/t_sc_000_verify.sh`** |
| 2026-04-20 | **T-SC-010～013、020～022、030～032、040～042、050～051**：SMB2/1 解析与文档、YARA CI job、`--expect-builtin`、语料 HTTP/SMB 扩展、告警 **`det_layer`/`rule_confidence`**、**30s** 告警去重、**`wd_stats.alert_dedup`**、TLS ADR、SOAR **§5.4** 候选 PID 草案等（见各 **`docs/SHELLCODE_*.md`**） |
