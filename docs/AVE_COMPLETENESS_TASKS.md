# AVE 完整度评估与修复任务表

本文基于当前**已跑通**路径与已知差距整理，便于逐项关闭。权威差距分析仍以 **`docs/AVE_ONNX_CONTRACT.md`**、**`docs/STATIC_ONNX_SPEC_GAP.md`**、**`docs/BEHAVIOR_ONNX_SPEC_GAP.md`** 为准。

---

## 1. 当前已验证范围（基线）

| 维度 | 状态 | 说明 |
|------|------|------|
| C 端双模型加载 + 扫描 + 行为推理 | **已通** | `test_ave_e2e_full` / `scripts/ave_e2e_release_smoke.sh`；`model_dir` 下 `static.onnx` + `behavior.onnx`。 |
| static 大图输入元素上限 | **已调** | `EDR_AVE_STATIC_INPUT_NELEM_MAX`（20Mi）；与训练导出的大 `features` 张量一致。 |
| Python ORT 集成测试 | **已通** | 仓库 **`T-integration-test/test_ave_pipeline.py`**（默认指向 `model/releases/current.json`）；与 C 端输入形态**不必相同**（见下表差距）。 |
| 设计文档 §7.2 三输出名 | **C/Python 对齐** | 三输出名匹配时 C 端写入 `EdrAveInferResult` 并 **`apply_infer_verdict`** → `AVEScanResult`（`family_name` Top-1、`is_packed`）；契约见 **`AVE_ONNX_CONTRACT.md` §1 P0**。 |

---

## 2. 完整度结论（高层）

- **behavior.onnx 端侧路径**：与《11》对齐度**较高**（序列维、双输出、管线集成已有落地）。
- **static.onnx 端侧路径**：与《static_onnx》**全量 §8 流水线**仍有明显差距；**P0** 已在 `AVE_ONNX_CONTRACT.md` 冻结 **Lite512** 与 **Legacy 字节填充** 的分支规则；产品侧若需「仅支持一种导出」，再收窄加载策略。
- **AVEngine 策略层**（误报抑制、证书、IOC、PMFE 联动）：**Python 集成测试中有模拟**；C 端 `ave_suppression` 等与《09》逐条对照仍有待办。
- **跨栈一致性**：Python 集成测试 **≠** 与 **`edr_agent` 进程内路径**等价；需任务表区分「ORT 契约测试」与「Agent 真链测试」。

---

## 3. 任务表（建议按优先级）

### P0 — 定义单一事实与门禁（**已关闭**）

| ID | 主题 | 现状 / 风险 | 建议动作 | 验收 |
|----|------|-------------|----------|------|
| **P0-1** | static 输入语义 | 训练侧为 `[B,512]` 特征 vs 端上可能存在大维 `features` / legacy 字节填充并存 | **已做**：`AVE_ONNX_CONTRACT.md` §1 **P0 门禁**表（Lite512 vs Legacy 字节填充、环境变量 `EDR_AVE_STATIC_LEGACY512`）；`STATIC_ONNX_SPEC_GAP` 已同步 | 文档与 `edr_onnx_infer_file` 分支一致 |
| **P0-2** | 三输出在 C 侧落地 | 扫描结果需可观测 family/packer | **已做**：`edr_onnx_infer_file` 三输出 + **`apply_infer_verdict`**（`family_name` Top-1、`is_packed`）；差距文档已更新 | 三输出 ONNX + 扫描路径可见上述字段 |
| **P0-3** | Windows 默认 `model_dir` | 默认仍为 Unix 风格路径，易误用 | **已做**：`config.c` 在 **`#ifdef _WIN32`** 下默认 **`<edr_agent.exe 同目录>\\models`**（`GetModuleFileNameW`）；从示例复制的 **`/opt/edr/models`** 在加载后自动改写；若解析失败则回退 **`C:\\ProgramData\\EDR Agent\\models`**（与 Inno **`%ProgramFiles%\\EDR Agent`** 命名一致） | 无 `[ave]` 或示例 Unix 路径时 Win 与安装目录一致 |

### P1 — 测试与 CI（**已关闭**）

| ID | 主题 | 现状 | 建议动作 | 验收 |
|----|------|------|----------|------|
| **P1-1** | C 全流程进 CI | 依赖本机 ORT + 大模型可能过重 | **已做**：CMake **`ave_e2e_full_smoke`** 将 `tests/fixtures/*_minimal.onnx` 拷为 `build/test_models_e2e/` 下 **`static.onnx` + `behavior.onnx`** 并跑 **`test_ave_e2e_full`**；**`.github/workflows/edr-agent-ci.yml`** 增加 **`ort-e2e-ubuntu`** job（下载 ONNX Runtime、`-DEDR_WITH_ONNXRUNTIME=ON`、全量 ctest） | 默认无 ORT 的 job 仍绿；ORT job 含 e2e |
| **P1-2** | Python 与 C 对齐 | `T-integration-test` 固定 `(N,512)`，与 C 大图路径不一致 | **已做**：`probe_static_session` + 报告 banner；**`random_static_tensor`** 按首路 shape 造随机输入；**tail≠512** 时跳过依赖 `make_static_feature` 的组并提示 C 脚本；**`T-integration-test/README.md`** 对照表 | 报告无歧义 |
| **P1-3** | `--stub` 关闭后的语义用例 | stub 下方向性断言跳过 | **已做**：**`ITEST_SEMANTIC_SEED`** 固定 numpy 种子；非 stub 且 512 契约时增加 **ORT 同输入确定性** 断言；README 给出无 `--stub` 命令示例 | 与 release 模型组合可本地复现 |

### P2 — 特征与性能（**已关闭**）

| ID | 主题 | 现状 | 建议动作 | 验收 |
|----|------|------|----------|------|
| **P2-1** | EMBER+PCA+81+投影 | 端侧未做完整 §3 | **已做**：**`STATIC_ONNX_SPEC_GAP.md` §4** 明确 **P2-1 工程口径**（Lite512+Legacy / 训练导出张量；完整 §3 为后续阶段） | 与 `AVE_ONNX_CONTRACT` §1 P0 一致 |
| **P2-2** | 结果缓存 / MD5 | 未实现 | **已做**：`AVE_ScanFile` 在 SHA256 后 **LRU** 缓存 **`EdrAveInferResult`**（**`[ave].static_infer_cache_*` + env**）；**`AVE_SyncFromEdrConfig` / `AVE_ApplyHotfix` / `AVE_UpdateModel`(static) / `AVE_Shutdown`** 清空 | 默认关闭；开启后可测重复扫描同一文件 |
| **P2-3** | 性能基线 | 阈值依赖机器 | **已做**：**`AVE_ONNX_LOCAL_STACK.md` §7** 汇总 **`ITEST_*` / `EDR_AVE_*` / 缓存**；CI 仍用 **ort-e2e-ubuntu** 固定 ORT | 同机可对比 |

### P3 — 行为管线与《09》策略（**已关闭**）

| ID | 主题 | 现状 | 建议动作 | 验收 |
|----|------|------|----------|------|
| **P3-1** | PMFE / 步长 / §7 立即推理 | 部分启发式，与文档逐条未闭合 | **已做**：**`docs/AVE_P3_TRACEABILITY.md`**（§7 立即推理 / 步长 / `EDR_AVE_BEH_INFER_MIN_EVENTS` / PMFE 与 Python）；**`BEHAVIOR_ONNX_SPEC_GAP`** 更新一行 | 章节 ↔ 源码可追踪 |
| **P3-2** | 四层抑制与 Python 模拟一致性 | Python `test_ave_pipeline` 有逻辑；C 路径更复杂 | **已做**：可追溯表 **§3**（标明 L1–L4 与 **0.80/0.40 vs C 默认 0.60** 差异）；**`EDR_AVE_PMFE_TRIGGER_SCORE`** + 扩展 **`test_ave_behavior_gates`** 校验 **0.40/0.65/0.45** | 阈值宏与 `feature_config` 一致；策略差异文档化 |

### P4 — 打包与部署（**已关闭**）

| ID | 主题 | 现状 | 建议动作 | 验收 |
|----|------|------|----------|------|
| **P4-1** | `.avepkg` / manifest | Agent 未内置解包 | **已做**：**`docs/AVE_PACKAGING_P4.md`** + 仓库根 **`model/README.md`** 指针；平台解压至 `model_dir` | 无「静默失败」 |
| **P4-2** | 模型热更 / `AVE_ApplyHotfix` | 已有代码路径，覆盖不足 | **已做**：**`AVE_GetStatus`** 填 **`static_model_version`**（`onnx:<leaf>`）；目录热更无 onnx 时 **`EDR_ERR_INVALID_ARG`**；**`scripts/ave_hotfix_release_smoke.sh`** + **`test_ave_hotfix_smoke`** / **`ave_hotfix_smoke`**（及 Unix **`ave_hotfix_empty_dir_fail`**） | 热更后 ORT 重载与版本串可见 |

---

## 4. 建议执行顺序（迭代）

1. ~~**P0**~~（**已关闭**：契约 + 三输出扫描字段 + Win 默认 `model_dir`）。  
2. ~~**P1**~~（**已关闭**：ORT CI e2e + Python 探针/种子 + 文档）。  
3. ~~**P2**~~（**已关闭**：§3 口径文档 + LRU 缓存 + 环境变量表）。  
4. ~~**P3**~~（**已关闭**：**`AVE_P3_TRACEABILITY.md`** + 宏/门禁）。  
5. ~~**P4**~~（**已关闭**：**`AVE_PACKAGING_P4.md`** + 热更冒烟 + GetStatus）。

---

## 5. 相关脚本与入口（便于挂任务）

| 用途 | 路径 |
|------|------|
| C 端全流程（ORT + 扫描 + behavior infer） | `edr-agent/scripts/ave_e2e_release_smoke.sh`、`tests/test_ave_e2e_full.c` |
| P4 热更 + GetStatus | **`edr-agent/scripts/ave_hotfix_release_smoke.sh`**、`tests/test_ave_hotfix_smoke.c`；说明 **`docs/AVE_PACKAGING_P4.md`** |
| Python ORT 契约与策略模拟 | 仓库根 `T-integration-test/run.sh` |
| 差距权威 | `docs/STATIC_ONNX_SPEC_GAP.md`、`docs/BEHAVIOR_ONNX_SPEC_GAP.md`、`docs/AVE_ONNX_CONTRACT.md` |
| P3 可追溯（《09》/《11》/Python） | **`docs/AVE_P3_TRACEABILITY.md`** |
| 平台 / 控制台与 AVE | **`docs/AVE_PLATFORM_FRONTEND.md`**（服务端指令与前端展示边界） |

---

*随任务关闭请同步更新本表状态列（可在 PR 中勾选 ID）。*
