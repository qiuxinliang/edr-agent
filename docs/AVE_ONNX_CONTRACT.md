# AVE：static / behavior ONNX 接口契约

本文档**冻结**两类约定：

1. **目标（Target）**：与《static_onnx_设计规范 v1.0》§7.2 及训练导出脚本一致时的期望接口，供训练与端侧对齐验收。
2. **当前（Current）**：`edr-agent` 现有 `src/ave/ave_onnx_infer.c` 行为，供 Code Review 与渐进迁移。

变更训练或端侧任一侧时，**须同步更新**本表。

---

## 1. static（`model_dir` 下首个非 `behavior.onnx` 的 `.onnx`）

| 项目 | 目标（规范 §7.2） | 当前实现 |
|------|-------------------|----------|
| 加载 | `ave_engine.c` 选首个非 `behavior.onnx` 的 `.onnx` | 相同 |
| 输入名 | `features`（建议） | 会话**第 0 个**输入名（任意） |
| 输入形状 / 数据 | `[batch, 512]`，float32，L2 归一化 | **若**首输入元素数为 **512**：`edr_ave_static_features_lite_512`（256 维字节直方图 + 256 维分块熵，再 **L2 归一化**）。**否则**：legacy — 动态维 `EDR_AVE_ONNX_IN_LEN`（默认 4096），**byte/255**。`EDR_AVE_STATIC_LEGACY512=1` 可强制 legacy 填充（即便 512 维）。 |
| 输出 | 三路：`verdict_probs`、`family_probs`、`packer_probs` | 若加载时检出输出名分别 **包含**（不区分大小写）`verdict` / `family` / `packer`，则 **一次 Run 取三路**，写入 `EdrAveInferResult`（`onnx_layout=1`）。否则 **legacy 单输出**。 |
| 元数据 | ONNX metadata 中版本、阈值等 | 未强制读取 |
| 环境变量 | — | `EDR_AVE_ONNX_IN_LEN`、`EDR_AVE_STATIC_READ_MAX`、`EDR_AVE_INFER_DRY_RUN` 等见 `ave_onnx_infer.c` / `ave_static_features.c` |

### P0 门禁：static 输入「多形态」与分支规则（冻结）

训练与端侧验收时，**须**在下列形态中明确其一（或同时支持并分别写用例）；与《static_onnx》§7.2 的 **`[B,512]`** 对齐时，通常对应下表 **Lite512** 行。

| 形态 | 触发条件（首输入元素数 `n`） | 端侧填充 | 与 §7.2 关系 |
|------|------------------------------|----------|--------------|
| **Lite512** | `n == 512` 且未设置 `EDR_AVE_STATIC_LEGACY512=1` | `edr_ave_static_features_lite_512`（256 字节直方图 + 256 分块熵 + **L2**） | 张量形状与 §7.2 一致；特征为 **lite 近似**（非完整 EMBER+PCA，见 `STATIC_ONNX_SPEC_GAP`） |
| **Legacy 字节填充** | `n != 512`，或 `EDR_AVE_STATIC_LEGACY512=1` | `fill_input_from_file`：`byte/255.f` 填入 `n` 维，不足补零（元素上限见 `EDR_AVE_STATIC_INPUT_NELEM_MAX`） | 与训练侧「大图 `features`」导出一致；**语义**与 §7.2 的 512 维向量**不同**，须单独验收 |

**三输出 → 扫描结果**：加载时若输出名分别匹配（不区分大小写，子串）`verdict` / `family` / `packer`，则一次 `Run` 取三路，`EdrAveInferResult.onnx_layout = 1`；`src/ave/ave_sdk.c` 中 **`apply_infer_verdict`** 将 verdict 映射为 `AVEScanResult` 的 `raw_ai_verdict` / `final_verdict`，并将 **family** 写入 `family_name`（Top-1）、**packer** 派生 `is_packed`（任一路径概率高于阈值时）。

**说明**：完整 **EMBER 2351 + PCA + 扩展 81** 仍属训练/后续迭代；lite 512 与规范 §3「681→512」不同，但张量形状与 L2 约束与 §7.2 对齐，便于接规范导出之 ONNX。**差距**见 `docs/STATIC_ONNX_SPEC_GAP.md`。

---

## 2. behavior（`model_dir/behavior.onnx`）

| 项目 | 目标（与《behavior_onnx_设计规范》对齐，摘要） | 当前实现 |
|------|-----------------------------------------------|----------|
| 路径 | `…/behavior.onnx` | 相同 |
| 输入 | `(1,128,64)` 或 `(128,64)` 或展平 **`8192`**（与 `PidHistory.feat_chrono` 一致） | 会话第 0 个输入；**`refine_behavior_input_dims`** 解析动态维；**`edr_onnx_behavior_input_nelem()`** / **`edr_onnx_behavior_input_seq_len()`**；单轴 `[-1]` 按 `EDR_AVE_BEH_SEQ_LEN`×`EDR_AVE_BEH_IN_LEN` 展开 |
| 输出 | **`anomaly_score`** + **`tactic_probs`**（14） | 加载时扫描输出名：含 **`tactic`** 的为战术头；含 **`anomaly`** 的为异常分；否则回退为输出 0 / 1。双输出时 **一次 Run** 取两路；`tactic_probs` 张量元素数 ≥14 时取前 14 维写入回调缓冲。单输出时战术向量填 **0**。异常分：单元素取标量，否则 **argmax** 作兼容分数。 |
| 调用方 | `ave_behavior_pipeline.c` 等 | `edr_onnx_behavior_infer(..., tactic_probs)`；告警中 **`triggered_tactics`** 为概率 **>0.5** 的战术名（§6.3 顺序） |

环境变量：**`EDR_AVE_BEH_IN_LEN`**（feat 默认 **64**）、**`EDR_AVE_BEH_SEQ_LEN`**（seq 默认 **128**）用于解析动态轴。**差距**见 `docs/BEHAVIOR_ONNX_SPEC_GAP.md`。

---

## 3. 全局前置：`edr_ave_infer_file`（`ave_engine.c`）

在调用 `edr_onnx_infer_file` 之前：

- 若 **`EDR_AVE_INFER_DRY_RUN=1`**：直接 **`EDR_OK`**，不加载 ORT（用于 CI / 无模型环境）。
- 否则若 **`edr_onnx_runtime_ready()==0`**：返回 **`EDR_ERR_NOT_IMPL`**（未加载静态会话）。

---

## 4. 相关文件

- 实现：`src/ave/ave_onnx_infer.c`、`src/ave/ave_engine.c`
- 差距：`docs/STATIC_ONNX_SPEC_GAP.md`
- 路线：`docs/AVE_RD_ROADMAP.md`
