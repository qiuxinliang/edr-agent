# static.onnx 与《static_onnx_设计规范 v1.0》对齐说明

本文档对照仓库外设计文档 **`Cauld Design/static_onnx_设计规范_v1.0.md`**，说明当前 **`edr-agent`**（`src/ave/ave_onnx_infer.c`、`ave_engine.c`、`ave_sdk.c`）的**落地范围**与**差距**，便于排期与验收。

设计规范全文仍以 Cauld Design 目录为准；此处不重复特征字典与训练细节。

**相关文档**：`docs/AVE_ONNX_CONTRACT.md`（接口目标 vs 现状）、`docs/AVE_RD_ROADMAP.md`（研发路线与第一阶段完成情况）。

---

## 1. 章节级对照

| 规范章节 | 主题 | edr-agent 状态 |
|----------|------|----------------|
| §1 | 问题建模（三任务、512 维、输出结构） | **部分**：三输出名匹配时，`EdrAveInferResult` 与 `AVEScanResult`（`family_name`、`is_packed` 等）已落地；EMBER 全量特征仍非 Agent 范围。 |
| §2 | 文件格式与 Magic/各 Extractor | **未实现**：无 PE/ELF/脚本等提取器链。 |
| §3 | EMBER 2351 → PCA → 扩展 81 → 投影 512 | **部分**：已实现 **lite 512**（256 字节直方图 + 256 分块熵 + L2），**非**完整 EMBER+PCA。 |
| §4–§6 | 模型架构、数据集、训练、损失/SHAP | **训练侧**（非 Agent 仓库范围）。 |
| §7.1 | ONNX 导出、`features` 命名、三输出、`.avepkg` | **训练侧**；Agent 未内置解包 `static_pkg.avepkg`。 |
| §7.2 | 输入 `[B,512]`、三输出张量、metadata | **部分**：512 维 + 三输出名匹配时已对齐；metadata 未强制；非 512 或非三输出仍走 legacy。 |
| §8 | 端侧流水线（缓存、EMBER、PCA、L2、ORT、解析） | **部分**：具备 SHA256、ORT `Run`、lite512 的 L2、三输出解析与 `apply_infer_verdict` 阈值后处理；缺缓存、完整 EMBER/PCA/投影流水线。 |
| §9–§11 | 门禁、局限性、附录 | **流程/文档**，不属端点代码交付项。 |

---

## 2. §7.2 / §8 与实现逐条对照

| 规范要求 | 当前实现 |
|----------|----------|
| 输入名 `features`，形状 `[batch,512]`，float32，L2 归一化 | **512 元素且未 legacy**：`edr_ave_static_features_lite_512`（L2）。**否则**：`fill_input_from_file` 按首输入元素数读字节 `byte/255.f`（与 §7.2 512 维语义不同）。分支规则见 **`docs/AVE_ONNX_CONTRACT.md` §1 P0**。 |
| 输出 `verdict_probs` / `family_probs` / `packer_probs` | 三输出名匹配时一次 `Run` 三路，写入 `EdrAveInferResult`；legacy 单输出仍走标量/argmax。 |
| EMBER → PCA → 扩展 → 投影 → L2 | **未实现**（lite512 为近似路径）。 |
| 24h 结果缓存、MD5 | **未实现** / **未实现**。 |
| §8 示例中的 verdict 阈值修正（如 SUSPICIOUS 低置信度降 CLEAN） | **`apply_infer_verdict`** 中已实现（与静态规则域一致的可调阈值）。 |

---

## 3. 代码入口（便于 Code Review）

- 静态模型发现与加载：`src/ave/ave_engine.c`（`model_dir` 下首个非 `behavior.onnx` 的 `.onnx`）。
- ONNX Runtime 会话与推理：`src/ave/ave_onnx_infer.c`（`EDR_HAVE_ONNXRUNTIME`）。
- 扫描集成：`src/ave/ave_sdk.c` → `edr_ave_infer_file`。

---

## 4. 若需与规范 v1.0 严格对齐（建议方向）

1. **特征（P2-1 工程口径）**：**当前 Agent 不实现**完整 EMBER 2351 + PCA + 扩展 81 + 投影 §3 流水线。端侧与训练对齐的方式为：  
   - **Lite512**（`edr_ave_static_features_lite_512`）或 **Legacy 字节填充** 填入 ONNX `features`（见 **`docs/AVE_ONNX_CONTRACT.md` §1 P0**）；或  
   - **产品另行约定**「大块特征在训练侧完成、导出为单张量」——与 §7.1「特征在 ONNX 内」若冲突，需在规范侧正式改版。  
   完整 §3 端上实现仍属**后续阶段**，非本表「已关闭」项的交付范围。
2. **张量**：输入 **`[1,512]`** 的 `features` 与训练导出一致时走 Lite512；大图张量走 Legacy；可选加载 `pca_matrix` / 投影矩阵及版本 manifest（未实现）。
3. **输出**：三输出路径已写入 `AVEScanResult.family_name` / `is_packed`；若需 Top-K family 或 packer 明细，再与 `09_AVEngine` / 序列化约定扩展字段。
4. **结果缓存（P2-2）**：`AVE_ScanFile` 在已有 **SHA256** 前提下，对 **`edr_ave_infer_file`** 结果做进程内 **LRU + 可选 TTL**（`[ave].static_infer_cache_*` / `EDR_AVE_STATIC_INFER_CACHE_*`）；**`AVE_SyncFromEdrConfig` / `AVE_ApplyHotfix` / `AVE_UpdateModel`（static）/ `AVE_Shutdown`** 会清空缓存。§8 的 24h 磁盘缓存仍属可选扩展。
5. **§8 置信度修正**：`apply_infer_verdict` 已覆盖部分静态阈值策略；更复杂的 §8 后处理按需排期。

---

## 5. 版本

- 文档首次写入：与 `static_onnx_设计规范_v1.0.md`（v1.0）对照。
- 实现演进时请同步更新本节或 `docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md` 中的相关段落。
