# AVE / static·behavior ONNX 研发路线

本文档给出推荐任务顺序，与 **`docs/STATIC_ONNX_SPEC_GAP.md`**（static 与规范差距）、**`docs/AVE_ENGINE_IMPLEMENTATION_PLAN.md`**（AVE 总览）配合使用。与 **管控 / 控制台** 的协作边界见 **`docs/AVE_PLATFORM_FRONTEND.md`**。

---

## 阶段总览

| 阶段 | 目标 | 说明 |
|------|------|------|
| **第一阶段** | 契约冻结、基线测试、文档同步 | 见下文「第一阶段」与 `docs/AVE_ONNX_CONTRACT.md` |
| **第二阶段** | static.onnx 对齐规范 | **已完成（基线）**：lite 512 特征 + 三输出解析 + SDK 映射；完整 EMBER+PCA 仍见差距文档 |
| **第三阶段** | 行为与联动 | behavior.onnx 与规范、L4×实时、证书吊销调优 |
| **第四阶段** | 运维与交付 | 模型包校验、独立 `edr_ave`、FL 接在特征稳定之后 |
| **第五阶段** | 持续优化 | FP/TP 闭环、多平台降级、可解释性（偏离线） |

---

## 第一阶段（已完成）

**目标**：在不大改代码的前提下，把「目标契约 vs 现状」写清，并加上可 CI 运行的最小回归。

| 项 | 状态 | 说明 |
|----|------|------|
| ONNX I/O 契约文档 | **已完成** | `docs/AVE_ONNX_CONTRACT.md`（目标规范 + 当前实现） |
| 基线自动化测试 | **已完成** | `tests/test_ave_phase1_contract.c` → `test_ave_phase1`，CMake `ave_phase1_contract` |
| 实施计划版本号 | **已完成** | `AVE_ENGINE_IMPLEMENTATION_PLAN.md` §6 与 `ave_sdk.h` / `AVE_GetVersion` 对齐 |
| 交叉引用 | **已完成** | `STATIC_ONNX_SPEC_GAP.md` 链到本路线与契约文档 |

**后续（仍属第一阶段的轻量维护）**

- 训练侧发布新版 ONNX 时，更新 `AVE_ONNX_CONTRACT.md` 的「目标」表与 `manifest` 约定。
- CI 中确保 `ctest -R ave_` 或全量 `ctest` 通过。

---

## 第二阶段（已完成 — 基线）

| 项 | 说明 |
|----|------|
| 512 维输入 | `src/ave/ave_static_features.c`：`edr_ave_static_features_lite_512`，在 `g_in_nelem==512` 且未设 `EDR_AVE_STATIC_LEGACY512=1` 时使用 |
| 三输出 | `ave_onnx_infer.c`：输出名匹配 `verdict`/`family`/`packer` 时 `Run` 三路，填充 `EdrAveInferResult` |
| 扫描结果 | `ave_sdk.c`：`onnx_layout==1` 时映射 verdict（含 SUSPICIOUS&lt;0.40→CLEAN）、首家族、`is_packed` |
| 测试 | `tests/test_ave_static_features.c`（L2≈1）、既有 `test_ave_*` 回归 |
| ORT 集成 | **`ave_static_onnx_triple_integration`**：`tests/test_ave_static_onnx_integration.c`，需 CMake **`-DEDR_WITH_ONNXRUNTIME=ON`** 且本机可链接 ONNX Runtime；fixture 为 `tests/fixtures/static_triple_minimal.onnx`（可用 `scripts/gen_minimal_static_triple_onnx.py` 再生） |

**仍待（非本阶段必达）**：完整 EMBER+PCA、`.avepkg`、ONNX metadata 校验 — 见 `STATIC_ONNX_SPEC_GAP.md`。

## 第三阶段及以后（摘要）

1. **Static 深化**：按差距文档补齐 EMBER 或经批准的替代特征与矩阵文件加载。
2. **Behavior**：与 `behavior_onnx_设计规范` 对齐（可另起 gap 文档）。
3. **联动与交付**：L4、吊销、模型包、`edr_ave` ABI。

---

## 版本

- 文档首次写入：与第一阶段交付同步。
