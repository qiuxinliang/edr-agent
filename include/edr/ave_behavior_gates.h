/**
 * 《11_behavior.onnx详细设计》**§7** 推理触发与分数带、**§8.1** 端侧 ONNX 形状门禁。
 * 与 `ave_behavior_pipeline.c` / `pid_history.h` 文实一致；训练侧质量指标见《11》**§9.3**。
 *
 * ### 阈值命名（文档 ↔ 源码）
 *
 * | 《11》文档用语 | C 宏 | 值 | 语义 |
 * |----------------|------|-----|------|
 * | 中危下界 / 中等分数区间下界 | **EDR_AVE_BEH_SCORE_MEDIUM_LOW** | 0.40 | 模型分 ∈ **[MEDIUM_LOW, HIGH)** 计「连续中等」并走中危告警带 |
 * | 高危阈值 / 高危告警（含） | **EDR_AVE_BEH_SCORE_HIGH** | 0.65 | **`on_behavior_alert`** 高危分支；**`[ave] l4_realtime_anomaly_threshold`** 产品默认与此对齐（`config.h`） |
 * | PMFE 建议扫描线（§2.2 / `feature_config.pmfe_trigger`） | **EDR_AVE_PMFE_TRIGGER_SCORE** | **0.45** | 与 Python **`T-integration-test`** / `BEHAVIOR_THRESHOLDS` 对齐；行为管线对 PMFE 另见 **立即推理** 路径 |
 *
 * 推理步长宏见下表 **EDR_AVE_BEH_INFER_STEP_***。
 */
#ifndef EDR_AVE_BEHAVIOR_GATES_H
#define EDR_AVE_BEHAVIOR_GATES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 《11》§7.2：**中危下界**（含）；连续「中等模型分」计数与 **[MEDIUM_LOW, HIGH)** 区间 */
#define EDR_AVE_BEH_SCORE_MEDIUM_LOW 0.40f
/** 《11》§7.3：**高危阈值**（含）；上一条为开区间上界（中等为 **[MEDIUM_LOW, HIGH)**） */
#define EDR_AVE_BEH_SCORE_HIGH 0.65f
/** 《11》§2.2 / 训练 `feature_config.BEHAVIOR_THRESHOLDS["pmfe_trigger"]`：PMFE 建议内存扫描线（Python 契约与集成测试） */
#define EDR_AVE_PMFE_TRIGGER_SCORE 0.45f

/** 《11》§7.1：步长自适应触发 — 默认每 N 个事件可触发一次 ORT（无显式 legacy 环境变量时） */
#define EDR_AVE_BEH_INFER_STEP_DEFAULT 16u
/** §7.1：连续 ≥3 次中等模型分后步长减半 */
#define EDR_AVE_BEH_INFER_STEP_TIGHT 8u
#define EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT 3u

/** 《11》§8.1：端侧固定输入 shape (1, seq, feat)；须与 `EDR_PID_HISTORY_*` 一致 */
#define EDR_AVE_BEH_ONNX_SEQ_LEN 128
#define EDR_AVE_BEH_ONNX_FEAT_DIM 64

#ifdef __cplusplus
}
#endif

#endif
