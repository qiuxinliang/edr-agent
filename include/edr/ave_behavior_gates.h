/**
 * 端侧行为启发式的告警分数带。
 *
 * ### 阈值命名（文档 ↔ 源码）
 *
 * | 《11》文档用语 | C 宏 | 值 | 语义 |
 * |----------------|------|-----|------|
 * | 高危阈值 / 高危告警（含） | **EDR_AVE_BEH_SCORE_HIGH** | 0.65 | **`on_behavior_alert`** 高危分支；**`[ave] l4_realtime_anomaly_threshold`** 产品默认与此对齐（`config.h`） |
 */
#ifndef EDR_AVE_BEHAVIOR_GATES_H
#define EDR_AVE_BEHAVIOR_GATES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 行为启发式高危阈值（含）。 */
#define EDR_AVE_BEH_SCORE_HIGH 0.65f

#ifdef __cplusplus
}
#endif

#endif
