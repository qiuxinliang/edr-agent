/**
 * §4 本地预处理：30s 去重、1s 窗口高频限流（与设计阈值对齐，可配置）。
 */
#ifndef EDR_DEDUP_H
#define EDR_DEDUP_H

#include "edr/behavior_record.h"

#include <stdint.h>

/** 在去重表使用前调用（与 §11 preprocessing 对齐） */
void edr_dedup_configure(uint32_t dedup_window_s, uint32_t high_freq_threshold_per_sec);

void edr_dedup_init(void);
void edr_dedup_reset(void);

/** priority==0 始终上报；否则去重 + 限流。返回 1=输出，0=丢弃 */
int edr_preprocess_should_emit(const EdrBehaviorRecord *r);

void edr_dedup_get_stats(uint64_t *out_dedup_drops, uint64_t *out_rate_drops);

#endif
