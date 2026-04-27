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

/**
 * 是否上送：默认可丢弃「ETW1 非可打印、仅 `raw_etw…parse=failed` 且无 reg/file/dns/网络等字段」的槽位
 *（含原网络 20–23 类与同类其它 type；不受 priority 豁免）。
 * `EDR_PREPROCESS_ALLOW_UNPARSED_NET_EVENTS=1` / `true` / `yes` 恢复上送（对拍/定位）。
 * 其馀：priority==0 始终上报；否则 emit 规则 + 去重 + 限流。返回 1=输出，0=丢弃
 */
int edr_preprocess_should_emit(const EdrBehaviorRecord *r);

void edr_dedup_get_stats(uint64_t *out_dedup_drops, uint64_t *out_rate_drops);

/** 因上述 parse=failed 策略丢弃的条数（可对照 shutdown 日志中 junk_parse_failed_drops） */
uint64_t edr_dedup_junk_parse_failed_drops(void);

#endif
