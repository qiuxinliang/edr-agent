/**
 * 预处理上送前：P0 动态规则直出 BehaviorAlert（与平台 dynamicrules 对拍，见 p0_golden_test.go）。
 * 默认开：环境变量 EDR_P0_DIRECT_EMIT=0 可关闭。
 */
#ifndef EDR_P0_RULE_DIRECT_EMIT_H
#define EDR_P0_RULE_DIRECT_EMIT_H

#include "edr/behavior_record.h"

void edr_p0_rule_try_emit(const EdrBehaviorRecord *br);

typedef struct { uint64_t suppressed_total, exact_suppressed, equal_quality_suppressed, identity_upgrade_seen, lower_quality_suppressed, intermediate_upgrade_suppressed, pre_rule_event_duplicates; } EdrP0DedupMetrics;
void edr_p0_rule_get_dedup_metrics(EdrP0DedupMetrics *out);
typedef struct {
  /* full and degraded are mutually exclusive per emitted alert. A minimal
   * literal is a degraded alert and is included in both degraded and
   * emitted_without_full_context; omission is also counted once for it. */
  uint64_t user_subject_full, user_subject_degraded;
  /* Number of degraded alerts for which optional context was omitted, not a field count. */
  uint64_t alerts_with_optional_omission;
  /* Raw values capped at their field limit while constructing user_subject_json. */
  uint64_t values_truncated, escape_overflow_values;
  uint64_t minimal_failures, emitted_without_full_context;
} EdrP0EmitMetrics;
void edr_p0_rule_get_emit_metrics(EdrP0EmitMetrics *out);
#ifdef EDR_P0_DIRECT_EMIT_TESTING
void edr_p0_rule_test_reset_dedup(void);
void edr_p0_rule_test_set_monotonic_ms(uint64_t value);
#endif

#endif
