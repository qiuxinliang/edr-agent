/**
 * 预处理上送前：P0 动态规则直出 BehaviorAlert（与平台 dynamicrules 对拍，见 p0_golden_test.go）。
 * 默认关：环境变量 EDR_P0_DIRECT_EMIT=1 开启。
 */
#ifndef EDR_P0_RULE_DIRECT_EMIT_H
#define EDR_P0_RULE_DIRECT_EMIT_H

#include "edr/behavior_record.h"

void edr_p0_rule_try_emit(const EdrBehaviorRecord *br);

#endif
