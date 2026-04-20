/**
 * §4 预处理 — 可配置「是否上报」规则（路径/命令行等子串匹配），在 dedup 之前求值。
 * 规则列表格式见 docs/PREPROCESS_RULES.md。
 */
#ifndef EDR_EMIT_RULES_H
#define EDR_EMIT_RULES_H

#include "edr/behavior_record.h"

#include <stdint.h>

#define EDR_EMIT_RULE_NAME_LEN 64u
#define EDR_EMIT_RULE_PAT_LEN 256u

typedef enum {
  EdrEmitRuleActionUnset = 0,
  /** 命中则丢弃（不进入批次） */
  EdrEmitRuleActionDrop = 1,
  /** 命中则直接上报（绕过 dedup 与秒级限流；仍低于 priority==0 的采集侧高优） */
  EdrEmitRuleActionEmitAlways = 2,
} EdrEmitRuleAction;

typedef struct EdrEmitRule {
  char name[EDR_EMIT_RULE_NAME_LEN];
  /** 以下字段为空表示「不限制该维度」；多字段同时填写时为 AND。 */
  char exe_path_contains[EDR_EMIT_RULE_PAT_LEN];
  char cmdline_contains[EDR_EMIT_RULE_PAT_LEN];
  char file_path_contains[EDR_EMIT_RULE_PAT_LEN];
  char dns_query_contains[EDR_EMIT_RULE_PAT_LEN];
  char script_snippet_contains[EDR_EMIT_RULE_PAT_LEN];
  /** -1 = 任意类型；否则须等于 EdrEventType 数值 */
  int32_t event_type;
  uint8_t action;
  int icase_exe_path;
  int icase_cmdline;
  int icase_file_path;
  int icase_dns;
  int icase_script;
} EdrEmitRule;

struct EdrConfig;

void edr_emit_rules_configure(const struct EdrConfig *cfg);

/**
 * 按配置顺序匹配第一条满足全部条件的规则。
 * 返回：-1 无命中（继续 dedup/限流）；0 丢弃；1 立即上报。
 */
int edr_emit_rules_evaluate(const EdrBehaviorRecord *r);

#endif
