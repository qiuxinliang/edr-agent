/**
 * 从 p0_rule_bundle_ir_v1.json 加载 P0 条件（B2.1），用 PCRE2 对 command_* 与 *_regex 求值，语义对齐
 * edr-backend `internal/dynamicrules`（process_create / file_read|file_write / network_connect / registry_set）。
 * 无 PCRE2 或未成功加载时由 p0_rule_match 回退到内嵌启发式（legacy，仅 process_create）。
 */
#ifndef EDR_P0_RULE_IR_H
#define EDR_P0_RULE_IR_H

#include "edr/behavior_record.h"

/* 在首次需匹配时惰性加载；可多次调用。 */
void edr_p0_rule_ir_lazy_init(void);

/* 1 = 已从 JSON 成功编译至少一条 P0 规则。 */
int edr_p0_rule_ir_is_ready(void);

/* 在 IR 已就绪时，对单条已加载规则按 rule_id 求值（仅对 event_type=process_create 有效；对拍/legacy）。 */
int edr_p0_rule_ir_matches(
    const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int process_chain_depth);

/* 为直出取元数据；若未加载或无该 id 则返回 0 且 *title=*mitre= 置空。 */
int edr_p0_rule_ir_get_meta(const char *rule_id, const char **out_title, const char **out_mitre_csv);

/* 已加载且 event_type=process_create 的规则条数（供直出遍历）。 */
int edr_p0_rule_ir_process_create_count(void);

int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id);

/* 已加载规则总条数（各 event_type）。 */
int edr_p0_rule_ir_rule_count(void);
int edr_p0_rule_ir_rule_id_at(int index, const char **out_id);
/* 根据 br 的 type 与规则 event_type 是否一致 + 条件求值；用于直出遍历。 */
int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index);

#endif
