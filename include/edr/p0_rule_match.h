/**
 * P0 动态规则（R-EXEC-001 / R-CRED-001 / R-FILELESS-001）在 process_create 上的整体验证，
 * 与 `edr-backend` `dynamicrules.MatchRules` 单条规则语义同构。供 `p0_rule_direct_emit` 与
 * `edr_p0_golden_test` 使用。
 */
#ifndef EDR_P0_RULE_MATCH_H
#define EDR_P0_RULE_MATCH_H

/**
 * 若 (process_name, cmdline) 对给定 rule_id 应命中则返回 1，否则 0。未知 rule_id 恒为 0。
 * rule_id 形如 "R-EXEC-001"。`process_chain_depth` 为 0 表示未知/无链深（与金线用例一致）。
 */
/** `parent_name` 可为 NULL；无父进程名时带 parent_* 条件的规则不命中。 */
int edr_p0_rule_matches3(
    const char *rule_id, const char *process_name, const char *cmdline, const char *parent_name, int process_chain_depth
);

int edr_p0_rule_matches2(
    const char *rule_id, const char *process_name, const char *cmdline, int process_chain_depth
);

/* 与金线/旧调用兼容：无父名、链深 0。 */
#define edr_p0_rule_matches(rid, pn, cmd) edr_p0_rule_matches3((rid), (pn), (cmd), NULL, 0)

#endif
