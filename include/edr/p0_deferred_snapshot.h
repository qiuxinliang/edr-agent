#ifndef EDR_P0_DEFERRED_SNAPSHOT_H
#define EDR_P0_DEFERRED_SNAPSHOT_H
#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"

/* Stable, field-based local persistence; never memcpy a compiler-dependent
 * BehaviorRecord ABI to disk. The caller frees the encoded allocation. */
int edr_p0_deferred_snapshot_encode(const EdrBehaviorRecord *record,
    const EdrP0RuleIrBinding *binding, const char *rule_id,
    char **out, size_t *length);
int edr_p0_deferred_snapshot_decode(const char *json, size_t length,
    EdrBehaviorRecord *record, EdrP0RuleIrBinding *binding,
    char *rule_id, size_t rule_cap);
#endif
