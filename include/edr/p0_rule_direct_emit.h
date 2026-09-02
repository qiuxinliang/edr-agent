/**
 * 预处理上送前：P0 动态规则直出 BehaviorAlert（与平台 dynamicrules 对拍，见 p0_golden_test.go）。
 * 默认开：环境变量 EDR_P0_DIRECT_EMIT=0 可关闭。
 */
#ifndef EDR_P0_RULE_DIRECT_EMIT_H
#define EDR_P0_RULE_DIRECT_EMIT_H

#include "edr/behavior_record.h"

#include <stddef.h>

/* Returns the number of P0 combined frames synchronously accepted by the
 * persistent high-priority offline queue. */
int edr_p0_rule_try_emit(const EdrBehaviorRecord *br);

/* Collector capability gates have no rule/bundle/action authority.  Return
 * 1 only after the source-only record is durably accepted; return 2 when it
 * is retained in the bounded, non-overwrite retry lane; return 0 after the
 * lane/capability has become terminal-unhealthy. Callers must stay paused
 * until the normal preprocess retry loop reports a durable commit. */
int edr_p0_rule_emit_collector_evidence_gate(const EdrBehaviorRecord *record);

/* Submits a production-built process pre-evaluation source-only record through
 * the same bounded durable handoff. The caller supplies the registered reason
 * used to construct its typed context; arbitrary telemetry cannot claim this
 * gate. Return values match the collector gate API. */
int edr_p0_rule_emit_pre_evaluation_gate(const EdrBehaviorRecord *record,
                                         const char *reason);

/* Attempts one retained source-only durable record without creating a worker
 * or a second persistent queue.  A positive result copies the exactly
 * committed record to `committed_out`, so the collector can resume only after
 * its own capability gate was actually accepted by SQLite. */
int edr_p0_rule_poll_source_only_durable_retry(EdrBehaviorRecord *committed_out);

/* A retry-lane capacity or SQLite failure is a P0 capability boundary: no
 * direct enforcement may run while this returns false. */
int edr_p0_rule_source_only_capability_healthy(char *reason, size_t reason_cap);

/* Runtime source-only faults are scoped to the P0 event family which lost
 * authority. A historic latch recovered after restart has no trustworthy
 * in-memory family and therefore remains global until its central ACK is
 * observed. */
int edr_p0_rule_source_only_capability_healthy_for_event(
    EdrEventType type, char *reason, size_t reason_cap);

/* Supplies the durable capability-audit identity after agent configuration is
 * available. `endpoint_id=auto` is intentionally not sufficient to recover. */
void edr_p0_rule_source_only_set_runtime_identity(const char *tenant_id,
                                                   const char *endpoint_id);

/* Called after the existing offline queue opens and periodically by the
 * preprocess loop. A historic latch is cleared only after the exact
 * source_only_delivery capability audit has committed through event_queue and
 * the current P0 IR is healthy. */
int edr_p0_rule_source_only_recover_after_queue_open(void);

typedef struct { uint64_t suppressed_total, exact_suppressed, equal_quality_suppressed, identity_upgrade_seen, lower_quality_suppressed, intermediate_upgrade_suppressed, pre_rule_event_duplicates, pending_backpressure; } EdrP0DedupMetrics;
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
  /* Block-policy candidates reserve a separately metered critical lane so
   * ordinary alert rate limits cannot suppress a required durable intent. */
  uint64_t critical_reservations;
  /* Normal alert governor suppression is an expected rate-limit outcome,
   * not a source-only durability failure. */
  uint64_t governor_suppressed;
  /* A full dedup/ordinary queue never permits an unrecorded action. These
   * count the source-only NOT_EVALUABLE fallback and its durable-write error. */
  uint64_t source_only_backpressure_emitted, source_only_backpressure_failed;
  uint64_t source_only_retry_pending, source_only_retry_attempts;
  uint64_t source_only_retry_committed, source_only_retry_capacity_exhausted;
  int source_only_terminal_unhealthy;
  uint32_t source_only_unhealthy_families;
  int source_only_loss_detected;
  uint64_t source_only_latch_counter;
  uint64_t source_only_latch_epoch;
  char source_only_queue_nonce[33];
  char source_only_terminal_reason[96];
} EdrP0EmitMetrics;
void edr_p0_rule_get_emit_metrics(EdrP0EmitMetrics *out);
#ifdef EDR_P0_DIRECT_EMIT_TESTING
#include "edr/policy_enforcement.h"

void edr_p0_rule_test_reset_dedup(void);
/* Simulates a fresh process before queue-open recovery without mutating the
 * production queue/header implementation. */
void edr_p0_rule_test_force_source_only_startup(void);
void edr_p0_rule_test_set_monotonic_ms(uint64_t value);
/* Uses the production source-only context builder; test-only so fixture
 * generators cannot drift into a hand-written terminal/source schema. */
int edr_p0_rule_test_build_source_only_direct_record(const EdrBehaviorRecord *record,
                                                      const char *rule_id,
                                                      const char *reason,
                                                      EdrBehaviorRecord *out);
/* Uses the production no-rule/no-bundle ruleset-evaluation gate builder. */
int edr_p0_rule_test_build_source_only_ruleset_evaluation_record(
    const EdrBehaviorRecord *record, const char *reason, EdrBehaviorRecord *out);
int edr_p0_rule_test_build_source_only_collector_evidence_record(
    const EdrBehaviorRecord *record, EdrBehaviorRecord *out);
int edr_p0_rule_test_build_source_only_delivery_record(
    const uint8_t queue_nonce[16], uint64_t latch_counter, uint64_t latch_epoch,
    EdrBehaviorRecord *out);
/* Builds both terminal phases through the production terminal builders.  It
 * deliberately exposes no production admission or execution side effect. */
int edr_p0_rule_test_build_terminal_authority_records(
    const EdrBehaviorRecord *record, const char *rule_id,
    const EdrPolicyEnforcementResult *result,
    EdrBehaviorRecord *intent_out, EdrBehaviorRecord *result_out);
#endif

#endif
