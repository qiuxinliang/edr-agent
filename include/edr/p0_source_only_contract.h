#ifndef EDR_P0_SOURCE_ONLY_CONTRACT_H
#define EDR_P0_SOURCE_ONLY_CONTRACT_H

/*
 * Single authority for source-only P0 dispositions.  These strings cross the
 * Agent/backend trust boundary, so an emitting path may not invent a reason
 * ad hoc.  Direct-stage records bind a real matched IR rule and its published
 * bundle; pre-evaluation records deliberately carry only this gate identity
 * because missing process evidence makes a rule match unsafe to claim.
 */

#include <stddef.h>
#include <string.h>

#include "edr/behavior_record.h"

#define EDR_P0_SOURCE_ONLY_CONTRACT_VERSION "p0-source-only-v2"
#define EDR_P0_PROCESS_EVIDENCE_GATE "P0_PROCESS_EVIDENCE_GATE"
#define EDR_P0_RULESET_EVALUATION_GATE "P0_RULESET_EVALUATION_GATE"
#define EDR_P0_FILE_READ_METADATA_GATE "P0_FILE_READ_METADATA_GATE"
#define EDR_P0_SOURCE_ONLY_DURABILITY_GATE "P0_SOURCE_ONLY_DURABILITY_GATE"
/* Retained for Agent <=3.2.408 durable-queue compatibility. New collectors
 * emit one of the two precise causes below. */
#define EDR_P0_FILE_READ_REASON_METADATA_BACKPRESSURE "file_read_metadata_backpressure"
#define EDR_P0_FILE_READ_REASON_CRITICAL_BINDING_CAPACITY \
  "file_read_critical_binding_capacity_exhausted"
#define EDR_P0_FILE_READ_REASON_FILE_KEY_AMBIGUOUS \
  "file_read_file_key_ambiguous"
#define EDR_P0_FILE_READ_REASON_START_KEY_MISSING "file_read_process_start_key_missing"
#define EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE \
  "file_read_live_generation_unavailable"
#define EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH "file_read_generation_mismatch"
#define EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED \
  "file_read_canonical_path_unresolved"
#define EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE "file_read_payload_unavailable"
#define EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE \
  "file_read_event_time_unavailable"
#define EDR_P0_FILE_READ_REASON_EVENT_BUS_UNAVAILABLE \
  "file_read_event_bus_unavailable"
#define EDR_P0_FILE_READ_REASON_ACTOR_IMAGE_UNRESOLVED "file_read_actor_image_unresolved"
#define EDR_P0_FILE_READ_REASON_DEFERRED_CAPACITY "file_read_deferred_capacity_exhausted"
#define EDR_P0_FILE_READ_REASON_DEFERRED_TIMEOUT "file_read_deferred_timeout"
#define EDR_P0_FILE_READ_REASON_DEFERRED_SHUTDOWN "file_read_deferred_shutdown"

typedef enum EdrP0SourceOnlyStage {
  EDR_P0_SOURCE_ONLY_STAGE_INVALID = 0,
  EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION = 1,
  EDR_P0_SOURCE_ONLY_STAGE_DIRECT = 2,
  /* An authenticated ruleset existed, but a source record could not be
   * evaluated under one retained snapshot.  It is neither a rule hit nor a
   * process-evidence gate, and intentionally carries no rule/bundle claim. */
  EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION = 3,
  /* A collector-side capability disposition.  This is deliberately neither
   * an IR rule match nor an alert/action authority. */
  EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE = 4,
  /* A restart/overflow lost the in-memory assertion before it reached the
   * existing durable event queue. It carries an explicit capability audit,
   * never a rule/bundle/action claim. */
  EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY = 5
} EdrP0SourceOnlyStage;

typedef struct EdrP0SourceOnlyReason {
  const char *reason;
  EdrP0SourceOnlyStage stage;
  const char *gate_id;
  /* Collector evidence-gate reasons bind to the exact field or bounded
   * collector resource that prevented evaluation. Other stages leave this
   * empty because their reason already identifies the owning boundary. */
  const char *rejected_field;
} EdrP0SourceOnlyReason;

#define EDR_P0_SOURCE_ONLY_PRE_EVALUATION_REASONS(X) \
  X("security_4688_enrichment") \
  X("evidence_enrichment_timeout") \
  X("evidence_worker_terminal_unhealthy") \
  X("evidence_worker_stalled") \
  X("target_4688_live_identity_mismatch") \
  X("target_4688_identity_incomplete") \
  X("target_4688_live_identity_unavailable") \
  X("process_generation_or_correlation_unavailable") \
  X("coalescer_backpressure") \
  X("missing_process_generation") \
  X("file_identity_unavailable") \
  X("image_path_not_resolved") \
  X("missing_process_identity") \
  X("missing_cmdline") \
  X("missing_parent_generation") \
  X("creator_only_identity") \
  X("missing_target_identity") \
  X("source_fields_truncated")

#define EDR_P0_SOURCE_ONLY_DIRECT_REASONS(X) \
  X("p0_dedup_pending_backpressure") \
  X("p0_alert_queue_backpressure") \
  X("terminal_authority_unavailable") \
  X("terminal_context_merge_failed") \
  X("terminal_intent_encoding_failed") \
  X("terminal_intent_conflict") \
  X("terminal_journal_unavailable")

#define EDR_P0_SOURCE_ONLY_RULESET_EVALUATION_REASONS(X) \
  X("p0_ir_evaluation_unavailable") \
  X("p0_ir_not_ready")

/* Kernel-File NameCreate/Read correlation and its live actor generation are
 * metadata only. These dispositions must never be relabelled as FILE_READ
 * rule hits merely because a later read cannot be safely correlated. */
#define EDR_P0_SOURCE_ONLY_COLLECTOR_EVIDENCE_GATE_REASONS(X) \
  X(EDR_P0_FILE_READ_REASON_METADATA_BACKPRESSURE, "collector_queue") \
  X(EDR_P0_FILE_READ_REASON_CRITICAL_BINDING_CAPACITY, "critical_binding") \
  X(EDR_P0_FILE_READ_REASON_FILE_KEY_AMBIGUOUS, "file_key") \
  X(EDR_P0_FILE_READ_REASON_START_KEY_MISSING, "process_start_key") \
  X(EDR_P0_FILE_READ_REASON_LIVE_GENERATION_UNAVAILABLE, "process_generation") \
  X(EDR_P0_FILE_READ_REASON_GENERATION_MISMATCH, "process_generation") \
  X(EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED, "canonical_path") \
  X(EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE, "payload") \
  X(EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE, "event_time_ns") \
  X(EDR_P0_FILE_READ_REASON_EVENT_BUS_UNAVAILABLE, "event_bus") \
  X(EDR_P0_FILE_READ_REASON_ACTOR_IMAGE_UNRESOLVED, "actor_image") \
  X(EDR_P0_FILE_READ_REASON_DEFERRED_CAPACITY, "deferred_queue") \
  X(EDR_P0_FILE_READ_REASON_DEFERRED_TIMEOUT, "deferred_queue") \
  X(EDR_P0_FILE_READ_REASON_DEFERRED_SHUTDOWN, "deferred_queue")

#define EDR_P0_SOURCE_ONLY_DELIVERY_REASONS(X) \
  X("pending_assertion_lost_on_restart")

#define EDR_P0_SOURCE_ONLY_PRE_ENTRY(reason_value) \
  {reason_value, EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION, EDR_P0_PROCESS_EVIDENCE_GATE, ""},
#define EDR_P0_SOURCE_ONLY_DIRECT_ENTRY(reason_value) \
  {reason_value, EDR_P0_SOURCE_ONLY_STAGE_DIRECT, "", ""},
#define EDR_P0_SOURCE_ONLY_RULESET_EVALUATION_ENTRY(reason_value) \
  {reason_value, EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION, \
   EDR_P0_RULESET_EVALUATION_GATE, ""},
#define EDR_P0_SOURCE_ONLY_COLLECTOR_EVIDENCE_GATE_ENTRY(reason_value, rejected_field_value) \
  {reason_value, EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE, \
   EDR_P0_FILE_READ_METADATA_GATE, rejected_field_value},
#define EDR_P0_SOURCE_ONLY_DELIVERY_ENTRY(reason_value) \
  {reason_value, EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY, \
   EDR_P0_SOURCE_ONLY_DURABILITY_GATE, ""},

static const EdrP0SourceOnlyReason edr_p0_source_only_reason_table[] = {
    EDR_P0_SOURCE_ONLY_PRE_EVALUATION_REASONS(EDR_P0_SOURCE_ONLY_PRE_ENTRY)
    EDR_P0_SOURCE_ONLY_DIRECT_REASONS(EDR_P0_SOURCE_ONLY_DIRECT_ENTRY)
    EDR_P0_SOURCE_ONLY_RULESET_EVALUATION_REASONS(
        EDR_P0_SOURCE_ONLY_RULESET_EVALUATION_ENTRY)
    EDR_P0_SOURCE_ONLY_COLLECTOR_EVIDENCE_GATE_REASONS(
        EDR_P0_SOURCE_ONLY_COLLECTOR_EVIDENCE_GATE_ENTRY)
    EDR_P0_SOURCE_ONLY_DELIVERY_REASONS(EDR_P0_SOURCE_ONLY_DELIVERY_ENTRY)
};

#undef EDR_P0_SOURCE_ONLY_PRE_ENTRY
#undef EDR_P0_SOURCE_ONLY_DIRECT_ENTRY
#undef EDR_P0_SOURCE_ONLY_RULESET_EVALUATION_ENTRY
#undef EDR_P0_SOURCE_ONLY_COLLECTOR_EVIDENCE_GATE_ENTRY
#undef EDR_P0_SOURCE_ONLY_DELIVERY_ENTRY

static inline size_t edr_p0_source_only_reason_count(void) {
  return sizeof(edr_p0_source_only_reason_table) /
         sizeof(edr_p0_source_only_reason_table[0]);
}

static inline const EdrP0SourceOnlyReason *edr_p0_source_only_reason_find(const char *reason) {
  size_t i;
  if (!reason || !reason[0]) return NULL;
  for (i = 0u; i < edr_p0_source_only_reason_count(); ++i) {
    if (strcmp(edr_p0_source_only_reason_table[i].reason, reason) == 0) {
      return &edr_p0_source_only_reason_table[i];
    }
  }
  return NULL;
}

static inline const char *edr_p0_source_only_stage_name(EdrP0SourceOnlyStage stage) {
  switch (stage) {
  case EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION:
    return "pre_evaluation";
  case EDR_P0_SOURCE_ONLY_STAGE_DIRECT:
    return "direct";
  case EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION:
    return "ruleset_evaluation";
  case EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE:
    return "collector_evidence_gate";
  case EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY:
    return "source_only_delivery";
  default:
    return "invalid";
  }
}

/* The pre-evaluation builder is the only production path that may turn an
 * incomplete process-create record into a source-only disposition.  Keeping
 * it beside the reason authority prevents the pipeline and durable encoder
 * from assembling divergent hand-written JSON. */
int edr_p0_source_only_build_pre_evaluation_record(const EdrBehaviorRecord *source,
                                                    const char *reason,
                                                    EdrBehaviorRecord *out);

/* Reject malformed, unregistered, or stage-mixed P0 source-only envelopes
 * before they cross the durable boundary.  Backend still verifies published
 * direct-rule bindings against its immutable artifact authority. */
int edr_p0_source_only_validate_record(const EdrBehaviorRecord *record);

/* P0 terminal actions may consume an artifact identity only when evidence
 * explicitly says it came from the process image section, not from a path
 * reopened after the ProcessCreate event.  The marker stays inside the
 * existing detection-context envelope, so no parallel protobuf field or UI
 * schema can silently diverge from the action boundary. */
int edr_p0_artifact_identity_is_action_authoritative(const char *detection_context);

#endif
