/**
 * 将 §12.4 行为告警推入 EventBatch（与 HTTP ReportEvents payload 同源）。
 */
#ifndef EDR_BEHAVIOR_ALERT_EMIT_H
#define EDR_BEHAVIOR_ALERT_EMIT_H

#include "ave_sdk.h"
#include "behavior_record.h"

#include <stddef.h>
#include <stdint.h>

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a);
/* Resolve generation-bound command facts before encoding. No network I/O. */
size_t edr_behavior_record_encode_frame(const EdrBehaviorRecord *record,
    const AVEBehaviorAlert *alert, uint8_t *frame, size_t capacity);
/* Owned BAT1 bytes within the existing event-batch cap. Caller frees. */
uint8_t *edr_behavior_record_alloc_durable_wire(const EdrBehaviorRecord *record,
    const AVEBehaviorAlert *alert, size_t *length);
uint8_t *edr_behavior_record_alloc_durable_wire_facts(const EdrBehaviorRecord *record,
    const AVEBehaviorAlert *alert, const EdrCommandFacts *facts, size_t *length);
/* One-frame encoders read evidence storage; caller owns `wire`. */
size_t edr_behavior_record_alert_encode_durable_wire(const EdrBehaviorRecord *record,
                                                      const AVEBehaviorAlert *alert,
                                                      uint8_t *wire, size_t wire_cap);
size_t edr_behavior_record_encode_durable_wire(const EdrBehaviorRecord *record,
                                               uint8_t *wire, size_t wire_cap);
/* Builds the stable queue/transport id for a durable wire payload. */
int edr_behavior_durable_wire_batch_id(const char *kind, const uint8_t *wire, size_t wire_len,
                                       char *out, size_t out_cap);
/* Returns 1 only after the combined BehaviorEvent is accepted by the persistent offline queue. */
int edr_behavior_record_alert_emit_to_batch(const EdrBehaviorRecord *record,
                                            const AVEBehaviorAlert *alert);
/* The prepare callback runs only after the alert governor has reserved a
 * semantic admission slot and never while its lock is held.  Returning zero
 * releases that reservation without writing the combined frame. */
typedef int (*EdrBehaviorRecordAlertPrepareFn)(void *context);

/* The P0 caller must distinguish normal alert-volume suppression from an
 * actual durable encoding/queue failure. Only the latter is NOT_EVALUABLE. */
typedef enum EdrBehaviorRecordAlertEmitOutcome {
  EDR_BEHAVIOR_RECORD_ALERT_EMIT_ACCEPTED = 1,
  EDR_BEHAVIOR_RECORD_ALERT_EMIT_GOVERNOR_SUPPRESSED = 2,
  EDR_BEHAVIOR_RECORD_ALERT_EMIT_PREPARE_OR_QUEUE_FAILED = 3,
  EDR_BEHAVIOR_RECORD_ALERT_EMIT_POLICY_DENIED = 4,
} EdrBehaviorRecordAlertEmitOutcome;

EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_to_batch_with_prepare_outcome(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context);

/* Atomic deferred snapshot -> normal offline wire handoff. Admission and
 * governor rules remain identical; a committed key cannot emit twice. */
EdrBehaviorRecordAlertEmitOutcome edr_behavior_record_alert_emit_deferred(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    const char *deferred_key, const EdrCommandFacts *facts);

/* Compatibility boolean wrapper for callers that only need durable success. */
int edr_behavior_record_alert_emit_to_batch_with_prepare(
    const EdrBehaviorRecord *record, const AVEBehaviorAlert *alert,
    EdrBehaviorRecordAlertPrepareFn prepare, void *prepare_context);
/* High-priority source-only path for P0 records that are not safely evaluable. */
int edr_behavior_record_emit_durable(const EdrBehaviorRecord *record);
void edr_behavior_alert_emit_periodic_summary(void);

#endif
