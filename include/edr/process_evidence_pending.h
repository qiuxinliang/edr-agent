#ifndef EDR_PROCESS_EVIDENCE_PENDING_H
#define EDR_PROCESS_EVIDENCE_PENDING_H
#include "edr/behavior_record.h"
#include "edr/process_evidence_worker.h"
/* Preprocess-thread owned continuations. Same one-second observation deadline
 * as the former blocking wait; full capacity means continue with an explicit
 * unavailable result, never discard a record. Allocations are demand-only. */
int edr_process_evidence_pending_add(const EdrBehaviorRecord *record,
    const EdrEventSlot *slot, const EdrProcessEvidence *initial, uint64_t now);
int edr_process_evidence_pending_take(uint64_t now, int stopping,
    EdrBehaviorRecord *record, EdrEventSlot *slot, int *has_slot,
    EdrProcessEvidence *evidence);
#endif
