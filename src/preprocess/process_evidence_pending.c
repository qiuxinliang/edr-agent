#include "edr/process_evidence_pending.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Matches the bounded evidence worker's 32 slots. This is a continuation
 * bound, not a rule/admission gate; overflow falls back to immediate handling. */
#define PENDING_CAPACITY EDR_PROCESS_EVIDENCE_CAPACITY
typedef struct {
  EdrBehaviorRecord record;
  EdrEventSlot slot;
  EdrProcessEvidence initial;
  uint64_t deadline;
  int has_slot;
} Pending;
static Pending *s_pending[PENDING_CAPACITY];

int edr_process_evidence_pending_add(const EdrBehaviorRecord *record,
    const EdrEventSlot *slot, const EdrProcessEvidence *initial, uint64_t now) {
  if (!record || !initial || !record->process_start_key) return 0;
  for (size_t i = 0; i < PENDING_CAPACITY; ++i) {
    if (s_pending[i]) continue;
    Pending *p = (Pending *)malloc(sizeof(*p));
    if (!p) return 0;
    p->record = *record;
    p->initial = *initial;
    p->has_slot = slot != NULL;
    if (slot) p->slot = *slot;
    p->deadline = now + 1000000000ULL;
    s_pending[i] = p;
    return 1;
  }
  return 0;
}
int edr_process_evidence_pending_take(uint64_t now, int stopping,
    EdrBehaviorRecord *record, EdrEventSlot *slot, int *has_slot,
    EdrProcessEvidence *evidence) {
  if (!record || !slot || !has_slot || !evidence) return 0;
  for (size_t i = 0; i < PENDING_CAPACITY; ++i) {
    Pending *p = s_pending[i];
    if (!p) continue;
    const char *path = p->record.image_path_canonical[0]
        ? p->record.image_path_canonical : p->record.exe_path;
    int state = edr_process_evidence_poll(path, p->record.process_start_key, now, evidence);
    if (state == 0 && !stopping && now < p->deadline) continue;
    if (state == 0) {
      *evidence = p->initial;
      if (!stopping) edr_process_evidence_note_wait_timeout();
      const char *reason = stopping ? "shutdown_cancelled" : "evidence_wait_timeout";
      snprintf(evidence->hash_reason, sizeof(evidence->hash_reason), "%s", reason);
      snprintf(evidence->signature_reason, sizeof(evidence->signature_reason), "%s", reason);
    }
    if (!evidence->file_identity[0]) {
      snprintf(evidence->file_identity, sizeof(evidence->file_identity), "%s", p->initial.file_identity);
      evidence->file_write_time = p->initial.file_write_time;
    }
    *record = p->record;
    *has_slot = p->has_slot;
    if (p->has_slot) *slot = p->slot;
    free(p);
    s_pending[i] = NULL;
    return 1;
  }
  return 0;
}
