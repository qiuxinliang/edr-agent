#ifndef EDR_FILE_READ_DEFERRED_H
#define EDR_FILE_READ_DEFERRED_H

#include "edr/behavior_record.h"
#include <string.h>

/* Preprocess-thread owned, like the ProcessCreate coalescer. Never retain an
 * EVENT_RECORD pointer or resolve the actor again after a wait. Overflow,
 * timeout and shutdown must go through the existing durable source-only lane. */
#define EDR_FILE_READ_DEFERRED_CAPACITY 8u
#define EDR_FILE_READ_DEFERRED_TTL_NS 5000000000ULL
typedef struct {
  EdrBehaviorRecord record;
  uint64_t queued_ns;
} EdrFileReadDeferredEntry;
typedef struct {
  EdrFileReadDeferredEntry entries[EDR_FILE_READ_DEFERRED_CAPACITY];
  unsigned head, count;
  uint64_t admitted, released, expired, rejected;
} EdrFileReadDeferred;

static inline int edr_file_read_deferred_push(EdrFileReadDeferred *q,
                                             const EdrBehaviorRecord *record,
                                             uint64_t now_ns) {
  if (!q || !record || record->type != EDR_EVENT_FILE_READ) return 0;
  if (!now_ns || q->count == EDR_FILE_READ_DEFERRED_CAPACITY) {
    q->rejected++;
    return 0;
  }
  EdrFileReadDeferredEntry *entry =
      &q->entries[(q->head + q->count) % EDR_FILE_READ_DEFERRED_CAPACITY];
  entry->record = *record;
  entry->queued_ns = now_ns;
  q->count++;
  q->admitted++;
  return 1;
}

/* 0: remain held; 1: evaluate; 2: timeout/clock fault; 3: shutdown.
 * Expiry wins over recovery at the deadline; waiting never extends a lifetime. */
static inline int edr_file_read_deferred_pop(EdrFileReadDeferred *q, uint64_t now_ns,
                                            int gate_ready, int stopping,
                                            EdrBehaviorRecord *out) {
  if (!q || !q->count || !out) return 0;
  EdrFileReadDeferredEntry *entry = &q->entries[q->head];
  int expired = !now_ns || now_ns < entry->queued_ns ||
                now_ns - entry->queued_ns >= EDR_FILE_READ_DEFERRED_TTL_NS;
  if (!gate_ready && !expired && !stopping) return 0;
  *out = entry->record;
  memset(entry, 0, sizeof(*entry));
  q->head = (q->head + 1u) % EDR_FILE_READ_DEFERRED_CAPACITY;
  q->count--;
  if (stopping) return 3;
  if (expired) { q->expired++; return 2; }
  q->released++;
  return 1;
}
#endif
