#ifndef EDR_BEHAVIOR_FROM_SLOT_H
#define EDR_BEHAVIOR_FROM_SLOT_H

#include "edr/behavior_record.h"
#include "edr/types.h"

#include <stdint.h>

void edr_behavior_from_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r);
/* Bounded pre-queue observation: -1 unrelated/disabled, 0 protected canary or
 * active mass-write burst, 1 ordinary mass-write input. May attach an internal
 * content snapshot to r; it never emits a detection or response action. */
int edr_behavior_file_activity_priority(EdrBehaviorRecord *r);
/* Preprocess-thread only, after actor binding. Parsing a slot has no counters/actions. */
void edr_behavior_enrich_file_activity(EdrBehaviorRecord *r);

#if defined(_WIN32)
void edr_behavior_get_ppid_stats(int64_t *out_zero, int64_t *out_total,
                                 int64_t *out_snap_ok, int64_t *out_ntqi_ok,
                                 int64_t *out_wmi_ok, int64_t *out_env_ok,
                                 int64_t *out_infer_ok);
#endif

#endif
