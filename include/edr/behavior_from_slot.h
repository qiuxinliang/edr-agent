#ifndef EDR_BEHAVIOR_FROM_SLOT_H
#define EDR_BEHAVIOR_FROM_SLOT_H

#include "edr/behavior_record.h"
#include "edr/types.h"

#include <stdint.h>

void edr_behavior_from_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r);
/* Read-only admission: -1 unrelated/disabled, 0 exact canary, 1 mass-write input. */
int edr_behavior_file_activity_priority(const EdrBehaviorRecord *r);
/* Preprocess-thread only, after actor binding. Parsing a slot has no counters/actions. */
void edr_behavior_enrich_file_activity(EdrBehaviorRecord *r);

#if defined(_WIN32)
void edr_behavior_get_ppid_stats(int64_t *out_zero, int64_t *out_total,
                                 int64_t *out_snap_ok, int64_t *out_ntqi_ok,
                                 int64_t *out_wmi_ok, int64_t *out_env_ok,
                                 int64_t *out_infer_ok);
#endif

#endif
