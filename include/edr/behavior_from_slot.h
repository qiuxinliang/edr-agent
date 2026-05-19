#ifndef EDR_BEHAVIOR_FROM_SLOT_H
#define EDR_BEHAVIOR_FROM_SLOT_H

#include "edr/behavior_record.h"
#include "edr/types.h"

#include <stdint.h>

void edr_behavior_from_slot(const EdrEventSlot *slot, EdrBehaviorRecord *r);

#if defined(_WIN32)
void edr_behavior_get_ppid_stats(int64_t *out_zero, int64_t *out_total,
                                 int64_t *out_snap_ok, int64_t *out_ntqi_ok);
#endif

#endif
