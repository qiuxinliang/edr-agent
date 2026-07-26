#ifndef EDR_DETECTION_TRIGGER_H
#define EDR_DETECTION_TRIGGER_H

#include "edr/behavior_record.h"
#include "edr/config.h"
#include "edr/types.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  bool recommend_pmfe;
  uint32_t pmfe_pid;
  uint8_t pmfe_priority;
  bool recommend_minidump;
  char pmfe_reason[128];
} EdrDetectionDecision;

void edr_detection_decision_init(EdrDetectionDecision *out);

/*
 * Evaluate whether an event should trigger lightweight follow-up collection.
 * P0 only emits PMFE recommendations and deliberately keeps minidump disabled.
 */
bool edr_detection_trigger_evaluate(const EdrConfig *cfg,
                                    const EdrEventSlot *slot,
                                    const EdrBehaviorRecord *br,
                                    EdrDetectionDecision *out);

#ifdef __cplusplus
}
#endif

#endif
