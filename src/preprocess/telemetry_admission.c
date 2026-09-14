#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include <string.h>

int edr_preprocess_admit_telemetry(const EdrBehaviorRecord *record,
                                  const EdrDetectionDecision *decision) {
  if (!record || !decision) return 0;
  /* Cache owns retention, aggregation and candidate attribution. Neither a
   * local-only decision nor duplicate transport is authority to skip it. */
  edr_local_evidence_cache_record_behavior(record);
  if (decision->drop || strcmp(decision->selection_action, "local_only") == 0)
    return 0;
  return edr_preprocess_should_emit(record);
}
