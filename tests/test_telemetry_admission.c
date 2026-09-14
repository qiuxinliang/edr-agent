#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include <assert.h>
#include <string.h>
static unsigned stored, considered;
static int allow;
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  assert(r && strcmp(r->event_id, "context-for-live-candidate") == 0);
  stored++;
}
int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  assert(r && stored > considered);
  considered++;
  return allow;
}
int main(void) {
  EdrBehaviorRecord r = {0};
  EdrDetectionDecision d = {0};
  strcpy(r.event_id, "context-for-live-candidate");
  r.priority = 1u; /* Not a separately emitted P0 alert. */
  allow = 1;
  assert(edr_preprocess_admit_telemetry(&r, &d));
  allow = 0; /* Duplicate upload must still reach the evidence owner. */
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  assert(stored == 2u && considered == 2u);
  strcpy(d.selection_action, "local_only");
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  d.selection_action[0] = '\0';
  d.drop = 1u;
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  assert(stored == 4u && considered == 2u);
  assert(!edr_preprocess_admit_telemetry(NULL, &d));
  assert(stored == 4u);
  return 0;
}
