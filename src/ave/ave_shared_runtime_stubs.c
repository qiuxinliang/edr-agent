/*
 * Standalone AVE shared-library hooks. The embedded AVE DLL/so should not pull
 * in the full Agent transport, queue, or resource monitor just to satisfy
 * behavior-pipeline optional callbacks.
 */
#include <stdbool.h>
#include <stddef.h>

#include "edr/behavior_alert_emit.h"

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) {
  (void)a;
}

void edr_ingest_http_copy_policy_version(char *out, size_t out_cap) {
  if (out && out_cap > 0u) {
    out[0] = '\0';
  }
}

bool edr_resource_preprocess_throttle_active(void) {
  return false;
}
