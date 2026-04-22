#include "edr/behavior_record.h"

#include <stdio.h>
#include <string.h>

void edr_behavior_record_init(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  memset(r, 0, sizeof(*r));
  snprintf(r->tenant_id, sizeof(r->tenant_id), "tenant_default");
  snprintf(r->endpoint_id, sizeof(r->endpoint_id), "ep-local");
}
