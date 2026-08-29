#include "edr/behavior_record.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void edr_behavior_record_init(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  memset(r, 0, sizeof(*r));
  snprintf(r->tenant_id, sizeof(r->tenant_id), "tenant_default");
  snprintf(r->endpoint_id, sizeof(r->endpoint_id), "ep-local");
}

void edr_behavior_record_enrich_system_context(EdrBehaviorRecord *r) {
  if (!r) {
    return;
  }
  if (!r->hostname[0]) {
#ifdef _WIN32
    DWORD n = sizeof(r->hostname);
    if (!GetComputerNameA(r->hostname, &n)) {
      r->hostname[0] = '\0';
    }
#else
    if (gethostname(r->hostname, sizeof(r->hostname)) != 0) {
      r->hostname[0] = '\0';
    }
#endif
  }
  /* USERDOMAIN belongs to the Agent service, not necessarily the observed process.
   * Leave an unknown process domain empty instead of manufacturing attribution. */
}

int edr_process_create_is_lifecycle_authoritative(const EdrBehaviorRecord *r) {
  return r && r->type == EDR_EVENT_PROCESS_CREATE && !r->is_security_4688;
}
