/**
 * Test-only stub: `behavior_alert_emit.c` calls `edr_preprocess_copy_agent_ids` without
 * linking the full preprocess pipeline (threads, event bus, dedup, …).
 */
#include <stddef.h>

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap > 0u) {
    endpoint_id[0] = '\0';
  }
  if (tenant_id && tenant_cap > 0u) {
    tenant_id[0] = '\0';
  }
}
