/**
 * Test-only preprocess boundary for AVE/transport integration tests, without
 * linking the full pipeline (threads, event bus, dedup, ...). All compilers
 * use this explicit dependency; production transport must not supply no-op
 * weak definitions that mask missing owners on GCC/Clang but fail on MSVC.
 */
#include "edr/preprocess.h"
#include <stdatomic.h>

static atomic_uint s_sampling_pct;

void edr_preprocess_apply_sampling_pct(uint32_t pct) {
  atomic_store(&s_sampling_pct, pct);
}

uint32_t edr_preprocess_sampling_pct(void) {
  return atomic_load(&s_sampling_pct);
}

void edr_preprocess_copy_agent_ids(char *endpoint_id, size_t endpoint_cap, char *tenant_id, size_t tenant_cap) {
  if (endpoint_id && endpoint_cap > 0u) {
    endpoint_id[0] = '\0';
  }
  if (tenant_id && tenant_cap > 0u) {
    tenant_id[0] = '\0';
  }
}
