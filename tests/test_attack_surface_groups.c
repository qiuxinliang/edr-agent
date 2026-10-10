#include <assert.h>
#include <stdint.h>
#include "../src/attack_surface/attack_surface_groups.h"
int main(void) {
  const char payload[] = "{\"collection_group\":\"inventoryOnly\"}";
  assert(edr_asurf_periodic_payload_mode("cmd-manual", (const uint8_t *)payload, sizeof(payload)-1u) == EDR_ASURF_FULL);
  assert(edr_asurf_periodic_payload_mode("auto-asurf-inventoryOnly-1", (const uint8_t *)payload, sizeof(payload)-1u) == EDR_ASURF_INVENTORY);
  assert(edr_asurf_samples_listeners(EDR_ASURF_NETWORK) && edr_asurf_samples_egress(EDR_ASURF_NETWORK));
  assert(!edr_asurf_samples_inventory(EDR_ASURF_NETWORK) && !edr_asurf_samples_policy(EDR_ASURF_NETWORK));
  for (int mode=EDR_ASURF_FULL; mode<=EDR_ASURF_NETWORK; ++mode) {
    cJSON *root = cJSON_Parse("{\"summary\":{\"listenerCount\":1,\"serviceCount\":2,\"suspiciousEgressCount\":3},\"listeners\":{\"items\":[]},\"webServices\":[],\"processHighlights\":[],\"egressTop\":[],\"services\":{\"items\":[]},\"securityPolicy\":{},\"firewall\":{}}");
    assert(edr_asurf_project_sampled_groups(root, (EdrAttackSurfaceMode)mode) == 0);
    assert((cJSON_GetObjectItemCaseSensitive(root,"listeners") != NULL) == edr_asurf_samples_listeners((EdrAttackSurfaceMode)mode));
    assert((cJSON_GetObjectItemCaseSensitive(root,"services") != NULL) == edr_asurf_samples_inventory((EdrAttackSurfaceMode)mode));
    assert((cJSON_GetObjectItemCaseSensitive(root,"securityPolicy") != NULL) == edr_asurf_samples_policy((EdrAttackSurfaceMode)mode));
    assert((cJSON_GetObjectItemCaseSensitive(root,"egressTop") != NULL) == edr_asurf_samples_egress((EdrAttackSurfaceMode)mode));
    cJSON *summary = cJSON_GetObjectItemCaseSensitive(root,"summary");
    assert((cJSON_GetObjectItemCaseSensitive(summary,"listenerCount") != NULL) == edr_asurf_samples_listeners((EdrAttackSurfaceMode)mode));
    assert((cJSON_GetObjectItemCaseSensitive(summary,"serviceCount") != NULL) == edr_asurf_samples_inventory((EdrAttackSurfaceMode)mode));
    assert((cJSON_GetObjectItemCaseSensitive(summary,"suspiciousEgressCount") != NULL) == edr_asurf_samples_egress((EdrAttackSurfaceMode)mode));
    cJSON_Delete(root);
  }
  return 0;
}
