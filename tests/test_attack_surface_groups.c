#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "edr/command_contract.h"
#include "../src/attack_surface/attack_surface_groups.h"
int main(void) {
  const char payload[] = "{\"collection_group\":\"inventoryOnly\"}";
  assert(edr_asurf_periodic_payload_mode("cmd-manual", (const uint8_t *)payload, sizeof(payload)-1u) == EDR_ASURF_FULL);
  assert(edr_asurf_periodic_payload_mode("auto-asurf-inventoryOnly-1", (const uint8_t *)payload, sizeof(payload)-1u) == EDR_ASURF_INVENTORY);
  assert(edr_asurf_samples_listeners(EDR_ASURF_NETWORK) && edr_asurf_samples_egress(EDR_ASURF_NETWORK));
  assert(!edr_asurf_samples_inventory(EDR_ASURF_NETWORK) && !edr_asurf_samples_policy(EDR_ASURF_NETWORK));
  const char *groups[] = {"full", "networkOnly", "inventoryOnly", "policyOnly"};
  const EdrAttackSurfaceMode modes[] = {EDR_ASURF_FULL, EDR_ASURF_NETWORK, EDR_ASURF_INVENTORY, EDR_ASURF_POLICY};
  for (size_t i = 0; i < sizeof(groups)/sizeof(groups[0]); ++i) {
    char request[160], reason[192];
    snprintf(request, sizeof(request), "{\"reason\":\"periodic_attack_surface\",\"collection_group\":\"%s\"}", groups[i]);
    assert(edr_command_contract_validate("GET_ATTACK_SURFACE", (const uint8_t *)request, strlen(request), reason, sizeof(reason)));
    assert(edr_asurf_periodic_payload_mode("auto-asurf-group-1", (const uint8_t *)request, strlen(request)) == modes[i]);
    assert(edr_asurf_periodic_payload_mode("cmd-manual", (const uint8_t *)request, strlen(request)) == EDR_ASURF_FULL);
    cJSON *root = cJSON_Parse("{\"summary\":{\"listenerCount\":1,\"serviceCount\":2,\"suspiciousEgressCount\":3},\"listeners\":{},\"services\":{},\"securityPolicy\":{},\"egressTop\":[]}");
    assert(edr_asurf_project_sampled_groups(root, modes[i]) == 0);
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(root, "snapshotKind")->valuestring, groups[i]));
    cJSON_Delete(root);
  }
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
