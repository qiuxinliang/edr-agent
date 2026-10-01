#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/installer_worker/runtime_health.h"

int main(void) {
  for (int service_required = 0; service_required <= 1; ++service_required) {
    for (int failed_probe = 0; failed_probe < 4; ++failed_probe) {
      EdrHealthState states[] = {EDR_HEALTH_PRESENT, EDR_HEALTH_PRESENT, EDR_HEALTH_RUNNING, EDR_HEALTH_RUNNING};
      states[failed_probe] = EDR_HEALTH_UNKNOWN;
      assert(strcmp(edr_health_presence_status(states[0], states[1], states[2], states[3], service_required),
                    failed_probe == 3 && !service_required ? "ok" : "unknown") == 0);
      states[failed_probe] = EDR_HEALTH_MISSING;
      assert(strcmp(edr_health_presence_status(states[0], states[1], states[2], states[3], service_required),
                    failed_probe == 3 && !service_required ? "ok" : "failed") == 0);
    }
  }
  assert(strcmp(edr_health_presence_status(EDR_HEALTH_PRESENT, EDR_HEALTH_PRESENT,
                    EDR_HEALTH_RUNNING, EDR_HEALTH_STOPPED, 1), "failed") == 0);
  assert(strcmp(edr_health_presence_status(EDR_HEALTH_PRESENT, EDR_HEALTH_PRESENT,
                    EDR_HEALTH_RUNNING, EDR_HEALTH_PENDING, 1), "warning") == 0);
  assert(strcmp(edr_health_state_name(EDR_HEALTH_UNKNOWN), "unknown") == 0);
  assert(strcmp(edr_health_state_name(EDR_HEALTH_STOPPED), "stopped") == 0);
  puts("runtime presence classifications passed");
  return 0;
}
