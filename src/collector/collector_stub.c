/* 非 Windows/Linux：采集占位 */

#include "edr/collector.h"
#include "edr/config.h"
#include "edr/event_bus.h"

#include <stdio.h>
#include <string.h>

EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {
  (void)bus;
  (void)cfg;
  return EDR_OK;
}

void edr_collector_stop(void) {}

void edr_collector_stop_orphan_etw_session(void) {}

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  if (!out_health) {
    return -1;
  }
  memset(out_health, 0, sizeof(*out_health));
  snprintf(out_health->auditd_last_error, sizeof(out_health->auditd_last_error), "%s", "collector_stub");
  snprintf(out_health->ebpf_last_error, sizeof(out_health->ebpf_last_error), "%s", "collector_stub");
  return 0;
}
