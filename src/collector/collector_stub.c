/* 非 Windows/Linux：采集占位 */

#include "edr/collector.h"
#include "edr/adaptive_collection.h"
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
  EdrAdaptiveCollectionStatus adaptive;
  if (!out_health) {
    return -1;
  }
  memset(out_health, 0, sizeof(*out_health));
  memset(&adaptive, 0, sizeof(adaptive));
  edr_adaptive_collection_get_status(&adaptive);
  out_health->adaptive_collection_enabled = adaptive.enabled;
  out_health->adaptive_collection_active = adaptive.active;
  out_health->adaptive_collection_ttl_s = adaptive.ttl_s;
  out_health->adaptive_collection_remaining_s = adaptive.remaining_s;
  out_health->adaptive_collection_min_severity = adaptive.min_severity;
  out_health->adaptive_collection_level = adaptive.level;
  out_health->adaptive_collection_boosts = adaptive.boosts;
  out_health->adaptive_collection_last_boost_unix_ms = adaptive.last_boost_unix_ms;
  snprintf(out_health->adaptive_collection_last_rule_id,
           sizeof(out_health->adaptive_collection_last_rule_id), "%s", adaptive.last_rule_id);
  snprintf(out_health->auditd_last_error, sizeof(out_health->auditd_last_error), "%s", "collector_stub");
  snprintf(out_health->ebpf_last_error, sizeof(out_health->ebpf_last_error), "%s", "collector_stub");
  return 0;
}
