/* 非 Windows/Linux：采集占位 */

#include "edr/collector.h"
#include "edr/adaptive_collection.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/sensor_interest.h"

#include <stdio.h>
#include <string.h>

EdrError edr_collector_start(EdrEventBus *bus, const EdrConfig *cfg) {
  (void)bus;
  (void)cfg;
  return EDR_OK;
}

int edr_collector_stop(void) { return 1; }

void edr_collector_stop_orphan_etw_session(void) {}

void edr_collector_register_policy_canary_process(uint32_t pid, const char *command) {
  (void)pid;
  (void)command;
}

int edr_collector_get_health(EdrCollectorHealth *out_health) {
  EdrAdaptiveCollectionStatus adaptive;
  EdrSensorInterestStatus si;
  if (!out_health) {
    return -1;
  }
  memset(out_health, 0, sizeof(*out_health));
  memset(&si, 0, sizeof(si));
  edr_sensor_interest_get_status(&si);
  out_health->sensor_interest_enabled = si.enabled;
  out_health->sensor_interest_loaded = si.loaded;
  out_health->sensor_interest_file_read_full_admission = si.file_read_full_admission;
  out_health->sensor_interest_file_write_full_admission = si.file_write_full_admission;
  out_health->sensor_interest_registry_set_full_admission = si.registry_set_full_admission;
  out_health->sensor_interest_full_admission_contract_valid = si.full_admission_contract_valid;
  out_health->sensor_interest_p0_binding_valid = si.p0_binding_valid;
  snprintf(out_health->sensor_interest_version, sizeof(out_health->sensor_interest_version), "%s", si.version);
  snprintf(out_health->sensor_interest_rules_version, sizeof(out_health->sensor_interest_rules_version), "%s", si.rules_version);
  snprintf(out_health->sensor_interest_p0_artifact_sha256,
           sizeof(out_health->sensor_interest_p0_artifact_sha256), "%s", si.p0_artifact_sha256);
  snprintf(out_health->sensor_interest_p0_rule_coverage_sha256,
           sizeof(out_health->sensor_interest_p0_rule_coverage_sha256), "%s", si.p0_rule_coverage_sha256);
  snprintf(out_health->sensor_interest_manifest_sha256,
           sizeof(out_health->sensor_interest_manifest_sha256), "%s", si.sensor_interest_manifest_sha256);
  snprintf(out_health->sensor_interest_manifest_hash_mode,
           sizeof(out_health->sensor_interest_manifest_hash_mode), "%s", si.sensor_interest_manifest_hash_mode);
  out_health->sensor_interest_p0_artifact_rule_count = si.p0_artifact_rule_count;
  out_health->sensor_interest_snapshot_epoch = si.snapshot_epoch;
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
