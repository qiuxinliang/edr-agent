#ifndef EDR_COLLECTOR_HEALTH_JSON_H
#define EDR_COLLECTOR_HEALTH_JSON_H

#include "edr/collector.h"
#include <stddef.h>
#include <stdio.h>

/* Private fragment shared by basic/detailed health and its wire-contract test.
 * Both totals come from the collector snapshot, never from a cross-stage delta. */
static inline int edr_collector_health_json(const EdrCollectorHealth *health,
                                           int diagnostic, char *out, size_t capacity) {
  static const char *const drop_names[EDR_COLLECTOR_DROP_REASON_COUNT] = {
      "slot_admission_rejected", "sensor_interest_rejected", "security_render_failed",
      "security_event_unsupported", "security_required_overflow"};
  static const char *const unresolved_names[EDR_FILE_WRITE_UNRESOLVED_REASON_COUNT] = {
      "invalid_event", "missing_file_key_or_schema", "actor_unavailable",
      "file_key_ambiguous", "binding_conflict", "history_discarded", "lifetime_ended",
      "path_unavailable", "object_conflict", "unknown_boundary", "no_retained_lifetime"};
  static const char *const no_lifetime_names[EDR_FILE_WRITE_NO_LIFETIME_REASON_COUNT] = {
      "verified_self_object_available", "verified_self_object_unavailable",
      "same_pid_unverified_object_available", "same_pid_unverified_object_unavailable",
      "other_pid_object_available", "other_pid_object_unavailable"};
  size_t used = 0u;
  int n;
  if (!health || !out || !capacity) return -1;
#define EDR_COLLECTOR_JSON_APPEND(...) do { \
    n = snprintf(out + used, capacity - used, __VA_ARGS__); \
    if (n < 0 || (size_t)n >= capacity - used) { out[0] = '\0'; return -1; } \
    used += (size_t)n; \
  } while (0)
  EDR_COLLECTOR_JSON_APPEND(
      "\"collector_dropped\":%llu,\"queue_dropped\":%llu,"
      "\"collector_drop_accounting\":{\"available\":%s,"
      "\"unit\":\"collector_rejections\",\"reasons\":{",
      (unsigned long long)health->collector_dropped,
      (unsigned long long)health->queue_dropped,
      health->disposition_accounting_available ? "true" : "false");
  for (size_t i = 0u; i < EDR_COLLECTOR_DROP_REASON_COUNT; ++i)
    EDR_COLLECTOR_JSON_APPEND("%s\"%s\":%llu", i ? "," : "", drop_names[i],
        (unsigned long long)health->collector_drop_reasons[i]);
  EDR_COLLECTOR_JSON_APPEND(
      "}},\"file_write_collection\":{\"path_resolved\":%llu,\"path_unresolved\":%llu,"
      "\"payload_incomplete\":%llu,\"unresolved_accounting\":{\"available\":%s,"
      "\"unit\":\"file_write_callbacks\",\"reasons\":{",
      (unsigned long long)health->file_write_path_resolved,
      (unsigned long long)health->file_write_path_unresolved,
      (unsigned long long)health->file_write_payload_incomplete,
      health->disposition_accounting_available ? "true" : "false");
  for (size_t i = 0u; i < EDR_FILE_WRITE_UNRESOLVED_REASON_COUNT; ++i)
    EDR_COLLECTOR_JSON_APPEND("%s\"%s\":%llu", i ? "," : "", unresolved_names[i],
        (unsigned long long)health->file_write_unresolved_reasons[i]);
  EDR_COLLECTOR_JSON_APPEND("}}");
  if (diagnostic) {
    EDR_COLLECTOR_JSON_APPEND(
        ",\"no_lifetime_diagnostics\":{\"available\":%s,\"unit\":\"file_write_callbacks\",\"reasons\":{",
        health->disposition_accounting_available ? "true" : "false");
    for (size_t i = 0u; i < EDR_FILE_WRITE_NO_LIFETIME_REASON_COUNT; ++i)
      EDR_COLLECTOR_JSON_APPEND("%s\"%s\":%llu", i ? "," : "", no_lifetime_names[i],
          (unsigned long long)health->file_write_no_lifetime_reasons[i]);
    EDR_COLLECTOR_JSON_APPEND(
        "}},\"object_history\":{\"available\":%s,\"capacity\":%llu,\"open_paths\":%llu,"
        "\"open_unusable\":%llu,\"closed_lifetimes\":%llu,\"close_boundaries\":%llu,\"evictions\":%llu}",
        health->file_object_history_available ? "true" : "false",
        (unsigned long long)health->file_object_history_capacity,
        (unsigned long long)health->file_object_history_open_paths,
        (unsigned long long)health->file_object_history_open_unusable,
        (unsigned long long)health->file_object_history_closed_lifetimes,
        (unsigned long long)health->file_object_history_close_boundaries,
        (unsigned long long)health->file_object_history_evictions);
  }
  EDR_COLLECTOR_JSON_APPEND("},");
#undef EDR_COLLECTOR_JSON_APPEND
  return 0;
}
#endif
