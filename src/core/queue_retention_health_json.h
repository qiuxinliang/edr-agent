#ifndef EDR_QUEUE_RETENTION_HEALTH_JSON_H
#define EDR_QUEUE_RETENTION_HEALTH_JSON_H

#include "edr/storage_queue.h"
#include <stddef.h>
#include <stdio.h>

/* Shared by the basic and diagnostic health profiles. Only bounded numeric
 * inventory is exported: creation classes do not describe outstanding ACKs,
 * and typed diagnostic/terminal owners expire only after dependency checks. */
static inline int edr_queue_retention_health_json(
    const EdrStorageQueueCapacityMetrics *m, char *out, size_t capacity) {
  int n;
  if (!m || !out || !capacity) return -1;
  if (!m->accounting_available || m->ledger_version != 1u) {
    n = snprintf(out, capacity, "{\"accounting_available\":false}");
  } else {
    n = snprintf(out, capacity,
        "{\"accounting_available\":true,\"ledger_version\":1,"
        "\"retirement_enabled\":true,\"state\":\"retained\",\"local_retention_policy_version\":2,"
        "\"terminal_local_policy_version\":3,"
        "\"typed_rows\":%llu,\"unclassified_rows\":%llu,"
        "\"retired_rows\":%llu,\"retired_bytes\":%llu,"
        "\"terminal_local_retired_rows\":%llu,\"terminal_local_retired_bytes\":%llu,"
        "\"protected_slices\":%llu,\"integrity_failures\":%llu,"
        "\"maintenance_oversize_holds\":%llu,\"maintenance_failures\":%llu,"
        "\"physical_admission_failures\":%llu,\"physical_available_bytes\":%llu,"
        "\"physical_required_bytes\":%llu,\"physical_min_free_bytes\":%llu,\"physical_failure_kind\":%u,"
        "\"legacy_unclassified\":{\"rows\":%llu,\"bytes\":%llu},"
        "\"local_v3\":{\"rows\":%llu,\"bytes\":%llu},"
        "\"delivery_created\":{\"rows\":%llu,\"bytes\":%llu},"
        "\"projection_created\":{\"rows\":%llu,\"bytes\":%llu},"
        "\"journal_bytes\":%llu,\"deferred_bytes\":%llu,"
        "\"projection_relation_bytes\":%llu,\"recovery_metadata_bytes\":%llu}",
        (unsigned long long)m->local_retention_typed_rows,
        (unsigned long long)m->local_retention_unclassified_rows,
        (unsigned long long)m->local_retired_rows,
        (unsigned long long)m->local_retired_bytes,
        (unsigned long long)m->terminal_local_retired_rows,
        (unsigned long long)m->terminal_local_retired_bytes,
        (unsigned long long)m->local_retention_protected_slices,
        (unsigned long long)m->local_retention_integrity_failures,
        (unsigned long long)m->maintenance_oversize_holds,
        (unsigned long long)m->maintenance_failures,
        (unsigned long long)m->physical_admission_failures,
        (unsigned long long)m->physical_available_bytes,
        (unsigned long long)m->physical_required_bytes,
        (unsigned long long)m->physical_min_free_bytes,
        m->physical_failure_kind,
        (unsigned long long)m->retention_legacy_rows,
        (unsigned long long)m->retention_legacy_bytes,
        (unsigned long long)m->retention_local_rows,
        (unsigned long long)m->retention_local_bytes,
        (unsigned long long)m->retention_delivery_rows,
        (unsigned long long)m->retention_delivery_bytes,
        (unsigned long long)m->retention_recovery_rows,
        (unsigned long long)m->retention_recovery_bytes,
        (unsigned long long)m->terminal_journal_bytes,
        (unsigned long long)m->deferred_bytes,
        (unsigned long long)m->projection_relation_bytes,
        (unsigned long long)m->recovery_metadata_bytes);
  }
  if (n < 0 || (size_t)n >= capacity) { out[0] = '\0'; return -1; }
  return 0;
}
#endif
