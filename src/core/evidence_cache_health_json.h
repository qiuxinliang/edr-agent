#ifndef EDR_CORE_EVIDENCE_CACHE_HEALTH_JSON_H
#define EDR_CORE_EVIDENCE_CACHE_HEALTH_JSON_H

#include "edr/local_evidence_cache.h"
#include <stdio.h>

#define EDR_EVIDENCE_HEALTH_JSON_BYTES 16384u

/* One canonical cache block for basic and diagnostic health. Accounting and
 * context sources are bounded JSON fragments from their existing owners. */
static inline int edr_evidence_cache_health_json(const EdrEvidenceCacheStatus *st,
    const char *accounting, const char *context_sources, char *out, size_t cap) {
  if (!out || !cap) return -1;
  out[0] = '\0';
  if (!st || !accounting || !context_sources) return -1;
  int written = snprintf(out, cap,
        "{\"db_open\":%s,\"storage_format\":%u,\"utilization_bps\":%u,"
        "\"accounting_generation\":%llu,\"candidate_requests\":%llu,\"candidate_reused\":%llu,"
        "\"candidate_admitted\":%llu,\"candidate_rejected\":%llu,"
        "\"context_facts_written\":%llu,\"context_refs_written\":%llu,"
		"\"write_budget\":{\"used\":%u,\"limit\":%u,\"base_limit\":%u,"
		"\"scope\":\"context_only\",\"dropped\":%llu,"
		"\"candidate\":{\"mode\":\"exempt\",\"dropped\":%llu},"
		"\"critical_context\":{\"mode\":\"capacity_bound\",\"used\":%u,\"limit\":%u,\"dropped\":%llu},"
		"\"ordinary_context\":{\"used\":%u,\"limit\":%u,\"dropped\":%llu},"
		"\"context_dropped\":%llu},"
        "\"p0_candidate_rows\":%llu,\"db_bytes\":%llu,\"wal_bytes\":%llu,\"shm_bytes\":%llu,\"physical_bytes\":%llu,"
        "\"max_db_mb\":%u,\"maintenance\":{\"state\":%u,\"pending\":%s,\"runs\":%llu,"
        "\"retention_evicted\":%llu,\"capacity_evicted\":%llu,\"metric_write_failures\":%llu,\"metric_unrecorded\":%llu},"
        "\"context_window_evictions\":%llu,"
        "\"context_window_nominal_ended_replacements\":%llu,"
        "\"context_window_protected_replacements\":%llu,\"context_ref_write_sources\":%s,\"accounting\":%s}",
        st->db_open ? "true" : "false", st->storage_format, st->db_utilization_bps,
        (unsigned long long)st->accounting_generation,
        (unsigned long long)st->candidate_requests,
        (unsigned long long)st->candidate_reused,
        (unsigned long long)st->candidate_admitted,
        (unsigned long long)st->candidate_rejected,
        (unsigned long long)st->context_facts_written,
        (unsigned long long)st->context_refs_written,
		st->write_budget_used, st->write_budget_limit,
		st->write_budget_base_limit,
		(unsigned long long)st->write_budget_dropped,
		(unsigned long long)st->write_budget_candidate_dropped,
		st->write_budget_critical_context_used,
		st->write_budget_critical_context_limit,
		(unsigned long long)st->write_budget_critical_context_dropped,
		st->write_budget_ordinary_context_used,
		st->write_budget_ordinary_context_limit,
		(unsigned long long)st->write_budget_ordinary_context_dropped,
		(unsigned long long)st->write_budget_context_dropped,
        (unsigned long long)st->p0_candidate_rows,
        (unsigned long long)st->db_bytes,
        (unsigned long long)st->wal_bytes,
        (unsigned long long)st->shm_bytes,
        (unsigned long long)st->physical_bytes, st->max_db_mb,
        st->maintenance_state, st->maintenance_pending ? "true" : "false",
        (unsigned long long)st->maintenance_runs,
        (unsigned long long)st->db_retention_evicted,
        (unsigned long long)st->db_capacity_evicted,
        (unsigned long long)st->metric_write_failures,
        (unsigned long long)st->metric_unrecorded,
        (unsigned long long)st->context_window_evictions,
        (unsigned long long)st->context_window_nominal_ended_replacements,
        (unsigned long long)st->context_window_protected_replacements,
        context_sources, accounting);
  if (written < 0 || (size_t)written >= cap) { out[0] = '\0'; return -1; }
  return 0;
}

#endif
