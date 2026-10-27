#ifndef EDR_EVIDENCE_RECALL_MANIFEST_H
#define EDR_EVIDENCE_RECALL_MANIFEST_H

#include "cJSON.h"
#include "edr/sha256.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline int edr_evidence_window_metadata_valid(const char *state, const char *gap) {
  static const char *states[] = {"unknown", "active", "interrupted", "expired", "identity_unresolved"};
  static const char *gaps[] = {"", "service_restart_gap", "window_capacity_replaced", "invalid_window_bounds",
      "legacy_window_expired", "process_generation_unresolved", "parent_generation_unresolved", "legacy_activation_gap", "invalid_window_metadata",
      "monotonic_clock_reset", "restart_after_window", "live_generation_unverified"};
  int state_ok = 0, gap_ok = 0;
  if (!state || !gap) return 0;
  /* Preserve one proven activation omission alongside the latest recovery
   * cause. The suffix remains the same bounded enum, never arbitrary text. */
  if (!strcmp(gap, "activation_gap")) gap_ok = 1;
  else if (!strncmp(gap, "activation_gap+", 15)) {
    gap += 15;
    if (!gap[0]) return 0;
  }
  for (size_t i = 0; i < sizeof(states)/sizeof(states[0]); ++i) state_ok |= !strcmp(state, states[i]);
  for (size_t i = 0; i < sizeof(gaps)/sizeof(gaps[0]); ++i) gap_ok |= !strcmp(gap, gaps[i]);
  return state_ok && gap_ok;
}

/* A projection boundary shared by local recall and the final signed-purpose
 * result gate. Derive metadata from the frozen request and projected rows;
 * never copy caller-provided manifest strings into an authorized result.
 * Event extrema are samples, not continuously observed time intervals. */
static inline cJSON *edr_evidence_recall_manifest(const cJSON *rows,
    int64_t issued_ms, int64_t window_s, int partial) {
  if (!cJSON_IsArray(rows) || issued_ms <= 0 ||
      issued_ms > INT64_MAX / 1000000LL - 300000 ||
      window_s < 1 || window_s > 604800) return NULL;
  char from[32], until[32], digest[65];
  snprintf(from, sizeof(from), "%lld", (long long)((issued_ms-window_s*1000LL)*1000000LL));
  snprintf(until, sizeof(until), "%lld", (long long)((issued_ms+300000LL)*1000000LL));
  char *payload = cJSON_PrintUnformatted(rows);
  if (!payload) return NULL;
  size_t payload_bytes = strlen(payload);
  int hashed = edr_sha256_hex((const uint8_t *)payload, payload_bytes, digest) == 0;
  cJSON_free(payload);
  if (!hashed) return NULL;
  int incomplete_fields = 0, observed = 0, window_gap = 0;
  double first = 0, last = 0;
  const cJSON *row = NULL;
  cJSON_ArrayForEach(row, rows) {
    const cJSON *ts = cJSON_GetObjectItemCaseSensitive(row, "event_time_ns");
    const cJSON *quality = cJSON_GetObjectItemCaseSensitive(row, "source_completeness");
    const cJSON *truncated = cJSON_GetObjectItemCaseSensitive(row, "source_truncated_fields");
    const cJSON *gap = cJSON_GetObjectItemCaseSensitive(row, "context_window_gap_reason");
    if (cJSON_IsString(gap) && gap->valuestring[0]) window_gap = 1;
    if (cJSON_IsNumber(ts) && ts->valuedouble > 0) {
      if (!observed || ts->valuedouble < first) first = ts->valuedouble;
      if (!observed || ts->valuedouble > last) last = ts->valuedouble;
      observed = 1;
      if (!cJSON_IsString(quality) || strcmp(quality->valuestring, "COMPLETE") ||
          (cJSON_IsString(truncated) && truncated->valuestring[0])) incomplete_fields = 1;
    }
  }
  cJSON *m = cJSON_CreateObject();
  if (!m) return NULL;
  cJSON *interval = cJSON_AddObjectToObject(m, "requested_interval");
  cJSON *gaps = cJSON_AddArrayToObject(m, "gap_reasons");
  if (!interval || !gaps ||
      !cJSON_AddStringToObject(m, "schema", "edr.evidence-recall.v1") ||
      !cJSON_AddStringToObject(interval, "from_ns", from) ||
      !cJSON_AddStringToObject(interval, "until_ns", until) ||
      !cJSON_AddStringToObject(m, "coverage_status", partial || incomplete_fields || window_gap ? "partial" : "unknown") ||
      !cJSON_AddNumberToObject(m, "serialized_count", cJSON_GetArraySize(rows)) ||
      !cJSON_AddNullToObject(m, "retained_count") ||
      !cJSON_AddNullToObject(m, "omitted_count") ||
      !cJSON_AddStringToObject(m, "snapshot_consistency", "per_store") ||
      !cJSON_AddStringToObject(m, "hash_algorithm", "sha256") ||
      !cJSON_AddStringToObject(m, "payload_encoding", "cjson_compact_rows_v1") ||
      !cJSON_AddNumberToObject(m, "payload_bytes", (double)payload_bytes) ||
      !cJSON_AddStringToObject(m, "payload_digest", digest)) goto failed;
  const char *reasons[] = {"source_coverage_unknown", "independent_store_snapshots",
      partial ? "result_budget_or_scan_limit" : NULL,
      incomplete_fields ? "source_fields_incomplete" : NULL,
      window_gap ? "window_observation_gap" : NULL};
  for (size_t i = 0; i < sizeof(reasons)/sizeof(reasons[0]); ++i) {
    if (!reasons[i]) continue;
    cJSON *reason = cJSON_CreateString(reasons[i]);
    if (!reason || !cJSON_AddItemToArray(gaps, reason)) { cJSON_Delete(reason); goto failed; }
  }
  if (observed) {
    cJSON *range = cJSON_AddObjectToObject(m, "observed_event_range");
    if (!range || !cJSON_AddNumberToObject(range, "first_ns", first) ||
        !cJSON_AddNumberToObject(range, "last_ns", last)) goto failed;
  } else if (!cJSON_AddNullToObject(m, "observed_event_range")) goto failed;
  return m;
failed:
  cJSON_Delete(m); return NULL;
}
#endif
