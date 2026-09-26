#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include "cJSON.h"
#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t s_baseline_rename_upload_skipped;
static _Atomic uint64_t s_baseline_file_upload_skipped;

static int baseline_context_has_no_server_signal(const char *json) {
  static const char *const positive_signals[] = {
      "remote", "ransom_note", "tls_anomaly", "ransom_canary",
      "script_sensor", "process_context", "ransom_behavior",
      "rmm_policy_match", "extension_changed", "ransom_note_burst",
      "suspicious_parent", "webshell_semantic", "persistence_change",
      "high_content_entropy", "cert_revoked_ancestor",
      "security_product_kill", "ransom_recovery_tamper",
      "silverfox_attack_chain"};
  int safe = 0;
  cJSON *root = json && json[0] ? cJSON_Parse(json) : NULL;
  if (!root) return 0;
  const cJSON *signals = cJSON_GetObjectItemCaseSensitive(root, "signals");
  const cJSON *control = cJSON_GetObjectItemCaseSensitive(root, "ransom_control");
  const cJSON *quality = cJSON_GetObjectItemCaseSensitive(root, "event_quality");
  const cJSON *phase = cJSON_GetObjectItemCaseSensitive(control, "phase");
  const cJSON *kind = cJSON_GetObjectItemCaseSensitive(control, "kind");
  const cJSON *rate = cJSON_GetObjectItemCaseSensitive(control, "file_rate_per_min");
  const cJSON *chain = cJSON_GetObjectItemCaseSensitive(signals, "ransom_chain_score");
  const cJSON *reasons = cJSON_GetObjectItemCaseSensitive(quality, "signal_reasons");
  if (!cJSON_IsObject(signals) || !cJSON_IsObject(control) ||
      !cJSON_IsObject(quality) || !cJSON_IsString(phase) ||
      strcmp(phase->valuestring, "baseline") != 0 ||
      !cJSON_IsString(kind) || kind->valuestring[0] ||
      !cJSON_IsNumber(rate) || rate->valuedouble < 0.0 ||
      rate->valuedouble >= 80.0 ||
      !cJSON_IsNumber(chain) || chain->valuedouble != 0.0 ||
      !cJSON_IsArray(reasons) || cJSON_GetArraySize(reasons) != 0 ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "canary")) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "extension_changed"))) {
    goto done;
  }
  for (size_t i = 0u; i < sizeof(positive_signals) / sizeof(positive_signals[0]); i++) {
    if (!cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(signals,
                                                       positive_signals[i]))) goto done;
  }
  safe = 1;
done:
  cJSON_Delete(root);
  return safe;
}

int edr_preprocess_admit_telemetry(const EdrBehaviorRecord *record,
                                  const EdrDetectionDecision *decision) {
  if (!record || !decision) return 0;
  /* Cache owns retention, aggregation and candidate attribution. Neither a
   * local-only decision nor duplicate transport is authority to skip it. */
  edr_local_evidence_cache_record_behavior(record);
  if (decision->drop || strcmp(decision->selection_action, "local_only") == 0)
    return 0;
  return edr_preprocess_should_emit(record);
}

int edr_preprocess_upload_admit(const EdrBehaviorRecord *record,
                               const EdrDetectionDecision *decision,
                               int p0_proven_miss, int local_forensics_dispatched) {
  if (!record || !decision || !p0_proven_miss || local_forensics_dispatched > 0 ||
      (record->type != EDR_EVENT_FILE_CREATE &&
       record->type != EDR_EVENT_FILE_WRITE &&
       record->type != EDR_EVENT_FILE_DELETE &&
       record->type != EDR_EVENT_FILE_RENAME) ||
      !record->event_id[0] || !record->file_path[0] ||
      record->collector_evidence_gate[0] || record->source_truncated_fields[0] ||
      (record->source_completeness[0] &&
       strcmp(record->source_completeness, "COMPLETE") != 0) ||
      record->pmfe_snapshot[0] || record->cert_revoked_ancestor ||
      decision->signal_reasons[0] || decision->has_remote ||
      decision->suspicious_parent || decision->context_correlated ||
      decision->persistence_change || decision->trigger_pmfe_scan ||
      decision->trigger_single_process_minidump) {
    return 1;
  }

  /* The ordinary frame has no further server consumer when the local IR
   * proved a miss and the generated context has no ransomware signal. Keep
   * every unknown or changed context shape on the upload path. */
  if (!baseline_context_has_no_server_signal(record->detection_context)) return 1;
  const int allowlisted_baseline = decision->suppress &&
      decision->allowlisted_path &&
      strcmp(decision->selection_action, "emit_context") == 0 &&
      strstr(decision->noise_reasons, "allowlisted_path") != NULL;
  const int structured_baseline = strcmp(decision->reason, "baseline") == 0 &&
      decision->event_quality_score <= 20u;
  if (!allowlisted_baseline && !structured_baseline) return 1;

  if (record->type == EDR_EVENT_FILE_RENAME) {
    atomic_fetch_add_explicit(&s_baseline_rename_upload_skipped, 1u,
                              memory_order_relaxed);
  } else {
    atomic_fetch_add_explicit(&s_baseline_file_upload_skipped, 1u,
                              memory_order_relaxed);
  }
  return 0;
}

uint64_t edr_preprocess_baseline_rename_upload_skipped_count(void) {
  return atomic_load_explicit(&s_baseline_rename_upload_skipped,
                              memory_order_relaxed);
}

uint64_t edr_preprocess_baseline_file_upload_skipped_count(void) {
  return atomic_load_explicit(&s_baseline_file_upload_skipped,
                              memory_order_relaxed);
}
