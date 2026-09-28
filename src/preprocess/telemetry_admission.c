#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include "edr/windows_event_policy.h"
#include "cJSON.h"
#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t s_baseline_rename_upload_skipped;
static _Atomic uint64_t s_baseline_file_upload_skipped;
static _Atomic uint64_t s_baseline_process_upload_skipped;
static _Atomic uint64_t s_baseline_registry_upload_skipped;

static int baseline_context_has_no_server_signal(const char *json,
                                               int uncombined_tool_file) {
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
      /* The decision owner assigns exactly 20 for the tool identity alone.
       * Any additional or inherited chain contribution keeps the upload. */
      !cJSON_IsNumber(chain) ||
      chain->valuedouble != (uncombined_tool_file ? 20.0 : 0.0) ||
      !cJSON_IsArray(reasons) ||
      cJSON_GetArraySize(reasons) != (uncombined_tool_file ? 1 : 0) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "canary")) ||
      !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "extension_changed"))) {
    goto done;
  }
  if (uncombined_tool_file) {
    const cJSON *reason = cJSON_GetArrayItem(reasons, 0);
    if (!cJSON_IsString(reason) || strcmp(reason->valuestring, "lolbin") != 0 ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "tracking_saturated")) ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "state_transition")) ||
        !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(control, "periodic_summary"))) {
      goto done;
    }
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

static int is_uncombined_tool_file(const EdrBehaviorRecord *r,
                                  const EdrDetectionDecision *d) {
  EdrWindowsEventPolicy policy;
  if (!r || !d ||
      (r->type != EDR_EVENT_FILE_CREATE && r->type != EDR_EVENT_FILE_WRITE &&
       r->type != EDR_EVENT_FILE_DELETE && r->type != EDR_EVENT_FILE_RENAME) ||
      !r->pid || !r->process_start_key || !r->process_creation_filetime_100ns ||
      !r->file_actor_generation_validated ||
      strcmp(r->source_completeness, "COMPLETE") != 0 ||
      !d->suppress || d->event_quality_score > 32u ||
      strcmp(d->reason, "lolbin,lolbin_without_combo_condition") != 0 ||
      strcmp(d->signal_reasons, "lolbin") != 0 ||
      strcmp(d->noise_reasons, "lolbin_without_combo_condition") != 0 ||
      strcmp(d->selection_action, "emit_context") != 0) return 0;
  /* Tool identity alone adds no standalone file evidence to the server.
   * Reuse the path policy owner so startup, credential and other sensitive
   * targets remain eligible even if the local rule bundle proved a miss. */
  edr_windows_event_policy_evaluate(r, &policy);
  return policy.applies && !policy.high_value && !policy.suspicious;
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
  const int is_process = record && record->type == EDR_EVENT_PROCESS_CREATE;
  const int is_registry = record && (record->type == EDR_EVENT_REG_CREATE_KEY ||
      record->type == EDR_EVENT_REG_SET_VALUE || record->type == EDR_EVENT_REG_DELETE_KEY);
  const int uncombined_tool_file = is_uncombined_tool_file(record, decision);
  if (!record || !decision || !p0_proven_miss || local_forensics_dispatched > 0 ||
      (!is_process && !is_registry && record->type != EDR_EVENT_FILE_CREATE &&
       record->type != EDR_EVENT_FILE_WRITE &&
       record->type != EDR_EVENT_FILE_DELETE &&
       record->type != EDR_EVENT_FILE_RENAME) ||
      !record->event_id[0] || (!is_process && !is_registry && !record->file_path[0]) ||
      (is_process && (record->is_security_4688 || !record->process_start_key ||
                      !record->process_creation_filetime_100ns)) ||
      (is_registry && (!record->pid || !record->reg_key_path[0] ||
          !record->process_start_key || !record->process_creation_filetime_100ns ||
          strcmp(record->source_completeness, "COMPLETE") != 0 ||
          strcmp(record->reg_attribution, "process_id") != 0 ||
          strcmp(record->reg_detail_status, "captured") != 0)) ||
      record->collector_evidence_gate[0] || record->source_truncated_fields[0] ||
      (is_process
           ? (strcmp(record->source_completeness, "COALESCED") != 0 &&
              strcmp(record->source_completeness, "CORRELATION_MISSING") != 0 &&
              strcmp(record->source_completeness, "COMPLETE") != 0)
           : (record->source_completeness[0] &&
              strcmp(record->source_completeness, "COMPLETE") != 0)) ||
      record->pmfe_snapshot[0] || record->cert_revoked_ancestor ||
      (decision->signal_reasons[0] && !uncombined_tool_file) || decision->has_remote ||
      decision->suspicious_parent || decision->context_correlated ||
      decision->persistence_change || decision->trigger_pmfe_scan ||
      decision->trigger_single_process_minidump) {
    return 1;
  }

  /* The ordinary frame has no further server consumer when the local IR
   * proved a miss and the generated context has no ransomware signal. Keep
   * every unknown or changed context shape on the upload path. */
  if (!baseline_context_has_no_server_signal(record->detection_context,
                                            uncombined_tool_file)) return 1;
  const int allowlisted_baseline = decision->suppress &&
      decision->allowlisted_path &&
      strcmp(decision->selection_action, "emit_context") == 0 &&
      strstr(decision->noise_reasons, "allowlisted_path") != NULL;
  const int structured_baseline = strcmp(decision->reason, "baseline") == 0 &&
      decision->event_quality_score <= 20u;
  if ((is_process || is_registry) ? !structured_baseline :
      (!allowlisted_baseline && !structured_baseline && !uncombined_tool_file))
    return 1;

  if (is_registry) {
    atomic_fetch_add_explicit(&s_baseline_registry_upload_skipped, 1u, memory_order_relaxed);
  } else if (is_process) {
    atomic_fetch_add_explicit(&s_baseline_process_upload_skipped, 1u,
                              memory_order_relaxed);
  } else if (record->type == EDR_EVENT_FILE_RENAME) {
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

uint64_t edr_preprocess_baseline_process_upload_skipped_count(void) {
  return atomic_load_explicit(&s_baseline_process_upload_skipped,
                              memory_order_relaxed);
}

uint64_t edr_preprocess_baseline_registry_upload_skipped_count(void) {
  return atomic_load_explicit(&s_baseline_registry_upload_skipped, memory_order_relaxed);
}
