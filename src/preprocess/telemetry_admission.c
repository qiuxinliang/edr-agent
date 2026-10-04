#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include "edr/windows_event_policy.h"
#include "baseline_context.h"
#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t s_baseline_rename_upload_skipped;
static _Atomic uint64_t s_baseline_file_upload_skipped;
static _Atomic uint64_t s_baseline_process_upload_skipped;
static _Atomic uint64_t s_baseline_registry_upload_skipped;

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
      (strcmp(d->selection_action, "local_only") != 0 &&
       strcmp(d->selection_action, "emit_context") != 0)) return 0;
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
  if (decision->drop || (strcmp(decision->selection_action, "local_only") == 0 &&
                         !decision->p0_miss_local_only))
    return 0;
  return edr_preprocess_should_emit(record);
}

int edr_preprocess_upload_admit(const EdrBehaviorRecord *record,
                               const EdrDetectionDecision *decision,
                               int p0_proven_miss, int local_forensics_dispatched) {
  const int is_process = record && record->type == EDR_EVENT_PROCESS_CREATE;
  const int is_file_read = record && record->type == EDR_EVENT_FILE_READ;
  const int is_registry = record && (record->type == EDR_EVENT_REG_CREATE_KEY ||
      record->type == EDR_EVENT_REG_SET_VALUE || record->type == EDR_EVENT_REG_DELETE_KEY);
  const int uncombined_tool_file = is_uncombined_tool_file(record, decision);
  const int user_path_only = decision && decision->p0_miss_local_only &&
      strcmp(decision->reason, "suspicious_parent_or_user_path") == 0;
  if (!record || !decision || !p0_proven_miss || local_forensics_dispatched > 0 ||
      (decision->p0_miss_local_only && (!record->pid || !record->process_start_key ||
          !record->process_creation_filetime_100ns ||
          strcmp(record->source_completeness, "COMPLETE") != 0)) ||
      (!is_process && !is_registry && !is_file_read && record->type != EDR_EVENT_FILE_CREATE &&
       record->type != EDR_EVENT_FILE_WRITE &&
       record->type != EDR_EVENT_FILE_DELETE &&
       record->type != EDR_EVENT_FILE_RENAME) ||
      !record->event_id[0] || (!is_process && !is_registry && !record->file_path[0]) ||
      (is_process && (record->is_security_4688 || !record->process_start_key ||
                      !record->process_creation_filetime_100ns)) ||
      (is_file_read && (!record->pid || !record->process_start_key ||
          !record->process_creation_filetime_100ns ||
          !record->file_actor_generation_validated ||
          strcmp(record->source_completeness, "COMPLETE") != 0)) ||
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
      (decision->signal_reasons[0] && !uncombined_tool_file && !user_path_only) || decision->has_remote ||
      (decision->suspicious_parent && !user_path_only) || decision->context_correlated ||
      decision->persistence_change || decision->trigger_pmfe_scan ||
      decision->trigger_single_process_minidump) {
    return 1;
  }

  if (is_file_read || (decision->p0_miss_local_only && !is_process)) {
    /* Full collection for the signed P0 bundle is not authority for a second
     * standalone baseline upload. Preserve sensitive targets and collector
     * diagnostics; the local cache and detectors have already seen this fact. */
    EdrWindowsEventPolicy policy;
    edr_windows_event_policy_evaluate(record, &policy);
    if (!policy.applies || policy.high_value || policy.suspicious) return 1;
    if (!is_registry && !record->file_actor_generation_validated) return 1;
  }

  /* The ordinary frame has no further server consumer when the local IR
   * proved a miss and the generated context has no ransomware signal. Keep
   * every unknown or changed context shape on the upload path. */
  cJSON *context = cJSON_Parse(record->detection_context);
  const int baseline = baseline_context_has_no_server_signal(context, uncombined_tool_file,
                                                            user_path_only);
  cJSON_Delete(context);
  if (!baseline) return 1;
  const int allowlisted_baseline = decision->suppress &&
      decision->allowlisted_path &&
      decision->event_quality_score <= 20u &&
      (strcmp(decision->selection_action, "drop") == 0 ||
       strcmp(decision->selection_action, "local_only") == 0 ||
       strcmp(decision->selection_action, "emit_context") == 0) &&
      strstr(decision->noise_reasons, "allowlisted_path") != NULL;
  const int structured_baseline = (strcmp(decision->reason, "baseline") == 0 &&
      decision->event_quality_score <= 20u) || user_path_only;
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
