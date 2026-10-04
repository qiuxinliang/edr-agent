#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include "edr/windows_event_policy.h"
#include "cJSON.h"
#include <assert.h>
#include <string.h>
static unsigned stored, considered;
static int allow;
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  assert(r && r->event_id[0]);
  stored++;
}
int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  assert(r && stored > considered);
  considered++;
  return allow;
}

static void test_proven_baseline_read_stays_local(void) {
  EdrBehaviorRecord r = {0};
  EdrDetectionDecision d = {0};
  r.type = EDR_EVENT_FILE_READ;
  r.priority = 0u; /* The collector reserves the P0 lane before matching. */
  r.pid = 74002u;
  r.process_start_key = 74002u;
  r.process_creation_filetime_100ns = 134348800000000000ull;
  r.file_actor_generation_validated = 1u;
  strcpy(r.event_id, "read-baseline-context");
  strcpy(r.source_completeness, "COMPLETE");
  strcpy(r.process_name, "ordinary.exe");
  strcpy(r.exe_path, "C:\\Vendor\\ordinary.exe");
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\ordinary.dat");
  edr_windows_event_policy_configure(NULL);
  edr_detection_decision_evaluate_after_p0(&r, &d, 1);
  assert(strcmp(d.reason, "baseline") == 0);
  assert(strcmp(d.selection_action, "local_only") == 0);
  assert(d.p0_miss_local_only);
  unsigned before_stored = stored;
  allow = 1;
  assert(edr_preprocess_admit_telemetry(&r, &d));
  uint64_t before_skipped = edr_preprocess_baseline_file_upload_skipped_count();
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(stored == before_stored + 1u);
  assert(edr_preprocess_baseline_file_upload_skipped_count() == before_skipped + 1u);

  /* An unavailable rule authority or any retained alert/forensic signal
   * cannot be mistaken for an ordinary read, even at an ordinary path. */
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));
  strcpy(d.signal_reasons, "process_context");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  d.signal_reasons[0] = 0;
  strcpy(r.pmfe_snapshot, "{\"image_hits\":1}");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.pmfe_snapshot[0] = 0;
  strcpy(r.source_completeness, "NOT_EVALUABLE");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.source_completeness, "COMPLETE");
  r.process_start_key = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 74002u;
  r.file_actor_generation_validated = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.file_actor_generation_validated = 1u;
  strcpy(r.collector_evidence_gate, "file_path_unresolved");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.collector_evidence_gate[0] = 0;
  strcpy(r.source_truncated_fields, "source.cmdline");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.source_truncated_fields[0] = 0;

  strcpy(r.file_path, "C:\\Windows\\System32\\config\\SAM");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\inetpub\\wwwroot\\shell.aspx");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\ordinary.dat");
  char context[sizeof(r.detection_context)];
  strcpy(context, r.detection_context);
  cJSON *root = cJSON_Parse(context);
  assert(root);
  cJSON *signals = cJSON_GetObjectItemCaseSensitive(root, "signals");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(signals, "process_context", cJSON_CreateBool(1)));
  assert(cJSON_PrintPreallocated(root, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  cJSON_DeleteItemFromObjectCaseSensitive(signals, "process_context");
  assert(cJSON_PrintPreallocated(root, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  cJSON_Delete(root);
  strcpy(r.detection_context, "{broken");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.detection_context, context);
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
}

static void test_priority_does_not_create_detection_authority(void) {
  EdrBehaviorRecord r = {0};
  EdrDetectionDecision d = {0};
  r.type = EDR_EVENT_FILE_WRITE;
  r.priority = 0u;
  r.pid = 74003u;
  r.process_start_key = 74003u;
  r.process_creation_filetime_100ns = 134348800000000000ull;
  r.file_actor_generation_validated = 1u;
  strcpy(r.event_id, "priority-reservation-is-not-detection");
  strcpy(r.source_completeness, "COMPLETE");
  strcpy(r.process_name, "ordinary.exe");
  strcpy(r.exe_path, "C:\\Vendor\\ordinary.exe");
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\ordinary.dat");
  strcpy(r.cmdline, "ordinary.exe --cache C:\\Users\\alice\\AppData\\Local\\Example");
  edr_detection_decision_evaluate_after_p0(&r, &d, 1);
  assert(strcmp(d.reason, "suspicious_parent_or_user_path") == 0);
  assert(d.event_quality_score == 32u && d.p0_miss_local_only);
  assert(strcmp(d.selection_action, "local_only") == 0);
  assert(r.priority == 0u); /* Reliability/queue priority is unchanged. */
  unsigned before = stored;
  allow = 1;
  assert(edr_preprocess_admit_telemetry(&r, &d));
  assert(stored == before + 1u); /* Local analysis precedes final admission. */
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));
  cJSON *context = cJSON_Parse(r.detection_context);
  const cJSON *quality = cJSON_GetObjectItemCaseSensitive(context, "event_quality");
  assert(strcmp(cJSON_GetObjectItemCaseSensitive(quality, "selection_action")->valuestring,
                "local_only") == 0);
  char baseline[sizeof(r.detection_context)];
  strcpy(baseline, r.detection_context);
  cJSON *signals = cJSON_GetObjectItemCaseSensitive(context, "signals");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(signals, "script_sensor", cJSON_CreateBool(1)));
  assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  cJSON_DeleteItemFromObjectCaseSensitive(signals, "script_sensor");
  assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  cJSON_Delete(context);
  strcpy(r.detection_context, baseline);
  strcpy(r.file_path, "C:\\Windows\\System32\\config\\SAM");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\ordinary.dat");
  r.process_start_key = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 74003u;
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));

  /* A rule hit is never a proved miss. Unknown matcher/gate outcomes and
   * incomplete actor facts preserve the existing conservative path. */
  edr_detection_decision_evaluate_after_p0(&r, &d, 0);
  assert(!d.p0_miss_local_only);
  assert(d.event_quality_score == 32u);
  assert(strcmp(d.selection_action, "local_only") == 0);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  strcpy(r.source_completeness, "NOT_EVALUABLE");
  edr_detection_decision_evaluate_after_p0(&r, &d, 1);
  assert(!d.p0_miss_local_only);
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.source_completeness, "COMPLETE");
  r.process_start_key = 0u;
  edr_detection_decision_evaluate_after_p0(&r, &d, 1);
  assert(!d.p0_miss_local_only);
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 74003u;

  /* Real Office/browser parent context and combined remote/script evidence
   * do not become a user-path-only baseline. */
  static const char *const parents[] = {"WINWORD.EXE", "chrome.exe"};
  for (size_t i = 0; i < sizeof(parents) / sizeof(parents[0]); i++) {
    strcpy(r.parent_name, parents[i]);
    edr_detection_decision_evaluate_after_p0(&r, &d, 1);
    assert(!d.p0_miss_local_only);
    assert(d.event_quality_score == 32u);
    assert(strcmp(d.selection_action, "local_only") == 0);
    assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  }
  r.parent_name[0] = 0;
  strcpy(r.cmdline, "ordinary.exe --cache C:\\Users\\alice\\AppData\\Local\\Example --url https://example.test/");
  edr_detection_decision_evaluate_after_p0(&r, &d, 1);
  assert(d.has_remote && !d.p0_miss_local_only);
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
}

static void test_uncombined_tool_file_upload(void) {
  EdrBehaviorRecord r = {0};
  EdrDetectionDecision d = {0};
  r.type = EDR_EVENT_FILE_WRITE;
  r.priority = 0u;
  r.pid = 74001u;
  r.process_start_key = 74001u;
  r.process_creation_filetime_100ns = 134348800000000000ull;
  r.kernel_file_activity = 1u;
  r.file_actor_generation_validated = 1u;
  strcpy(r.event_id, "tool-cache-write");
  strcpy(r.source_completeness, "COMPLETE");
  strcpy(r.process_name, "powershell.exe");
  strcpy(r.exe_path, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  strcpy(r.cmdline, "powershell.exe -NoProfile -NonInteractive");
  strcpy(r.file_path, "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive");
  edr_windows_event_policy_configure(NULL);
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(strcmp(d.reason, "lolbin,lolbin_without_combo_condition") == 0);
  assert(strcmp(d.signal_reasons, "lolbin") == 0);
  assert(d.event_quality_score == 32u);
  assert(strcmp(d.selection_action, "local_only") == 0);
  uint64_t before = edr_preprocess_baseline_file_upload_skipped_count();
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_file_upload_skipped_count() == before + 1u);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));

  /* Frozen UTM failure: SYSTEMprofile matched the SYSTEM hive prefix and
   * bypassed the already supported uncombined-tool admission decision. */
  strcpy(r.file_path, "C:\\WINDOWS\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive");
  edr_detection_decision_evaluate(&r, &d);
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Windows\\System32\\config\\SYSTEM");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive");

  /* Identity, attribution, diagnostics and sensitive targets still upload. */
  r.process_start_key = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 74001u;
  r.process_creation_filetime_100ns = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_creation_filetime_100ns = 134348800000000000ull;
  r.file_actor_generation_validated = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.file_actor_generation_validated = 1u;
  strcpy(r.collector_evidence_gate, "file_path_unresolved");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.collector_evidence_gate[0] = 0;
  strcpy(r.source_completeness, "NOT_EVALUABLE");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.source_completeness, "COMPLETE");
  strcpy(r.source_truncated_fields, "source.cmdline");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.source_truncated_fields[0] = 0;
  strcpy(r.file_path, "C:\\inetpub\\wwwroot\\shell.aspx");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startup.ps1");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.file_path, "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive");
  r.type = EDR_EVENT_PROCESS_CREATE;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.type = EDR_EVENT_FILE_READ;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.type = EDR_EVENT_FILE_WRITE;

  /* The same tool gains upload value as soon as another signal or retained
   * process context appears. Missing/changed JSON must not grant suppression. */
  char baseline[sizeof(r.detection_context)];
  strcpy(baseline, r.detection_context);
  static const char *const positive[] = {
      "remote", "ransom_note", "tls_anomaly", "ransom_canary", "script_sensor",
      "process_context", "ransom_behavior", "extension_changed", "ransom_note_burst",
      "suspicious_parent", "webshell_semantic", "persistence_change",
      "high_content_entropy", "cert_revoked_ancestor", "security_product_kill",
      "ransom_recovery_tamper", "silverfox_attack_chain"};
  for (size_t i = 0; i < sizeof(positive) / sizeof(positive[0]); ++i) {
    cJSON *context = cJSON_Parse(baseline);
    assert(context);
    cJSON *signals = cJSON_GetObjectItemCaseSensitive(context, "signals");
    assert(cJSON_ReplaceItemInObjectCaseSensitive(signals, positive[i], cJSON_CreateBool(1)));
    assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
    assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
    cJSON_Delete(context);
  }
  cJSON *context = cJSON_Parse(baseline);
  assert(context);
  cJSON *signals = cJSON_GetObjectItemCaseSensitive(context, "signals");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(signals, "ransom_chain_score", cJSON_CreateNumber(35)));
  assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(cJSON_ReplaceItemInObjectCaseSensitive(signals, "ransom_chain_score", cJSON_CreateNumber(20)));
  cJSON_DeleteItemFromObjectCaseSensitive(signals, "remote");
  assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  cJSON_Delete(context);
  static const char *const retained[] = {
      "tracking_saturated", "state_transition", "periodic_summary"};
  for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); ++i) {
    context = cJSON_Parse(baseline);
    assert(context);
    cJSON *control = cJSON_GetObjectItemCaseSensitive(context, "ransom_control");
    assert(cJSON_ReplaceItemInObjectCaseSensitive(control, retained[i], cJSON_CreateBool(1)));
    assert(cJSON_PrintPreallocated(context, r.detection_context, sizeof(r.detection_context), 0));
    assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
    cJSON_Delete(context);
  }
  strcpy(r.detection_context, "{broken");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.detection_context, baseline);
  strcpy(d.signal_reasons, "lolbin,script_or_encoded_payload");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
}

int main(void) {
  EdrBehaviorRecord r = {0};
  EdrDetectionDecision d = {0};
  strcpy(r.event_id, "context-for-live-candidate");
  r.priority = 1u; /* Not a separately emitted P0 alert. */
  allow = 1;
  assert(edr_preprocess_admit_telemetry(&r, &d));
  allow = 0; /* Duplicate upload must still reach the evidence owner. */
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  assert(stored == 2u && considered == 2u);
  strcpy(d.selection_action, "local_only");
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  d.selection_action[0] = '\0';
  d.drop = 1u;
  assert(!edr_preprocess_admit_telemetry(&r, &d));
  assert(stored == 4u && considered == 2u);
  assert(!edr_preprocess_admit_telemetry(NULL, &d));
  assert(stored == 4u);

  /* Ordinary suppressed rename can skip only its standalone upload. A schema
   * change, missing P0 rule authority, or any signal keeps the upload. */
  memset(&r, 0, sizeof(r));
  memset(&d, 0, sizeof(d));
  r.type = EDR_EVENT_FILE_RENAME;
  r.priority = 0u;
  strcpy(r.event_id, "rename-baseline-1");
  strcpy(r.process_name, "setup.exe");
  strcpy(r.exe_path, "C:\\Program Files\\Example\\setup.exe");
  strcpy(r.file_path, "C:\\Program Files\\Example\\file.txt");
  strcpy(r.file_old_path, "C:\\Program Files\\Example\\old-file.txt");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress && d.allowlisted_path);
  assert(d.event_quality_score < 20u);
  assert(strcmp(d.selection_action, "drop") == 0);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_rename_upload_skipped_count() == 1u);
  strcpy(d.signal_reasons, "ransom_behavior_counter");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  d.signal_reasons[0] = '\0';
  r.priority = 0u;
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.priority = 2u;
  r.type = EDR_EVENT_FILE_DELETE;
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_file_upload_skipped_count() == 1u);
  r.type = EDR_EVENT_FILE_WRITE;
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_file_upload_skipped_count() == 2u);
  r.source_completeness[0] = 'N';
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.source_completeness[0] = '\0';
  strcpy(r.pmfe_snapshot, "{\"image_hits\":1}");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.pmfe_snapshot[0] = '\0';
  r.type = EDR_EVENT_PROCESS_CREATE;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.type = EDR_EVENT_FILE_RENAME;
  strcpy(r.detection_context, "{\"ransom_control\":{\"phase\":\"candidate\"}}");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_rename_upload_skipped_count() == 2u);

  /* A server-style structured baseline file frame can skip only after an
   * authoritative P0 miss. */
  memset(&r, 0, sizeof(r));
  memset(&d, 0, sizeof(d));
  r.type = EDR_EVENT_FILE_CREATE;
  r.priority = 0u;
  strcpy(r.event_id, "structured-baseline-file");
  strcpy(r.process_name, "ordinary.exe");
  strcpy(r.exe_path, "C:\\Vendor\\ordinary.exe");
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\ordinary.dat");
  edr_detection_decision_evaluate(&r, &d);
  assert(strcmp(d.reason, "baseline") == 0);
  assert(d.event_quality_score <= 20u);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_file_upload_skipped_count() == 3u);
  char baseline_context[sizeof(r.detection_context)];
  strcpy(baseline_context, r.detection_context);
  char *kind = strstr(r.detection_context, "\"kind\":\"\"");
  assert(kind);
  kind += strlen("\"kind\":\"");
  assert(strlen(r.detection_context) + 1u < sizeof(r.detection_context));
  memmove(kind + 1u, kind, strlen(kind) + 1u);
  *kind = 'X';
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.detection_context, baseline_context);
  r.source_truncated_fields[0] = 'x';
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.source_truncated_fields[0] = '\0';
  r.type = EDR_EVENT_PROCESS_CREATE;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));

  /* The server drops these ordinary process baselines. Suppress only a
   * generation-bound source after a P0 miss; retain incomplete source,
   * active signals and dispatched forensics on the existing upload path. */
  memset(&r, 0, sizeof(r));
  memset(&d, 0, sizeof(d));
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 123u;
  r.ppid = 4u;
  r.process_start_key = 12345u;
  r.process_creation_filetime_100ns = 134348800000000000ull;
  strcpy(r.event_id, "structured-baseline-process");
  strcpy(r.process_name, "ordinary.exe");
  strcpy(r.exe_path, "C:\\Vendor\\ordinary.exe");
  strcpy(r.source_completeness, "COALESCED");
  edr_detection_decision_evaluate(&r, &d);
  assert(strcmp(d.reason, "baseline") == 0);
  assert(d.event_quality_score <= 20u);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_process_upload_skipped_count() == 1u);
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));
  r.process_start_key = 0u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 12345u;
  strcpy(r.source_completeness, "NOT_EVALUABLE");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.source_completeness, "CORRELATION_MISSING");
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_process_upload_skipped_count() == 2u);
  strcpy(d.signal_reasons, "suspicious_parent");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  d.signal_reasons[0] = '\0';
  r.is_security_4688 = 1u;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));

  /* Run the real decision builder: its generic forensic suggestions do not
   * make an otherwise suppressed baseline rename an independent alert. */
  memset(&r, 0, sizeof(r));
  memset(&d, 0, sizeof(d));
  r.type = EDR_EVENT_FILE_RENAME;
  r.priority = 0u; /* Ransom burst admission can reserve this lane before evaluation. */
  r.pid = 11004u;
  strcpy(r.event_id, "rename-generated-context");
  strcpy(r.process_name, "setup.exe");
  strcpy(r.exe_path, "C:\\Program Files\\Example\\setup.exe");
  strcpy(r.file_path, "C:\\Users\\alice\\Documents\\report.docx");
  strcpy(r.file_old_path, "C:\\Users\\alice\\Documents\\report-old.docx");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress && d.allowlisted_path);
  assert(r.priority == 0u);
  assert(d.event_quality_score < 20u);
  assert(strcmp(d.selection_action, "drop") == 0);
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_rename_upload_skipped_count() == 3u);

  /* Registry baselines need captured, generation-bound attribution and a
   * proved P0 miss. Markers in commands never grant an exemption. */
  memset(&r, 0, sizeof(r));
  r.type = EDR_EVENT_REG_DELETE_KEY;
  r.pid = 123u; r.process_start_key = 45u;
  r.process_creation_filetime_100ns = 134348800000000000ull;
  strcpy(r.event_id, "registry-baseline");
  strcpy(r.process_name, "ordinary.exe");
  strcpy(r.reg_key_path, "HKCU\\Software\\Example\\Temporary");
  strcpy(r.reg_attribution, "process_id");
  strcpy(r.reg_detail_status, "captured");
  strcpy(r.source_completeness, "COMPLETE");
  edr_detection_decision_evaluate(&r, &d);
  assert(strcmp(d.reason, "baseline") == 0);
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_registry_upload_skipped_count() == 1u);
  assert(edr_preprocess_upload_admit(&r, &d, 0, 0));
  assert(edr_preprocess_upload_admit(&r, &d, 1, 1));
  r.process_start_key = 0;
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  r.process_start_key = 45u;
  strcpy(r.reg_attribution, "unavailable");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.reg_attribution, "process_id");
  strcpy(d.signal_reasons, "persistence_change");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  strcpy(r.cmdline, "ordinary.exe source=agent_internal cmd_forensic_fake");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  d.signal_reasons[0] = 0;
  strcpy(r.source_completeness, "NOT_EVALUABLE");
  assert(edr_preprocess_upload_admit(&r, &d, 1, 0));
  test_uncombined_tool_file_upload();
  test_proven_baseline_read_stays_local();
  test_priority_does_not_create_detection_authority();
  return 0;
}
