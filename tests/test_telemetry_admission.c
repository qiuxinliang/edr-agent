#include "edr/preprocess.h"
#include "edr/detection_decision.h"
#include "edr/dedup.h"
#include "edr/local_evidence_cache.h"
#include <assert.h>
#include <string.h>
static unsigned stored, considered;
static int allow;
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  assert(r && strcmp(r->event_id, "context-for-live-candidate") == 0);
  stored++;
}
int edr_preprocess_should_emit(const EdrBehaviorRecord *r) {
  assert(r && stored > considered);
  considered++;
  return allow;
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
  assert(strcmp(d.selection_action, "emit_context") == 0);
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
   * authoritative P0 miss. A process baseline remains for source validation. */
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
  assert(strcmp(d.selection_action, "emit_context") == 0);
  assert(!edr_preprocess_upload_admit(&r, &d, 1, 0));
  assert(edr_preprocess_baseline_rename_upload_skipped_count() == 3u);
  return 0;
}
