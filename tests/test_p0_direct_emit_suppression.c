#define _DARWIN_C_SOURCE
#include "edr/behavior_record.h"
#include "edr/ave_sdk.h"
#include "edr/p0_rule_direct_emit.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
extern int setenv(const char *, const char *, int);
#endif

int edr_p0_test_should_suppress_known_false_positive(const char *rule_id,
                                                     const EdrBehaviorRecord *br,
                                                     const char *detail,
                                                     const char **out_reason);

void edr_adaptive_collection_raise(int severity, const char *rule_id, uint32_t pid,
                                   uint32_t parent_pid, const char *process_name) {
  (void)severity;
  (void)rule_id;
  (void)pid;
  (void)parent_pid;
  (void)process_name;
}

static int g_emit_count;
static AVEBehaviorAlert g_last_alert;
void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) { g_emit_count++; if (a) g_last_alert=*a; }

bool edr_resource_preprocess_throttle_active(void) { return false; }

int enrich_parent_info_by_pid(uint32_t ppid, char *parent_name, size_t name_len,
                              char *parent_path, size_t path_len) {
  (void)ppid;
  if (parent_name && name_len > 0u) {
    parent_name[0] = '\0';
  }
  if (parent_path && path_len > 0u) {
    parent_path[0] = '\0';
  }
  return 1;
}

void edr_p0_rule_ir_lazy_init(void) {}
void edr_p0_rule_ir_reload(void) {}
int edr_p0_bundle_dst_path(char *out, size_t cap) {
  if (out && cap > 0u) {
    out[0] = '\0';
  }
  return -1;
}
int edr_p0_rule_ir_is_ready(void) { return 1; }
int edr_p0_rule_ir_get_bundle_info(const char **out_source, size_t *out_plain_size,
                                   const char **out_plain_sha256) {
  if (out_source) {
    *out_source = "";
  }
  if (out_plain_size) {
    *out_plain_size = 0u;
  }
  if (out_plain_sha256) {
    *out_plain_sha256 = "";
  }
  return 0;
}
int edr_p0_rule_ir_matches(const char *rule_id, const char *process_name, const char *cmdline,
                           const char *parent_name, int process_chain_depth) {
  (void)rule_id;
  (void)process_name;
  (void)cmdline;
  (void)parent_name;
  (void)process_chain_depth;
  return 0;
}
int edr_p0_rule_ir_get_meta(const char *rule_id, const char **out_title, const char **out_mitre_csv) {
  if (strcmp(rule_id, "R-TEST-DEDUP") != 0) return -1;
  if (out_title) *out_title = "test";
  if (out_mitre_csv) *out_mitre_csv = "T1059";
  return 1;
}
int edr_p0_rule_ir_get_severity(const char *rule_id) { return strcmp(rule_id,"R-TEST-DEDUP")==0 ? 3 : 0; }
int edr_p0_rule_ir_process_create_count(void) { return 0; }
int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  (void)index;
  if (out_id) {
    *out_id = "";
  }
  return 0;
}
int edr_p0_rule_ir_rule_count(void) { return 1; }
int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  if (index != 0) return 0; if (out_id) *out_id = "R-TEST-DEDUP"; return 1;
}
int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) { return br && index==0 && strcmp(br->process_name,"dedup-test.exe")==0; }
int edr_p0_rule_ir_br_matches_any(const EdrBehaviorRecord *br) {
  (void)br;
  return 0;
}
int edr_p0_rule_ir_is_interesting_remote_port(uint32_t port) {
  (void)port;
  return 0;
}
int edr_p0_rule_ir_is_interesting_process_name(const char *process_name) {
  (void)process_name;
  return 0;
}
void edr_p0_rule_ir_stats_record(int rule_idx, int hit) {
  (void)rule_idx;
  (void)hit;
}
void edr_p0_rule_ir_stats_dump(void) {}
void edr_p0_rule_ir_stats_init(void) {}

static void init_record(EdrBehaviorRecord *r) {
  edr_behavior_record_init(r);
  r->type = EDR_EVENT_PROCESS_CREATE;
  r->priority = 0u;
  r->pid = 4242u;
}

static int suppressed(const char *rule_id, EdrBehaviorRecord *r, const char *detail,
                      const char *want_reason) {
  const char *reason = NULL;
  int ok = edr_p0_test_should_suppress_known_false_positive(rule_id, r, detail, &reason);
  if (want_reason) {
    assert(ok);
    assert(reason != NULL);
    assert(strcmp(reason, want_reason) == 0);
  }
  return ok;
}

static void init_signed_edge_update(EdrBehaviorRecord *r) {
  init_record(r);
  snprintf(r->process_name, sizeof(r->process_name), "MicrosoftEdgeUpdate.exe");
  snprintf(r->exe_path, sizeof(r->exe_path),
           "C:\\Program Files (x86)\\Microsoft\\Temp\\EU8AA.tmp\\MicrosoftEdgeUpdate.exe");
  snprintf(r->exe_hash, sizeof(r->exe_hash),
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  snprintf(r->cmdline, sizeof(r->cmdline),
           "\"C:\\Program Files (x86)\\Microsoft\\Temp\\EU8AA.tmp\\MicrosoftEdgeUpdate.exe\" /update /sessionid \"{788F1F69-597A-44E0-B28D-F001647BB3BB}\"");
  snprintf(r->parent_name, sizeof(r->parent_name), "MicrosoftEdgeUpdateSetup_X86_1.3.239.19.exe");
  snprintf(r->parent_path, sizeof(r->parent_path),
           "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Install\\x\\MicrosoftEdgeUpdateSetup_X86_1.3.239.19.exe");
  snprintf(r->script_snippet, sizeof(r->script_snippet),
           "signature_status=trusted signer=Microsoft Corporation");
}

static void test_edge_update_signed_chain_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  assert(suppressed("R-LOLBIN-010", &r, r.cmdline, "microsoft_edge_update_temp_baseline"));
}

static void test_edge_update_without_signature_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  r.script_snippet[0] = '\0';
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_edge_update_malicious_command_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_signed_edge_update(&r);
  strncat(r.cmdline, " -EncodedCommand AAAA", sizeof(r.cmdline) - strlen(r.cmdline) - 1u);
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_fdsecurity_sensor_task_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\\Program Files\\FDSecurity\\FDSensorTaskLaunch.ps1\"");
  assert(suppressed("R-EXEC-002", &r, r.cmdline, "fdsecurity_self_installer_baseline"));
}

static void test_fdsecurity_setup_diagnostics_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\ProgramData\\FDSecurity\\setup-ui\\install-diagnostics.zip");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "powershell.exe -NoProfile -Command Compress-Archive -Path logs -DestinationPath C:\\ProgramData\\FDSecurity\\setup-ui\\install-diagnostics.zip");
  assert(suppressed("R-EXFIL-001", &r, r.cmdline, "fdsecurity_self_installer_baseline"));
}

static void test_fdsecurity_arbitrary_dll_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe C:\\ProgramData\\FDSecurity\\evil.dll,Start");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_localhost_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe C:\\WINDOWS\\system32\\davclnt.dll,DavSetCookie localhost@9843 http://localhost:9843/Desktop.ini");
  assert(suppressed("R-LOLBIN-002", &r, r.cmdline, "rundll32_davclnt_loopback_baseline"));
}

static void test_rundll32_davclnt_127_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://127.0.0.1:9843/edr-agent-win_3.2.155-windows-amd64-setup-ui");
  assert(suppressed("R-LOLBIN-002", &r, r.cmdline, "rundll32_davclnt_loopback_baseline"));
}

static void test_rundll32_davclnt_external_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://evil.example/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_remote_ip_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://10.0.0.5/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_localhost_suffix_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://localhost.evil.example/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_rundll32_davclnt_127_prefix_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "rundll32.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\rundll32.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "rundll32.exe davclnt.dll,DavSetCookie http://127.0.0.10/Desktop.ini");
  assert(!suppressed("R-LOLBIN-002", &r, r.cmdline, NULL));
}

static void test_t1091_local_fixed_desktop_ini_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini");
  assert(suppressed("R-MITRE-WIN-T1091", &r, r.file_path, "local_fixed_disk_desktop_ini"));
}

static void test_t1091_autorun_inf_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  r.type = EDR_EVENT_FILE_WRITE;
  snprintf(r.file_path, sizeof(r.file_path), "E:\\autorun.inf");
  assert(!suppressed("R-MITRE-WIN-T1091", &r, r.file_path, NULL));
}

static void test_searchprotocolhost_indexing_is_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe45_ Global\\UsGthrCtrlFltPipeMssGthrPipe45 1 -2147483646 \"Software\\Microsoft\\Windows Search\"");
  assert(suppressed("R-LOLBIN-010", &r, r.cmdline, "searchprotocolhost_indexing_baseline"));
}

static void test_searchprotocolhost_user_path_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Users\\Public\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Users\\Public\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe45_");
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_searchprotocolhost_without_pipe_is_not_suppressed(void) {
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  snprintf(r.cmdline, sizeof(r.cmdline),
           "\"C:\\Windows\\System32\\SearchProtocolHost.exe\" powershell -enc AAAA");
  assert(!suppressed("R-LOLBIN-010", &r, r.cmdline, NULL));
}

static void test_searchprotocolhost_no_cmdline_system32_is_suppressed(void) {
  /* behavior_70 缺字段场景：无命令行但 System32 标准路径 + 进程名 → 按正常索引降级。 */
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Windows\\System32\\SearchProtocolHost.exe");
  /* cmdline 留空 */
  assert(suppressed("R-LOLBIN-010", &r, "", "searchprotocolhost_indexing_baseline"));
}

static void test_searchprotocolhost_no_cmdline_user_path_not_suppressed(void) {
  /* 无命令行但伪装到用户目录：仍不豁免，保留检测能力。 */
  EdrBehaviorRecord r;
  init_record(&r);
  snprintf(r.process_name, sizeof(r.process_name), "SearchProtocolHost.exe");
  snprintf(r.exe_path, sizeof(r.exe_path), "C:\\Users\\Public\\SearchProtocolHost.exe");
  assert(!suppressed("R-LOLBIN-010", &r, "", NULL));
}

static void test_real_p0_dedup_metric_matrix(void) {
  assert(setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1000u); g_emit_count = 0;
  EdrBehaviorRecord r; init_record(&r); r.pid=99001u; r.event_time_ns=10; r.type=EDR_EVENT_PROCESS_CREATE;
  snprintf(r.endpoint_id,sizeof(r.endpoint_id),"ep-dedup"); snprintf(r.process_name,sizeof(r.process_name),"dedup-test.exe");
  snprintf(r.identity_quality,sizeof(r.identity_quality),"creator_fallback");
  edr_p0_rule_try_emit(&r); assert(g_emit_count==1);
  EdrP0EmitMetrics emit_metrics; edr_p0_rule_get_emit_metrics(&emit_metrics); assert(emit_metrics.user_subject_full == 1u && emit_metrics.user_subject_degraded == 0u);
  r.type=EDR_EVENT_NET_CONNECT; edr_p0_rule_try_emit(&r); assert(g_emit_count==1); /* exact rank/time */
  r.event_time_ns=11; snprintf(r.identity_quality,sizeof(r.identity_quality),"token_sid"); edr_p0_rule_try_emit(&r); assert(g_emit_count==1); /* intermediate upgrade is suppressed */
  r.event_time_ns=12; snprintf(r.identity_quality,sizeof(r.identity_quality),"target_4688"); snprintf(r.identity_source,sizeof(r.identity_source),"target_4688"); snprintf(r.user_sid,sizeof(r.user_sid),"S-1-5-18"); snprintf(r.event_id,sizeof(r.event_id),"target-event"); edr_p0_rule_try_emit(&r); assert(g_emit_count==2); /* target evidence is the sole material upgrade */
  assert(strstr(g_last_alert.user_subject_json, "S-1-5-18") && strstr(g_last_alert.user_subject_json, "target_4688") && strstr(g_last_alert.user_subject_json, "target-event"));
  r.event_time_ns=13; edr_p0_rule_try_emit(&r); assert(g_emit_count==2); /* repeated target */
  r.event_time_ns=14; snprintf(r.identity_quality,sizeof(r.identity_quality),"creator_fallback"); edr_p0_rule_try_emit(&r); assert(g_emit_count==2); /* lower */
  EdrP0DedupMetrics m; edr_p0_rule_get_dedup_metrics(&m);
  assert(m.exact_suppressed==1u && m.equal_quality_suppressed==1u && m.identity_upgrade_seen==1u && m.lower_quality_suppressed==1u && m.intermediate_upgrade_suppressed==1u);
  assert(m.suppressed_total==4u && m.pre_rule_event_duplicates==0u);
}

static void test_p0_window_expiry_rearms_single_target_upgrade(void) {
  EdrBehaviorRecord r;
  EdrP0DedupMetrics before, after;
  assert(setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(setenv("EDR_P0_DEDUP_SEC", "3", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1000u); g_emit_count = 0;
  init_record(&r); r.pid = 99005u; r.event_time_ns = 100;
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-window"); snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "creator_fallback");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 1);
  r.event_time_ns = 101; snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688"); snprintf(r.user_sid, sizeof(r.user_sid), "S-window");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 2);
  edr_p0_rule_get_dedup_metrics(&before);
  edr_p0_rule_test_set_monotonic_ms(4001u); /* exactly beyond the 3s window */
  r.event_time_ns = 102; snprintf(r.identity_quality, sizeof(r.identity_quality), "creator_fallback");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 3);
  r.event_time_ns = 103; snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  edr_p0_rule_try_emit(&r); assert(g_emit_count == 4);
  edr_p0_rule_get_dedup_metrics(&after);
  assert(after.identity_upgrade_seen == before.identity_upgrade_seen + 1u);
  assert(after.suppressed_total == before.suppressed_total);
}

static void fill_escaped(char *out, size_t cap) {
  size_t i;
  assert(cap > 2u);
  for (i = 0; i + 2u < cap; i++) out[i] = (i % 4u == 0u) ? '"' : (i % 4u == 1u) ? '\\' : (i % 4u == 2u) ? '\n' : 'X';
  out[i] = '\0';
}

static void test_p0_full_context_counts_capped_value_once(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  assert(setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1500u); g_emit_count = 0;
  init_record(&r); r.pid = 99003u; r.event_time_ns = 88;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  memset(r.cmdline, 'A', 600u); r.cmdline[600] = '\0'; /* full JSON remains below its 4090-byte cap. */
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(after.user_subject_full == before.user_subject_full + 1u);
  assert(after.user_subject_degraded == before.user_subject_degraded);
  assert(after.values_truncated == before.values_truncated + 1u);
  assert(after.alerts_with_optional_omission == before.alerts_with_optional_omission);
}

static void test_p0_escape_overflow_degrades_without_silent_core_loss(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  assert(setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(1700u); g_emit_count = 0;
  init_record(&r); r.pid = 99004u; r.event_time_ns = 89;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.event_id, sizeof(r.event_id), "escape-core-event");
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-18");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  memset(r.cmdline, '\1', 480u); r.cmdline[480] = '\0'; /* raw == max, escaped output exceeds esc buffer. */
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(strstr(g_last_alert.user_subject_json, "\"context_degraded\":true") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "escape-core-event") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "S-1-5-18") != NULL);
  assert(after.user_subject_full == before.user_subject_full);
  assert(after.user_subject_degraded == before.user_subject_degraded + 1u);
  assert(after.escape_overflow_values == before.escape_overflow_values + 1u);
  assert(after.values_truncated == before.values_truncated);
}

static void test_p0_user_subject_overflow_degrades_without_losing_alert(void) {
  EdrBehaviorRecord r;
  EdrP0EmitMetrics before, after;
  uint64_t expected_full_caps;
  assert(setenv("EDR_P0_DIRECT_EMIT", "1", 1) == 0);
  assert(setenv("EDR_P0_DEDUP_SEC", "0", 1) == 0);
  edr_p0_rule_test_reset_dedup(); edr_p0_rule_test_set_monotonic_ms(2000u); g_emit_count = 0;
  init_record(&r); r.pid = 99002u; r.event_time_ns = 99; r.type = EDR_EVENT_PROCESS_CREATE;
  snprintf(r.process_name, sizeof(r.process_name), "dedup-test.exe");
  snprintf(r.endpoint_id, sizeof(r.endpoint_id), "ep-overflow");
  snprintf(r.tenant_id, sizeof(r.tenant_id), "tenant-overflow");
  snprintf(r.event_id, sizeof(r.event_id), "source-event-\"\\\\-id");
  snprintf(r.user_sid, sizeof(r.user_sid), "S-1-5-21-quoted\\\\sid");
  snprintf(r.identity_quality, sizeof(r.identity_quality), "target_4688");
  snprintf(r.identity_source, sizeof(r.identity_source), "target_4688");
  fill_escaped(r.cmdline, sizeof(r.cmdline)); fill_escaped(r.parent_cmdline, sizeof(r.parent_cmdline));
  fill_escaped(r.powershell_script_block, sizeof(r.powershell_script_block)); fill_escaped(r.reg_old_value_data, sizeof(r.reg_old_value_data));
  fill_escaped(r.exe_path, sizeof(r.exe_path)); fill_escaped(r.parent_path, sizeof(r.parent_path));
  fill_escaped(r.current_directory, sizeof(r.current_directory)); fill_escaped(r.username, sizeof(r.username));
  fill_escaped(r.domain, sizeof(r.domain)); fill_escaped(r.creator_username, sizeof(r.creator_username));
  fill_escaped(r.creator_domain, sizeof(r.creator_domain)); fill_escaped(r.creator_sid, sizeof(r.creator_sid));
  /* exe_path is also compacted at a smaller limit. This exact full-pass count
   * proves compact reconstruction does not count it a second time. */
  expected_full_caps = (uint64_t)(strlen(r.cmdline) > 480u) +
                       (uint64_t)(strlen(r.parent_cmdline) > 480u) +
                       (uint64_t)(strlen(r.powershell_script_block) > 360u) +
                       (uint64_t)(strlen(r.reg_old_value_data) > 220u) +
                       (uint64_t)(strlen(r.exe_path) > 400u) +
                       (uint64_t)(strlen(r.parent_path) > 400u) +
                       (uint64_t)(strlen(r.current_directory) > 240u) +
                       (uint64_t)(strlen(r.username) > 160u) +
                       (uint64_t)(strlen(r.domain) > 128u) +
                       (uint64_t)(strlen(r.creator_username) > 160u) +
                       (uint64_t)(strlen(r.creator_domain) > 160u) +
                       (uint64_t)(strlen(r.creator_sid) > 256u);
  edr_p0_rule_get_emit_metrics(&before);
  edr_p0_rule_try_emit(&r);
  edr_p0_rule_get_emit_metrics(&after);
  assert(g_emit_count == 1);
  assert(strlen(g_last_alert.user_subject_json) < sizeof(g_last_alert.user_subject_json));
  assert(strstr(g_last_alert.user_subject_json, "\"context_degraded\":true") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"source_event_id\":\"source-event-\\\"\\\\\\\\-id\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"user_sid\":\"S-1-5-21-quoted\\\\\\\\sid\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "\"identity_quality\":\"target_4688\"") != NULL);
  assert(strstr(g_last_alert.user_subject_json, "powershell_script_block") == NULL);
  assert(after.user_subject_degraded == before.user_subject_degraded + 1u);
  assert(after.emitted_without_full_context == before.emitted_without_full_context + 1u);
  assert(after.alerts_with_optional_omission == before.alerts_with_optional_omission + 1u);
  assert(after.values_truncated == before.values_truncated + expected_full_caps);
  assert(after.minimal_failures == before.minimal_failures);
}

int main(void) {
  test_edge_update_signed_chain_is_suppressed();
  test_edge_update_without_signature_is_not_suppressed();
  test_edge_update_malicious_command_is_not_suppressed();
  test_fdsecurity_sensor_task_is_suppressed();
  test_fdsecurity_setup_diagnostics_is_suppressed();
  test_fdsecurity_arbitrary_dll_is_not_suppressed();
  test_rundll32_davclnt_localhost_is_suppressed();
  test_rundll32_davclnt_127_is_suppressed();
  test_rundll32_davclnt_external_is_not_suppressed();
  test_rundll32_davclnt_remote_ip_is_not_suppressed();
  test_rundll32_davclnt_localhost_suffix_is_not_suppressed();
  test_rundll32_davclnt_127_prefix_is_not_suppressed();
  test_t1091_local_fixed_desktop_ini_is_suppressed();
  test_t1091_autorun_inf_is_not_suppressed();
  test_searchprotocolhost_indexing_is_suppressed();
  test_searchprotocolhost_user_path_is_not_suppressed();
  test_searchprotocolhost_without_pipe_is_not_suppressed();
  test_searchprotocolhost_no_cmdline_system32_is_suppressed();
  test_searchprotocolhost_no_cmdline_user_path_not_suppressed();
  test_real_p0_dedup_metric_matrix();
  test_p0_window_expiry_rearms_single_target_upgrade();
  test_p0_full_context_counts_capped_value_once();
  test_p0_escape_overflow_degrades_without_silent_core_loss();
  test_p0_user_subject_overflow_degrades_without_losing_alert();
  puts("test_p0_direct_emit_suppression: ok");
  return 0;
}
