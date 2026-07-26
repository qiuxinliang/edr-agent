#include "edr/behavior_record.h"
#include "edr/ave_sdk.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

void edr_behavior_alert_emit_to_batch(const AVEBehaviorAlert *a) { (void)a; }

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
  return 0;
}

void edr_p0_rule_ir_lazy_init(void) {}
void edr_p0_rule_ir_reload(void) {}
int edr_p0_bundle_dst_path(char *out, size_t cap) {
  if (out && cap > 0u) {
    out[0] = '\0';
  }
  return -1;
}
int edr_p0_rule_ir_is_ready(void) { return 0; }
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
  (void)rule_id;
  if (out_title) {
    *out_title = "";
  }
  if (out_mitre_csv) {
    *out_mitre_csv = "";
  }
  return 0;
}
int edr_p0_rule_ir_get_severity(const char *rule_id) {
  (void)rule_id;
  return 0;
}
int edr_p0_rule_ir_process_create_count(void) { return 0; }
int edr_p0_rule_ir_process_create_id_at(int index, const char **out_id) {
  (void)index;
  if (out_id) {
    *out_id = "";
  }
  return 0;
}
int edr_p0_rule_ir_rule_count(void) { return 0; }
int edr_p0_rule_ir_rule_id_at(int index, const char **out_id) {
  (void)index;
  if (out_id) {
    *out_id = "";
  }
  return 0;
}
int edr_p0_rule_ir_br_matches_index(const EdrBehaviorRecord *br, int index) {
  (void)br;
  (void)index;
  return 0;
}
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

int main(void) {
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
  puts("test_p0_direct_emit_suppression: ok");
  return 0;
}
