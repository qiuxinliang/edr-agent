#include "edr/behavior_record.h"
#include "edr/windows_event_policy.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void init_record(EdrBehaviorRecord *r, EdrEventType t) {
  edr_behavior_record_init(r);
  r->type = t;
  r->priority = 1u;
}

static void test_webshell_path_is_high_signal(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path), "C:\\inetpub\\wwwroot\\upload\\shell.aspx");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.high_value);
  assert(p.suspicious);
  assert(p.should_emit);
  assert(p.should_persist);
  assert(r.priority == 0u);
  assert(strstr(r.script_snippet, "webshell_candidate") != NULL);
}

static void test_browser_cache_stays_ring_only(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\f_000123");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(!p.high_value);
  assert(p.noisy);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
}

static void test_initial_access_artifact_is_suspicious(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_CREATE);
  snprintf(r.file_path, sizeof(r.file_path), "C:\\Users\\alice\\AppData\\Local\\Temp\\invoice.js");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.suspicious);
  assert(p.should_emit);
  assert(p.should_persist);
  assert(r.priority == 0u);
  assert(strstr(r.script_snippet, "script_temp_staging") != NULL);
}

static void test_autorun_registry_is_high_signal(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_REG_SET_VALUE);
  snprintf(r.reg_key_path, sizeof(r.reg_key_path),
           "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
  snprintf(r.reg_value_name, sizeof(r.reg_value_name), "Updater");
  snprintf(r.reg_value_data, sizeof(r.reg_value_data), "C:\\Users\\alice\\AppData\\Roaming\\updater.exe");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.suspicious);
  assert(p.should_emit);
  assert(p.should_persist);
  assert(r.priority == 0u);
  assert(strstr(r.script_snippet, "autorun_persistence") != NULL);
}

static void test_registry_noise_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_REG_SET_VALUE);
  snprintf(r.reg_key_path, sizeof(r.reg_key_path),
           "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced");
  snprintf(r.reg_value_name, sizeof(r.reg_value_name), "Hidden");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
}

static void test_agent_forensic_bundle_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "tar.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\edr_forensic\\cmd_forensic_1\\bundle.tgz");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(strstr(p.reason, "agent_internal_forensic") != NULL);
}

static void test_cleanmgr_temp_xml_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "cleanmgr.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\xml_file_42.xml");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
}

static void test_policy_can_be_disabled_by_runtime_config(void) {
  EdrWindowsEventFilterConfig cfg;
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  EdrWindowsEventFilterStatus st;
  memset(&cfg, 0, sizeof(cfg));
  cfg.enabled = 0u;
  snprintf(cfg.version, sizeof(cfg.version), "%s", "agent-event-filter-test-off");
  edr_windows_event_policy_configure(&cfg);

  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\edr_forensic\\cmd_forensic_1\\bundle.tgz");
  assert(edr_windows_event_policy_should_emit(&r) == 1);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(!p.applies);
  edr_windows_event_policy_get_status(&st);
  assert(st.enabled == 0u);
  assert(st.evaluated == 0u);

  edr_windows_event_policy_configure(NULL);
}

static void test_policy_status_counts_drop_reasons(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventFilterStatus st;
  edr_windows_event_policy_configure(NULL);
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\xml_file_42.xml");
  assert(edr_windows_event_policy_should_emit(&r) == 0);
  edr_windows_event_policy_get_status(&st);
  assert(st.enabled == 1u);
  assert(st.evaluated == 1u);
  assert(st.dropped == 1u);
  assert(st.temp_xml == 1u);
}

int main(void) {
  edr_windows_event_policy_configure(NULL);
  test_webshell_path_is_high_signal();
  test_browser_cache_stays_ring_only();
  test_initial_access_artifact_is_suspicious();
  test_autorun_registry_is_high_signal();
  test_registry_noise_is_not_emitted();
  test_agent_forensic_bundle_is_not_emitted();
  test_cleanmgr_temp_xml_is_not_emitted();
  test_policy_can_be_disabled_by_runtime_config();
  test_policy_status_counts_drop_reasons();
  puts("windows_event_policy ok");
  return 0;
}
