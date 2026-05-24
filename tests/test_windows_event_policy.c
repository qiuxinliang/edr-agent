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

int main(void) {
  test_webshell_path_is_high_signal();
  test_browser_cache_stays_ring_only();
  test_initial_access_artifact_is_suspicious();
  test_autorun_registry_is_high_signal();
  test_registry_noise_is_not_emitted();
  puts("windows_event_policy ok");
  return 0;
}
