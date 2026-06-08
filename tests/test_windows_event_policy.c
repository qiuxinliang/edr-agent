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

static void test_localservice_tfs_dav_cache_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "xtac64se.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\TfsStore\\Tfs_DAV\\{390D9B48-C3E2-401C-8CD6-0AAB3475278E}.ps1");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "service_temp_dav_cache") != NULL);
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

static void test_system_driver_enumeration_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "svchost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\ndisuio.sys");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(strstr(p.reason, "known_windows_driver_enumeration") != NULL);
}

static void test_powershell_policy_probe_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "powershell.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\__PSScriptPolicyTest_abcd.ps1");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "powershell_script_policy_probe") != NULL);
}

static void test_systemprofile_cache_db_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "svchost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\AppData\\Local"
           "\\Microsoft\\Windows\\Caches\\cversions.3.db");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "systemprofile_windows_cache_db") != NULL);
}

static void test_installservice_catalog_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "svchost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\AppData\\Local"
           "\\Microsoft\\InstallService\\{17A33966-CC08-4A93-B766-3FF4CF533B5D}.catalogItem"
           ":$DSC:$LOGGED_UTILITY_STREAM");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "systemprofile_installservice_catalog") != NULL);
}

static void test_installservice_plain_catalog_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "svchost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\AppData\\Local"
           "\\Microsoft\\InstallService\\{17A33966-CC08-4A93-B766-3FF4CF533B5D}.catalogItem");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "systemprofile_installservice_catalog") != NULL);
}

static void test_systemprofile_cryptnet_metadata_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow"
           "\\Microsoft\\CryptnetUrlCache\\MetaData\\7F9657FD5D75F23149C6D23124EB2E79");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "systemprofile_cryptnet_url_cache") != NULL);
}

static void test_systemprofile_cryptnet_content_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow"
           "\\Microsoft\\CryptnetUrlCache\\Content\\B76BE66D46C355931939D8CF818D03FD");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "systemprofile_cryptnet_url_cache") != NULL);
}

static void test_windowsapps_webexperience_assets_are_not_webshell_signal(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "svchost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Program Files\\WindowsApps"
           "\\MicrosoftWindows.Client.WebExperience_526.11701.50.0_arm64__cw5n1h2txyewy"
           "\\Dashboard\\WebContent\\wwwroot\\com-msn-weather\\images");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "windowsapps_webexperience_assets") != NULL);
}

static void test_edge_update_temp_staging_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "MicrosoftEdgeUpdate.exe");
  snprintf(r.exe_path, sizeof(r.exe_path),
           "C:\\Program Files (x86)\\Microsoft\\Temp\\EUF397.tmp\\MicrosoftEdgeUpdate.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Program Files (x86)\\Microsoft\\Temp\\EUF397.tmp\\msedgeupdate.dll");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "microsoft_edge_update_temp_staging") != NULL);
}

static void test_windows_update_umdf_mui_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "MoUsoCoreWorker.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\UMDF\\zh-CN\\UsbccidDriver.dll.mui");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "windows_update_umdf_mui") != NULL);
}

static void test_installservice_smartretry_task_is_not_emitted(void) {
  EdrBehaviorRecord r;
  EdrWindowsEventPolicy p;
  init_record(&r, EDR_EVENT_FILE_WRITE);
  snprintf(r.process_name, sizeof(r.process_name), "backgroundTaskHost.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "\\Device\\HarddiskVolume3\\Windows\\System32\\Tasks\\Microsoft\\Windows\\InstallService\\SmartRetry");
  edr_windows_event_policy_apply(&r);
  edr_windows_event_policy_evaluate(&r, &p);
  assert(p.applies);
  assert(p.noisy);
  assert(!p.high_value);
  assert(!p.should_emit);
  assert(!p.should_persist);
  assert(r.priority == 2u);
  assert(strstr(p.reason, "installservice_smartretry_task") != NULL);
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
  snprintf(r.process_name, sizeof(r.process_name), "cleanmgr.exe");
  snprintf(r.file_path, sizeof(r.file_path),
           "C:\\Users\\alice\\AppData\\Local\\Temp\\xml_file_42.xml");
  assert(edr_windows_event_policy_should_emit(&r) == 0);
  edr_windows_event_policy_get_status(&st);
  assert(st.enabled == 1u);
  assert(st.evaluated == 1u);
  assert(st.dropped == 1u);
  assert(st.temp_xml == 1u);
  assert(strstr(st.last_drop_reason, "temp_xml_low_value_file") != NULL);
  assert(strstr(st.last_drop_process, "cleanmgr.exe") != NULL);
  assert(strstr(st.last_drop_path, "xml_file_42.xml") != NULL);
}

int main(void) {
  edr_windows_event_policy_configure(NULL);
  test_webshell_path_is_high_signal();
  test_browser_cache_stays_ring_only();
  test_initial_access_artifact_is_suspicious();
  test_localservice_tfs_dav_cache_is_not_emitted();
  test_autorun_registry_is_high_signal();
  test_registry_noise_is_not_emitted();
  test_agent_forensic_bundle_is_not_emitted();
  test_cleanmgr_temp_xml_is_not_emitted();
  test_system_driver_enumeration_is_not_emitted();
  test_powershell_policy_probe_is_not_emitted();
  test_systemprofile_cache_db_is_not_emitted();
  test_installservice_catalog_is_not_emitted();
  test_installservice_plain_catalog_is_not_emitted();
  test_systemprofile_cryptnet_metadata_is_not_emitted();
  test_systemprofile_cryptnet_content_is_not_emitted();
  test_windowsapps_webexperience_assets_are_not_webshell_signal();
  test_edge_update_temp_staging_is_not_emitted();
  test_windows_update_umdf_mui_is_not_emitted();
  test_installservice_smartretry_task_is_not_emitted();
  test_policy_can_be_disabled_by_runtime_config();
  test_policy_status_counts_drop_reasons();
  puts("windows_event_policy ok");
  return 0;
}
