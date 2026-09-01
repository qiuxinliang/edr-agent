#include "edr/adaptive_collection.h"
#include "edr/behavior_record.h"
#include "edr/config.h"
#include "edr/sensor_interest.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void edr_correlation_observe_interest(const EdrSensorInterestEvent *ev) {
  (void)ev;
}

#if defined(_WIN32)
#include <stdlib.h>
static void set_env_value(const char *name, const char *value) {
  _putenv_s(name, value ? value : "");
}
#else
#include <stdlib.h>
static void set_env_value(const char *name, const char *value) {
  setenv(name, value ? value : "", 1);
}
#endif

static EdrConfig adaptive_config(int enabled) {
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.collection.adaptive_enabled = enabled ? true : false;
  cfg.collection.adaptive_boost_seconds = 180u;
  cfg.collection.adaptive_min_severity = 3u;
  return cfg;
}

static EdrSensorInterestEvent event_of(EdrEventType type, uint32_t pid,
                                       uint32_t ppid, const char *process_name,
                                       const char *path) {
  EdrSensorInterestEvent e;
  memset(&e, 0, sizeof(e));
  e.type = type;
  e.pid = pid;
  e.parent_pid = ppid;
  snprintf(e.process_name, sizeof(e.process_name), "%s", process_name ? process_name : "");
  snprintf(e.path, sizeof(e.path), "%s", path ? path : "");
  return e;
}

static void test_adaptive_requires_boosted_process_tree(void) {
  EdrConfig cfg = adaptive_config(1);
  edr_adaptive_collection_configure(&cfg);
  edr_adaptive_collection_raise(3, "R-EXEC-002", 100u, 50u, "powershell.exe");

  EdrSensorInterestEvent unrelated =
      event_of(EDR_EVENT_FILE_READ, 200u, 20u, "powershell.exe",
               "C:\\Users\\alice\\Documents\\notes.txt");
  assert(edr_adaptive_collection_should_admit_interest(&unrelated) == 0);

  EdrSensorInterestEvent related =
      event_of(EDR_EVENT_FILE_WRITE, 100u, 50u, "powershell.exe",
               "C:\\Users\\alice\\Documents\\notes.txt");
  assert(edr_adaptive_collection_should_admit_interest(&related) == 1);

  EdrSensorInterestEvent child =
      event_of(EDR_EVENT_PROCESS_CREATE, 101u, 100u, "cmd.exe", "");
  assert(edr_adaptive_collection_should_admit_interest(&child) == 1);

  EdrSensorInterestEvent unrelated_proc =
      event_of(EDR_EVENT_PROCESS_CREATE, 300u, 20u, "cmd.exe", "");
  assert(edr_adaptive_collection_should_admit_interest(&unrelated_proc) == 0);
}

static void test_adaptive_budget_limits_expansion(void) {
  EdrConfig cfg = adaptive_config(1);
  set_env_value("EDR_ADAPTIVE_COLLECTION_ADMIT_BUDGET_PER_MIN", "2");
  set_env_value("EDR_ADAPTIVE_COLLECTION_SCRIPT_BUDGET_PER_MIN", "1");
  edr_adaptive_collection_configure(&cfg);
  edr_adaptive_collection_raise(3, "R-FILELESS-001", 1000u, 900u, "powershell.exe");

  EdrSensorInterestEvent first =
      event_of(EDR_EVENT_SCRIPT_POWERSHELL, 1000u, 900u, "powershell.exe", "");
  EdrSensorInterestEvent second =
      event_of(EDR_EVENT_SCRIPT_POWERSHELL, 1000u, 900u, "powershell.exe", "");
  EdrSensorInterestEvent third =
      event_of(EDR_EVENT_FILE_WRITE, 1000u, 900u, "powershell.exe",
               "C:\\Users\\alice\\Documents\\notes.txt");
  assert(edr_adaptive_collection_should_admit_interest(&first) == 1);
  assert(edr_adaptive_collection_should_admit_interest(&second) == 0);
  assert(edr_adaptive_collection_should_admit_interest(&third) == 1);

  EdrSensorInterestEvent fourth =
      event_of(EDR_EVENT_FILE_CREATE, 1000u, 900u, "powershell.exe",
               "C:\\Users\\alice\\Documents\\next.txt");
  assert(edr_adaptive_collection_should_admit_interest(&fourth) == 0);
  set_env_value("EDR_ADAPTIVE_COLLECTION_ADMIT_BUDGET_PER_MIN", "");
  set_env_value("EDR_ADAPTIVE_COLLECTION_SCRIPT_BUDGET_PER_MIN", "");
}

static void test_adaptive_record_rejects_unrepresentable_interest_field(void) {
  EdrConfig cfg = adaptive_config(1);
  EdrBehaviorRecord record;
  edr_adaptive_collection_configure(&cfg);
  edr_adaptive_collection_raise(3, "R-EXEC-002", 714u, 713u, "scanner.exe");

  memset(&record, 0, sizeof(record));
  record.type = EDR_EVENT_FILE_WRITE;
  record.pid = 714u;
  record.ppid = 713u;
  snprintf(record.process_name, sizeof(record.process_name), "%s", "scanner.exe");
  memset(record.file_path, 'p', sizeof(record.file_path) - 1u);
  record.file_path[sizeof(record.file_path) - 1u] = '\0';
  assert(edr_adaptive_collection_should_admit_record(&record) == 0);

  snprintf(record.file_path, sizeof(record.file_path), "%s", "/tmp/lossless-interest.txt");
  assert(edr_adaptive_collection_should_admit_record(&record) == 1);
}

static void test_sensor_interest_fails_full_without_verified_p0_binding(void) {
  EdrConfig cfg = adaptive_config(0);
  const char *manifest_path = "sensor_interest_test_manifest.json";
  FILE *f = fopen(manifest_path, "wb");
  assert(f != NULL);
  fputs("{\"interest_version\":\"sensor-interest-test\","
        "\"rules_bundle_version\":\"test\","
        "\"process_names\":[\"powershell.exe\"],"
        "\"full_admission_event_types\":[],"
        "\"file_path_contains\":[\"\\\\appdata\\\\local\\\\temp\\\\\"],"
        "\"registry_path_contains\":[\"\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\"],"
        "\"remote_ports\":[445]}",
        f);
  fclose(f);
  set_env_value("EDR_SENSOR_INTEREST_PATH", manifest_path);
  set_env_value("EDR_SENSOR_INTEREST_ENABLED", "1");
  edr_adaptive_collection_configure(&cfg);
  edr_sensor_interest_reload();

  EdrSensorInterestEvent ordinary =
      event_of(EDR_EVENT_FILE_READ, 4321u, 1234u, "powershell.exe",
               "C:\\Users\\alice\\Documents\\notes.txt");
  /* A hand-written/narrow manifest without a current P0 artifact binding
   * cannot remove telemetry before the matcher. */
  assert(edr_sensor_interest_should_admit(&ordinary) == 1);

  EdrSensorInterestEvent temp_script =
      event_of(EDR_EVENT_FILE_WRITE, 4321u, 1234u, "powershell.exe",
               "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.ps1");
  assert(edr_sensor_interest_should_admit(&temp_script) == 1);
  {
    EdrSensorInterestStatus status;
    edr_sensor_interest_get_status(&status);
    assert(status.full_admission_contract_valid == 0);
    assert(status.p0_binding_valid == 0);
    assert(status.file_read_full_admission == 1);
    assert(status.file_write_full_admission == 1);
    assert(status.registry_set_full_admission == 1);
  }
  remove(manifest_path);
}

static void test_file_regex_requires_full_event_type_admission(void) {
  EdrConfig cfg = adaptive_config(0);
  const char *manifest_path = "sensor_interest_regex_manifest.json";
  FILE *f = fopen(manifest_path, "wb");
  assert(f != NULL);
  fputs("{\"interest_version\":\"sensor-interest-regex\","
        "\"rules_bundle_version\":\"test\","
        "\"full_admission_event_types\":[\"file_read\",\"file_write\",\"registry_set\"]}", f);
  fclose(f);
  set_env_value("EDR_SENSOR_INTEREST_PATH", manifest_path);
  set_env_value("EDR_SENSOR_INTEREST_ENABLED", "1");
  edr_adaptive_collection_configure(&cfg);
  edr_sensor_interest_reload();

  /* These paths deliberately do not occur in the literal-interest lists.
   * Their enabled P0 rules use regex, so collection must retain them for the
   * authoritative IR matcher rather than guessing regex tokens here. */
  EdrSensorInterestEvent login_data =
      event_of(EDR_EVENT_FILE_READ, 4321u, 1234u, "reader.exe",
               "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\Default\\Login Data");
  EdrSensorInterestEvent cloud_credentials =
      event_of(EDR_EVENT_FILE_READ, 4321u, 1234u, "reader.exe",
               "C:\\Users\\alice\\.aws\\credentials");
  EdrSensorInterestEvent webshell =
      event_of(EDR_EVENT_FILE_WRITE, 4321u, 1234u, "w3wp.exe",
               "D:\\arbitrary\\unlisted\\shell.php");
  EdrSensorInterestEvent archive =
      event_of(EDR_EVENT_FILE_WRITE, 4321u, 1234u, "archiver.exe",
               "D:\\arbitrary\\unlisted\\archive.7z");
  EdrSensorInterestEvent registry_value_only =
      event_of(EDR_EVENT_REG_SET_VALUE, 4321u, 1234u, "reg.exe",
               "HKCU\\Unlisted\\Arbitrary\\Path");
  assert(edr_sensor_interest_should_admit(&login_data) == 1);
  assert(edr_sensor_interest_should_admit(&cloud_credentials) == 1);
  assert(edr_sensor_interest_should_admit(&webshell) == 1);
  assert(edr_sensor_interest_should_admit(&archive) == 1);
  assert(edr_sensor_interest_should_admit(&registry_value_only) == 1);
  remove(manifest_path);
}

int main(void) {
  test_adaptive_requires_boosted_process_tree();
  test_adaptive_budget_limits_expansion();
  test_adaptive_record_rejects_unrepresentable_interest_field();
  test_sensor_interest_fails_full_without_verified_p0_binding();
  test_file_regex_requires_full_event_type_admission();
  puts("collection_admission ok");
  return 0;
}
