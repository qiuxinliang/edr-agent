#include "edr/adaptive_collection.h"
#include "edr/config.h"
#include "edr/sensor_interest.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

static void test_sensor_interest_uses_path_not_process_name_for_files(void) {
  EdrConfig cfg = adaptive_config(0);
  const char *manifest_path = "sensor_interest_test_manifest.json";
  FILE *f = fopen(manifest_path, "wb");
  assert(f != NULL);
  fputs("{\"interest_version\":\"sensor-interest-test\","
        "\"rules_bundle_version\":\"test\","
        "\"process_names\":[\"powershell.exe\"],"
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
  assert(edr_sensor_interest_should_admit(&ordinary) == 0);

  EdrSensorInterestEvent temp_script =
      event_of(EDR_EVENT_FILE_WRITE, 4321u, 1234u, "powershell.exe",
               "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.ps1");
  assert(edr_sensor_interest_should_admit(&temp_script) == 1);
  remove(manifest_path);
}

int main(void) {
  test_adaptive_requires_boosted_process_tree();
  test_adaptive_budget_limits_expansion();
  test_sensor_interest_uses_path_not_process_name_for_files();
  puts("collection_admission ok");
  return 0;
}
