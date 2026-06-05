#include "edr/behavior_record.h"
#include "edr/dedup.h"
#include "edr/emit_rules.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int edr_emit_rules_evaluate(const EdrBehaviorRecord *r) {
  (void)r;
  return -1;
}

static void init_script(EdrBehaviorRecord *r, uint32_t pid, int64_t ts_ns,
                        const char *snippet) {
  edr_behavior_record_init(r);
  r->type = EDR_EVENT_SCRIPT_POWERSHELL;
  r->priority = 1u;
  r->pid = pid;
  r->event_time_ns = ts_ns;
  snprintf(r->process_name, sizeof(r->process_name), "%s", "powershell.exe");
  snprintf(r->script_snippet, sizeof(r->script_snippet), "%s", snippet ? snippet : "");
}

static void test_scriptblock_duplicate_is_coalesced(void) {
  EdrBehaviorRecord r;
  uint64_t dedup_drops = 0u;
  uint64_t rate_drops = 0u;
  edr_dedup_configure(30u, 1000u);
  edr_dedup_reset();

  init_script(&r, 1234u, 1000000000LL,
              "sensor=scriptblock provider=Microsoft-Windows-PowerShell");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s",
           "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert(edr_preprocess_should_emit(&r) == 1);

  init_script(&r, 1234u, 1001000000LL,
              "sensor=scriptblock provider=Microsoft-Windows-PowerShell");
  snprintf(r.exe_path, sizeof(r.exe_path), "%s",
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  snprintf(r.cmdline, sizeof(r.cmdline), "%s", "powershell.exe -NoProfile");
  assert(edr_preprocess_should_emit(&r) == 0);

  edr_dedup_get_stats(&dedup_drops, &rate_drops);
  assert(dedup_drops == 1u);
  assert(rate_drops == 0u);
}

static void test_distinct_scriptblock_id_is_kept(void) {
  EdrBehaviorRecord r;
  edr_dedup_configure(30u, 1000u);
  edr_dedup_reset();

  init_script(&r, 2222u, 2000000000LL,
              "sensor=scriptblock provider=Microsoft-Windows-PowerShell scriptblock_id=aaa");
  assert(edr_preprocess_should_emit(&r) == 1);

  init_script(&r, 2222u, 2001000000LL,
              "sensor=scriptblock provider=Microsoft-Windows-PowerShell scriptblock_id=bbb");
  assert(edr_preprocess_should_emit(&r) == 1);
}

static void test_priority_zero_bypasses_script_sensor_coalesce(void) {
  EdrBehaviorRecord r;
  edr_dedup_configure(30u, 1000u);
  edr_dedup_reset();

  init_script(&r, 3333u, 3000000000LL,
              "sensor=amsi provider=Microsoft-Antimalware-Scan-Interface amsi_session=1");
  r.priority = 0u;
  assert(edr_preprocess_should_emit(&r) == 1);

  init_script(&r, 3333u, 3001000000LL,
              "sensor=amsi provider=Microsoft-Antimalware-Scan-Interface amsi_session=1");
  r.priority = 0u;
  assert(edr_preprocess_should_emit(&r) == 1);
}

int main(void) {
  test_scriptblock_duplicate_is_coalesced();
  test_distinct_scriptblock_id_is_kept();
  test_priority_zero_bypasses_script_sensor_coalesce();
  puts("preprocess_dedup ok");
  return 0;
}
