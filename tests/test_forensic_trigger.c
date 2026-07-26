#include "edr/forensic_trigger.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

static void expect_true(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    g_failures++;
  }
}

static void base_config(EdrForensicAutoConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->enabled = true;
  cfg->cooldown_s = 0;
  cfg->max_per_hour = 10;
  cfg->trigger_on_p0 = true;
  cfg->trigger_on_detection = true;
  cfg->collector_timeout_s = 300;
}

static void base_event(EdrEventSlot *slot, EdrBehaviorRecord *rec) {
  memset(slot, 0, sizeof(*slot));
  memset(rec, 0, sizeof(*rec));
  slot->type = EDR_EVENT_PROCESS_CREATE;
  slot->priority = 1;
  rec->type = EDR_EVENT_PROCESS_CREATE;
  rec->pid = 4321;
  snprintf(rec->process_name, sizeof(rec->process_name), "%s", "regsvr32.exe");
  snprintf(rec->exe_path, sizeof(rec->exe_path), "%s", "C:\\Windows\\System32\\regsvr32.exe");
}

static void test_detection_trigger_enqueues_quick_scope(void) {
  EdrForensicAutoConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord rec;
  EdrForensicTrigger out;

  base_config(&cfg);
  base_event(&slot, &rec);
  edr_forensic_trigger_init(&cfg);
  edr_forensic_trigger_evaluate_detection(&slot, &rec, "lolbin_remote_payload", rec.pid, 1);

  expect_true(edr_forensic_trigger_try_pop(&out), "detection trigger should enqueue forensic work");
  expect_true(out.scope == EDR_FT_SCOPE_QUICK, "detection trigger should use quick scope");
  expect_true(out.target_pid == 4321, "detection trigger should keep target pid");
  expect_true(strstr(out.reason, "lolbin_remote_payload") != NULL, "reason should include detection name");
  edr_forensic_trigger_shutdown();
}

static void test_detection_trigger_can_be_disabled(void) {
  EdrForensicAutoConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord rec;
  EdrForensicTrigger out;

  base_config(&cfg);
  cfg.trigger_on_detection = false;
  base_event(&slot, &rec);
  edr_forensic_trigger_init(&cfg);
  edr_forensic_trigger_evaluate_detection(&slot, &rec, "lolbin_remote_payload", rec.pid, 1);

  expect_true(!edr_forensic_trigger_try_pop(&out), "disabled detection trigger should not enqueue work");
  edr_forensic_trigger_shutdown();
}

static void test_p0_trigger_keeps_full_scope(void) {
  EdrForensicAutoConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord rec;
  EdrForensicTrigger out;

  base_config(&cfg);
  base_event(&slot, &rec);
  slot.priority = 0;
  edr_forensic_trigger_init(&cfg);
  edr_forensic_trigger_evaluate(&slot, &rec);

  expect_true(edr_forensic_trigger_try_pop(&out), "P0 trigger should enqueue forensic work");
  expect_true(out.scope == EDR_FT_SCOPE_FULL, "P0 trigger should keep full scope");
  edr_forensic_trigger_shutdown();
}

int main(void) {
  test_detection_trigger_enqueues_quick_scope();
  test_detection_trigger_can_be_disabled();
  test_p0_trigger_keeps_full_scope();
  return g_failures == 0 ? 0 : 1;
}
