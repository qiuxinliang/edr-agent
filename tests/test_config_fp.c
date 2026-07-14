#include "edr/config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
void edr_win_listen_apply_config(const EdrConfig *cfg) { (void)cfg; }
#endif

static void test_detection_policy_fp_feedback_maps_to_env(void) {
  const char *fn = "edr_test_cfg_detpol.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[detection_policy]\n"
          "source = \"server\"\n"
          "fp_policy_version = \"fp-pol-test-v9\"\n"
          "fp_feedback = \"FDSensorTaskLaunch.ps1,C:\\\\Program Files\\\\FDSecurity\\\\\"\n");
  fclose(f);

#ifdef _WIN32
  _putenv_s("EDR_DETECTION_FP_FEEDBACK", "");
  _putenv_s("EDR_DETECTION_FP_POLICY_VERSION", "");
#else
  unsetenv("EDR_DETECTION_FP_FEEDBACK");
  unsetenv("EDR_DETECTION_FP_POLICY_VERSION");
#endif

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(strstr(cfg.detection_policy.fp_feedback, "FDSensorTaskLaunch.ps1") != NULL);
  const char *env = getenv("EDR_DETECTION_FP_FEEDBACK");
  assert(env != NULL);
  assert(strstr(env, "FDSensorTaskLaunch.ps1") != NULL);
  const char *ver = getenv("EDR_DETECTION_FP_POLICY_VERSION");
  assert(ver != NULL && strcmp(ver, "fp-pol-test-v9") == 0);
}

static void test_command_forensic_yara_rules_dir(void) {
  const char *fn = "edr_test_cfg_yara_dir.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[command]\n"
          "forensic_yara_rules_dir = \"rules/forensic\"\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(strcmp(cfg.command.forensic_yara_rules_dir, "rules/forensic") == 0);
}

static void test_remote_detection_modes_parse(void) {
  const char *fn = "edr_test_cfg_detection.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[detection]\n"
          "auto_profile = false\n"
          "shellcode_mode = 1\n"
          "webshell_mode = -1\n"
          "pmfe_mode = 2\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(!cfg.detection.auto_profile);
  assert(cfg.detection.shellcode_mode == 1);
  assert(cfg.detection.webshell_mode == -1);
  assert(cfg.detection.pmfe_mode == 2);
}

static void test_correlation_policy_parse(void) {
  const char *fn = "edr_test_cfg_correlation.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[correlation]\n"
          "enabled = true\n"
          "inject_feedback_enabled = false\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(cfg.correlation.configured);
  assert(cfg.correlation.enabled);
  assert(!cfg.correlation.inject_feedback_enabled);
}

static void test_policy_v2_and_attack_surface_parse(void) {
  const char *fn = "edr_test_cfg_policy_v2.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[policy_v2]\n"
          "credential_mode = \"observe\"\n"
          "impact_mode = \"block\"\n"
          "ransomware_honey = false\n"
          "ransomware_forensic = false\n\n"
          "[attack_surface]\n"
          "listeners_enabled = false\n"
          "public_service_enabled = true\n"
          "browser_enabled = true\n"
          "software_enabled = true\n"
          "egress_enabled = false\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(cfg.policy_v2.credential_mode == 1);
  assert(cfg.policy_v2.impact_mode == 3);
  assert(!cfg.policy_v2.ransomware_honey);
  assert(!cfg.policy_v2.ransomware_forensic);
  assert(!cfg.attack_surface.listeners_enabled);
  assert(cfg.attack_surface.public_service_enabled);
  assert(cfg.attack_surface.browser_enabled);
  assert(cfg.attack_surface.software_enabled);
  assert(!cfg.attack_surface.egress_enabled);
}

static void test_detection_policy_conditional_suppression(void) {
  const char *fn = "edr_test_cfg_supp.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[detection_policy]\nsource = \"server\"\n\n"
          "[[detection_policy.suppression]]\n"
          "target_rule_id = \"R-LOLBIN-002\"\n"
          "process_name = \"rundll32.exe\"\n"
          "contains_all = [\"davclnt.dll,DavSetCookie\", \"localhost\"]\n"
          "action = \"downgrade\"\n"
          "reason = \"auto_fp_feedback\"\n");
  fclose(f);

#ifdef _WIN32
  _putenv_s("EDR_DETECTION_SUPPRESSION_RULES", "");
#else
  unsetenv("EDR_DETECTION_SUPPRESSION_RULES");
#endif

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  const char *env = getenv("EDR_DETECTION_SUPPRESSION_RULES");
  assert(env != NULL);
  assert(strstr(env, "R-LOLBIN-002") != NULL);
  assert(strstr(env, "rundll32.exe") != NULL);
  assert(strstr(env, "davclnt.dll,DavSetCookie") != NULL);
  assert(strstr(env, "localhost") != NULL);
  assert(strstr(env, "downgrade") != NULL);
}

int main(void) {
  const char *fn = "edr_test_cfg_fp.toml";
  FILE *f = fopen(fn, "wb");
  if (!f) {
    return 1;
  }
  fprintf(f, "[agent]\nendpoint_id = \"t\"\n");
  fclose(f);
  char fp[80];
  edr_config_fingerprint(fn, fp, sizeof(fp));
  (void)remove(fn);
  if (!fp[0]) {
    return 1;
  }
  test_detection_policy_fp_feedback_maps_to_env();
  test_detection_policy_conditional_suppression();
  test_command_forensic_yara_rules_dir();
  test_remote_detection_modes_parse();
  test_correlation_policy_parse();
  test_policy_v2_and_attack_surface_parse();
  puts("config_fp ok");
  return 0;
}
