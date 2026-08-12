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

static void test_lifecycle_maintenance_policy_is_separate_from_dangerous_commands(void) {
  const char *fn = "edr_test_cfg_lifecycle.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[command]\n"
          "allow_dangerous = false\n"
          "allow_lifecycle_maintenance = false\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(!cfg.command.allow_dangerous);
  assert(!cfg.command.allow_lifecycle_maintenance);

  edr_config_apply_defaults(&cfg);
  assert(cfg.command.allow_lifecycle_maintenance);
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

static void test_webshell_roots_parse(void) {
  const char *fn = "edr_test_cfg_webshell_roots.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[webshell_detector]\n"
          "roots = \"C:\\\\inetpub\\\\wwwroot;D:\\\\sites\\\\portal\"\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(strcmp(cfg.webshell_detector.roots,
                "C:\\inetpub\\wwwroot;D:\\sites\\portal") == 0);
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

static void test_control_http2_policy_parse_and_legacy_fallback(void) {
  const char *legacy_fn = "edr_test_cfg_http2_legacy.toml";
  FILE *f = fopen(legacy_fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[platform]\n"
          "http2_enabled = true\n"
          "http2_require = false\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(legacy_fn, &cfg);
  (void)remove(legacy_fn);
  assert(e == EDR_OK);
  assert(cfg.platform.control_http2_enabled);
  assert(!cfg.platform.control_http2_require);
  assert(cfg.platform.control_http1_fallback);

  const char *strict_fn = "edr_test_cfg_http2_strict.toml";
  f = fopen(strict_fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[agent]\nendpoint_id = \"t\"\n\n"
          "[platform]\n"
          "http2_enabled = false\n"
          "control_http2_enabled = false\n"
          "control_http2_require = true\n"
          "control_http1_fallback = true\n");
  fclose(f);
  memset(&cfg, 0, sizeof(cfg));
  e = edr_config_load(strict_fn, &cfg);
  (void)remove(strict_fn);
  assert(e == EDR_OK);
  assert(cfg.platform.control_http2_enabled);
  assert(cfg.platform.control_http2_require);
  assert(!cfg.platform.control_http1_fallback);
}

static void test_legacy_windows_path_escape_compatibility(void) {
  const char *fn = "edr_test_cfg_legacy_windows_paths.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  /* Deliberately emit single backslashes, as older headless packages did. */
  fprintf(f,
          "[server]\n"
          "ca_cert = \"C:\\Program Files\\FDSecurity\\certs\\ca.pem\"\n"
          "client_cert = \"C:\\Program Files\\FDSecurity\\certs\\client.pem\"\n"
          "\n[agent]\nendpoint_id = \"legacy\"\n"
          "\n[platform]\nrest_base_url = \"https://edr.example.test/api/v1\"\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrError e = edr_config_load(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(strcmp(cfg.server.ca_cert, "C:\\Program Files\\FDSecurity\\certs\\ca.pem") == 0);
  assert(strcmp(cfg.server.client_cert, "C:\\Program Files\\FDSecurity\\certs\\client.pem") == 0);
  assert(strcmp(cfg.agent.endpoint_id, "legacy") == 0);
  assert(strcmp(cfg.platform.rest_base_url, "https://edr.example.test/api/v1") == 0);
  edr_config_free_heap(&cfg);
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

static void test_remote_preprocessing_rules_replace_only_rule_section(void) {
  const char *fn = "edr_test_remote_rules.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fprintf(f,
          "[preprocessing]\n"
          "dedup_window_s = 17\n"
          "high_freq_threshold = 29\n"
          "rules_version = \"rules-hot-v2\"\n\n"
          "[[preprocessing.rules]]\n"
          "name = \"drop-reg-delete\"\n"
          "action = \"drop\"\n"
          "event_type = \"REG_DELETE_KEY\"\n");
  fclose(f);

  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  edr_config_apply_defaults(&cfg);
  snprintf(cfg.agent.endpoint_id, sizeof(cfg.agent.endpoint_id), "%s", "ep-preserved");
  EdrError e = edr_config_load_preprocessing_rules(fn, &cfg);
  (void)remove(fn);
  assert(e == EDR_OK);
  assert(strcmp(cfg.agent.endpoint_id, "ep-preserved") == 0);
  assert(strcmp(cfg.preprocessing.rules_version, "rules-hot-v2") == 0);
  assert(cfg.preprocessing.dedup_window_s == 17u);
  assert(cfg.preprocessing.high_freq_threshold == 29u);
  assert(cfg.preprocessing.rules_count == 1u);
  assert(cfg.preprocessing.rules[0].event_type == EDR_EVENT_REG_DELETE_KEY);
  edr_config_free_heap(&cfg);
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
  test_lifecycle_maintenance_policy_is_separate_from_dangerous_commands();
  test_remote_detection_modes_parse();
  test_webshell_roots_parse();
  test_correlation_policy_parse();
  test_policy_v2_and_attack_surface_parse();
  test_control_http2_policy_parse_and_legacy_fallback();
  test_legacy_windows_path_escape_compatibility();
  test_remote_preprocessing_rules_replace_only_rule_section();
  puts("config_fp ok");
  return 0;
}
