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
          "contains_none = [\"remote.example\", \"credentials\"]\n"
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
  assert(strcmp(env, "R-LOLBIN-002\037rundll32.exe\037downgrade\037auto_fp_feedback\037"
                     "davclnt.dll,DavSetCookie\035localhost\037remote.example\035credentials") == 0);
}

static void test_detection_policy_rejects_partial_counterexamples(void) {
  const char *fn = "edr_test_cfg_supp_invalid.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fputs("[agent]\nendpoint_id = \"t\"\n[detection_policy]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"valid.exe\"\n"
        "contains_all = [\"valid.ps1\"]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"oversized.exe\"\n"
        "contains_all = [\"benign.ps1\"]\ncontains_none = [\"", f);
  for (int i = 0; i < 300; i++) fputc('x', f);
  fputs("\"]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"invalid.exe\"\n"
        "contains_all = [\"benign.ps1\"]\ncontains_none = [\"forbidden\", 7]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"control.exe\"\n"
        "contains_none = [\"bad\\tvalue\"]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"buffer.exe\"\ncontains_all = [", f);
  for (int token = 0; token < 40; token++) {
    if (token) fputc(',', f);
    fputc('"', f);
    for (int i = 0; i < 240; i++) fputc('x', f);
    fputc('"', f);
  }
  fputs("]\ncontains_none = [\"forbidden\"]\n"
        "[[detection_policy.suppression]]\nprocess_name = \"last.exe\"\ncontains_all = [\"last.ps1\"]\n", f);
  fclose(f);
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  assert(edr_config_load(fn, &cfg) == EDR_OK);
  remove(fn);
  assert(strcmp(cfg.detection_policy.suppression_rules,
                "\037valid.exe\037downgrade\037\037valid.ps1\036"
                "\037last.exe\037downgrade\037\037last.ps1") == 0);
  edr_config_free_heap(&cfg);
}

static void test_detection_policy_empty_server_rules_revoke_previous(void) {
  const char *fn = "edr_test_cfg_supp_revoke.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fputs("[agent]\nendpoint_id = \"t\"\n[detection_policy]\nsource = \"server\"\n", f);
  fclose(f);
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  assert(getenv("EDR_DETECTION_SUPPRESSION_RULES") && getenv("EDR_DETECTION_SUPPRESSION_RULES")[0]);
#ifdef _WIN32
  _putenv_s("EDR_DETECTION_FP_FEEDBACK", "stale-flat-feedback.exe");
#else
  setenv("EDR_DETECTION_FP_FEEDBACK", "stale-flat-feedback.exe", 1);
#endif
  assert(edr_config_load(fn, &cfg) == EDR_OK);
  remove(fn);
  const char *rules = getenv("EDR_DETECTION_SUPPRESSION_RULES");
  assert(!rules || !rules[0]);
  const char *feedback = getenv("EDR_DETECTION_FP_FEEDBACK");
  assert(!feedback || !feedback[0]);
  edr_config_free_heap(&cfg);
}

static void test_detection_policy_local_manual_feedback_remains(void) {
  const char *fn = "edr_test_cfg_local_feedback.toml";
  FILE *f = fopen(fn, "wb");
  assert(f != NULL);
  fputs("[agent]\nendpoint_id = \"t\"\n", f);
  fclose(f);
#ifdef _WIN32
  _putenv_s("EDR_DETECTION_FP_FEEDBACK", "manual-local.exe");
#else
  setenv("EDR_DETECTION_FP_FEEDBACK", "manual-local.exe", 1);
#endif
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  assert(edr_config_load(fn, &cfg) == EDR_OK);
  remove(fn);
  assert(strcmp(getenv("EDR_DETECTION_FP_FEEDBACK"), "manual-local.exe") == 0);
  edr_config_free_heap(&cfg);
#ifdef _WIN32
  _putenv_s("EDR_DETECTION_FP_FEEDBACK", "");
#else
  unsetenv("EDR_DETECTION_FP_FEEDBACK");
#endif
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


static void test_effective_policy_survives_restart_and_recovery(void) {
  const char *primary = "edr_test_policy_primary.toml";
  const char *lkg = "edr_test_policy_lkg.toml";
  EdrConfig live = {0}, loaded = {0};
  char before[80], after[80];
  FILE *f = fopen(primary, "wb");
  assert(f);
  fputs("[server]\nclient_key_provider = 'cert_store'\nclient_cert_store = 'LocalMachine/My'\n"
        "client_cert_thumbprint = 'test-thumbprint'\n"
        "[config_signing]\nsignature_required = true\nsigning_key_id = 'test-key'\n"
        "public_key_pem = 'test-public-key'\n"
        "[platform]\nrest_bearer_token = 'on-disk-test-token'\n"
        "[platform.request_signing]\nenabled = true\nkey_id = 'request-key'\nsecret = 'on-disk-test-secret'\n"
        "[offline]\nretention_hours = 37\nevidence_cache_retention_hours = 19\n"
        "[event_filter]\nenabled = true\nlow_value_file_process = false\n"
        "[command.rtr_shell]\nallowlist = ['old-command']\nmax_timeout_sec = 40\n"
        "[upload]\nbatch_max_events = 123\n"
        "[future_extension]\nvalue = { items = [1, 2], child = { active = true } }\n"
        "[[preprocessing.rules]]\nevent_type = 'PROCESS_CREATE'\naction = 'emit_always'\n", f);
  assert(fclose(f) == 0);
  assert(edr_config_load(primary, &live) == EDR_OK);
  live.upload.batch_max_events = 456;
  live.event_filter.low_value_file_process = true;
  snprintf(live.command.rtr_shell_allowlist, sizeof(live.command.rtr_shell_allowlist), "new-command");
  live.command.rtr_shell_max_timeout_sec = 55;
  /* An in-memory/env credential must never be introduced into the snapshot. */
  snprintf(live.platform.rest_bearer_token, sizeof(live.platform.rest_bearer_token), "runtime-only-token");
  snprintf(live.platform.request_signing.secret, sizeof(live.platform.request_signing.secret), "runtime-only-secret");
  snprintf(live.applied_remote_policy.version, sizeof(live.applied_remote_policy.version), "policy-42");
  snprintf(live.applied_remote_policy.hash, sizeof(live.applied_remote_policy.hash), "test-hash");
  live.applied_remote_policy.sequence = 42;
  assert(edr_config_save_effective_policy(primary, primary, &live) == 0);
  assert(edr_config_atomic_copy(primary, lkg) == 0);
  assert(edr_config_load(primary, &loaded) == EDR_OK);
  assert(loaded.upload.batch_max_events == 456);
  assert(loaded.event_filter.low_value_file_process);
  assert(loaded.offline.retention_hours == 37);
  assert(loaded.offline.evidence_cache_retention_hours == 19);
  assert(loaded.config_signing.signature_required);
#ifdef _WIN32
  _putenv_s("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED", "0");
#else
  setenv("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED", "0", 1);
#endif
  assert(edr_config_signature_required(&loaded));
  loaded.config_signing.signature_required = false;
#ifdef _WIN32
  _putenv_s("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED", "1");
#else
  setenv("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED", "1", 1);
#endif
  assert(edr_config_signature_required(&loaded));
  loaded.config_signing.signature_required = true;
#ifdef _WIN32
  _putenv_s("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED", "");
#else
  unsetenv("EDR_AGENT_CONFIG_SIGNATURE_REQUIRED");
#endif
  assert(!strcmp(loaded.config_signing.public_key_pem, "test-public-key"));
  assert(!strcmp(loaded.server.client_cert_store, "LocalMachine/My"));
  assert(!strcmp(loaded.server.client_cert_thumbprint, "test-thumbprint"));
  assert(loaded.platform.request_signing.enabled);
  assert(!strcmp(loaded.platform.request_signing.secret, "on-disk-test-secret"));
  assert(!strcmp(loaded.platform.rest_bearer_token, "on-disk-test-token"));
  assert(!strcmp(loaded.command.rtr_shell_allowlist, "new-command"));
  assert(loaded.command.rtr_shell_max_timeout_sec == 55);
  assert(loaded.preprocessing.rules_count == live.preprocessing.rules_count);
  assert(loaded.applied_remote_policy.sequence == 42);
  assert(!strcmp(loaded.applied_remote_policy.version, "policy-42"));
  /* Repeated saves and unknown nested values must remain parseable. */
  assert(edr_config_save_effective_policy(primary, primary, &loaded) == 0);
  edr_config_fingerprint(primary, before, sizeof(before));
  assert(edr_config_save_effective_policy("missing-policy-source", primary, &loaded) != 0);
  edr_config_fingerprint(primary, after, sizeof(after));
  assert(!strcmp(before, after));
  f = fopen(primary, "wb"); assert(f); fputs("[broken", f); fclose(f);
  assert(edr_config_load(primary, &loaded) != EDR_OK);
  assert(edr_config_load(lkg, &loaded) == EDR_OK);
  assert(loaded.upload.batch_max_events == 456);
  assert(loaded.config_signing.signature_required);
  assert(loaded.platform.request_signing.enabled);
  assert(loaded.offline.retention_hours == 37);
  assert(loaded.applied_remote_policy.sequence == 42);
  /* Long, escaped strings must not be truncated by the old 2048-byte buffer. */
  memset(loaded.command.signing_public_key_pem, 'a', sizeof(loaded.command.signing_public_key_pem) - 1);
  loaded.command.signing_public_key_pem[3] = '\n';
  loaded.command.signing_public_key_pem[4] = '"';
  assert(edr_config_save_effective_policy(lkg, primary, &loaded) == 0);
  assert(edr_config_load(primary, &live) == EDR_OK);
  assert(!strcmp(live.command.signing_public_key_pem, loaded.command.signing_public_key_pem));
  edr_config_free_heap(&live);
  edr_config_free_heap(&loaded);
  remove(primary); remove(lkg);
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
  test_effective_policy_survives_restart_and_recovery();
  test_detection_policy_fp_feedback_maps_to_env();
  test_detection_policy_conditional_suppression();
  test_detection_policy_rejects_partial_counterexamples();
  test_detection_policy_empty_server_rules_revoke_previous();
  test_detection_policy_local_manual_feedback_remains();
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
