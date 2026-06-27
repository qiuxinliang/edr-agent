#include "edr/config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  puts("config_fp ok");
  return 0;
}
