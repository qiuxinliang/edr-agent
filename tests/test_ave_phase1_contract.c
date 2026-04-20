/**
 * 第一阶段基线：edr_ave_infer_file 在无会话时的 NOT_IMPL、dry-run OK、edr_ave_file_fingerprint 冒烟。
 * 不依赖 ONNX Runtime 模型文件，适合默认 CI。
 */
#include "edr/ave.h"
#include "edr/config.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void clear_dry_run_env(void) {
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=");
}
static void set_dry_run_env(void) {
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=1");
}
#else
#include <stdlib.h>
static void clear_dry_run_env(void) {
  (void)unsetenv("EDR_AVE_INFER_DRY_RUN");
}
static void set_dry_run_env(void) {
  (void)setenv("EDR_AVE_INFER_DRY_RUN", "1", 1);
}
#endif

static int fail(const char *msg) {
  fprintf(stderr, "test_ave_phase1_contract: %s\n", msg);
  return 1;
}

int main(void) {
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrAveInferResult res;
  memset(&res, 0, sizeof(res));

  clear_dry_run_env();
  EdrError e = edr_ave_infer_file(&cfg, __FILE__, &res);
  if (e != EDR_ERR_NOT_IMPL) {
    return fail("without dry_run and without loaded session, expect EDR_ERR_NOT_IMPL");
  }

  set_dry_run_env();
  memset(&res, 0, sizeof(res));
  e = edr_ave_infer_file(&cfg, __FILE__, &res);
  if (e != EDR_OK) {
    return fail("EDR_AVE_INFER_DRY_RUN=1 should yield EDR_OK");
  }
  if (strncmp(res.detail, "dry_run", 7) != 0) {
    return fail("dry_run detail should start with dry_run");
  }

  char hex[24];
  memset(hex, 0, sizeof(hex));
  if (edr_ave_file_fingerprint(__FILE__, hex, sizeof(hex)) != 0) {
    return fail("edr_ave_file_fingerprint failed");
  }
  if (strlen(hex) < 16u) {
    return fail("fingerprint hex too short");
  }

  return 0;
}
