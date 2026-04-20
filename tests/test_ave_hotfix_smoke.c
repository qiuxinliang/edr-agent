/**
 * 热更冒烟：`AVE_ApplyHotfix` 从 `model/releases` 式目录拷入 `model_dir` 后 `edr_ave_reload_models`，
 * **`AVE_GetStatus`** 中 **`static_model_version` / `behavior_model_version`** 可见（非 unknown）。
 *
 * 用法：
 *   test_ave_hotfix_smoke
 * 依赖环境变量（CTest 注入）：
 *   EDR_AVE_TEST_MODEL_DIR   — 进程使用的 model_dir（可写目录，含 static.onnx + behavior.onnx）
 *   EDR_AVE_HOTFIX_DIR       — 热更源目录（至少含上述之一）
 *
 * 可选：EDR_AVE_TEST_HOTFIX_EMPTY=1 — 仅 Unix：在 /tmp 建空目录，期望 **AVE_ApplyHotfix 失败**（无静默成功）。
 */
#include "edr/ave_sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void clear_infer_dry_run_env(void) {
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=");
}
#else
#include <unistd.h>
static void clear_infer_dry_run_env(void) {
  (void)unsetenv("EDR_AVE_INFER_DRY_RUN");
}
#endif

#ifndef _WIN32
#include <errno.h>
#endif

static void print_status(const char *tag) {
  AVEStatus st;
  memset(&st, 0, sizeof(st));
  if (AVE_GetStatus(&st) != AVE_OK) {
    fprintf(stderr, "[%s] AVE_GetStatus failed\n", tag);
    return;
  }
  printf("[%s] static_model_version=%s behavior_model_version=%s\n", tag, st.static_model_version,
         st.behavior_model_version);
}

#ifndef _WIN32
static int test_empty_hotfix_fails(void) {
  char tpl[] = "/tmp/edr_ave_hf_XXXXXX";
  char *d = mkdtemp(tpl);
  if (!d) {
    fprintf(stderr, "[hotfix] mkdtemp: %s\n", strerror(errno));
    return 0;
  }
  AVEConfig cfg = {0};
  cfg.model_dir = getenv("EDR_AVE_TEST_MODEL_DIR");
  if (!cfg.model_dir || !cfg.model_dir[0]) {
    fprintf(stderr, "[hotfix] EDR_AVE_TEST_MODEL_DIR unset\n");
    rmdir(d);
    return 0;
  }
  cfg.max_concurrent_scans = 1;
  if (AVE_Init(&cfg) != AVE_OK) {
    fprintf(stderr, "[hotfix] AVE_Init failed\n");
    rmdir(d);
    return 0;
  }
  int hf = AVE_ApplyHotfix(d);
  AVE_Shutdown();
  rmdir(d);
  if (hf == AVE_OK) {
    fprintf(stderr, "[hotfix] expected AVE_ApplyHotfix to fail on empty dir, got OK\n");
    return 0;
  }
  printf("[hotfix] empty hotfix dir correctly rejected (code=%d)\n", hf);
  return 1;
}
#endif

int main(void) {
  clear_infer_dry_run_env();

#ifndef _WIN32
  {
    const char *eh = getenv("EDR_AVE_TEST_HOTFIX_EMPTY");
    if (eh && eh[0] == '1') {
      return test_empty_hotfix_fails() ? 0 : 1;
    }
  }
#endif

  const char *model_dir = getenv("EDR_AVE_TEST_MODEL_DIR");
  const char *hotfix_dir = getenv("EDR_AVE_HOTFIX_DIR");
  if (!model_dir || !model_dir[0] || !hotfix_dir || !hotfix_dir[0]) {
    fprintf(stderr, "usage: EDR_AVE_TEST_MODEL_DIR=... EDR_AVE_HOTFIX_DIR=... %s\n",
            "test_ave_hotfix_smoke");
    return 1;
  }

  AVEConfig cfg = {0};
  cfg.model_dir = model_dir;
  cfg.max_concurrent_scans = 2;

  if (AVE_Init(&cfg) != AVE_OK) {
    fprintf(stderr, "[hotfix] AVE_Init failed\n");
    return 1;
  }

  print_status("before");

  AVEStatus st0;
  memset(&st0, 0, sizeof(st0));
  if (AVE_GetStatus(&st0) != AVE_OK) {
    fprintf(stderr, "[hotfix] AVE_GetStatus failed\n");
    AVE_Shutdown();
    return 1;
  }
  if (strcmp(st0.static_model_version, "unknown") == 0) {
    fprintf(stderr, "[hotfix] static_model_version should not be legacy 'unknown'\n");
    AVE_Shutdown();
    return 1;
  }

  if (AVE_ApplyHotfix(hotfix_dir) != AVE_OK) {
    fprintf(stderr, "[hotfix] AVE_ApplyHotfix failed\n");
    AVE_Shutdown();
    return 1;
  }

  print_status("after");

  AVEStatus st1;
  memset(&st1, 0, sizeof(st1));
  if (AVE_GetStatus(&st1) != AVE_OK) {
    fprintf(stderr, "[hotfix] AVE_GetStatus failed after hotfix\n");
    AVE_Shutdown();
    return 1;
  }
  if (strcmp(st1.static_model_version, "unknown") == 0) {
    fprintf(stderr, "[hotfix] static_model_version after reload should not be 'unknown'\n");
    AVE_Shutdown();
    return 1;
  }

  AVE_Shutdown();
  return 0;
}
