/**
 * 三输出 static ONNX 集成测试：需 CMake `-DEDR_WITH_ONNXRUNTIME=ON` 且本机 ORT。
 * 将 `tests/fixtures/static_triple_minimal.onnx` 拷入当前工作目录后 `edr_ave_init` + `edr_ave_infer_file`。
 */
#include "edr/ave.h"
#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_TEST_FIXTURE_ONNX
#error "EDR_TEST_FIXTURE_ONNX must be set by CMake for this target"
#endif

static int copy_bin(const char *src, const char *dst) {
  FILE *a = fopen(src, "rb");
  FILE *b = fopen(dst, "wb");
  if (!a || !b) {
    if (a) {
      fclose(a);
    }
    if (b) {
      fclose(b);
    }
    return -1;
  }
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), a)) > 0u) {
    if (fwrite(buf, 1, n, b) != n) {
      fclose(a);
      fclose(b);
      return -1;
    }
  }
  fclose(a);
  fclose(b);
  return 0;
}

int main(void) {
#ifdef _WIN32
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=");
#else
  (void)unsetenv("EDR_AVE_INFER_DRY_RUN");
#endif

  static const char k_src[] = EDR_TEST_FIXTURE_ONNX;
  const char *leaf = "static_triple_minimal.onnx";
  char dst[512];
  snprintf(dst, sizeof(dst), "./%s", leaf);
  if (copy_bin(k_src, dst) != 0) {
    fprintf(stderr, "copy fixture from %s failed\n", k_src);
    return 1;
  }

  EdrConfig cfg;
  edr_config_apply_defaults(&cfg);
  snprintf(cfg.ave.model_dir, sizeof(cfg.ave.model_dir), ".");
  cfg.ave.cert_whitelist_enabled = false;

  if (edr_ave_init(&cfg) != EDR_OK) {
    fprintf(stderr, "edr_ave_init failed (ORT missing or load error?)\n");
    (void)remove(dst);
    return 1;
  }

  EdrAveInferResult res;
  memset(&res, 0, sizeof(res));
  EdrError e = edr_ave_infer_file(&cfg, __FILE__, &res);
  edr_ave_shutdown();
  (void)remove(dst);

  if (e != EDR_OK) {
    fprintf(stderr, "edr_ave_infer_file -> %d\n", (int)e);
    return 1;
  }
  if (res.onnx_layout != 1) {
    fprintf(stderr, "expected onnx_layout=1 (triple output), got %d\n", res.onnx_layout);
    return 1;
  }
  return 0;
}
