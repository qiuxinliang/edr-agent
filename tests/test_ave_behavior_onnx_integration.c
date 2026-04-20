/**
 * behavior.onnx 双输出集成测试：需 CMake `-DEDR_WITH_ONNXRUNTIME=ON` 且本机 ORT。
 * 覆盖 (1,64) 与《11》§6.1 (1,128,64) + 展平 8192 与 PidHistory 对齐路径。
 */
#include "ave_onnx_infer.h"
#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_TEST_BEHAVIOR_FIXTURE
#error "EDR_TEST_BEHAVIOR_FIXTURE must be set by CMake for this target"
#endif
#ifndef EDR_TEST_BEHAVIOR_SEQ128_FIXTURE
#error "EDR_TEST_BEHAVIOR_SEQ128_FIXTURE must be set by CMake for this target"
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

static int run_case(const char *src, const char *dst_leaf, size_t want_ne, size_t want_seq) {
  char dst[512];
  snprintf(dst, sizeof(dst), "./%s", dst_leaf);
  if (copy_bin(src, dst) != 0) {
    fprintf(stderr, "copy fixture from %s failed\n", src);
    return 1;
  }
  EdrConfig cfg;
  edr_config_apply_defaults(&cfg);
  cfg.ave.scan_threads = 1;
  if (edr_onnx_behavior_load(dst, &cfg) != EDR_OK) {
    fprintf(stderr, "edr_onnx_behavior_load failed for %s\n", dst_leaf);
    (void)remove(dst);
    return 1;
  }
  if (!edr_onnx_behavior_ready()) {
    fprintf(stderr, "behavior session not ready (%s)\n", dst_leaf);
    edr_onnx_runtime_cleanup();
    (void)remove(dst);
    return 1;
  }
  size_t ne = edr_onnx_behavior_input_nelem();
  size_t seq = edr_onnx_behavior_input_seq_len();
  if (ne != want_ne || seq != want_seq) {
    fprintf(stderr, "%s: nelem=%zu seq=%zu (want %zu %zu)\n", dst_leaf, ne, seq, want_ne, want_seq);
    edr_onnx_runtime_cleanup();
    (void)remove(dst);
    return 1;
  }
  float *feat = (float *)calloc(ne, sizeof(float));
  if (!feat) {
    fprintf(stderr, "calloc feat failed\n");
    edr_onnx_runtime_cleanup();
    (void)remove(dst);
    return 1;
  }
  feat[0] = 1.f;
  float score = 0.f;
  float tactic[14];
  memset(tactic, 0, sizeof(tactic));
  EdrError err = edr_onnx_behavior_infer(feat, ne, &score, tactic);
  free(feat);
  edr_onnx_runtime_cleanup();
  (void)remove(dst);
  if (err != EDR_OK) {
    fprintf(stderr, "edr_onnx_behavior_infer %s -> %d\n", dst_leaf, (int)err);
    return 1;
  }
  if (tactic[0] <= 0.f) {
    fprintf(stderr, "%s: expected positive tactic_probs[0]\n", dst_leaf);
    return 1;
  }
  return 0;
}

int main(void) {
  if (run_case(EDR_TEST_BEHAVIOR_FIXTURE, "behavior_dual_minimal.onnx", 64u, 1u) != 0) {
    return 1;
  }
  if (run_case(EDR_TEST_BEHAVIOR_SEQ128_FIXTURE, "behavior_seq128_dual_minimal.onnx", 128u * 64u, 128u) != 0) {
    return 1;
  }
  return 0;
}
