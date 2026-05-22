/**
 * 全流程冒烟：同一进程内加载 model_dir 下 static.onnx + behavior.onnx，
 * 执行 AVE_ScanFile（静态 ONNX）与 edr_onnx_behavior_infer（行为 ONNX）。
 *
 * 用法：
 *   test_ave_e2e_full <model_dir> [file_to_scan]
 * 未传 file 时：POSIX 默认 /bin/ls，Windows 默认 C:\\Windows\\System32\\notepad.exe
 *
 * 需 CMake -DEDR_WITH_ONNXRUNTIME=ON；勿设置 EDR_AVE_INFER_DRY_RUN=1。
 */
#include "ave_onnx_infer.h"
#include "edr/ave_sdk.h"
#include "edr/error.h"

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

int main(int argc, char **argv) {
  clear_infer_dry_run_env();

  const char *model_dir = getenv("EDR_AVE_TEST_MODEL_DIR");
  if (argc > 1 && argv[1][0]) {
    model_dir = argv[1];
  }
  if (!model_dir || !model_dir[0]) {
    fprintf(stderr, "usage: %s <model_dir> [file_to_scan]\n", argv[0] ? argv[0] : "test_ave_e2e_full");
    return 1;
  }

#ifdef _WIN32
  const char *def_scan = "C:\\Windows\\System32\\notepad.exe";
#else
  const char *def_scan = "/bin/ls";
#endif
  const char *scan = def_scan;
  if (argc > 2 && argv[2][0]) {
    scan = argv[2];
  }

  AVEConfig cfg = {0};
  cfg.model_dir = model_dir;
  cfg.max_concurrent_scans = 2;

  if (AVE_Init(&cfg) != AVE_OK) {
    fprintf(stderr, "[e2e] AVE_Init failed\n");
    return 1;
  }

  printf("[e2e] model_dir=%s scan=%s\n", model_dir, scan);

  AVEScanResult res;
  memset(&res, 0, sizeof(res));
  int sr = AVE_ScanFile(scan, &res);
  printf("[e2e] AVE_ScanFile -> %d final_verdict=%d confidence=%.6f path=%s\n", sr, (int)res.final_verdict,
         res.final_confidence, res.scanned_path);

  if (!edr_onnx_behavior_ready()) {
    fprintf(stderr, "[e2e] behavior ONNX not ready (skip behavior infer)\n");
    AVE_Shutdown();
    return sr == AVE_OK ? 0 : 2;
  }

  size_t ne = edr_onnx_behavior_input_nelem();
  float *feat = (float *)calloc(ne, sizeof(float));
  if (!feat) {
    fprintf(stderr, "[e2e] calloc feat failed\n");
    AVE_Shutdown();
    return 1;
  }
  feat[0] = 1.f;

  float score = 0.f;
  float tactic[14];
  memset(tactic, 0, sizeof(tactic));

  EdrError be = edr_onnx_behavior_infer(feat, ne, &score, tactic);
  free(feat);

  printf("[e2e] edr_onnx_behavior_infer -> %d anomaly_score=%.6f tactic[0..2]=%.6f %.6f %.6f\n", (int)be,
         (double)score, (double)tactic[0], (double)tactic[1], (double)tactic[2]);

  AVE_Shutdown();

  if (sr != AVE_OK) {
    return 2;
  }
  if (be != EDR_OK) {
    return 3;
  }
  return 0;
}
