/**
 * 最小化 AVE SDK 自检：AVE_Init / AVE_GetVersion / AVE_ScanFile（首个可选参数为待扫文件）。
 */
#include "edr/ave_sdk.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  AVEConfig cfg = {0};
  cfg.max_concurrent_scans = 2;

  int r = AVE_Init(&cfg);
  if (r != AVE_OK) {
    fprintf(stderr, "AVE_Init failed: %d\n", r);
    return 1;
  }

  printf("AVE_GetVersion: %s\n", AVE_GetVersion());

  if (argc > 1) {
    AVEScanResult res;
    r = AVE_ScanFile(argv[1], &res);
    printf("AVE_ScanFile -> %d final_verdict=%d confidence=%.4f path=%s\n", r, (int)res.final_verdict,
           res.final_confidence, res.scanned_path);
  }

  AVE_Shutdown();
  return 0;
}
