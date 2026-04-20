#include "edr/fl_trainer.h"

#include <string.h>

int main(void) {
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.fl.enabled = true;
  cfg.fl.min_new_samples = 100;
  cfg.fl.idle_cpu_threshold = 0.3f;
  if (FLT_InitFromEdrConfig(&cfg) != FLT_OK) {
    return 1;
  }
  if (FLT_Start() != FLT_OK) {
    FLT_Shutdown();
    return 2;
  }
  FLT_Shutdown();
  return 0;
}
