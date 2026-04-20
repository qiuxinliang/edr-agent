#include "edr/ave.h"
#include "edr/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
static void set_dry_default(void) {
  if (getenv("EDR_AVE_INFER_DRY_RUN")) {
    return;
  }
  (void)_putenv("EDR_AVE_INFER_DRY_RUN=1");
}
#else
static void set_dry_default(void) {
  if (getenv("EDR_AVE_INFER_DRY_RUN")) {
    return;
  }
  (void)setenv("EDR_AVE_INFER_DRY_RUN", "1", 1);
}
#endif

int main(void) {
  set_dry_default();
  EdrConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  EdrAveInferResult res;
  memset(&res, 0, sizeof(res));
  EdrError e = edr_ave_infer_file(&cfg, __FILE__, &res);
  if (e != EDR_OK) {
    return 1;
  }
  return res.detail[0] ? 0 : 1;
}
