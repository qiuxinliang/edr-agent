/**
 * 预处理链与 P0 IR 共用的 getenv 辅助（单独 .c，便于 edr_p0_golden_test 等不含 preprocess_pipeline 的目标链接）。
 */
#include <stdlib.h>

#include "edr/preprocess.h"

int edr_getenv_int_default(const char *key, int defv) {
  const char *v = getenv(key);
  if (!v || !v[0]) {
    return defv;
  }
  return atoi(v);
}
