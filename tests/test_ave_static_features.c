/** 第二阶段：lite 512 维特征 L2 范数（非空文件） */
#include "ave_static_features.h"

#include <math.h>
#include <stdio.h>

int main(void) {
  float v[512];
  if (edr_ave_static_features_lite_512(__FILE__, v) != 0) {
    return 1;
  }
  double s = 0.0;
  for (int i = 0; i < 512; i++) {
    double t = (double)v[i];
    s += t * t;
  }
  if (s < 0.9 || s > 1.1) {
    fprintf(stderr, "expected L2 norm ~1, got %f\n", s);
    return 1;
  }
  return 0;
}
