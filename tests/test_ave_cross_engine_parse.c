#include "edr/ave_cross_engine_feed.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

static int near_f(float a, float b) { return fabsf(a - b) < 1e-5f; }

int main(void) {
  float x = edr_ave_cross_engine_parse_first_score("x score=0.8123 tail", "", NULL);
  if (!near_f(x, 0.8123f)) {
    fprintf(stderr, "parse score got %f\n", (double)x);
    return 1;
  }
  float y = edr_ave_cross_engine_parse_first_score("", "score=0.5", NULL);
  if (!near_f(y, 0.5f)) {
    fprintf(stderr, "parse score2 got %f\n", (double)y);
    return 2;
  }
  const char *j = "{\"stomp\":0,\"dns\":1,\"mz\":2,\"elf\":0,\"image_hits\":1,\"ave\":0.4412}";
  if (!near_f(edr_ave_cross_engine_pmfe_snapshot_ave(j), 0.4412f)) {
    fprintf(stderr, "json ave fail\n");
    return 3;
  }
  if (edr_ave_cross_engine_pmfe_snapshot_pe_hint(j) != 1) {
    fprintf(stderr, "json pe hint expected 1\n");
    return 4;
  }
  const char *j2 = "{\"stomp\":0,\"dns\":0,\"mz\":0,\"elf\":0,\"ave\":0}";
  if (edr_ave_cross_engine_pmfe_snapshot_pe_hint(j2) != 0) {
    fprintf(stderr, "json pe hint expected 0\n");
    return 5;
  }
  if (edr_ave_cross_engine_pmfe_snapshot_pe_hint(
          "{\"private_exec\":1,\"mz\":1,\"elf\":1,\"stomp\":1}") != 0) {
    fprintf(stderr, "legacy aggregates must not imply same-region image evidence\n");
    return 6;
  }
  puts("ok");
  return 0;
}
