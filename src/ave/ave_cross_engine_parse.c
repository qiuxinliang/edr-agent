#include "edr/ave_cross_engine_feed.h"

#include <stdlib.h>
#include <string.h>

static float scan_score_equals(const char *s) {
  if (!s || !s[0]) {
    return 0.f;
  }
  for (const char *p = s; *p; p++) {
    if (strncmp(p, "score=", 6) == 0) {
      char *end = NULL;
      float v = strtof(p + 6, &end);
      (void)end;
      if (v > 1.f) {
        v = 1.f;
      }
      if (v < 0.f) {
        v = 0.f;
      }
      return v;
    }
  }
  return 0.f;
}

float edr_ave_cross_engine_parse_first_score(const char *t1, const char *t2, const char *t3) {
  float v = scan_score_equals(t1);
  if (v > 0.f) {
    return v;
  }
  v = scan_score_equals(t2);
  if (v > 0.f) {
    return v;
  }
  return scan_score_equals(t3);
}

static const char *json_num_after(const char *json, const char *key) {
  if (!json || !key) {
    return NULL;
  }
  const char *p = strstr(json, key);
  if (!p) {
    return NULL;
  }
  return p + strlen(key);
}

float edr_ave_cross_engine_pmfe_snapshot_ave(const char *json) {
  const char *p = json_num_after(json, "\"ave\":");
  if (!p) {
    return 0.f;
  }
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  char *end = NULL;
  float v = strtof(p, &end);
  (void)end;
  if (v < 0.f) {
    v = 0.f;
  }
  if (v > 1.f) {
    v = 1.f;
  }
  return v;
}

static int json_int_field(const char *json, const char *key) {
  const char *p = json_num_after(json, key);
  if (!p) {
    return 0;
  }
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  return (int)strtol(p, NULL, 10);
}

int edr_ave_cross_engine_pmfe_snapshot_pe_hint(const char *json) {
  if (!json || !json[0]) {
    return 0;
  }
  int mz = json_int_field(json, "\"mz\":");
  int stomp = json_int_field(json, "\"stomp\":");
  int elf = json_int_field(json, "\"elf\":");
  return (mz >= 1 || stomp >= 1 || elf >= 1) ? 1 : 0;
}
