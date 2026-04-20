/**
 * 《11》M3a：64 维特征布局 — §5.1 A 组 one-hot；8–43 为 0；57 is_real_event。
 */
#include "edr/ave_behavior_features.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

static int expect_eq_f(const char *name, float a, float b, float eps) {
  if (fabsf(a - b) > eps) {
    fprintf(stderr, "FAIL: %s expected %f got %f\n", name, (double)b, (double)a);
    return -1;
  }
  return 0;
}

int main(void) {
  float feat[64];
  AVEBehaviorEvent e;
  memset(&e, 0, sizeof(e));
  EdrAveBehaviorFeatExtra ex;
  memset(&ex, 0, sizeof(ex));

  memset(feat, 0, sizeof(feat));
  e.event_type = AVE_EVT_PROCESS_CREATE;
  edr_ave_behavior_encode_m3a(&e, 0u, NULL, feat, 64u);
  if (expect_eq_f("A[0] process_create", feat[0], 1.f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("A[1] zero", feat[1], 0.f, 1e-5f) != 0) {
    return 1;
  }

  memset(feat, 0, sizeof(feat));
  e.event_type = AVE_EVT_NET_DNS;
  edr_ave_behavior_encode_m3a(&e, 0u, NULL, feat, 64u);
  if (expect_eq_f("A[5] net_dns", feat[5], 1.f, 1e-5f) != 0) {
    return 1;
  }

  memset(feat, 0, sizeof(feat));
  e.event_type = AVE_EVT_MEM_ALLOC_EXEC;
  edr_ave_behavior_encode_m3a(&e, 0u, NULL, feat, 64u);
  if (expect_eq_f("MEM_ALLOC_EXEC→inject A[1]", feat[1], 1.f, 1e-5f) != 0) {
    return 1;
  }

  memset(feat, 0, sizeof(feat));
  e.event_type = AVE_EVT_WEBSHELL_SIGNAL;
  edr_ave_behavior_encode_m3a(&e, 0u, NULL, feat, 64u);
  if (expect_eq_f("WEBSHELL→net A[4]", feat[4], 1.f, 1e-5f) != 0) {
    return 1;
  }

  memset(feat, 0xcc, sizeof(feat));
  e.event_type = AVE_EVT_FILE_WRITE;
  e.ave_confidence = 0.5f;
  e.shellcode_score = 0.25f;
  e.behavior_flags = AVE_BEH_DNS_TUNNEL;
  ex.static_max_conf = 0.8f;
  ex.static_verdict_norm = 0.33f;
  edr_ave_behavior_encode_m3a(&e, 3u, &ex, feat, 64u);
  if (expect_eq_f("A[2] file_write", feat[2], 1.f, 1e-5f) != 0) {
    return 1;
  }
  for (size_t k = 8u; k < 44u; k++) {
    if (feat[k] != 0.f) {
      return fail("M3a dims 8-43 must be 0");
    }
  }
  if (expect_eq_f("E[44]", feat[44], 0.8f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("E[45]", feat[45], 0.33f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("E[46] shellcode", feat[46], 0.25f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("E[55] flags/14", feat[55], 1.f / 14.f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("E[57] is_real_event", feat[57], 1.f, 1e-5f) != 0) {
    return 1;
  }
  if (expect_eq_f("E[58] reserved", feat[58], 0.f, 1e-5f) != 0) {
    return 1;
  }

  return 0;
}
