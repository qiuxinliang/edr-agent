/**
 * 《11》§5：behavior.onnx 64 维特征 — M3a（回归占位）/ M3b（§5.2–5.4 + C 组启发式）。
 */
#include "edr/ave_behavior_features.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static int popcount_u32(uint32_t x) {
  int n = 0;
  while (x) {
    n++;
    x &= x - 1u;
  }
  return n;
}

static float clamp01(float x) {
  if (x <= 0.f) {
    return 0.f;
  }
  if (x >= 1.f) {
    return 1.f;
  }
  return x;
}

static int a_slot_for_event_type(AVEEventType et) {
  switch ((int)et) {
  case AVE_EVT_PROCESS_CREATE:
    return 0;
  case AVE_EVT_PROCESS_INJECT:
  case AVE_EVT_MEM_ALLOC_EXEC:
  case AVE_EVT_LSASS_ACCESS:
  case AVE_EVT_AUTH_EVENT:
  case AVE_EVT_SHELLCODE_SIGNAL:
  case AVE_EVT_PMFE_RESULT:
    return 1;
  case AVE_EVT_FILE_WRITE:
    return 2;
  case AVE_EVT_FILE_EXECUTE:
    return 3;
  case AVE_EVT_NET_CONNECT:
    return 4;
  case AVE_EVT_NET_DNS:
    return 5;
  case AVE_EVT_REG_WRITE:
    return 6;
  case AVE_EVT_DLL_LOAD:
    return 7;
  case AVE_EVT_WEBSHELL_SIGNAL:
    return 4;
  default:
    return -1;
  }
}

static void encode_e_group(const AVEBehaviorEvent *e, const EdrAveBehaviorFeatExtra *ex, float *feat, size_t n) {
  if (n > 44u) {
    float c44 = ex ? ex->static_max_conf : e->ave_confidence;
    feat[44] = clamp01(c44);
  }
  if (n > 45u) {
    feat[45] = ex ? ex->static_verdict_norm : 0.f;
  }
  if (n > 46u) {
    feat[46] = clamp01(e->shellcode_score);
  }
  if (n > 47u) {
    feat[47] = clamp01(e->webshell_score);
  }
  if (n > 48u) {
    feat[48] = e->ioc_ip_hit ? 1.f : 0.f;
  }
  if (n > 49u) {
    feat[49] = e->ioc_domain_hit ? 1.f : 0.f;
  }
  if (n > 50u) {
    feat[50] = e->ioc_sha256_hit ? 1.f : 0.f;
  }
  if (n > 51u) {
    feat[51] = ex ? clamp01(ex->parent_static_max_conf) : 0.f;
  }
  if (n > 52u) {
    feat[52] = ex ? clamp01(ex->sibling_anomaly_mean) : 0.f;
  }
  if (n > 53u) {
    feat[53] = clamp01(e->pmfe_confidence);
  }
  if (n > 54u) {
    feat[54] = e->pmfe_pe_found ? 1.f : 0.f;
  }
  if (n > 55u) {
    feat[55] = (float)popcount_u32(e->behavior_flags) / 14.f;
  }
  if (n > 56u) {
    int ev56 = e->cert_revoked_ancestor ? 1 : 0;
    int ex56 = (ex && ex->cert_revoked_ancestor > 0.5f) ? 1 : 0;
    feat[56] = (ev56 || ex56) ? 1.f : 0.f;
  }
  /* 《11》§5.6：维 57 is_real_event。真实事件步=1.0；序列左 PAD 步在 ph_build_ort_input 中全零写入（含本维）。 */
  if (n > 57u) {
    feat[57] = 1.f;
  }
}

static float shannon_entropy_bytes(const char *s, size_t max_len) {
  int cnt[256];
  memset(cnt, 0, sizeof(cnt));
  size_t len = 0;
  for (; s && *s && len < max_len; s++, len++) {
    cnt[(unsigned char)*s]++;
  }
  if (len == 0u) {
    return 0.f;
  }
  float h = 0.f;
  for (int i = 0; i < 256; i++) {
    if (cnt[i] == 0) {
      continue;
    }
    float pi = (float)cnt[i] / (float)len;
    h -= pi * logf(pi + 1e-30f) / logf(2.f);
  }
  return h;
}

static int str_has_ci(const char *hay, const char *needle) {
  if (!hay || !needle) {
    return 0;
  }
  while (*hay) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
    hay++;
  }
  return 0;
}

static int path_looks_system(const char *p) {
  if (!p || !p[0]) {
    return 0;
  }
  return str_has_ci(p, "\\windows\\") || str_has_ci(p, "/system/") || str_has_ci(p, "system32");
}

static int path_looks_temp(const char *p) {
  if (!p || !p[0]) {
    return 0;
  }
  return str_has_ci(p, "\\temp\\") || str_has_ci(p, "/tmp/") || str_has_ci(p, "appdata\\local\\temp");
}

static int path_looks_unc(const char *p) {
  return p && ((p[0] == '\\' && p[1] == '\\') || (p[0] == '/' && p[1] == '/'));
}

static float file_ext_risk_heuristic(const char *path) {
  if (!path || !path[0]) {
    return 0.f;
  }
  const char *dot = strrchr(path, '.');
  if (!dot) {
    return 0.f;
  }
  char ext[16];
  size_t i = 0;
  for (const char *q = dot + 1; *q && i + 1u < sizeof(ext); q++) {
    ext[i++] = (char)tolower((unsigned char)*q);
  }
  ext[i] = '\0';
  if (strcmp(ext, "exe") == 0 || strcmp(ext, "ps1") == 0 || strcmp(ext, "bat") == 0 || strcmp(ext, "cmd") == 0) {
    return 1.f;
  }
  if (strcmp(ext, "dll") == 0) {
    return 0.5f;
  }
  return 0.f;
}

static int parse_ipv4_octets(const char *s, unsigned *o0, unsigned *o1, unsigned *o2, unsigned *o3) {
  if (!s) {
    return -1;
  }
  unsigned a, b, c, d;
  int n = 0;
  if (sscanf(s, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n) != 4) {
    return -1;
  }
  if (a > 255u || b > 255u || c > 255u || d > 255u) {
    return -1;
  }
  *o0 = a;
  *o1 = b;
  *o2 = c;
  *o3 = d;
  return 0;
}

static float ip_is_public_flag(const char *ip) {
  unsigned a, b, c, d;
  if (parse_ipv4_octets(ip, &a, &b, &c, &d) != 0) {
    return 0.f;
  }
  if (a == 127u || a == 0u) {
    return 0.f;
  }
  if (a == 10u) {
    return 0.f;
  }
  if (a == 172u && b >= 16u && b <= 31u) {
    return 0.f;
  }
  if (a == 192u && b == 168u) {
    return 0.f;
  }
  return 1.f;
}

static float port_risk_heuristic(uint16_t port) {
  if (port == 445u || port == 3389u || port == 135u) {
    return 0.9f;
  }
  if (port == 80u || port == 443u || port == 53u) {
    return 0.2f;
  }
  if (port == 0u) {
    return 0.f;
  }
  return 0.5f;
}

static float reg_key_risk_heuristic(const char *path) {
  if (!path || !path[0]) {
    return 0.f;
  }
  if (str_has_ci(path, "currentversion\\run") || str_has_ci(path, "\\run\\")) {
    return 0.9f;
  }
  return 0.3f;
}

static void wall_sin_cos_from_ns(int64_t ns, float *sin_h, float *cos_h) {
  time_t sec = (time_t)(ns / 1000000000LL);
  struct tm tmb;
  memset(&tmb, 0, sizeof(tmb));
#ifdef _WIN32
  if (localtime_s(&tmb, &sec) != 0) {
    *sin_h = 0.f;
    *cos_h = 1.f;
    return;
  }
#else
  if (localtime_r(&sec, &tmb) == NULL) {
    *sin_h = 0.f;
    *cos_h = 1.f;
    return;
  }
#endif
  float hour = (float)tmb.tm_hour + (float)tmb.tm_min / 60.f + (float)tmb.tm_sec / 3600.f;
  float ang = (float)(2.0 * M_PI) * hour / 24.f;
  *sin_h = sinf(ang);
  *cos_h = cosf(ang);
}

static void encode_c_group(const AVEBehaviorEvent *e, float *feat, size_t n) {
  if (n <= 24u) {
    return;
  }
  int path_evt = (e->event_type == AVE_EVT_FILE_WRITE || e->event_type == AVE_EVT_FILE_EXECUTE ||
                  e->event_type == AVE_EVT_DLL_LOAD);
  int net_evt = (e->event_type == AVE_EVT_NET_CONNECT);
  int dns_evt = (e->event_type == AVE_EVT_NET_DNS);
  int reg_evt = (e->event_type == AVE_EVT_REG_WRITE);

  float pe = shannon_entropy_bytes(e->target_path, 512u);
  if (path_evt && pe > 0.f) {
    feat[24] = clamp01(pe / 16.f);
  } else {
    feat[24] = 0.f;
  }
  if (path_evt) {
    feat[25] = path_looks_system(e->target_path) ? 1.f : 0.f;
    feat[26] = path_looks_temp(e->target_path) ? 1.f : 0.f;
    feat[27] = path_looks_unc(e->target_path) ? 1.f : 0.f;
    feat[28] = file_ext_risk_heuristic(e->target_path);
    feat[35] = e->target_has_motw ? 1.f : 0.f;
  } else {
    feat[25] = feat[26] = feat[27] = feat[28] = feat[35] = 0.f;
  }
  if (net_evt) {
    feat[29] = ip_is_public_flag(e->target_ip);
    feat[30] = feat[29] > 0.5f ? 0.6f : 0.1f;
    feat[31] = port_risk_heuristic(e->target_port);
  } else {
    feat[29] = feat[30] = feat[31] = 0.f;
  }
  if (reg_evt) {
    feat[32] = reg_key_risk_heuristic(e->target_path);
  } else {
    feat[32] = 0.f;
  }
  if (dns_evt) {
    float de = shannon_entropy_bytes(e->target_domain, 256u);
    feat[33] = clamp01(de / 8.f);
    feat[34] = e->ioc_domain_hit ? 1.f : 0.f;
  } else {
    feat[33] = feat[34] = 0.f;
  }
}

void edr_ave_behavior_encode_m3a(const AVEBehaviorEvent *e, uint32_t event_count_before,
                                 const EdrAveBehaviorFeatExtra *ex, float *feat, size_t n) {
  (void)event_count_before;
  if (!feat || n == 0u || !e) {
    return;
  }
  memset(feat, 0, n * sizeof(float));

  int slot = a_slot_for_event_type(e->event_type);
  if (slot >= 0 && (size_t)slot < n) {
    feat[slot] = 1.f;
  }

  encode_e_group(e, ex, feat, n);
}

/**
 * 《11》§5.2 **B(8–23)**、§5.3 **C**（`encode_c_group` 24–35）、§5.4 **D(36–43)**。
 * 变更须同步 **`scripts/behavior_encode_m3b.py`** 与 **`test_ave_behavior_features_m3b`**。
 */
void edr_ave_behavior_encode_m3b(const AVEBehaviorEvent *e, const EdrAveBehaviorFeatExtra *ex,
                                 const EdrAveBehaviorPidSnapshot *snap, float *feat, size_t n) {
  if (!feat || n == 0u || !e || !snap) {
    return;
  }
  memset(feat, 0, n * sizeof(float));

  int slot = a_slot_for_event_type(e->event_type);
  if (slot >= 0 && (size_t)slot < n) {
    feat[slot] = 1.f;
  }

  if (n > 8u) {
    float t = (float)snap->total_events_incl_current / 1000.f;
    feat[8] = clamp01(t);
  }
  if (n > 9u) {
    feat[9] = clamp01((float)snap->file_write_count / 100.f);
  }
  if (n > 10u) {
    feat[10] = clamp01((float)snap->net_connect_count / 100.f);
  }
  if (n > 11u) {
    feat[11] = clamp01((float)snap->reg_write_count / 100.f);
  }
  if (n > 12u) {
    feat[12] = clamp01((float)snap->dll_load_count / 50.f);
  }
  if (n > 13u) {
    feat[13] = snap->has_injected_memory;
  }
  if (n > 14u) {
    feat[14] = snap->has_accessed_lsass;
  }
  if (n > 15u) {
    feat[15] = snap->has_loaded_suspicious_dll;
  }
  if (n > 16u) {
    feat[16] = snap->has_ioc_connection;
  }
  if (n > 17u) {
    float c17 = ex ? ex->static_max_conf : e->ave_confidence;
    feat[17] = clamp01(c17);
  }
  if (n > 18u) {
    feat[18] = ex ? ex->static_verdict_norm : 0.f;
  }
  if (n > 19u) {
    feat[19] = clamp01(snap->parent_chain_depth_norm);
  }
  if (n > 20u) {
    feat[20] = snap->is_system_account;
  }
  if (n > 21u) {
    feat[21] = clamp01(snap->time_since_birth_norm);
  }
  if (n > 22u) {
    feat[22] = clamp01((float)snap->unique_ip_count / 20.f);
  }
  if (n > 23u) {
    feat[23] = snap->is_high_value_host;
  }

  encode_c_group(e, feat, n);

  if (n > 36u) {
    double gap_ms = 0.0;
    if (snap->prev_event_ns > 0 && snap->now_ns > snap->prev_event_ns) {
      gap_ms = (double)(snap->now_ns - snap->prev_event_ns) / 1e6;
    }
    double g = log10(gap_ms + 1.0) / 6.0;
    if (g > 1.0) {
      g = 1.0;
    }
    if (g < 0.0) {
      g = 0.0;
    }
    feat[36] = (float)g;
  }
  if (n > 37u) {
    feat[37] = clamp01((float)snap->burst_1s_count / 100.f);
  }
  if (n > 38u) {
    float s, c;
    wall_sin_cos_from_ns(snap->now_ns, &s, &c);
    feat[38] = s;
    feat[39] = c;
  }
  if (n > 40u) {
    feat[40] = clamp01((float)snap->events_last_1min / 100.f);
  }
  if (n > 41u) {
    feat[41] = clamp01((float)snap->events_last_5min / 100.f);
  }
  if (n > 42u) {
    feat[42] = snap->is_first_event_of_proc ? 1.f : 0.f;
  }
  if (n > 43u) {
    feat[43] = clamp01((float)snap->events_after_net_connect / 10.f);
  }

  encode_e_group(e, ex, feat, n);
}
