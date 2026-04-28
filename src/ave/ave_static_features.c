#include "ave_static_features.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EDR_AVE_STATIC_READ_MAX
#  define EDR_AVE_STATIC_READ_MAX (4u * 1024u * 1024u)
#endif

static size_t env_read_max(void) {
  const char *e = getenv("EDR_AVE_STATIC_READ_MAX");
  if (e && e[0]) {
    char *end = NULL;
    unsigned long v = strtoul(e, &end, 10);
    if (end != e && v >= 4096ul && v <= 64ul * 1024ul * 1024ul) {
      return (size_t)v;
    }
  }
  return (size_t)EDR_AVE_STATIC_READ_MAX;
}

static float shannon_entropy(const uint8_t *p, size_t len) {
  if (len == 0u || !p) {
    return 0.f;
  }
  unsigned cnt[256];
  memset(cnt, 0, sizeof(cnt));
  for (size_t i = 0; i < len; i++) {
    cnt[p[i]]++;
  }
  float h = 0.f;
  float inv = 1.0f / (float)len;
  for (int i = 0; i < 256; i++) {
    if (cnt[i] == 0u) {
      continue;
    }
    float p_i = (float)cnt[i] * inv;
    h -= p_i * logf(p_i + 1e-30f) / 0.69314718f;
  }
  return h;
}

static void l2_normalize_512(float *v) {
  double s = 0.0;
  for (int i = 0; i < 512; i++) {
    double t = (double)v[i];
    s += t * t;
  }
  if (s <= 1e-30) {
    return;
  }
  float inv = (float)(1.0 / sqrt(s));
  for (int i = 0; i < 512; i++) {
    v[i] *= inv;
  }
}

static int env_smart_read_enabled(void) {
  const char *e = getenv("EDR_AVE_STATIC_READ_SMART");
  if (e && (e[0] == '1' || e[0] == 'y' || e[0] == 'Y')) {
    return 1;
  }
  return 1;  // 默认启用
}

int edr_ave_static_features_lite_512(const char *path, float *out512) {
  if (!path || !path[0] || !out512) {
    return -1;
  }
  memset(out512, 0, 512u * sizeof(float));

  size_t cap = env_read_max();
  uint8_t *buf = (uint8_t *)malloc(cap);
  if (!buf) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    free(buf);
    return -1;
  }
  
  // 智能读取策略
  size_t n = 0;
  if (env_smart_read_enabled()) {
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= (long)cap) {
      // 小文件：全读
      n = fread(buf, 1u, (size_t)file_size, f);
    } else {
      // 大文件：读头部 + 尾部（各占一半容量）
      size_t half = cap / 2;
      n = fread(buf, 1u, half, f);  // 读取前半部分
      
      fseek(f, -((long)half), SEEK_END);  // 移动到文件尾部前 half 处
      size_t tail_n = fread(buf + n, 1u, half, f);  // 读取后半部分
      n += tail_n;
    }
  } else {
    // 传统模式：全读
    n = fread(buf, 1u, cap, f);
  }
  
  fclose(f);
  if (n == 0u) {
    free(buf);
    return 0;
  }

  unsigned long long hist[256];
  memset(hist, 0, sizeof(hist));
  for (size_t i = 0; i < n; i++) {
    hist[buf[i]]++;
  }
  float invn = 1.0f / (float)n;
  for (int i = 0; i < 256; i++) {
    out512[i] = (float)hist[i] * invn;
  }

  const size_t nseg = 256u;
  size_t seglen = n / nseg;
  if (seglen == 0u) {
    seglen = 1u;
  }
  for (size_t s = 0; s < nseg; s++) {
    size_t off = s * seglen;
    if (off >= n) {
      out512[256 + (int)s] = 0.f;
      continue;
    }
    size_t slen = seglen;
    if (off + slen > n) {
      slen = n - off;
    }
    out512[256 + (int)s] = shannon_entropy(buf + off, slen);
  }

  l2_normalize_512(out512);
  free(buf);
  return 0;
}
