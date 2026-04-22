#include "edr/fl_dp.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>

void fl_dp_clip_l2(float *vec, size_t n, float max_norm) {
  float sum = 0.0f;
  size_t i;
  float norm;
  float s;

  if (!vec || n == 0u || max_norm <= 0.0f) {
    return;
  }
  for (i = 0; i < n; i++) {
    sum += vec[i] * vec[i];
  }
  norm = sqrtf(sum);
  if (norm <= max_norm || norm < 1e-12f) {
    return;
  }
  s = max_norm / norm;
  for (i = 0; i < n; i++) {
    vec[i] *= s;
  }
}

static uint64_t xorshift64star(uint64_t *s) {
  uint64_t x = *s;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *s = x * 2685821657736338717ull;
  return x;
}

static float laplace_sample(uint64_t *s, float scale) {
  float u1 = (float)(xorshift64star(s) & 0xffffff) / 16777216.0f;
  float u2 = (float)(xorshift64star(s) & 0xffffff) / 16777216.0f;
  float e1 = -logf(u1 + 1e-8f) * scale;
  float e2 = -logf(u2 + 1e-8f) * scale;
  return e1 - e2;
}

void fl_dp_add_laplace(float *vec, size_t n, float scale, uint64_t *rng_state) {
  uint64_t st = rng_state && *rng_state != 0u ? *rng_state : 0xD6E8FEB86612FD37ull;
  size_t i;
  if (!vec || n == 0u || scale <= 0.0f) {
    return;
  }
  for (i = 0; i < n; i++) {
    vec[i] += laplace_sample(&st, scale);
  }
  if (rng_state) {
    *rng_state = st;
  }
}
