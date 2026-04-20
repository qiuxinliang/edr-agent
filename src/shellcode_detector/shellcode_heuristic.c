#include "edr/shellcode_detector.h"

#include <stddef.h>
#include <stdint.h>

/** 连续 0x90 超过阈值则加分 */
static double score_nop_sled(const uint8_t *d, size_t len) {
  size_t best = 0, cur = 0;
  for (size_t i = 0; i < len; i++) {
    if (d[i] == 0x90u) {
      cur++;
      if (cur > best) {
        best = cur;
      }
    } else {
      cur = 0;
    }
  }
  if (best > 8u) {
    double t = (double)(best - 8u);
    if (t > 32.0) {
      t = 32.0;
    }
    return 0.25 * (t / 32.0);
  }
  return 0.0;
}

/** 常见 call $+5; pop ebx 类 GetPC 片段（极简化） */
static double score_getpc_hint(const uint8_t *d, size_t len) {
  if (len < 6u) {
    return 0.0;
  }
  for (size_t i = 0; i + 5u < len; i++) {
    if (d[i] == 0xE8u && d[i + 5u] == 0x58u) {
      return 0.15;
    }
  }
  return 0.0;
}

double edr_shellcode_heuristic_score(const uint8_t *data, size_t len) {
  if (!data || len < 16u) {
    return 0.0;
  }
  double e = edr_shellcode_shannon_entropy_bits(data, len);
  double score = 0.0;
  if (e >= 6.8) {
    double span = 8.0 - 6.8;
    if (span <= 0.0) {
      span = 1.0;
    }
    double excess = (e - 6.8) / span;
    if (excess > 1.0) {
      excess = 1.0;
    }
    score += 0.45 * excess;
  }
  score += score_nop_sled(data, len);
  score += score_getpc_hint(data, len);
  if (score > 1.0) {
    score = 1.0;
  }
  return score;
}
