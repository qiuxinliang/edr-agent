#include "edr/shellcode_detector.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>

double edr_shellcode_shannon_entropy_bits(const uint8_t *data, size_t len) {
  if (!data || len == 0u) {
    return 0.0;
  }
  unsigned count[256];
  for (int i = 0; i < 256; i++) {
    count[i] = 0u;
  }
  for (size_t i = 0; i < len; i++) {
    count[data[i]]++;
  }
  double h = 0.0;
  const double invlen = 1.0 / (double)len;
  for (int i = 0; i < 256; i++) {
    if (count[i] == 0) {
      continue;
    }
    double p = (double)count[i] * invlen;
    h -= p * (log(p) / log(2.0));
  }
  return h;
}
