#include "fl_b64.h"

#include <stdint.h>
#include <string.h>

static const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t fl_b64_encode(const unsigned char *in, size_t len, char *out, size_t out_cap) {
  size_t i = 0;
  size_t o = 0;
  if (!in || !out || out_cap == 0u) {
    return 0;
  }
  while (i + 3u <= len) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | (uint32_t)in[i + 2];
    if (o + 4u >= out_cap) {
      return 0;
    }
    out[o++] = kB64[(v >> 18) & 63u];
    out[o++] = kB64[(v >> 12) & 63u];
    out[o++] = kB64[(v >> 6) & 63u];
    out[o++] = kB64[v & 63u];
    i += 3u;
  }
  if (i < len) {
    if (len - i == 1u) {
      uint32_t v = (uint32_t)in[i] << 16;
      if (o + 4u >= out_cap) {
        return 0;
      }
      out[o++] = kB64[(v >> 18) & 63u];
      out[o++] = kB64[(v >> 12) & 63u];
      out[o++] = '=';
      out[o++] = '=';
    } else {
      uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
      if (o + 4u >= out_cap) {
        return 0;
      }
      out[o++] = kB64[(v >> 18) & 63u];
      out[o++] = kB64[(v >> 12) & 63u];
      out[o++] = kB64[(v >> 6) & 63u];
      out[o++] = '=';
    }
  }
  if (o >= out_cap) {
    return 0;
  }
  out[o] = '\0';
  return o;
}
