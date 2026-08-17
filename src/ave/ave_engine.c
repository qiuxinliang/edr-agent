/* AV Engine support shared by rule/heuristic detection and file fingerprinting.
 * Endpoint ONNX model execution was retired: static decisions now come from
 * signed IOC/allow-list policy and behavior scoring remains heuristic. */

#include "edr/ave.h"
#include "edr/sha256.h"

#include <stdint.h>
#include <stdio.h>

int edr_ave_file_fingerprint(const char *path, char *out_hex, size_t cap) {
  if (!path || !path[0] || !out_hex || cap < 17u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t buf[4096];
  edr_sha256_init(&ctx);
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (n > 0u) {
      edr_sha256_update(&ctx, buf, n);
    }
    if (n < sizeof(buf)) {
      if (ferror(f)) {
        fclose(f);
        return -1;
      }
      break;
    }
  }
  fclose(f);
  edr_sha256_final(&ctx, digest);
  static const char *hx = "0123456789abcdef";
  size_t hex_chars = (cap - 1u < 64u) ? cap - 1u : 64u;
  hex_chars -= hex_chars % 2u;
  for (size_t i = 0; i < hex_chars / 2u; i++) {
    out_hex[i * 2u] = hx[digest[i] >> 4];
    out_hex[i * 2u + 1u] = hx[digest[i] & 0x0f];
  }
  out_hex[hex_chars] = '\0';
  return 0;
}

EdrError edr_ave_init(const EdrConfig *cfg) {
  return cfg ? EDR_OK : EDR_ERR_INVALID_ARG;
}

void edr_ave_shutdown(void) {}

void edr_ave_get_scan_counts(int *out_model_files, int *out_non_dir_files, int *out_ready_flag) {
  if (out_model_files) {
    *out_model_files = 0;
  }
  if (out_non_dir_files) {
    *out_non_dir_files = 0;
  }
  if (out_ready_flag) {
    *out_ready_flag = 0;
  }
}
