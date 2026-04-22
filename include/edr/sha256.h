/**
 * SHA-256 (FIPS 180-4) — compact portable implementation for agent utilities.
 */
#ifndef EDR_SHA256_H
#define EDR_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define EDR_SHA256_DIGEST_LEN 32

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buf[64];
  size_t buflen;
} EdrSha256Ctx;

void edr_sha256_init(EdrSha256Ctx *ctx);
void edr_sha256_update(EdrSha256Ctx *ctx, const uint8_t *data, size_t len);
void edr_sha256_final(EdrSha256Ctx *ctx, uint8_t out[EDR_SHA256_DIGEST_LEN]);

/** One-shot: digest + lowercase hex string (65 bytes including NUL). Returns 0 on success. */
int edr_sha256_hex(const uint8_t *data, size_t len, char out65[65]);

#endif
