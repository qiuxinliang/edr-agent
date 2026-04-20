#include "edr/sha256.h"

#include <string.h>

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static void transform(EdrSha256Ctx *ctx, const uint8_t block[64]) {
  uint32_t W[64];
  unsigned i;
  for (i = 0; i < 16; i++) {
    W[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) |
           (uint32_t)block[i * 4 + 3];
  }
  for (i = 16; i < 64; i++) {
    uint32_t s0 = rotr(W[i - 15], 7u) ^ rotr(W[i - 15], 18u) ^ (W[i - 15] >> 3);
    uint32_t s1 = rotr(W[i - 2], 17u) ^ rotr(W[i - 2], 19u) ^ (W[i - 2] >> 10);
    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (i = 0; i < 64; i++) {
    uint32_t S1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + K[i] + W[i];
    uint32_t S0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void edr_sha256_init(EdrSha256Ctx *ctx) {
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
  ctx->bitlen = 0;
  ctx->buflen = 0;
}

void edr_sha256_update(EdrSha256Ctx *ctx, const uint8_t *data, size_t len) {
  size_t i = 0;
  while (i < len) {
    size_t take = 64u - ctx->buflen;
    if (take > len - i) {
      take = len - i;
    }
    memcpy(ctx->buf + ctx->buflen, data + i, take);
    ctx->buflen += take;
    i += take;
    if (ctx->buflen == 64u) {
      transform(ctx, ctx->buf);
      ctx->bitlen += 512ull;
      ctx->buflen = 0;
    }
  }
}

void edr_sha256_final(EdrSha256Ctx *ctx, uint8_t out[EDR_SHA256_DIGEST_LEN]) {
  uint64_t bitlen = ctx->bitlen + (uint64_t)ctx->buflen * 8ull;
  size_t n = ctx->buflen;
  ctx->buf[n++] = 0x80u;
  if (n > 56u) {
    while (n < 64u) {
      ctx->buf[n++] = 0;
    }
    transform(ctx, ctx->buf);
    memset(ctx->buf, 0, 56u);
  } else {
    while (n < 56u) {
      ctx->buf[n++] = 0;
    }
  }
  for (int j = 0; j < 8; j++) {
    ctx->buf[56 + j] = (uint8_t)(bitlen >> (56 - j * 8));
  }
  transform(ctx, ctx->buf);
  for (int i = 0; i < 8; i++) {
    out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
    out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
  }
}

int edr_sha256_hex(const uint8_t *data, size_t len, char out65[65]) {
  EdrSha256Ctx ctx;
  uint8_t d[EDR_SHA256_DIGEST_LEN];
  edr_sha256_init(&ctx);
  edr_sha256_update(&ctx, data, len);
  edr_sha256_final(&ctx, d);
  static const char *hx = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out65[i * 2] = hx[d[i] >> 4];
    out65[i * 2 + 1] = hx[d[i] & 15];
  }
  out65[64] = '\0';
  return 0;
}
