#include "edr/request_signing.h"

#include "edr/sha256.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

static const char kHex[] = "0123456789abcdef";

int edr_reqsig_body_sha256_hex(const uint8_t *body, size_t body_len, char out65[65]) {
  return edr_sha256_hex(body, body_len, out65);
}

int edr_reqsig_canonical(const char *method, const char *path_with_query,
                         const char *timestamp_ms, const char *nonce,
                         const char *content_sha256_hex, const char *endpoint_id,
                         char *out, size_t out_cap) {
  char method_upper[16];
  size_t i = 0u;
  if (!method || !path_with_query || !timestamp_ms || !nonce || !content_sha256_hex || !endpoint_id || !out || out_cap == 0u) {
    return -1;
  }
  while (method[i] && i + 1u < sizeof(method_upper)) {
    method_upper[i] = (char)toupper((unsigned char)method[i]);
    i++;
  }
  method_upper[i] = '\0';
  if (!method_upper[0]) {
    return -1;
  }
  if (snprintf(out, out_cap, "REQSIG-V1\n%s\n%s\n%s\n%s\n%s\n%s",
               method_upper, path_with_query[0] ? path_with_query : "/",
               timestamp_ms, nonce, content_sha256_hex, endpoint_id) >= (int)out_cap) {
    return -1;
  }
  return 0;
}

static void to_hex(const uint8_t *bytes, size_t len, char *out) {
  for (size_t i = 0u; i < len; i++) {
    out[i * 2u] = kHex[bytes[i] >> 4];
    out[i * 2u + 1u] = kHex[bytes[i] & 15u];
  }
  out[len * 2u] = '\0';
}

int edr_reqsig_hmac_sha256_hex(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               char out65[65]) {
  uint8_t key_block[64];
  uint8_t ipad[64];
  uint8_t opad[64];
  uint8_t inner[EDR_SHA256_DIGEST_LEN];
  uint8_t outer[EDR_SHA256_DIGEST_LEN];
  EdrSha256Ctx ctx;
  if (!key || key_len == 0u || !data || !out65) {
    return -1;
  }
  memset(key_block, 0, sizeof(key_block));
  if (key_len > sizeof(key_block)) {
    edr_sha256_hex(key, key_len, out65);
    EdrSha256Ctx kctx;
    edr_sha256_init(&kctx);
    edr_sha256_update(&kctx, key, key_len);
    edr_sha256_final(&kctx, key_block);
  } else {
    memcpy(key_block, key, key_len);
  }
  for (size_t i = 0u; i < sizeof(key_block); i++) {
    ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
    opad[i] = (uint8_t)(key_block[i] ^ 0x5cu);
  }
  edr_sha256_init(&ctx);
  edr_sha256_update(&ctx, ipad, sizeof(ipad));
  edr_sha256_update(&ctx, data, data_len);
  edr_sha256_final(&ctx, inner);
  edr_sha256_init(&ctx);
  edr_sha256_update(&ctx, opad, sizeof(opad));
  edr_sha256_update(&ctx, inner, sizeof(inner));
  edr_sha256_final(&ctx, outer);
  to_hex(outer, sizeof(outer), out65);
  return 0;
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  return -1;
}

static int decode_hex_secret(const char *secret, uint8_t *out, size_t out_cap, size_t *out_len) {
  const char *p = secret;
  size_t n = 0u;
  if (!p) return -1;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
  while (p[n]) {
    if (hex_value((unsigned char)p[n]) < 0) return -1;
    n++;
  }
  if (n == 0u || (n % 2u) != 0u || n / 2u > out_cap) return -1;
  for (size_t i = 0u; i < n / 2u; i++) {
    int hi = hex_value((unsigned char)p[i * 2u]);
    int lo = hex_value((unsigned char)p[i * 2u + 1u]);
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  if (out_len) *out_len = n / 2u;
  return 0;
}

static int b64url_value(int c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return 26 + c - 'a';
  if (c >= '0' && c <= '9') return 52 + c - '0';
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

static int decode_b64_secret(const char *secret, uint8_t *out, size_t out_cap, size_t *out_len) {
  uint32_t acc = 0u;
  int bits = 0;
  size_t outn = 0u;
  if (!secret) return -1;
  for (const unsigned char *p = (const unsigned char *)secret; *p; p++) {
    if (*p == '=') break;
    if (isspace(*p)) continue;
    int v = b64url_value(*p);
    if (v < 0) return -1;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (outn >= out_cap) return -1;
      out[outn++] = (uint8_t)((acc >> bits) & 0xffu);
    }
  }
  if (outn == 0u) return -1;
  if (out_len) *out_len = outn;
  return 0;
}

int edr_reqsig_secret_decode(const char *secret, uint8_t *out, size_t out_cap, size_t *out_len) {
  if (!secret || !secret[0] || !out || out_cap == 0u) {
    return -1;
  }
  if (decode_b64_secret(secret, out, out_cap, out_len) == 0) {
    return 0;
  }
  return decode_hex_secret(secret, out, out_cap, out_len);
}

static int random_bytes(uint8_t *out, size_t len) {
#ifdef _WIN32
  HCRYPTPROV prov = 0;
  if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    BOOL ok = CryptGenRandom(prov, (DWORD)len, out);
    CryptReleaseContext(prov, 0);
    if (ok) return 0;
  }
#else
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    size_t got = 0u;
    while (got < len) {
      ssize_t n = read(fd, out + got, len - got);
      if (n <= 0) break;
      got += (size_t)n;
    }
    close(fd);
    if (got == len) return 0;
  }
#endif
  srand((unsigned)time(NULL));
  for (size_t i = 0u; i < len; i++) {
    out[i] = (uint8_t)(rand() & 0xffu);
  }
  return 0;
}

int edr_reqsig_random_nonce_hex(char out33[33]) {
  uint8_t nonce[16];
  if (!out33 || random_bytes(nonce, sizeof(nonce)) != 0) {
    return -1;
  }
  to_hex(nonce, sizeof(nonce), out33);
  return 0;
}

int edr_reqsig_build_headers(const EdrRequestSigningConfig *cfg,
                             const char *method, const char *path_with_query,
                             const char *endpoint_id,
                             const uint8_t *body, size_t body_len,
                             int64_t timestamp_ms,
                             char *out, size_t out_cap) {
  char body_hash[65];
  if (edr_reqsig_body_sha256_hex(body, body_len, body_hash) != 0) {
    return -1;
  }
  return edr_reqsig_build_headers_from_hash(cfg, method, path_with_query, endpoint_id,
                                            body_hash, timestamp_ms, out, out_cap);
}

int edr_reqsig_build_headers_from_hash(const EdrRequestSigningConfig *cfg,
                                       const char *method, const char *path_with_query,
                                       const char *endpoint_id,
                                       const char *content_sha256_hex,
                                       int64_t timestamp_ms,
                                       char *out, size_t out_cap) {
  char timestamp[32];
  char nonce[33];
  char canonical[2048];
  uint8_t secret[128];
  size_t secret_len = 0u;
  char sig[65];
  if (!out || out_cap == 0u || !content_sha256_hex || strlen(content_sha256_hex) != 64u) {
    return -1;
  }
  out[0] = '\0';
  if (!cfg || !cfg->enabled || !cfg->key_id[0] || !cfg->secret[0] || !endpoint_id || !endpoint_id[0]) {
    return 0;
  }
  snprintf(timestamp, sizeof(timestamp), "%lld", (long long)timestamp_ms);
  if (edr_reqsig_random_nonce_hex(nonce) != 0) {
    return -1;
  }
  if (edr_reqsig_secret_decode(cfg->secret, secret, sizeof(secret), &secret_len) != 0) {
    return -1;
  }
  if (edr_reqsig_canonical(method, path_with_query, timestamp, nonce, content_sha256_hex, endpoint_id,
                           canonical, sizeof(canonical)) != 0) {
    return -1;
  }
  if (edr_reqsig_hmac_sha256_hex(secret, secret_len, (const uint8_t *)canonical, strlen(canonical), sig) != 0) {
    return -1;
  }
  if (snprintf(out, out_cap,
               "X-EDR-Signature-Version: %s\r\n"
               "X-EDR-Key-ID: %s\r\n"
               "X-EDR-Timestamp-Ms: %s\r\n"
               "X-EDR-Nonce: %s\r\n"
               "X-EDR-Content-SHA256: %s\r\n"
               "X-EDR-Signature: %s\r\n",
               EDR_REQSIG_VERSION, cfg->key_id, timestamp, nonce, content_sha256_hex, sig) >= (int)out_cap) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}
