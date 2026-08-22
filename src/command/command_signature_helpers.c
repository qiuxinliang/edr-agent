#include "edr/config.h"
#include "edr/command_util.h"
#include "edr/sha256.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(EDR_HAVE_OPENSSL_HTTP) || defined(EDR_HAVE_OPENSSL_FL)
#define EDR_HAVE_COMMAND_SIGNATURE_OPENSSL 1
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif


void hex_from_bytes(const uint8_t *in, size_t len, char *out, size_t cap) {
  static const char *hx = "0123456789abcdef";
  if (!out || cap == 0u) {
    return;
  }
  size_t o = 0;
  for (size_t i = 0; i < len && o + 2u < cap; i++) {
    out[o++] = hx[in[i] >> 4];
    out[o++] = hx[in[i] & 15u];
  }
  out[o] = 0;
}

void hmac_sha256_hex(const char *key, const uint8_t *data, size_t len, char out65[65]) {
  uint8_t key_block[64];
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t ipad[64];
  uint8_t opad[64];
  memset(key_block, 0, sizeof(key_block));
  if (!key) {
    key = "";
  }
  size_t key_len = strlen(key);
  if (key_len > sizeof(key_block)) {
    EdrSha256Ctx kh;
    edr_sha256_init(&kh);
    edr_sha256_update(&kh, (const uint8_t *)key, key_len);
    edr_sha256_final(&kh, key_block);
  } else if (key_len > 0u) {
    memcpy(key_block, key, key_len);
  }
  for (size_t i = 0; i < sizeof(key_block); i++) {
    ipad[i] = key_block[i] ^ 0x36u;
    opad[i] = key_block[i] ^ 0x5cu;
  }
  EdrSha256Ctx inner;
  edr_sha256_init(&inner);
  edr_sha256_update(&inner, ipad, sizeof(ipad));
  edr_sha256_update(&inner, data, len);
  edr_sha256_final(&inner, digest);

  EdrSha256Ctx outer;
  edr_sha256_init(&outer);
  edr_sha256_update(&outer, opad, sizeof(opad));
  edr_sha256_update(&outer, digest, sizeof(digest));
  edr_sha256_final(&outer, digest);
  hex_from_bytes(digest, sizeof(digest), out65, 65u);
}

int command_signature_extract_sigv1(const char *idempotency_key, char sig65[65]) {
  if (!idempotency_key || !sig65) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  if (!mark) {
    return 0;
  }
  const char *keyid = mark + strlen("|sigv1|");
  const char *bar = strchr(keyid, '|');
  if (!bar || strlen(bar + 1) != 64u) {
    return 0;
  }
  for (size_t i = 0; i < 64u; i++) {
    char c = bar[1 + i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return 0;
    }
    sig65[i] = (char)tolower((unsigned char)c);
  }
  sig65[64] = 0;
  return 1;
}

int b64url_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
  if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

static int b64url_decode_raw(const char *s, uint8_t *out, size_t out_cap, size_t *out_len) {
  if (!s || !out || !out_len) {
    return -1;
  }
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t o = 0;
  for (; *s; s++) {
    if (*s == '=') {
      break;
    }
    int v = b64url_value((unsigned char)*s);
    if (v < 0) {
      return -1;
    }
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((acc >> bits) & 0xffu);
    }
  }
  *out_len = o;
  return 0;
}

int command_signature_extract_sigv2(const char *idempotency_key, char *alg, size_t alg_cap,
                                           uint8_t *sig, size_t sig_cap, size_t *sig_len) {
  if (!idempotency_key || !alg || alg_cap == 0u || !sig || !sig_len) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv2|");
  if (!mark) {
    return 0;
  }
  const char *algp = mark + strlen("|sigv2|");
  const char *bar1 = strchr(algp, '|');
  if (!bar1 || bar1 == algp) {
    return 0;
  }
  size_t alg_len = (size_t)(bar1 - algp);
  if (alg_len >= alg_cap) {
    alg_len = alg_cap - 1u;
  }
  memcpy(alg, algp, alg_len);
  alg[alg_len] = '\0';
  const char *keyid = bar1 + 1;
  const char *bar2 = strchr(keyid, '|');
  if (!bar2 || bar2 == keyid || !bar2[1]) {
    return 0;
  }
  if (b64url_decode_raw(bar2 + 1, sig, sig_cap, sig_len) != 0) {
    return 0;
  }
  return *sig_len > 0u;
}

static void normalize_pem_newlines(char *s) {
  if (!s) {
    return;
  }
  char *r = s;
  char *w = s;
  while (*r) {
    if (r[0] == '\\' && r[1] == 'n') {
      *w++ = '\n';
      r += 2;
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
}

static int read_text_file_small(const char *path, char *out, size_t cap) {
  if (!path || !path[0] || !out || cap < 2u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
	size_t n = fread(out, 1, cap - 1u, f);
	fclose(f);
	out[n] = '\0';
	return n > 0u ? 0 : -1;
}

static int read_command_public_key_path(const char *path, char *out, size_t cap) {
  if (!path || !path[0]) {
    return -1;
  }
  if (read_text_file_small(path, out, cap) == 0) {
    return 0;
  }
#ifdef _WIN32
  {
    const char *legacy = "\\EDR Agent\\";
    const char *p = strstr(path, legacy);
    if (p) {
      char alt[1024];
      size_t prefix_len = (size_t)(p - path);
      int n = snprintf(alt, sizeof(alt), "%.*s\\FDSecurity\\%s",
                       (int)prefix_len, path, p + strlen(legacy));
      if (n > 0 && (size_t)n < sizeof(alt) &&
          read_text_file_small(alt, out, cap) == 0) {
        return 0;
      }
    }
  }
#endif
  return -1;
}

int command_public_key_pem(char *out, size_t cap) {
  if (!out || cap < 2u) {
    return 0;
  }
  out[0] = '\0';
  const char *inline_pem = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY");
  if (!inline_pem || !inline_pem[0]) {
    inline_pem = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY");
  }
  if (inline_pem && inline_pem[0]) {
    snprintf(out, cap, "%s", inline_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  const char *path = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY_PATH");
  if (!path || !path[0]) {
    path = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY_PATH");
  }
  if (path && path[0] && read_command_public_key_path(path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  if (edr_command_get_config() && edr_command_get_config()->command.signing_public_key_pem[0]) {
    snprintf(out, cap, "%s", edr_command_get_config()->command.signing_public_key_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  if (edr_command_get_config() && edr_command_get_config()->command.signing_public_key_path[0] &&
      read_command_public_key_path(edr_command_get_config()->command.signing_public_key_path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  return 0;
}

int command_verify_ed25519_pem(const char *public_key_pem, const uint8_t *msg, size_t msg_len,
                                      const uint8_t *sig, size_t sig_len) {
#ifdef EDR_HAVE_COMMAND_SIGNATURE_OPENSSL
  if (!public_key_pem || !public_key_pem[0] || !msg || !sig || sig_len == 0u) {
    return 0;
  }
  BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
  if (!bio) {
    return 0;
  }
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    return 0;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = 0;
  if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) {
    ok = 1;
  }
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
  EVP_PKEY_free(pkey);
  return ok;
#else
  (void)public_key_pem;
  (void)msg;
  (void)msg_len;
  (void)sig;
  (void)sig_len;
  return -1;
#endif
}

void command_signature_idempotency_value(const char *idempotency_key, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!idempotency_key || !idempotency_key[0]) {
    return;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  const char *mark2 = strstr(idempotency_key, "|sigv2|");
  if (!mark || (mark2 && mark2 < mark)) {
    mark = mark2;
  }
  size_t n = mark ? (size_t)(mark - idempotency_key) : strlen(idempotency_key);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, idempotency_key, n);
  out[n] = '\0';
}
