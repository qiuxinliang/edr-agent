#include "edr/encrypt_p0_rules.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef EDR_HAVE_OPENSSL_FL
#include <openssl/evp.h>
#endif

#ifdef EDR_HAVE_OPENSSL_FL
static const uint8_t s_seed_a[] = {0x7f, 0xe1, 0x4a, 0xd2, 0x91, 0x3b, 0x88, 0x5c, 0x2d, 0xf6};
static const uint8_t s_seed_b[] = {0x0e, 0x73, 0xa9, 0x44, 0xcb, 0x1f, 0x68, 0x35, 0xd7, 0x0b, 0xea};
static const uint8_t s_seed_c[] = {0x52, 0x99, 0x7d, 0x1c, 0x4e, 0xb8, 0x30, 0xf2, 0x65, 0xa1, 0x8e};

static void derive_key(uint8_t key[32]) {
  uint8_t seed[32];
  memcpy(seed, s_seed_a, sizeof(s_seed_a));
  memcpy(seed + sizeof(s_seed_a), s_seed_b, sizeof(s_seed_b));
  memcpy(seed + sizeof(s_seed_a) + sizeof(s_seed_b), s_seed_c, sizeof(s_seed_c));

  const uint8_t salt[] = "edr-p0-rule-v1";
  const uint8_t info[] = "aes-256-gcm-rule";

  /* HKDF-extract: PRK = HMAC-SHA256(salt, seed) */
  uint8_t prk[32];
  {
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) return;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
    EVP_MAC_free(hmac);
    if (!ctx) return;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t out_len = 32;
    EVP_MAC_init(ctx, salt, sizeof(salt) - 1, params);
    EVP_MAC_update(ctx, seed, sizeof(seed));
    EVP_MAC_final(ctx, prk, &out_len, sizeof(prk));
    EVP_MAC_CTX_free(ctx);
  }

  /* HKDF-expand: OKM = T(1) || T(2) || ... until 32 bytes */
  uint8_t okm[32];
  uint8_t ctr = 1;
  size_t off = 0;

  while (off < 32) {
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) break;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
    EVP_MAC_free(hmac);
    if (!ctx) break;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, prk, sizeof(prk), params);
    if (off > 0) {
      EVP_MAC_update(ctx, okm, off);
    }
    EVP_MAC_update(ctx, info, sizeof(info) - 1);
    EVP_MAC_update(ctx, &ctr, 1);

    uint8_t t[32];
    size_t t_len = sizeof(t);
    EVP_MAC_final(ctx, t, &t_len, sizeof(t));
    EVP_MAC_CTX_free(ctx);

    size_t need = 32 - off;
    if (need > t_len) need = t_len;
    memcpy(okm + off, t, need);
    off += need;
    ctr++;
  }
  memcpy(key, okm, 32);
}
#endif /* EDR_HAVE_OPENSSL_FL */

int edr_p0_encrypt_is_edr1(const uint8_t *data, size_t data_len) {
  if (!data || data_len < EDR_P0_ENCRYPT_OVERHEAD) {
    return 0;
  }
  return memcmp(data, EDR_P0_ENCRYPT_MAGIC, EDR_P0_ENCRYPT_MAGIC_LEN) == 0 ? 1 : 0;
}

int edr_p0_encrypt_decrypt_edr1(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
  if (!in || !out || !out_len) {
    return -1;
  }
  if (in_len < EDR_P0_ENCRYPT_OVERHEAD) {
    return -2;
  }
  if (in_len > EDR_P0_ENCRYPT_ENVELOPE_MAX_BYTES) {
    return -2;
  }
  if (memcmp(in, EDR_P0_ENCRYPT_MAGIC, EDR_P0_ENCRYPT_MAGIC_LEN) != 0) {
    return -1;
  }

#ifdef EDR_HAVE_OPENSSL_FL
  const uint8_t *nonce = in + EDR_P0_ENCRYPT_MAGIC_LEN;
  const uint8_t *ciphertext = nonce + EDR_P0_ENCRYPT_NONCE_LEN;
  size_t ciphertext_len = in_len - EDR_P0_ENCRYPT_OVERHEAD;

  uint8_t key[32];
  derive_key(key);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return -4;
  }

  size_t plain_len = ciphertext_len;
  uint8_t *plain = (uint8_t *)malloc(plain_len + 1u);
  if (!plain) {
    EVP_CIPHER_CTX_free(ctx);
    return -2;
  }

  int outl = 0;
  int ret = 0;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    ret = -4;
  }
  if (ret == 0 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EDR_P0_ENCRYPT_NONCE_LEN, NULL) != 1) {
    ret = -4;
  }
  if (ret == 0 &&
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    ret = -4;
  }
  if (ret == 0 &&
      EVP_DecryptUpdate(ctx, plain, &outl, ciphertext, (int)ciphertext_len) != 1) {
    ret = -3;
  }
  if (ret == 0) {
    const uint8_t *tag = ciphertext + ciphertext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EDR_P0_ENCRYPT_TAG_LEN, (void *)tag) != 1) {
      ret = -3;
    }
    int finl = 0;
    if (EVP_DecryptFinal_ex(ctx, plain + outl, &finl) != 1) {
      ret = -3;
    }
    plain_len = (size_t)(outl + finl);
  }

  EVP_CIPHER_CTX_free(ctx);

  if (ret != 0) {
    free(plain);
    return ret;
  }
  if (plain_len > EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES) {
    free(plain);
    return -2;
  }

  plain[plain_len] = 0;
  *out = plain;
  *out_len = plain_len;
  return 0;
#else
  (void)in;
  return -4;
#endif
}

#if defined(EDR_P0_ENCRYPT_TESTING) && defined(EDR_HAVE_OPENSSL_FL)
int edr_p0_encrypt_encrypt_edr1_for_test(const uint8_t *plain, size_t plain_len,
                                         uint8_t **out, size_t *out_len) {
  uint8_t key[32];
  uint8_t *envelope;
  EVP_CIPHER_CTX *ctx;
  int outl = 0;
  int finl = 0;
  int ret = -4;
  /* Deliberately permits one-byte-over-limit envelopes so the boundary test
   * proves the deployed loader rejects them before decryption. */
  if (!plain || !out || !out_len || plain_len > (size_t)INT_MAX ||
      plain_len > SIZE_MAX - EDR_P0_ENCRYPT_OVERHEAD) {
    return -2;
  }
  *out = NULL;
  *out_len = 0u;
  envelope = (uint8_t *)malloc(EDR_P0_ENCRYPT_OVERHEAD + plain_len);
  if (!envelope) return -2;
  memcpy(envelope, EDR_P0_ENCRYPT_MAGIC, EDR_P0_ENCRYPT_MAGIC_LEN);
  for (size_t i = 0u; i < EDR_P0_ENCRYPT_NONCE_LEN; ++i) {
    envelope[EDR_P0_ENCRYPT_MAGIC_LEN + i] = (uint8_t)(0xa0u + i);
  }
  derive_key(key);
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    free(envelope);
    return -4;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EDR_P0_ENCRYPT_NONCE_LEN, NULL) == 1 &&
      EVP_EncryptInit_ex(ctx, NULL, NULL, key,
                         envelope + EDR_P0_ENCRYPT_MAGIC_LEN) == 1 &&
      EVP_EncryptUpdate(ctx, envelope + EDR_P0_ENCRYPT_MAGIC_LEN + EDR_P0_ENCRYPT_NONCE_LEN,
                        &outl, plain, (int)plain_len) == 1 &&
      EVP_EncryptFinal_ex(ctx, envelope + EDR_P0_ENCRYPT_MAGIC_LEN +
                           EDR_P0_ENCRYPT_NONCE_LEN + outl, &finl) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EDR_P0_ENCRYPT_TAG_LEN,
                          envelope + EDR_P0_ENCRYPT_MAGIC_LEN +
                          EDR_P0_ENCRYPT_NONCE_LEN + plain_len) == 1 &&
      (size_t)(outl + finl) == plain_len) {
    *out = envelope;
    *out_len = EDR_P0_ENCRYPT_OVERHEAD + plain_len;
    ret = 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  if (ret != 0) free(envelope);
  return ret;
}
#endif
