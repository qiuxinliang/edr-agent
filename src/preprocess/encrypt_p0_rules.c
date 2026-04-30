#include "edr/encrypt_p0_rules.h"

#include <stdlib.h>
#include <string.h>

#ifdef EDR_HAVE_OPENSSL_FL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
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

  uint8_t prk[32];
  unsigned int prk_len = 32;
  HMAC(EVP_sha256(), salt, (int)(sizeof(salt) - 1), seed, sizeof(seed), prk, &prk_len);

  uint8_t okm[32];
  uint8_t t[32];
  unsigned int t_len;
  uint8_t ctr = 1;
  size_t off = 0;

  while (off < 32) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, prk, 32, EVP_sha256(), NULL);
    if (off > 0) {
      HMAC_Update(ctx, okm, (unsigned int)off);
    }
    HMAC_Update(ctx, info, (size_t)(sizeof(info) - 1));
    HMAC_Update(ctx, &ctr, 1);
    t_len = 32;
    HMAC_Final(ctx, t, &t_len);
    HMAC_CTX_free(ctx);

    size_t need = 32 - off;
    if (need > t_len) {
      need = t_len;
    }
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

  plain[plain_len] = 0;
  *out = plain;
  *out_len = plain_len;
  return 0;
#else
  (void)in;
  return -4;
#endif
}
