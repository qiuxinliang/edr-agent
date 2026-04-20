#include "edr/fl_crypto.h"

#include <stdlib.h>
#include <string.h>

#define FLSTUB_MAGIC "FLSTUB1"
#define FLSTUB_MAGIC_LEN 7u

#define FL2_MAGIC "FL2"
#define FL2_MAGIC_LEN 3u
#define FL2_VERSION 1u

#define FL3_MAGIC "FL3"
#define FL3_MAGIC_LEN 3u
#define FL3_VERSION 2u

#ifdef EDR_HAVE_OPENSSL_FL
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#ifdef EDR_HAVE_OPENSSL_FL
static uint8_t s_coord_pub[96];
static size_t s_coord_pub_len;

void fl_crypto_set_coordinator_pubkey(const uint8_t *pub, size_t pub_len) {
  if (!pub || pub_len == 0u || pub_len > sizeof(s_coord_pub)) {
    s_coord_pub_len = 0;
    return;
  }
  memcpy(s_coord_pub, pub, pub_len);
  s_coord_pub_len = pub_len;
}

/** RFC 5869 HKDF-SHA256：Extract + Expand */
static int hkdf_sha256_full(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
  uint8_t prk[32];
  uint8_t salt0[32];
  uint8_t t[32];
  unsigned int prk_len = 32u;
  size_t off = 0;
  uint8_t ctr = 1u;

  if (!ikm || ikm_len == 0u || !okm || okm_len == 0u) {
    return -1;
  }
  if (!salt || salt_len == 0u) {
    memset(salt0, 0, sizeof(salt0));
    salt = salt0;
    salt_len = sizeof(salt0);
  }
  if (HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len) == NULL) {
    return -1;
  }
  memset(t, 0, sizeof(t));
  while (off < okm_len) {
    uint8_t inbuf[32 + 256 + 1];
    size_t il = 0;
    if (off > 0u) {
      memcpy(inbuf, t, 32u);
      il = 32u;
    }
    if (info_len > 0u && info) {
      memcpy(inbuf + il, info, info_len);
      il += info_len;
    }
    inbuf[il] = ctr;
    il++;
    {
      unsigned int olen = 32u;
      if (HMAC(EVP_sha256(), prk, 32, inbuf, il, t, &olen) == NULL) {
        return -1;
      }
    }
    {
      size_t take = okm_len - off;
      if (take > 32u) {
        take = 32u;
      }
      memcpy(okm + off, t, take);
      off += take;
    }
    ctr++;
  }
  OPENSSL_cleanse(prk, sizeof(prk));
  return 0;
}

/** OpenSSL 3：P-256 临时密钥 + `EVP_PKEY_derive`（替代已弃用的 `EC_KEY` / `ECDH_compute_key`）。 */
static int p256_gen_ephemeral(EVP_PKEY **out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  EVP_PKEY *pkey = NULL;
  if (!ctx) {
    return -1;
  }
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  EVP_PKEY_CTX_free(ctx);
  *out = pkey;
  return 0;
}

/**
 * SEC1 公钥 → `EVP_PKEY`（仅公钥）。纯 `EVP_PKEY_fromdata(ENCODED_PUBLIC_KEY)` 在部分 OpenSSL 3
 * 构建下会使 `EVP_PKEY_derive_set_peer` 失败；此处用 `EC_POINT_oct2point` + `EVP_PKEY_set1_EC_KEY`。
 * 私钥同理用 `EC_KEY` 填好标量与公钥点再封进 `EVP_PKEY`，保证与 `EVP_PKEY_derive` 兼容。
 */
static int p256_pubkey_from_sec1(const uint8_t *pub, size_t pub_len, EVP_PKEY **out) {
  int ret = -1;
  EC_KEY *ec = NULL;
  EC_POINT *pt = NULL;
  BN_CTX *bn = NULL;
  EVP_PKEY *pkey = NULL;
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  if (pub_len != 33u && pub_len != 65u) {
    goto end;
  }
  ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  bn = BN_CTX_new();
  if (!ec || !bn) {
    goto end;
  }
  pt = EC_POINT_new(EC_KEY_get0_group(ec));
  if (!pt || EC_POINT_oct2point(EC_KEY_get0_group(ec), pt, pub, pub_len, bn) != 1) {
    goto end;
  }
  if (EC_KEY_set_public_key(ec, pt) != 1) {
    goto end;
  }
  EC_POINT_free(pt);
  pt = NULL;
  BN_CTX_free(bn);
  bn = NULL;
  pkey = EVP_PKEY_new();
  if (!pkey) {
    goto end;
  }
  if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
    goto end;
  }
  EC_KEY_free(ec);
  ec = NULL;
  *out = pkey;
  ret = 0;
end:
  if (pt) {
    EC_POINT_free(pt);
  }
  if (bn) {
    BN_CTX_free(bn);
  }
  if (ec) {
    EC_KEY_free(ec);
  }
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  return ret;
}

static int p256_keypair_from_priv32(const uint8_t *priv32, EVP_PKEY **out) {
  int ret = -1;
  EC_KEY *ec = NULL;
  BN_CTX *bn = NULL;
  BIGNUM *priv_bn = NULL;
  EC_POINT *pub_pt = NULL;
  EVP_PKEY *pkey = NULL;
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  bn = BN_CTX_new();
  priv_bn = BN_bin2bn(priv32, 32, NULL);
  if (!ec || !bn || !priv_bn) {
    goto end;
  }
  if (EC_KEY_set_private_key(ec, priv_bn) != 1) {
    goto end;
  }
  pub_pt = EC_POINT_new(EC_KEY_get0_group(ec));
  if (!pub_pt || EC_POINT_mul(EC_KEY_get0_group(ec), pub_pt, priv_bn, NULL, NULL, bn) != 1) {
    goto end;
  }
  if (EC_KEY_set_public_key(ec, pub_pt) != 1) {
    goto end;
  }
  EC_POINT_free(pub_pt);
  pub_pt = NULL;
  BN_free(priv_bn);
  priv_bn = NULL;
  BN_CTX_free(bn);
  bn = NULL;
  pkey = EVP_PKEY_new();
  if (!pkey) {
    goto end;
  }
  if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
    goto end;
  }
  EC_KEY_free(ec);
  ec = NULL;
  *out = pkey;
  ret = 0;
end:
  if (pub_pt) {
    EC_POINT_free(pub_pt);
  }
  if (priv_bn) {
    BN_free(priv_bn);
  }
  if (bn) {
    BN_CTX_free(bn);
  }
  if (ec) {
    EC_KEY_free(ec);
  }
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
  return ret;
}

static int p256_ecdh_derive(EVP_PKEY *local, EVP_PKEY *peer, uint8_t *secret, size_t cap, size_t *secret_len) {
  EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(local, NULL);
  size_t l = 0;
  if (!dctx) {
    return -1;
  }
  if (EVP_PKEY_derive_init(dctx) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return -1;
  }
  /* 与 `ECDH_compute_key(..., NULL)` 一致：原始共享密钥 */
  if (EVP_PKEY_CTX_set_ecdh_kdf_type(dctx, EVP_PKEY_ECDH_KDF_NONE) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return -1;
  }
  if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return -1;
  }
  if (EVP_PKEY_derive(dctx, NULL, &l) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return -1;
  }
  if (l > cap) {
    *secret_len = l;
    EVP_PKEY_CTX_free(dctx);
    return -2;
  }
  if (EVP_PKEY_derive(dctx, secret, &l) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return -1;
  }
  EVP_PKEY_CTX_free(dctx);
  *secret_len = l;
  return 0;
}

static int p256_export_enc_pubkey(EVP_PKEY *pkey, uint8_t *buf, size_t buf_cap, size_t *out_len) {
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, &len) != 1) {
    return -1;
  }
  if (buf_cap < len) {
    *out_len = len;
    return -2;
  }
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, buf_cap, &len) != 1) {
    return -1;
  }
  *out_len = len;
  return 0;
}

static int seal_fl3_ecdh(const uint8_t *plain, size_t plain_len, const uint8_t *srv_pub, size_t srv_pub_len,
                         uint8_t *out, size_t out_cap, size_t *out_len) {
  EVP_PKEY *cli = NULL;
  EVP_PKEY *peer = NULL;
  uint8_t shared[64];
  size_t shared_len = 0u;
  uint8_t aes_key[32];
  uint8_t iv[12];
  uint8_t cli_pub[72];
  size_t cli_pub_len = 0u;
  EVP_CIPHER_CTX *ctx = NULL;
  int n = 0;
  int ct_total = 0;
  size_t need;
  uint8_t *p;
  static const char hkdf_info[] = "edr-fl-gradient-v3";

  if (!plain || plain_len == 0u || !srv_pub || (srv_pub_len != 33u && srv_pub_len != 65u)) {
    return -1;
  }
  if (p256_gen_ephemeral(&cli) != 0) {
    goto fail;
  }
  if (p256_pubkey_from_sec1(srv_pub, srv_pub_len, &peer) != 0) {
    goto fail;
  }
  if (p256_ecdh_derive(cli, peer, shared, sizeof(shared), &shared_len) != 0) {
    goto fail;
  }
  if (hkdf_sha256_full(NULL, 0u, shared, shared_len, (const uint8_t *)hkdf_info, sizeof(hkdf_info) - 1u, aes_key,
                       sizeof(aes_key)) != 0) {
    goto fail;
  }
  if (p256_export_enc_pubkey(cli, cli_pub, sizeof(cli_pub), &cli_pub_len) != 0) {
    goto fail;
  }
  if (cli_pub_len != 65u && cli_pub_len != 33u) {
    goto fail;
  }
  if (RAND_bytes(iv, (int)sizeof(iv)) != 1) {
    goto fail;
  }
  need = 4u + 1u + cli_pub_len + sizeof(iv) + plain_len + 16u;
  if (out_cap < need) {
    *out_len = need;
    EVP_PKEY_free(cli);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    return -2;
  }
  p = out;
  memcpy(p, FL3_MAGIC, FL3_MAGIC_LEN);
  p[3] = (uint8_t)FL3_VERSION;
  p += 4u;
  p[0] = (uint8_t)cli_pub_len;
  p += 1u;
  memcpy(p, cli_pub, cli_pub_len);
  p += cli_pub_len;
  memcpy(p, iv, sizeof(iv));
  p += sizeof(iv);
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    goto fail;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
    goto fail;
  }
  if (EVP_EncryptUpdate(ctx, p, &n, plain, (int)plain_len) != 1) {
    goto fail;
  }
  ct_total = n;
  if (EVP_EncryptFinal_ex(ctx, p + ct_total, &n) != 1) {
    goto fail;
  }
  ct_total += n;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, p + ct_total) != 1) {
    goto fail;
  }
  EVP_CIPHER_CTX_free(ctx);
  ctx = NULL;
  *out_len = 4u + 1u + cli_pub_len + sizeof(iv) + (size_t)ct_total + 16u;
  EVP_PKEY_free(cli);
  EVP_PKEY_free(peer);
  OPENSSL_cleanse(shared, sizeof(shared));
  OPENSSL_cleanse(aes_key, sizeof(aes_key));
  return 0;

fail:
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  if (cli) {
    EVP_PKEY_free(cli);
  }
  if (peer) {
    EVP_PKEY_free(peer);
  }
  OPENSSL_cleanse(shared, sizeof(shared));
  OPENSSL_cleanse(aes_key, sizeof(aes_key));
  return -3;
}

int fl_crypto_coordinator_open_fl3(const uint8_t *coord_priv, size_t coord_priv_len, const uint8_t *blob,
                                   size_t blob_len, uint8_t *plain_out, size_t plain_cap, size_t *plain_len) {
  EVP_PKEY *srv = NULL;
  EVP_PKEY *peer = NULL;
  uint8_t shared[64];
  size_t shared_len = 0u;
  uint8_t aes_key[32];
  EVP_CIPHER_CTX *ctx = NULL;
  const uint8_t *cli_pub_bytes = NULL;
  size_t cli_pub_len = 0u;
  const uint8_t *iv = NULL;
  const uint8_t *ct = NULL;
  const uint8_t *tag = NULL;
  size_t ct_len = 0u;
  int n = 0;
  int n2 = 0;
  int pt = 0;
  static const char hkdf_info[] = "edr-fl-gradient-v3";

  if (!plain_len) {
    return -1;
  }
  if (!coord_priv || coord_priv_len != 32u || !blob) {
    *plain_len = 0u;
    return -1;
  }
  if (blob_len < 4u + 1u + 33u + 12u + 16u) {
    *plain_len = 0u;
    return -1;
  }
  if (memcmp(blob, FL3_MAGIC, FL3_MAGIC_LEN) != 0 || blob[3] != FL3_VERSION) {
    *plain_len = 0u;
    return -1;
  }
  cli_pub_len = (size_t)blob[4];
  if (cli_pub_len != 33u && cli_pub_len != 65u) {
    *plain_len = 0u;
    return -1;
  }
  if (blob_len < 4u + 1u + cli_pub_len + 12u + 16u) {
    *plain_len = 0u;
    return -1;
  }
  ct_len = blob_len - 4u - 1u - cli_pub_len - 12u - 16u;
  cli_pub_bytes = blob + 4u + 1u;
  iv = cli_pub_bytes + cli_pub_len;
  ct = iv + 12u;
  tag = ct + ct_len;

  if (p256_keypair_from_priv32(coord_priv, &srv) != 0) {
    goto fail;
  }
  if (p256_pubkey_from_sec1(cli_pub_bytes, cli_pub_len, &peer) != 0) {
    goto fail;
  }
  if (p256_ecdh_derive(srv, peer, shared, sizeof(shared), &shared_len) != 0) {
    goto fail;
  }
  if (hkdf_sha256_full(NULL, 0u, shared, shared_len, (const uint8_t *)hkdf_info, sizeof(hkdf_info) - 1u, aes_key,
                       sizeof(aes_key)) != 0) {
    goto fail;
  }
  if (!plain_out) {
    *plain_len = ct_len;
    EVP_PKEY_free(srv);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    return 0;
  }
  if (plain_cap < ct_len) {
    *plain_len = ct_len;
    EVP_PKEY_free(srv);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    return -2;
  }
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    goto fail;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
    goto fail;
  }
  if (EVP_DecryptUpdate(ctx, plain_out, &n, ct, (int)ct_len) != 1) {
    goto fail;
  }
  pt = n;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
    goto fail;
  }
  if (EVP_DecryptFinal_ex(ctx, plain_out + pt, &n2) != 1) {
    goto fail;
  }
  pt += n2;
  EVP_CIPHER_CTX_free(ctx);
  ctx = NULL;
  *plain_len = (size_t)pt;
  EVP_PKEY_free(srv);
  EVP_PKEY_free(peer);
  OPENSSL_cleanse(shared, sizeof(shared));
  OPENSSL_cleanse(aes_key, sizeof(aes_key));
  return 0;

fail:
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  if (srv) {
    EVP_PKEY_free(srv);
  }
  if (peer) {
    EVP_PKEY_free(peer);
  }
  OPENSSL_cleanse(shared, sizeof(shared));
  OPENSSL_cleanse(aes_key, sizeof(aes_key));
  *plain_len = 0u;
  return -3;
}

/**
 * FL2 legacy：明文 aes_key 附尾（仅当 `EDR_FL_CRYPTO_ALLOW_INSECURE_FL2=1`）。
 */
static int seal_openssl_fl2_legacy(const uint8_t *plain, size_t plain_len, uint8_t *out, size_t out_cap,
                                   size_t *out_len) {
  uint8_t key[32];
  uint8_t iv[12];
  EVP_CIPHER_CTX *ctx = NULL;
  int n = 0;
  int ct_total = 0;
  size_t need;
  uint8_t *p;

  if (RAND_bytes(key, (int)sizeof(key)) != 1 || RAND_bytes(iv, (int)sizeof(iv)) != 1) {
    return -3;
  }
  need = 4u + sizeof(iv) + plain_len + 16u + sizeof(key);
  if (out_cap < need) {
    *out_len = need;
    return -2;
  }
  p = out;
  memcpy(p, FL2_MAGIC, FL2_MAGIC_LEN);
  p[3] = (uint8_t)FL2_VERSION;
  p += 4u;
  memcpy(p, iv, sizeof(iv));
  p += sizeof(iv);
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return -3;
  }
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  if (EVP_EncryptUpdate(ctx, p, &n, plain, (int)plain_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  ct_total = n;
  if (EVP_EncryptFinal_ex(ctx, p + ct_total, &n) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  ct_total += n;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, p + ct_total) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  EVP_CIPHER_CTX_free(ctx);
  memcpy(p + ct_total + 16u, key, sizeof(key));
  *out_len = 4u + sizeof(iv) + (size_t)ct_total + 16u + sizeof(key);
  return 0;
}

static int open_openssl_fl2_legacy(const uint8_t *blob, size_t blob_len, uint8_t *plain_out, size_t plain_cap,
                                   size_t *plain_len) {
  const uint8_t *iv;
  const uint8_t *ct;
  const uint8_t *tag;
  const uint8_t *key;
  size_t ct_len;
  EVP_CIPHER_CTX *ctx = NULL;
  int n = 0;
  int pt = 0;

  if (blob_len < 4u + 12u + 16u + 32u) {
    return -1;
  }
  if (memcmp(blob, FL2_MAGIC, FL2_MAGIC_LEN) != 0 || blob[3] != FL2_VERSION) {
    return -1;
  }
  iv = blob + 4u;
  ct_len = blob_len - 4u - 12u - 16u - 32u;
  ct = iv + 12u;
  tag = ct + ct_len;
  key = tag + 16u;
  if (plain_out && plain_cap < ct_len) {
    *plain_len = ct_len;
    return -2;
  }
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return -3;
  }
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  if (!plain_out) {
    *plain_len = ct_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  if (EVP_DecryptUpdate(ctx, plain_out, &n, ct, (int)ct_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  pt = n;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  if (EVP_DecryptFinal_ex(ctx, plain_out + pt, &n) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return -3;
  }
  pt += n;
  EVP_CIPHER_CTX_free(ctx);
  *plain_len = (size_t)pt;
  return 0;
}
#else
void fl_crypto_set_coordinator_pubkey(const uint8_t *pub, size_t pub_len) {
  (void)pub;
  (void)pub_len;
}

int fl_crypto_coordinator_open_fl3(const uint8_t *coord_priv, size_t coord_priv_len, const uint8_t *blob,
                                   size_t blob_len, uint8_t *plain_out, size_t plain_cap, size_t *plain_len) {
  (void)coord_priv;
  (void)coord_priv_len;
  (void)blob;
  (void)blob_len;
  (void)plain_out;
  (void)plain_cap;
  if (plain_len) {
    *plain_len = 0u;
  }
  return -1;
}
#endif

int fl_crypto_seal_gradient(const uint8_t *plain, size_t plain_len, uint8_t *out, size_t out_cap,
                            size_t *out_len) {
  size_t need = FLSTUB_MAGIC_LEN + plain_len;
  if (!plain || !out || !out_len) {
    return -1;
  }
  if (plain_len == 0u) {
    return -1;
  }
#ifdef EDR_HAVE_OPENSSL_FL
  {
    const char *env = getenv("EDR_FL_CRYPTO_OPENSSL");
    if (env && env[0] == '1') {
      if (s_coord_pub_len == 33u || s_coord_pub_len == 65u) {
        return seal_fl3_ecdh(plain, plain_len, s_coord_pub, s_coord_pub_len, out, out_cap, out_len);
      }
      {
        const char *allow = getenv("EDR_FL_CRYPTO_ALLOW_INSECURE_FL2");
        if (allow && allow[0] == '1') {
          return seal_openssl_fl2_legacy(plain, plain_len, out, out_cap, out_len);
        }
      }
      return -4;
    }
  }
#endif
  if (out_cap < need) {
    *out_len = need;
    return -2;
  }
  memcpy(out, FLSTUB_MAGIC, FLSTUB_MAGIC_LEN);
  memcpy(out + FLSTUB_MAGIC_LEN, plain, plain_len);
  *out_len = need;
  return 0;
}

int fl_crypto_open_gradient(const uint8_t *blob, size_t blob_len, uint8_t *plain_out, size_t plain_cap,
                            size_t *plain_len) {
  if (!blob || !plain_len) {
    return -1;
  }
#ifdef EDR_HAVE_OPENSSL_FL
  if (blob_len >= FL3_MAGIC_LEN && memcmp(blob, FL3_MAGIC, FL3_MAGIC_LEN) == 0 && blob[3] == FL3_VERSION) {
    (void)plain_out;
    (void)plain_cap;
    *plain_len = 0;
    return -5;
  }
  if (blob_len >= FL2_MAGIC_LEN && memcmp(blob, FL2_MAGIC, FL2_MAGIC_LEN) == 0) {
    return open_openssl_fl2_legacy(blob, blob_len, plain_out, plain_cap, plain_len);
  }
#endif
  if (blob_len <= FLSTUB_MAGIC_LEN) {
    return -1;
  }
  if (memcmp(blob, FLSTUB_MAGIC, FLSTUB_MAGIC_LEN) != 0) {
    return -1;
  }
  *plain_len = blob_len - FLSTUB_MAGIC_LEN;
  if (!plain_out) {
    return 0;
  }
  if (plain_cap < *plain_len) {
    return -2;
  }
  memcpy(plain_out, blob + FLSTUB_MAGIC_LEN, *plain_len);
  return 0;
}
