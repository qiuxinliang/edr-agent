/**
 * FL3：ECDH+HKDF+GCM 封装自检（需 OpenSSL 3 + EDR_HAVE_OPENSSL_FL，`EVP_PKEY` 路径）。
 */
#include "edr/fl_crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
#ifndef EDR_HAVE_OPENSSL_FL
  fprintf(stderr, "skip: no OpenSSL FL\n");
  return 0;
#else
  EVP_PKEY_CTX *kctx = NULL;
  EVP_PKEY *srv = NULL;
  uint8_t pub[72];
  uint8_t priv32[32];
  BIGNUM *priv_bn = NULL;
  size_t pub_len = 0;
  uint8_t plain[16];
  uint8_t out[512];
  uint8_t opened[32];
  size_t out_len = 0;
  size_t plen = 0;
  size_t olen = 0;

  kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0 || EVP_PKEY_keygen(kctx, &srv) <= 0) {
    fprintf(stderr, "EVP_PKEY keygen failed\n");
    if (kctx) {
      EVP_PKEY_CTX_free(kctx);
    }
    EVP_PKEY_free(srv);
    return 1;
  }
  EVP_PKEY_CTX_free(kctx);
  kctx = NULL;

  if (EVP_PKEY_get_octet_string_param(srv, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, sizeof(pub), &pub_len) != 1) {
    fprintf(stderr, "pub export failed\n");
    EVP_PKEY_free(srv);
    return 1;
  }
  if (EVP_PKEY_get_bn_param(srv, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) != 1 || !priv_bn ||
      BN_bn2binpad(priv_bn, priv32, (int)sizeof(priv32)) != (int)sizeof(priv32)) {
    fprintf(stderr, "priv export failed\n");
    BN_free(priv_bn);
    EVP_PKEY_free(srv);
    return 1;
  }
  BN_free(priv_bn);
  priv_bn = NULL;
  EVP_PKEY_free(srv);
  srv = NULL;

  if (pub_len != 33u && pub_len != 65u) {
    fprintf(stderr, "unexpected pub_len %zu\n", pub_len);
    return 1;
  }

  fl_crypto_set_coordinator_pubkey(pub, pub_len);
  if (setenv("EDR_FL_CRYPTO_OPENSSL", "1", 1) != 0) {
    return 1;
  }

  memset(plain, 0xab, sizeof(plain));
  if (fl_crypto_seal_gradient(plain, sizeof(plain), out, sizeof(out), &out_len) != 0) {
    fprintf(stderr, "seal failed\n");
    return 1;
  }
  if (out_len < 80u || memcmp(out, "FL3", 3) != 0 || out[3] != 2u) {
    fprintf(stderr, "bad FL3 header\n");
    return 1;
  }
  if (fl_crypto_open_gradient(out, out_len, NULL, 0, &plen) != -5) {
    fprintf(stderr, "open FL3 should return -5 on agent\n");
    return 1;
  }
  olen = 0u;
  if (fl_crypto_coordinator_open_fl3(priv32, sizeof(priv32), out, out_len, opened, sizeof(opened), &olen) != 0) {
    fprintf(stderr, "coordinator_open_fl3 failed\n");
    return 1;
  }
  if (olen != sizeof(plain) || memcmp(opened, plain, sizeof(plain)) != 0) {
    fprintf(stderr, "coordinator plaintext mismatch\n");
    return 1;
  }
  fl_crypto_set_coordinator_pubkey(NULL, 0);
  fprintf(stderr, "fl_crypto_fl3 ok\n");
  return 0;
#endif
}
