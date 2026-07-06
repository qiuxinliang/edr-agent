#ifndef EDR_REQUEST_SIGNING_H
#define EDR_REQUEST_SIGNING_H

#include <stddef.h>
#include <stdint.h>

#define EDR_REQSIG_VERSION "reqsig-v1"
#define EDR_REQSIG_EMPTY_BODY_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

typedef struct EdrRequestSigningConfig {
  int enabled;
  char key_id[128];
  char secret[256];
} EdrRequestSigningConfig;

int edr_reqsig_body_sha256_hex(const uint8_t *body, size_t body_len, char out65[65]);
int edr_reqsig_canonical(const char *method, const char *path_with_query,
                         const char *timestamp_ms, const char *nonce,
                         const char *content_sha256_hex, const char *endpoint_id,
                         char *out, size_t out_cap);
int edr_reqsig_hmac_sha256_hex(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               char out65[65]);
int edr_reqsig_secret_decode(const char *secret, uint8_t *out, size_t out_cap, size_t *out_len);
int edr_reqsig_random_nonce_hex(char out33[33]);
int edr_reqsig_build_headers(const EdrRequestSigningConfig *cfg,
                             const char *method, const char *path_with_query,
                             const char *endpoint_id,
                             const uint8_t *body, size_t body_len,
                             int64_t timestamp_ms,
                             char *out, size_t out_cap);

#endif
