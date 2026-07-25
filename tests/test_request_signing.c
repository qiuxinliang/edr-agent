#include "edr/request_signing.h"

#include <stdio.h>
#include <string.h>

static int expect_str(const char *name, const char *got, const char *want) {
  if (strcmp(got, want) != 0) {
    fprintf(stderr, "%s mismatch\n got: %s\nwant: %s\n", name, got, want);
    return 1;
  }
  return 0;
}

int main(void) {
  char canonical[512];
  char mac[65];
  char headers[1024];
  char headers_second[1024];
  EdrRequestSigningConfig cfg;
  char nonces[64][33];

  for (size_t i = 0u; i < sizeof(nonces) / sizeof(nonces[0]); i++) {
    if (edr_reqsig_random_nonce_hex(nonces[i]) != 0 || strlen(nonces[i]) != 32u) {
      fprintf(stderr, "secure nonce generation failed at %zu\n", i);
      return 1;
    }
    for (size_t j = 0u; j < i; j++) {
      if (strcmp(nonces[i], nonces[j]) == 0) {
        fprintf(stderr, "duplicate request nonce at %zu/%zu\n", j, i);
        return 1;
      }
    }
  }

  const char *poll_path =
      "/api/v1/ingest/poll-commands?endpoint_id=ep-1&limit=8&wait_s=5&agent_version=3.2.228&dict_ver=edr-zstd-dict-v1&schema_ver=edr-control-schema-v1&profile_id=default-h2-zstd&h2=1&zstd=1";
  if (edr_reqsig_canonical("get", poll_path,
                           "1700000000000", "00112233445566778899aabbccddeeff",
                           EDR_REQSIG_EMPTY_BODY_SHA256, "ep-1",
                           canonical, sizeof(canonical)) != 0) {
    fprintf(stderr, "canonical build failed\n");
    return 1;
  }
  if (expect_str("canonical", canonical,
                 "REQSIG-V1\nGET\n/api/v1/ingest/poll-commands?endpoint_id=ep-1&limit=8&wait_s=5&agent_version=3.2.228&dict_ver=edr-zstd-dict-v1&schema_ver=edr-control-schema-v1&profile_id=default-h2-zstd&h2=1&zstd=1\n1700000000000\n00112233445566778899aabbccddeeff\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nep-1")) {
    return 1;
  }

  if (edr_reqsig_hmac_sha256_hex((const unsigned char *)"key", 3u,
                                 (const unsigned char *)"The quick brown fox jumps over the lazy dog", 43u,
                                 mac) != 0) {
    fprintf(stderr, "hmac failed\n");
    return 1;
  }
  if (expect_str("hmac", mac, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")) {
    return 1;
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.enabled = 1;
  snprintf(cfg.key_id, sizeof(cfg.key_id), "%s", "reqsig_test");
  snprintf(cfg.secret, sizeof(cfg.secret), "%s", "a2V5");
  if (edr_reqsig_build_headers(&cfg, "GET", poll_path,
                               "ep-1", NULL, 0u, 1700000000000LL,
                               headers, sizeof(headers)) != 0) {
    fprintf(stderr, "header build failed\n");
    return 1;
  }
  if (!strstr(headers, "X-EDR-Signature-Version: reqsig-v1\r\n") ||
      !strstr(headers, "X-EDR-Key-ID: reqsig_test\r\n") ||
      !strstr(headers, "X-EDR-Timestamp-Ms: 1700000000000\r\n") ||
      !strstr(headers, "X-EDR-Nonce: ") ||
      !strstr(headers, "X-EDR-Content-SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n") ||
      !strstr(headers, "X-EDR-Signature: ")) {
    fprintf(stderr, "missing expected request signing headers:\n%s\n", headers);
    return 1;
  }
  if (edr_reqsig_build_headers(&cfg, "GET", poll_path,
                               "ep-1", NULL, 0u, 1700000000000LL,
                               headers_second, sizeof(headers_second)) != 0 ||
      strcmp(headers, headers_second) == 0) {
    fprintf(stderr, "independent signing attempts must produce fresh headers\n");
    return 1;
  }
  memset(headers, 0, sizeof(headers));
  if (edr_reqsig_build_headers_from_hash(&cfg, "GET", poll_path, "ep-1",
                                         EDR_REQSIG_EMPTY_BODY_SHA256,
                                         1700000000000LL, headers, sizeof(headers)) != 0 ||
      !strstr(headers, "X-EDR-Content-SHA256: " EDR_REQSIG_EMPTY_BODY_SHA256 "\r\n") ||
      !strstr(headers, "X-EDR-Signature: ")) {
    fprintf(stderr, "pre-hashed header build failed:\n%s\n", headers);
    return 1;
  }
  return 0;
}
