#include "edr/encrypt_p0_rules.h"
#include "edr/p0_rule_ir.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const uint8_t *data, size_t len) {
  while (len > 0u) {
    ssize_t n = write(fd, data, len);
    if (n <= 0) return 0;
    data += (size_t)n;
    len -= (size_t)n;
  }
  return 1;
}

static int make_valid_plaintext(size_t len, uint8_t **out) {
  static const char document[] =
      "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":3,"
      "\"rules_bundle_version\":\"boundary-v1\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":"
      "\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"sensor_interest_manifest_hash_mode\":"
      "\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"boundary\",\"event_type\":\"process_create\","
      "\"condition\":{\"process_name_in\":[\"boundary.exe\"]}}]}";
  size_t document_len = sizeof(document) - 1u;
  uint8_t *plain;
  if (!out || len < document_len) return 0;
  plain = (uint8_t *)malloc(len);
  if (!plain) return 0;
  memcpy(plain, document, document_len);
  memset(plain + document_len, ' ', len - document_len);
  *out = plain;
  return 1;
}

static int make_missing_binding_plaintext(size_t len, uint8_t **out) {
  static const char document[] =
      "{\"rules\":[{\"id\":\"boundary\",\"event_type\":\"process_create\","
      "\"condition\":{\"process_name_in\":[\"boundary.exe\"]}}]}";
  size_t document_len = sizeof(document) - 1u;
  uint8_t *plain;
  if (!out || len < document_len) return 0;
  plain = (uint8_t *)malloc(len);
  if (!plain) return 0;
  memcpy(plain, document, document_len);
  memset(plain + document_len, ' ', len - document_len);
  *out = plain;
  return 1;
}

static int validate_envelope(size_t plain_len, int expect_valid) {
  char path[] = "/tmp/edr-p0-envelope-XXXXXX";
  uint8_t *plain = NULL;
  uint8_t *envelope = NULL;
  size_t envelope_len = 0u;
  int fd = -1;
  int ok = 0;

  if (!make_valid_plaintext(plain_len, &plain) ||
      edr_p0_encrypt_encrypt_edr1_for_test(plain, plain_len, &envelope, &envelope_len) != 0) {
    goto done;
  }
  if (envelope_len != plain_len + EDR_P0_ENCRYPT_OVERHEAD) goto done;
  fd = mkstemp(path);
  if (fd < 0 || !write_all(fd, envelope, envelope_len) || close(fd) != 0) {
    if (fd >= 0) close(fd);
    fd = -1;
    goto done;
  }
  fd = -1;
  ok = edr_p0_rule_ir_validate_candidate_path(path) == expect_valid;
done:
  if (fd >= 0) close(fd);
  unlink(path);
  free(envelope);
  free(plain);
  return ok;
}

static int validate_missing_binding_envelope(void) {
  char path[] = "/tmp/edr-p0-envelope-XXXXXX";
  uint8_t *plain = NULL;
  uint8_t *envelope = NULL;
  size_t envelope_len = 0u;
  int fd = -1;
  int ok = 0;

  if (!make_missing_binding_plaintext(EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES, &plain) ||
      edr_p0_encrypt_encrypt_edr1_for_test(plain, EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES,
                                            &envelope, &envelope_len) != 0) {
    goto done;
  }
  fd = mkstemp(path);
  if (fd < 0 || !write_all(fd, envelope, envelope_len) || close(fd) != 0) {
    if (fd >= 0) close(fd);
    fd = -1;
    goto done;
  }
  fd = -1;
  ok = edr_p0_rule_ir_validate_candidate_path(path) == 0;
done:
  if (fd >= 0) close(fd);
  unlink(path);
  free(envelope);
  free(plain);
  return ok;
}

int main(void) {
  if (EDR_P0_ENCRYPT_OVERHEAD != 32u ||
      EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES + EDR_P0_ENCRYPT_OVERHEAD !=
          EDR_P0_ENCRYPT_ENVELOPE_MAX_BYTES) {
    fprintf(stderr, "invalid EDR1 size constants\n");
    return 1;
  }
  if (!validate_envelope(EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES, 1)) {
    fprintf(stderr, "4MiB-32 plaintext / 4MiB envelope must be accepted\n");
    return 1;
  }
  if (!validate_envelope(EDR_P0_ENCRYPT_PLAINTEXT_MAX_BYTES + 1u, 0)) {
    fprintf(stderr, "4MiB-31 plaintext / oversized envelope must be rejected\n");
    return 1;
  }
  if (!validate_missing_binding_envelope()) {
    fprintf(stderr, "4MiB envelope with missing artifact binding must be rejected\n");
    return 1;
  }
  return 0;
}
