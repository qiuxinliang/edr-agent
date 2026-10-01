#include "edr/report_events_ack.h"
#include "edr/sha256.h"
#include "cJSON.h"
#include <string.h>

static int string_is(const cJSON *object, const char *key, const char *expected) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  return cJSON_IsString(value) && value->valuestring && !strcmp(value->valuestring, expected);
}

int edr_report_events_acknowledged(const char *response, const char *endpoint_id,
                                   const char *batch_id, const uint8_t *header,
                                   size_t header_len, const uint8_t *payload, size_t payload_len) {
  cJSON *root;
  const cJSON *data, *ack, *version, *accepted, *invalid;
  EdrSha256Ctx hash;
  uint8_t digest[32];
  char hex[65];
  static const char digits[] = "0123456789abcdef";
  int ok;
  if (!response || !endpoint_id || !endpoint_id[0] || !batch_id || !batch_id[0] ||
      !header || header_len != 12u || !payload || !payload_len) return 0;
  root = cJSON_ParseWithOpts(response, NULL, 1);
  if (!root) return 0;
  data = cJSON_GetObjectItemCaseSensitive(root, "data");
  ack = cJSON_GetObjectItemCaseSensitive(data, "ack");
  version = cJSON_GetObjectItemCaseSensitive(ack, "version");
  accepted = cJSON_GetObjectItemCaseSensitive(data, "accepted");
  invalid = cJSON_GetObjectItemCaseSensitive(data, "invalid_frames");
  edr_sha256_init(&hash);
  edr_sha256_update(&hash, header, header_len);
  edr_sha256_update(&hash, payload, payload_len);
  edr_sha256_final(&hash, digest);
  for (size_t i = 0; i < sizeof(digest); ++i) {
    hex[2*i] = digits[digest[i] >> 4]; hex[2*i+1] = digits[digest[i] & 15];
  }
  hex[64] = 0;
  ok = string_is(root, "code", "OK") && cJSON_IsObject(data) && cJSON_IsObject(ack) &&
       cJSON_IsNumber(version) && version->valuedouble == 1 &&
       (cJSON_IsTrue(accepted) || (cJSON_IsNumber(accepted) && accepted->valuedouble > 0)) &&
       (!invalid || (cJSON_IsNumber(invalid) && invalid->valuedouble == 0)) &&
       (string_is(ack, "state", "durable") || string_is(ack, "state", "processed")) &&
       string_is(ack, "endpoint_id", endpoint_id) && string_is(ack, "batch_id", batch_id) &&
       string_is(ack, "payload_sha256", hex);
  cJSON_Delete(root);
  return ok;
}
