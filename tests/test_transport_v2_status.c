#include "edr/ingest_http.h"
#include "edr/transport_v2.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
static int s_http_result;

_Static_assert(sizeof(((EdrTransportV2Runtime *)0)->envelope_format) >=
                   sizeof("protobuf:edr.transport.envelope.v1"),
               "transport v2 runtime must retain the complete envelope format");

int edr_ingest_http_post_report_events(const char *batch_id, const uint8_t *header12, size_t header_len,
                                       const uint8_t *payload, size_t payload_len) {
  (void)batch_id;
  (void)header12;
  (void)header_len;
  (void)payload;
  (void)payload_len;
  return s_http_result;
}

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
  }
}

int edr_ingest_http_post_command_result_typed(const char *command_id, const char *command_type,
                                              const struct EdrSoarCommandMeta *meta,
                                              int execution_status, int exit_code,
                                              const char *detail_utf8) {
  (void)command_id;
  (void)command_type;
  (void)meta;
  (void)execution_status;
  (void)exit_code;
  (void)detail_utf8;
  return s_http_result;
}

void edr_ingest_http_get_last_command_result_delivery_error(char *out, size_t cap, int *retryable) {
  if (out && cap > 0u) {
    out[0] = '\0';
  }
  if (retryable) {
    *retryable = 1;
  }
}

int edr_ingest_http_upload_file_multipart_for_command(const char *command_id,
                                                      const char *upload_id,
                                                      const char *file_path,
                                                      const char *sha256_hex,
                                                      char *out_minio_key,
                                                      size_t out_minio_key_cap) {
  (void)command_id;
  (void)upload_id;
  (void)file_path;
  (void)sha256_hex;
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  return s_http_result;
}

static int expect_text(const char *name, const char *got, const char *want) {
  if (strcmp(got, want) != 0) {
    fprintf(stderr, "%s: got '%s', want '%s'\n", name, got, want);
    return 0;
  }
  return 1;
}

int main(void) {
  EdrTransportV2Config before;
  EdrTransportV2Config after;
  EdrTransportV2Runtime runtime;
  char overlong_dict[sizeof(before.dict_ver) + 1u];

  edr_transport_v2_init_from_config(NULL);
  memset(&runtime, 0, sizeof(runtime));
  edr_transport_v2_get_runtime(&runtime);
  if (!expect_text("envelope format", runtime.envelope_format, "protobuf:edr.transport.envelope.v1")) {
    return 1;
  }

  memset(&before, 0, sizeof(before));
  edr_transport_v2_get_config(&before);
  memset(overlong_dict, 'x', sizeof(overlong_dict) - 1u);
  overlong_dict[sizeof(overlong_dict) - 1u] = '\0';
  edr_transport_v2_apply_profile(overlong_dict, "new-schema", "new-profile", 0, 1, "CS1", 17u,
                                 "low", 0);
  memset(&after, 0, sizeof(after));
  edr_transport_v2_get_config(&after);
  if (memcmp(&before, &after, sizeof(before)) != 0) {
    fprintf(stderr, "overlong profile changed transport configuration\n");
    return 1;
  }
  memset(&runtime, 0, sizeof(runtime));
  edr_transport_v2_get_runtime(&runtime);
  if (!expect_text("profile rejection", runtime.last_error,
                   "transport profile value exceeds field capacity")) {
    return 1;
  }

  edr_transport_v2_on_control(overlong_dict);
  memset(&runtime, 0, sizeof(runtime));
  edr_transport_v2_get_runtime(&runtime);
  if (!expect_text("control frame marker", runtime.last_operation, "overlong_control_frame") ||
      !expect_text("control frame rejection", runtime.last_error,
                   "control frame type exceeds status capacity")) {
    return 1;
  }
  const uint8_t header[12] = {0}, payload[1] = {1};
  s_http_result = -1;
  assert(edr_transport_v2_report_events("fixture", header, sizeof(header), payload, 1u) == -1);
  edr_transport_v2_get_runtime(&runtime);
  assert(runtime.send_attempts == 1u && runtime.send_ok == 0u && runtime.send_fail == 1u);
  s_http_result = 0;
  assert(edr_transport_v2_report_events("fixture", header, sizeof(header), payload, 1u) == 0);
  assert(edr_transport_v2_command_result("fixture", NULL, 0, 0, "ok") == 0);
  assert(edr_transport_v2_upload_file("fixture", "fixture-path", "hash", NULL, 0u) == 0);
  s_http_result = -1;
  assert(edr_transport_v2_upload_file_for_command("command", "fixture", "path", "hash", NULL, 0u) == -1);
  assert(edr_transport_v2_command_result("fixture", NULL, 0, 0, "failed") == -1);
  edr_transport_v2_get_runtime(&runtime);
  assert(runtime.send_attempts == 6u && runtime.send_ok == 3u && runtime.send_fail == 3u);
  return 0;
}
