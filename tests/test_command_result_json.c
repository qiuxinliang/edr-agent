#include "edr/command_result_json.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_true(int ok, const char *message) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
  }
}

static void verify_type(const char *command_type) {
  char *json = edr_command_result_http_json(
      "ep-contract", "3.2.227", "cmd-contract", command_type, 1, 0,
      "line 1\n\"quoted\" \\ path", 1783924000123LL, "corr", "run", "step");
  require_true(json != NULL, "serialize command result");

  cJSON *root = cJSON_Parse(json);
  require_true(cJSON_IsObject(root), "serialized result is valid JSON");
  cJSON *result = cJSON_GetObjectItemCaseSensitive(root, "result");
  require_true(cJSON_IsObject(result), "result object exists");
  cJSON *type = cJSON_GetObjectItemCaseSensitive(result, "command_type");
  require_true(cJSON_IsString(type) && strcmp(type->valuestring, command_type) == 0,
               "command_type is a JSON string");
  cJSON *detail = cJSON_GetObjectItemCaseSensitive(result, "detail_utf8");
  require_true(cJSON_IsString(detail) && strstr(detail->valuestring, "quoted") != NULL,
               "detail round trips through JSON escaping");

  cJSON_Delete(root);
  edr_command_result_json_free(json);
}

static void verify_http_ack_contract(void) {
  require_true(edr_command_result_http_response_acked(
                   "{\"code\":\"OK\",\"data\":{\"accepted\":true,\"complete\":true},"
                   "\"message\":\"success\"}"),
               "current backend success envelope is accepted");
  require_true(edr_command_result_http_response_acked(
                   "{\"accepted\":true,\"complete\":true}"),
               "legacy top-level success envelope is accepted");
  require_true(edr_command_result_http_response_acked(
                   "{\"accepted\":true,\"complete\":true,\"data\":{\"message\":\"success\"}}"),
               "legacy ACK survives an unrelated standard data envelope");
  require_true(!edr_command_result_http_response_acked(
                   "{\"accepted\":true,\"complete\":true,"
                   "\"data\":{\"accepted\":false,\"complete\":true}}"),
               "explicit nested ACK remains authoritative");
  require_true(!edr_command_result_http_response_acked(
                   "{\"accepted\":true,\"complete\":true,\"data\":{\"complete\":false}}"),
               "nested incomplete state cannot be masked by a root ACK");
  require_true(edr_command_result_http_response_acked("{\"accepted\":true}"),
               "complete may be omitted after accepted");
  require_true(!edr_command_result_http_response_acked(
                   "{\"code\":\"OK\",\"data\":{\"accepted\":true,\"complete\":false}}"),
               "explicit incomplete response is rejected");
  require_true(edr_command_result_http_chunk_response_acked(
                   "{\"code\":\"OK\",\"data\":{\"accepted\":true,\"complete\":false}}"),
               "chunk sender accepts an explicit incomplete acknowledgement");
  require_true(edr_command_result_http_chunk_response_acked(
                   "{\"code\":\"OK\",\"data\":{\"accepted\":true,\"complete\":true}}"),
               "chunk sender accepts an already complete acknowledgement");
  require_true(!edr_command_result_http_chunk_response_acked(
                   "{\"code\":\"OK\",\"data\":{\"accepted\":false,\"complete\":false}}"),
               "chunk sender rejects a negative acknowledgement");
  require_true(!edr_command_result_http_response_acked(
                   "{\"code\":\"OK\",\"message\":\"success\"}"),
               "transport success without application ack is rejected");
  require_true(!edr_command_result_http_response_acked("not-json"),
               "malformed response is rejected");
  require_true(!edr_command_result_http_response_acked(NULL),
               "missing response is rejected");
}

int main(void) {
  verify_type("rtq_execute");
  verify_type("rtr_shell");
  verify_type("velo_query");
  verify_type("targeted_forensic");
  verify_http_ack_contract();
  printf("ok\n");
  return 0;
}
