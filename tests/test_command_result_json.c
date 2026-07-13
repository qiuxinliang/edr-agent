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

int main(void) {
  verify_type("rtq_execute");
  verify_type("rtr_shell");
  verify_type("velo_query");
  verify_type("targeted_forensic");
  printf("ok\n");
  return 0;
}
