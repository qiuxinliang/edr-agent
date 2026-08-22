#include "edr/response_capability_manifest.h"
#include "cJSON.h"

#include <stdio.h>
#include <string.h>

static int check_case(int supported, int dangerous, const char *runtime) {
  char entries[2048];
  if (edr_response_capability_manifest_json(supported, dangerous, entries, sizeof(entries)) < 0) return 0;
  char json[2200];
  snprintf(json, sizeof(json), "{%s\"end\":true}", entries);
  cJSON *root = cJSON_Parse(json);
  if (!root) return 0;
  const char *names[] = {"isolate_host", "restore_host", "kill_process"};
  int ok = 1;
  for (size_t i = 0; i < 3; ++i) {
    cJSON *row = cJSON_GetObjectItemCaseSensitive(root, names[i]);
    ok = ok && row && cJSON_IsTrue(cJSON_GetObjectItem(row, "code_supported"));
    ok = ok && (cJSON_IsTrue(cJSON_GetObjectItem(row, "build_supported")) == supported);
    ok = ok && (cJSON_IsTrue(cJSON_GetObjectItem(row, "policy_enabled")) == dangerous);
    cJSON *status = cJSON_GetObjectItem(row, "runtime_status");
    ok = ok && cJSON_IsString(status) && strcmp(status->valuestring, runtime) == 0;
  }
  cJSON_Delete(root);
  return ok;
}

int main(void) {
  if (!check_case(1, 1, "healthy")) return 1;
  if (!check_case(1, 0, "disabled")) return 1;
  if (!check_case(0, 1, "unavailable")) return 1;
  if (!check_case(0, 0, "unavailable")) return 1;
  return 0;
}
