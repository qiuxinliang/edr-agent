#include "edr/command_result_json.h"

#include "cJSON.h"

static const char *non_null(const char *value) { return value ? value : ""; }

char *edr_command_result_http_json(const char *endpoint_id,
                                   const char *agent_version,
                                   const char *command_id,
                                   const char *command_type,
                                   int execution_status,
                                   int exit_code,
                                   const char *detail_utf8,
                                   int64_t finished_unix_ms,
                                   const char *soar_correlation_id,
                                   const char *playbook_run_id,
                                   const char *playbook_step_id) {
  cJSON *root = cJSON_CreateObject();
  cJSON *result = cJSON_CreateObject();
  if (!root || !result) {
    cJSON_Delete(root);
    cJSON_Delete(result);
    return NULL;
  }

  cJSON_AddStringToObject(root, "endpoint_id", non_null(endpoint_id));
  cJSON_AddItemToObject(root, "result", result);
  cJSON_AddStringToObject(result, "command_id", non_null(command_id));
  cJSON_AddStringToObject(result, "command_type", non_null(command_type));
  cJSON_AddStringToObject(result, "endpoint_id", non_null(endpoint_id));
  cJSON_AddStringToObject(result, "agent_version", non_null(agent_version));
  cJSON_AddNumberToObject(result, "status", execution_status);
  cJSON_AddNumberToObject(result, "exit_code", exit_code);
  cJSON_AddStringToObject(result, "detail_utf8", non_null(detail_utf8));
  cJSON_AddNumberToObject(result, "finished_unix_ms", (double)finished_unix_ms);
  cJSON_AddStringToObject(result, "soar_correlation_id", non_null(soar_correlation_id));
  cJSON_AddStringToObject(result, "playbook_run_id", non_null(playbook_run_id));
  cJSON_AddStringToObject(result, "playbook_step_id", non_null(playbook_step_id));

  char *json = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  return json;
}

void edr_command_result_json_free(char *json) { cJSON_free(json); }
