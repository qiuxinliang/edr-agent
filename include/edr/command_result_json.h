#ifndef EDR_COMMAND_RESULT_JSON_H
#define EDR_COMMAND_RESULT_JSON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Builds the HTTP command-result contract consumed by PostReportCommandResult. */
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
                                   const char *playbook_step_id);

void edr_command_result_json_free(char *json);

#ifdef __cplusplus
}
#endif

#endif
