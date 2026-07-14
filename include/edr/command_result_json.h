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

/** Returns non-zero only when an HTTP response contains a positive application ACK. */
int edr_command_result_http_response_acked(const char *json);

/** Returns non-zero when a non-terminal chunk was accepted. A complete ACK is
 * also accepted so retrying a chunk after server-side assembly remains safe. */
int edr_command_result_http_chunk_response_acked(const char *json);

void edr_command_result_json_free(char *json);

#ifdef __cplusplus
}
#endif

#endif
