#ifndef EDR_SHELL_EXEC_H
#define EDR_SHELL_EXEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int edr_shell_is_allowed(const char *command);

int edr_shell_exec(const char *command, int timeout_sec,
                   char *output, size_t output_size, int *exit_code);

int edr_parse_json_string(const uint8_t *payload, size_t len,
                          const char *key, char *out, size_t out_size);

int edr_parse_json_int(const uint8_t *payload, size_t len,
                       const char *key, int *out);

#ifdef __cplusplus
}
#endif

#endif
