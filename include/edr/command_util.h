#ifndef EDR_COMMAND_UTIL_H
#define EDR_COMMAND_UTIL_H

#include "edr/command.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct EdrConfig;

void edr_command_bind_config(const struct EdrConfig *cfg);
const struct EdrConfig *edr_command_get_config(void);

int edr_command_dangerous_enabled(void);
int edr_command_kill_pid_allowed(long pid);

void edr_command_audit_both(const char *cmd_id, const char *msg);

int edr_command_soar_want_report(const EdrSoarCommandMeta *m);
void edr_command_soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm,
                           EdrCommandExecutionStatus st, int exit_code, const char *detail);
void edr_command_emit_always(const char *cmd_id, const EdrSoarCommandMeta *sm,
                             EdrCommandExecutionStatus st, int exit_code, const char *detail);

int edr_command_parse_pid_json(const uint8_t *p, size_t len, long *out_pid);
int edr_command_parse_path_json(const uint8_t *p, size_t len, char *out, size_t outcap);
int edr_command_parse_server_address_json(const uint8_t *p, size_t len, char *out, size_t outcap);

int edr_command_streq(const char *a, const char *b);

extern unsigned long g_cmd_handled;
extern unsigned long g_cmd_rejected;
extern unsigned long g_cmd_exec_ok;
extern unsigned long g_cmd_exec_fail;

static inline void edr_cmd_inc_handled(void) { g_cmd_handled++; }
static inline void edr_cmd_inc_rejected(void) { g_cmd_rejected++; }
static inline void edr_cmd_inc_exec_ok(void) { g_cmd_exec_ok++; }
static inline void edr_cmd_inc_exec_fail(void) { g_cmd_exec_fail++; }

#ifdef __cplusplus
}
#endif

#endif
