#ifndef EDR_RESPONSE_H
#define EDR_RESPONSE_H

#include "edr/command.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void edr_response_kill(const char *cmd_id, const uint8_t *pl, size_t len,
                       const EdrSoarCommandMeta *sm);

void edr_response_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm);
void edr_response_isolate_auto_from_shellcode(void);

void edr_response_quarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                  const EdrSoarCommandMeta *sm);
void edr_response_restore_file(const char *cmd_id, const uint8_t *pl, size_t len,
                               const EdrSoarCommandMeta *sm);
void edr_response_get_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm);
void edr_response_put_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm);
void edr_response_remove_file(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);

void edr_response_collect_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                   const EdrSoarCommandMeta *sm);
void edr_response_targeted_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm);
void edr_response_deep_forensic(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm);
void edr_response_shell_open(const char *cmd_id, const uint8_t *pl, size_t len,
                             const EdrSoarCommandMeta *sm);
void edr_response_shell_input(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);
void edr_response_shell_close(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);
void edr_shell_stream_output_cb(const char *sid, const char *data, size_t len,
                                int exit_code, bool closed, void *user);
void edr_response_memory_dump(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);
void edr_response_yara_scan(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);
void edr_response_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);

void edr_response_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);

void edr_response_eventlog_view(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm);
void edr_response_reg_query(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm);
void edr_response_rtq_execute(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm);
void edr_response_collector_start(const char *cmd_id, const uint8_t *pl, size_t len,
                                  const EdrSoarCommandMeta *sm);

#ifdef __cplusplus
}
#endif

#endif
