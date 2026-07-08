#ifndef EDR_COMMAND_STATE_H
#define EDR_COMMAND_STATE_H

#include "edr/command.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EdrCommandStateRecord {
  char command_id[128];
  char command_type[64];
  char idempotency_key[512];
  char response_status[32];
  int execution_status;
  int exit_code;
  int retry_count;
  int final_record;
  int report_pending;
  int64_t updated_unix_ms;
  char soar_correlation_id[128];
  char playbook_run_id[128];
  char playbook_step_id[128];
  char artifacts[1024];
  char detail[2048];
} EdrCommandStateRecord;

typedef struct EdrCommandInboxRecord {
  char command_id[128];
  char command_type[64];
  EdrSoarCommandMeta meta;
  uint8_t *payload;
  size_t payload_len;
  int64_t received_unix_ms;
} EdrCommandInboxRecord;

enum {
  EDR_COMMAND_STATE_BEGIN_READY = 0,
  EDR_COMMAND_STATE_BEGIN_DUP_FINAL = 1,
  EDR_COMMAND_STATE_BEGIN_DUP_RUNNING = 2,
};

int edr_command_state_begin(const char *command_id, const char *command_type,
                            const EdrSoarCommandMeta *meta, int *out_retry_count,
                            EdrCommandStateRecord *out_duplicate);

void edr_command_state_finish(const char *command_id, const char *command_type,
                              const EdrSoarCommandMeta *meta, const char *response_status,
                              int execution_status, int exit_code, const char *detail,
                              const char *artifacts, int report_pending);

int edr_command_state_store_inbox(const char *command_id, const char *command_type,
                                  const uint8_t *payload, size_t payload_len,
                                  const EdrSoarCommandMeta *meta);
int edr_command_state_collect_inbox(EdrCommandInboxRecord *out, size_t cap);
void edr_command_state_delete_inbox(const char *command_id);
void edr_command_state_free_inbox_record(EdrCommandInboxRecord *record);

int edr_command_state_collect_pending(EdrCommandStateRecord *out, size_t cap);
void edr_command_state_mark_reported(const EdrCommandStateRecord *record);
void edr_command_state_compact_if_needed(void);

#ifdef __cplusplus
}
#endif

#endif
