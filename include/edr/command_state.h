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
  char agent_boot_id[64];
  int process_id;
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

typedef int (*EdrCommandInboxFilter)(const char *command_type, void *user);

/* Durable receipt ACK retry record. An ACK is delivery bookkeeping only: a
 * failed ACK must never undo a locally persisted command or its execution. */
typedef struct EdrControlAckRecord {
  char command_id[128];
  char transport[96];
  int64_t last_seq;
  uint32_t attempts;
  int64_t first_failure_unix_ms;
  int64_t last_failure_unix_ms;
  int64_t next_retry_unix_ms;
} EdrControlAckRecord;

typedef struct EdrCommandStateQuarantineStats {
  uint64_t inbox_record_count;
  uint64_t ack_record_count;
  uint64_t move_failure_count;
  int64_t last_quarantine_unix_ms;
  char last_record_kind[32];
  char last_reason[96];
} EdrCommandStateQuarantineStats;

enum {
  EDR_COMMAND_STATE_BEGIN_ERROR = -1,
  EDR_COMMAND_STATE_BEGIN_READY = 0,
  EDR_COMMAND_STATE_BEGIN_DUP_FINAL = 1,
  EDR_COMMAND_STATE_BEGIN_DUP_RUNNING = 2,
  EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED = 3,
};

enum {
  EDR_COMMAND_STATE_CANCEL_ERROR = -1,
  EDR_COMMAND_STATE_CANCEL_NOT_FOUND = 0,
  EDR_COMMAND_STATE_CANCEL_REQUESTED = 1,
  EDR_COMMAND_STATE_CANCEL_ALREADY_FINAL = 2,
};

int edr_command_state_begin(const char *command_id, const char *command_type,
                            const EdrSoarCommandMeta *meta, int *out_retry_count,
                            EdrCommandStateRecord *out_duplicate);

int edr_command_state_replay_begin(const char *command_id, const char *command_type,
                                   const EdrSoarCommandMeta *meta, int *out_retry_count,
                                   EdrCommandStateRecord *out_duplicate);
int edr_command_state_replay_begin_policy(const char *command_id, const char *command_type,
                                          const EdrSoarCommandMeta *meta,
                                          int allow_replay_after_start,
                                          int *out_retry_count,
                                          EdrCommandStateRecord *out_duplicate);

int edr_command_state_finish(const char *command_id, const char *command_type,
                             const EdrSoarCommandMeta *meta, const char *response_status,
                             int execution_status, int exit_code, const char *detail,
                             const char *artifacts, int report_pending);

int edr_command_state_store_inbox(const char *command_id, const char *command_type,
                                  const uint8_t *payload, size_t payload_len,
                                  const EdrSoarCommandMeta *meta);
int edr_command_state_collect_inbox(EdrCommandInboxRecord *out, size_t cap);
int edr_command_state_collect_inbox_filtered(EdrCommandInboxRecord *out, size_t cap,
                                             EdrCommandInboxFilter filter, void *user);
size_t edr_command_state_count_inbox(void);
void edr_command_state_delete_inbox(const char *command_id);
void edr_command_state_free_inbox_record(EdrCommandInboxRecord *record);

int edr_command_state_request_cancel(const char *command_id,
                                     EdrCommandStateRecord *out_target);

int edr_command_state_upsert_pending_ack(const EdrControlAckRecord *record);
int edr_command_state_collect_pending_acks(EdrControlAckRecord *out, size_t cap);
void edr_command_state_delete_pending_ack(const char *command_id);
void edr_command_state_get_quarantine_stats(EdrCommandStateQuarantineStats *out_stats);

int edr_command_state_collect_pending(EdrCommandStateRecord *out, size_t cap);
void edr_command_state_mark_reported(const EdrCommandStateRecord *record);
void edr_command_state_compact_if_needed(void);

#ifdef __cplusplus
}
#endif

#endif
