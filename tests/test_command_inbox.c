#include "edr/command_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#define TEST_PID _getpid()
static void test_setenv(const char *name, const char *value) { _putenv_s(name, value); }
#else
#include <sys/stat.h>
#include <unistd.h>
#define TEST_PID getpid()
static void test_setenv(const char *name, const char *value) { setenv(name, value, 1); }
#endif

void edr_local_evidence_cache_record_command_result(
    const char *command_id, const char *command_type, const char *status,
    int execution_status, int exit_code, const char *detail, const char *artifacts) {
  (void)command_id;
  (void)command_type;
  (void)status;
  (void)execution_status;
  (void)exit_code;
  (void)detail;
  (void)artifacts;
}

static void require_true(int ok, const char *msg) {
  if (!ok) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
  }
}

static void write_corrupt_record(const char *path) {
  FILE *f = fopen(path, "wb");
  require_true(f != NULL, "open corrupt record");
  require_true(fputs("{not-valid-json}\n", f) >= 0, "write corrupt record");
  require_true(fclose(f) == 0, "close corrupt record");
#ifndef _WIN32
  require_true(chmod(path, 0600) == 0, "secure corrupt record");
#endif
}

static int file_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  fclose(f);
  return 1;
}

static int only_velo(const char *command_type, void *user) {
  (void)user;
  return command_type && strcmp(command_type, "velo_query") == 0;
}

int main(void) {
  char state_dir[512];
  char state_path[512];
  char inbox_dir[512];
  char ack_dir[512];
  long long suffix = ((long long)time(NULL) * 100000LL) + (long long)TEST_PID;
  snprintf(state_dir, sizeof(state_dir), "./test_command_state_%lld", suffix);
  snprintf(state_path, sizeof(state_path), "%s/command_state.jsonl", state_dir);
  snprintf(inbox_dir, sizeof(inbox_dir), "./test_command_inbox_%lld", suffix);
  snprintf(ack_dir, sizeof(ack_dir), "./test_command_ack_%lld", suffix);
  test_setenv("EDR_COMMAND_STATE_DB", state_path);
  test_setenv("EDR_COMMAND_INBOX_DIR", inbox_dir);
  test_setenv("EDR_COMMAND_ACK_DIR", ack_dir);

  EdrSoarCommandMeta meta;
  memset(&meta, 0, sizeof(meta));
  snprintf(meta.soar_correlation_id, sizeof(meta.soar_correlation_id), "%s", "corr-1");
  snprintf(meta.playbook_run_id, sizeof(meta.playbook_run_id), "%s", "run-1");
  snprintf(meta.playbook_step_id, sizeof(meta.playbook_step_id), "%s", "step-1");
  snprintf(meta.idempotency_key, sizeof(meta.idempotency_key), "%s", "idem-1|sigv1|placeholder");
  snprintf(meta.initiated_by, sizeof(meta.initiated_by), "%s", "operator");
  meta.issued_at_unix_ms = 1783000000000LL;
  meta.deadline_ms = 60000u;

  const uint8_t payload[] = "{\"pid\":5604,\"action\":\"refresh\"}";
  require_true(edr_command_state_store_inbox("cmd-inbox-1", "velo_query",
                                            payload, sizeof(payload) - 1u, &meta) == 0,
               "store inbox");
  require_true(edr_command_state_count_inbox() == 1u, "count durable inbox records");

  EdrCommandInboxRecord records[4];
  int n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 1, "collect one inbox record");
  require_true(strcmp(records[0].command_id, "cmd-inbox-1") == 0, "command_id round trip");
  require_true(strcmp(records[0].command_type, "velo_query") == 0, "command_type round trip");
  require_true(records[0].payload_len == sizeof(payload) - 1u, "payload len round trip");
  require_true(memcmp(records[0].payload, payload, sizeof(payload) - 1u) == 0, "payload round trip");
  require_true(strcmp(records[0].meta.initiated_by, "operator") == 0, "initiated_by round trip");
  edr_command_state_free_inbox_record(&records[0]);
  n = edr_command_state_collect_inbox_filtered(records, 4, only_velo, NULL);
  require_true(n == 1, "filtered inbox returns matching execution lane candidate");
  edr_command_state_free_inbox_record(&records[0]);

  edr_command_state_delete_inbox("cmd-inbox-1");
  n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 0, "delete inbox record");

  require_true(edr_command_state_store_inbox("cmd-inbox-final", "echo",
                                            payload, sizeof(payload) - 1u, &meta) == 0,
               "store final inbox");
  require_true(edr_command_state_finish("cmd-inbox-final", "echo", &meta, "ok", 1, 0,
                                        "done", NULL, 0) == 0,
               "persist final command state");
  n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 0, "final command is not replayed from inbox");

  EdrSoarCommandMeta replay_meta = meta;
  snprintf(replay_meta.idempotency_key, sizeof(replay_meta.idempotency_key), "%s", "idem-replay|sigv1|placeholder");
  require_true(edr_command_state_store_inbox("cmd-inbox-replay", "echo",
                                            payload, sizeof(payload) - 1u, &replay_meta) == 0,
               "store replay inbox");
  int retries = 0;
  EdrCommandStateRecord dup;
  require_true(edr_command_state_begin("cmd-inbox-replay", "echo", &replay_meta, &retries, &dup) ==
                   EDR_COMMAND_STATE_BEGIN_READY,
               "begin replay command");
  require_true(edr_command_state_replay_begin("cmd-inbox-replay", "echo", &replay_meta, &retries, &dup) ==
                   EDR_COMMAND_STATE_BEGIN_READY,
               "queued command transitions to running");
  EdrCommandStateRecord cancelling;
  require_true(edr_command_state_request_cancel("cmd-inbox-replay", &cancelling) ==
                   EDR_COMMAND_STATE_CANCEL_REQUESTED,
               "running command transitions to cancelling");
  require_true(strcmp(cancelling.response_status, "running") == 0,
               "cancel request returns previous running state");
  require_true(edr_command_state_replay_begin("cmd-inbox-replay", "echo", &replay_meta, &retries, &dup) ==
                   EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED,
               "cancelling command is blocked from replay");
  require_true(edr_command_state_finish("cmd-inbox-replay", "echo", &replay_meta,
                                        "cancelled", 3, 130, "cancelled", NULL, 0) == 0,
               "persist cancelled final state");
  require_true(edr_command_state_replay_begin("cmd-inbox-replay", "echo", &replay_meta, &retries, &dup) ==
                   EDR_COMMAND_STATE_BEGIN_DUP_FINAL,
               "final replay is suppressed");
  edr_command_state_delete_inbox("cmd-inbox-replay");

  EdrSoarCommandMeta shell_meta = meta;
  snprintf(shell_meta.idempotency_key, sizeof(shell_meta.idempotency_key), "%s",
           "idem-shell|sigv1|placeholder");
  require_true(edr_command_state_begin("cmd-shell-replay", "shell_open", &shell_meta,
                                       &retries, &dup) == EDR_COMMAND_STATE_BEGIN_READY,
               "queue non-replayable shell command");
  require_true(edr_command_state_replay_begin("cmd-shell-replay", "shell_open", &shell_meta,
                                              &retries, &dup) == EDR_COMMAND_STATE_BEGIN_READY,
               "start non-replayable shell command once");
  require_true(edr_command_state_replay_begin_policy(
                   "cmd-shell-replay", "shell_open", &shell_meta, 0, &retries, &dup) ==
                   EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED,
               "started shell command cannot be replayed after interruption");
  require_true(edr_command_state_finish("cmd-shell-replay", "shell_open", &shell_meta,
                                        "failed", 3, 17, "replay blocked", NULL, 0) == 0,
               "finish replay-blocked shell command");

  EdrControlAckRecord ack;
  memset(&ack, 0, sizeof(ack));
  snprintf(ack.command_id, sizeof(ack.command_id), "%s", "cmd-ack-1");
  snprintf(ack.transport, sizeof(ack.transport), "%s", "https_control_stream");
  ack.last_seq = 42;
  ack.attempts = 1u;
  ack.first_failure_unix_ms = 1783000000000LL;
  ack.last_failure_unix_ms = 1783000001000LL;
  ack.next_retry_unix_ms = 1783000006000LL;
  require_true(edr_command_state_upsert_pending_ack(&ack) == 0, "store pending ACK");
  EdrControlAckRecord pending[4];
  n = edr_command_state_collect_pending_acks(pending, 4);
  require_true(n == 1, "collect one pending ACK");
  require_true(strcmp(pending[0].command_id, "cmd-ack-1") == 0, "ACK command id round trip");
  require_true(strcmp(pending[0].transport, "https_control_stream") == 0, "ACK transport round trip");
  require_true(pending[0].last_seq == 42 && pending[0].attempts == 1u, "ACK delivery fields round trip");
  ack.attempts = 2u;
  ack.last_failure_unix_ms = 1783000007000LL;
  ack.next_retry_unix_ms = 1783000017000LL;
  require_true(edr_command_state_upsert_pending_ack(&ack) == 0, "update pending ACK retry");
  n = edr_command_state_collect_pending_acks(pending, 4);
  require_true(n == 1 && pending[0].attempts == 2u &&
                   pending[0].next_retry_unix_ms == 1783000017000LL,
               "ACK retry update is durable");
  edr_command_state_delete_pending_ack("cmd-ack-1");
  n = edr_command_state_collect_pending_acks(pending, 4);
  require_true(n == 0, "delete pending ACK after server receipt");

  EdrSoarCommandMeta result_meta = meta;
  snprintf(result_meta.idempotency_key, sizeof(result_meta.idempotency_key), "%s",
           "idem-json-state|sigv1|placeholder");
  const char *escaped_detail = "path=C:\\temp\\tail\\\"quoted\"";
  require_true(edr_command_state_finish("cmd-json-state", "velo_query", &result_meta,
                                        "failed", 3, 42, escaped_detail, NULL, 1) == 0,
               "persist escaped command result detail");
  EdrCommandStateRecord result_pending[4];
  n = edr_command_state_collect_pending(result_pending, 4);
  require_true(n >= 1, "collect pending escaped command result");
  int found_escaped = 0;
  for (int i = 0; i < n; i++) {
    if (strcmp(result_pending[i].command_id, "cmd-json-state") == 0) {
      found_escaped = 1;
      require_true(strcmp(result_pending[i].detail, escaped_detail) == 0,
                   "escaped detail survives durable JSON round trip");
      edr_command_state_mark_report_rejected(&result_pending[i], "HTTP 400 INVALID_ARGUMENT");
    }
  }
  require_true(found_escaped, "escaped command result present in pending outbox");
  n = edr_command_state_collect_pending(result_pending, 4);
  for (int i = 0; i < n; i++) {
    require_true(strcmp(result_pending[i].command_id, "cmd-json-state") != 0,
                 "permanently rejected result is removed from retry outbox");
  }

  char corrupt_inbox_path[1024];
  snprintf(corrupt_inbox_path, sizeof(corrupt_inbox_path), "%s/corrupt-inbox.json", inbox_dir);
  write_corrupt_record(corrupt_inbox_path);
  n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 0, "malformed inbox is not replayed");
  require_true(!file_exists(corrupt_inbox_path), "malformed inbox is moved out of active directory");

  EdrCommandStateQuarantineStats quarantine;
  memset(&quarantine, 0, sizeof(quarantine));
  edr_command_state_get_quarantine_stats(&quarantine);
  require_true(quarantine.inbox_record_count >= 1u, "inbox quarantine counter increments");
  require_true(strcmp(quarantine.last_record_kind, "command_inbox") == 0,
               "inbox quarantine records kind");

  char corrupt_ack_path[1024];
  snprintf(corrupt_ack_path, sizeof(corrupt_ack_path), "%s/corrupt-ack.json", ack_dir);
  write_corrupt_record(corrupt_ack_path);
  n = edr_command_state_collect_pending_acks(pending, 4);
  require_true(n == 0, "malformed ACK is not retried");
  require_true(!file_exists(corrupt_ack_path), "malformed ACK is moved out of active directory");
  memset(&quarantine, 0, sizeof(quarantine));
  edr_command_state_get_quarantine_stats(&quarantine);
  require_true(quarantine.ack_record_count >= 1u, "ACK quarantine counter increments");
  require_true(strcmp(quarantine.last_record_kind, "control_ack") == 0,
               "ACK quarantine records kind");

#ifndef _WIN32
  char bad_inbox_dir[512];
  snprintf(bad_inbox_dir, sizeof(bad_inbox_dir), "./test_command_inbox_bad_%lld", suffix);
  require_true(mkdir(bad_inbox_dir, 0777) == 0, "create insecure inbox dir");
  require_true(chmod(bad_inbox_dir, 0777) == 0, "chmod insecure inbox dir");
  test_setenv("EDR_COMMAND_INBOX_DIR", bad_inbox_dir);
  require_true(edr_command_state_store_inbox("cmd-inbox-bad", "echo",
                                            payload, sizeof(payload) - 1u, &replay_meta) != 0,
               "reject group/world writable inbox dir");
  (void)chmod(bad_inbox_dir, 0700);
  (void)rmdir(bad_inbox_dir);

  char bad_ack_dir[512];
  snprintf(bad_ack_dir, sizeof(bad_ack_dir), "./test_command_ack_bad_%lld", suffix);
  require_true(mkdir(bad_ack_dir, 0777) == 0, "create insecure ACK dir");
  require_true(chmod(bad_ack_dir, 0777) == 0, "chmod insecure ACK dir");
  test_setenv("EDR_COMMAND_ACK_DIR", bad_ack_dir);
  require_true(edr_command_state_upsert_pending_ack(&ack) != 0,
               "reject group/world writable ACK outbox dir");
  (void)chmod(bad_ack_dir, 0700);
  (void)rmdir(bad_ack_dir);
#endif

  printf("ok\n");
  return 0;
}
