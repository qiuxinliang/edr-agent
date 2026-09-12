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
  char state_path[sizeof(state_dir) + sizeof("/command_state.jsonl")];
  char inbox_dir[512];
  char ack_dir[512];
  long long suffix = ((long long)time(NULL) * 100000LL) + (long long)TEST_PID;
  snprintf(state_dir, sizeof(state_dir), "./test_command_state_%lld", suffix);
  {
    static const char state_filename[] = "/command_state.jsonl";
    size_t state_dir_len = strlen(state_dir);
    require_true(state_dir_len + sizeof(state_filename) <= sizeof(state_path),
                 "state path fixture fits exactly");
    memcpy(state_path, state_dir, state_dir_len);
    memcpy(state_path + state_dir_len, state_filename, sizeof(state_filename));
  }
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

  char backlog_ids[20][64];
  for (int i = 0; i < 18; i++) {
    EdrSoarCommandMeta queued_meta = meta;
    queued_meta.deadline_ms = 60u * 60u * 1000u;
    snprintf(backlog_ids[i], sizeof(backlog_ids[i]), "cmd-backlog-%02d", i);
    snprintf(queued_meta.idempotency_key, sizeof(queued_meta.idempotency_key),
             "idem-backlog-%02d|sigv1|placeholder", i);
    require_true(edr_command_state_store_inbox(backlog_ids[i], "velo_query",
                                               payload, sizeof(payload) - 1u,
                                               &queued_meta) == 0,
                 "store bulk backlog record");
  }
  for (int i = 18; i < 20; i++) {
    EdrSoarCommandMeta urgent_meta = meta;
    urgent_meta.deadline_ms = (uint32_t)(i - 17) * 1000u;
    snprintf(backlog_ids[i], sizeof(backlog_ids[i]), "zz-urgent-%d", i - 17);
    snprintf(urgent_meta.idempotency_key, sizeof(urgent_meta.idempotency_key),
             "idem-urgent-%d|sigv1|placeholder", i - 17);
    require_true(edr_command_state_store_inbox(backlog_ids[i], "velo_query",
                                               payload, sizeof(payload) - 1u,
                                               &urgent_meta) == 0,
                 "store deadline-sensitive backlog record");
  }
  n = edr_command_state_collect_inbox_filtered(records, 2, only_velo, NULL);
  require_true(n == 2, "bounded inbox collection returns requested top-k");
  require_true(strcmp(records[0].command_id, "zz-urgent-1") == 0 &&
                   strcmp(records[1].command_id, "zz-urgent-2") == 0,
               "deadline ordering scans the full backlog instead of filesystem prefix order");
  for (int i = 0; i < n; i++) {
    edr_command_state_free_inbox_record(&records[i]);
  }
  for (int i = 0; i < 20; i++) {
    edr_command_state_delete_inbox(backlog_ids[i]);
  }

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

  {
    static const int64_t scan_now = 1783000100000LL;
    char ack_ids[24][64];
    unsigned int due_seen = 0u;
    EdrControlAckScanStats scan_stats;
    for (int i = 0; i < 24; i++) {
      EdrControlAckRecord queued;
      memset(&queued, 0, sizeof(queued));
      snprintf(ack_ids[i], sizeof(ack_ids[i]),
               i < 16 ? "ack-a-future-%02d" : "ack-z-due-%02d", i);
      snprintf(queued.command_id, sizeof(queued.command_id), "%s", ack_ids[i]);
      snprintf(queued.transport, sizeof(queued.transport), "%s", "https_control_stream");
      queued.last_seq = i;
      queued.attempts = 1u;
      queued.first_failure_unix_ms = scan_now - 5000LL;
      queued.last_failure_unix_ms = scan_now - 1000LL;
      queued.next_retry_unix_ms = i < 16 ? scan_now + 3600000LL : scan_now - 1LL;
      require_true(edr_command_state_upsert_pending_ack(&queued) == 0,
                   "store ACK fairness backlog");
    }

    for (int round = 0; round < 16 && due_seen != 0xffu; round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      n = edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      require_true(n >= 0 && n <= 4, "due ACK selection respects attempt cap");
      require_true(scan_stats.scanned_entry_count <= 8u,
                   "due ACK traversal respects scan budget");
      require_true(scan_stats.selected_due_count == (size_t)n,
                   "selected due count is distinct and accurate");
      for (int i = 0; i < n; i++) {
        int suffix = -1;
        require_true(pending[i].next_retry_unix_ms <= scan_now,
                     "future ACK is never selected for transmission");
        require_true(sscanf(pending[i].command_id, "ack-z-due-%d", &suffix) == 1 &&
                         suffix >= 16 && suffix < 24,
                     "selected ACK belongs to the due suffix backlog");
        due_seen |= 1u << (unsigned)(suffix - 16);
        pending[i].attempts++;
        pending[i].last_failure_unix_ms = scan_now;
        pending[i].next_retry_unix_ms = scan_now - 1LL;
        require_true(edr_command_state_upsert_pending_ack(&pending[i]) == 0,
                     "continued ACK failure remains durably retryable");
      }
    }
    require_true(due_seen == 0xffu,
                 "later due ACKs are served within bounded fair traversal rounds");
    /* Finish the mutation-overlapped pass, then measure one quiet complete
     * traversal so atomic replacements cannot make the count a mixed view. */
    int pass_complete = 0;
    for (int round = 0; round < 16 && !pass_complete; round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      (void)edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      pass_complete = scan_stats.traversal_complete;
    }
    require_true(pass_complete, "mutation-overlapped ACK traversal terminates");
    pass_complete = 0;
    for (int round = 0; round < 16 && !pass_complete; round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      (void)edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      pass_complete = scan_stats.traversal_complete;
    }
    require_true(pass_complete, "quiet ACK traversal terminates");
    require_true(scan_stats.pending_record_count_observed == 24u,
                 "completed quiet traversal reports total pending separately from selection");

    memset(&scan_stats, 0, sizeof(scan_stats));
    (void)edr_command_state_collect_due_pending_acks(
        pending, 4u, scan_now, 8u, &scan_stats);
    require_true(!scan_stats.traversal_complete,
                 "new ACK traversal remains open before concurrent insert");

    EdrControlAckRecord inserted;
    memset(&inserted, 0, sizeof(inserted));
    snprintf(inserted.command_id, sizeof(inserted.command_id), "%s", "cmd-ack-inserted");
    snprintf(inserted.transport, sizeof(inserted.transport), "%s", "https_control_stream");
    inserted.last_seq = 99;
    inserted.attempts = 1u;
    inserted.first_failure_unix_ms = scan_now;
    inserted.last_failure_unix_ms = scan_now;
    inserted.next_retry_unix_ms = scan_now - 1LL;
    require_true(edr_command_state_upsert_pending_ack(&inserted) == 0,
                 "insert ACK while fair traversal is active");

    char corrupt_fair_path[1024];
    snprintf(corrupt_fair_path, sizeof(corrupt_fair_path),
             "%s/corrupt-fair-ack.json", ack_dir);
    write_corrupt_record(corrupt_fair_path);
    int inserted_seen = 0;
    int complete_25_seen = 0;
    for (int round = 0; round < 40 && (!inserted_seen || !complete_25_seen); round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      n = edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      for (int i = 0; i < n; i++) {
        if (strcmp(pending[i].command_id, "cmd-ack-inserted") == 0) {
          inserted_seen = 1;
        }
      }
      if (scan_stats.traversal_complete &&
          scan_stats.pending_record_count_observed == 25u) {
        complete_25_seen = 1;
      }
    }
    require_true(inserted_seen,
                 "ACK inserted during traversal is discovered after bounded wrap");
    require_true(!file_exists(corrupt_fair_path),
                 "corrupt ACK encountered by fair traversal is quarantined");
    require_true(complete_25_seen,
                 "post-insert traversal reports all valid pending ACKs");

    /* Reaching end closes the native enumeration handle. The next calls start
     * a fresh pass, matching process-restart cursor semantics without relying
     * on an inherited POSIX DIR* or Windows find handle. */
    int reopened_due_seen = 0;
    for (int round = 0; round < 8 && !reopened_due_seen; round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      n = edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      reopened_due_seen = n > 0;
    }
    require_true(reopened_due_seen,
                 "fresh traversal after close/restart reaches due ACKs again");

    for (int i = 0; i < 24; i++) {
      edr_command_state_delete_pending_ack(ack_ids[i]);
    }
    edr_command_state_delete_pending_ack("cmd-ack-inserted");
    for (int round = 0; round < 16; round++) {
      memset(&scan_stats, 0, sizeof(scan_stats));
      (void)edr_command_state_collect_due_pending_acks(
          pending, 4u, scan_now, 8u, &scan_stats);
      if (scan_stats.traversal_complete) {
        break;
      }
    }
  }

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
      if (edr_command_state_mark_report_rejected(&result_pending[i],
                                                 "HTTP 400 INVALID_ARGUMENT") != 0) {
        fprintf(stderr, "failed to persist rejected result state\n");
        return 1;
      }
    }
  }
  require_true(found_escaped, "escaped command result present in pending outbox");
  n = edr_command_state_collect_pending(result_pending, 4);
  for (int i = 0; i < n; i++) {
    require_true(strcmp(result_pending[i].command_id, "cmd-json-state") != 0,
                 "permanently rejected result is removed from retry outbox");
  }

  char long_detail[12000];
  size_t long_detail_len = sizeof(long_detail) - 1u;
  for (size_t i = 0; i < long_detail_len; i++) {
    static const char pattern[] = "RTR C:\\Program Files\\FDSecurity\\ \"output\" | ";
    long_detail[i] = pattern[i % (sizeof(pattern) - 1u)];
  }
  long_detail[long_detail_len] = '\0';
  require_true(edr_command_state_finish("cmd-rtr-long-state", "shell_open", &result_meta,
                                        "ok", 1, 0, long_detail, NULL, 1) == 0,
               "persist long RTR command result detail");
  n = edr_command_state_collect_pending(result_pending, 4);
  int found_long = 0;
  for (int i = 0; i < n; i++) {
    if (strcmp(result_pending[i].command_id, "cmd-rtr-long-state") == 0) {
      found_long = 1;
      require_true(strlen(result_pending[i].detail) == long_detail_len,
                   "long RTR detail length survives durable JSON round trip");
      require_true(strcmp(result_pending[i].detail, long_detail) == 0,
                   "long RTR detail content survives durable JSON round trip");
      require_true(edr_command_state_mark_reported(&result_pending[i]) == 0,
                   "mark long RTR result reported");
    }
  }
  require_true(found_long, "long RTR command result present in pending outbox");

  EdrCommandStateRecord persistence_probe;
  memset(&persistence_probe, 0, sizeof(persistence_probe));
  snprintf(persistence_probe.command_id, sizeof(persistence_probe.command_id), "%s",
           "cmd-report-persistence-probe");
  snprintf(persistence_probe.command_type, sizeof(persistence_probe.command_type), "%s", "echo");
  /* An existing directory is never a valid append target, while a missing
   * parent is created intentionally by the production state writer. */
  test_setenv("EDR_COMMAND_STATE_DB", state_dir);
  require_true(edr_command_state_mark_reported(&persistence_probe) != 0,
               "reported state fails closed when durable append fails");
  test_setenv("EDR_COMMAND_STATE_DB", state_path);

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
  {
    EdrControlAckScanStats failed_scan;
    memset(&failed_scan, 0, sizeof(failed_scan));
    n = edr_command_state_collect_due_pending_acks(
        pending, 4u, 1783000100000LL, 8u, &failed_scan);
    require_true(n == 0 && failed_scan.traversal_error &&
                     !failed_scan.traversal_complete,
                 "ACK scan permission failure cannot publish an empty completed traversal");
  }
  (void)chmod(bad_ack_dir, 0700);
  (void)rmdir(bad_ack_dir);
#endif

  printf("ok\n");
  return 0;
}
