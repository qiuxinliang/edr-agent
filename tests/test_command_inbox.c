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

int main(void) {
  char state_path[512];
  char inbox_dir[512];
  long long suffix = ((long long)time(NULL) * 100000LL) + (long long)TEST_PID;
  snprintf(state_path, sizeof(state_path), "./test_command_state_%lld.jsonl", suffix);
  snprintf(inbox_dir, sizeof(inbox_dir), "./test_command_inbox_%lld", suffix);
  test_setenv("EDR_COMMAND_STATE_DB", state_path);
  test_setenv("EDR_COMMAND_INBOX_DIR", inbox_dir);

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

  EdrCommandInboxRecord records[4];
  int n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 1, "collect one inbox record");
  require_true(strcmp(records[0].command_id, "cmd-inbox-1") == 0, "command_id round trip");
  require_true(strcmp(records[0].command_type, "velo_query") == 0, "command_type round trip");
  require_true(records[0].payload_len == sizeof(payload) - 1u, "payload len round trip");
  require_true(memcmp(records[0].payload, payload, sizeof(payload) - 1u) == 0, "payload round trip");
  require_true(strcmp(records[0].meta.initiated_by, "operator") == 0, "initiated_by round trip");
  edr_command_state_free_inbox_record(&records[0]);

  edr_command_state_delete_inbox("cmd-inbox-1");
  n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 0, "delete inbox record");

  require_true(edr_command_state_store_inbox("cmd-inbox-final", "echo",
                                            payload, sizeof(payload) - 1u, &meta) == 0,
               "store final inbox");
  edr_command_state_finish("cmd-inbox-final", "echo", &meta, "ok", 1, 0,
                           "done", NULL, 0);
  n = edr_command_state_collect_inbox(records, 4);
  require_true(n == 0, "final command is not replayed from inbox");

  printf("ok\n");
  return 0;
}
