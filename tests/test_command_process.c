#include "edr/command.h"
#include "edr/command_state.h"
#include "edr/command_util.h"
#include "edr/policy_v2.h"
#include "cJSON.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
static void env(const char *k, const char *v) { _putenv_s(k, v); }
#else
#include <unistd.h>
static void env(const char *k, const char *v) { setenv(k, v, 1); }
#endif

static const uint64_t creation = 134170000000000123ULL;
static const char *os_reason = "process_exit_verified";
static int os_ok = 1, os_calls, queued;
static int cancelled, cancel_during_os;
static char ids[8][128], types[8][64], payloads[8][256];
static EdrSoarCommandMeta metas[8];
static int impact_mode = EDR_POLICY_MODE_ALERT;

int edr_policy_v2_mode_for_category(const char *category) { (void)category; return impact_mode; }
int edr_process_terminate_checked(uint32_t pid, uint64_t expected, uint32_t timeout, char *reason, size_t cap) {
  assert(pid == 7000u && expected == creation && timeout == 5000u);
  os_calls++;
  if (cancel_during_os) cancelled = 1;
  snprintf(reason, cap, "%s", os_reason);
  return os_ok;
}
void edr_command_on_internal_envelope(const char *id, const char *type, const uint8_t *payload,
    size_t size, const EdrSoarCommandMeta *meta) {
  assert(queued < 8 && size < sizeof(payloads[0]));
  snprintf(ids[queued], sizeof(ids[0]), "%s", id);
  snprintf(types[queued], sizeof(types[0]), "%s", type);
  memcpy(payloads[queued], payload, size);
  payloads[queued][size] = 0;
  metas[queued] = *meta;
  queued++;
}
int edr_command_cancel_requested(const char *id) { (void)id; return cancelled; }
int edr_ingest_http_configured(void) { return 1; }
const char *edr_command_normalize_forensic_result(const char *type, EdrCommandExecutionStatus status,
    int code, const char *detail, char *out, size_t cap) {
  (void)type; (void)status; (void)code; (void)out; (void)cap; return detail;
}
int edr_parse_json_string(const uint8_t *p, size_t n, const char *k, char *out, size_t cap) {
  (void)p; (void)n; (void)k; if (cap) out[0] = 0; return 0;
}
int edr_parse_json_int(const uint8_t *p, size_t n, const char *k, int *out) {
  (void)p; (void)n; (void)k; (void)out; return 0;
}
void edr_local_evidence_cache_record_command_result(const char *id, const char *type,
    const char *status, int execution, int code, const char *detail, const char *artifacts) {
  (void)id; (void)type; (void)status; (void)execution; (void)code; (void)detail; (void)artifacts;
}

static void verify_receipt(const char *id, int status, const char *reason) {
  EdrCommandStateRecord *records = calloc(24, sizeof(*records));
  assert(records);
  int count = edr_command_state_collect_pending(records, 24);
  for (int i = 0; i < count; ++i) {
    if (strcmp(records[i].command_id, id)) continue;
    assert(records[i].execution_status == status && records[i].final_record && records[i].report_pending);
    assert(strcmp(records[i].command_type, "kill_process") == 0);
    cJSON *root = cJSON_Parse(records[i].detail);
    assert(root);
    assert(strcmp(cJSON_GetObjectItem(root, "reason")->valuestring, reason) == 0);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(root, "enforcement_verified")) == (status == EdrCmdExecOk));
    cJSON_Delete(root);
    free(records);
    return;
  }
  free(records);
  assert(!"durable receipt not found");
}

int main(void) {
  char dir[512], db[600], inbox[600], blocked[600];
#ifdef _WIN32
  char tmp[MAX_PATH];
  assert(GetTempPathA(sizeof(tmp), tmp));
  assert(GetTempFileNameA(tmp, "edr", 0, dir));
  assert(DeleteFileA(dir) && CreateDirectoryA(dir, NULL));
#else
  const char *tmp = getenv("TMPDIR");
  snprintf(dir, sizeof(dir), "%s/edr-response.XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
  assert(mkdtemp(dir));
#endif
  snprintf(db, sizeof(db), "%s/state.jsonl", dir);
  snprintf(inbox, sizeof(inbox), "%s/inbox", dir);
  env("EDR_COMMAND_STATE_DB", db);
  env("EDR_COMMAND_INBOX_DIR", inbox);
  env("EDR_RANSOM_AUTO_ISOLATE", "1");
  env("EDR_RANSOM_AUTO_TERMINATE", "1");
  env("EDR_CMD_ENABLED", "1");
  env("EDR_CMD_KILL_ALLOWLIST", "7000");
  EdrBehaviorRecord record = {0};
  record.pid = 7000;
  record.event_time_ns = 1780000000000000000LL;
  record.process_creation_filetime_100ns = creation;
  snprintf(record.event_id, sizeof(record.event_id), "%s", "e-1-2-3");
  edr_isolate_auto_from_ransom_alarm(&record);
  assert(queued == 2 && os_calls == 0);
  assert(strcmp(types[0], "kill_process") == 0 && strcmp(types[1], "isolate_host") == 0);
  assert(strcmp(metas[0].soar_correlation_id, record.event_id) == 0);
  assert(strcmp(metas[0].playbook_step_id, "terminate") == 0 && strcmp(metas[1].playbook_step_id, "isolate") == 0);
  assert(strstr(payloads[0], "134170000000000123"));
  edr_isolate_auto_from_ransom_alarm(&record);
  assert(strcmp(ids[0], ids[2]) == 0 && strcmp(ids[1], ids[3]) == 0);
  record.process_creation_filetime_100ns++;
  edr_isolate_auto_from_ransom_alarm(&record);
  assert(strcmp(ids[0], ids[4]) != 0);
  record.process_creation_filetime_100ns = 0;
  edr_isolate_auto_from_ransom_alarm(&record);
  assert(queued == 7 && os_calls == 0); /* Missing identity: only isolation queued. */

  const struct { const char *reason; int ok; EdrCommandExecutionStatus status; } cases[] = {
      {"process_exit_verified", 1, EdrCmdExecOk},
      {"process_generation_mismatch", 0, EdrCmdExecRejected},
      {"protected_process_target", 0, EdrCmdExecRejected},
      {"process_already_gone", 1, EdrCmdExecRejected},
      {"process_open_failed", 0, EdrCmdExecFailed},
      {"process_exit_timeout", 0, EdrCmdExecFailed},
      {"verified_termination_unsupported_platform", 0, EdrCmdExecRejected},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char id[64];
    snprintf(id, sizeof(id), "auto-ransom-test-%u", i);
    EdrSoarCommandMeta meta = metas[0];
    snprintf(meta.idempotency_key, sizeof(meta.idempotency_key), "%s", id);
    assert(edr_command_state_store_inbox(id, "kill_process", (uint8_t *)payloads[0], strlen(payloads[0]), &meta) == 0);
    assert(edr_command_state_begin(id, "kill_process", &meta, NULL, NULL) == EDR_COMMAND_STATE_BEGIN_READY);
    os_reason = cases[i].reason; os_ok = cases[i].ok;
    assert(edr_command_kill_process(id, (uint8_t *)payloads[0], strlen(payloads[0]), &meta) == cases[i].status);
    verify_receipt(id, cases[i].status, cases[i].reason);
    assert(edr_command_state_begin(id, "kill_process", &meta, NULL, NULL) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
  }
  int before = os_calls;
  env("EDR_RANSOM_AUTO_TERMINATE", "0");
  assert(edr_command_kill_process("auto-ransom-policy-changed", (uint8_t *)payloads[0], strlen(payloads[0]), &metas[0]) == EdrCmdExecRejected);
  verify_receipt("auto-ransom-policy-changed", EdrCmdExecRejected, "policy_disabled");
  env("EDR_RANSOM_AUTO_TERMINATE", "1");
  env("EDR_CMD_ENABLED", "0");
  assert(edr_command_kill_process("disabled", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == EdrCmdExecRejected);
  env("EDR_CMD_ENABLED", "1");
  env("EDR_CMD_KILL_ALLOWLIST", "8000");
  assert(edr_command_kill_process("allowlist", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == EdrCmdExecRejected);
  env("EDR_CMD_KILL_ALLOWLIST", "7000");
  const char *missing = "{\"pid\":7000}";
  assert(edr_command_kill_process("missing", (uint8_t *)missing, strlen(missing), NULL) == EdrCmdExecRejected);
  const char *invalid[] = {
      "{\"pid\":7000.5,\"process_creation_filetime_100ns\":\"134170000000000123\"}",
      "{\"pid\":-1,\"process_creation_filetime_100ns\":\"134170000000000123\"}",
      "{\"pid\":7000,\"process_creation_filetime_100ns\":\"18446744073709551616\"}",
      "{\"pid\":7000,\"process_creation_filetime_100ns\":134170000000000123}",
  };
  for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    assert(edr_command_kill_process("invalid-identity", (uint8_t *)invalid[i], strlen(invalid[i]), NULL) == EdrCmdExecRejected);
  }
  assert(os_calls == before);
  cancelled = 1;
  assert(edr_command_kill_process("cancelled", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == EdrCmdExecFailed);
  verify_receipt("cancelled", EdrCmdExecFailed, "cancelled_before_execution");
  assert(os_calls == before);
  cancelled = 0;
  cancel_during_os = 1;
  os_reason = "process_exit_verified"; os_ok = 1;
  assert(edr_command_kill_process("late-cancel", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == EdrCmdExecOk);
  verify_receipt("late-cancel", EdrCmdExecOk, "process_exit_verified");
  cancelled = cancel_during_os = 0;
  assert(edr_command_state_count_inbox() == 0);

  EdrCommandStateRecord *pending = calloc(24, sizeof(*pending));
  assert(pending);
  int count = edr_command_state_collect_pending(pending, 24), found = 0;
  for (int i = 0; i < count; ++i) {
    if (strcmp(pending[i].command_id, "auto-ransom-test-0")) continue;
    found = 1;
    assert(edr_command_state_mark_report_retry(&pending[i], "transport unavailable", 1) == 0);
    verify_receipt(pending[i].command_id, EdrCmdExecOk, "process_exit_verified");
    break;
  }
  assert(found);
  count = edr_command_state_collect_pending(pending, 24);
  found = 0;
  for (int i = 0; i < count; ++i) {
    if (strcmp(pending[i].command_id, "auto-ransom-test-0")) continue;
    found = 1;
    assert(pending[i].report_attempts == 1);
    assert(edr_command_state_mark_reported(&pending[i]) == 0);
    EdrCommandStateRecord terminal;
    assert(edr_command_state_begin(pending[i].command_id, "kill_process", NULL, NULL, &terminal) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
    assert(!terminal.report_pending && strcmp(terminal.detail, pending[i].detail) == 0);
    assert(edr_command_state_replay_begin_policy(pending[i].command_id, "kill_process", NULL, 0, NULL, &terminal) == EDR_COMMAND_STATE_BEGIN_DUP_FINAL);
    break;
  }
  assert(found);
  free(pending);

  /* Failure after OS execution must retain the durable intent and cannot
   * turn into an acknowledged success. Use a file as the DB parent. */
  assert(edr_command_state_store_inbox("persist-failure", "kill_process", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == 0);
  snprintf(blocked, sizeof(blocked), "%s/blocked", dir);
  FILE *f = fopen(blocked, "wb"); assert(f); fclose(f);
  char bad_db[700]; snprintf(bad_db, sizeof(bad_db), "%s/state.jsonl", blocked);
  env("EDR_COMMAND_STATE_DB", bad_db);
  os_reason = "process_exit_verified"; os_ok = 1;
  assert(edr_command_kill_process("persist-failure", (uint8_t *)payloads[0], strlen(payloads[0]), NULL) == EdrCmdExecFailed);
  assert(edr_command_state_count_inbox() == 1);
  env("EDR_COMMAND_STATE_DB", db);
  edr_command_state_delete_inbox("persist-failure");
  assert(remove(blocked) == 0);
  assert(remove(db) == 0);
  char lock[700]; snprintf(lock, sizeof(lock), "%s.lock", db); (void)remove(lock);
#ifdef _WIN32
  (void)RemoveDirectoryA(inbox); (void)RemoveDirectoryA(dir);
#else
  (void)rmdir(inbox); (void)rmdir(dir);
#endif
  puts("command_process identity and durable receipts ok");
  return 0;
}
