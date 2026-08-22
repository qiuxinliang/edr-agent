#include "edr/command_util.h"
#include "edr/forensic_result_contract.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static CRITICAL_SECTION s_mu;
static CONDITION_VARIABLE s_cv;
typedef HANDLE TestThread;
#else
#include <pthread.h>
static pthread_mutex_t s_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_cv = PTHREAD_COND_INITIALIZER;
typedef pthread_t TestThread;
#endif

typedef struct {
  const char *command_id;
  const char *command_type;
} WorkerArg;

static int s_ready;
static char s_type_a[64];
static char s_type_b[64];
static int s_direct_report_pending = -1;
static int s_internal_report_pending = -1;

static void lock_test(void) {
#ifdef _WIN32
  EnterCriticalSection(&s_mu);
#else
  pthread_mutex_lock(&s_mu);
#endif
}

static void unlock_test(void) {
#ifdef _WIN32
  LeaveCriticalSection(&s_mu);
#else
  pthread_mutex_unlock(&s_mu);
#endif
}

static void wait_for_both_workers(void) {
  lock_test();
  s_ready++;
  if (s_ready == 2) {
#ifdef _WIN32
    WakeAllConditionVariable(&s_cv);
#else
    pthread_cond_broadcast(&s_cv);
#endif
  } else {
    while (s_ready < 2) {
#ifdef _WIN32
      SleepConditionVariableCS(&s_cv, &s_mu, INFINITE);
#else
      pthread_cond_wait(&s_cv, &s_mu);
#endif
    }
  }
  unlock_test();
}

static void worker_run(const WorkerArg *arg) {
  edr_command_set_active_type(arg->command_type);
  wait_for_both_workers();
  edr_command_emit_always(arg->command_id, NULL, EdrCmdExecOk, 0, "ok");
}

#ifdef _WIN32
static DWORD WINAPI worker_main(void *opaque) {
  worker_run((const WorkerArg *)opaque);
  return 0;
}
#else
static void *worker_main(void *opaque) {
  worker_run((const WorkerArg *)opaque);
  return NULL;
}
#endif

int edr_command_cancel_requested(const char *command_id) {
  (void)command_id;
  return 0;
}

int edr_ingest_http_configured(void) { return 1; }

int edr_command_state_finish(const char *command_id, const char *command_type,
                             const EdrSoarCommandMeta *meta, const char *response_status,
                             int execution_status, int exit_code, const char *detail,
                             const char *artifacts, int report_pending) {
  (void)meta;
  (void)response_status;
  (void)execution_status;
  (void)exit_code;
  (void)detail;
  (void)artifacts;
  lock_test();
  if (strcmp(command_id, "cmd-a") == 0) {
    snprintf(s_type_a, sizeof(s_type_a), "%s", command_type ? command_type : "");
  } else if (strcmp(command_id, "cmd-b") == 0) {
    snprintf(s_type_b, sizeof(s_type_b), "%s", command_type ? command_type : "");
  } else if (strcmp(command_id, "cmd_put_direct") == 0) {
    s_direct_report_pending = report_pending;
  } else if (strcmp(command_id, "internal-maintenance") == 0) {
    s_internal_report_pending = report_pending;
  }
  unlock_test();
  return 0;
}

void edr_command_state_delete_inbox(const char *command_id) { (void)command_id; }

const char *edr_command_normalize_forensic_result(const char *command_type,
                                                  EdrCommandExecutionStatus status,
                                                  int exit_code, const char *detail,
                                                  char *out, size_t out_cap) {
  (void)command_type;
  (void)status;
  (void)exit_code;
  (void)out;
  (void)out_cap;
  return detail;
}

int edr_parse_json_string(const uint8_t *payload, size_t len, const char *key,
                          char *out, size_t out_size) {
  (void)payload;
  (void)len;
  (void)key;
  if (out && out_size > 0u) out[0] = '\0';
  return 0;
}

int edr_parse_json_int(const uint8_t *payload, size_t len, const char *key, int *out) {
  (void)payload;
  (void)len;
  (void)key;
  (void)out;
  return 0;
}

int main(void) {
  WorkerArg args[2] = {{"cmd-a", "shell_open"}, {"cmd-b", "get_attack_surface"}};
  TestThread threads[2];
#ifdef _WIN32
  InitializeCriticalSection(&s_mu);
  InitializeConditionVariable(&s_cv);
  threads[0] = CreateThread(NULL, 0, worker_main, &args[0], 0, NULL);
  threads[1] = CreateThread(NULL, 0, worker_main, &args[1], 0, NULL);
  if (!threads[0] || !threads[1]) return 1;
  WaitForMultipleObjects(2, threads, TRUE, INFINITE);
  CloseHandle(threads[0]);
  CloseHandle(threads[1]);
#else
  if (pthread_create(&threads[0], NULL, worker_main, &args[0]) != 0 ||
      pthread_create(&threads[1], NULL, worker_main, &args[1]) != 0) {
    return 1;
  }
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);
#endif
  edr_command_set_active_type("rtr_put");
  edr_command_soar_emit("cmd_put_direct", NULL, EdrCmdExecOk, 0, "PUT_OK");
  edr_command_soar_emit("internal-maintenance", NULL, EdrCmdExecOk, 0, "ok");
  if (strcmp(s_type_a, "shell_open") != 0 ||
      strcmp(s_type_b, "get_attack_surface") != 0) {
    fprintf(stderr, "command type crossed worker threads: a=%s b=%s\n", s_type_a, s_type_b);
    return 1;
  }
  if (s_direct_report_pending != 1 || s_internal_report_pending != 0) {
    fprintf(stderr, "direct result reporting mismatch: direct=%d internal=%d\n",
            s_direct_report_pending, s_internal_report_pending);
    return 1;
  }
  if (edr_command_terminal_allows_cancel_override(1, 0, "ok") ||
      edr_command_terminal_allows_cancel_override(1, 1, "failed") ||
      !edr_command_terminal_allows_cancel_override(0, 0, "ok") ||
      edr_command_terminal_allows_cancel_override(0, 130, "failed") ||
      edr_command_terminal_allows_cancel_override(0, 1, "cancelled")) {
    fprintf(stderr, "authoritative terminal late-cancel policy mismatch\n");
    return 1;
  }
#ifdef _WIN32
  DeleteCriticalSection(&s_mu);
#endif
  return 0;
}
