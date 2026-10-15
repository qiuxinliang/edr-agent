/* Compile-time fixture boundary. The production Agent has no test modes. */
#if defined(_WIN32) && defined(EDR_COMMAND_STATE_INVENTORY_TEST)
#include <windows.h>
#include <stdlib.h>
#include <string.h>
static int q_injected_mode(const char *name) {
  const char *mode=getenv("EDR_PREFLIGHT_TEST_MODE");
  return mode && !strcmp(mode,name);
}
static HANDLE q_cli_create_event(LPSECURITY_ATTRIBUTES a,BOOL manual,BOOL initial,LPCSTR name) {
  if (q_injected_mode("watchdog_event_failure")) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
  return CreateEventA(a,manual,initial,name);
}
static HANDLE q_cli_create_thread(LPSECURITY_ATTRIBUTES a,SIZE_T size,LPTHREAD_START_ROUTINE fn,
                                  LPVOID context,DWORD flags,LPDWORD id) {
  if (q_injected_mode("watchdog_thread_failure")) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
  return CreateThread(a,size,fn,context,flags,id);
}
/* Failure injection is confined to the explicit CLI wrapper in this TU. */
#define CreateEventA q_cli_create_event
#define CreateThread q_cli_create_thread
#endif
#include "core/storage_space_preflight.h"
#if defined(_WIN32) && defined(EDR_COMMAND_STATE_INVENTORY_TEST)
#undef CreateEventA
#undef CreateThread
BOOL edr_command_state_inventory_test_unlock(HANDLE h,DWORD reserved,DWORD low,DWORD high,LPOVERLAPPED ov) {
  if (q_injected_mode("unlock_failure")) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  return UnlockFileEx(h,reserved,low,high,ov);
}
#endif
#if defined(_WIN32) && defined(EDR_COMMAND_STATE_INVENTORY_TEST)
static unsigned q_count[10];
static DWORD q_error[10];
static ULONGLONG q_started;
static const char *q_mode;
static HANDLE q_pending, q_cancel_entered, q_grant, q_resume;
static HANDLE q_completion_ready, q_completion_resume;
static HANDLE q_stall_entered, q_stall_resume, q_finished, q_finish_resume;

static void q_require(int ok) { if (!ok) abort(); }
static HANDLE q_event(const char *prefix, const char *suffix) {
  char name[160];
  int n = snprintf(name, sizeof(name), "%s-%s", prefix, suffix);
  q_require(n > 0 && (size_t)n < sizeof(name));
  HANDLE h = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
  q_require(h != NULL);
  return h;
}
static void q_trace(const char *point, int rc) {
  fprintf(stderr,
    "queued_test {\"schema\":\"inventory_queued_observation_v1\",\"point\":\"%s\","
    "\"mode\":\"%s\",\"rc\":%d,\"elapsed_ms\":%llu,\"watchdog_ms\":15000,"
    "\"requests\":%u,\"request_error\":%lu,\"lock_pending\":%u,"
    "\"cancel_calls\":%u,\"cancel_error\":%lu,\"lock_completions\":%u,\"lock_completion_error\":%lu,"
    "\"unlock_requests\":%u,\"unlock_request_error\":%lu,\"unlock_pending\":%u,"
    "\"unlock_completions\":%u,\"unlock_completion_error\":%lu,"
    "\"expired_observations\":%u,\"inventory_scan_calls\":%u}\n",
    point, q_mode, rc, (unsigned long long)(GetTickCount64()-q_started),
    q_count[1], (unsigned long)q_error[1], q_count[2],
    q_count[3], (unsigned long)q_error[3], q_count[4], (unsigned long)q_error[4],
    q_count[5], (unsigned long)q_error[5], q_count[6], q_count[7], (unsigned long)q_error[7],
    q_count[8], q_count[9]);
  fflush(stderr);
}
static void q_init(void) {
  q_started = GetTickCount64();
  q_mode = getenv("EDR_PREFLIGHT_TEST_MODE");
  if (!q_mode) return;
  q_require((!strcmp(q_mode,"observe") || !strcmp(q_mode,"late_grant") ||
      !strcmp(q_mode,"completion_expired") || !strcmp(q_mode,"stall") ||
      !strcmp(q_mode,"watchdog_event_failure") || !strcmp(q_mode,"watchdog_thread_failure") || !strcmp(q_mode,"unlock_failure")));
  const char *prefix = getenv("EDR_PREFLIGHT_TEST_EVENT_PREFIX");
  q_require(prefix && !strncmp(prefix,"Local\\EDRInventory-",19) && strlen(prefix)<96u);
  q_pending=q_event(prefix,"q-pending");
  q_cancel_entered=q_event(prefix,"q-cancel-entered");
  q_grant=q_event(prefix,"q-grant");
  q_resume=q_event(prefix,"q-resume");
  q_completion_ready=q_event(prefix,"q-completion-ready");
  q_completion_resume=q_event(prefix,"q-completion-resume");
  q_stall_entered=q_event(prefix,"q-stall-entered");
  q_stall_resume=q_event(prefix,"q-stall-resume");
  q_finished=q_event(prefix,"q-finished");
  q_finish_resume=q_event(prefix,"q-finish-resume");
}
void edr_command_state_inventory_test_observe(unsigned phase, DWORD error) {
  if (!q_mode) return;
  q_require(phase>0u && phase<10u && q_count[phase]<16u);
  q_count[phase]++; q_error[phase]=error;
  if (phase==2u) q_require(SetEvent(q_pending));
  if (phase==4u && error==ERROR_SUCCESS && !strcmp(q_mode,"completion_expired")) {
    q_require(SetEvent(q_completion_ready));
    q_require(WaitForSingleObject(q_completion_resume,5000u)==WAIT_OBJECT_0);
  }
}
void edr_command_state_inventory_test_before_cancel(HANDLE completion_event) {
  if (!q_mode) return;
  if (!strcmp(q_mode,"late_grant")) {
    q_require(SetEvent(q_cancel_entered));
    /* Completion is the real kernel lock event, not the parent's unlock guess. */
    q_require(WaitForSingleObject(completion_event,5000u)==WAIT_OBJECT_0);
    q_require(SetEvent(q_grant));
    q_require(WaitForSingleObject(q_resume,5000u)==WAIT_OBJECT_0);
  } else if (!strcmp(q_mode,"stall")) {
    q_trace("cleanup_stall_entered",-1);
    q_require(SetEvent(q_stall_entered));
    /* Intentional test-only native blocking wait; only CLI watchdog bounds it. */
    q_require(WaitForSingleObject(q_stall_resume,INFINITE)==WAIT_OBJECT_0);
  }
}
#endif
#ifdef _WIN32
/* Config loading has no socket listener in this CLI client. */
void edr_win_listen_apply_config(const EdrConfig *cfg) { (void)cfg; }
#endif
int edr_local_evidence_cache_record_command_result(const char *a,const char *b,
    const char *c,int d,int e,const char *f,const char *g) {
  (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;abort();
}
int main(int argc,char **argv) {
  if (argc<2 || strcmp(argv[1],"--storage-space-preflight")) return 2;
#if defined(_WIN32) && defined(EDR_COMMAND_STATE_INVENTORY_TEST)
  q_init();
  int rc=edr_storage_space_preflight_main(argc,argv);
  if (!q_mode) return rc;
  q_trace("returned",rc);
  /* Keep this process alive after real cleanup so third-party reacquisition
   * cannot accidentally be satisfied by OS process-exit lock cleanup. */
  q_require(SetEvent(q_finished));
  q_require(WaitForSingleObject(q_finish_resume,5000u)==WAIT_OBJECT_0);
  HANDLE events[]={q_pending,q_cancel_entered,q_grant,q_resume,q_completion_ready,
    q_completion_resume,q_stall_entered,q_stall_resume,q_finished,q_finish_resume};
  for (size_t i=0;i<sizeof(events)/sizeof(events[0]);i++) q_require(CloseHandle(events[i]));
  return rc;
#else
  return edr_storage_space_preflight_main(argc,argv);
#endif
}
