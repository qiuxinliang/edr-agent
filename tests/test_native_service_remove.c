/* Executes the production SCM state machine. Only Win32 I/O is simulated;
 * no service or process on the test host is stopped. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>
#else
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *SC_HANDLE;
typedef unsigned char *LPBYTE;
typedef struct { DWORD dwCurrentState, dwProcessId, dwCheckPoint, dwWaitHint; } SERVICE_STATUS_PROCESS;
typedef SERVICE_STATUS_PROCESS SERVICE_STATUS;
typedef struct { DWORD Type, Delay; } SC_ACTION;
typedef struct { DWORD dwResetPeriod, cActions; SC_ACTION *lpsaActions; } SERVICE_FAILURE_ACTIONSW;
typedef struct { BOOL fFailureActionsOnNonCrashFailures; } SERVICE_FAILURE_ACTIONS_FLAG;
#define FALSE 0
#define ERROR_SUCCESS 0u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_DATA 13u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_GEN_FAILURE 31u
#define ERROR_SERVICE_DOES_NOT_EXIST 1060u
#define ERROR_SERVICE_NOT_ACTIVE 1062u
#define ERROR_SERVICE_CANNOT_ACCEPT_CTRL 1061u
#define ERROR_SERVICE_MARKED_FOR_DELETE 1072u
#define ERROR_TIMEOUT 1460u
#define SERVICE_STOPPED 1u
#define SERVICE_START_PENDING 2u
#define SERVICE_STOP_PENDING 3u
#define SERVICE_RUNNING 4u
#define SC_MANAGER_CONNECT 1u
#define SERVICE_QUERY_STATUS 4u
#define SERVICE_QUERY_CONFIG 1u
#define SERVICE_START 16u
#define SERVICE_STOP 32u
#define SERVICE_CHANGE_CONFIG 2u
#define DELETE 0x10000u
#define SYNCHRONIZE 0x100000u
#define SERVICE_CONFIG_FAILURE_ACTIONS 2u
#define SERVICE_CONFIG_FAILURE_ACTIONS_FLAG 4u
#define SC_STATUS_PROCESS_INFO 0u
#define SERVICE_CONTROL_STOP 1u
#define ZeroMemory(p,n) memset((p),0,(n))
#endif

static struct {
  DWORD now, error, state, pid, control_error, fallback_error;
  unsigned queries, query_fail_at, controls, stops, deletes, config_calls;
  int manager_fail, open_fail, config_fail, delete_fail, pin_fail;
  int stuck, pid_changes, recheck_pid_changes, missing, deletion_stuck;
  int post_query_fail, post_stuck, race_stopped, marked_delete, recheck_fail;
  int snapshot_fail, restoring, starts, pin_attempted, pin_exit_race, empty_actions;
  DWORD start_error;
  int deleted, recovery_disabled, manager_handles, service_handles, pinned;
} scm;

static DWORD fake_GetLastError(void) { return scm.error; }
static DWORD fake_GetTickCount(void) { return scm.now; }
static void fake_Sleep(DWORD ms) { scm.now += ms; }
static SC_HANDLE fake_OpenSCManagerW(const wchar_t *a, const wchar_t *b, DWORD access) {
  (void)a; (void)b; assert(access == SC_MANAGER_CONNECT);
  if (scm.manager_fail) { scm.error = ERROR_ACCESS_DENIED; return NULL; }
  scm.manager_handles++; return (SC_HANDLE)(uintptr_t)1;
}
static SC_HANDLE fake_OpenServiceW(SC_HANDLE m, const wchar_t *name, DWORD access) {
  (void)name; (void)access; assert(m);
  if (scm.open_fail) { scm.error = ERROR_ACCESS_DENIED; return NULL; }
  if (scm.missing || scm.deleted) {
    scm.error = scm.deletion_stuck && scm.deleted ? ERROR_SERVICE_MARKED_FOR_DELETE
                                                : ERROR_SERVICE_DOES_NOT_EXIST;
    return NULL;
  }
  scm.service_handles++; return (SC_HANDLE)(uintptr_t)2;
}
static BOOL fake_CloseServiceHandle(SC_HANDLE h) {
  if (h == (SC_HANDLE)(uintptr_t)1) scm.manager_handles--;
  else { assert(h == (SC_HANDLE)(uintptr_t)2); scm.service_handles--; }
  scm.error = 999u; return 1; /* Cleanup must not overwrite the real failure. */
}
static BOOL fake_ChangeServiceConfig2W(SC_HANDLE h, DWORD level, void *data) {
  assert(h); scm.config_calls++;
  if (scm.restoring) {
    if (level == SERVICE_CONFIG_FAILURE_ACTIONS) {
      SERVICE_FAILURE_ACTIONSW *actions = data;
      assert(actions->cActions == (scm.empty_actions ? 0u : 2u));
      assert(actions->lpsaActions);
      if (!scm.empty_actions) {
        assert(actions->dwResetPeriod == 1234u);
        assert(actions->lpsaActions[0].Type == 1 && actions->lpsaActions[0].Delay == 60000);
        assert(actions->lpsaActions[1].Type == 1 && actions->lpsaActions[1].Delay == 70000);
      }
    } else assert(((SERVICE_FAILURE_ACTIONS_FLAG *)data)->fFailureActionsOnNonCrashFailures == 1);
    return 1;
  }
  if (scm.config_fail == (int)scm.config_calls) { scm.error = ERROR_ACCESS_DENIED; return 0; }
  if (level == SERVICE_CONFIG_FAILURE_ACTIONS) {
    SERVICE_FAILURE_ACTIONSW *actions = data;
    assert(actions->cActions == 0 && actions->lpsaActions != NULL);
    scm.recovery_disabled = 1;
  } else {
    assert(level == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG);
    assert(!((SERVICE_FAILURE_ACTIONS_FLAG *)data)->fFailureActionsOnNonCrashFailures);
  }
  return 1;
}
static BOOL fake_QueryServiceConfig2W(SC_HANDLE h, DWORD level, LPBYTE data, DWORD size, DWORD *needed) {
  assert(h);
  if (scm.snapshot_fail) { scm.error = ERROR_ACCESS_DENIED; return 0; }
  if (level == SERVICE_CONFIG_FAILURE_ACTIONS) {
    *needed = (DWORD)(sizeof(SERVICE_FAILURE_ACTIONSW) + 2 * sizeof(SC_ACTION));
    if (size < *needed) { scm.error = ERROR_INSUFFICIENT_BUFFER; return 0; }
    SERVICE_FAILURE_ACTIONSW *actions = (SERVICE_FAILURE_ACTIONSW *)data;
    ZeroMemory(data, size);
    actions->dwResetPeriod = 1234;
    actions->cActions = scm.empty_actions ? 0 : 2;
    if (!scm.empty_actions) {
      actions->lpsaActions = (SC_ACTION *)(data + sizeof(*actions));
      actions->lpsaActions[0].Type = 1; actions->lpsaActions[0].Delay = 60000;
      actions->lpsaActions[1].Type = 1; actions->lpsaActions[1].Delay = 70000;
    }
  } else {
    assert(size == sizeof(SERVICE_FAILURE_ACTIONS_FLAG));
    ((SERVICE_FAILURE_ACTIONS_FLAG *)data)->fFailureActionsOnNonCrashFailures = 1;
    *needed = sizeof(SERVICE_FAILURE_ACTIONS_FLAG);
  }
  return 1;
}
static BOOL fake_StartServiceW(SC_HANDLE h, DWORD argc, const wchar_t **argv) {
  (void)argv; assert(h && !argc && scm.restoring); scm.starts++;
  if (scm.start_error) { scm.error = scm.start_error; return 0; }
  return 1;
}
static BOOL fake_QueryServiceStatusEx(SC_HANDLE h, int info, LPBYTE dst, DWORD size, DWORD *bytes) {
  SERVICE_STATUS_PROCESS *status = (SERVICE_STATUS_PROCESS *)dst;
  (void)info; assert(h && size == sizeof(*status)); scm.queries++;
  if (scm.queries == scm.query_fail_at || (scm.stops && scm.post_query_fail) ||
      (scm.pinned && scm.recheck_fail)) {
    scm.error = ERROR_ACCESS_DENIED; return 0;
  }
  if (!scm.stuck && scm.state == SERVICE_STOP_PENDING && scm.now >= 100u)
    scm.state = SERVICE_STOPPED;
  if (scm.pin_attempted && scm.pin_exit_race) scm.state = SERVICE_STOPPED;
  ZeroMemory(status, sizeof(*status));
  status->dwCurrentState = scm.state;
  status->dwProcessId = scm.state == SERVICE_STOPPED ? 0 : scm.pid;
  if ((scm.pid_changes && scm.now >= 30000u) || (scm.recheck_pid_changes && scm.pinned))
    status->dwProcessId++;
  status->dwCheckPoint = 1; status->dwWaitHint = 30000;
  *bytes = sizeof(*status); return 1;
}
static BOOL fake_ControlService(SC_HANDLE h, DWORD command, SERVICE_STATUS *ignored) {
  (void)ignored; assert(h && command == SERVICE_CONTROL_STOP); scm.controls++;
  if (scm.control_error) {
    if (scm.race_stopped) scm.state = SERVICE_STOPPED;
    scm.error = scm.control_error; return 0;
  }
  scm.state = SERVICE_STOP_PENDING; return 1;
}
static BOOL fake_DeleteService(SC_HANDLE h) {
  assert(h && scm.state == SERVICE_STOPPED); scm.deletes++;
  if (scm.delete_fail) { scm.error = ERROR_ACCESS_DENIED; return 0; }
  scm.deleted = 1;
  if (scm.marked_delete) { scm.error = ERROR_SERVICE_MARKED_FOR_DELETE; return 0; }
  return 1;
}
static HANDLE fake_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
  assert(access == SYNCHRONIZE && !inherit && pid == scm.pid && pid);
  scm.pin_attempted = 1;
  if (scm.pin_fail) { scm.error = ERROR_ACCESS_DENIED; return NULL; }
  scm.pinned++; return (HANDLE)(uintptr_t)3;
}
static BOOL fake_CloseHandle(HANDLE h) {
  assert(h == (HANDLE)(uintptr_t)3 && scm.pinned == 1);
  scm.pinned--; scm.error = 999u; return 1;
}
static int fake_stop_sensor(const wchar_t *dir, DWORD pid, int strict) {
  assert(dir && pid == scm.pid && pid && strict && scm.pinned == 1);
  assert(scm.recovery_disabled && !scm.deleted && scm.now >= 30000u);
  scm.stops++;
  if (scm.fallback_error) return (int)scm.fallback_error;
  if (!scm.post_stuck) scm.state = SERVICE_STOPPED;
  return ERROR_SUCCESS;
}

#define GetLastError fake_GetLastError
#define GetTickCount fake_GetTickCount
#define Sleep fake_Sleep
#define OpenSCManagerW fake_OpenSCManagerW
#define OpenServiceW fake_OpenServiceW
#define CloseServiceHandle fake_CloseServiceHandle
#define ChangeServiceConfig2W fake_ChangeServiceConfig2W
#define QueryServiceConfig2W fake_QueryServiceConfig2W
#define StartServiceW fake_StartServiceW
#define QueryServiceStatusEx fake_QueryServiceStatusEx
#define ControlService fake_ControlService
#define DeleteService fake_DeleteService
#define OpenProcess fake_OpenProcess
#define CloseHandle fake_CloseHandle
#include "../src/installer_worker/native_service_remove.h"

static void reset_scm(void) {
  memset(&scm, 0, sizeof(scm)); scm.pid = 708; scm.state = SERVICE_RUNNING;
}
static EdrNativeServiceRemoval check(DWORD expected, const char *stage) {
  EdrNativeServiceRemoval out;
  DWORD result = edr_native_stop_delete_service(L"fixture", L"fixture-dir", &out, fake_stop_sensor);
  if (result != expected || (stage && strcmp(out.stage, stage))) {
    fprintf(stderr, "service removal: got error=%lu stage=%s; expected=%lu stage=%s\n",
        (unsigned long)result, out.stage, (unsigned long)expected, stage ? stage : "any");
    assert(0);
  }
  assert(!scm.manager_handles && !scm.service_handles && !scm.pinned);
  assert(!out.recovery_attempted); /* Sole recovery owner is the finalizer. */
  if (out.recovery_changed && !out.deletion_committed) {
    scm.restoring = 1;
    assert(edr_native_restore_service_and_start(L"fixture", &out) == scm.start_error);
    assert(scm.starts == 1 && !scm.manager_handles && !scm.service_handles);
  }
  free(out.previous_actions);
  out.previous_actions = NULL;
  return out;
}
int edr_test_native_service_removal(void);
int edr_test_native_service_removal(void) {
  EdrNativeServiceRemoval out;
  reset_scm(); check(ERROR_SUCCESS, "verify-service-deleted"); assert(!scm.stops && scm.deletes == 1);
  reset_scm(); scm.state = SERVICE_STOPPED; check(ERROR_SUCCESS, NULL); assert(!scm.controls && !scm.stops);
  reset_scm(); scm.stuck = 1;
  out = check(ERROR_SUCCESS, "verify-service-deleted");
  assert(scm.stops == 1 && scm.deletes == 1 && out.deletion_committed && out.pid == 708);
  reset_scm(); scm.stuck = 1; scm.state = SERVICE_STOP_PENDING;
  check(ERROR_SUCCESS, NULL); assert(!scm.controls && scm.stops == 1);
  reset_scm(); scm.missing = 1; check(ERROR_SUCCESS, "open-service"); assert(!scm.deletes && !scm.stops);
  reset_scm(); scm.manager_fail = 1; check(ERROR_ACCESS_DENIED, "open-service-manager");
  reset_scm(); scm.open_fail = 1; check(ERROR_ACCESS_DENIED, "open-service");
  reset_scm(); scm.snapshot_fail = 1;
  out = check(ERROR_ACCESS_DENIED, "snapshot-service-recovery"); assert(!out.recovery_changed && !scm.config_calls);
  for (int i = 1; i <= 2; ++i) {
    reset_scm(); scm.config_fail = i;
    out = check(ERROR_ACCESS_DENIED, "disable-service-recovery"); assert(out.recovery_changed && !scm.stops);
  }
  reset_scm(); scm.query_fail_at = 1; check(ERROR_ACCESS_DENIED, "query-service-before-stop");
  reset_scm(); scm.query_fail_at = 2; check(ERROR_ACCESS_DENIED, "wait-service-stop");
  reset_scm(); scm.control_error = ERROR_ACCESS_DENIED; check(ERROR_ACCESS_DENIED, "request-service-stop");
  reset_scm(); scm.control_error = ERROR_SERVICE_NOT_ACTIVE; scm.race_stopped = 1; check(ERROR_SUCCESS, NULL);
  reset_scm(); scm.control_error = ERROR_SERVICE_CANNOT_ACCEPT_CTRL; scm.state = SERVICE_START_PENDING;
  check(ERROR_SERVICE_CANNOT_ACCEPT_CTRL, "request-service-stop"); assert(!scm.stops);
  reset_scm(); scm.stuck = 1; scm.pid = 0; check(ERROR_TIMEOUT, "wait-service-stop"); assert(!scm.stops);
  reset_scm(); scm.stuck = 1; scm.pid_changes = 1; check(ERROR_TIMEOUT, "wait-service-stop"); assert(!scm.stops);
  reset_scm(); scm.stuck = 1; scm.recheck_pid_changes = 1;
  check(ERROR_INVALID_DATA, "recheck-service-process"); assert(!scm.stops);
  reset_scm(); scm.stuck = 1; scm.recheck_fail = 1;
  check(ERROR_ACCESS_DENIED, "recheck-service-process"); assert(!scm.stops);
  reset_scm(); scm.stuck = 1; scm.pin_fail = 1; check(ERROR_ACCESS_DENIED, "pin-service-process");
  reset_scm(); scm.stuck = 1; scm.pin_fail = 1; scm.pin_exit_race = 1;
  check(ERROR_SUCCESS, "verify-service-deleted"); assert(!scm.stops && scm.deletes == 1);
  reset_scm(); scm.stuck = 1; scm.fallback_error = ERROR_INVALID_DATA;
  check(ERROR_INVALID_DATA, "stop-service-process"); assert(!scm.deletes);
  reset_scm(); scm.stuck = 1; scm.fallback_error = ERROR_ACCESS_DENIED;
  check(ERROR_ACCESS_DENIED, "stop-service-process"); assert(!scm.deletes);
  reset_scm(); scm.stuck = 1; scm.post_query_fail = 1;
  check(ERROR_ACCESS_DENIED, "verify-service-stopped"); assert(!scm.deletes);
  reset_scm(); scm.stuck = 1; scm.post_stuck = 1;
  check(ERROR_TIMEOUT, "verify-service-stopped"); assert(scm.stops == 1 && !scm.deletes);
  reset_scm(); scm.delete_fail = 1;
  out = check(ERROR_ACCESS_DENIED, "delete-service"); assert(!out.deletion_committed);
  reset_scm(); scm.delete_fail = 1; scm.empty_actions = 1; check(ERROR_ACCESS_DENIED, "delete-service");
  reset_scm(); scm.delete_fail = 1; scm.start_error = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
  check(ERROR_ACCESS_DENIED, "delete-service"); /* Recovery failure cannot replace primary denial. */
  reset_scm(); scm.deletion_stuck = 1;
  out = check(ERROR_TIMEOUT, "verify-service-deleted"); assert(out.deletion_committed);
  reset_scm(); scm.marked_delete = 1; check(ERROR_SUCCESS, "verify-service-deleted");
  puts("native service removal: stop-pending, identity, error and deletion contracts passed");
  return 1;
}
#ifdef EDR_SERVICE_REMOVE_STANDALONE
int main(void) { return edr_test_native_service_removal() ? 0 : 1; }
#endif
