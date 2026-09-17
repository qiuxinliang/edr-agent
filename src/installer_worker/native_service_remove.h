#ifndef EDR_NATIVE_SERVICE_REMOVE_H
#define EDR_NATIVE_SERVICE_REMOVE_H
#include <stdlib.h>
/* Internal Win32 I/O boundary, shared by the finalizer and its fault fixtures.
 * Caller supplies Win32 types/APIs and the existing identity-checked stopper,
 * then frees previous_actions after any recovery and receipt publication. */
typedef struct {
  const char *stage;
  SERVICE_STATUS_PROCESS status;
  DWORD pid;
  int recovery_changed;
  int deletion_committed;
  int recovery_attempted;
  DWORD recovery_error;
  SERVICE_FAILURE_ACTIONSW *previous_actions;
  SERVICE_FAILURE_ACTIONS_FLAG previous_flags;
} EdrNativeServiceRemoval;

static DWORD edr_native_service_error(void) {
  DWORD error = GetLastError();
  return error ? error : ERROR_GEN_FAILURE;
}

static DWORD edr_native_stop_delete_service(const wchar_t *service_name,
    const wchar_t *install_dir, EdrNativeServiceRemoval *out,
    int (*stop_sensor)(const wchar_t *, DWORD, int)) {
  SC_HANDLE manager = NULL, service = NULL;
  HANDLE pinned = NULL;
  DWORD bytes = 0, started, error = ERROR_SUCCESS;
  SERVICE_FAILURE_ACTIONSW no_actions;
  SERVICE_FAILURE_ACTIONS_FLAG no_failure_flag;
  SC_ACTION unused_action;
  ZeroMemory(out, sizeof(*out));
  out->stage = "open-service-manager";
  manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!manager) return edr_native_service_error();
  out->stage = "open-service";
  service = OpenServiceW(manager, service_name,
      SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE);
  if (!service) {
    error = edr_native_service_error();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) error = ERROR_SUCCESS;
    goto cleanup;
  }
  out->stage = "snapshot-service-recovery";
  if (QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, NULL, 0, &bytes) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(*out->previous_actions)) {
    error = edr_native_service_error(); goto cleanup;
  }
  out->previous_actions = (SERVICE_FAILURE_ACTIONSW *)malloc(bytes);
  if (!out->previous_actions) { error = ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
  if (!QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS,
      (LPBYTE)out->previous_actions, bytes, &bytes) ||
      !QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
      (LPBYTE)&out->previous_flags, sizeof(out->previous_flags), &bytes)) {
    error = edr_native_service_error(); goto cleanup;
  }
  out->stage = "disable-service-recovery";
  ZeroMemory(&no_actions, sizeof(no_actions));
  ZeroMemory(&unused_action, sizeof(unused_action));
  no_actions.lpsaActions = &unused_action;
  /* cActions=0 with NULL lpsaActions means UNCHANGED, not disabled. */
  no_failure_flag.fFailureActionsOnNonCrashFailures = FALSE;
  out->recovery_changed = 1; /* Either configuration call may partially succeed. */
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &no_actions) ||
      !ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &no_failure_flag)) {
    error = edr_native_service_error(); goto cleanup;
  }
  out->stage = "query-service-before-stop";
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
      (LPBYTE)&out->status, sizeof(out->status), &bytes)) {
    error = edr_native_service_error(); goto cleanup;
  }
  out->pid = out->status.dwProcessId;
  started = GetTickCount();
  if (out->status.dwCurrentState != SERVICE_STOPPED &&
      out->status.dwCurrentState != SERVICE_STOP_PENDING) {
    SERVICE_STATUS ignored;
    out->stage = "request-service-stop";
    if (!ControlService(service, SERVICE_CONTROL_STOP, &ignored)) {
      error = edr_native_service_error();
      /* A concurrent stop is acceptable only if the next query proves it. */
      if (error != ERROR_SERVICE_NOT_ACTIVE && error != ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
        goto cleanup;
      if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
          (LPBYTE)&out->status, sizeof(out->status), &bytes)) {
        out->stage = "query-service-after-stop";
        error = edr_native_service_error(); goto cleanup;
      }
      if (out->status.dwCurrentState != SERVICE_STOPPED &&
          out->status.dwCurrentState != SERVICE_STOP_PENDING) goto cleanup;
      error = ERROR_SUCCESS;
    }
  }
  out->stage = "wait-service-stop";
  while (out->status.dwCurrentState != SERVICE_STOPPED) {
    if (GetTickCount() - started >= 30000u) {
      error = ERROR_TIMEOUT;
      if (out->status.dwCurrentState != SERVICE_STOP_PENDING || !out->pid ||
          out->status.dwProcessId != out->pid) goto cleanup;
      /* Pin identity BEFORE rechecking the authoritative SCM PID. Never use
       * the stopper's pid=0 enumeration path for a stuck service. */
      out->stage = "pin-service-process";
      pinned = OpenProcess(SYNCHRONIZE, FALSE, out->pid);
      if (!pinned) {
        error = edr_native_service_error();
        /* Natural exit can win the race after the last pending observation.
         * Only a fresh STOPPED result permits progress without a pinned PID. */
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&out->status, sizeof(out->status), &bytes) &&
            out->status.dwCurrentState == SERVICE_STOPPED) { error = ERROR_SUCCESS; break; }
        goto cleanup;
      }
      out->stage = "recheck-service-process";
      if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
          (LPBYTE)&out->status, sizeof(out->status), &bytes)) {
        error = edr_native_service_error(); goto cleanup;
      }
      if (out->status.dwCurrentState == SERVICE_STOPPED) { error = ERROR_SUCCESS; break; }
      if (out->status.dwCurrentState != SERVICE_STOP_PENDING ||
          out->status.dwProcessId != out->pid) { error = ERROR_INVALID_DATA; goto cleanup; }
      out->stage = "stop-service-process";
      error = (DWORD)stop_sensor(install_dir, out->pid, 1);
      if (error != ERROR_SUCCESS) goto cleanup;
      out->stage = "verify-service-stopped";
      /* Process exit and SCM publication need not happen simultaneously. */
      started = GetTickCount();
      do {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&out->status, sizeof(out->status), &bytes)) {
          error = edr_native_service_error(); goto cleanup;
        }
        if (out->status.dwCurrentState == SERVICE_STOPPED) break;
        if (out->status.dwProcessId != out->pid) { error = ERROR_INVALID_DATA; goto cleanup; }
        if (GetTickCount() - started >= 5000u) { error = ERROR_TIMEOUT; goto cleanup; }
        Sleep(100);
      } while (1);
      break;
    }
    Sleep(100);
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&out->status, sizeof(out->status), &bytes)) {
      error = edr_native_service_error(); goto cleanup;
    }
  }
  out->stage = "delete-service";
  if (!DeleteService(service)) {
    error = edr_native_service_error();
    if (error != ERROR_SERVICE_MARKED_FOR_DELETE) goto cleanup;
  }
  out->deletion_committed = 1;
  CloseServiceHandle(service);
  service = NULL;
  out->stage = "verify-service-deleted";
  started = GetTickCount();
  for (;;) {
    service = OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
    if (!service) {
      error = edr_native_service_error();
      if (error == ERROR_SERVICE_DOES_NOT_EXIST) { error = ERROR_SUCCESS; break; }
      if (error != ERROR_SERVICE_MARKED_FOR_DELETE) break;
    } else {
      CloseServiceHandle(service); service = NULL;
    }
    if (GetTickCount() - started >= 30000u) { error = ERROR_TIMEOUT; break; }
    Sleep(100);
  }
cleanup:
  if (pinned) CloseHandle(pinned);
  if (service) CloseServiceHandle(service);
  if (manager) CloseServiceHandle(manager);
  /* Recovery belongs to the finalizer, exactly once and only pre-deletion. */
  return error;
}

static DWORD edr_native_restore_service_and_start(const wchar_t *service_name,
    const EdrNativeServiceRemoval *saved) {
  SC_HANDLE manager, service;
  DWORD error;
  SERVICE_FAILURE_ACTIONSW actions;
  SERVICE_FAILURE_ACTIONS_FLAG flags = saved->previous_flags;
  SC_ACTION unused_action;
  if (!saved->previous_actions) return ERROR_INVALID_DATA;
  actions = *saved->previous_actions;
  ZeroMemory(&unused_action, sizeof(unused_action));
  /* A saved empty array must also be explicitly restored as empty. */
  if (!actions.cActions) actions.lpsaActions = &unused_action;
  manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (!manager) return edr_native_service_error();
  service = OpenServiceW(manager, service_name, SERVICE_CHANGE_CONFIG | SERVICE_START);
  if (!service) { error = edr_native_service_error(); CloseServiceHandle(manager); return error; }
  error = ERROR_SUCCESS;
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &actions) ||
      !ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flags) ||
      !StartServiceW(service, 0, NULL)) error = edr_native_service_error();
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return error;
}
#endif
