#include "edr/policy_enforcement.h"

#include "edr/policy_v2.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static const char *basename_c(const char *path) {
  const char *base = path ? path : "";
  for (const char *p = base; *p; ++p) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
    }
  }
  return base;
}

static int protected_process_name(const char *name) {
  static const char *protected_names[] = {
      "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
      "services.exe", "lsass.exe", "winlogon.exe", "fdsensor.exe",
      "edr_agent.exe"};
  const char *base = basename_c(name);
  for (size_t i = 0; i < sizeof(protected_names) / sizeof(protected_names[0]); ++i) {
    if (_stricmp(base, protected_names[i]) == 0) {
      return 1;
    }
  }
  return 0;
}
#endif

void edr_policy_enforce_alert(const EdrBehaviorRecord *record,
                              const char *triggered_tactics,
                              const char *rule_id,
                              EdrPolicyEnforcementResult *result) {
  if (!result) {
    return;
  }
  memset(result, 0, sizeof(*result));
  snprintf(result->action, sizeof(result->action), "%s", "none");
  if (edr_policy_v2_mode_for_alert(triggered_tactics, rule_id) != EDR_POLICY_MODE_BLOCK) {
    snprintf(result->message, sizeof(result->message), "%s", "policy mode is not block");
    return;
  }
  result->requested = 1;
  if (!record) {
    snprintf(result->message, sizeof(result->message), "%s", "missing behavior record");
    return;
  }

#if defined(_WIN32)
  if ((record->type != EDR_EVENT_PROCESS_CREATE &&
       record->type != EDR_EVENT_SCRIPT_POWERSHELL &&
       record->type != EDR_EVENT_SCRIPT_WMI) ||
      record->pid <= 4u || record->pid == GetCurrentProcessId()) {
    snprintf(result->message, sizeof(result->message), "%s", "event has no terminable process");
    return;
  }
  if (protected_process_name(record->process_name) || protected_process_name(record->exe_path)) {
    snprintf(result->action, sizeof(result->action), "%s", "protected");
    snprintf(result->message, sizeof(result->message), "%s", "protected process denied");
    return;
  }

  result->attempted = 1;
  snprintf(result->action, sizeof(result->action), "%s", "terminate_process");
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                               FALSE, (DWORD)record->pid);
  if (!process) {
    result->error_code = (uint32_t)GetLastError();
    snprintf(result->message, sizeof(result->message), "OpenProcess failed: %lu",
             (unsigned long)result->error_code);
    return;
  }

  char live_path[1024];
  DWORD live_path_size = (DWORD)sizeof(live_path);
  live_path[0] = '\0';
  if (QueryFullProcessImageNameA(process, 0, live_path, &live_path_size) &&
      record->process_name[0] &&
      _stricmp(basename_c(live_path), basename_c(record->process_name)) != 0) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "stale_pid");
    snprintf(result->message, sizeof(result->message), "%s", "PID image changed before enforcement");
    return;
  }
  if (protected_process_name(live_path)) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "protected");
    snprintf(result->message, sizeof(result->message), "%s", "live image is protected");
    return;
  }
  if (!TerminateProcess(process, 137u)) {
    result->error_code = (uint32_t)GetLastError();
    CloseHandle(process);
    snprintf(result->message, sizeof(result->message), "TerminateProcess failed: %lu",
             (unsigned long)result->error_code);
    return;
  }
  (void)WaitForSingleObject(process, 1500u);
  CloseHandle(process);
  result->succeeded = 1;
  snprintf(result->message, sizeof(result->message), "%s", "process terminated");
#else
  (void)record;
  snprintf(result->action, sizeof(result->action), "%s", "unsupported_platform");
  snprintf(result->message, sizeof(result->message), "%s", "blocking is not implemented on this platform");
#endif
}
