#include "edr/policy_enforcement.h"

#include "edr/p0_source_only_contract.h"
#include "edr/policy_v2.h"
#include "edr/windows_file_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef EDR_P0_DIRECT_EMIT_TESTING
static EdrPolicyEnforcementTestExecuteHook s_test_execute_hook;
void edr_policy_enforcement_test_set_execute_hook(EdrPolicyEnforcementTestExecuteHook hook) {
  s_test_execute_hook = hook;
}
#endif

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

static int record_file_identity(const EdrBehaviorRecord *record, char *out, size_t out_cap) {
  const char *value;
  const char *end;
  size_t len;
  if (out && out_cap > 0u) out[0] = '\0';
  if (!record || !out || out_cap < EDR_WINDOWS_FILE_IDENTITY_V1_CAP) return 0;
  if (!edr_p0_artifact_identity_is_action_authoritative(record->detection_context)) return 0;
  value = strstr(record->detection_context, "\"file_identity\":\"");
  if (!value) return 0;
  value += strlen("\"file_identity\":\"");
  end = strchr(value, '\"');
  if (!end) return 0;
  len = (size_t)(end - value);
  if (len + 1u > out_cap) return 0;
  memcpy(out, value, len);
  out[len] = '\0';
  return edr_windows_file_identity_valid(out);
}

static int live_file_identity(const char *path, char *out, size_t out_cap) {
  uint64_t ignored_write_time = 0u;
  if (out && out_cap > 0u) out[0] = '\0';
  if (!path || !path[0] || !out || out_cap < EDR_WINDOWS_FILE_IDENTITY_V1_CAP) return 0;
  return edr_windows_file_identity_from_path(path, out, out_cap, &ignored_write_time);
}
#endif

void edr_policy_enforcement_plan(const EdrBehaviorRecord *record,
                                 const char *triggered_tactics,
                                 const char *rule_id,
                                 EdrPolicyEnforcementResult *result) {
  if (!result) {
    return;
  }
  memset(result, 0, sizeof(*result));
  snprintf(result->planned_action, sizeof(result->planned_action), "%s", "none");
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
  snprintf(result->planned_action, sizeof(result->planned_action), "%s", "terminate_process");
}

void edr_policy_enforcement_execute(const EdrBehaviorRecord *record,
                                    EdrPolicyEnforcementResult *result) {
  if (!result || !result->requested) {
    return;
  }
  if (!record) {
    snprintf(result->message, sizeof(result->message), "%s", "missing behavior record");
    return;
  }
  /* This guard intentionally precedes the test executor and platform action.
   * A direct caller cannot turn an after-the-fact pathname snapshot into a
   * process-image authority by bypassing p0_rule_direct_emit. */
  if (record->type == EDR_EVENT_PROCESS_CREATE &&
      !edr_p0_artifact_identity_is_action_authoritative(record->detection_context)) {
    snprintf(result->action, sizeof(result->action), "%s", "artifact_authority_unavailable");
    snprintf(result->message, sizeof(result->message), "%s",
             "process image artifact is only a post-event path snapshot");
    return;
  }
#ifdef EDR_P0_DIRECT_EMIT_TESTING
  if (s_test_execute_hook) {
    s_test_execute_hook(record, result);
    return;
  }
#endif

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

  /* PID alone is never an enforcement identity.  The ETW process-create
   * timestamp is the observed creation generation; reject a reused PID when
   * the live kernel creation time is not that generation. */
  FILETIME created, exited, kernel, user;
  ULARGE_INTEGER live_created;
  uint64_t expected_created;
  char expected_file_id[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char observed_file_id[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  const char *expected_path;
  if (!record->process_creation_filetime_100ns) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "generation_unavailable");
    snprintf(result->message, sizeof(result->message), "%s", "process FILETIME generation is required");
    return;
  }
  expected_created = record->process_creation_filetime_100ns;
  expected_path = record->image_path_canonical;
  if (!expected_path[0] ||
      !record_file_identity(record, expected_file_id, sizeof(expected_file_id))) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "identity_unavailable");
    snprintf(result->message, sizeof(result->message), "%s", "canonical image path and file identity are required");
    return;
  }
  if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
    result->error_code = (uint32_t)GetLastError();
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "generation_unavailable");
    snprintf(result->message, sizeof(result->message), "GetProcessTimes failed: %lu",
             (unsigned long)result->error_code);
    return;
  }
  live_created.LowPart = created.dwLowDateTime;
  live_created.HighPart = created.dwHighDateTime;
  if (live_created.QuadPart != expected_created) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "stale_pid_generation");
    snprintf(result->message, sizeof(result->message), "%s", "PID creation generation changed before enforcement");
    return;
  }

  char live_path[EDR_BR_STR_LONG];
  EdrWindowsUtf8PathCompareResult path_compare;
  live_path[0] = '\0';
  if (!edr_windows_process_image_path_utf8(process, live_path, sizeof(live_path))) {
    result->error_code = (uint32_t)GetLastError();
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "identity_unavailable");
    snprintf(result->message, sizeof(result->message), "%s", "live canonical image query failed");
    return;
  }
  path_compare = edr_windows_utf8_path_compare_ci(live_path, expected_path);
  if (path_compare == EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "identity_unavailable");
    snprintf(result->message, sizeof(result->message), "%s",
             "canonical image path is invalid UTF-8");
    return;
  }
  if (path_compare == EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR) {
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "identity_unavailable");
    snprintf(result->message, sizeof(result->message), "%s",
             "canonical image path comparison failed");
    return;
  }
  if (path_compare != EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH ||
      !live_file_identity(live_path, observed_file_id, sizeof(observed_file_id)) ||
      strcmp(observed_file_id, expected_file_id) != 0) {
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
  DWORD wait = WaitForSingleObject(process, 1500u);
  if (wait != WAIT_OBJECT_0) {
    result->error_code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : (uint32_t)GetLastError();
    CloseHandle(process);
    snprintf(result->action, sizeof(result->action), "%s", "terminate_unconfirmed");
    snprintf(result->message, sizeof(result->message), "%s", "process exit was not confirmed");
    return;
  }
  CloseHandle(process);
  result->succeeded = 1;
  snprintf(result->message, sizeof(result->message), "%s", "process terminated");
#else
  (void)record;
  snprintf(result->action, sizeof(result->action), "%s", "unsupported_platform");
  snprintf(result->message, sizeof(result->message), "%s", "blocking is not implemented on this platform");
#endif
}

void edr_policy_enforce_alert(const EdrBehaviorRecord *record,
                              const char *triggered_tactics,
                              const char *rule_id,
                              EdrPolicyEnforcementResult *result) {
  edr_policy_enforcement_plan(record, triggered_tactics, rule_id, result);
  edr_policy_enforcement_execute(record, result);
}
