#include "edr/process_generation.h"

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_reason(char *reason, size_t cap, const char *value) {
  if (!reason || cap == 0u) return;
  snprintf(reason, cap, "%s", value ? value : "unknown");
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* Microsoft documents this exact structure, but it intentionally has no SDK
 * header.  Keep the documented type local and runtime-link the native query.
 * See PROCESS_TELEMETRY_ID_INFORMATION_TYPE and NtQueryInformationProcess. */
typedef struct {
  ULONG HeaderSize;
  ULONG ProcessId;
  ULONGLONG ProcessStartKey;
  ULONGLONG CreateTime;
  ULONGLONG CreateInterruptTime;
  ULONGLONG CreateUnbiasedInterruptTime;
  ULONGLONG ProcessSequenceNumber;
  ULONGLONG SessionCreateTime;
  ULONG SessionId;
  ULONG BootId;
  ULONG ImageChecksum;
  ULONG ImageTimeDateStamp;
  ULONG UserSidOffset;
  ULONG ImagePathOffset;
  ULONG PackageNameOffset;
  ULONG RelativeAppNameOffset;
  ULONG CommandLineOffset;
} EdrProcessTelemetryIdInformation;

/* Documented PROCESSINFOCLASS value: ProcessTelemetryIdInformation. */
#define EDR_PROCESS_INFO_CLASS_TELEMETRY_ID 64u
#define EDR_PROCESS_INFO_CLASS_COMMAND_LINE 60u
typedef LONG (WINAPI *EdrNtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} EdrUnicodeString;

static EdrNtQueryInformationProcessFn resolve_native_query(void) {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  return ntdll ? (EdrNtQueryInformationProcessFn)(void *)GetProcAddress(
                     ntdll, "NtQueryInformationProcess")
               : NULL;
}

int edr_process_terminate_checked(uint32_t pid, uint64_t expected_creation_filetime,
                                  uint32_t timeout_ms, char *reason, size_t reason_cap) {
  if (pid <= 4u || pid == GetCurrentProcessId() || !expected_creation_filetime ||
      timeout_ms == 0u || timeout_ms > 5000u) {
    set_reason(reason, reason_cap, "invalid_or_self_process_target");
    return 0;
  }
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                                FALSE, (DWORD)pid);
  if (!process) {
    DWORD error = GetLastError();
    set_reason(reason, reason_cap, error == ERROR_INVALID_PARAMETER ? "process_already_gone" : "process_open_failed");
    return error == ERROR_INVALID_PARAMETER;
  }
  FILETIME created, exited, kernel, user;
  int ok = 0;
  BOOL critical = FALSE;
  typedef BOOL (WINAPI *IsCriticalFn)(HANDLE, PBOOL);
  HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
  IsCriticalFn is_critical = kernel32 ? (IsCriticalFn)(void *)GetProcAddress(kernel32, "IsProcessCritical") : NULL;
  if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
    set_reason(reason, reason_cap, "process_identity_query_failed");
  } else if ((((uint64_t)created.dwHighDateTime << 32u) | created.dwLowDateTime) != expected_creation_filetime) {
    set_reason(reason, reason_cap, "process_generation_mismatch");
  } else if (WaitForSingleObject(process, 0u) == WAIT_OBJECT_0) {
    set_reason(reason, reason_cap, "process_already_gone");
    ok = 1;
  } else if (!is_critical || !is_critical(process, &critical)) {
    set_reason(reason, reason_cap, "process_protection_query_failed");
  } else if (critical) {
    set_reason(reason, reason_cap, "protected_process_target");
  } else if (!TerminateProcess(process, 1u)) {
    set_reason(reason, reason_cap, "process_terminate_failed");
  } else {
    DWORD waited = WaitForSingleObject(process, timeout_ms);
    ok = waited == WAIT_OBJECT_0;
    set_reason(reason, reason_cap, ok ? "process_exit_verified" :
               waited == WAIT_TIMEOUT ? "process_exit_timeout" : "process_exit_wait_failed");
  }
  CloseHandle(process);
  return ok;
}

int edr_process_generation_query_live(void *native_process_handle,
                                      EdrLiveProcessGeneration *out,
                                      char *reason, size_t reason_cap) {
  EdrProcessTelemetryIdInformation info;
  EdrProcessTelemetryIdInformation *reply = &info;
  EdrNtQueryInformationProcessFn query;
  ULONG returned = 0u;
  ULONG capacity = (ULONG)sizeof(info);
  LONG status;
  if (out) memset(out, 0, sizeof(*out));
  if (!native_process_handle || !out) {
    set_reason(reason, reason_cap, "invalid_process_handle");
    return 0;
  }
  query = resolve_native_query();
  if (!query) {
    set_reason(reason, reason_cap, "telemetry_id_api_unavailable");
    return 0;
  }
  memset(&info, 0, sizeof(info));
  /* HeaderSize bounds the fixed structure portion we require. */
  info.HeaderSize = (ULONG)sizeof(info);
  status = query((HANDLE)native_process_handle, EDR_PROCESS_INFO_CLASS_TELEMETRY_ID,
                 &info, capacity, &returned);
  /* The documented response includes optional variable-length strings after
   * the fixed header.  Do not assume sizeof(fixed-header) is always enough:
   * retry once with the API-reported bounded size rather than treating a
   * valid process instance as a false generation mismatch. */
  if (status < 0 && returned > capacity && returned <= 65536u) {
    reply = (EdrProcessTelemetryIdInformation *)calloc(1u, returned);
    if (!reply) {
      set_reason(reason, reason_cap, "telemetry_id_buffer_unavailable");
      return 0;
    }
    capacity = returned;
    reply->HeaderSize = (ULONG)sizeof(*reply);
    returned = 0u;
    status = query((HANDLE)native_process_handle, EDR_PROCESS_INFO_CLASS_TELEMETRY_ID,
                   reply, capacity, &returned);
  }
  if (status < 0) {
    if (reply != &info) free(reply);
    set_reason(reason, reason_cap, "telemetry_id_query_unsupported");
    return 0;
  }
  if (capacity < offsetof(EdrProcessTelemetryIdInformation, CreateTime) +
                     sizeof(reply->CreateTime) ||
      reply->HeaderSize < offsetof(EdrProcessTelemetryIdInformation, CreateTime) +
                          sizeof(reply->CreateTime) ||
      reply->ProcessId == 0u || reply->ProcessStartKey == 0u || reply->CreateTime == 0u) {
    if (reply != &info) free(reply);
    set_reason(reason, reason_cap, "telemetry_id_incomplete");
    return 0;
  }
  out->pid = (uint32_t)reply->ProcessId;
  out->process_start_key = (uint64_t)reply->ProcessStartKey;
  out->creation_filetime_100ns = (uint64_t)reply->CreateTime;
  if (reply != &info) free(reply);
  set_reason(reason, reason_cap, "ok");
  return 1;
}

static int query_command_line(void *native_process_handle,
                               char *out, size_t out_cap, char **allocated,
                               char *reason, size_t reason_cap) {
  EdrNtQueryInformationProcessFn query;
  EdrUnicodeString *value;
  unsigned char *raw;
  uintptr_t raw_begin;
  uintptr_t raw_end;
  uintptr_t text_begin;
  ULONG needed = 0u;
  ULONG capacity;
  LONG status;
  size_t chars;
  int utf8_needed;
  int written;

  if (out && out_cap > 0u) out[0] = '\0';
  if (!native_process_handle || (!allocated && (!out || out_cap < 2u))) {
    set_reason(reason, reason_cap, "invalid_command_line_output");
    return 0;
  }
  query = resolve_native_query();
  if (!query) {
    set_reason(reason, reason_cap, "command_line_api_unavailable");
    return 0;
  }
  (void)query((HANDLE)native_process_handle, EDR_PROCESS_INFO_CLASS_COMMAND_LINE,
              NULL, 0u, &needed);
  if (needed < (ULONG)sizeof(EdrUnicodeString) || needed > 1024u * 1024u) {
    set_reason(reason, reason_cap, "command_line_size_unavailable");
    return 0;
  }
  capacity = needed;
  raw = (unsigned char *)calloc(1u, (size_t)capacity + sizeof(wchar_t));
  if (!raw) {
    set_reason(reason, reason_cap, "command_line_buffer_unavailable");
    return 0;
  }
  status = query((HANDLE)native_process_handle, EDR_PROCESS_INFO_CLASS_COMMAND_LINE,
                 raw, capacity, &needed);
  if (status < 0) {
    free(raw);
    set_reason(reason, reason_cap, "command_line_query_failed");
    return 0;
  }
  value = (EdrUnicodeString *)raw;
  raw_begin = (uintptr_t)raw;
  raw_end = raw_begin + (uintptr_t)capacity;
  text_begin = (uintptr_t)value->Buffer;
  if (!value->Buffer || value->Length == 0u ||
      (value->Length % sizeof(wchar_t)) != 0u ||
      value->MaximumLength < value->Length || text_begin < raw_begin ||
      text_begin > raw_end || (uintptr_t)value->Length > raw_end - text_begin) {
    free(raw);
    set_reason(reason, reason_cap, "command_line_reply_invalid");
    return 0;
  }
  chars = (size_t)value->Length / sizeof(wchar_t);
  if (chars > (size_t)INT_MAX) {
    free(raw);
    set_reason(reason, reason_cap, "command_line_too_long");
    return 0;
  }
  utf8_needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value->Buffer,
                                    (int)chars, NULL, 0, NULL, NULL);
  if (utf8_needed <= 0 || (size_t)utf8_needed >= EDR_PROCESS_COMMAND_FACT_CAP ||
      (!allocated && (size_t)utf8_needed >= out_cap)) {
    free(raw);
    set_reason(reason, reason_cap,
               utf8_needed > 0 ? "command_line_too_long" : "command_line_encoding_invalid");
    return 0;
  }
  if (allocated) {
    out = (char *)malloc((size_t)utf8_needed + 1u);
    if (!out) {
      free(raw);
      set_reason(reason, reason_cap, "command_line_buffer_unavailable");
      return 0;
    }
  }
  written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value->Buffer,
                                (int)chars, out, utf8_needed, NULL, NULL);
  free(raw);
  if (written != utf8_needed) {
    out[0] = '\0';
    if (allocated) free(out);
    set_reason(reason, reason_cap, "command_line_encoding_failed");
    return 0;
  }
  out[written] = '\0';
  if (allocated) *allocated = out;
  set_reason(reason, reason_cap, "ok");
  return 1;
}

int edr_process_command_line_query_live(void *handle, char *out, size_t cap,
                                        char *reason, size_t reason_cap) {
  return query_command_line(handle, out, cap, NULL, reason, reason_cap);
}

char *edr_process_command_line_query_alloc(void *handle, char *reason, size_t cap) {
  char *result = NULL;
  (void)query_command_line(handle, NULL, 0u, &result, reason, cap);
  return result;
}

int edr_process_generation_validate_live(void *native_process_handle,
                                         uint32_t expected_pid,
                                         uint64_t expected_process_start_key,
                                         uint64_t *out_creation_filetime_100ns,
                                         char *reason, size_t reason_cap) {
  EdrLiveProcessGeneration observed;
  if (out_creation_filetime_100ns) *out_creation_filetime_100ns = 0u;
  if (!expected_pid || !expected_process_start_key ||
      !edr_process_generation_query_live(native_process_handle, &observed, reason, reason_cap)) {
    return 0;
  }
  if (observed.pid != expected_pid) {
    set_reason(reason, reason_cap, "telemetry_pid_mismatch");
    return 0;
  }
  if (observed.process_start_key != expected_process_start_key) {
    set_reason(reason, reason_cap, "process_start_key_mismatch");
    return 0;
  }
  if (out_creation_filetime_100ns) {
    *out_creation_filetime_100ns = observed.creation_filetime_100ns;
  }
  set_reason(reason, reason_cap, "ok");
  return 1;
}

#else

char *edr_process_command_line_query_alloc(void *handle, char *reason, size_t cap) {
  (void)handle;
  set_reason(reason, cap, "unsupported_platform");
  return NULL;
}

int edr_process_terminate_checked(uint32_t pid, uint64_t expected_creation_filetime,
                                  uint32_t timeout_ms, char *reason, size_t reason_cap) {
  (void)pid; (void)expected_creation_filetime; (void)timeout_ms;
  /* No safe process-object binding is implemented by this Windows identity
   * module on other platforms. Never degrade a signed target to PID-only kill. */
  set_reason(reason, reason_cap, "verified_termination_unsupported_platform");
  return 0;
}

int edr_process_generation_query_live(void *native_process_handle,
                                      EdrLiveProcessGeneration *out,
                                      char *reason, size_t reason_cap) {
  (void)native_process_handle;
  if (out) memset(out, 0, sizeof(*out));
  set_reason(reason, reason_cap, "unsupported_platform");
  return 0;
}

int edr_process_generation_validate_live(void *native_process_handle,
                                         uint32_t expected_pid,
                                         uint64_t expected_process_start_key,
                                         uint64_t *out_creation_filetime_100ns,
                                         char *reason, size_t reason_cap) {
  (void)native_process_handle;
  (void)expected_pid;
  (void)expected_process_start_key;
  if (out_creation_filetime_100ns) *out_creation_filetime_100ns = 0u;
  set_reason(reason, reason_cap, "unsupported_platform");
  return 0;
}

int edr_process_command_line_query_live(void *native_process_handle,
                                        char *out, size_t out_cap,
                                        char *reason, size_t reason_cap) {
  (void)native_process_handle;
  if (out && out_cap > 0u) out[0] = '\0';
  set_reason(reason, reason_cap, "unsupported_platform");
  return 0;
}

#endif
