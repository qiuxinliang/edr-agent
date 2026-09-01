#include "edr/process_generation.h"

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
typedef LONG (WINAPI *EdrNtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

int edr_process_generation_query_live(void *native_process_handle,
                                      EdrLiveProcessGeneration *out,
                                      char *reason, size_t reason_cap) {
  EdrProcessTelemetryIdInformation info;
  EdrProcessTelemetryIdInformation *reply = &info;
  EdrNtQueryInformationProcessFn query;
  HMODULE ntdll;
  ULONG returned = 0u;
  ULONG capacity = (ULONG)sizeof(info);
  LONG status;
  if (out) memset(out, 0, sizeof(*out));
  if (!native_process_handle || !out) {
    set_reason(reason, reason_cap, "invalid_process_handle");
    return 0;
  }
  ntdll = GetModuleHandleA("ntdll.dll");
  query = ntdll ? (EdrNtQueryInformationProcessFn)(void *)GetProcAddress(
      ntdll, "NtQueryInformationProcess") : NULL;
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

#endif
