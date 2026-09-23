#ifndef EDR_PROCESS_GENERATION_H
#define EDR_PROCESS_GENERATION_H

#include <stddef.h>
#include <stdint.h>

/*
 * A live process generation is trusted only when it came from the documented
 * ProcessTelemetryIdInformation contract.  Callers must still compare its
 * CreateTime with GetProcessTimes and its image/file identity before using it
 * for a token query or enforcement.
 */
typedef struct {
  uint32_t pid;
  uint64_t process_start_key;
  uint64_t creation_filetime_100ns;
} EdrLiveProcessGeneration;

/* File events have no process-start delivery skew allowance. A replacement
 * PID created after the event cannot own it. Reject invalid/overflowing time. */
static inline int edr_process_generation_contains_event(uint64_t creation_filetime,
                                                         uint64_t event_unix_ns) {
  const uint64_t epoch = 116444736000000000ULL;
  if (!event_unix_ns || creation_filetime <= epoch ||
      creation_filetime - epoch > UINT64_MAX / 100u) return 0;
  return event_unix_ns >= (creation_filetime - epoch) * 100u;
}

/* `native_process_handle` is a Windows HANDLE on Windows and intentionally
 * opaque elsewhere.  The implementation runtime-links NtQueryInformationProcess
 * because Microsoft documents no import library for it. */
int edr_process_generation_query_live(void *native_process_handle,
                                      EdrLiveProcessGeneration *out,
                                      char *reason, size_t reason_cap);

/* Validate the currently-open handle against the ETW ProcessStartKey. */
int edr_process_generation_validate_live(void *native_process_handle,
                                         uint32_t expected_pid,
                                         uint64_t expected_process_start_key,
                                         uint64_t *out_creation_filetime_100ns,
                                         char *reason, size_t reason_cap);

/* Read the command line from the already-open process object.  Callers that
 * use this as detection evidence must validate the generation on this same
 * handle before accepting the returned text. */
int edr_process_command_line_query_live(void *native_process_handle,
                                        char *out, size_t out_cap,
                                        char *reason, size_t reason_cap);

/* Windows UNICODE_STRING has at most 32767 UTF-16 code units; UTF-8
 * needs at most three bytes per unit plus NUL. This is a fact bound, not a
 * hot-record or model-input budget. Caller frees the exact-sized result. */
#define EDR_PROCESS_COMMAND_FACT_CAP (32767u * 3u + 1u)
char *edr_process_command_line_query_alloc(void *native_process_handle,
                                          char *reason, size_t reason_cap);

/* Bind termination to the observed creation FILETIME and confirm exit using
 * the same OS process handle. No PID-only fallback is permitted. */
int edr_process_terminate_checked(uint32_t pid, uint64_t expected_creation_filetime,
                                  uint32_t timeout_ms, char *reason, size_t reason_cap);

#endif
