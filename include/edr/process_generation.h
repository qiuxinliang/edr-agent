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

#endif
