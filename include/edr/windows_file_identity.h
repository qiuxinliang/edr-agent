#ifndef EDR_WINDOWS_FILE_IDENTITY_H
#define EDR_WINDOWS_FILE_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/*
 * The Windows file identity carried across a P0 boundary is deliberately
 * lossless: volume serial plus the complete FILE_ID_128.  It is not the old
 * XOR diagnostic value, which could alias two different files.
 */
#define EDR_WINDOWS_FILE_IDENTITY_V1_PREFIX "win-fileid-v1:"
#define EDR_WINDOWS_FILE_IDENTITY_V1_CAP 64u
#define EDR_WINDOWS_FILE_IDENTITY_REASON_CAP 64u

/* Strict Windows pathname comparison has three meaningful outcomes.  Paths
 * arriving from ETW and rule/evidence records are UTF-8; an invalid byte
 * sequence must not quietly become an ACP path or a false match. */
typedef enum EdrWindowsUtf8PathCompareResult {
  EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR = -2,
  EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8 = -1,
  EDR_WINDOWS_UTF8_PATH_COMPARE_MISMATCH = 0,
  EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH = 1
} EdrWindowsUtf8PathCompareResult;

int edr_windows_file_identity_valid(const char *identity);

/* Both values must describe the same immutable capture. This shared lexical
 * boundary is used before publishing a hash/signature and by tests that
 * exercise adversarial pathname snapshots without a Windows kernel. */
int edr_windows_file_identity_snapshot_matches(const char *expected_identity,
                                               uint64_t expected_write_time_100ns,
                                               const char *observed_identity,
                                               uint64_t observed_write_time_100ns);

/* Convert both UTF-8 paths strictly to UTF-16 and use Windows' ordinal,
 * case-insensitive comparison.  This intentionally preserves UTF-16 code
 * units and namespace syntax (including \\?\\, UNC, and \\Device); it does not
 * normalize or reinterpret either pathname. */
EdrWindowsUtf8PathCompareResult edr_windows_utf8_path_compare_ci(
    const char *left_utf8, const char *right_utf8);

/* Query a process image through the Unicode Windows API and return strict
 * UTF-8.  `native_process_handle` is opaque on non-Windows builds. */
int edr_windows_process_image_path_utf8(void *native_process_handle,
                                        char *path_utf8, size_t path_utf8_cap);

/* Capture the authoritative identity and last-write FILETIME from an already
 * opened Windows file HANDLE. `native_file_handle` is opaque on non-Windows
 * builds. */
int edr_windows_file_identity_from_handle(void *native_file_handle,
                                          char *identity, size_t identity_cap,
                                          uint64_t *write_time_100ns);

/* Compatibility-preserving diagnostic variant. On failure, `failure_reason`
 * identifies the exact boundary and includes the Win32 error code when a
 * Windows API supplied one. On success it is empty. */
int edr_windows_file_identity_from_handle_diagnostic(
    void *native_file_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap);

/* Open one read-only, no-write/no-delete-share handle. On success the caller
 * exclusively owns `*out_handle` and must close it on every terminal path. */
int edr_windows_file_identity_open_readonly(const char *path, void **out_handle,
                                            char *identity, size_t identity_cap,
                                            uint64_t *write_time_100ns);

/* Diagnostic variant of the same fail-closed open. It uses identical access,
 * share, and reparse-point semantics; only failure reporting differs. */
int edr_windows_file_identity_open_readonly_diagnostic(
    const char *path, void **out_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap);

/* Snapshot a pathname for a revalidation only; this helper closes its own
 * temporary handle before it returns. */
int edr_windows_file_identity_from_path(const char *path, char *identity,
                                        size_t identity_cap,
                                        uint64_t *write_time_100ns);

#ifdef EDR_WINDOWS_FILE_IDENTITY_TESTING
/* Test-only seam for the same fail-closed branch used when an opened path is
 * a reparse point.  This keeps denial coverage deterministic without asking
 * native CI to have symlink-creation privileges. */
void edr_windows_file_identity_test_force_reparse_denied(int enabled);
#endif

#endif
