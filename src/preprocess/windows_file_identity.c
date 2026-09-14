#include "edr/windows_file_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_lower_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

int edr_windows_file_identity_valid(const char *identity) {
  static const char prefix[] = EDR_WINDOWS_FILE_IDENTITY_V1_PREFIX;
  const size_t prefix_len = sizeof(prefix) - 1u;
  size_t i;
  if (!identity || strlen(identity) != prefix_len + 16u + 1u + 32u ||
      strncmp(identity, prefix, prefix_len) != 0 || identity[prefix_len + 16u] != ':') {
    return 0;
  }
  for (i = prefix_len; i < prefix_len + 16u; ++i) {
    if (!is_lower_hex(identity[i])) return 0;
  }
  for (i = prefix_len + 17u; i < prefix_len + 17u + 32u; ++i) {
    if (!is_lower_hex(identity[i])) return 0;
  }
  return 1;
}

int edr_windows_file_identity_snapshot_matches(const char *expected_identity,
                                               uint64_t expected_write_time_100ns,
                                               const char *observed_identity,
                                               uint64_t observed_write_time_100ns) {
  return expected_write_time_100ns == observed_write_time_100ns &&
         edr_windows_file_identity_valid(expected_identity) &&
         edr_windows_file_identity_valid(observed_identity) &&
         strcmp(expected_identity, observed_identity) == 0;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static wchar_t *utf8_to_wide_strict(const char *utf8) {
  int wide_chars;
  wchar_t *wide;
  if (!utf8 || !utf8[0]) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
  }
  wide_chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
  if (wide_chars <= 0) {
    /* Preserve ERROR_NO_UNICODE_TRANSLATION for invalid UTF-8. */
    return NULL;
  }
  if ((size_t)wide_chars > ((size_t)-1) / sizeof(*wide)) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }
  wide = (wchar_t *)malloc((size_t)wide_chars * sizeof(*wide));
  if (!wide) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, wide, wide_chars) !=
      wide_chars) {
    DWORD error = GetLastError();
    free(wide);
    SetLastError(error);
    return NULL;
  }
  return wide;
}

EdrWindowsUtf8PathCompareResult edr_windows_utf8_path_compare_ci(
    const char *left_utf8, const char *right_utf8) {
  wchar_t *left = utf8_to_wide_strict(left_utf8);
  wchar_t *right;
  int comparison;
  if (!left) {
    return GetLastError() == ERROR_NO_UNICODE_TRANSLATION
               ? EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8
               : EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR;
  }
  right = utf8_to_wide_strict(right_utf8);
  if (!right) {
    EdrWindowsUtf8PathCompareResult result =
        GetLastError() == ERROR_NO_UNICODE_TRANSLATION
            ? EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8
            : EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR;
    free(left);
    return result;
  }
  /* Do not call a path canonicalizer or Unicode normalizer here.  Windows
   * process/image identity is an ordinal UTF-16 path comparison; rewriting
   * a namespace prefix or combining sequence could alias distinct objects. */
  comparison = CompareStringOrdinal(left, -1, right, -1, TRUE);
  free(right);
  free(left);
  if (comparison == CSTR_EQUAL) return EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH;
  if (comparison == CSTR_LESS_THAN || comparison == CSTR_GREATER_THAN) {
    return EDR_WINDOWS_UTF8_PATH_COMPARE_MISMATCH;
  }
  return EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR;
}

int edr_windows_process_image_path_utf8(void *native_process_handle,
                                        char *path_utf8, size_t path_utf8_cap) {
  HANDLE process = (HANDLE)native_process_handle;
  DWORD wide_cap = 512u;
  if (path_utf8 && path_utf8_cap > 0u) path_utf8[0] = '\0';
  if (!process || process == INVALID_HANDLE_VALUE || !path_utf8 || path_utf8_cap == 0u) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  }
  while (wide_cap <= 32768u) {
    wchar_t *wide = (wchar_t *)calloc((size_t)wide_cap, sizeof(*wide));
    DWORD copied = wide_cap;
    int utf8_bytes;
    if (!wide) {
      SetLastError(ERROR_NOT_ENOUGH_MEMORY);
      return 0;
    }
    if (QueryFullProcessImageNameW(process, 0u, wide, &copied)) {
      if (copied >= wide_cap) {
        free(wide);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
      }
      utf8_bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)copied,
                                       NULL, 0, NULL, NULL);
      if (utf8_bytes <= 0) {
        free(wide);
        return 0;
      }
      if ((size_t)utf8_bytes + 1u > path_utf8_cap) {
        free(wide);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
      }
      if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)copied,
                              path_utf8, utf8_bytes, NULL, NULL) != utf8_bytes) {
        free(wide);
        path_utf8[0] = '\0';
        return 0;
      }
      path_utf8[utf8_bytes] = '\0';
      free(wide);
      return 1;
    }
    {
      DWORD error = GetLastError();
      free(wide);
      if (error != ERROR_INSUFFICIENT_BUFFER || wide_cap == 32768u) {
        return 0;
      }
    }
    wide_cap *= 2u;
  }
  SetLastError(ERROR_INSUFFICIENT_BUFFER);
  return 0;
}

#ifdef EDR_WINDOWS_FILE_IDENTITY_TESTING
static int s_test_force_reparse_denied;

void edr_windows_file_identity_test_force_reparse_denied(int enabled) {
  s_test_force_reparse_denied = enabled ? 1 : 0;
}
#endif

/* FILE_ID_INFO is not present in every SDK we support. The documented
 * FileIdInfo payload layout is stable, so keep a local payload definition and
 * use the documented enum value without relying on a newer header typedef. */
typedef struct EdrWindowsFileIdInfo {
  ULONGLONG volume_serial_number;
  BYTE file_id[16];
} EdrWindowsFileIdInfo;

#define EDR_FILE_INFO_BY_HANDLE_CLASS_FILE_ID 18

static void file_identity_reason_clear(char *reason, size_t reason_cap) {
  if (reason && reason_cap > 0u) reason[0] = '\0';
}

static void file_identity_reason_set(char *reason, size_t reason_cap,
                                     const char *stage, DWORD error) {
  if (!reason || reason_cap == 0u) return;
  if (error != ERROR_SUCCESS) {
    (void)snprintf(reason, reason_cap, "file_identity_%s_win32_%lu", stage,
                   (unsigned long)error);
  } else {
    (void)snprintf(reason, reason_cap, "file_identity_%s", stage);
  }
}

int edr_windows_file_identity_from_handle_diagnostic(
    void *native_file_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap) {
  static const char hex[] = "0123456789abcdef";
  HANDLE file = (HANDLE)native_file_handle;
  EdrWindowsFileIdInfo file_id;
  BY_HANDLE_FILE_INFORMATION basic;
  size_t prefix_len;
  size_t used;
  ULARGE_INTEGER write_time;
  file_identity_reason_clear(failure_reason, failure_reason_cap);
  if (identity && identity_cap > 0u) identity[0] = '\0';
  if (write_time_100ns) *write_time_100ns = 0u;
  if (!file || file == INVALID_HANDLE_VALUE || !identity ||
      identity_cap < EDR_WINDOWS_FILE_IDENTITY_V1_CAP || !write_time_100ns) {
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "invalid_argument", ERROR_INVALID_PARAMETER);
    return 0;
  }
  memset(&file_id, 0, sizeof(file_id));
  memset(&basic, 0, sizeof(basic));
  if (!GetFileInformationByHandleEx(
          file, (FILE_INFO_BY_HANDLE_CLASS)EDR_FILE_INFO_BY_HANDLE_CLASS_FILE_ID,
          &file_id, (DWORD)sizeof(file_id))) {
    DWORD error = GetLastError();
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "file_id_info_failed", error);
    return 0;
  }
  if (!GetFileInformationByHandle(file, &basic)) {
    DWORD error = GetLastError();
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "basic_info_failed", error);
    return 0;
  }
  if ((basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u) {
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "directory_denied", ERROR_SUCCESS);
    return 0;
  }
  if ((basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u) {
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "reparse_denied", ERROR_SUCCESS);
    return 0;
  }
  prefix_len = strlen(EDR_WINDOWS_FILE_IDENTITY_V1_PREFIX);
  memcpy(identity, EDR_WINDOWS_FILE_IDENTITY_V1_PREFIX, prefix_len);
  used = prefix_len;
  for (int shift = 60; shift >= 0; shift -= 4) {
    identity[used++] = hex[(file_id.volume_serial_number >> shift) & 0x0fu];
  }
  identity[used++] = ':';
  for (size_t i = 0u; i < sizeof(file_id.file_id); ++i) {
    identity[used++] = hex[file_id.file_id[i] >> 4u];
    identity[used++] = hex[file_id.file_id[i] & 0x0fu];
  }
  identity[used] = '\0';
  write_time.LowPart = basic.ftLastWriteTime.dwLowDateTime;
  write_time.HighPart = basic.ftLastWriteTime.dwHighDateTime;
  *write_time_100ns = write_time.QuadPart;
  if (!edr_windows_file_identity_valid(identity)) {
    identity[0] = '\0';
    *write_time_100ns = 0u;
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "format_invalid", ERROR_SUCCESS);
    return 0;
  }
  return 1;
}

int edr_windows_file_identity_from_handle(void *native_file_handle,
                                          char *identity, size_t identity_cap,
                                          uint64_t *write_time_100ns) {
  return edr_windows_file_identity_from_handle_diagnostic(
      native_file_handle, identity, identity_cap, write_time_100ns, NULL, 0u);
}

int edr_windows_file_identity_open_readonly_diagnostic(
    const char *path, void **out_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap) {
  HANDLE file;
  wchar_t *wide_path;
  file_identity_reason_clear(failure_reason, failure_reason_cap);
  if (out_handle) *out_handle = NULL;
  if (identity && identity_cap > 0u) identity[0] = '\0';
  if (write_time_100ns) *write_time_100ns = 0u;
  if (!path || !path[0] || !out_handle || !identity ||
      identity_cap < EDR_WINDOWS_FILE_IDENTITY_V1_CAP || !write_time_100ns) {
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "invalid_argument", ERROR_INVALID_PARAMETER);
    return 0;
  }
  wide_path = utf8_to_wide_strict(path);
  if (!wide_path) {
    DWORD error = GetLastError();
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "path_encoding_failed", error);
    return 0;
  }
  /* The held file cannot coexist with a writer or deleter. Opening the
   * reparse point itself and rejecting it prevents an indirection from
   * swapping the pathname's object between the capture and WVT checks. */
  file = CreateFileW(wide_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                         FILE_FLAG_OPEN_REPARSE_POINT,
                     NULL);
  if (file == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    free(wide_path);
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "open_failed", error);
    return 0;
  }
  free(wide_path);
#ifdef EDR_WINDOWS_FILE_IDENTITY_TESTING
  /* Exercise the exact deny path deterministically.  Native reparse-point
   * construction is privilege-dependent, while production always relies on
   * FILE_FLAG_OPEN_REPARSE_POINT plus the attribute check below. */
  if (s_test_force_reparse_denied) {
    file_identity_reason_set(failure_reason, failure_reason_cap,
                             "reparse_denied", ERROR_SUCCESS);
    CloseHandle(file);
    return 0;
  }
#endif
  if (!edr_windows_file_identity_from_handle_diagnostic(
          file, identity, identity_cap, write_time_100ns, failure_reason,
          failure_reason_cap)) {
    CloseHandle(file);
    return 0;
  }
  *out_handle = (void *)file;
  return 1;
}

int edr_windows_file_identity_open_readonly(const char *path, void **out_handle,
                                            char *identity, size_t identity_cap,
                                            uint64_t *write_time_100ns) {
  return edr_windows_file_identity_open_readonly_diagnostic(
      path, out_handle, identity, identity_cap, write_time_100ns, NULL, 0u);
}

int edr_windows_file_identity_from_path(const char *path, char *identity,
                                        size_t identity_cap,
                                        uint64_t *write_time_100ns) {
  void *owned_handle = NULL;
  if (!edr_windows_file_identity_open_readonly(path, &owned_handle, identity,
                                               identity_cap, write_time_100ns)) {
    return 0;
  }
  CloseHandle((HANDLE)owned_handle);
  return 1;
}

#else

EdrWindowsUtf8PathCompareResult edr_windows_utf8_path_compare_ci(
    const char *left_utf8, const char *right_utf8) {
  (void)left_utf8;
  (void)right_utf8;
  return EDR_WINDOWS_UTF8_PATH_COMPARE_ERROR;
}

int edr_windows_process_image_path_utf8(void *native_process_handle,
                                        char *path_utf8, size_t path_utf8_cap) {
  (void)native_process_handle;
  if (path_utf8 && path_utf8_cap > 0u) path_utf8[0] = '\0';
  return 0;
}

int edr_windows_file_identity_from_handle(void *native_file_handle,
                                          char *identity, size_t identity_cap,
                                          uint64_t *write_time_100ns) {
  (void)native_file_handle;
  if (identity && identity_cap > 0u) identity[0] = '\0';
  if (write_time_100ns) *write_time_100ns = 0u;
  return 0;
}

int edr_windows_file_identity_from_handle_diagnostic(
    void *native_file_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap) {
  if (failure_reason && failure_reason_cap > 0u) {
    snprintf(failure_reason, failure_reason_cap, "%s",
             "file_identity_windows_only");
  }
  return edr_windows_file_identity_from_handle(
      native_file_handle, identity, identity_cap, write_time_100ns);
}

int edr_windows_file_identity_open_readonly(const char *path, void **out_handle,
                                            char *identity, size_t identity_cap,
                                            uint64_t *write_time_100ns) {
  (void)path;
  if (out_handle) *out_handle = NULL;
  if (identity && identity_cap > 0u) identity[0] = '\0';
  if (write_time_100ns) *write_time_100ns = 0u;
  return 0;
}

int edr_windows_file_identity_open_readonly_diagnostic(
    const char *path, void **out_handle, char *identity, size_t identity_cap,
    uint64_t *write_time_100ns, char *failure_reason,
    size_t failure_reason_cap) {
  if (failure_reason && failure_reason_cap > 0u) {
    snprintf(failure_reason, failure_reason_cap, "%s",
             "file_identity_windows_only");
  }
  return edr_windows_file_identity_open_readonly(
      path, out_handle, identity, identity_cap, write_time_100ns);
}

int edr_windows_file_identity_from_path(const char *path, char *identity,
                                        size_t identity_cap,
                                        uint64_t *write_time_100ns) {
  (void)path;
  if (identity && identity_cap > 0u) identity[0] = '\0';
  if (write_time_100ns) *write_time_100ns = 0u;
  return 0;
}

#endif
