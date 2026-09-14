#include "edr/windows_file_identity.h"
#include "edr/behavior_record.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define UTF8_USER "\xE7\x94\xA8\xE6\x88\xB7"

static void wide_to_utf8(const wchar_t *wide, char *utf8, size_t utf8_cap) {
  int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                  NULL, 0, NULL, NULL);
  assert(bytes > 0);
  assert((size_t)bytes <= utf8_cap);
  assert(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, utf8,
                             bytes, NULL, NULL) == bytes);
}

static void test_ordinal_compare_preserves_windows_namespace(void) {
  const char unc_a[] = "\\\\?\\UNC\\Server\\Share\\" UTF8_USER "\\Agent.EXE";
  const char unc_b[] = "\\\\?\\unc\\server\\share\\" UTF8_USER "\\agent.exe";
  const char device_a[] = "\\\\Device\\HarddiskVolume3\\" UTF8_USER "\\Agent.EXE";
  const char device_b[] = "\\\\device\\harddiskvolume3\\" UTF8_USER "\\agent.exe";
  const char ordinary[] = "\\\\Server\\Share\\" UTF8_USER "\\agent.exe";
  const char decomposed[] = "C:\\cases\\e" "\xCC\x81" ".exe";
  const char composed[] = "C:\\cases\\" "\xC3\xA9" ".exe";

  assert(edr_windows_utf8_path_compare_ci(unc_a, unc_b) ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH);
  assert(edr_windows_utf8_path_compare_ci(device_a, device_b) ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH);
  /* Namespace prefixes are not parsed or stripped. */
  assert(edr_windows_utf8_path_compare_ci(unc_a, ordinary) ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_MISMATCH);
  /* NTFS identity is not Unicode-normalization equivalence. */
  assert(edr_windows_utf8_path_compare_ci(decomposed, composed) ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_MISMATCH);
}

static void test_invalid_utf8_is_not_a_path(void) {
  const char invalid[] = "C:\\bad\\" "\xC3\x28" ".exe";
  char identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char reason[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  char expected[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  uint64_t write_time = 0u;
  void *owner = (void *)1;

  assert(edr_windows_utf8_path_compare_ci(invalid, "C:\\bad\\x.exe") ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_INVALID_UTF8);
  assert(!edr_windows_file_identity_open_readonly_diagnostic(
      invalid, &owner, identity, sizeof(identity), &write_time, reason,
      sizeof(reason)));
  assert(snprintf(expected, sizeof(expected),
                  "file_identity_path_encoding_failed_win32_%lu",
                  (unsigned long)ERROR_NO_UNICODE_TRANSLATION) > 0);
  assert(strcmp(reason, expected) == 0);
  assert(owner == NULL);
  assert(identity[0] == '\0');
  assert(write_time == 0u);
}

static void test_file_info_failure_retains_win32_error(void) {
  char identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char reason[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  char expected[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  uint64_t write_time = 0u;

  assert(!edr_windows_file_identity_from_handle_diagnostic(
      (void *)(uintptr_t)0x1234u, identity, sizeof(identity), &write_time,
      reason, sizeof(reason)));
  assert(snprintf(expected, sizeof(expected),
                  "file_identity_file_id_info_failed_win32_%lu",
                  (unsigned long)ERROR_INVALID_HANDLE) > 0);
  assert(strcmp(reason, expected) == 0);
  assert(identity[0] == '\0');
  assert(write_time == 0u);
}

static void test_chinese_directory_file_identity_and_process_query(void) {
  wchar_t temp[MAX_PATH];
  wchar_t root[MAX_PATH];
  wchar_t directory[MAX_PATH];
  wchar_t file_path[MAX_PATH];
  const wchar_t child[] = L"\\\x7528\x6237\x5b89\x88c5";
  const wchar_t leaf[] = L"\\agent.exe";
  char path_utf8[EDR_BR_STR_LONG];
  char self_utf8[EDR_BR_STR_LONG];
  char identity[EDR_WINDOWS_FILE_IDENTITY_V1_CAP];
  char reason[EDR_WINDOWS_FILE_IDENTITY_REASON_CAP];
  uint64_t write_time = 0u;
  HANDLE file;
  void *owner = NULL;
  DWORD temp_len;

  temp_len = GetTempPathW((DWORD)(sizeof(temp) / sizeof(temp[0])), temp);
  assert(temp_len > 0u && temp_len < sizeof(temp) / sizeof(temp[0]));
  assert(GetTempFileNameW(temp, L"edu", 0u, root) != 0u);
  assert(DeleteFileW(root));
  assert(CreateDirectoryW(root, NULL));
  assert(wcslen(root) + wcslen(child) + wcslen(leaf) + 1u <
         sizeof(file_path) / sizeof(file_path[0]));
  wcscpy(directory, root);
  wcscat(directory, child);
  assert(CreateDirectoryW(directory, NULL));
  wcscpy(file_path, directory);
  wcscat(file_path, leaf);
  file = CreateFileW(file_path, GENERIC_WRITE, 0u, NULL, CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  assert(file != INVALID_HANDLE_VALUE);
  assert(CloseHandle(file));

  wide_to_utf8(file_path, path_utf8, sizeof(path_utf8));
  assert(edr_windows_file_identity_open_readonly_diagnostic(
      path_utf8, &owner, identity, sizeof(identity), &write_time, reason,
      sizeof(reason)));
  assert(reason[0] == '\0');
  assert(edr_windows_file_identity_valid(identity));
  assert(write_time != 0u);
  assert(CloseHandle((HANDLE)owner));

  assert(edr_windows_process_image_path_utf8(GetCurrentProcess(), self_utf8,
                                             sizeof(self_utf8)));
  assert(edr_windows_utf8_path_compare_ci(self_utf8, self_utf8) ==
         EDR_WINDOWS_UTF8_PATH_COMPARE_MATCH);

  assert(DeleteFileW(file_path));
  assert(RemoveDirectoryW(directory));
  assert(RemoveDirectoryW(root));
}

int main(void) {
  test_ordinal_compare_preserves_windows_namespace();
  test_invalid_utf8_is_not_a_path();
  test_file_info_failure_retains_win32_error();
  test_chinese_directory_file_identity_and_process_query();
  puts("windows Unicode path native contract: ok");
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
