#include "edr/response_utils.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

static int read_dacl(const char *path, char *out, size_t cap) {
  DWORD required = 0;
  GetFileSecurityA(path, DACL_SECURITY_INFORMATION, NULL, 0, &required);
  if (!required || required > 65536u) return -1;
  PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)malloc(required);
  LPSTR text = NULL;
  int ok = sd && GetFileSecurityA(path, DACL_SECURITY_INFORMATION, sd, required, &required) &&
      ConvertSecurityDescriptorToStringSecurityDescriptorA(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, NULL);
  if (ok && strlen(text) < cap) memcpy(out, text, strlen(text) + 1u);
  else ok = 0;
  if (text) LocalFree(text);
  free(sd);
  return ok ? 0 : -1;
}

static int apply_dacl(const char *path, const char *text) {
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  SECURITY_DESCRIPTOR_CONTROL control;
  DWORD revision = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(text, SDDL_REVISION_1, &sd, NULL)) return -1;
  int ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl &&
      GetSecurityDescriptorControl(sd, &control, &revision);
  if (ok) {
    SECURITY_INFORMATION info = DACL_SECURITY_INFORMATION |
        ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    ok = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, info, NULL, NULL, dacl, NULL) == ERROR_SUCCESS;
  }
  LocalFree(sd);
  return ok ? 0 : -1;
}

int response_file_security_snapshot(const char *path, EdrResponseFileSecurity *out) {
  if (!path || !out) return -1;
  memset(out, 0, sizeof(*out));
  DWORD attr = GetFileAttributesA(path);
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return -1;
  HANDLE file = CreateFileA(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) return -1;
  BY_HANDLE_FILE_INFORMATION info;
  int single_file = GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 &&
      !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY));
  CloseHandle(file);
  if (!single_file) return -1;
  out->attributes = attr;
  return read_dacl(path, out->dacl, sizeof(out->dacl));
}

int response_file_security_lock(const char *path, int directory) {
  DWORD attr = GetFileAttributesA(path);
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_REPARSE_POINT) ||
      (!!(attr & FILE_ATTRIBUTE_DIRECTORY) != !!directory)) return -1;
  const char *dacl = directory ? "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)" : "D:P(A;;FA;;;BA)(A;;FA;;;SY)";
  char actual[8192];
  if (apply_dacl(path, dacl) != 0 || read_dacl(path, actual, sizeof(actual)) != 0 || strcmp(actual, dacl) != 0) return -1;
  if (!directory) {
    DWORD wanted = (attr & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if (!SetFileAttributesA(path, wanted) || GetFileAttributesA(path) != wanted) return -1;
  }
  return 0;
}

int response_file_security_restore(const char *path, const EdrResponseFileSecurity *saved) {
  char actual[8192];
  DWORD attr = GetFileAttributesA(path);
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return -1;
  if (!saved || !saved->dacl[0] || apply_dacl(path, saved->dacl) != 0 ||
      !SetFileAttributesA(path, saved->attributes) || GetFileAttributesA(path) != saved->attributes ||
      read_dacl(path, actual, sizeof(actual)) != 0 || strcmp(actual, saved->dacl) != 0) return -1;
  return 0;
}

#else
#include <sys/stat.h>
#include <unistd.h>

int response_file_security_snapshot(const char *path, EdrResponseFileSecurity *out) {
  struct stat st;
  if (!path || !out || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) return -1;
  memset(out, 0, sizeof(*out));
  out->mode = (uint32_t)(st.st_mode & 07777);
  out->uid = (uint32_t)st.st_uid;
  out->gid = (uint32_t)st.st_gid;
  return 0;
}

int response_file_security_lock(const char *path, int directory) {
  struct stat st;
  if (!path || lstat(path, &st) != 0 || (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) return -1;
  if (directory && st.st_uid != geteuid()) return -1;
  mode_t mode = directory ? 0700 : 0400;
  return chmod(path, mode) == 0 && lstat(path, &st) == 0 && (st.st_mode & 07777) == mode ? 0 : -1;
}

int response_file_security_restore(const char *path, const EdrResponseFileSecurity *saved) {
  struct stat st;
  if (!saved || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
      chown(path, (uid_t)saved->uid, (gid_t)saved->gid) != 0 || chmod(path, (mode_t)saved->mode) != 0 ||
      lstat(path, &st) != 0 || (st.st_mode & 07777) != saved->mode ||
      st.st_uid != saved->uid || st.st_gid != saved->gid) return -1;
  return 0;
}
#endif
