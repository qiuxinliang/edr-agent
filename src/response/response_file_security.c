#include "edr/response_utils.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>

static int security_failure(const char *stage, DWORD error) {
  fprintf(stderr, "response_file_security: stage=%s win32_error=%lu\n", stage, (unsigned long)error);
  SetLastError(error);
  return -1;
}

static int dacl_matches(const char *actual, const char *expected, SECURITY_DESCRIPTOR_CONTROL control_mask) {
  PSECURITY_DESCRIPTOR descriptors[2] = {NULL, NULL};
  PACL acls[2] = {NULL, NULL};
  SECURITY_DESCRIPTOR_CONTROL controls[2] = {0, 0};
  const char *texts[2] = {actual, expected};
  int matches = 0;
  for (int i = 0; i < 2; ++i) {
    BOOL present = FALSE, defaulted = FALSE;
    DWORD revision = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(texts[i], SDDL_REVISION_1, &descriptors[i], NULL) ||
        !GetSecurityDescriptorControl(descriptors[i], &controls[i], &revision) ||
        !GetSecurityDescriptorDacl(descriptors[i], &present, &acls[i], &defaulted) ||
        !present || !acls[i] || !IsValidAcl(acls[i])) goto done;
  }
  /* Locking permits OS-generated AI bookkeeping; snapshot restoration must
     retain it. Both retain every ordered ACE byte and reject null DACLs. */
  if ((controls[0] & control_mask) != (controls[1] & control_mask)) {
    fprintf(stderr, "response_file_security: mismatch=control expected=0x%x actual=0x%x\n",
        (unsigned)(controls[1] & control_mask), (unsigned)(controls[0] & control_mask));
    goto done;
  }
  if (acls[0]->AceCount != acls[1]->AceCount) {
    fprintf(stderr, "response_file_security: mismatch=ace-count expected=%u actual=%u\n",
        (unsigned)acls[1]->AceCount, (unsigned)acls[0]->AceCount);
    goto done;
  }
  for (DWORD i = 0; i < acls[0]->AceCount; ++i) {
    ACE_HEADER *a = NULL, *b = NULL;
    if (!GetAce(acls[0], i, (LPVOID *)&a) || !GetAce(acls[1], i, (LPVOID *)&b) ||
        a->AceSize != b->AceSize || memcmp(a, b, a->AceSize) != 0) {
      fprintf(stderr, "response_file_security: mismatch=ace-content index=%lu\n", (unsigned long)i);
      goto done;
    }
  }
  matches = 1;
done:
  if (descriptors[0]) LocalFree(descriptors[0]);
  if (descriptors[1]) LocalFree(descriptors[1]);
  return matches;
}

static int read_dacl(const char *path, char *out, size_t cap) {
  DWORD required = 0;
  GetFileSecurityA(path, DACL_SECURITY_INFORMATION, NULL, 0, &required);
  if (!required) return security_failure("read-dacl-size", GetLastError());
  if (required > 65536u) return security_failure("read-dacl-size", ERROR_INSUFFICIENT_BUFFER);
  PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)malloc(required);
  if (!sd) return security_failure("read-dacl-allocate", ERROR_NOT_ENOUGH_MEMORY);
  LPSTR text = NULL;
  int ok = GetFileSecurityA(path, DACL_SECURITY_INFORMATION, sd, required, &required) &&
      ConvertSecurityDescriptorToStringSecurityDescriptorA(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, NULL);
  DWORD error = ok ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
  if (ok && strlen(text) < cap) memcpy(out, text, strlen(text) + 1u);
  else ok = 0;
  if (text) LocalFree(text);
  free(sd);
  return ok ? 0 : security_failure("read-dacl", error);
}

static int apply_dacl(const char *path, const char *text) {
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(text, SDDL_REVISION_1, &sd, NULL))
    return security_failure("parse-dacl", GetLastError());
  int ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl &&
      GetSecurityDescriptorControl(sd, &control, &revision);
  DWORD error = ERROR_INVALID_SECURITY_DESCR;
  if (ok) {
    SECURITY_INFORMATION info = DACL_SECURITY_INFORMATION |
        ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    error = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, info, NULL, NULL, dacl, NULL);
  }
  LocalFree(sd);
  return error == ERROR_SUCCESS ? 0 : security_failure("set-dacl", error);
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
  if (apply_dacl(path, dacl) != 0 || read_dacl(path, actual, sizeof(actual)) != 0) return -1;
  if (!dacl_matches(actual, dacl, SE_DACL_PROTECTED)) return security_failure("lock-verify-dacl", ERROR_INVALID_SECURITY_DESCR);
  if (!directory) {
    DWORD wanted = (attr & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    if (!SetFileAttributesA(path, wanted)) return security_failure("lock-set-attributes", GetLastError());
    DWORD observed = GetFileAttributesA(path);
    if (observed == INVALID_FILE_ATTRIBUTES) return security_failure("lock-read-attributes", GetLastError());
    if (observed != wanted) return security_failure("lock-verify-attributes", ERROR_INVALID_DATA);
  }
  return 0;
}

int response_file_security_restore(const char *path, const EdrResponseFileSecurity *saved) {
  char actual[8192];
  DWORD attr = GetFileAttributesA(path);
  if (attr == INVALID_FILE_ATTRIBUTES || (attr & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return -1;
  if (!saved || !saved->dacl[0]) return security_failure("restore-snapshot", ERROR_INVALID_PARAMETER);
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(saved->dacl, SDDL_REVISION_1, &sd, NULL))
    return security_failure("restore-parse-dacl", GetLastError());
  DWORD error = ERROR_INVALID_SECURITY_DESCR;
  const char *stage = "restore-validate-dacl";
  if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl || !IsValidAcl(dacl)) goto done;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  stage = "restore-prepare-inheritance";
  /* The low-level setter consumes AR as the request to retain an existing AI
     state; AI alone is cleared. AR is not added to the saved snapshot. */
  if (!GetSecurityDescriptorControl(sd, &control, &revision) ||
      ((control & SE_DACL_AUTO_INHERITED) &&
       !SetSecurityDescriptorControl(sd, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERIT_REQ))) {
    error = GetLastError();
    goto done;
  }

  /* Restore attributes while the quarantine ACL still permits writing them.
     A valid original ACL can deny FILE_WRITE_ATTRIBUTES even to SYSTEM. */
  stage = "restore-set-attributes";
  if (!SetFileAttributesA(path, saved->attributes)) { error = GetLastError(); goto done; }

  /* Snapshot replay, not a new inheritance policy. SetNamedSecurityInfo with
     UNPROTECTED_DACL_SECURITY_INFORMATION merges the current parent's ACEs.
     The low-level file API preserves this saved descriptor without that merge.
     This path is file-only; directory locking retains SetNamedSecurityInfo. */
  stage = "restore-set-dacl";
  error = SetFileSecurityA(path, DACL_SECURITY_INFORMATION, sd) ? ERROR_SUCCESS : GetLastError();
done:
  LocalFree(sd);
  if (error != ERROR_SUCCESS) return security_failure(stage, error);
  DWORD observed = GetFileAttributesA(path);
  if (observed == INVALID_FILE_ATTRIBUTES) return security_failure("restore-read-attributes", GetLastError());
  if (observed != saved->attributes) return security_failure("restore-verify-attributes", ERROR_INVALID_DATA);
  if (read_dacl(path, actual, sizeof(actual)) != 0) return -1;
  if (!dacl_matches(actual, saved->dacl, SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ))
    return security_failure("restore-verify-dacl", ERROR_INVALID_SECURITY_DESCR);
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
