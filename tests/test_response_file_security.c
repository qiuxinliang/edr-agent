#include "edr/response_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

/* Keep filesystem writes real; inject only OS failures/readback for the
   negative cases. No production hooks or alternate security path. */
static const char *injected_readback;
static DWORD injected_set_security_error, injected_set_attributes_error;

static BOOL WINAPI test_get_file_security(LPCSTR path, SECURITY_INFORMATION info,
    PSECURITY_DESCRIPTOR buffer, DWORD length, LPDWORD needed) {
  if (!injected_readback) return GetFileSecurityA(path, info, buffer, length, needed);
  PSECURITY_DESCRIPTOR sd = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(injected_readback, SDDL_REVISION_1, &sd, NULL)) return FALSE;
  *needed = GetSecurityDescriptorLength(sd);
  BOOL ok = buffer && length >= *needed;
  if (ok) memcpy(buffer, sd, *needed);
  LocalFree(sd);
  if (!ok) SetLastError(ERROR_INSUFFICIENT_BUFFER);
  return ok;
}

static DWORD WINAPI test_set_named_security(LPSTR path, SE_OBJECT_TYPE type,
    SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl, PACL sacl) {
  if (injected_set_security_error) return injected_set_security_error;
  return SetNamedSecurityInfoA(path, type, info, owner, group, dacl, sacl);
}

static BOOL WINAPI test_set_file_security(LPCSTR path, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR sd) {
  if (injected_set_security_error) {
    SetLastError(injected_set_security_error);
    return FALSE;
  }
  return SetFileSecurityA(path, info, sd);
}

static BOOL WINAPI test_set_file_attributes(LPCSTR path, DWORD attributes) {
  if (injected_set_attributes_error) {
    SetLastError(injected_set_attributes_error);
    return FALSE;
  }
  return SetFileAttributesA(path, attributes);
}

#define GetFileSecurityA test_get_file_security
#define SetNamedSecurityInfoA test_set_named_security
#define SetFileSecurityA test_set_file_security
#define SetFileAttributesA test_set_file_attributes
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "../src/response/response_file_security.c"
#ifdef _WIN32
#undef GetFileSecurityA
#undef SetNamedSecurityInfoA
#undef SetFileSecurityA
#undef SetFileAttributesA
#endif

static void require(int ok, const char *why) {
  if (!ok) {
#ifdef _WIN32
    fprintf(stderr, "FAIL: %s (win32_error=%lu)\n", why, (unsigned long)GetLastError());
#else
    fprintf(stderr, "FAIL: %s\n", why);
#endif
    exit(1);
  }
}

#ifdef _WIN32
static void verify_restricted_dacl(const char *path, BYTE flags) {
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL acl = NULL;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  require(GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
      NULL, NULL, &acl, NULL, &sd) == ERROR_SUCCESS, "independent DACL readback");
  require(GetSecurityDescriptorControl(sd, &control, &revision) && (control & SE_DACL_PROTECTED), "DACL remains protected");
  require(acl && IsValidAcl(acl) && acl->AceCount == 2, "exactly two restricted ACEs");
  for (DWORD i = 0; i < 2; ++i) {
    ACCESS_ALLOWED_ACE *ace = NULL;
    require(GetAce(acl, i, (LPVOID *)&ace), "read restricted ACE");
    require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == flags &&
        ace->Mask == FILE_ALL_ACCESS && IsWellKnownSid(&ace->SidStart, i == 0 ? WinBuiltinAdministratorsSid : WinLocalSystemSid),
        "restricted ACE type, flags, mask and SID verified");
  }
  LocalFree(sd);
}

static void verify_failure_paths(const char *path, const EdrResponseFileSecurity *original) {
  static const struct { const char *sddl; const char *why; } mismatches[] = {
    {"D:AI(A;;FA;;;BA)(A;;FA;;;SY)", "reject unprotected DACL readback"},
    {"D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;WD)", "reject extra ACE"},
    {"D:PAI(A;;FA;;;BA)(A;;FA;;;WD)", "reject changed SID"},
    {"D:PAI(A;;FR;;;BA)(A;;FA;;;SY)", "reject changed access mask"},
    {"D:PAI(A;OICI;FA;;;BA)(A;;FA;;;SY)", "reject changed inheritance flags"},
    {"D:PAI(D;;FA;;;BA)(A;;FA;;;SY)", "reject changed ACE type"},
    {"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)", "reject reordered ACEs"},
    {"D:PAI", "reject empty DACL in place of restricted DACL"},
    {"D:NO_ACCESS_CONTROL", "reject null DACL"}
  };
  EdrResponseFileSecurity protected_snapshot = *original;
  strcpy(protected_snapshot.dacl, "D:P(A;;FA;;;BA)(A;;FA;;;SY)");
  injected_readback = "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)";
  require(response_file_security_lock(path, 0) == 0, "accept identical protected ACEs with OS AI bookkeeping");
  require(response_file_security_restore(path, &protected_snapshot) != 0, "restore rejects changed snapshot inheritance state");
  injected_readback = protected_snapshot.dacl;
  require(response_file_security_restore(path, &protected_snapshot) == 0, "restore accepts exact protected snapshot");
  injected_readback = NULL;
  strcpy(protected_snapshot.dacl, "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)");
  for (size_t i = 0; i < sizeof(mismatches) / sizeof(mismatches[0]); ++i) {
    injected_readback = mismatches[i].sddl;
    require(response_file_security_lock(path, 0) != 0, mismatches[i].why);
    require(GetLastError() == ERROR_INVALID_SECURITY_DESCR, "lock DACL mismatch preserves reason");
    require(response_file_security_restore(path, &protected_snapshot) != 0, mismatches[i].why);
    require(GetLastError() == ERROR_INVALID_SECURITY_DESCR, "restore DACL mismatch preserves reason");
    injected_readback = NULL;
  }
  injected_set_security_error = ERROR_ACCESS_DENIED;
  SetLastError(ERROR_SUCCESS);
  require(response_file_security_lock(path, 0) != 0 && GetLastError() == ERROR_ACCESS_DENIED, "preserve SetNamedSecurityInfo return code on lock");
  SetLastError(ERROR_SUCCESS);
  require(response_file_security_restore(path, original) != 0 && GetLastError() == ERROR_ACCESS_DENIED, "preserve SetFileSecurity error on restore");
  injected_set_security_error = 0;
  injected_set_attributes_error = ERROR_ACCESS_DENIED;
  require(response_file_security_lock(path, 0) != 0 && GetLastError() == ERROR_ACCESS_DENIED, "attribute failure is not lock success");
  require(response_file_security_restore(path, original) != 0 && GetLastError() == ERROR_ACCESS_DENIED, "attribute failure is not restore success");
  injected_set_attributes_error = 0;
  require(response_file_security_restore(path, original) == 0, "restore after injected failures");
  EdrResponseFileSecurity invalid = *original, before, after;
  require(response_file_security_lock(path, 0) == 0 && response_file_security_snapshot(path, &before) == 0,
      "lock fixture for invalid snapshot rejection");
  const char *invalid_sd[] = {"invalid-sddl", "D:NO_ACCESS_CONTROL"};
  for (size_t i = 0; i < sizeof(invalid_sd) / sizeof(invalid_sd[0]); ++i) {
    strcpy(invalid.dacl, invalid_sd[i]);
    require(response_file_security_restore(path, &invalid) != 0, "invalid snapshot rejected before writing attributes");
    require(response_file_security_snapshot(path, &after) == 0 && memcmp(&before, &after, sizeof(before)) == 0,
        "invalid snapshot cannot change locked state");
  }
  require(response_file_security_restore(path, original) == 0, "restore after invalid snapshot rejection");
  puts("PASS: lock AI bookkeeping; exact restore state; nine ACL mutations rejected; invalid snapshots and OS errors");
}

static void verify_restore_matrix(const char *tmp) {
  static const struct { const char *name; const char *sddl; } cases[] = {
    {"ci-explicit-no-ai", "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)"},
    {"protected-explicit", "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)"},
    {"auto-explicit", "D:AI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)"},
    {"inherited-only", "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FR;;;WD)"},
    {"mixed-explicit-inherited", "D:AI(A;;FR;;;LA)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FR;;;WD)"},
    {"deny-write-attributes", "D:P(D;;0x100;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)"}
  };
  char root[MAX_PATH];
  require(GetTempFileNameA(tmp, "erm", 0, root) != 0 && DeleteFileA(root) && CreateDirectoryA(root, NULL),
      "create own matrix directory");
  PSECURITY_DESCRIPTOR parent = NULL;
  require(ConvertStringSecurityDescriptorToSecurityDescriptorA(
      "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)", SDDL_REVISION_1, &parent, NULL), "parse fixed parent ACL");
  require(SetFileSecurityA(root, DACL_SECURITY_INFORMATION, parent), "set deterministic parent ACL");
  LocalFree(parent);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char path[MAX_PATH + 32];
    snprintf(path, sizeof(path), "%s\\case-%u.tmp", root, (unsigned)i);
    FILE *f = fopen(path, "wb");
    require(f && fwrite("benign evidence", 1, 15, f) == 15 && fclose(f) == 0, "write matrix fixture");
    PSECURITY_DESCRIPTOR seed = NULL;
    LPSTR canonical = NULL;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorA(cases[i].sddl, SDDL_REVISION_1, &seed, NULL), "parse matrix seed");
    require(ConvertSecurityDescriptorToStringSecurityDescriptorA(seed, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &canonical, NULL),
        "canonical matrix seed");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(seed, &control, &revision), "read matrix seed control");
    if (control & SE_DACL_AUTO_INHERITED)
      require(SetSecurityDescriptorControl(seed, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERIT_REQ), "request persisted matrix AI state");
    require(SetFileSecurityA(path, DACL_SECURITY_INFORMATION, seed), "set exact matrix initial ACL");
    EdrResponseFileSecurity original, restored;
    require(response_file_security_snapshot(path, &original) == 0 && strcmp(original.dacl, canonical) == 0,
        "initial ACL must match fixture, not machine defaults");
    LocalFree(seed);
    LocalFree(canonical);
    require(response_file_security_lock(path, 0) == 0, "lock matrix fixture");
    verify_restricted_dacl(path, 0);
    int rc = response_file_security_restore(path, &original);
    DWORD error = rc == 0 ? ERROR_SUCCESS : GetLastError();
    int read_rc = response_file_security_snapshot(path, &restored);
    printf("restore_case=%s rc=%d error=%lu expected=%s actual=%s\n", cases[i].name, rc,
        (unsigned long)error, original.dacl, read_rc == 0 ? restored.dacl : "<read-failed>");
    int exact = read_rc == 0 && memcmp(&original, &restored, sizeof(original)) == 0;
    char content[32] = {0};
    f = fopen(path, "rb");
    int unchanged = f && fread(content, 1, sizeof(content), f) == 15 && strcmp(content, "benign evidence") == 0;
    if (f) fclose(f);
    /* Cleanup must also work when the old implementation leaves a file locked. */
    PSECURITY_DESCRIPTOR cleanup = NULL;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &cleanup, NULL),
        "parse own fixture cleanup ACL");
    require(SetFileSecurityA(path, DACL_SECURITY_INFORMATION, cleanup) && SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL) && DeleteFileA(path),
        "cleanup own matrix file");
    LocalFree(cleanup);
    if (rc != 0 || !exact || !unchanged) {
      require(RemoveDirectoryA(root), "cleanup own failed matrix directory");
      require(0, "matrix must restore exact ACL, attributes and content");
    }
  }
  require(RemoveDirectoryA(root), "cleanup own matrix directory");
  puts("PASS: six deterministic restore states under a fixed inheritable parent ACL");
}
#endif

int main(void) {
  char path[1024];
#ifdef _WIN32
  char tmp[MAX_PATH];
  require(GetTempPathA(sizeof(tmp), tmp) > 0, "temp directory");
  require(GetTempFileNameA(tmp, "ers", 0, path) != 0, "temp file");
#else
  snprintf(path, sizeof(path), "/tmp/edr-file-security-XXXXXX");
  int fd = mkstemp(path);
  require(fd >= 0, "temp file");
  close(fd);
  require(chmod(path, 0640) == 0, "initial mode");
#endif
  FILE *f = fopen(path, "wb");
  require(f != NULL, "open benign fixture");
  require(fwrite("benign evidence", 1, 15, f) == 15, "write fixture");
  require(fclose(f) == 0, "close fixture");
  EdrResponseFileSecurity original, locked, restored;
  require(response_file_security_snapshot(path, &original) == 0, "snapshot original security");
  require(response_file_security_lock(path, 1) != 0, "file cannot be treated as directory");
  require(response_file_security_lock(path, 0) == 0, "lock and read back security");
  require(response_file_security_snapshot(path, &locked) == 0, "read locked security");
#ifdef _WIN32
  DWORD required_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
  require(locked.attributes == ((original.attributes & ~FILE_ATTRIBUTE_NORMAL) | required_attributes), "all locked attributes verified");
  printf("original_dacl=%s locked_dacl=%s\n", original.dacl, locked.dacl);
  verify_restricted_dacl(path, 0);
#else
  require(locked.mode == 0400, "execute and write bits removed");
#endif
  int restore_rc = response_file_security_restore(path, &original);
#ifdef _WIN32
  if (restore_rc != 0) {
    DWORD error = GetLastError();
    int read_rc = response_file_security_snapshot(path, &restored);
    fprintf(stderr, "restore expected=%s actual=%s\n", original.dacl, read_rc == 0 ? restored.dacl : "<read-failed>");
    SetLastError(error);
  }
#endif
  require(restore_rc == 0, "restore original security");
  require(response_file_security_snapshot(path, &restored) == 0, "verify restoration");
  require(memcmp(&original, &restored, sizeof(original)) == 0, "security restored exactly");
  char content[32] = {0};
  f = fopen(path, "rb");
  require(f && fread(content, 1, sizeof(content), f) == 15, "read evidence after restore");
  require(fclose(f) == 0 && strcmp(content, "benign evidence") == 0, "evidence unchanged");
#ifdef _WIN32
  verify_failure_paths(path, &original);
  require(response_file_security_snapshot(path, &restored) == 0 && memcmp(&original, &restored, sizeof(original)) == 0,
      "original security unchanged after failure cases");
  char directory[MAX_PATH];
  require(GetTempFileNameA(tmp, "erd", 0, directory) != 0 && DeleteFileA(directory) && CreateDirectoryA(directory, NULL),
      "create own directory fixture");
  require(response_file_security_lock(directory, 0) != 0, "directory cannot be treated as file");
  require(response_file_security_lock(directory, 1) == 0, "lock directory with AI bookkeeping");
  verify_restricted_dacl(directory, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
  require(RemoveDirectoryA(directory), "cleanup own directory fixture");
  puts("PASS: real protected file/directory ACLs and exact original restoration");
  verify_restore_matrix(tmp);
#endif
#ifndef _WIN32
  char linkpath[1100];
  snprintf(linkpath, sizeof(linkpath), "%s.link", path);
  require(symlink(path, linkpath) == 0, "create own symlink fixture");
  require(response_file_security_snapshot(linkpath, &locked) != 0, "reject symlink evidence");
  require(response_file_security_lock(linkpath, 0) != 0, "do not follow symlink during locking");
  require(unlink(linkpath) == 0, "cleanup own link");
#endif
  require(remove(path) == 0, "cleanup own fixture");
  require(response_file_security_lock(path, 0) != 0, "missing file is not locked success");
  puts("PASS: file security lock, exact restore, unchanged evidence, failure paths");
  return 0;
}
