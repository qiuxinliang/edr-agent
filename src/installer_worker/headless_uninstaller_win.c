#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <rpc.h>
#include <shlobj.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <taskschd.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <ncrypt.h>
#include <wchar.h>
#include "cJSON.h"
#include "edr/windows_native_manifest.h"
#include "edr/windows_handoff.h"
#include "edr/windows_spawn.h"
#include "edr/windows_spawn_lock.h"

#define EDR_UNINSTALL_TITLE L"FDSecurity Agent Uninstaller"
#define EDR_FINALIZER_IO_TIMEOUT_MS 5000u
#ifndef EDR_FINALIZER_DELETE_RETRY_TIMEOUT_MS
#define EDR_FINALIZER_DELETE_RETRY_TIMEOUT_MS 5000u
#endif
#define EDR_FINALIZER_DELETE_RETRY_INTERVAL_MS 100u
#define MAX_PATH_LONG 32768
static const char *HEADLESS_UNINSTALLER_CAPABILITIES =
    "{\"schema\":\"edr.windows.native-capabilities.v1\","
    "\"component\":\"headless-uninstaller\","
    "\"uninstall_attestation\":\"v3\","
    "\"native_in_memory_token_handoff\":true}";

static int join_path(wchar_t *out, size_t out_count, const wchar_t *dir, const wchar_t *name);
static DWORD child_creation_flags(DWORD base_flags);
static int file_exists(const wchar_t *path);
static int append_quoted_arg(wchar_t *out, size_t out_count, size_t *used,
                             const wchar_t *arg);
static int append_text(wchar_t *out, size_t out_count, size_t *used,
                       const wchar_t *text);
static int edr_finalizer_canonical_path(const wchar_t *path, wchar_t *canonical,
                                        DWORD canonical_capacity);
static int edr_native_hex_value(wchar_t ch);
static int edr_native_crack_attestation_url(const wchar_t *url,
                                            URL_COMPONENTSW *components,
                                            wchar_t *host, DWORD host_count,
                                            wchar_t *path, DWORD path_count);
static int edr_native_valid_bearer_token(const BYTE *token, DWORD token_length);

typedef struct EdrFinalizerHandoff {
  HANDLE secret_write;
  HANDLE ack_read;
} EdrFinalizerHandoff;

/* A local uninstall has no bearer token.  It still uses a non-empty framed
 * value so the shared handoff protocol never treats an empty frame as valid.
 * This value is only a routing marker; it is never accepted by the remote
 * bearer-token validator or sent to attestation. */
static const BYTE EDR_LOCAL_HANDOFF_MARKER[] = "edr.local.uninstall.handoff.v1";

static int edr_native_is_local_handoff_marker(const BYTE *value, DWORD length) {
  return value && length == sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1 &&
         memcmp(value, EDR_LOCAL_HANDOFF_MARKER,
                sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1) == 0;
}

static DWORD edr_finalizer_last_error(void) {
  DWORD error = GetLastError();
  return error ? error : ERROR_GEN_FAILURE;
}

static int edr_native_wait_for_parent_delivery_window(HANDLE parent_handle,
                                                       DWORD timeout_ms) {
  DWORD wait_result;
  if (!parent_handle) return ERROR_INVALID_HANDLE;
  wait_result = WaitForSingleObject(parent_handle, timeout_ms);
  if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_TIMEOUT) return ERROR_SUCCESS;
  return (int)edr_finalizer_last_error();
}

/* The finalizer directory and executable are outside the package being
 * removed. Its ACL is established before any package-derived bytes are
 * written; only SYSTEM and the local Administrators group can replace it. */
static int edr_finalizer_protect_path(const wchar_t *path) {
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PACL dacl = NULL;
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1,
          &descriptor, NULL)) {
    return 0;
  }
  if (!GetSecurityDescriptorDacl(descriptor, &dacl_present, &dacl, &dacl_defaulted) || !dacl_present ||
      SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            NULL, NULL, dacl, NULL) != ERROR_SUCCESS) {
    LocalFree(descriptor);
    return 0;
  }
  LocalFree(descriptor);
  return 1;
}

static int edr_finalizer_security_attributes(SECURITY_ATTRIBUTES *attributes,
                                              PSECURITY_DESCRIPTOR *descriptor_out) {
  if (!attributes || !descriptor_out) return 0;
  *descriptor_out = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1,
          descriptor_out, NULL)) return 0;
  ZeroMemory(attributes, sizeof(*attributes));
  attributes->nLength = sizeof(*attributes);
  attributes->lpSecurityDescriptor = *descriptor_out;
  attributes->bInheritHandle = FALSE;
  return 1;
}

static int edr_finalizer_unique_name(wchar_t *out, size_t cap, const wchar_t *directory) {
  UUID uuid;
  RPC_WSTR text = NULL;
  RPC_STATUS uuid_status = UuidCreate(&uuid);
  if ((uuid_status != RPC_S_OK && uuid_status != RPC_S_UUID_LOCAL_ONLY) ||
      UuidToStringW(&uuid, &text) != RPC_S_OK || !text) return 0;
  int written = _snwprintf(out, cap, L"%ls\\uninstall-finalizer-%ls.exe", directory, text);
  RpcStringFreeW(&text);
  return written >= 0 && (size_t)written < cap;
}

static int edr_finalizer_sha256_handle(HANDLE file, BYTE digest[32]) {
  HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; int ok = 0;
  LARGE_INTEGER origin;
  origin.QuadPart = 0;
  if (!file || file == INVALID_HANDLE_VALUE || !digest ||
      !SetFilePointerEx(file, origin, NULL, FILE_BEGIN) ||
      !CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
      !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
  BYTE buffer[16384]; DWORD got = 0;
  for (;;) {
    if (!ReadFile(file, buffer, sizeof(buffer), &got, NULL)) goto cleanup;
    if (got && !CryptHashData(hash, buffer, got, 0)) goto cleanup;
    if (!got) break;
  }
  DWORD size = 32;
  ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == 32;
cleanup:
  SecureZeroMemory(buffer, sizeof(buffer));
  if (hash) CryptDestroyHash(hash);
  if (provider) CryptReleaseContext(provider, 0);
  return ok;
}

static int edr_native_read_toml_scalar(const wchar_t *path, const char *key,
                                       wchar_t *out, size_t out_count) {
  FILE *file;
  char line[4096];
  size_t key_length;
  if (!path || !path[0] || !key || !key[0] || !out || out_count == 0) return 0;
  out[0] = L'\0';
  file = _wfopen(path, L"rb");
  if (!file) return 0;
  key_length = strlen(key);
  while (fgets(line, sizeof(line), file)) {
    char *cursor = line;
    char value[2048];
    size_t value_length = 0;
    while (*cursor && isspace((unsigned char)*cursor)) ++cursor;
    if (*cursor == '#' || strncmp(cursor, key, key_length) != 0) continue;
    cursor += key_length;
    while (*cursor && isspace((unsigned char)*cursor)) ++cursor;
    if (*cursor++ != '=') continue;
    while (*cursor && isspace((unsigned char)*cursor)) ++cursor;
    if (*cursor == '"') {
      ++cursor;
      while (*cursor && *cursor != '"' && value_length + 1 < sizeof(value)) {
        if (*cursor == '\\' && cursor[1] != '\0') ++cursor;
        value[value_length++] = *cursor++;
      }
    } else {
      while (*cursor && *cursor != '#' && *cursor != '\r' && *cursor != '\n' &&
             value_length + 1 < sizeof(value)) value[value_length++] = *cursor++;
      while (value_length && isspace((unsigned char)value[value_length - 1])) --value_length;
    }
    value[value_length] = '\0';
    fclose(file);
    if (!value[0] || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1,
                                         out, (int)out_count) <= 0) {
      out[0] = L'\0';
      return 0;
    }
    out[out_count - 1] = L'\0';
    return 1;
  }
  fclose(file);
  return 0;
}

static int edr_native_validate_package_shape(const wchar_t *install_dir) {
  return edr_windows_native_manifest_validate(install_dir, NULL) ? ERROR_SUCCESS
                                                                   : ERROR_INVALID_DATA;
}

static int edr_finalizer_copy_verified(const wchar_t *source, const wchar_t *target) {
  BYTE source_hash[32], target_hash[32];
  HANDLE input = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
  LARGE_INTEGER origin;
  int created_target = 0;
  int ok = 0;
  input = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  SECURITY_ATTRIBUTES security;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (!edr_finalizer_security_attributes(&security, &descriptor)) goto cleanup;
  output = CreateFileW(target, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                       FILE_SHARE_READ, &security, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
  LocalFree(descriptor);
  if (output != INVALID_HANDLE_VALUE) created_target = 1;
  if (input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE) goto cleanup;
  origin.QuadPart = 0;
  if (!edr_finalizer_sha256_handle(input, source_hash) ||
      !SetFilePointerEx(input, origin, NULL, FILE_BEGIN)) goto cleanup;
  BYTE buffer[16384];
  DWORD got = 0;
  DWORD written = 0;
  for (;;) {
    if (!ReadFile(input, buffer, sizeof(buffer), &got, NULL)) goto cleanup;
    if (!got) break;
    if (!WriteFile(output, buffer, got, &written, NULL) || written != got) goto cleanup;
  }
  if (!FlushFileBuffers(output)) goto cleanup;
  ok = edr_finalizer_sha256_handle(output, target_hash) &&
       memcmp(source_hash, target_hash, sizeof(source_hash)) == 0;
cleanup:
  if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
  if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
  if (!ok && created_target) DeleteFileW(target);
  SecureZeroMemory(source_hash, sizeof(source_hash));
  SecureZeroMemory(target_hash, sizeof(target_hash));
  return ok;
}

static int edr_finalizer_exchange_ready(EdrFinalizerHandoff *handoff,
                                        const BYTE *secret, DWORD secret_length) {
  BYTE acknowledgement[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD acknowledgement_length = 0;
  static const BYTE ready[] = "edr.finalizer.ready.v1";
  if (!handoff || handoff->secret_write == INVALID_HANDLE_VALUE ||
      handoff->ack_read == INVALID_HANDLE_VALUE || secret_length > EDR_WINDOWS_HANDOFF_MAX_FRAME ||
      !edr_windows_handoff_write_frame(handoff->secret_write, secret, secret_length)) {
    return 0;
  }
  CloseHandle(handoff->secret_write);
  handoff->secret_write = INVALID_HANDLE_VALUE;
  if (!edr_windows_handoff_read_frame(handoff->ack_read, acknowledgement,
                                      sizeof(acknowledgement), &acknowledgement_length)) {
    CloseHandle(handoff->ack_read);
    handoff->ack_read = INVALID_HANDLE_VALUE;
    return 0;
  }
  CloseHandle(handoff->ack_read);
  handoff->ack_read = INVALID_HANDLE_VALUE;
  int ok = acknowledgement_length == sizeof(ready) - 1 &&
           memcmp(acknowledgement, ready, sizeof(ready) - 1) == 0;
  SecureZeroMemory(acknowledgement, sizeof(acknowledgement));
  return ok;
}

static int edr_finalizer_normalize_final_path(wchar_t *path, size_t capacity) {
  size_t length;
  if (!path || !capacity) return 0;
  length = wcslen(path);
  if (length >= capacity) return 0;
  if (!_wcsnicmp(path, L"\\\\?\\UNC\\", 8)) {
    if (length + 2 >= capacity) return 0;
    memmove(path + 2, path + 8, (length - 8 + 1) * sizeof(wchar_t));
    path[0] = L'\\';
    path[1] = L'\\';
  } else if (!_wcsnicmp(path, L"\\\\?\\", 4)) {
    memmove(path, path + 4, (length - 4 + 1) * sizeof(wchar_t));
  }
  return 1;
}

static int edr_finalizer_canonical_path(const wchar_t *path, wchar_t *canonical,
                                        DWORD canonical_capacity) {
  HANDLE handle;
  DWORD length;
  if (!path || !path[0] || !canonical || !canonical_capacity) return 0;
  handle = CreateFileW(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                       NULL);
  if (handle == INVALID_HANDLE_VALUE) return 0;
  length = GetFinalPathNameByHandleW(handle, canonical, canonical_capacity,
                                     FILE_NAME_NORMALIZED);
  CloseHandle(handle);
  return length && length < canonical_capacity &&
         edr_finalizer_normalize_final_path(canonical, canonical_capacity);
}

static int edr_finalizer_is_exact_path(const wchar_t *left, const wchar_t *right) {
  size_t left_length;
  size_t right_length;
  if (!left || !right) return 0;
  left_length = wcslen(left);
  right_length = wcslen(right);
  while (left_length > 3 && (left[left_length - 1] == L'\\' || left[left_length - 1] == L'/')) {
    left_length--;
  }
  while (right_length > 3 && (right[right_length - 1] == L'\\' || right[right_length - 1] == L'/')) {
    right_length--;
  }
  return left_length == right_length && _wcsnicmp(left, right, left_length) == 0;
}

static int edr_finalizer_is_volume_root(const wchar_t *canonical) {
  wchar_t volume_root[MAX_PATH_LONG];
  DWORD length;
  if (!canonical || !canonical[0]) return 0;
  length = GetVolumePathNameW(canonical, volume_root,
                              (DWORD)(sizeof(volume_root) / sizeof(volume_root[0])));
  return length && edr_finalizer_is_exact_path(canonical, volume_root);
}

static int edr_finalizer_is_protected_root(const wchar_t *canonical) {
  wchar_t *paths;
  wchar_t *system_path;
  wchar_t *protected_root;
  DWORD length;
  int protected = 0;

  if (!canonical ||
      !((canonical[0] >= L'A' && canonical[0] <= L'Z') ||
        (canonical[0] >= L'a' && canonical[0] <= L'z')) ||
      canonical[1] != L':' || canonical[2] != L'\\') return 1;
  if (edr_finalizer_is_volume_root(canonical)) return 1;
  paths = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                               2u * MAX_PATH_LONG * sizeof(wchar_t));
  if (!paths) return 1;
  system_path = paths;
  protected_root = paths + MAX_PATH_LONG;
  length = GetWindowsDirectoryW(system_path, MAX_PATH_LONG);
  if (!length || length >= MAX_PATH_LONG) {
    protected = 1;
    goto cleanup;
  }
  if (edr_finalizer_is_exact_path(canonical, system_path)) {
    protected = 1;
    goto cleanup;
  }
  if (_wcsnicmp(canonical, system_path, length) == 0 &&
      (canonical[length] == L'\\' || canonical[length] == L'/')) {
    protected = 1;
    goto cleanup;
  }

  if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT,
                       system_path) == S_OK &&
      edr_finalizer_canonical_path(system_path, protected_root, MAX_PATH_LONG) &&
      edr_finalizer_is_exact_path(canonical, protected_root)) {
    protected = 1;
    goto cleanup;
  }
  if (SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT,
                       system_path) == S_OK &&
      edr_finalizer_canonical_path(system_path, protected_root, MAX_PATH_LONG) &&
      edr_finalizer_is_exact_path(canonical, protected_root)) {
    protected = 1;
  }
cleanup:
  HeapFree(GetProcessHeap(), 0, paths);
  return protected;
}

static void edr_finalizer_record_failure_path(wchar_t *out, size_t out_count,
                                              const wchar_t *path) {
  size_t length;
  if (!out || out_count == 0) return;
  out[0] = L'\0';
  if (!path) return;
  length = wcslen(path);
  if (length >= out_count) length = out_count - 1;
  memcpy(out, path, length * sizeof(wchar_t));
  out[length] = L'\0';
}

static int edr_finalizer_delete_path_with_retry(const wchar_t *path, int directory,
                                                 DWORD *error_out) {
  DWORD error = ERROR_SUCCESS;
  ULONGLONG retry_deadline = 0;
  for (;;) {
    ULONGLONG now;
    DWORD delay_ms;
    if (directory ? RemoveDirectoryW(path) : DeleteFileW(path)) {
      if (error_out) *error_out = ERROR_SUCCESS;
      return 1;
    }
    error = edr_finalizer_last_error();
    now = GetTickCount64();
    if (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION) {
      if (error_out) *error_out = error;
      return 0;
    }
    if (!retry_deadline) {
      retry_deadline = now + EDR_FINALIZER_DELETE_RETRY_TIMEOUT_MS;
    }
    if (now >= retry_deadline) {
      if (error_out) *error_out = error;
      return 0;
    }
    delay_ms = (DWORD)(retry_deadline - now);
    if (delay_ms > EDR_FINALIZER_DELETE_RETRY_INTERVAL_MS) {
      delay_ms = EDR_FINALIZER_DELETE_RETRY_INTERVAL_MS;
    }
    Sleep(delay_ms);
  }
}

static int edr_finalizer_safe_delete_tree(const wchar_t *root, DWORD *error_out,
                                          wchar_t *failure_path,
                                          size_t failure_path_count) {
  FILE_ATTRIBUTE_TAG_INFO tag_info;
  DWORD root_attributes;
  DWORD root_error;
  wchar_t *path;
  HANDLE root_handle;
  DWORD canonical_length;
  WIN32_FIND_DATAW item;
  HANDLE find;
  int ok = 1;
  DWORD last_error = ERROR_SUCCESS;
  if (!root || !root[0]) {
    if (error_out) *error_out = ERROR_INVALID_PARAMETER;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    return 0;
  }
  root_attributes = GetFileAttributesW(root);
  if (root_attributes == INVALID_FILE_ATTRIBUTES) {
    root_error = edr_finalizer_last_error();
    if (root_error == ERROR_FILE_NOT_FOUND || root_error == ERROR_PATH_NOT_FOUND) {
      if (error_out) *error_out = ERROR_SUCCESS;
      return 1;
    }
    if (error_out) *error_out = root_error;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    return 0;
  }
  path = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, MAX_PATH_LONG * sizeof(wchar_t));
  if (!path) {
    if (error_out) *error_out = ERROR_NOT_ENOUGH_MEMORY;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    return 0;
  }
  root_handle = CreateFileW(root, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            NULL);
  if (root_handle == INVALID_HANDLE_VALUE) {
    if (error_out) *error_out = edr_finalizer_last_error();
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  if (!GetFileInformationByHandleEx(root_handle, FileAttributeTagInfo,
                                    &tag_info, sizeof(tag_info)) ||
      (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      !(tag_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    CloseHandle(root_handle);
    if (error_out) *error_out = ERROR_INVALID_REPARSE_DATA;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  canonical_length = GetFinalPathNameByHandleW(root_handle, path, MAX_PATH_LONG,
                                               FILE_NAME_NORMALIZED);
  CloseHandle(root_handle);
  if (!canonical_length || canonical_length >= MAX_PATH_LONG) {
    if (error_out) *error_out = canonical_length ? ERROR_BUFFER_OVERFLOW : GetLastError();
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  if (!edr_finalizer_normalize_final_path(path, MAX_PATH_LONG) ||
      edr_finalizer_is_protected_root(path)) {
    if (error_out) *error_out = ERROR_ACCESS_DENIED;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  if (!join_path(path, MAX_PATH_LONG, root, L"*")) {
    if (error_out) *error_out = ERROR_BUFFER_OVERFLOW;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  find = FindFirstFileW(path, &item);
  if (find == INVALID_HANDLE_VALUE) {
    DWORD find_error = edr_finalizer_last_error();
    if (find_error == ERROR_FILE_NOT_FOUND || find_error == ERROR_PATH_NOT_FOUND) {
      if (!edr_finalizer_delete_path_with_retry(root, 1, error_out)) {
        edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
        HeapFree(GetProcessHeap(), 0, path);
        return 0;
      }
      if (error_out) *error_out = ERROR_SUCCESS;
      HeapFree(GetProcessHeap(), 0, path);
      return 1;
    }
    if (error_out) *error_out = find_error;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
    HeapFree(GetProcessHeap(), 0, path);
    return 0;
  }
  do {
    if (!wcscmp(item.cFileName, L".") || !wcscmp(item.cFileName, L"..")) continue;
    if (!join_path(path, MAX_PATH_LONG, root, item.cFileName)) {
      ok = 0;
      last_error = ERROR_BUFFER_OVERFLOW;
      edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
      break;
    }
    if (item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      if (!edr_finalizer_delete_path_with_retry(
              path, (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
              &last_error)) {
        ok = 0;
        edr_finalizer_record_failure_path(failure_path, failure_path_count, path);
        break;
      }
    } else if (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      if (!edr_finalizer_safe_delete_tree(path, &last_error,
                                          failure_path, failure_path_count)) {
        ok = 0;
        break;
      }
    } else {
      SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
      if (!edr_finalizer_delete_path_with_retry(path, 0, &last_error)) {
        ok = 0;
        edr_finalizer_record_failure_path(failure_path, failure_path_count, path);
        break;
      }
    }
  } while (FindNextFileW(find, &item));
  if (ok && GetLastError() != ERROR_NO_MORE_FILES) {
    ok = 0;
    last_error = GetLastError();
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
  }
  FindClose(find);
  if (ok && !edr_finalizer_delete_path_with_retry(root, 1, &last_error)) {
    ok = 0;
    edr_finalizer_record_failure_path(failure_path, failure_path_count, root);
  }
  if (error_out) *error_out = ok ? ERROR_SUCCESS : last_error;
  HeapFree(GetProcessHeap(), 0, path);
  return ok;
}

static DWORD edr_finalizer_schedule_self_delete(const wchar_t *path) {
  if (DeleteFileW(path)) return ERROR_SUCCESS;
  if (MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) return ERROR_SUCCESS_REBOOT_REQUIRED;
  return edr_finalizer_last_error();
}

static DWORD edr_native_unlink_self(const wchar_t *path) {
  HANDLE file;
  FILE_DISPOSITION_INFO_EX disposition;
  if (!path || !path[0]) return ERROR_INVALID_PARAMETER;
  file = CreateFileW(path, DELETE | SYNCHRONIZE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return edr_finalizer_last_error();
  ZeroMemory(&disposition, sizeof(disposition));
  disposition.Flags = FILE_DISPOSITION_FLAG_DELETE |
                      FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                      FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
  if (!SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition,
                                  sizeof(disposition))) {
    DWORD error = edr_finalizer_last_error();
    CloseHandle(file);
    return error;
  }
  CloseHandle(file);
  if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
    DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
    return error;
  }
  return ERROR_DELETE_PENDING;
}

static DWORD child_creation_flags(DWORD base_flags) {
  BOOL in_job = FALSE;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job) return base_flags;
  ZeroMemory(&limits, sizeof(limits));
  if (QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &limits,
                                sizeof(limits), NULL) &&
      (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)) {
    return base_flags | CREATE_BREAKAWAY_FROM_JOB;
  }
  return base_flags;
}

static int has_flag(int argc, wchar_t **argv, const wchar_t *flag) {
  int i;
  for (i = 1; i < argc; ++i) {
    if (_wcsicmp(argv[i], flag) == 0) return 1;
  }
  return 0;
}

static const wchar_t *arg_value(int argc, wchar_t **argv, const wchar_t *name) {
  size_t name_len = wcslen(name);
  int i;
  for (i = 1; i < argc; ++i) {
    if (_wcsicmp(argv[i], name) == 0 && i + 1 < argc) return argv[i + 1];
    if (_wcsnicmp(argv[i], name, name_len) == 0 && argv[i][name_len] == L'=') {
      return argv[i] + name_len + 1;
    }
  }
  return L"";
}

static int edr_finalizer_parse_handle(const wchar_t *text, HANDLE *handle_out) {
  wchar_t *end = NULL;
  unsigned long long value;
  HANDLE handle;
  DWORD handle_flags = 0;
  if (!text || !text[0] || !handle_out || text[0] < L'0' || text[0] > L'9') return 0;
  errno = 0;
  value = _wcstoui64(text, &end, 10);
  if (errno == ERANGE || !end || *end != L'\0' || value == 0 ||
      (unsigned long long)(ULONG_PTR)value != value) return 0;
  handle = (HANDLE)(ULONG_PTR)value;
  if (!handle || handle == INVALID_HANDLE_VALUE || !GetHandleInformation(handle, &handle_flags)) {
    return 0;
  }
  *handle_out = handle;
  return 1;
}

static int edr_native_process_running_at_path(const wchar_t *image_path) {
  HANDLE snapshot;
  PROCESSENTRY32W entry;
  wchar_t canonical_target[MAX_PATH_LONG];
  const wchar_t *target_name;
  int found = 0;
  if (!image_path || !image_path[0] ||
      !edr_finalizer_canonical_path(image_path, canonical_target,
                                    (DWORD)(sizeof(canonical_target) / sizeof(canonical_target[0])))) {
    return -1;
  }
  snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return -1;
  target_name = wcsrchr(image_path, L'\\');
  target_name = target_name ? target_name + 1 : image_path;
  ZeroMemory(&entry, sizeof(entry));
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      BOOL has_next;
      if (_wcsicmp(entry.szExeFile, target_name) != 0) {
        has_next = Process32NextW(snapshot, &entry);
        if (!has_next) break;
        continue;
      }
      HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
      if (!process) {
        CloseHandle(snapshot);
        return -1;
      }
      wchar_t process_path[MAX_PATH_LONG];
      DWORD length = (DWORD)(sizeof(process_path) / sizeof(process_path[0]));
      wchar_t canonical_process[MAX_PATH_LONG];
      if (!QueryFullProcessImageNameW(process, 0, process_path, &length) ||
          !edr_finalizer_canonical_path(process_path, canonical_process,
                                        (DWORD)(sizeof(canonical_process) / sizeof(canonical_process[0]))) ) {
        CloseHandle(process);
        CloseHandle(snapshot);
        return -1;
      }
      if (_wcsicmp(canonical_process, canonical_target) == 0) found = 1;
      CloseHandle(process);
      if (found) break;
      has_next = Process32NextW(snapshot, &entry);
      if (!has_next) break;
    } while (1);
    if (!found && GetLastError() != ERROR_NO_MORE_FILES) {
      CloseHandle(snapshot);
      return -1;
    }
  } else if (GetLastError() != ERROR_NO_MORE_FILES) {
    CloseHandle(snapshot);
    return -1;
  }
  CloseHandle(snapshot);
  return found;
}

static int edr_native_run_process(const wchar_t *executable, const wchar_t *arguments,
                                  const wchar_t *working_directory, DWORD timeout_ms) {
  wchar_t command[32768];
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
  int written;
  DWORD wait_result;
  DWORD exit_code = ERROR_GEN_FAILURE;

  if (!executable || !executable[0] || !working_directory) return ERROR_INVALID_PARAMETER;
  written = _snwprintf(command, sizeof(command) / sizeof(command[0]),
                       L"\"%ls\"%ls", executable, arguments ? arguments : L"");
  if (written < 0 || (size_t)written >= sizeof(command) / sizeof(command[0])) {
    return ERROR_INSUFFICIENT_BUFFER;
  }
  ZeroMemory(&startup, sizeof(startup));
  ZeroMemory(&process, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  if (!CreateProcessW(NULL, command, NULL, NULL, FALSE,
                      child_creation_flags(CREATE_NO_WINDOW), NULL, working_directory,
                      &startup, &process)) {
    return (int)GetLastError();
  }
  CloseHandle(process.hThread);
  wait_result = WaitForSingleObject(process.hProcess, timeout_ms);
  if (wait_result == WAIT_TIMEOUT) {
    TerminateProcess(process.hProcess, ERROR_TIMEOUT);
    WaitForSingleObject(process.hProcess, 5000);
    CloseHandle(process.hProcess);
    return ERROR_TIMEOUT;
  }
  if (wait_result != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exit_code)) {
    DWORD error = wait_result == WAIT_OBJECT_0 ? GetLastError() : wait_result;
    CloseHandle(process.hProcess);
    return (int)(error ? error : ERROR_GEN_FAILURE);
  }
  CloseHandle(process.hProcess);
  return (int)exit_code;
}

static int edr_native_disable_service_recovery(SC_HANDLE service) {
  SERVICE_FAILURE_ACTIONSW no_actions;
  BOOL failure_flag = FALSE;
  ZeroMemory(&no_actions, sizeof(no_actions));
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &no_actions)) return 0;
  return ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                               &failure_flag) != FALSE;
}

static int edr_native_restore_service_and_start(const wchar_t *service_name) {
  SC_HANDLE manager;
  SC_HANDLE service;
  SERVICE_FAILURE_ACTIONSW recovery;
  SC_ACTION action;
  SERVICE_FAILURE_ACTIONS_FLAG flag;
  int ok = 0;

  manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (manager == NULL) return 0;
  service = OpenServiceW(manager, service_name,
                         SERVICE_CHANGE_CONFIG | SERVICE_START);
  if (service == NULL) {
    CloseServiceHandle(manager);
    return 0;
  }
  ZeroMemory(&action, sizeof(action));
  action.Type = SC_ACTION_RESTART;
  action.Delay = 60000;
  ZeroMemory(&recovery, sizeof(recovery));
  recovery.dwResetPeriod = 86400;
  recovery.cActions = 1;
  recovery.lpsaActions = &action;
  flag.fFailureActionsOnNonCrashFailures = TRUE;
  if (ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &recovery) &&
      ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag) &&
      StartServiceW(service, 0, NULL)) {
    ok = 1;
  }
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}

static int edr_native_stop_delete_service(const wchar_t *service_name) {
  SC_HANDLE manager;
  SC_HANDLE service;
  SERVICE_STATUS_PROCESS status;
  DWORD bytes = 0;
  DWORD started = GetTickCount();
  int deleted = 0;

  if (!service_name || !service_name[0]) return 1;
  manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (manager == NULL) return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
  service = OpenServiceW(manager, service_name,
                         SERVICE_QUERY_STATUS | SERVICE_STOP |
                             SERVICE_CHANGE_CONFIG | DELETE);
  if (service == NULL) {
    DWORD error = GetLastError();
    CloseServiceHandle(manager);
    return error == ERROR_SERVICE_DOES_NOT_EXIST;
  }
  if (!edr_native_disable_service_recovery(service)) goto cleanup;
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&status, sizeof(status), &bytes)) goto cleanup;
  if (status.dwCurrentState != SERVICE_STOPPED) {
    SERVICE_STATUS ignored;
    ControlService(service, SERVICE_CONTROL_STOP, &ignored);
    do {
      Sleep(100);
      if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                (LPBYTE)&status, sizeof(status), &bytes)) goto cleanup;
      if (GetTickCount() - started > 30000) goto cleanup;
    } while (status.dwCurrentState != SERVICE_STOPPED);
  }
  if (!DeleteService(service)) goto cleanup;
  deleted = 1;
cleanup:
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!deleted) {
    edr_native_restore_service_and_start(service_name);
    return 0;
  }
  started = GetTickCount();
  for (;;) {
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL) return -1;
    service = OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
    if (service == NULL) {
      DWORD error = GetLastError();
      CloseServiceHandle(manager);
      if (error == ERROR_SERVICE_DOES_NOT_EXIST) return 1;
      if (error != ERROR_SERVICE_MARKED_FOR_DELETE || GetTickCount() - started > 30000) return -1;
      Sleep(100);
      continue;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (GetTickCount() - started > 30000) return -1;
    Sleep(100);
  }
}

static int edr_native_delete_tasks(void) {
  static const wchar_t *task_names[] = {
      L"FDSecurityAgent", L"EdrAgent", L"FDSecurityAgentUninstall"};
  ITaskService *task_service = NULL;
  ITaskFolder *root_folder = NULL;
  VARIANT empty;
  BSTR root_name = NULL;
  HRESULT hr;
  HRESULT init_hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
  int ok = 1;
  size_t index;

  if (FAILED(init_hr) && init_hr != RPC_E_CHANGED_MODE) return 0;
  hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                        &IID_ITaskService, (void **)&task_service);
  if (FAILED(hr)) {
    if (SUCCEEDED(init_hr)) CoUninitialize();
    return 0;
  }
  VariantInit(&empty);
  root_name = SysAllocString(L"\\");
  if (!root_name || FAILED(ITaskService_Connect(task_service, empty, empty, empty, empty)) ||
      FAILED(ITaskService_GetFolder(task_service, root_name, &root_folder))) {
    ok = 0;
    goto cleanup;
  }
  for (index = 0; index < sizeof(task_names) / sizeof(task_names[0]); ++index) {
    BSTR name = SysAllocString(task_names[index]);
    if (!name) {
      ok = 0;
      break;
    }
    hr = ITaskFolder_DeleteTask(root_folder, name, 0);
    SysFreeString(name);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) ok = 0;
  }
cleanup:
  if (root_name) SysFreeString(root_name);
  if (root_folder) ITaskFolder_Release(root_folder);
  if (task_service) ITaskService_Release(task_service);
  VariantClear(&empty);
  if (SUCCEEDED(init_hr)) CoUninitialize();
  return ok;
}

static int edr_native_validate_install_root(const wchar_t *install_dir) {
  wchar_t sensor[MAX_PATH_LONG];
  wchar_t config[MAX_PATH_LONG];
  wchar_t canonical[MAX_PATH_LONG];
  HANDLE root_handle = INVALID_HANDLE_VALUE;
  FILE_ATTRIBUTE_TAG_INFO tag_info;
  if (!install_dir || !install_dir[0] ||
      !edr_finalizer_canonical_path(install_dir, canonical,
                                    (DWORD)(sizeof(canonical) / sizeof(canonical[0])))) {
    return ERROR_INVALID_PARAMETER;
  }
  if (edr_finalizer_is_protected_root(canonical)) return ERROR_ACCESS_DENIED;
  root_handle = CreateFileW(install_dir, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            NULL);
  if (root_handle == INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandleEx(root_handle, FileAttributeTagInfo,
                                    &tag_info, sizeof(tag_info)) ||
      (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
    return ERROR_INVALID_REPARSE_DATA;
  }
  CloseHandle(root_handle);
  if (!join_path(sensor, sizeof(sensor) / sizeof(sensor[0]), install_dir, L"FDSensor.exe") ||
      !join_path(config, sizeof(config) / sizeof(config[0]), install_dir, L"agent.toml") ||
      !file_exists(sensor) || !file_exists(config)) {
    return ERROR_FILE_NOT_FOUND;
  }
  return ERROR_SUCCESS;
}

static int edr_native_run_etw_cleanup(const wchar_t *install_dir) {
  wchar_t sensor[MAX_PATH_LONG];
  if (!join_path(sensor, sizeof(sensor) / sizeof(sensor[0]), install_dir, L"FDSensor.exe")) {
    return ERROR_INSUFFICIENT_BUFFER;
  }
  return edr_native_run_process(sensor, L" --etw-uninstall-cleanup", install_dir, 30000);
}

static int edr_native_delete_install_root(const wchar_t *install_dir,
                                          wchar_t *failure_path,
                                          size_t failure_path_count) {
  DWORD error = ERROR_SUCCESS;
  if (failure_path && failure_path_count) failure_path[0] = L'\0';
  if (!edr_finalizer_safe_delete_tree(install_dir, &error,
                                      failure_path, failure_path_count)) {
    return (int)error;
  }
  return ERROR_SUCCESS;
}

static int edr_native_verify_removed(const wchar_t *install_dir,
                                     const wchar_t *service_name) {
  if (service_name && service_name[0]) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager != NULL) {
      SC_HANDLE service = OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
      if (service != NULL) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return ERROR_SERVICE_EXISTS;
      }
      if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
        CloseServiceHandle(manager);
        return ERROR_ACCESS_DENIED;
      }
      CloseServiceHandle(manager);
    }
  }
  if (GetFileAttributesW(install_dir) != INVALID_FILE_ATTRIBUTES) return ERROR_DIR_NOT_EMPTY;
  return ERROR_SUCCESS;
}

static int edr_native_prepare_state_directory(wchar_t *out, size_t out_count) {
  wchar_t common_data[MAX_PATH_LONG];
  wchar_t vendor_dir[MAX_PATH_LONG];
  DWORD result;

  if (!out || out_count == 0 ||
      SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT,
                       common_data) != S_OK ||
      !join_path(vendor_dir, sizeof(vendor_dir) / sizeof(vendor_dir[0]),
                 common_data, L"FDSecurity") ||
      !join_path(out, out_count, vendor_dir, L"state")) {
    return 0;
  }
  if (!CreateDirectoryW(vendor_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return 0;
  if (!CreateDirectoryW(out, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return 0;
  result = GetFileAttributesW(vendor_dir);
  if (result == INVALID_FILE_ATTRIBUTES || !(result & FILE_ATTRIBUTE_DIRECTORY) ||
      !edr_finalizer_protect_path(vendor_dir)) return 0;
  result = GetFileAttributesW(out);
  if (result == INVALID_FILE_ATTRIBUTES || !(result & FILE_ATTRIBUTE_DIRECTORY) ||
      !edr_finalizer_protect_path(out)) return 0;
  return 1;
}

static int edr_native_stop_sensor(const wchar_t *install_dir) {
  wchar_t sensor[MAX_PATH_LONG];
  wchar_t canonical_sensor[MAX_PATH_LONG];
  HANDLE snapshot;
  PROCESSENTRY32W entry;
  DWORD started = GetTickCount();

  if (!join_path(sensor, sizeof(sensor) / sizeof(sensor[0]), install_dir, L"FDSensor.exe") ||
      !edr_finalizer_canonical_path(sensor, canonical_sensor,
                                    (DWORD)(sizeof(canonical_sensor) / sizeof(canonical_sensor[0])))) {
    return ERROR_INVALID_PARAMETER;
  }
  snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return (int)GetLastError();
  ZeroMemory(&entry, sizeof(entry));
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      HANDLE process;
      wchar_t process_path[MAX_PATH_LONG];
      DWORD process_path_length = (DWORD)(sizeof(process_path) / sizeof(process_path[0]));
      wchar_t canonical_process[MAX_PATH_LONG];
      if (_wcsicmp(entry.szExeFile, L"FDSensor.exe") != 0) continue;
      process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE |
                                SYNCHRONIZE,
                            FALSE, entry.th32ProcessID);
      if (!process) {
        CloseHandle(snapshot);
        return ERROR_ACCESS_DENIED;
      }
      if (!QueryFullProcessImageNameW(process, 0, process_path, &process_path_length) ||
          !edr_finalizer_canonical_path(process_path, canonical_process,
                                        (DWORD)(sizeof(canonical_process) / sizeof(canonical_process[0])))) {
        CloseHandle(process);
        CloseHandle(snapshot);
        return ERROR_ACCESS_DENIED;
      }
      if (_wcsicmp(canonical_process, canonical_sensor) == 0) {
        if (!TerminateProcess(process, ERROR_CANCELLED) ||
            WaitForSingleObject(process, 5000) != WAIT_OBJECT_0) {
          CloseHandle(process);
          CloseHandle(snapshot);
          return ERROR_TIMEOUT;
        }
      }
      CloseHandle(process);
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  for (;;) {
    int process_state = edr_native_process_running_at_path(sensor);
    if (process_state < 0) return ERROR_ACCESS_DENIED;
    if (!process_state) break;
    if (GetTickCount() - started > 30000) return ERROR_TIMEOUT;
    Sleep(100);
  }
  return ERROR_SUCCESS;
}

static int edr_native_attestation_should_retry(DWORD error) {
  return error == 429 || error >= 500;
}

static DWORD edr_native_attestation_retry_delay_ms(DWORD error, int attempt) {
  if (error == 429) return 60000u;
  return 250u * (DWORD)(attempt + 1);
}

static int edr_native_attest(const wchar_t *url, const wchar_t *task_id,
                             const wchar_t *endpoint_id, const BYTE *token,
                             DWORD token_length, const char **failure_stage_out) {
  URL_COMPONENTSW components;
  wchar_t host[256];
  wchar_t path[2048];
  char task_utf8[256];
  char endpoint_utf8[256];
  char authorization[EDR_WINDOWS_HANDOFF_MAX_FRAME + 32];
  wchar_t request_headers[EDR_WINDOWS_HANDOFF_MAX_FRAME + 64];
  char body[2048];
  SYSTEMTIME now;
  int task_length;
  int endpoint_length;
  int body_length;
  int attempt;
  int is_https;
  HINTERNET session = NULL;
  HINTERNET connection = NULL;
  HINTERNET request = NULL;
  BOOL result = FALSE;
  DWORD last_error = ERROR_NETWORK_UNREACHABLE;

  if (failure_stage_out) *failure_stage_out = "attestation";

  if (!url || !url[0]) return ERROR_SUCCESS;
  if (!edr_native_valid_bearer_token(token, token_length) || !task_id || !endpoint_id) {
    if (failure_stage_out) *failure_stage_out = "attestation-input";
    return ERROR_INVALID_DATA;
  }
  if (!edr_native_crack_attestation_url(url, &components, host,
                                        sizeof(host) / sizeof(host[0]), path,
                                        sizeof(path) / sizeof(path[0]))) {
    if (failure_stage_out) *failure_stage_out = "attestation-url";
    return ERROR_INVALID_PARAMETER;
  }
  is_https = components.nScheme == INTERNET_SCHEME_HTTPS;
  task_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, task_id, -1,
                                    task_utf8, sizeof(task_utf8), NULL, NULL);
  endpoint_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, endpoint_id, -1,
                                    endpoint_utf8, sizeof(endpoint_utf8), NULL, NULL);
  if (!task_length || !endpoint_length) {
    if (failure_stage_out) *failure_stage_out = "attestation-encoding";
    return ERROR_INVALID_DATA;
  }
  {
    int written;
    written = _snprintf(authorization, sizeof(authorization),
                        "Authorization: Bearer %.*s\r\n", (int)token_length,
                        (const char *)token);
    if (written < 0 || (size_t)written >= sizeof(authorization)) {
      if (failure_stage_out) *failure_stage_out = "attestation-headers";
      return ERROR_INVALID_DATA;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, authorization, -1,
                            request_headers,
                            (int)(sizeof(request_headers) / sizeof(request_headers[0]))) <= 0) {
      SecureZeroMemory(authorization, sizeof(authorization));
      if (failure_stage_out) *failure_stage_out = "attestation-headers";
      return ERROR_INVALID_DATA;
    }
  }
  GetSystemTime(&now);
  body_length = _snprintf(body, sizeof(body),
                          "{\"schema\":\"edr.endpoint.uninstall.attestation.v1\","
                          "\"task_id\":\"%s\",\"endpoint_id\":\"%s\","
                          "\"service_removed\":true,\"process_stopped\":true,"
                          "\"install_dir_removed\":true,"
                          "\"completed_at\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\"}",
                          task_utf8, endpoint_utf8, now.wYear, now.wMonth, now.wDay,
                          now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
  if (body_length < 0 || (size_t)body_length >= sizeof(body)) {
    SecureZeroMemory(authorization, sizeof(authorization));
    SecureZeroMemory(request_headers, sizeof(request_headers));
    SecureZeroMemory(body, sizeof(body));
    if (failure_stage_out) *failure_stage_out = "attestation-body";
    return ERROR_INSUFFICIENT_BUFFER;
  }

  session = WinHttpOpen(L"FDSecurity-Agent-Uninstaller/1",
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session) {
    SecureZeroMemory(authorization, sizeof(authorization));
    SecureZeroMemory(request_headers, sizeof(request_headers));
    SecureZeroMemory(body, sizeof(body));
    if (failure_stage_out) *failure_stage_out = "attestation-session";
    return (int)edr_finalizer_last_error();
  }
  WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);
  for (attempt = 0; attempt < 3 && !result; ++attempt) {
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    request = NULL;
    connection = WinHttpConnect(session, host, components.nPort, 0);
    if (connection) {
      request = WinHttpOpenRequest(connection, L"POST", path, NULL,
                                   WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   is_https ? WINHTTP_FLAG_SECURE : 0);
    }
    if (!connection) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-connect";
    } else if (!request) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-request";
    } else if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                                 &redirect_policy, sizeof(redirect_policy)) ||
               !WinHttpAddRequestHeaders(request, L"Content-Type: application/json\r\n",
                                          (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) ||
               !WinHttpAddRequestHeaders(request, request_headers, (DWORD)-1L,
                                          WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-headers";
    } else if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   body, (DWORD)body_length, (DWORD)body_length, 0)) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-send";
    } else if (!WinHttpReceiveResponse(request, NULL)) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-response";
    } else if (!WinHttpQueryHeaders(request,
                                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                                    WINHTTP_NO_HEADER_INDEX)) {
      last_error = edr_finalizer_last_error();
      if (failure_stage_out) *failure_stage_out = "attestation-status";
    } else if (status >= 200 && status < 300) {
      result = TRUE;
    } else {
      /* Keep the HTTP status in the receipt/result instead of collapsing an
       * authenticated rejection or replay/expiry response into a network error. */
      last_error = status;
      if (failure_stage_out) *failure_stage_out = "attestation-http";
    }
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (!result && !edr_native_attestation_should_retry(last_error)) break;
    if (!result && attempt < 2) {
      Sleep(edr_native_attestation_retry_delay_ms(last_error, attempt));
    }
  }
  WinHttpCloseHandle(session);
  SecureZeroMemory(authorization, sizeof(authorization));
  SecureZeroMemory(request_headers, sizeof(request_headers));
  SecureZeroMemory(body, sizeof(body));
  return result ? ERROR_SUCCESS : (int)last_error;
}

static int edr_native_crack_attestation_url(const wchar_t *url,
                                            URL_COMPONENTSW *components,
                                            wchar_t *host, DWORD host_count,
                                            wchar_t *path, DWORD path_count) {
  if (!url || !url[0] || !components || !host || !path || !host_count || !path_count ||
      wcschr(url, L'#') != NULL) return 0;
  ZeroMemory(components, sizeof(*components));
  components->dwStructSize = sizeof(*components);
  components->lpszHostName = host;
  components->dwHostNameLength = host_count;
  components->lpszUrlPath = path;
  components->dwUrlPathLength = path_count;
  if (!WinHttpCrackUrl(url, 0, 0, components) || !host[0] || !path[0] ||
      components->nScheme != INTERNET_SCHEME_HTTPS || components->dwUserNameLength != 0 ||
      components->dwPasswordLength != 0 || components->dwUrlPathLength >= path_count ||
      components->dwHostNameLength >= host_count) return 0;
  return 1;
}

static int edr_native_valid_attestation_url(const wchar_t *url) {
  URL_COMPONENTSW components;
  wchar_t host[256];
  wchar_t path[2048];
  return edr_native_crack_attestation_url(url, &components, host,
                                          sizeof(host) / sizeof(host[0]), path,
                                          sizeof(path) / sizeof(path[0]));
}

static int edr_native_hex_value(wchar_t ch) {
  if (ch >= L'0' && ch <= L'9') return ch - L'0';
  if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
  if (ch >= L'A' && ch <= L'F') return ch - L'A' + 10;
  return -1;
}

static int edr_native_safe_identifier(const wchar_t *value) {
  const wchar_t *cursor;
  if (!value || !value[0] || wcslen(value) > 128) return 0;
  for (cursor = value; *cursor; ++cursor) {
    if (!((*cursor >= L'a' && *cursor <= L'z') ||
          (*cursor >= L'A' && *cursor <= L'Z') ||
          (*cursor >= L'0' && *cursor <= L'9') ||
          *cursor == L'-' || *cursor == L'_' || *cursor == L'.')) {
      return 0;
    }
  }
  return 1;
}

static int edr_native_valid_bearer_token(const BYTE *token, DWORD token_length) {
  DWORD index;
  if (!token || token_length < 32 || token_length > EDR_WINDOWS_HANDOFF_MAX_FRAME) return 0;
  for (index = 0; index < token_length; ++index) {
    if (token[index] < 0x21 || token[index] > 0x7e || token[index] == '\r' ||
        token[index] == '\n' || token[index] == '\0') return 0;
  }
  return 1;
}

static int edr_native_valid_thumbprint(const wchar_t *thumbprint) {
  size_t length;
  size_t index;
  if (!thumbprint) return 0;
  length = wcslen(thumbprint);
  if (length != 40 && length != 64) return 0;
  for (index = 0; index < length; ++index) {
    if (edr_native_hex_value(thumbprint[index]) < 0) return 0;
  }
  return 1;
}

static int edr_native_validate_certificate_identity(const wchar_t *install_dir,
                                                    const wchar_t *endpoint_id,
                                                    const wchar_t *thumbprint,
                                                    wchar_t *store_out,
                                                    size_t store_count) {
  wchar_t config_path[MAX_PATH_LONG];
  wchar_t config_endpoint[256];
  wchar_t config_thumbprint[129];
  if (!endpoint_id || !endpoint_id[0] || !thumbprint || !thumbprint[0] ||
      !store_out || store_count == 0 ||
      !join_path(config_path, sizeof(config_path) / sizeof(config_path[0]),
                 install_dir, L"agent.toml") ||
      !edr_native_read_toml_scalar(config_path, "endpoint_id", config_endpoint,
                                   sizeof(config_endpoint) / sizeof(config_endpoint[0])) ||
      !edr_native_read_toml_scalar(config_path, "client_cert_thumbprint",
                                   config_thumbprint,
                                   sizeof(config_thumbprint) / sizeof(config_thumbprint[0])) ||
      !edr_native_read_toml_scalar(config_path, "client_cert_store", store_out,
                                   store_count) ||
      !edr_native_valid_thumbprint(thumbprint) ||
      !edr_native_valid_thumbprint(config_thumbprint) ||
      _wcsicmp(config_endpoint, endpoint_id) != 0 ||
      _wcsicmp(config_thumbprint, thumbprint) != 0 ||
      (_wcsicmp(store_out, L"LocalMachine\\My") != 0 &&
       _wcsicmp(store_out, L"CurrentUser\\My") != 0)) {
    return 0;
  }
  return 1;
}

static void edr_native_write_failure_receipt(const wchar_t *self_path,
                                             const char *failure_stage, int error,
                                             const wchar_t *failure_path) {
  wchar_t receipt[MAX_PATH_LONG];
  wchar_t temporary[MAX_PATH_LONG];
  wchar_t directory[MAX_PATH_LONG];
  wchar_t *separator;
  SECURITY_ATTRIBUTES security;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  HANDLE file = INVALID_HANDLE_VALUE;
  char *content = NULL;
  char *path_utf8 = NULL;
  SIZE_T content_capacity = 128;
  int path_utf8_count = 0;
  int written;
  DWORD bytes_written = 0;
  int write_ok = 0;
  if (!self_path || !self_path[0] ||
      wcslen(self_path) >= sizeof(directory) / sizeof(directory[0])) {
    return;
  }
  if (!failure_stage || !failure_stage[0]) failure_stage = "finalizer";
  content_capacity += strlen(failure_stage);
  wcscpy(directory, self_path);
  separator = wcsrchr(directory, L'\\');
  if (!separator) return;
  *separator = L'\0';
  if (_snwprintf(receipt, sizeof(receipt) / sizeof(receipt[0]),
                 L"%ls\\last-native-uninstall-failure.receipt", directory) < 0 ||
      _snwprintf(temporary, sizeof(temporary) / sizeof(temporary[0]),
                 L"%ls\\last-native-uninstall-failure.receipt.tmp", directory) < 0) return;
  if (failure_path && failure_path[0]) {
    path_utf8_count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                          failure_path, -1, NULL, 0, NULL, NULL);
    if (path_utf8_count > 0) {
      path_utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)path_utf8_count);
      if (!path_utf8 ||
          WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, failure_path, -1,
                              path_utf8, path_utf8_count, NULL, NULL) != path_utf8_count) {
        if (path_utf8) HeapFree(GetProcessHeap(), 0, path_utf8);
        path_utf8 = NULL;
      } else {
        char *cursor;
        for (cursor = path_utf8; *cursor; ++cursor) {
          if (*cursor == '\r' || *cursor == '\n') *cursor = '?';
        }
        content_capacity += (SIZE_T)path_utf8_count + 6;
      }
    }
  }
  content = (char *)HeapAlloc(GetProcessHeap(), 0, content_capacity);
  if (!content) {
    if (path_utf8) HeapFree(GetProcessHeap(), 0, path_utf8);
    return;
  }
  if (!edr_finalizer_security_attributes(&security, &descriptor)) goto cleanup;
  file = CreateFileW(temporary, GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE) goto cleanup;
  written = path_utf8
                ? _snprintf(content, content_capacity,
                            "stage=%s\nerror=%d\npath=%s\n",
                            failure_stage, error, path_utf8)
                : _snprintf(content, content_capacity,
                            "stage=%s\nerror=%d\n", failure_stage, error);
  if (written > 0 && (SIZE_T)written < content_capacity &&
      WriteFile(file, content, (DWORD)written, &bytes_written, NULL) &&
      bytes_written == (DWORD)written) {
    write_ok = FlushFileBuffers(file) != FALSE;
  }
  CloseHandle(file);
  file = INVALID_HANDLE_VALUE;
  if (write_ok) {
    (void)MoveFileExW(temporary, receipt, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
  } else {
    DeleteFileW(temporary);
  }
cleanup:
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (content) {
    SecureZeroMemory(content, content_capacity);
    HeapFree(GetProcessHeap(), 0, content);
  }
  if (path_utf8) {
    SecureZeroMemory(path_utf8, (SIZE_T)path_utf8_count);
    HeapFree(GetProcessHeap(), 0, path_utf8);
  }
}

static void edr_native_clear_failure_receipt(const wchar_t *self_path) {
  wchar_t directory[MAX_PATH_LONG];
  wchar_t receipt[MAX_PATH_LONG];
  wchar_t *separator;
  DWORD error;
  if (!self_path || !self_path[0] ||
      wcslen(self_path) >= sizeof(directory) / sizeof(directory[0])) return;
  wcscpy(directory, self_path);
  separator = wcsrchr(directory, L'\\');
  if (!separator) return;
  *separator = L'\0';
  if (_snwprintf(receipt, sizeof(receipt) / sizeof(receipt[0]),
                 L"%ls\\last-native-uninstall-failure.receipt", directory) < 0) return;
  if (!DeleteFileW(receipt)) {
    error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
      OutputDebugStringW(L"native uninstall: failed to clear previous failure receipt\n");
    }
  }
}

static int edr_native_certificate_identity_action(const wchar_t *thumbprint,
                                                  const wchar_t *endpoint_id,
                                                  const wchar_t *store_name,
                                                  int remove_certificate) {
  BYTE hash[32];
  DWORD hash_length;
  size_t text_length;
  HCERTSTORE store = NULL;
  PCCERT_CONTEXT certificate = NULL;
  CRYPT_HASH_BLOB blob;
  DWORD index;
  int hash_value;
  DWORD find_type;
  DWORD store_location;
  int ok = 0;

  if (!edr_native_valid_thumbprint(thumbprint) || !endpoint_id || !endpoint_id[0] ||
      !store_name || !store_name[0]) return ERROR_INVALID_DATA;
  text_length = wcslen(thumbprint);
  find_type = CERT_FIND_SHA1_HASH;
  store_location = _wcsicmp(store_name, L"CurrentUser\\My") == 0
                       ? CERT_SYSTEM_STORE_CURRENT_USER
                       : CERT_SYSTEM_STORE_LOCAL_MACHINE;
  hash_length = (DWORD)(text_length / 2);
  for (index = 0; index < hash_length; ++index) {
    hash_value = edr_native_hex_value(thumbprint[index * 2]);
    if (hash_value < 0) return ERROR_INVALID_DATA;
    hash[index] = (BYTE)(hash_value << 4);
    hash_value = edr_native_hex_value(thumbprint[index * 2 + 1]);
    if (hash_value < 0) return ERROR_INVALID_DATA;
    hash[index] |= (BYTE)hash_value;
  }
  store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV_LEGACY)0,
                        store_location, L"My");
  if (!store) return (int)GetLastError();
  blob.cbData = hash_length;
  blob.pbData = hash;
  if (text_length == 40) {
    certificate = CertFindCertificateInStore(store,
                                             X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                             0, find_type, &blob, NULL);
  } else {
    PCCERT_CONTEXT candidate = NULL;
    while ((candidate = CertEnumCertificatesInStore(store, candidate)) != NULL) {
      BYTE sha256[32];
      DWORD sha256_size = sizeof(sha256);
      if (CertGetCertificateContextProperty(candidate, CERT_SHA256_HASH_PROP_ID,
                                            sha256, &sha256_size) &&
          sha256_size == sizeof(sha256) && memcmp(sha256, hash, sizeof(sha256)) == 0) {
        certificate = candidate;
        SecureZeroMemory(sha256, sizeof(sha256));
        break;
      }
      SecureZeroMemory(sha256, sizeof(sha256));
    }
  }
  if (!certificate) {
    ok = 0;
    goto cleanup;
  }
  {
    wchar_t friendly_name[256];
    DWORD name_length = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                           0, NULL, friendly_name,
                                           (DWORD)(sizeof(friendly_name) / sizeof(friendly_name[0])));
    if (!name_length || _wcsicmp(friendly_name, endpoint_id) != 0) goto cleanup;
  }
  if (!remove_certificate) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL must_free = FALSE;
    if (CryptAcquireCertificatePrivateKey(certificate,
                                          CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                              CRYPT_ACQUIRE_SILENT_FLAG,
                                          NULL, &key, &key_spec, &must_free)) {
      if (must_free) NCryptFreeObject((NCRYPT_HANDLE)key);
      ok = 1;
      goto cleanup;
    }
    {
      DWORD property_size = 0;
      PCRYPT_KEY_PROV_INFO property = NULL;
      HCRYPTPROV provider = 0;
      if (!CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID,
                                             NULL, &property_size) || !property_size) {
        goto cleanup;
      }
      property = (PCRYPT_KEY_PROV_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                 property_size);
      if (!property ||
          !CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID,
                                             property, &property_size) ||
          !CryptAcquireContextW(&provider, property->pwszContainerName,
                                property->pwszProvName, property->dwProvType,
                                property->dwFlags)) {
        if (property) HeapFree(GetProcessHeap(), 0, property);
        goto cleanup;
      }
      CryptReleaseContext(provider, 0);
      HeapFree(GetProcessHeap(), 0, property);
      ok = 1;
      goto cleanup;
    }
  }
  {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL must_free = FALSE;
    if (CryptAcquireCertificatePrivateKey(certificate,
                                          CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                              CRYPT_ACQUIRE_SILENT_FLAG,
                                          NULL, &key, &key_spec, &must_free)) {
      if (NCryptDeleteKey((NCRYPT_KEY_HANDLE)key, 0) != ERROR_SUCCESS) {
        if (must_free) NCryptFreeObject((NCRYPT_HANDLE)key);
        goto cleanup;
      }
      must_free = FALSE;
    } else {
      DWORD property_size = 0;
      if (!CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID,
                                             NULL, &property_size)) {
        if (GetLastError() != (DWORD)CRYPT_E_NOT_FOUND) goto cleanup;
      } else {
        PCRYPT_KEY_PROV_INFO property =
            (PCRYPT_KEY_PROV_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                            property_size);
        HCRYPTPROV provider = 0;
        if (!property ||
            !CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID,
                                               property, &property_size) ||
            !CryptAcquireContextW(&provider, property->pwszContainerName,
                                  property->pwszProvName, property->dwProvType,
                                  property->dwFlags | CRYPT_DELETEKEYSET)) {
          if (property) HeapFree(GetProcessHeap(), 0, property);
          goto cleanup;
        }
        if (provider) CryptReleaseContext(provider, 0);
        HeapFree(GetProcessHeap(), 0, property);
      }
    }
    if (must_free) NCryptFreeObject((NCRYPT_HANDLE)key);
  }
  ok = CertDeleteCertificateFromStore(certificate) ? 1 : 0;
  certificate = NULL;
cleanup:
  if (certificate) CertFreeCertificateContext(certificate);
  if (store) CertCloseStore(store, 0);
  SecureZeroMemory(hash, sizeof(hash));
  return ok ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

static int edr_native_preflight_certificate_identity(const wchar_t *thumbprint,
                                                     const wchar_t *endpoint_id,
                                                     const wchar_t *store_name) {
  return edr_native_certificate_identity_action(thumbprint, endpoint_id, store_name, 0);
}

static int edr_native_remove_certificate_identity(const wchar_t *thumbprint,
                                                  const wchar_t *endpoint_id,
                                                  const wchar_t *store_name) {
  return edr_native_certificate_identity_action(thumbprint, endpoint_id, store_name, 1);
}

static int edr_native_remove_registry_tree_64(const wchar_t *subkey) {
  HKEY key = NULL;
  LONG status;
  status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                         KEY_READ | KEY_WRITE | DELETE | KEY_WOW64_64KEY, &key);
  if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
  if (status != ERROR_SUCCESS) return (int)status;
  status = RegDeleteTreeW(key, NULL);
  RegCloseKey(key);
  if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) return (int)status;
  status = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, subkey, KEY_WOW64_64KEY, 0);
  if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
  return (int)status;
}

static int edr_native_remove_common_program_links(void) {
  wchar_t common_programs[MAX_PATH_LONG];
  wchar_t common_desktop[MAX_PATH_LONG];
  wchar_t program_link[MAX_PATH_LONG];
  wchar_t desktop_link[MAX_PATH_LONG];
  int result;

  if (SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, SHGFP_TYPE_CURRENT,
                       common_programs) != S_OK ||
      SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT,
                       common_desktop) != S_OK ||
      !join_path(program_link, sizeof(program_link) / sizeof(program_link[0]),
                 common_programs, L"FDSecurity.lnk") ||
      !join_path(desktop_link, sizeof(desktop_link) / sizeof(desktop_link[0]),
                 common_desktop, L"FDSecurity.lnk")) {
    return ERROR_PATH_NOT_FOUND;
  }
  if (!DeleteFileW(program_link)) {
    result = (int)GetLastError();
    if (result != ERROR_FILE_NOT_FOUND && result != ERROR_PATH_NOT_FOUND) return result;
  }
  if (!DeleteFileW(desktop_link)) {
    result = (int)GetLastError();
    if (result != ERROR_FILE_NOT_FOUND && result != ERROR_PATH_NOT_FOUND) return result;
  }
  return ERROR_SUCCESS;
}

static int edr_native_remove_registration(void) {
  static const wchar_t *environment_names[] = {
      L"EDR_GRPC_REQUIRE_MTLS", L"EDR_UPLOAD_FILE_RETRIES",
      L"EDR_UPLOAD_FILE_RETRY_BACKOFF_MS", L"EDR_FORENSIC_OUT",
      L"EDR_FORENSIC_COLLECTOR", L"EDR_FORENSIC_COLLECTOR_BIN",
      L"EDR_FORENSIC_COLLECTOR_BUILTIN_BIN", L"EDR_VELOCIRAPTOR_BIN",
      L"EDR_FORENSIC_VERSION_CHECK_SEC", L"EDR_FORENSIC_PREFETCH_RETRY_SEC",
      L"EDR_FORENSIC_COLLECTOR_AUTOFETCH", L"EDR_FORENSIC_ADAPTER_MANIFEST_URL",
      L"EDR_FORENSIC_COLLECTOR_MANIFEST_URL", L"EDR_CMD_AUDIT_PATH",
      L"EDR_SELF_PROTECT_PIDFILE", L"EDR_ISOLATE_STAMP_PATH",
      L"EDR_ISOLATE_HOOK", L"EDR_CMD_ENABLED"};
  HKEY environment = NULL;
  LONG status;
  size_t index;
  static const wchar_t *uninstall_keys[] = {
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FDSecurityAgentHeadless",
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}_is1"};

  status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                         0, KEY_SET_VALUE, &environment);
  if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) return (int)status;
  if (environment) {
    for (index = 0; index < sizeof(environment_names) / sizeof(environment_names[0]); ++index) {
      status = RegDeleteValueW(environment, environment_names[index]);
      if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        RegCloseKey(environment);
        return (int)status;
      }
    }
    RegCloseKey(environment);
  }
  for (index = 0; index < sizeof(uninstall_keys) / sizeof(uninstall_keys[0]); ++index) {
    status = (LONG)edr_native_remove_registry_tree_64(uninstall_keys[index]);
    if (status != ERROR_SUCCESS) return (int)status;
  }
  return edr_native_remove_common_program_links();
}

static int edr_native_finalizer(int argc, wchar_t **argv) {
  const wchar_t *install_dir = arg_value(argc, argv, L"--install-dir");
  const wchar_t *service_name = arg_value(argc, argv, L"--service-name");
  const wchar_t *attestation_url = arg_value(argc, argv, L"--attestation-url");
  const wchar_t *task_id = arg_value(argc, argv, L"--task-id");
  const wchar_t *endpoint_id = arg_value(argc, argv, L"--endpoint-id");
  const wchar_t *thumbprint = arg_value(argc, argv, L"--cert-thumbprint");
  const wchar_t *secret_text = arg_value(argc, argv, L"--secret-handle");
  const wchar_t *ack_text = arg_value(argc, argv, L"--ack-handle");
  const wchar_t *parent_text = arg_value(argc, argv, L"--parent-pid");
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE acknowledgement = INVALID_HANDLE_VALUE;
  BYTE token[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD token_length = 0;
  wchar_t self_path[MAX_PATH_LONG];
  wchar_t certificate_store[64];
  DWORD self_length;
  int result = ERROR_GEN_FAILURE;
  int service_touched = 0;
  int service_deleted = 0;
  int remote_requested = 0;
  int local_handoff = 0;
  int certificate_configured = 0;
  int handoff_acknowledged = 0;
  int self_delete_attempted = 0;
  DWORD self_delete_error = ERROR_SUCCESS;
  const char *failure_stage = "preflight";
  const char *attestation_failure_stage = "attestation";
  DWORD parent_pid = 0;
  HANDLE parent_handle = NULL;
  wchar_t *failure_path = NULL;
  static const BYTE ready[] = "edr.finalizer.ready.v1";

  ZeroMemory(token, sizeof(token));
  self_path[0] = L'\0';
  certificate_store[0] = L'\0';
  if (!install_dir || !install_dir[0] || !service_name || !service_name[0] ||
      !edr_finalizer_parse_handle(secret_text, &secret_read) ||
      !edr_finalizer_parse_handle(ack_text, &acknowledgement) ||
      edr_native_validate_install_root(install_dir) != ERROR_SUCCESS ||
      !edr_windows_handoff_read_frame(secret_read, token, sizeof(token), &token_length)) {
      goto cleanup;
  }
  local_handoff = edr_native_is_local_handoff_marker(token, token_length);
  if (local_handoff) {
    /* A marker is valid only for the no-attestation local path. */
    if ((attestation_url && attestation_url[0]) || (task_id && task_id[0])) {
      goto cleanup;
    }
    SecureZeroMemory(token, sizeof(token));
    token_length = 0;
  }
  remote_requested = !local_handoff && ((attestation_url && attestation_url[0]) ||
                                         (task_id && task_id[0]) ||
                                         token_length != 0);
  if (remote_requested) {
    if (!attestation_url || !edr_native_valid_attestation_url(attestation_url) ||
        !task_id || !edr_native_safe_identifier(task_id) ||
        !endpoint_id || !edr_native_safe_identifier(endpoint_id) ||
        !edr_native_valid_bearer_token(token, token_length) ||
        !thumbprint || !thumbprint[0]) {
      goto cleanup;
    }
  } else if (!local_handoff || !endpoint_id || !edr_native_safe_identifier(endpoint_id)) {
    goto cleanup;
  }
  /* Local administrators may remove an unenrolled install. Remote uninstall
     required a valid certificate thumbprint above. */
  certificate_configured = thumbprint && thumbprint[0];
  if (certificate_configured) {
    failure_stage = "certificate-preflight";
    if (!edr_native_validate_certificate_identity(install_dir, endpoint_id, thumbprint,
                                                  certificate_store,
                                                  sizeof(certificate_store) /
                                                      sizeof(certificate_store[0]))) {
      result = ERROR_INVALID_DATA;
      goto cleanup;
    }
    result = edr_native_preflight_certificate_identity(thumbprint, endpoint_id,
                                                       certificate_store);
    if (result != ERROR_SUCCESS) goto cleanup;
  }
  if (parent_text && parent_text[0]) {
    wchar_t *end = NULL;
    unsigned long parsed = wcstoul(parent_text, &end, 10);
    if (!end || *end || parsed == 0 || parsed > 0xffffffffUL) goto cleanup;
    parent_pid = (DWORD)parsed;
  } else {
    goto cleanup;
  }
  result = edr_native_validate_package_shape(install_dir);
  if (result != ERROR_SUCCESS) goto cleanup;
  parent_handle = OpenProcess(SYNCHRONIZE, FALSE, parent_pid);
  if (!parent_handle) {
    result = (int)edr_finalizer_last_error();
    goto cleanup;
  }
  CloseHandle(secret_read);
  secret_read = INVALID_HANDLE_VALUE;
  if (!edr_windows_handoff_write_frame(acknowledgement, ready, sizeof(ready) - 1)) goto cleanup;
  CloseHandle(acknowledgement);
  acknowledgement = INVALID_HANDLE_VALUE;
  handoff_acknowledged = 1;
  /* The remote Agent owns command-result delivery and normally remains alive
     until SCM stops it below.  Treat this bounded wait as a delivery window,
     not as proof that uninstall failed.  A real wait error still fails closed. */
  failure_stage = "wait-command-delivery-window";
  result = edr_native_wait_for_parent_delivery_window(parent_handle, 30000);
  CloseHandle(parent_handle);
  parent_handle = NULL;
  if (result != ERROR_SUCCESS) goto cleanup;
  failure_stage = "delete-tasks";
  if (!edr_native_delete_tasks()) {
    result = ERROR_ACCESS_DENIED;
    goto recovery;
  }
  {
    int service_result;
    failure_stage = "delete-service";
    service_touched = 1;
    service_result = edr_native_stop_delete_service(service_name);
    if (service_result < 0) {
      service_deleted = 1;
      result = ERROR_TIMEOUT;
      goto cleanup;
    }
    if (service_result == 0) {
      result = ERROR_SERVICE_NOT_ACTIVE;
      goto recovery;
    }
  }
  service_deleted = 1;
  failure_stage = "stop-sensor";
  result = edr_native_stop_sensor(install_dir);
  if (result != ERROR_SUCCESS) goto cleanup;
  failure_stage = "etw-cleanup";
  result = edr_native_run_etw_cleanup(install_dir);
  if (result != ERROR_SUCCESS) goto cleanup;
  failure_stage = "remove-registration";
  result = edr_native_remove_registration();
  if (result != ERROR_SUCCESS) goto cleanup;
  failure_path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      MAX_PATH_LONG * sizeof(wchar_t));
  if (!failure_path) {
    result = ERROR_NOT_ENOUGH_MEMORY;
    goto cleanup;
  }
  failure_stage = "remove-install-root";
  result = edr_native_delete_install_root(install_dir, failure_path, MAX_PATH_LONG);
  if (result != ERROR_SUCCESS) goto cleanup;
  failure_stage = "verify-removed";
  result = edr_native_verify_removed(install_dir, service_name);
  if (result != ERROR_SUCCESS) goto cleanup;
  if (certificate_configured) {
    failure_stage = "remove-certificate";
    result = edr_native_remove_certificate_identity(thumbprint, endpoint_id,
                                                    certificate_store);
    if (result != ERROR_SUCCESS) goto cleanup;
  }
  self_length = GetModuleFileNameW(NULL, self_path,
                                   (DWORD)(sizeof(self_path) / sizeof(self_path[0])));
  if (!self_length || self_length >= sizeof(self_path) / sizeof(self_path[0])) {
    result = ERROR_FILE_NOT_FOUND;
    goto cleanup;
  }
  failure_stage = "self-delete";
  self_delete_error = edr_native_unlink_self(self_path);
  self_delete_attempted = 1;
  if (self_delete_error != ERROR_SUCCESS) {
    /* The finalizer is already outside the verified package tree. A locked
     * image must not prevent proof of the completed service/process/tree
     * teardown; retain a durable receipt and request reboot cleanup. */
    edr_native_write_failure_receipt(self_path, "self-delete", (int)self_delete_error, NULL);
    DWORD deferred_result = edr_finalizer_schedule_self_delete(self_path);
    if (deferred_result != ERROR_SUCCESS &&
        deferred_result != ERROR_SUCCESS_REBOOT_REQUIRED) {
      DWORD deferred_error = deferred_result;
      edr_native_write_failure_receipt(self_path, "self-delete-schedule",
                                       (int)deferred_error, NULL);
    }
  }
  if (local_handoff) {
    /* Local uninstall has no attestation endpoint or bearer token. */
    if (self_delete_error == ERROR_SUCCESS) edr_native_clear_failure_receipt(self_path);
    result = ERROR_SUCCESS;
    goto cleanup;
  }
  failure_stage = "attestation";
  result = edr_native_attest(attestation_url, task_id, endpoint_id, token, token_length,
                             &attestation_failure_stage);
  if (result != ERROR_SUCCESS) failure_stage = attestation_failure_stage;
  if (result == ERROR_SUCCESS && self_delete_error == ERROR_SUCCESS) {
    edr_native_clear_failure_receipt(self_path);
  }
  goto cleanup;
recovery:
  if (service_touched && !service_deleted) {
    edr_native_restore_service_and_start(service_name);
  }
cleanup:
  if (handoff_acknowledged) {
    self_length = GetModuleFileNameW(NULL, self_path,
                                     (DWORD)(sizeof(self_path) / sizeof(self_path[0])));
    if (self_length && self_length < sizeof(self_path) / sizeof(self_path[0])) {
      if (result != ERROR_SUCCESS) {
        edr_native_write_failure_receipt(self_path, failure_stage, result, failure_path);
      }
      if (!self_delete_attempted) (void)edr_finalizer_schedule_self_delete(self_path);
    }
  }
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (acknowledgement != INVALID_HANDLE_VALUE) CloseHandle(acknowledgement);
  if (parent_handle) CloseHandle(parent_handle);
  if (failure_path) HeapFree(GetProcessHeap(), 0, failure_path);
  SecureZeroMemory(token, sizeof(token));
  return result;
}

static int edr_native_build_finalizer_command(wchar_t *command, size_t command_count,
                                              const wchar_t *target,
                                              const wchar_t *install_dir,
                                              const wchar_t *service_name,
                                              const wchar_t *attestation_url,
                                              const wchar_t *task_id,
                                              const wchar_t *endpoint_id,
                                              const wchar_t *thumbprint,
                                              HANDLE secret_read, HANDLE ack_write,
                                              DWORD parent_pid) {
  size_t used = 0;
  wchar_t handle_text[64];
  if (!append_quoted_arg(command, command_count, &used, target) ||
      !append_text(command, command_count, &used, L" --native-finalizer --install-dir ") ||
      !append_quoted_arg(command, command_count, &used, install_dir) ||
      !append_text(command, command_count, &used, L" --service-name ") ||
      !append_quoted_arg(command, command_count, &used, service_name) ||
      !append_text(command, command_count, &used, L" --task-id ") ||
      !append_quoted_arg(command, command_count, &used, task_id ? task_id : L"") ||
      !append_text(command, command_count, &used, L" --endpoint-id ") ||
      !append_quoted_arg(command, command_count, &used, endpoint_id ? endpoint_id : L"") ||
      !append_text(command, command_count, &used, L" --attestation-url ") ||
      !append_quoted_arg(command, command_count, &used, attestation_url ? attestation_url : L"") ||
      !append_text(command, command_count, &used, L" --secret-handle ")) {
    return 0;
  }
  _snwprintf(handle_text, sizeof(handle_text) / sizeof(handle_text[0]),
             L"%llu", (unsigned long long)(ULONG_PTR)secret_read);
  if (!append_text(command, command_count, &used, handle_text) ||
      !append_text(command, command_count, &used, L" --ack-handle ")) return 0;
  _snwprintf(handle_text, sizeof(handle_text) / sizeof(handle_text[0]),
             L"%llu", (unsigned long long)(ULONG_PTR)ack_write);
  if (!append_text(command, command_count, &used, handle_text) ||
      !append_text(command, command_count, &used, L" --parent-pid ")) return 0;
  _snwprintf(handle_text, sizeof(handle_text) / sizeof(handle_text[0]),
             L"%lu", (unsigned long)parent_pid);
  if (!append_text(command, command_count, &used, handle_text)) return 0;
  if (thumbprint && thumbprint[0]) {
    if (!append_text(command, command_count, &used, L" --cert-thumbprint ") ||
        !append_quoted_arg(command, command_count, &used, thumbprint)) return 0;
  }
  return 1;
}

static int edr_native_coordinator(int argc, wchar_t **argv) {
  const wchar_t *install_dir = arg_value(argc, argv, L"--install-dir");
  const wchar_t *service_name = arg_value(argc, argv, L"--service-name");
  const wchar_t *attestation_url = arg_value(argc, argv, L"--attestation-url");
  const wchar_t *task_id = arg_value(argc, argv, L"--task-id");
  const wchar_t *endpoint_id = arg_value(argc, argv, L"--endpoint-id");
  const wchar_t *thumbprint = arg_value(argc, argv, L"--cert-thumbprint");
  const wchar_t *input_secret_text = arg_value(argc, argv, L"--secret-read-handle");
  const wchar_t *external_ack_text = arg_value(argc, argv, L"--ack-write-handle");
  const wchar_t *upstream_parent_text = arg_value(argc, argv, L"--parent-pid");
  wchar_t configured_endpoint[129];
  wchar_t configured_thumbprint[129];
  wchar_t configured_config[MAX_PATH_LONG];
  wchar_t derived_install_dir[MAX_PATH_LONG];
  wchar_t module_path[MAX_PATH_LONG];
  wchar_t source[MAX_PATH_LONG];
  wchar_t state_dir[MAX_PATH_LONG];
  wchar_t finalizer[MAX_PATH_LONG];
  wchar_t command[32768];
  DWORD source_length;
  BYTE token[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD token_length = 0;
  HANDLE input_secret = INVALID_HANDLE_VALUE;
  HANDLE external_ack = INVALID_HANDLE_VALUE;
  HANDLE upstream_parent = NULL;
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE secret_write = INVALID_HANDLE_VALUE;
  HANDLE ack_read = INVALID_HANDLE_VALUE;
  HANDLE ack_write = INVALID_HANDLE_VALUE;
  HANDLE handles[2];
  EdrWindowsSpawnLock spawn_lock = { 0 };
  PROCESS_INFORMATION process;
  SECURITY_ATTRIBUTES pipe_security;
  EdrFinalizerHandoff handoff;
  int result = ERROR_GEN_FAILURE;
  int launched = 0;
  int handoff_accepted = 0;
  int remote_requested;
  DWORD upstream_parent_pid = GetCurrentProcessId();
  const BYTE *handoff_secret;
  DWORD handoff_secret_length;

  ZeroMemory(token, sizeof(token));
  ZeroMemory(&process, sizeof(process));
  ZeroMemory(&handoff, sizeof(handoff));
  finalizer[0] = L'\0';
  state_dir[0] = L'\0';
  handoff.secret_write = INVALID_HANDLE_VALUE;
  handoff.ack_read = INVALID_HANDLE_VALUE;
  remote_requested = (attestation_url && attestation_url[0]) ||
                     (task_id && task_id[0]) ||
                     (input_secret_text && input_secret_text[0]) ||
                     (upstream_parent_text && upstream_parent_text[0]);
  configured_endpoint[0] = L'\0';
  configured_thumbprint[0] = L'\0';
  configured_config[0] = L'\0';
  derived_install_dir[0] = L'\0';
  module_path[0] = L'\0';
  if (!install_dir || !install_dir[0]) {
    DWORD module_length = GetModuleFileNameW(NULL, module_path,
                                              (DWORD)(sizeof(module_path) / sizeof(module_path[0])));
    wchar_t *slash = module_length ? wcsrchr(module_path, L'\\') : NULL;
    if (!module_length || module_length >= sizeof(module_path) / sizeof(module_path[0]) ||
        !slash || slash == module_path) goto cleanup;
    *slash = L'\0';
    if (wcslen(module_path) >= sizeof(derived_install_dir) / sizeof(derived_install_dir[0])) {
      goto cleanup;
    }
    wcscpy(derived_install_dir, module_path);
    install_dir = derived_install_dir;
  }
  if (!service_name || !service_name[0]) service_name = L"FDSecurityAgent";
  if (join_path(configured_config, sizeof(configured_config) / sizeof(configured_config[0]),
                install_dir, L"agent.toml")) {
    (void)edr_native_read_toml_scalar(configured_config, "endpoint_id",
                                      configured_endpoint,
                                      sizeof(configured_endpoint) / sizeof(configured_endpoint[0]));
    (void)edr_native_read_toml_scalar(configured_config, "client_cert_thumbprint",
                                      configured_thumbprint,
                                      sizeof(configured_thumbprint) / sizeof(configured_thumbprint[0]));
  }
  if (!endpoint_id || !endpoint_id[0]) endpoint_id = configured_endpoint;
  if (!thumbprint || !thumbprint[0]) thumbprint = configured_thumbprint;
  if (upstream_parent_text && upstream_parent_text[0]) {
    wchar_t *end = NULL;
    unsigned long parsed = wcstoul(upstream_parent_text, &end, 10);
    if (!end || *end || parsed == 0 || parsed > 0xffffffffUL) goto cleanup;
    upstream_parent_pid = (DWORD)parsed;
    upstream_parent = OpenProcess(SYNCHRONIZE, FALSE, upstream_parent_pid);
    if (!upstream_parent) goto cleanup;
  }
  source_length = GetModuleFileNameW(NULL, source,
                                     (DWORD)(sizeof(source) / sizeof(source[0])));
  if (!install_dir || !install_dir[0] || !service_name || !service_name[0] ||
      !endpoint_id ||
      !edr_native_safe_identifier(endpoint_id) ||
      (remote_requested && (!attestation_url || !edr_native_valid_attestation_url(attestation_url) ||
                             !task_id || !edr_native_safe_identifier(task_id) ||
                             !endpoint_id || !edr_native_safe_identifier(endpoint_id) ||
                             !thumbprint || !thumbprint[0] ||
                             !input_secret_text || !input_secret_text[0])) ||
      (!remote_requested && ((attestation_url && attestation_url[0]) ||
                             (task_id && task_id[0]))) ||
      edr_native_validate_install_root(install_dir) != ERROR_SUCCESS ||
      !source_length || source_length >= sizeof(source) / sizeof(source[0]) ||
      !edr_native_prepare_state_directory(state_dir, sizeof(state_dir) / sizeof(state_dir[0])) ||
      !edr_finalizer_unique_name(finalizer, sizeof(finalizer) / sizeof(finalizer[0]), state_dir) ||
      !edr_finalizer_copy_verified(source, finalizer)) {
    goto cleanup;
  }
  if (input_secret_text && input_secret_text[0]) {
    if (!edr_finalizer_parse_handle(input_secret_text, &input_secret) ||
        !edr_windows_handoff_read_frame(input_secret, token, sizeof(token), &token_length)) goto cleanup;
    CloseHandle(input_secret);
    input_secret = INVALID_HANDLE_VALUE;
  }
  if (remote_requested) {
    handoff_secret = token;
    handoff_secret_length = token_length;
  } else {
    handoff_secret = EDR_LOCAL_HANDOFF_MARKER;
    handoff_secret_length = sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1;
  }
  if (external_ack_text && external_ack_text[0] &&
      !edr_finalizer_parse_handle(external_ack_text, &external_ack)) goto cleanup;
  ZeroMemory(&pipe_security, sizeof(pipe_security));
  pipe_security.nLength = sizeof(pipe_security);
  pipe_security.bInheritHandle = FALSE;
  if (!edr_windows_spawn_lock_acquire(&spawn_lock) ||
      !CreatePipe(&secret_read, &secret_write, &pipe_security, 0) ||
      !CreatePipe(&ack_read, &ack_write, &pipe_security, 0) ||
      !edr_native_build_finalizer_command(command, sizeof(command) / sizeof(command[0]),
                                          finalizer, install_dir, service_name,
                                          attestation_url, task_id, endpoint_id, thumbprint,
                                          secret_read, ack_write, upstream_parent_pid)) goto cleanup;
  handles[0] = secret_read;
  handles[1] = ack_write;
  if (!edr_windows_spawn_whitelisted(command, state_dir, handles, 2, &process,
                                     child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS))) goto cleanup;
  edr_windows_spawn_lock_release(&spawn_lock);
  launched = 1;
  CloseHandle(secret_read);
  secret_read = INVALID_HANDLE_VALUE;
  CloseHandle(ack_write);
  ack_write = INVALID_HANDLE_VALUE;
  handoff.secret_write = secret_write;
  handoff.ack_read = ack_read;
  secret_write = INVALID_HANDLE_VALUE;
  ack_read = INVALID_HANDLE_VALUE;
  if (!edr_finalizer_exchange_ready(&handoff, handoff_secret, handoff_secret_length)) {
    DWORD wait_result = WaitForSingleObject(process.hProcess, EDR_FINALIZER_IO_TIMEOUT_MS);
    DWORD finalizer_exit = STILL_ACTIVE;
    if (wait_result == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, &finalizer_exit) &&
        finalizer_exit != STILL_ACTIVE) {
      result = (int)finalizer_exit;
    } else if (wait_result == WAIT_TIMEOUT) {
      result = ERROR_TIMEOUT;
    } else {
      result = ERROR_BROKEN_PIPE;
    }
    goto cleanup;
  }
  SecureZeroMemory(token, sizeof(token));
  if (external_ack != INVALID_HANDLE_VALUE) {
    static const BYTE coordinator_ready[] = "edr.finalizer.ready.v1";
    if (!edr_windows_handoff_write_frame(external_ack, coordinator_ready,
                                         sizeof(coordinator_ready) - 1)) goto cleanup;
    CloseHandle(external_ack);
    external_ack = INVALID_HANDLE_VALUE;
  }
  handoff_accepted = 1;
  result = ERROR_SUCCESS;
cleanup:
  edr_windows_spawn_lock_release(&spawn_lock);
  if (process.hProcess && launched && !handoff_accepted) {
    DWORD process_exit = STILL_ACTIVE;
    if (GetExitCodeProcess(process.hProcess, &process_exit) && process_exit == STILL_ACTIVE) {
      TerminateProcess(process.hProcess, ERROR_CANCELLED);
      WaitForSingleObject(process.hProcess, 5000);
    }
  }
  if (process.hThread) CloseHandle(process.hThread);
  if (process.hProcess) CloseHandle(process.hProcess);
  if (input_secret != INVALID_HANDLE_VALUE) CloseHandle(input_secret);
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (secret_write != INVALID_HANDLE_VALUE) CloseHandle(secret_write);
  if (ack_read != INVALID_HANDLE_VALUE) CloseHandle(ack_read);
  if (ack_write != INVALID_HANDLE_VALUE) CloseHandle(ack_write);
  if (external_ack != INVALID_HANDLE_VALUE) CloseHandle(external_ack);
  if (upstream_parent) CloseHandle(upstream_parent);
  if (handoff.secret_write != INVALID_HANDLE_VALUE) CloseHandle(handoff.secret_write);
  if (handoff.ack_read != INVALID_HANDLE_VALUE) CloseHandle(handoff.ack_read);
  if (finalizer[0] && !handoff_accepted) DeleteFileW(finalizer);
  SecureZeroMemory(token, sizeof(token));
  return result;
}

static int write_capability_probe(const wchar_t *path, const char *payload) {
  HANDLE file;
  DWORD written = 0;
  size_t length;
  if (!path || !path[0] || !payload) return 0;
  file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;
  length = strlen(payload);
  if (!WriteFile(file, payload, (DWORD)length, &written, NULL) || written != (DWORD)length) {
    CloseHandle(file);
    return 0;
  }
  CloseHandle(file);
  return 1;
}

static int file_exists(const wchar_t *path) {
  DWORD attrs = GetFileAttributesW(path);
  return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int edr_native_process_is_elevated(void) {
  HANDLE token = NULL;
  TOKEN_ELEVATION elevation;
  DWORD size = 0;
  int elevated = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
  if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
    elevated = elevation.TokenIsElevated != 0;
  }
  CloseHandle(token);
  return elevated;
}

static int edr_native_relaunch_elevated(PWSTR command_line) {
  wchar_t module_path[MAX_PATH_LONG];
  SHELLEXECUTEINFOW execute;
  DWORD length = GetModuleFileNameW(NULL, module_path,
                                    (DWORD)(sizeof(module_path) / sizeof(module_path[0])));
  if (!length || length >= sizeof(module_path) / sizeof(module_path[0])) return 0;
  ZeroMemory(&execute, sizeof(execute));
  execute.cbSize = sizeof(execute);
  execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  execute.lpVerb = L"runas";
  execute.lpFile = module_path;
  execute.lpParameters = command_line;
  execute.nShow = SW_HIDE;
  if (!ShellExecuteExW(&execute)) return 0;
  if (execute.hProcess) CloseHandle(execute.hProcess);
  return 1;
}

static int join_path(wchar_t *out, size_t out_count, const wchar_t *dir, const wchar_t *name) {
  int written;
  size_t len;
  if (!out || !dir || !name || out_count < 2) return 0;
  len = wcslen(dir);
  written = _snwprintf(out, out_count, len > 0 && (dir[len - 1] == L'\\' || dir[len - 1] == L'/')
                                              ? L"%ls%ls"
                                              : L"%ls\\%ls",
                       dir, name);
  if (written < 0 || (size_t)written >= out_count) {
    out[out_count - 1] = L'\0';
    return 0;
  }
  return 1;
}

static int append_text(wchar_t *out, size_t out_count, size_t *used, const wchar_t *text) {
  size_t n;
  if (!out || !used || !text) return 0;
  n = wcslen(text);
  if (*used + n + 1 > out_count) return 0;
  memcpy(out + *used, text, n * sizeof(wchar_t));
  *used += n;
  out[*used] = L'\0';
  return 1;
}

/* Quote one argument using the CommandLineToArgvW escaping rules. */
static int append_quoted_arg(wchar_t *out, size_t out_count, size_t *used, const wchar_t *arg) {
  size_t backslashes = 0;
  const wchar_t *p;
  if (!append_text(out, out_count, used, L"\"")) return 0;
  for (p = arg; ; ++p) {
    if (*p == L'\\') {
      ++backslashes;
      continue;
    }
    if (*p == L'\"') {
      while (backslashes > 0) {
        if (!append_text(out, out_count, used, L"\\\\")) return 0;
        --backslashes;
      }
      if (!append_text(out, out_count, used, L"\\\"")) return 0;
      continue;
    }
    if (*p == L'\0') {
      while (backslashes > 0) {
        if (!append_text(out, out_count, used, L"\\\\")) return 0;
        --backslashes;
      }
      break;
    }
    while (backslashes > 0) {
      if (!append_text(out, out_count, used, L"\\")) return 0;
      --backslashes;
    }
    {
      wchar_t one[2] = {*p, L'\0'};
      if (!append_text(out, out_count, used, one)) return 0;
    }
  }
  return append_text(out, out_count, used, L"\"");
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command) {
  int argc = 0;
  wchar_t **argv;
  int rc;
  (void)instance;
  (void)previous;
  (void)command_line;
  (void)show_command;
  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv) return (int)GetLastError();
  {
    const wchar_t *capability_probe = arg_value(argc, argv, L"--capability-probe");
    if (capability_probe && capability_probe[0]) {
      int probe_ok = write_capability_probe(capability_probe, HEADLESS_UNINSTALLER_CAPABILITIES);
      LocalFree(argv);
      return probe_ok ? 0 : ERROR_WRITE_FAULT;
    }
  }
  if (has_flag(argc, argv, L"--keep-data") || has_flag(argc, argv, L"/KEEPDATA")) {
    fwprintf(stderr, L"KEEPDATA is unsupported; complete uninstall is the only supported path.\n");
    rc = ERROR_NOT_SUPPORTED;
  } else if (has_flag(argc, argv, L"--native-finalizer")) {
    rc = edr_native_finalizer(argc, argv);
  } else {
    if (!arg_value(argc, argv, L"--secret-read-handle")[0] &&
        !arg_value(argc, argv, L"--parent-pid")[0] &&
        !edr_native_process_is_elevated()) {
      rc = edr_native_relaunch_elevated(command_line) ? ERROR_SUCCESS : (int)GetLastError();
    } else {
      rc = edr_native_coordinator(argc, argv);
    }
  }
  LocalFree(argv);
  return rc;
}
