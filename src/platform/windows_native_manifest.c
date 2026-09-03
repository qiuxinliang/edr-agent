#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "edr/sha256.h"
#include "edr/windows_native_manifest.h"

#define EDR_NATIVE_MANIFEST_MAX (1024u * 1024u)
#define EDR_NATIVE_PATH_MAX 32768u
#define EDR_NATIVE_NAME_MAX 128u

static int manifest_hex_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

int edr_windows_native_manifest_name_safe(const char *name) {
  const char *dot;
  size_t length;
  size_t base_length;
  if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
  length = strlen(name);
  if (length > EDR_NATIVE_NAME_MAX) return 0;
  if (name[length - 1] == '.' || name[length - 1] == ' ') return 0;
  for (size_t i = 0; i < length; ++i) {
    unsigned char ch = (unsigned char)name[i];
    if (ch < 0x20 || ch == 0x7f || ch == '/' || ch == '\\' || ch == ':' ||
        ch == '"' || ch == '<' || ch == '>' || ch == '|' || ch == '?' || ch == '*') return 0;
  }
  dot = strchr(name, '.');
  base_length = dot ? (size_t)(dot - name) : length;
  while (base_length && (name[base_length - 1] == '.' || name[base_length - 1] == ' ')) {
    --base_length;
  }
  if ((base_length == 3 && (!_strnicmp(name, "CON", 3) ||
                           !_strnicmp(name, "PRN", 3) ||
                           !_strnicmp(name, "AUX", 3) ||
                           !_strnicmp(name, "NUL", 3))) ||
      (base_length == 6 && !_strnicmp(name, "CLOCK$", 6))) return 0;
  if (base_length == 4 && (!_strnicmp(name, "COM1", 4) ||
                          !_strnicmp(name, "COM2", 4) ||
                          !_strnicmp(name, "COM3", 4) ||
                          !_strnicmp(name, "COM4", 4) ||
                          !_strnicmp(name, "COM5", 4) ||
                          !_strnicmp(name, "COM6", 4) ||
                          !_strnicmp(name, "COM7", 4) ||
                          !_strnicmp(name, "COM8", 4) ||
                          !_strnicmp(name, "COM9", 4) ||
                          !_strnicmp(name, "LPT1", 4) ||
                          !_strnicmp(name, "LPT2", 4) ||
                          !_strnicmp(name, "LPT3", 4) ||
                          !_strnicmp(name, "LPT4", 4) ||
                          !_strnicmp(name, "LPT5", 4) ||
                          !_strnicmp(name, "LPT6", 4) ||
                          !_strnicmp(name, "LPT7", 4) ||
                          !_strnicmp(name, "LPT8", 4) ||
                          !_strnicmp(name, "LPT9", 4))) return 0;
  return 1;
}

static int manifest_unique_keys(cJSON *object, const char *const *allowed,
                                size_t allowed_count) {
  cJSON *item;
  if (!object || !cJSON_IsObject(object)) return 0;
  for (item = object->child; item; item = item->next) {
    int allowed_key = 0;
    for (size_t index = 0; index < allowed_count; ++index) {
      if (item->string && strcmp(item->string, allowed[index]) == 0) {
        allowed_key = 1;
        break;
      }
    }
    if (!allowed_key) return 0;
    for (cJSON *other = item->next; other; other = other->next) {
      if (item->string && other->string && strcmp(item->string, other->string) == 0) {
        return 0;
      }
    }
  }
  return 1;
}

static int manifest_path_is_regular_file(const wchar_t *path) {
  HANDLE file;
  FILE_ATTRIBUTE_TAG_INFO tag;
  DWORD attributes = GetFileAttributesW(path);
  if (attributes == INVALID_FILE_ATTRIBUTES ||
      (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return 0;
  file = CreateFileW(path, FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;
  if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) ||
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(file);
    return 0;
  }
  CloseHandle(file);
  return 1;
}

static int manifest_root_valid(const wchar_t *install_dir) {
  HANDLE root;
  FILE_ATTRIBUTE_TAG_INFO tag;
  if (!install_dir || !install_dir[0]) return 0;
  root = CreateFileW(install_dir, FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                     NULL);
  if (root == INVALID_HANDLE_VALUE) return 0;
  if (!GetFileInformationByHandleEx(root, FileAttributeTagInfo, &tag, sizeof(tag)) ||
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle(root);
    return 0;
  }
  CloseHandle(root);
  return 1;
}

static int manifest_hash_file(const wchar_t *path, char out[65]) {
  FILE *file = _wfopen(path, L"rb");
  EdrSha256Ctx hash;
  unsigned char buffer[16384];
  unsigned char digest[EDR_SHA256_DIGEST_LEN];
  int ok = 0;
  if (!file) return 0;
  edr_sha256_init(&hash);
  for (;;) {
    size_t count = fread(buffer, 1, sizeof(buffer), file);
    if (count) edr_sha256_update(&hash, buffer, count);
    if (count < sizeof(buffer)) {
      ok = !ferror(file);
      break;
    }
  }
  if (fclose(file) != 0) ok = 0;
  if (!ok) return 0;
  edr_sha256_final(&hash, digest);
  for (size_t i = 0; i < sizeof(digest); ++i) {
    static const char digits[] = "0123456789abcdef";
    out[i * 2] = digits[digest[i] >> 4];
    out[i * 2 + 1] = digits[digest[i] & 0x0f];
  }
  out[64] = '\0';
  SecureZeroMemory(digest, sizeof(digest));
  SecureZeroMemory(buffer, sizeof(buffer));
  return 1;
}

int edr_windows_native_manifest_validate(const wchar_t *install_dir,
                                         char manifest_sha256[65]) {
  wchar_t *manifest_path = NULL;
  wchar_t *entry_path = NULL;
  HANDLE file = INVALID_HANDLE_VALUE;
  LARGE_INTEGER size;
  FILE_ATTRIBUTE_TAG_INFO tag;
  char *contents = NULL;
  DWORD got = 0;
  int ok = 0;
  size_t install_length;
  size_t manifest_capacity;
  size_t entry_capacity;
  if (manifest_sha256) manifest_sha256[0] = '\0';
  if (!install_dir || !install_dir[0] ||
      (install_length = wcslen(install_dir)) >= EDR_NATIVE_PATH_MAX ||
      !manifest_root_valid(install_dir)) return 0;
  manifest_capacity = install_length + wcslen(L"\\native-package-integrity.json") + 1u;
  entry_capacity = install_length + 1u + EDR_NATIVE_NAME_MAX + 1u;
  if (manifest_capacity > EDR_NATIVE_PATH_MAX || entry_capacity > EDR_NATIVE_PATH_MAX) return 0;
  manifest_path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                       manifest_capacity * sizeof(wchar_t));
  entry_path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    entry_capacity * sizeof(wchar_t));
  if (!manifest_path || !entry_path) goto cleanup;
  {
    int written = _snwprintf(manifest_path, manifest_capacity,
                             L"%ls\\native-package-integrity.json", install_dir);
    if (written < 0 || (size_t)written >= manifest_capacity) goto cleanup;
  }
  file = CreateFileW(manifest_path, GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) ||
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !GetFileSizeEx(file, &size) ||
      size.QuadPart <= 0 || size.QuadPart > EDR_NATIVE_MANIFEST_MAX) goto cleanup;
  contents = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                               (SIZE_T)size.QuadPart + 1u);
  if (!contents || !ReadFile(file, contents, (DWORD)size.QuadPart, &got, NULL) ||
      got != (DWORD)size.QuadPart || memchr(contents, '\0', (size_t)size.QuadPart) != NULL) {
    goto cleanup;
  }
  contents[size.QuadPart] = '\0';
  {
    const char *parse_end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(contents, (size_t)size.QuadPart + 1u,
                                            &parse_end, 1);
    cJSON *schema;
    cJSON *files;
    int file_count;
    int required_seen[2] = {0, 0};
    static const char *const required[] = {
        "FDSecurityInstallerWorker.exe", "uninstall.exe"};
    static const char *const root_keys[] = {"schema", "files"};
    if (!root || !cJSON_IsObject(root) || parse_end != contents + size.QuadPart ||
        !manifest_unique_keys(root, root_keys, sizeof(root_keys) / sizeof(root_keys[0])) ||
        !(schema = cJSON_GetObjectItemCaseSensitive(root, "schema")) ||
        !cJSON_IsString(schema) ||
        strcmp(schema->valuestring, "edr.windows.native-package-integrity.v1") != 0 ||
        !(files = cJSON_GetObjectItemCaseSensitive(root, "files")) ||
        !cJSON_IsArray(files) || (file_count = cJSON_GetArraySize(files)) < 2 ||
        file_count > 64) {
      if (root) cJSON_Delete(root);
      goto cleanup;
    }
    for (int entry_index = 0; entry_index < file_count; ++entry_index) {
      cJSON *entry = cJSON_GetArrayItem(files, entry_index);
      cJSON *name = entry ? cJSON_GetObjectItemCaseSensitive(entry, "name") : NULL;
      cJSON *sha = entry ? cJSON_GetObjectItemCaseSensitive(entry, "sha256") : NULL;
      static const char *const entry_keys[] = {"name", "sha256"};
      wchar_t name_wide[512];
      char actual[65];
      if (!cJSON_IsObject(entry) ||
          !manifest_unique_keys(entry, entry_keys, sizeof(entry_keys) / sizeof(entry_keys[0])) ||
          !cJSON_IsString(name) || !name->valuestring ||
          strlen(name->valuestring) > EDR_NATIVE_NAME_MAX ||
          !edr_windows_native_manifest_name_safe(name->valuestring) ||
          !cJSON_IsString(sha) || !sha->valuestring || strlen(sha->valuestring) != 64 ||
          MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name->valuestring, -1,
                              name_wide, (int)(sizeof(name_wide) / sizeof(name_wide[0]))) <= 0) {
        cJSON_Delete(root);
        goto cleanup;
      }
      {
        int written = _snwprintf(entry_path, entry_capacity, L"%ls\\%ls", install_dir,
                                 name_wide);
        if (written < 0 || (size_t)written >= entry_capacity ||
            !manifest_path_is_regular_file(entry_path)) {
          cJSON_Delete(root);
          goto cleanup;
        }
      }
      for (size_t i = 0; i < 64; ++i) {
        if (manifest_hex_value(sha->valuestring[i]) < 0) {
          cJSON_Delete(root);
          goto cleanup;
        }
      }
      for (int previous_index = 0; previous_index < entry_index; ++previous_index) {
        cJSON *previous = cJSON_GetArrayItem(files, previous_index);
        cJSON *previous_name = previous ? cJSON_GetObjectItemCaseSensitive(previous, "name") : NULL;
        if (cJSON_IsString(previous_name) && !_stricmp(previous_name->valuestring,
                                                       name->valuestring)) {
          cJSON_Delete(root);
          goto cleanup;
        }
      }
      {
        const char *extension = strrchr(name->valuestring, '.');
        int required_name = !strcmp(name->valuestring, required[0]) ||
                            !strcmp(name->valuestring, required[1]);
        /* Releases 3.2.379..3.2.383 listed the standalone PCRE2 matcher
         * contract in this manifest. Those installed packages must stay
         * uninstallable-clean by newer coordinators, so the exact legacy
         * name is admitted here. The entry is still hash-verified below;
         * only the .dll/.exe extension policy is relaxed for it. */
        int legacy_contract = !_stricmp(name->valuestring, "p0_matcher_contract.json");
        if (!required_name && !legacy_contract &&
            (!extension || _stricmp(extension, ".dll") != 0)) {
          cJSON_Delete(root);
          goto cleanup;
        }
      }
      if (!manifest_hash_file(entry_path, actual) || _stricmp(actual, sha->valuestring) != 0) {
        cJSON_Delete(root);
        goto cleanup;
      }
      for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); ++i) {
        if (strcmp(name->valuestring, required[i]) == 0) required_seen[i] = 1;
      }
    }
    cJSON_Delete(root);
    if (!required_seen[0] || !required_seen[1]) goto cleanup;
  }
  if (manifest_sha256 && edr_sha256_hex((const uint8_t *)contents,
                                        (size_t)size.QuadPart, manifest_sha256) != 0) {
    goto cleanup;
  }
  ok = 1;
cleanup:
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (contents) {
    SecureZeroMemory(contents, (SIZE_T)size.QuadPart + 1u);
    HeapFree(GetProcessHeap(), 0, contents);
  }
  if (manifest_path) HeapFree(GetProcessHeap(), 0, manifest_path);
  if (entry_path) HeapFree(GetProcessHeap(), 0, entry_path);
  if (!ok && manifest_sha256) manifest_sha256[0] = '\0';
  return ok;
}
