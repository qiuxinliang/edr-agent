#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "edr/sha256.h"
#include "edr/windows_native_manifest.h"

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s (error=%lu)\n", message, (unsigned long)GetLastError());
  return 0;
}

static int expect_true(int value, const char *message) {
  return value ? 1 : fail(message);
}

static int join_path(const wchar_t *root, const wchar_t *name, wchar_t *out,
                     size_t capacity) {
  int written;
  if (!root || !name || !out || !capacity) return 0;
  written = _snwprintf(out, capacity, L"%ls\\%ls", root, name);
  return written >= 0 && (size_t)written < capacity;
}

static int write_bytes(const wchar_t *path, const void *data, size_t length) {
  HANDLE file;
  const unsigned char *cursor = (const unsigned char *)data;
  size_t remaining = length;
  file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;
  while (remaining) {
    DWORD chunk = remaining > 1024u * 1024u ? 1024u * 1024u : (DWORD)remaining;
    DWORD written = 0;
    if (!WriteFile(file, cursor, chunk, &written, NULL) || written != chunk) {
      CloseHandle(file);
      return 0;
    }
    cursor += written;
    remaining -= written;
  }
  if (!FlushFileBuffers(file) || !CloseHandle(file)) return 0;
  return 1;
}

static int sha256_file(const wchar_t *path, char output[65]) {
  HANDLE file = INVALID_HANDLE_VALUE;
  EdrSha256Ctx context;
  unsigned char buffer[16384];
  unsigned char digest[EDR_SHA256_DIGEST_LEN];
  DWORD got;
  int ok = 0;
  file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return 0;
  edr_sha256_init(&context);
  for (;;) {
    if (!ReadFile(file, buffer, sizeof(buffer), &got, NULL)) goto cleanup;
    if (got) edr_sha256_update(&context, buffer, got);
    if (got < sizeof(buffer)) break;
  }
  edr_sha256_final(&context, digest);
  for (size_t i = 0; i < sizeof(digest); ++i) {
    static const char digits[] = "0123456789abcdef";
    output[i * 2] = digits[digest[i] >> 4];
    output[i * 2 + 1] = digits[digest[i] & 0x0f];
  }
  output[64] = '\0';
  ok = 1;
cleanup:
  SecureZeroMemory(buffer, sizeof(buffer));
  SecureZeroMemory(digest, sizeof(digest));
  CloseHandle(file);
  return ok;
}

static int copy_file_to_name(const wchar_t *source, const wchar_t *root,
                             const wchar_t *name) {
  wchar_t target[32768];
  if (!join_path(root, name, target, sizeof(target) / sizeof(target[0]))) return 0;
  return CopyFileW(source, target, FALSE) != 0;
}

static int write_manifest(const wchar_t *root, const void *data, size_t length) {
  wchar_t path[32768];
  if (!join_path(root, L"native-package-integrity.json", path,
                 sizeof(path) / sizeof(path[0]))) return 0;
  return write_bytes(path, data, length);
}

static int validate_bytes(const wchar_t *root, const void *data, size_t length,
                          int expected, const char *message) {
  char identity[65];
  int actual;
  if (!write_manifest(root, data, length)) return fail("write manifest");
  actual = edr_windows_native_manifest_validate(root, identity);
  if (actual != expected) return fail(message);
  if (expected) {
    char expected_identity[65];
    if (edr_sha256_hex((const uint8_t *)data, length, expected_identity) != 0 ||
        strcmp(identity, expected_identity) != 0) return fail("manifest identity mismatch");
  }
  SecureZeroMemory(identity, sizeof(identity));
  return 1;
}

static int create_test_root(wchar_t root[32768]) {
  wchar_t temp_path[MAX_PATH];
  wchar_t temp_file[MAX_PATH];
  DWORD length = GetTempPathW((DWORD)(sizeof(temp_path) / sizeof(temp_path[0])), temp_path);
  if (!length || length >= sizeof(temp_path) / sizeof(temp_path[0])) return 0;
  if (!GetTempFileNameW(temp_path, L"edr", 0, temp_file)) return 0;
  if (!DeleteFileW(temp_file) || !CreateDirectoryW(temp_file, NULL)) return 0;
  {
    size_t root_length = wcslen(temp_file);
    if (root_length >= 32768u) return 0;
    memcpy(root, temp_file, (root_length + 1u) * sizeof(wchar_t));
  }
  return 1;
}

static void remove_tree(const wchar_t *root) {
  wchar_t path[32768];
  const wchar_t *names[] = {
      L"native-package-integrity.json", L"FDSecurityInstallerWorker.exe", L"uninstall.exe",
      L"source.exe", L"extra.exe", L"COM9.dll"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    if (join_path(root, names[i], path, sizeof(path) / sizeof(path[0]))) DeleteFileW(path);
  }
  for (unsigned i = 0; i < 63; ++i) {
    wchar_t name[32];
    if (_snwprintf(name, sizeof(name) / sizeof(name[0]), L"x%02u.dll", i) >= 0 &&
        join_path(root, name, path, sizeof(path) / sizeof(path[0]))) DeleteFileW(path);
  }
  RemoveDirectoryW(root);
}

int wmain(void) {
  wchar_t root[32768];
  wchar_t source[32768];
  wchar_t path[32768];
  char worker_hash[65];
  char uninstall_hash[65];
  char valid_manifest[4096];
  int valid_length;
  int ok = 1;
  DWORD source_length = GetModuleFileNameW(NULL, source,
                                           (DWORD)(sizeof(source) / sizeof(source[0])));
  if (!source_length || source_length >= sizeof(source) / sizeof(source[0]) ||
      !create_test_root(root) ||
      !copy_file_to_name(source, root, L"FDSecurityInstallerWorker.exe") ||
      !copy_file_to_name(source, root, L"uninstall.exe") ||
      !join_path(root, L"FDSecurityInstallerWorker.exe", path,
                 sizeof(path) / sizeof(path[0])) || !sha256_file(path, worker_hash) ||
      !join_path(root, L"uninstall.exe", path, sizeof(path) / sizeof(path[0])) ||
      !sha256_file(path, uninstall_hash)) {
    return fail("create native manifest test root");
  }
  valid_length = _snprintf(valid_manifest, sizeof(valid_manifest),
      "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
      "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
      "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}\n",
      worker_hash, uninstall_hash);
  ok &= expect_true(valid_length > 0 && (size_t)valid_length < sizeof(valid_manifest),
                    "build valid manifest");
  ok &= validate_bytes(root, valid_manifest, (size_t)valid_length, 1,
                       "valid manifest must pass");

  {
    char negative[4096];
    int length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}",
        worker_hash, uninstall_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0,
                         "duplicate root key must fail");
    length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\"FDSecurityInstallerWorker.exe\",\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}",
        worker_hash, uninstall_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0,
                         "duplicate entry key must fail");
  }
  {
    char trailing[4096];
    int length = _snprintf(trailing, sizeof(trailing), "%s{}", valid_manifest);
    ok &= validate_bytes(root, trailing, (size_t)length, 0, "trailing JSON must fail");
  }
  {
    const char prefix[] = "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
      "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"";
    const char suffix[] = "\"},{\"name\":\"uninstall.exe\",\"sha256\":\"";
    const char end[] = "\"}]}";
    unsigned char embedded[4096];
    size_t offset = 0;
    memcpy(embedded + offset, prefix, sizeof(prefix) - 1); offset += sizeof(prefix) - 1;
    memcpy(embedded + offset, worker_hash, 32); offset += 32;
    embedded[offset++] = 0;
    memcpy(embedded + offset, worker_hash + 32, 32); offset += 32;
    memcpy(embedded + offset, suffix, sizeof(suffix) - 1); offset += sizeof(suffix) - 1;
    memcpy(embedded + offset, uninstall_hash, 64); offset += 64;
    memcpy(embedded + offset, end, sizeof(end) - 1); offset += sizeof(end) - 1;
    memcpy(embedded + offset, "garbage", 7); offset += 7;
    ok &= validate_bytes(root, embedded, offset, 0, "embedded NUL/trailing data must fail");
  }
  ok &= expect_true(!edr_windows_native_manifest_name_safe("COM9.txt") &&
                    !edr_windows_native_manifest_name_safe("LPT9.txt") &&
                    !edr_windows_native_manifest_name_safe("name\x7f.dll") &&
                    !edr_windows_native_manifest_name_safe("bad<name.dll") &&
                    !edr_windows_native_manifest_name_safe("bad>name.dll") &&
                    !edr_windows_native_manifest_name_safe("bad|name.dll") &&
                    !edr_windows_native_manifest_name_safe("bad?name.dll") &&
                    !edr_windows_native_manifest_name_safe("bad*name.dll"),
                    "device, DEL, and Windows-invalid names must fail");
  {
    char name_limit[129];
    char name_over_limit[130];
    memset(name_limit, 'a', sizeof(name_limit) - 1u);
    name_limit[sizeof(name_limit) - 1u] = '\0';
    memcpy(name_over_limit, name_limit, sizeof(name_limit));
    name_over_limit[sizeof(name_over_limit) - 2u] = 'b';
    name_over_limit[sizeof(name_over_limit) - 1u] = '\0';
    ok &= expect_true(edr_windows_native_manifest_name_safe(name_limit) &&
                      !edr_windows_native_manifest_name_safe(name_over_limit),
                      "Windows manifest name length boundary must be enforced");
  }
  {
    char negative[4096];
    int length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\"fdsecurityinstallerworker.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}",
        worker_hash, uninstall_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0,
                         "wrong-case required name must fail");
  }
  {
    char negative[4096];
    int length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}",
        uninstall_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0,
                         "hash mismatch must fail");
    length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\".\\\\FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}]}",
        worker_hash, uninstall_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0, "path alias must fail");
  }
  if (!join_path(root, L"extra.exe", path, sizeof(path) / sizeof(path[0])) ||
      !CopyFileW(source, path, FALSE)) ok &= fail("create extra file");
  {
    char extra_hash[65];
    char negative[4096];
    int length;
    if (!sha256_file(path, extra_hash)) ok &= fail("hash extra file");
    length = _snprintf(negative, sizeof(negative),
        "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
        "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"},"
        "{\"name\":\"extra.exe\",\"sha256\":\"%s\"}]}",
        worker_hash, uninstall_hash, extra_hash);
    ok &= validate_bytes(root, negative, (size_t)length, 0,
                         "non-DLL extra must fail");
  }
  {
    wchar_t manifest_path[32768];
    if (join_path(root, L"native-package-integrity.json", manifest_path,
                  sizeof(manifest_path) / sizeof(manifest_path[0]))) DeleteFileW(manifest_path);
    if (!CreateSymbolicLinkW(manifest_path, path, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
      ok &= fail("manifest reparse link must be creatable in Windows CI");
    } else {
      char identity[65];
      ok &= expect_true(!edr_windows_native_manifest_validate(root, identity),
                        "manifest reparse must fail");
      DeleteFileW(manifest_path);
      ok &= write_manifest(root, valid_manifest, (size_t)valid_length);
    }
  }
  if (join_path(root, L"source.exe", path, sizeof(path) / sizeof(path[0]))) {
    if (!CopyFileW(source, path, FALSE)) ok &= fail("create reparse source");
  }
  {
    char entries[16384];
    size_t offset = 0;
    int written = _snprintf(entries + offset, sizeof(entries) - offset,
                            "{\"schema\":\"edr.windows.native-package-integrity.v1\",\"files\":["
                            "{\"name\":\"FDSecurityInstallerWorker.exe\",\"sha256\":\"%s\"},"
                            "{\"name\":\"uninstall.exe\",\"sha256\":\"%s\"}",
                            worker_hash, uninstall_hash);
    if (written < 0) ok &= fail("build 64-entry manifest prefix");
    else offset += (size_t)written;
    for (unsigned i = 0; i < 62; ++i) {
      wchar_t extra_name[32];
      if (_snwprintf(extra_name, sizeof(extra_name) / sizeof(extra_name[0]),
                     L"x%02u.dll", i) < 0 || !copy_file_to_name(source, root, extra_name)) {
        ok &= fail("create 64-entry DLL");
        break;
      }
      if (offset >= sizeof(entries)) {
        ok &= fail("64-entry manifest overflow");
        break;
      }
      written = _snprintf(entries + offset, sizeof(entries) - offset,
                          ",{\"name\":\"x%02u.dll\",\"sha256\":\"%s\"}", i, worker_hash);
      if (written < 0 || (size_t)written >= sizeof(entries) - offset) {
        ok &= fail("append 64-entry manifest");
        break;
      }
      offset += (size_t)written;
    }
    if (offset < sizeof(entries)) {
      written = _snprintf(entries + offset, sizeof(entries) - offset, "]}");
      if (written < 0 || (size_t)written >= sizeof(entries) - offset) {
        ok &= fail("finish 64-entry manifest");
      } else {
        offset += (size_t)written;
        ok &= validate_bytes(root, entries, offset, 1,
                             "64-entry manifest must pass");
      }
    }
    if (copy_file_to_name(source, root, L"x62.dll")) {
      if (offset < sizeof(entries)) {
        int extra_written = _snprintf(entries + offset - 2, sizeof(entries) - offset + 2,
                                      ",{\"name\":\"x62.dll\",\"sha256\":\"%s\"}]}",
                                      worker_hash);
        if (extra_written >= 0) {
          offset = offset - 2 + (size_t)extra_written;
          ok &= validate_bytes(root, entries, offset, 0,
                               ">64 manifest entries must fail");
        }
      }
    } else {
      ok &= fail("create 65th DLL");
    }
  }
  {
    wchar_t worker_path[32768];
    wchar_t source_path[32768];
    if (!join_path(root, L"FDSecurityInstallerWorker.exe", worker_path,
                   sizeof(worker_path) / sizeof(worker_path[0])) ||
        !join_path(root, L"source.exe", source_path, sizeof(source_path) / sizeof(source_path[0])) ||
        !DeleteFileW(worker_path) ||
        !CreateSymbolicLinkW(worker_path, source_path, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
      ok &= fail("entry reparse link must be creatable in Windows CI");
    } else {
      ok &= validate_bytes(root, valid_manifest, (size_t)valid_length, 0,
                           "entry reparse must fail");
      DeleteFileW(worker_path);
      ok &= CopyFileW(source, worker_path, FALSE);
    }
  }
  {
    wchar_t long_root[32768];
    size_t long_length = 32760;
    memcpy(long_root, L"C:\\", 3 * sizeof(wchar_t));
    for (size_t i = 3; i < long_length; ++i) long_root[i] = L'a';
    long_root[long_length] = L'\0';
    ok &= expect_true(!edr_windows_native_manifest_validate(long_root, NULL),
                      "oversized path must fail without truncating buffers");
  }
  {
    wchar_t sibling[32768];
    wchar_t sibling_worker[32768];
    wchar_t sibling_uninstall[32768];
    wchar_t sibling_manifest[32768];
    int sibling_ready = create_test_root(sibling);
    if (!sibling_ready ||
        !copy_file_to_name(source, sibling, L"FDSecurityInstallerWorker.exe") ||
        !copy_file_to_name(source, sibling, L"uninstall.exe") ||
        !join_path(sibling, L"native-package-integrity.json", sibling_manifest,
                   sizeof(sibling_manifest) / sizeof(sibling_manifest[0])) ||
        !write_bytes(sibling_manifest, valid_manifest, (size_t)valid_length)) {
      ok &= fail("create root reparse target");
    } else {
      remove_tree(root);
      if (!CreateSymbolicLinkW(root, sibling, SYMBOLIC_LINK_FLAG_DIRECTORY |
                               SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        ok &= fail("root reparse link must be creatable in Windows CI");
      } else {
        char identity[65];
        ok &= expect_true(!edr_windows_native_manifest_validate(root, identity),
                          "root reparse must fail");
        RemoveDirectoryW(root);
      }
      if (join_path(sibling, L"FDSecurityInstallerWorker.exe", sibling_worker,
                    sizeof(sibling_worker) / sizeof(sibling_worker[0]))) {
        DeleteFileW(sibling_worker);
      }
      if (join_path(sibling, L"uninstall.exe", sibling_uninstall,
                    sizeof(sibling_uninstall) / sizeof(sibling_uninstall[0]))) {
        DeleteFileW(sibling_uninstall);
      }
      DeleteFileW(sibling_manifest);
      RemoveDirectoryW(sibling);
      return ok ? 0 : 1;
    }
  }
  remove_tree(root);
  return ok ? 0 : 1;
}

#else
int main(void) { return 0; }
#endif
