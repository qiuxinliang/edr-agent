#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define EDR_FINALIZER_DELETE_RETRY_TIMEOUT_MS 1000u
#define wWinMain edr_native_test_embedded_entry
#include "../src/installer_worker/headless_uninstaller_win.c"
#undef wWinMain
#include "edr/windows_spawn.h"
#include "edr/windows_spawn_lock.h"

static int edr_finalizer_secure_directory(const wchar_t *path) {
  SECURITY_ATTRIBUTES security;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  BOOL created;
  if (!path || GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return 0;
  if (!edr_finalizer_security_attributes(&security, &descriptor)) return 0;
  created = CreateDirectoryW(path, &security);
  LocalFree(descriptor);
  return created && edr_finalizer_protect_path(path);
}

static int edr_finalizer_unique_directory(wchar_t *out, size_t out_count) {
  wchar_t temp_path[MAX_PATH_LONG];
  UUID uuid;
  RPC_WSTR uuid_text = NULL;
  DWORD temp_length;
  RPC_STATUS uuid_status;
  int written;
  if (!out || out_count == 0) return 0;
  temp_length = GetTempPathW((DWORD)(sizeof(temp_path) / sizeof(temp_path[0])), temp_path);
  if (!temp_length || temp_length >= sizeof(temp_path) / sizeof(temp_path[0])) return 0;
  uuid_status = UuidCreate(&uuid);
  if ((uuid_status != RPC_S_OK && uuid_status != RPC_S_UUID_LOCAL_ONLY) ||
      UuidToStringW(&uuid, &uuid_text) != RPC_S_OK || !uuid_text) return 0;
  written = _snwprintf(out, out_count, L"%lsFDSecurity-native-%ls", temp_path, uuid_text);
  RpcStringFreeW(&uuid_text);
  if (written < 0 || (size_t)written >= out_count) return 0;
  return edr_finalizer_secure_directory(out);
}

typedef struct EdrDelayedHandleClose {
  HANDLE handle;
  DWORD delay_ms;
} EdrDelayedHandleClose;

typedef struct EdrDelayedLibraryUnload {
  HMODULE module;
  DWORD delay_ms;
} EdrDelayedLibraryUnload;

static DWORD WINAPI edr_delayed_handle_close_thread(LPVOID context) {
  EdrDelayedHandleClose *close = (EdrDelayedHandleClose *)context;
  Sleep(close->delay_ms);
  return CloseHandle(close->handle) ? ERROR_SUCCESS : GetLastError();
}

static DWORD WINAPI edr_delayed_library_unload_thread(LPVOID context) {
  EdrDelayedLibraryUnload *unload = (EdrDelayedLibraryUnload *)context;
  Sleep(unload->delay_ms);
  return FreeLibrary(unload->module) ? ERROR_SUCCESS : GetLastError();
}

static int edr_test_parent_delivery_window(void) {
  HANDLE exited = CreateEventW(NULL, TRUE, TRUE, NULL);
  HANDLE running = CreateEventW(NULL, TRUE, FALSE, NULL);
  int ok = exited && running &&
           edr_native_wait_for_parent_delivery_window(exited, 10) == ERROR_SUCCESS &&
           edr_native_wait_for_parent_delivery_window(running, 10) == ERROR_SUCCESS &&
           edr_native_wait_for_parent_delivery_window(NULL, 10) == ERROR_INVALID_HANDLE;
  if (exited) CloseHandle(exited);
  if (running) CloseHandle(running);
  if (!ok) fprintf(stderr, "parent delivery window contract failed\n");
  return ok;
}

static int edr_test_attestation_retry_policy(void) {
  int ok = !edr_native_attestation_should_retry(401) &&
           !edr_native_attestation_should_retry(410) &&
           edr_native_attestation_should_retry(429) &&
           edr_native_attestation_should_retry(500) &&
           edr_native_attestation_should_retry(ERROR_WINHTTP_NAME_NOT_RESOLVED) &&
           edr_native_attestation_retry_delay_ms(429, 0) == 60000u &&
           edr_native_attestation_retry_delay_ms(500, 2) == 750u;
  if (!ok) fprintf(stderr, "attestation retry policy contract failed\n");
  return ok;
}

static int edr_test_transient_locked_delete(const wchar_t *root) {
  static wchar_t directory[MAX_PATH_LONG];
  static wchar_t file_path[MAX_PATH_LONG];
  static wchar_t failure_path[MAX_PATH_LONG];
  HANDLE file = INVALID_HANDLE_VALUE;
  HANDLE close_thread = NULL;
  EdrDelayedHandleClose delayed_close;
  DWORD error = ERROR_SUCCESS;
  DWORD thread_exit = ERROR_GEN_FAILURE;
  int ok = 0;

  failure_path[0] = L'\0';
  ZeroMemory(&delayed_close, sizeof(delayed_close));
  if (!join_path(directory, sizeof(directory) / sizeof(directory[0]),
                 root, L"transient-lock") ||
      !join_path(file_path, sizeof(file_path) / sizeof(file_path[0]),
                 directory, L"startup-task.log") ||
      !edr_finalizer_secure_directory(directory)) {
    goto cleanup;
  }
  file = CreateFileW(file_path, GENERIC_WRITE, FILE_SHARE_READ,
                     NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) goto cleanup;
  delayed_close.handle = file;
  delayed_close.delay_ms = 250;
  close_thread = CreateThread(NULL, 0, edr_delayed_handle_close_thread,
                              &delayed_close, 0, NULL);
  if (!close_thread) goto cleanup;
  file = INVALID_HANDLE_VALUE;
  if (!edr_finalizer_safe_delete_tree(directory, &error,
                                      failure_path,
                                      sizeof(failure_path) / sizeof(failure_path[0])) ||
      error != ERROR_SUCCESS || failure_path[0] != L'\0' ||
      WaitForSingleObject(close_thread, 5000) != WAIT_OBJECT_0 ||
      !GetExitCodeThread(close_thread, &thread_exit) || thread_exit != ERROR_SUCCESS ||
      GetFileAttributesW(directory) != INVALID_FILE_ATTRIBUTES) {
    goto cleanup;
  }
  CloseHandle(close_thread);
  close_thread = NULL;

  failure_path[0] = L'\0';
  error = ERROR_SUCCESS;
  if (!edr_finalizer_secure_directory(directory)) goto cleanup;
  file = CreateFileW(file_path, GENERIC_WRITE, FILE_SHARE_READ,
                     NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE ||
      edr_finalizer_safe_delete_tree(directory, &error,
                                     failure_path,
                                     sizeof(failure_path) / sizeof(failure_path[0])) ||
      error != ERROR_SHARING_VIOLATION ||
      _wcsicmp(failure_path, file_path) != 0) {
    goto cleanup;
  }
  CloseHandle(file);
  file = INVALID_HANDLE_VALUE;
  if (!edr_finalizer_safe_delete_tree(directory, &error, NULL, 0)) goto cleanup;
  ok = 1;

cleanup:
  if (!ok) {
    fwprintf(stderr,
             L"transient locked delete failed: error=%lu path=%ls thread_exit=%lu\n",
             (unsigned long)error, failure_path,
             (unsigned long)thread_exit);
  }
  if (close_thread) {
    WaitForSingleObject(close_thread, 5000);
    CloseHandle(close_thread);
  }
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (GetFileAttributesW(directory) != INVALID_FILE_ATTRIBUTES) {
    (void)edr_finalizer_safe_delete_tree(directory, &error, NULL, 0);
  }
  return ok;
}

static int edr_test_transient_mapped_image_delete(const wchar_t *root) {
  static wchar_t directory[MAX_PATH_LONG];
  static wchar_t system_directory[MAX_PATH_LONG];
  static wchar_t source_path[MAX_PATH_LONG];
  static wchar_t image_path[MAX_PATH_LONG];
  static wchar_t failure_path[MAX_PATH_LONG];
  EdrDelayedLibraryUnload delayed_unload;
  HMODULE module = NULL;
  HANDLE unload_thread = NULL;
  DWORD system_length;
  DWORD error = ERROR_SUCCESS;
  DWORD thread_exit = ERROR_GEN_FAILURE;
  int ok = 0;

  ZeroMemory(&delayed_unload, sizeof(delayed_unload));
  failure_path[0] = L'\0';
  system_length = GetSystemDirectoryW(
      system_directory,
      (UINT)(sizeof(system_directory) / sizeof(system_directory[0])));
  if (!system_length ||
      system_length >= sizeof(system_directory) / sizeof(system_directory[0]) ||
      !join_path(directory, sizeof(directory) / sizeof(directory[0]),
                 root, L"transient-mapped-image") ||
      !join_path(source_path, sizeof(source_path) / sizeof(source_path[0]),
                 system_directory, L"version.dll") ||
      !join_path(image_path, sizeof(image_path) / sizeof(image_path[0]),
                 directory, L"mapped-image.dll") ||
      !edr_finalizer_secure_directory(directory) ||
      !CopyFileW(source_path, image_path, TRUE)) {
    goto cleanup;
  }
  module = LoadLibraryW(image_path);
  if (!module) goto cleanup;
  delayed_unload.module = module;
  delayed_unload.delay_ms = 250;
  unload_thread = CreateThread(NULL, 0, edr_delayed_library_unload_thread,
                               &delayed_unload, 0, NULL);
  if (!unload_thread) goto cleanup;
  module = NULL;
  if (!edr_finalizer_safe_delete_tree(directory, &error,
                                      failure_path,
                                      sizeof(failure_path) / sizeof(failure_path[0])) ||
      error != ERROR_SUCCESS || failure_path[0] != L'\0' ||
      WaitForSingleObject(unload_thread, 5000) != WAIT_OBJECT_0 ||
      !GetExitCodeThread(unload_thread, &thread_exit) ||
      thread_exit != ERROR_SUCCESS ||
      GetFileAttributesW(directory) != INVALID_FILE_ATTRIBUTES) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  if (!ok) {
    fwprintf(stderr,
             L"transient mapped-image delete failed: error=%lu path=%ls thread_exit=%lu\n",
             (unsigned long)error, failure_path,
             (unsigned long)thread_exit);
  }
  if (unload_thread) {
    WaitForSingleObject(unload_thread, 5000);
    CloseHandle(unload_thread);
  }
  if (module) FreeLibrary(module);
  if (GetFileAttributesW(directory) != INVALID_FILE_ATTRIBUTES) {
    (void)edr_finalizer_safe_delete_tree(directory, &error, NULL, 0);
  }
  return ok;
}

static int edr_test_failure_receipt_replaces_open_previous(const wchar_t *root) {
  static wchar_t self_path[MAX_PATH_LONG];
  static wchar_t receipt_path[MAX_PATH_LONG];
  static wchar_t failure_path[MAX_PATH_LONG];
  EdrDelayedHandleClose delayed_close;
  HANDLE receipt = INVALID_HANDLE_VALUE;
  HANDLE close_thread = NULL;
  DWORD bytes_read = 0;
  DWORD thread_exit = ERROR_GEN_FAILURE;
  char content[512];
  int ok = 0;

  ZeroMemory(&delayed_close, sizeof(delayed_close));
  ZeroMemory(content, sizeof(content));
  if (!join_path(self_path, sizeof(self_path) / sizeof(self_path[0]),
                 root, L"uninstall-finalizer.exe") ||
      !join_path(receipt_path, sizeof(receipt_path) / sizeof(receipt_path[0]),
                 root, L"last-native-uninstall-failure.receipt") ||
      !join_path(failure_path, sizeof(failure_path) / sizeof(failure_path[0]),
                 root, L"current-failure.dll")) {
    goto cleanup;
  }
  edr_native_write_failure_receipt(self_path, "previous", ERROR_GEN_FAILURE, NULL);
  receipt = CreateFileW(receipt_path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (receipt == INVALID_HANDLE_VALUE) goto cleanup;
  delayed_close.handle = receipt;
  delayed_close.delay_ms = 250;
  close_thread = CreateThread(NULL, 0, edr_delayed_handle_close_thread,
                              &delayed_close, 0, NULL);
  if (!close_thread) goto cleanup;
  receipt = INVALID_HANDLE_VALUE;
  edr_native_write_failure_receipt(self_path, "remove-install-root",
                                   ERROR_ACCESS_DENIED, failure_path);
  if (WaitForSingleObject(close_thread, 5000) != WAIT_OBJECT_0 ||
      !GetExitCodeThread(close_thread, &thread_exit) ||
      thread_exit != ERROR_SUCCESS) {
    goto cleanup;
  }
  CloseHandle(close_thread);
  close_thread = NULL;
  receipt = CreateFileW(receipt_path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (receipt == INVALID_HANDLE_VALUE ||
      !ReadFile(receipt, content, sizeof(content) - 1, &bytes_read, NULL) ||
      !bytes_read ||
      !strstr(content, "stage=remove-install-root") ||
      !strstr(content, "error=5") ||
      !strstr(content, "current-failure.dll")) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  if (!ok) {
    fprintf(stderr,
            "failure receipt replacement failed: win32=%lu thread_exit=%lu content=%s\n",
            (unsigned long)GetLastError(), (unsigned long)thread_exit, content);
  }
  if (close_thread) {
    WaitForSingleObject(close_thread, 5000);
    CloseHandle(close_thread);
  }
  if (receipt != INVALID_HANDLE_VALUE) CloseHandle(receipt);
  DeleteFileW(receipt_path);
  return ok;
}

typedef struct EdrSpawnLockProbe {
  volatile LONG acquired;
} EdrSpawnLockProbe;

static DWORD WINAPI edr_spawn_lock_probe_thread(LPVOID context) {
  EdrSpawnLockProbe *probe = (EdrSpawnLockProbe *)context;
  EdrWindowsSpawnLock lock = { 0 };
  if (edr_windows_spawn_lock_acquire(&lock)) {
    InterlockedExchange(&probe->acquired, 1);
    edr_windows_spawn_lock_release(&lock);
  }
  return 0;
}

typedef struct EdrPartialFrameWriter {
  HANDLE handle;
  BYTE frame[8];
  DWORD length;
} EdrPartialFrameWriter;

static DWORD WINAPI edr_partial_frame_writer(LPVOID context) {
  EdrPartialFrameWriter *writer = (EdrPartialFrameWriter *)context;
  DWORD index;
  for (index = 0; index < writer->length; ++index) {
    DWORD written = 0;
    if (!WriteFile(writer->handle, writer->frame + index, 1, &written, NULL) || written != 1) {
      return 1;
    }
    Sleep(5);
  }
  CloseHandle(writer->handle);
  writer->handle = INVALID_HANDLE_VALUE;
  return 0;
}

static int edr_test_handoff_frames(void) {
  SECURITY_ATTRIBUTES security;
  HANDLE read_handle = INVALID_HANDLE_VALUE;
  HANDLE write_handle = INVALID_HANDLE_VALUE;
  HANDLE writer_thread = NULL;
  BYTE payload[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD payload_length = 0;
  DWORD expected = 3;
  EdrPartialFrameWriter writer;
  DWORD exit_code = ERROR_GEN_FAILURE;
  ZeroMemory(&security, sizeof(security));
  security.nLength = sizeof(security);
  if (!CreatePipe(&read_handle, &write_handle, &security, 0)) return 0;
  if (edr_windows_handoff_write_frame(write_handle, (const BYTE *)"x", 0) ||
      edr_windows_handoff_write_frame(write_handle, payload,
                                      EDR_WINDOWS_HANDOFF_MAX_FRAME + 1u)) goto cleanup;
  CloseHandle(write_handle);
  write_handle = INVALID_HANDLE_VALUE;
  if (edr_windows_handoff_read_frame(read_handle, payload, sizeof(payload), &payload_length) ||
      payload_length != 0) goto cleanup;
  CloseHandle(read_handle);
  read_handle = INVALID_HANDLE_VALUE;

  if (!CreatePipe(&read_handle, &write_handle, &security, 0)) return 0;
  ZeroMemory(&writer, sizeof(writer));
  writer.handle = write_handle;
  memcpy(writer.frame, &expected, sizeof(expected));
  memcpy(writer.frame + sizeof(expected), "abc", 3);
  writer.length = sizeof(expected) + 3;
  writer_thread = CreateThread(NULL, 0, edr_partial_frame_writer, &writer, 0, NULL);
  if (!writer_thread) goto cleanup;
  write_handle = INVALID_HANDLE_VALUE;
  if (!edr_windows_handoff_read_frame(read_handle, payload, sizeof(payload),
                                                         &payload_length) ||
      payload_length != 3 || memcmp(payload, "abc", 3) != 0 ||
      WaitForSingleObject(writer_thread, 5000) != WAIT_OBJECT_0 ||
      !GetExitCodeThread(writer_thread, &exit_code) || exit_code != 0) goto cleanup;
  CloseHandle(writer_thread);
  writer_thread = NULL;
  CloseHandle(read_handle);
  read_handle = INVALID_HANDLE_VALUE;
  if (!CreatePipe(&read_handle, &write_handle, &security, 0)) return 0;
  CloseHandle(read_handle);
  read_handle = INVALID_HANDLE_VALUE;
  if (edr_windows_handoff_write_frame(write_handle, (const BYTE *)"broken", 6)) goto cleanup;
  CloseHandle(write_handle);
  write_handle = INVALID_HANDLE_VALUE;
  {
    DWORD invalid_lengths[] = { 0u, EDR_WINDOWS_HANDOFF_MAX_FRAME + 1u };
    size_t index;
    for (index = 0; index < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]); ++index) {
      DWORD invalid_length = invalid_lengths[index];
      if (!CreatePipe(&read_handle, &write_handle, &security, 0) ||
          !WriteFile(write_handle, &invalid_length, sizeof(invalid_length), &exit_code, NULL)) {
        goto cleanup;
      }
      CloseHandle(write_handle);
      write_handle = INVALID_HANDLE_VALUE;
      payload_length = 123u;
      if (edr_windows_handoff_read_frame(read_handle, payload, sizeof(payload),
                                         &payload_length) || payload_length != 0) goto cleanup;
      CloseHandle(read_handle);
      read_handle = INVALID_HANDLE_VALUE;
    }
  }
  return 1;
cleanup:
  if (writer_thread) {
    WaitForSingleObject(writer_thread, 5000);
    CloseHandle(writer_thread);
  }
  if (read_handle != INVALID_HANDLE_VALUE) CloseHandle(read_handle);
  if (write_handle != INVALID_HANDLE_VALUE) CloseHandle(write_handle);
  return 0;
}

static int edr_test_create_identity_certificate(HCERTSTORE store,
                                                const wchar_t *endpoint_id,
                                                const wchar_t *container_name,
                                                wchar_t *thumbprint,
                                                size_t thumbprint_count) {
  HCRYPTPROV provider = 0;
  HCRYPTKEY key = 0;
  PCCERT_CONTEXT certificate = NULL;
  PCCERT_CONTEXT stored = NULL;
  BYTE encoded_name[1024];
  DWORD encoded_name_length = sizeof(encoded_name);
  BYTE hash[20];
  DWORD hash_length = sizeof(hash);
  wchar_t subject[256];
  CRYPT_KEY_PROV_INFO provider_info;
  CERT_NAME_BLOB subject_blob;
  SYSTEMTIME start;
  SYSTEMTIME end;
  size_t used = 0;
  DWORD index;
  int ok = 0;

  ZeroMemory(&provider_info, sizeof(provider_info));
  ZeroMemory(&subject_blob, sizeof(subject_blob));
  GetSystemTime(&start);
  end = start;
  end.wYear = (WORD)(end.wYear + 1);
  if (!store || !endpoint_id || !endpoint_id[0] || !container_name ||
      !container_name[0] || !thumbprint || thumbprint_count < 41 ||
      _snwprintf(subject, sizeof(subject) / sizeof(subject[0]),
                 L"CN=%ls", endpoint_id) < 0 ||
      !CertStrToNameW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, NULL,
                      encoded_name, &encoded_name_length, NULL) ||
      !CryptAcquireContextW(&provider, container_name, MS_ENH_RSA_AES_PROV_W,
                            PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT) ||
      !CryptGenKey(provider, AT_KEYEXCHANGE,
                   (2048u << 16) | CRYPT_EXPORTABLE, &key)) {
    goto cleanup;
  }
  provider_info.pwszContainerName = (LPWSTR)container_name;
  provider_info.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
  provider_info.dwProvType = PROV_RSA_AES;
  provider_info.dwKeySpec = AT_KEYEXCHANGE;
  subject_blob.cbData = encoded_name_length;
  subject_blob.pbData = encoded_name;
  certificate = CertCreateSelfSignCertificate(
      (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)provider, &subject_blob, 0,
      &provider_info, NULL, &start, &end, NULL);
  if (!certificate ||
      !CertAddCertificateContextToStore(store, certificate, CERT_STORE_ADD_ALWAYS,
                                        &stored) ||
      !CertGetCertificateContextProperty(stored, CERT_SHA1_HASH_PROP_ID,
                                         hash, &hash_length) ||
      hash_length != sizeof(hash)) {
    goto cleanup;
  }
  for (index = 0; index < hash_length; ++index) {
    int written = _snwprintf(thumbprint + used, thumbprint_count - used,
                             L"%02X", hash[index]);
    if (written != 2) goto cleanup;
    used += 2;
  }
  thumbprint[used] = L'\0';
  ok = 1;

cleanup:
  if (stored && !ok) {
    CertDeleteCertificateFromStore(stored);
    stored = NULL;
  }
  if (stored) CertFreeCertificateContext(stored);
  if (certificate) CertFreeCertificateContext(certificate);
  if (key) CryptDestroyKey(key);
  if (provider) CryptReleaseContext(provider, 0);
  if (!ok && container_name && container_name[0]) {
    HCRYPTPROV cleanup_provider = 0;
    (void)CryptAcquireContextW(&cleanup_provider, container_name,
                               MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                               CRYPT_DELETEKEYSET | CRYPT_SILENT);
    if (cleanup_provider) CryptReleaseContext(cleanup_provider, 0);
  }
  SecureZeroMemory(hash, sizeof(hash));
  return ok;
}

static int edr_test_remove_endpoint_certificates(void) {
  UUID uuid;
  RPC_STATUS uuid_status;
  RPC_WSTR uuid_text = NULL;
  wchar_t endpoint[128];
  wchar_t other_endpoint[128];
  wchar_t container_one[128];
  wchar_t container_two[128];
  wchar_t container_other[128];
  wchar_t endpoint_thumbprint[41];
  wchar_t other_thumbprint[41];
  HCERTSTORE store = NULL;
  PCCERT_CONTEXT certificate = NULL;
  DWORD endpoint_count = 0;
  DWORD other_count = 0;
  int ok = 0;

  endpoint_thumbprint[0] = L'\0';
  other_thumbprint[0] = L'\0';
  uuid_status = UuidCreate(&uuid);
  if ((uuid_status != RPC_S_OK && uuid_status != RPC_S_UUID_LOCAL_ONLY) ||
      UuidToStringW(&uuid, &uuid_text) != RPC_S_OK || !uuid_text) {
    return 0;
  }
  _snwprintf(endpoint, sizeof(endpoint) / sizeof(endpoint[0]),
             L"edr-cert-test-%ls", uuid_text);
  _snwprintf(other_endpoint, sizeof(other_endpoint) / sizeof(other_endpoint[0]),
             L"edr-cert-other-%ls", uuid_text);
  _snwprintf(container_one, sizeof(container_one) / sizeof(container_one[0]),
             L"edr-cert-key-1-%ls", uuid_text);
  _snwprintf(container_two, sizeof(container_two) / sizeof(container_two[0]),
             L"edr-cert-key-2-%ls", uuid_text);
  _snwprintf(container_other, sizeof(container_other) / sizeof(container_other[0]),
             L"edr-cert-key-other-%ls", uuid_text);
  RpcStringFreeW(&uuid_text);
  store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV_LEGACY)0,
                        CERT_SYSTEM_STORE_CURRENT_USER, L"My");
  if (!store ||
      !edr_test_create_identity_certificate(store, endpoint, container_one,
                                            endpoint_thumbprint,
                                            sizeof(endpoint_thumbprint) /
                                                sizeof(endpoint_thumbprint[0])) ||
      !edr_test_create_identity_certificate(store, endpoint, container_two,
                                            endpoint_thumbprint,
                                            sizeof(endpoint_thumbprint) /
                                                sizeof(endpoint_thumbprint[0])) ||
      !edr_test_create_identity_certificate(store, other_endpoint,
                                            container_other, other_thumbprint,
                                            sizeof(other_thumbprint) /
                                                sizeof(other_thumbprint[0]))) {
    goto cleanup;
  }
  CertCloseStore(store, 0);
  store = NULL;
  if (edr_native_remove_certificate_identity(endpoint_thumbprint, endpoint,
                                             L"CurrentUser\\My") != ERROR_SUCCESS) {
    goto cleanup;
  }
  store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV_LEGACY)0,
                        CERT_SYSTEM_STORE_CURRENT_USER, L"My");
  if (!store) goto cleanup;
  while ((certificate = CertEnumCertificatesInStore(store, certificate)) != NULL) {
    if (edr_native_certificate_matches_endpoint(certificate, endpoint)) ++endpoint_count;
    if (edr_native_certificate_matches_endpoint(certificate, other_endpoint)) ++other_count;
  }
  ok = endpoint_count == 0 && other_count == 1;

cleanup:
  if (certificate) CertFreeCertificateContext(certificate);
  if (store) CertCloseStore(store, 0);
  if (endpoint_thumbprint[0]) {
    (void)edr_native_remove_certificate_identity(endpoint_thumbprint, endpoint,
                                                  L"CurrentUser\\My");
  }
  if (other_thumbprint[0]) {
    (void)edr_native_remove_certificate_identity(other_thumbprint, other_endpoint,
                                                  L"CurrentUser\\My");
  }
  return ok;
}

static int edr_test_parse_handle_value(const wchar_t *text, HANDLE *handle_out) {
  wchar_t *end = NULL;
  unsigned long long value;
  if (!text || !text[0] || !handle_out || text[0] < L'0' || text[0] > L'9') return 0;
  errno = 0;
  value = _wcstoui64(text, &end, 10);
  if (errno == ERANGE || !end || *end != L'\0' || value == 0 ||
      (unsigned long long)(ULONG_PTR)value != value) return 0;
  *handle_out = (HANDLE)(ULONG_PTR)value;
  return 1;
}

/* A HANDLE is a process-local slot, not an object identity. The loader can
 * reuse an unlisted slot before wmain; a valid unrelated handle is not a leak.
 * The explicitly whitelisted duplicate pins the canary's object for comparison. */
static int edr_test_canary_isolated(HANDLE candidate, HANDLE reference) {
  DWORD flags = 0;
  if (!GetHandleInformation(reference, &flags)) return 0;
  return !CompareObjectHandles(candidate, reference);
}

static int edr_test_canary_identity(void) {
  HANDLE canary = CreateEventW(NULL, TRUE, FALSE, NULL);
  HANDLE unrelated = CreateEventW(NULL, TRUE, FALSE, NULL);
  HANDLE reference = NULL;
  int ok = canary && unrelated &&
           DuplicateHandle(GetCurrentProcess(), canary, GetCurrentProcess(),
                            &reference, 0, FALSE, DUPLICATE_SAME_ACCESS) &&
           !edr_test_canary_isolated(canary, reference) &&
           !edr_test_canary_isolated(reference, reference) &&
           edr_test_canary_isolated(unrelated, reference) &&
           edr_test_canary_isolated(NULL, reference) &&
           !edr_test_canary_isolated(unrelated, NULL);
  if (reference) CloseHandle(reference);
  if (unrelated) CloseHandle(unrelated);
  if (canary) CloseHandle(canary);
  if (!ok) fprintf(stderr, "canary object identity contract failed\n");
  return ok;
}

typedef struct EdrNativeTestFailureFrame {
  DWORD magic;
  DWORD error;
  char stage[64];
} EdrNativeTestFailureFrame;

static int edr_finalizer_foundation_child(int argc, wchar_t **argv) {
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE acknowledgement = INVALID_HANDLE_VALUE;
  HANDLE canary = INVALID_HANDLE_VALUE;
  HANDLE canary_reference = INVALID_HANDLE_VALUE;
  EdrWindowsSpawnLock child_spawn_lock = { 0 };
  BYTE secret[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD secret_length = 0;
  int ok = 0;
  const wchar_t *secret_text = arg_value(argc, argv, L"--secret-handle");
  const wchar_t *ack_text = arg_value(argc, argv, L"--ack-handle");
  const wchar_t *canary_text = arg_value(argc, argv, L"--canary-handle");
  const wchar_t *reference_text = arg_value(argc, argv, L"--canary-reference");
  const BYTE *expected_secret = EDR_LOCAL_HANDOFF_MARKER;
  DWORD expected_secret_length = sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1;
  static const BYTE ready[] = "edr.finalizer.ready.v1";
  const char *failure_stage = "parse-inherited-handles";
  ZeroMemory(secret, sizeof(secret));
  if (!edr_finalizer_parse_handle(secret_text, &secret_read) ||
      !edr_finalizer_parse_handle(ack_text, &acknowledgement) ||
      !edr_finalizer_parse_handle(reference_text, &canary_reference) ||
      !edr_test_parse_handle_value(canary_text, &canary)) {
    goto cleanup;
  }
  failure_stage = "reject-unlisted-canary";
  if (!edr_test_canary_isolated(canary, canary_reference)) {
    SetLastError(ERROR_INVALID_HANDLE);
    goto cleanup;
  }
  canary = INVALID_HANDLE_VALUE;
  failure_stage = "read-handoff-secret";
  if (!edr_windows_spawn_lock_acquire(&child_spawn_lock) ||
      !edr_windows_handoff_read_frame(secret_read, secret, sizeof(secret), &secret_length) ||
      secret_length != expected_secret_length ||
      memcmp(secret, expected_secret, expected_secret_length) != 0) {
    goto cleanup;
  }
  edr_windows_spawn_lock_release(&child_spawn_lock);
  SecureZeroMemory(secret, sizeof(secret));
  failure_stage = "write-ready-acknowledgement";
  if (!edr_windows_handoff_write_frame(acknowledgement, ready, sizeof(ready) - 1)) goto cleanup;
  ok = 1;
cleanup:
  if (!ok) {
    EdrNativeTestFailureFrame failure;
    ZeroMemory(&failure, sizeof(failure));
    failure.magic = EDR_FINALIZER_ERROR_MAGIC;
    failure.error = edr_finalizer_last_error();
    snprintf(failure.stage, sizeof(failure.stage), "%s", failure_stage);
    fprintf(stderr, "windows native uninstall child failed: stage=%s win32=%lu\n",
            failure_stage, (unsigned long)failure.error);
    (void)edr_windows_handoff_write_frame(acknowledgement,
                                         (const BYTE *)&failure, sizeof(failure));
  }
  edr_windows_spawn_lock_release(&child_spawn_lock);
  SecureZeroMemory(secret, sizeof(secret));
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (acknowledgement != INVALID_HANDLE_VALUE) CloseHandle(acknowledgement);
  if (canary_reference != INVALID_HANDLE_VALUE) CloseHandle(canary_reference);
  return ok ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
}

static int edr_test_write_marker(const wchar_t *path) {
  static const BYTE marker[] = "ok";
  HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD written = 0;
  int ok = file != INVALID_HANDLE_VALUE &&
           WriteFile(file, marker, sizeof(marker) - 1, &written, NULL) &&
           written == sizeof(marker) - 1 && FlushFileBuffers(file);
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  return ok;
}

static int edr_test_wait_for_marker(const wchar_t *path, DWORD timeout_ms) {
  DWORD started = GetTickCount();
  while (!file_exists(path)) {
    if (GetTickCount() - started >= timeout_ms) return 0;
    Sleep(50);
  }
  return 1;
}

static int edr_test_parse_pid(const wchar_t *text, DWORD *pid_out) {
  wchar_t *end = NULL;
  unsigned long value;
  if (!text || !text[0] || !pid_out) return 0;
  value = wcstoul(text, &end, 10);
  if (!end || *end || value == 0 || value > 0xffffffffUL) return 0;
  *pid_out = (DWORD)value;
  return 1;
}

static int edr_task_survivor_child(int argc, wchar_t **argv) {
  const wchar_t *pipe_name = arg_value(argc, argv, L"--handoff-pipe");
  const wchar_t *coordinator_text = arg_value(argc, argv, L"--coordinator-pid");
  const wchar_t *survivor_path = arg_value(argc, argv, L"--survivor-marker");
  HANDLE pipe = INVALID_HANDLE_VALUE;
  HANDLE coordinator = NULL;
  BYTE frame[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD frame_length = 0;
  DWORD coordinator_pid = 0;
  static const BYTE ready[] = "edr.finalizer.ready.v1";
  static const BYTE commit[] = "edr.finalizer.commit.v1";
  static const BYTE committed[] = "edr.finalizer.committed.v1";
  int ok = 0;

  ZeroMemory(frame, sizeof(frame));
  if (!survivor_path || !survivor_path[0] ||
      !edr_test_parse_pid(coordinator_text, &coordinator_pid) ||
      !(coordinator = OpenProcess(SYNCHRONIZE, FALSE, coordinator_pid)) ||
      (pipe = edr_finalizer_open_pipe(pipe_name)) == INVALID_HANDLE_VALUE ||
      !edr_windows_handoff_read_frame(pipe, frame, sizeof(frame), &frame_length) ||
      !edr_native_is_local_handoff_marker(frame, frame_length) ||
      !edr_windows_handoff_write_frame(pipe, ready, sizeof(ready) - 1) ||
      !edr_windows_handoff_read_frame(pipe, frame, sizeof(frame), &frame_length) ||
      frame_length != sizeof(commit) - 1 ||
      memcmp(frame, commit, sizeof(commit) - 1) != 0 ||
      !edr_windows_handoff_write_frame(pipe, committed, sizeof(committed) - 1)) {
    goto cleanup;
  }
  CloseHandle(pipe);
  pipe = INVALID_HANDLE_VALUE;
  if (WaitForSingleObject(coordinator, 10000) != WAIT_OBJECT_0 ||
      !edr_test_write_marker(survivor_path)) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
  if (coordinator) CloseHandle(coordinator);
  SecureZeroMemory(frame, sizeof(frame));
  return ok ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

static int edr_job_coordinator_child(int argc, wchar_t **argv) {
  const wchar_t *ready_path = arg_value(argc, argv, L"--ready-marker");
  const wchar_t *survivor_path = arg_value(argc, argv, L"--survivor-marker");
  const wchar_t *working_directory = arg_value(argc, argv, L"--working-directory");
  wchar_t executable[MAX_PATH_LONG];
  wchar_t pipe_name[256];
  wchar_t task_name[128];
  wchar_t arguments[32768];
  wchar_t pid_text[64];
  size_t used = 0;
  DWORD executable_length;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES security;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  DWORD finalizer_error = ERROR_BROKEN_PIPE;
  int task_registered = 0;
  int ok = 0;

  executable_length = GetModuleFileNameW(
      NULL, executable, (DWORD)(sizeof(executable) / sizeof(executable[0])));
  _snwprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]),
             L"%lu", (unsigned long)GetCurrentProcessId());
  if (!ready_path || !ready_path[0] || !survivor_path || !survivor_path[0] ||
      !working_directory || !working_directory[0] || !executable_length ||
      executable_length >= sizeof(executable) / sizeof(executable[0]) ||
      !edr_finalizer_unique_channel(pipe_name,
                                    sizeof(pipe_name) / sizeof(pipe_name[0]),
                                    task_name,
                                    sizeof(task_name) / sizeof(task_name[0])) ||
      !append_text(arguments, sizeof(arguments) / sizeof(arguments[0]), &used,
                   L"--native-task-survivor-child --handoff-pipe ") ||
      !append_quoted_arg(arguments, sizeof(arguments) / sizeof(arguments[0]),
                         &used, pipe_name) ||
      !append_text(arguments, sizeof(arguments) / sizeof(arguments[0]), &used,
                   L" --coordinator-pid ") ||
      !append_text(arguments, sizeof(arguments) / sizeof(arguments[0]), &used,
                   pid_text) ||
      !append_text(arguments, sizeof(arguments) / sizeof(arguments[0]), &used,
                   L" --survivor-marker ") ||
      !append_quoted_arg(arguments, sizeof(arguments) / sizeof(arguments[0]),
                         &used, survivor_path) ||
      !edr_finalizer_security_attributes(&security, &descriptor)) {
    goto cleanup;
  }
  pipe = CreateNamedPipeW(
      pipe_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, EDR_WINDOWS_HANDOFF_MAX_FRAME + sizeof(DWORD),
      EDR_WINDOWS_HANDOFF_MAX_FRAME + sizeof(DWORD), EDR_FINALIZER_IO_TIMEOUT_MS,
      &security);
  LocalFree(descriptor);
  descriptor = NULL;
  if (pipe == INVALID_HANDLE_VALUE ||
      !edr_native_register_finalizer_task(task_name, executable, arguments,
                                          working_directory)) {
    goto cleanup;
  }
  task_registered = 1;
  if (!edr_finalizer_wait_for_pipe(pipe) ||
      !edr_native_delete_finalizer_task(task_name)) {
    goto cleanup;
  }
  task_registered = 0;
  if (!edr_finalizer_exchange_ready(
          pipe, EDR_LOCAL_HANDOFF_MARKER,
          sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1, &finalizer_error) ||
      !edr_test_write_marker(ready_path)) {
    pipe = INVALID_HANDLE_VALUE;
    goto cleanup;
  }
  pipe = INVALID_HANDLE_VALUE;
  Sleep(30000);
  ok = 1;

cleanup:
  if (task_registered) (void)edr_native_delete_finalizer_task(task_name);
  if (descriptor) LocalFree(descriptor);
  if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
  return ok ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

static int edr_test_finalizer_task_survives_job(const wchar_t *self_path,
                                                const wchar_t *root) {
  wchar_t ready_path[MAX_PATH_LONG];
  wchar_t survivor_path[MAX_PATH_LONG];
  wchar_t command[32768];
  size_t used = 0;
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  HANDLE job = NULL;
  DWORD wait_result;
  DWORD exit_code = STILL_ACTIVE;
  int ok = 0;

  ZeroMemory(&startup, sizeof(startup));
  ZeroMemory(&process, sizeof(process));
  ZeroMemory(&limits, sizeof(limits));
  ready_path[0] = L'\0';
  survivor_path[0] = L'\0';
  startup.cb = sizeof(startup);
  if (!join_path(ready_path, sizeof(ready_path) / sizeof(ready_path[0]),
                 root, L"job-coordinator-ready.marker") ||
      !join_path(survivor_path, sizeof(survivor_path) / sizeof(survivor_path[0]),
                 root, L"job-finalizer-survived.marker") ||
      !append_quoted_arg(command, sizeof(command) / sizeof(command[0]), &used,
                         self_path) ||
      !append_text(command, sizeof(command) / sizeof(command[0]), &used,
                   L" --native-job-coordinator-child --ready-marker ") ||
      !append_quoted_arg(command, sizeof(command) / sizeof(command[0]), &used,
                         ready_path) ||
      !append_text(command, sizeof(command) / sizeof(command[0]), &used,
                   L" --survivor-marker ") ||
      !append_quoted_arg(command, sizeof(command) / sizeof(command[0]), &used,
                         survivor_path) ||
      !append_text(command, sizeof(command) / sizeof(command[0]), &used,
                   L" --working-directory ") ||
      !append_quoted_arg(command, sizeof(command) / sizeof(command[0]), &used,
                         root)) {
    goto cleanup;
  }
  job = CreateJobObjectW(NULL, NULL);
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job ||
      !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &limits, sizeof(limits)) ||
      !CreateProcessW(NULL, command, NULL, NULL, FALSE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, root,
                      &startup, &process) ||
      !AssignProcessToJobObject(job, process.hProcess) ||
      ResumeThread(process.hThread) == (DWORD)-1 ||
      !edr_test_wait_for_marker(ready_path, 15000)) {
    goto cleanup;
  }
  CloseHandle(job);
  job = NULL;
  wait_result = WaitForSingleObject(process.hProcess, 5000);
  if (wait_result != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(process.hProcess, &exit_code) ||
      exit_code == STILL_ACTIVE ||
      !edr_test_wait_for_marker(survivor_path, 10000)) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  if (job) CloseHandle(job);
  if (process.hProcess) {
    if (!ok && GetExitCodeProcess(process.hProcess, &exit_code) &&
        exit_code == STILL_ACTIVE) {
      TerminateProcess(process.hProcess, ERROR_CANCELLED);
      WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hProcess);
  }
  if (process.hThread) CloseHandle(process.hThread);
  if (ready_path[0]) DeleteFileW(ready_path);
  if (survivor_path[0]) DeleteFileW(survivor_path);
  return ok;
}

static int edr_finalizer_foundation_self_test(void) {
  /* This executable runs one self-test; long-path scratch must not consume the
     Windows default thread stack before the first assertion can run. */
  static wchar_t source[MAX_PATH_LONG];
  static wchar_t root[MAX_PATH_LONG];
  static wchar_t sibling[MAX_PATH_LONG];
  static wchar_t sentinel[MAX_PATH_LONG];
  static wchar_t target[MAX_PATH_LONG];
  static wchar_t empty_dir[MAX_PATH_LONG];
  static wchar_t payload[MAX_PATH_LONG];
  static wchar_t link_path[MAX_PATH_LONG];
  static wchar_t nested_dir[MAX_PATH_LONG];
  static wchar_t nested_child[MAX_PATH_LONG];
  static wchar_t command[32768];
  DWORD source_length;
  BYTE secret[] = "edr.local.uninstall.handoff.v1";
  BYTE acknowledgement[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD acknowledgement_length = 0;
  SECURITY_ATTRIBUTES pipe_security;
  PROCESS_INFORMATION process;
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE secret_write = INVALID_HANDLE_VALUE;
  HANDLE ack_read = INVALID_HANDLE_VALUE;
  HANDLE ack_write = INVALID_HANDLE_VALUE;
  HANDLE canary = INVALID_HANDLE_VALUE;
  HANDLE canary_reference = INVALID_HANDLE_VALUE;
  HANDLE handles[3];
  EdrWindowsSpawnLock spawn_lock = { 0 };
  HANDLE probe_thread = NULL;
  EdrSpawnLockProbe probe;
  DWORD cleanup_error = ERROR_SUCCESS;
  DWORD wait_result = WAIT_FAILED;
  DWORD failure_error = ERROR_SUCCESS;
  DWORD exit_code = STILL_ACTIVE;
  int child_exit_observed = 0;
  int result = ERROR_GEN_FAILURE;
  int created_link = 0;
  int root_deleted = 0;
  int sibling_written;
  const char *failure_stage = "handoff-frames";
  static const BYTE ready[] = "edr.finalizer.ready.v1";

  ZeroMemory(&process, sizeof(process));
  ZeroMemory(acknowledgement, sizeof(acknowledgement));
  ZeroMemory(&probe, sizeof(probe));
  if (!edr_test_handoff_frames()) goto cleanup;
  failure_stage = "canary-object-identity";
  if (!edr_test_canary_identity()) goto cleanup;
  failure_stage = "inno-uninstall-registry-key";
  if (wcscmp(EDR_INNO_UNINSTALL_REGISTRY_KEY,
             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
             L"{A73C1E7F-8D94-4A2C-BF5D-1E2F3A4B5C6D}}_is1") != 0) {
    goto cleanup;
  }
  failure_stage = "parent-delivery-window";
  if (!edr_test_parent_delivery_window()) goto cleanup;
  failure_stage = "attestation-retry-policy";
  if (!edr_test_attestation_retry_policy()) goto cleanup;
  failure_stage = "local-handoff-marker";
  if (!edr_native_is_local_handoff_marker(EDR_LOCAL_HANDOFF_MARKER,
                                          sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1) ||
      edr_native_valid_bearer_token(EDR_LOCAL_HANDOFF_MARKER,
                                    sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1)) {
    goto cleanup;
  }
  failure_stage = "endpoint-certificate-cleanup";
  if (!edr_test_remove_endpoint_certificates()) goto cleanup;
  root[0] = L'\0';
  failure_stage = "invalid-handle-parser";
  {
    HANDLE rejected_handle = INVALID_HANDLE_VALUE;
    if (edr_finalizer_parse_handle(L"0", &rejected_handle) ||
        edr_finalizer_parse_handle(L"12x", &rejected_handle) ||
        edr_finalizer_parse_handle(L"-1", &rejected_handle)) goto cleanup;
  }
  failure_stage = "spawn-lock";
  if (!edr_windows_spawn_lock_acquire(&spawn_lock)) goto cleanup;
  probe_thread = CreateThread(NULL, 0, edr_spawn_lock_probe_thread, &probe, 0, NULL);
  if (!probe_thread) goto cleanup;
  Sleep(100);
  if (probe.acquired) goto cleanup;
  edr_windows_spawn_lock_release(&spawn_lock);
  if (WaitForSingleObject(probe_thread, 5000) != WAIT_OBJECT_0 || !probe.acquired) {
    goto cleanup;
  }
  CloseHandle(probe_thread);
  probe_thread = NULL;
  failure_stage = "prepare-test-paths";
  sibling[0] = L'\0';
  source_length = GetModuleFileNameW(NULL, source,
                                     (DWORD)(sizeof(source) / sizeof(source[0])));
  sibling_written = -1;
  if (source_length && source_length < sizeof(source) / sizeof(source[0]) &&
      edr_finalizer_unique_directory(root, sizeof(root) / sizeof(root[0]))) {
    sibling_written = _snwprintf(sibling, sizeof(sibling) / sizeof(sibling[0]),
                                 L"%ls-sibling", root);
  }
  if (!source_length || source_length >= sizeof(source) / sizeof(source[0]) ||
      sibling_written < 0 || (size_t)sibling_written >= sizeof(sibling) / sizeof(sibling[0]) ||
      !join_path(sentinel, sizeof(sentinel) / sizeof(sentinel[0]), sibling, L"sentinel.txt") ||
      !join_path(target, sizeof(target) / sizeof(target[0]), root, L"probe.exe") ||
      !join_path(empty_dir, sizeof(empty_dir) / sizeof(empty_dir[0]), root, L"empty") ||
      !join_path(payload, sizeof(payload) / sizeof(payload[0]), root, L"payload.bin") ||
      !join_path(link_path, sizeof(link_path) / sizeof(link_path[0]), root, L"reparse-link")) {
    goto cleanup;
  }
  failure_stage = "empty-delete-and-copy";
  if (!edr_finalizer_secure_directory(empty_dir) ||
      !edr_finalizer_safe_delete_tree(empty_dir, &cleanup_error, NULL, 0) ||
      !edr_finalizer_copy_verified(source, target)) {
    goto cleanup;
  }
  failure_stage = "transient-locked-delete";
  if (!edr_test_transient_locked_delete(root)) goto cleanup;
  failure_stage = "transient-mapped-image-delete";
  if (!edr_test_transient_mapped_image_delete(root)) goto cleanup;
  failure_stage = "failure-receipt-replacement";
  if (!edr_test_failure_receipt_replaces_open_previous(root)) goto cleanup;
  failure_stage = "task-survives-agent-job";
  if (!edr_test_finalizer_task_survives_job(source, root)) goto cleanup;
  failure_stage = "recursive-delete-fixture";
  wcscpy(nested_dir, root);
  {
    unsigned int depth;
    for (depth = 0; depth < 12; ++depth) {
      wchar_t component[16];
      _snwprintf(component, sizeof(component) / sizeof(component[0]),
                 L"depth-%u", depth);
      component[(sizeof(component) / sizeof(component[0])) - 1] = L'\0';
      if (!join_path(nested_child,
                     sizeof(nested_child) / sizeof(nested_child[0]),
                     nested_dir, component) ||
          !edr_finalizer_secure_directory(nested_child)) {
        goto cleanup;
      }
      wcscpy(nested_dir, nested_child);
    }
  }
  failure_stage = "payload-file";
  {
    HANDLE file = CreateFileW(payload, GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    const BYTE marker[] = "foundation";
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, marker, sizeof(marker) - 1, &written, NULL) ||
        written != sizeof(marker) - 1 || !FlushFileBuffers(file)) {
      if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
      goto cleanup;
    }
    CloseHandle(file);
  }
  failure_stage = "sibling-sentinel";
  if (!edr_finalizer_secure_directory(sibling)) goto cleanup;
  {
    HANDLE sentinel_file = CreateFileW(sentinel, GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    const BYTE marker[] = "sibling-sentinel";
    DWORD written = 0;
    if (sentinel_file == INVALID_HANDLE_VALUE ||
        !WriteFile(sentinel_file, marker, sizeof(marker) - 1, &written, NULL) ||
        written != sizeof(marker) - 1 || !FlushFileBuffers(sentinel_file)) {
      if (sentinel_file != INVALID_HANDLE_VALUE) CloseHandle(sentinel_file);
      goto cleanup;
    }
    CloseHandle(sentinel_file);
  }
  failure_stage = "reparse-link";
  {
    if (!CreateSymbolicLinkW(link_path, sibling,
                             SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
      goto cleanup;
    } else {
      created_link = 1;
    }
  }
  failure_stage = "self-unlink";
  {
    wchar_t self_delete_path[MAX_PATH_LONG];
    HANDLE self_delete_file = INVALID_HANDLE_VALUE;
    DWORD self_delete_state;
    DWORD self_delete_error = ERROR_SUCCESS;
    if (!join_path(self_delete_path, sizeof(self_delete_path) / sizeof(self_delete_path[0]),
                   root, L"self-delete.tmp")) goto cleanup;
    self_delete_file = CreateFileW(self_delete_path, GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (self_delete_file == INVALID_HANDLE_VALUE) goto cleanup;
    CloseHandle(self_delete_file);
    self_delete_state = edr_native_unlink_self(self_delete_path);
    if (self_delete_state != ERROR_SUCCESS ||
        GetFileAttributesW(self_delete_path) != INVALID_FILE_ATTRIBUTES) goto cleanup;
    self_delete_error = GetLastError();
    if (self_delete_error != ERROR_FILE_NOT_FOUND &&
        self_delete_error != ERROR_PATH_NOT_FOUND) goto cleanup;
  }
  failure_stage = "handoff-pipes";
  ZeroMemory(&pipe_security, sizeof(pipe_security));
  pipe_security.nLength = sizeof(pipe_security);
  pipe_security.bInheritHandle = FALSE;
  if (!edr_windows_spawn_lock_acquire(&spawn_lock) ||
      !CreatePipe(&secret_read, &secret_write, &pipe_security, 0) ||
      !CreatePipe(&ack_read, &ack_write, &pipe_security, 0)) goto cleanup;
  canary = CreateEventW(&pipe_security, TRUE, FALSE, NULL);
  /* Identity comparison needs no event access rights on the reference. */
  if (!canary || !SetHandleInformation(canary, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
      !DuplicateHandle(GetCurrentProcess(), canary, GetCurrentProcess(),
                        &canary_reference, 0, FALSE, 0)) goto cleanup;
  failure_stage = "spawn-foundation-child";
  handles[0] = secret_read;
  handles[1] = ack_write;
  handles[2] = canary_reference;
  _snwprintf(command, sizeof(command) / sizeof(command[0]),
             L"\"%ls\" --native-foundation-child --secret-handle %llu --ack-handle %llu --canary-handle %llu --canary-reference %llu --local-marker",
             target, (unsigned long long)(ULONG_PTR)secret_read,
             (unsigned long long)(ULONG_PTR)ack_write,
             (unsigned long long)(ULONG_PTR)canary,
             (unsigned long long)(ULONG_PTR)canary_reference);
  command[(sizeof(command) / sizeof(command[0])) - 1] = L'\0';
  if (!edr_windows_spawn_whitelisted(command, root, handles, 3, &process,
                                     child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS))) goto cleanup;
  failure_stage = "parent-handle-flags";
  {
    DWORD secret_flags = 0;
    DWORD ack_flags = 0;
    DWORD canary_flags = 0;
    DWORD reference_flags = 0;
    if (!GetHandleInformation(secret_read, &secret_flags) ||
        !GetHandleInformation(ack_write, &ack_flags) ||
        !GetHandleInformation(canary, &canary_flags) ||
        !GetHandleInformation(canary_reference, &reference_flags) ||
        (secret_flags & HANDLE_FLAG_INHERIT) ||
        (ack_flags & HANDLE_FLAG_INHERIT) ||
        (reference_flags & HANDLE_FLAG_INHERIT) ||
        !(canary_flags & HANDLE_FLAG_INHERIT)) goto cleanup;
  }
  CloseHandle(secret_read);
  secret_read = INVALID_HANDLE_VALUE;
  CloseHandle(ack_write);
  ack_write = INVALID_HANDLE_VALUE;
  CloseHandle(canary);
  canary = INVALID_HANDLE_VALUE;
  CloseHandle(canary_reference);
  canary_reference = INVALID_HANDLE_VALUE;
  edr_windows_spawn_lock_release(&spawn_lock);
  failure_stage = "finalizer-ready-exchange";
  {
    int wrote = edr_windows_handoff_write_frame(secret_write, secret, sizeof(secret) - 1);
    DWORD write_error = wrote ? ERROR_SUCCESS : edr_finalizer_last_error();
    int read = edr_windows_handoff_read_frame(ack_read, acknowledgement,
                                              sizeof(acknowledgement),
                                              &acknowledgement_length);
    /* The child has no inherited stderr. Keep its diagnostic on the existing
     * bounded pipe even if it rejects a handle before reading the secret. */
    if (read && acknowledgement_length == sizeof(EdrNativeTestFailureFrame)) {
      EdrNativeTestFailureFrame failure;
      memcpy(&failure, acknowledgement, sizeof(failure));
      if (failure.magic == EDR_FINALIZER_ERROR_MAGIC) {
        failure.stage[sizeof(failure.stage) - 1] = '\0';
        fprintf(stderr, "windows native uninstall child failed: stage=%s win32=%lu\n",
                failure.stage, (unsigned long)failure.error);
        SetLastError(failure.error);
        goto cleanup;
      }
    }
    if (!wrote || !read || acknowledgement_length != sizeof(ready) - 1 ||
        memcmp(acknowledgement, ready, sizeof(ready) - 1) != 0) {
      if (!wrote) SetLastError(write_error);
      goto cleanup;
    }
  }
  CloseHandle(secret_write);
  secret_write = INVALID_HANDLE_VALUE;
  CloseHandle(ack_read);
  ack_read = INVALID_HANDLE_VALUE;
  SecureZeroMemory(secret, sizeof(secret));
  failure_stage = "foundation-child-exit";
  wait_result = WaitForSingleObject(process.hProcess, EDR_FINALIZER_IO_TIMEOUT_MS * 2);
  if (wait_result != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exit_code) ||
      exit_code != 0) goto cleanup;
  result = ERROR_SUCCESS;
  failure_stage = "complete";
cleanup:
  failure_error = GetLastError();
  edr_windows_spawn_lock_release(&spawn_lock);
  if (probe_thread) CloseHandle(probe_thread);
  if (process.hProcess) {
    wait_result = WaitForSingleObject(process.hProcess, EDR_FINALIZER_IO_TIMEOUT_MS);
    child_exit_observed = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    if (child_exit_observed && exit_code == STILL_ACTIVE) {
      TerminateProcess(process.hProcess, ERROR_CANCELLED);
      WaitForSingleObject(process.hProcess, EDR_FINALIZER_IO_TIMEOUT_MS);
    }
  }
  if (process.hThread) CloseHandle(process.hThread);
  if (process.hProcess) CloseHandle(process.hProcess);
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (secret_write != INVALID_HANDLE_VALUE) CloseHandle(secret_write);
  if (ack_read != INVALID_HANDLE_VALUE) CloseHandle(ack_read);
  if (ack_write != INVALID_HANDLE_VALUE) CloseHandle(ack_write);
  if (canary != INVALID_HANDLE_VALUE) CloseHandle(canary);
  if (canary_reference != INVALID_HANDLE_VALUE) CloseHandle(canary_reference);
  SecureZeroMemory(acknowledgement, sizeof(acknowledgement));
  SecureZeroMemory(secret, sizeof(secret));
  if (root[0]) {
    root_deleted = edr_finalizer_safe_delete_tree(root, &cleanup_error, NULL, 0);
    if (!root_deleted && result == ERROR_SUCCESS) {
      failure_stage = "cleanup-root";
      failure_error = cleanup_error;
      result = (int)cleanup_error;
    }
  }
  if (created_link && (!root_deleted ||
                       GetFileAttributesW(sibling) == INVALID_FILE_ATTRIBUTES ||
                       GetFileAttributesW(sentinel) == INVALID_FILE_ATTRIBUTES)) {
    failure_stage = "reparse-target-integrity";
    result = ERROR_DATA_CHECKSUM_ERROR;
  }
  if (sibling[0] && GetFileAttributesW(sibling) != INVALID_FILE_ATTRIBUTES &&
      !edr_finalizer_safe_delete_tree(sibling, &cleanup_error, NULL, 0) &&
      result == ERROR_SUCCESS) {
    failure_stage = "cleanup-sibling";
    failure_error = cleanup_error;
    result = (int)cleanup_error;
  }
  if (result != ERROR_SUCCESS) {
    fprintf(stderr,
            "windows native uninstall test failed: stage=%s result=%d win32=%lu "
            "cleanup=%lu wait=%lu child_exit_observed=%d child_exit=0x%08lx\n",
            failure_stage, result, (unsigned long)failure_error,
            (unsigned long)cleanup_error, (unsigned long)wait_result,
            child_exit_observed, (unsigned long)exit_code);
  }
  return result;
}

int wmain(int argc, wchar_t **argv) {
  if (has_flag(argc, argv, L"--native-foundation-child")) {
    return edr_finalizer_foundation_child(argc, argv);
  }
  if (has_flag(argc, argv, L"--native-job-coordinator-child")) {
    return edr_job_coordinator_child(argc, argv);
  }
  if (has_flag(argc, argv, L"--native-task-survivor-child")) {
    return edr_task_survivor_child(argc, argv);
  }
  return edr_finalizer_foundation_self_test();
}
