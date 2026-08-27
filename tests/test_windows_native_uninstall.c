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

static DWORD WINAPI edr_delayed_handle_close_thread(LPVOID context) {
  EdrDelayedHandleClose *close = (EdrDelayedHandleClose *)context;
  Sleep(close->delay_ms);
  return CloseHandle(close->handle) ? ERROR_SUCCESS : GetLastError();
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

static int edr_finalizer_foundation_child(int argc, wchar_t **argv) {
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE acknowledgement = INVALID_HANDLE_VALUE;
  HANDLE canary = INVALID_HANDLE_VALUE;
  EdrWindowsSpawnLock child_spawn_lock = { 0 };
  BYTE secret[EDR_WINDOWS_HANDOFF_MAX_FRAME];
  DWORD secret_length = 0;
  int ok = 0;
  const wchar_t *secret_text = arg_value(argc, argv, L"--secret-handle");
  const wchar_t *ack_text = arg_value(argc, argv, L"--ack-handle");
  const wchar_t *canary_text = arg_value(argc, argv, L"--canary-handle");
  const BYTE *expected_secret = EDR_LOCAL_HANDOFF_MARKER;
  DWORD expected_secret_length = sizeof(EDR_LOCAL_HANDOFF_MARKER) - 1;
  static const BYTE ready[] = "edr.finalizer.ready.v1";
  const char *failure_stage = "parse-inherited-handles";
  ZeroMemory(secret, sizeof(secret));
  if (!edr_finalizer_parse_handle(secret_text, &secret_read) ||
      !edr_finalizer_parse_handle(ack_text, &acknowledgement) ||
      !edr_test_parse_handle_value(canary_text, &canary)) {
    goto cleanup;
  }
  failure_stage = "reject-unlisted-canary";
  {
    DWORD canary_flags = 0;
    if (GetHandleInformation(canary, &canary_flags)) {
      goto cleanup;
    }
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
    fprintf(stderr, "windows native uninstall child failed: stage=%s win32=%lu\n",
            failure_stage, (unsigned long)GetLastError());
  }
  edr_windows_spawn_lock_release(&child_spawn_lock);
  SecureZeroMemory(secret, sizeof(secret));
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (acknowledgement != INVALID_HANDLE_VALUE) CloseHandle(acknowledgement);
  return ok ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
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
  SECURITY_ATTRIBUTES pipe_security;
  PROCESS_INFORMATION process;
  EdrFinalizerHandoff handoff;
  HANDLE secret_read = INVALID_HANDLE_VALUE;
  HANDLE secret_write = INVALID_HANDLE_VALUE;
  HANDLE ack_read = INVALID_HANDLE_VALUE;
  HANDLE ack_write = INVALID_HANDLE_VALUE;
  HANDLE canary = INVALID_HANDLE_VALUE;
  HANDLE handles[2];
  EdrWindowsSpawnLock spawn_lock = { 0 };
  HANDLE probe_thread = NULL;
  EdrSpawnLockProbe probe;
  DWORD cleanup_error = ERROR_SUCCESS;
  DWORD wait_result = WAIT_FAILED;
  DWORD failure_error = ERROR_SUCCESS;
  DWORD exit_code = ERROR_GEN_FAILURE;
  int result = ERROR_GEN_FAILURE;
  int created_link = 0;
  int root_deleted = 0;
  int sibling_written;
  const char *failure_stage = "handoff-frames";

  ZeroMemory(&process, sizeof(process));
  ZeroMemory(&handoff, sizeof(handoff));
  handoff.secret_write = INVALID_HANDLE_VALUE;
  handoff.ack_read = INVALID_HANDLE_VALUE;
  ZeroMemory(&probe, sizeof(probe));
  if (!edr_test_handoff_frames()) goto cleanup;
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
  if (!canary || !SetHandleInformation(canary, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) goto cleanup;
  failure_stage = "spawn-foundation-child";
  handles[0] = secret_read;
  handles[1] = ack_write;
  _snwprintf(command, sizeof(command) / sizeof(command[0]),
             L"\"%ls\" --native-foundation-child --secret-handle %llu --ack-handle %llu --canary-handle %llu --local-marker",
             target, (unsigned long long)(ULONG_PTR)secret_read,
             (unsigned long long)(ULONG_PTR)ack_write,
             (unsigned long long)(ULONG_PTR)canary);
  command[(sizeof(command) / sizeof(command[0])) - 1] = L'\0';
  if (!edr_windows_spawn_whitelisted(command, root, handles, 2, &process,
                                     child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS))) goto cleanup;
  failure_stage = "parent-handle-flags";
  {
    DWORD secret_flags = 0;
    DWORD ack_flags = 0;
    DWORD canary_flags = 0;
    if (!GetHandleInformation(secret_read, &secret_flags) ||
        !GetHandleInformation(ack_write, &ack_flags) ||
        !GetHandleInformation(canary, &canary_flags) ||
        (secret_flags & HANDLE_FLAG_INHERIT) ||
        (ack_flags & HANDLE_FLAG_INHERIT) ||
        !(canary_flags & HANDLE_FLAG_INHERIT)) goto cleanup;
  }
  CloseHandle(secret_read);
  secret_read = INVALID_HANDLE_VALUE;
  CloseHandle(ack_write);
  ack_write = INVALID_HANDLE_VALUE;
  CloseHandle(canary);
  canary = INVALID_HANDLE_VALUE;
  edr_windows_spawn_lock_release(&spawn_lock);
  handoff.secret_write = secret_write;
  handoff.ack_read = ack_read;
  secret_write = INVALID_HANDLE_VALUE;
  ack_read = INVALID_HANDLE_VALUE;
  failure_stage = "finalizer-ready-exchange";
  if (!edr_finalizer_exchange_ready(&handoff, secret, sizeof(secret) - 1)) goto cleanup;
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
    DWORD process_exit = STILL_ACTIVE;
    if (GetExitCodeProcess(process.hProcess, &process_exit) &&
        process_exit == STILL_ACTIVE) {
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
  if (handoff.secret_write != INVALID_HANDLE_VALUE) CloseHandle(handoff.secret_write);
  if (handoff.ack_read != INVALID_HANDLE_VALUE) CloseHandle(handoff.ack_read);
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
            "cleanup=%lu wait=%lu child_exit=%lu\n",
            failure_stage, result, (unsigned long)failure_error,
            (unsigned long)cleanup_error, (unsigned long)wait_result,
            (unsigned long)exit_code);
  }
  return result;
}

int wmain(int argc, wchar_t **argv) {
  if (has_flag(argc, argv, L"--native-foundation-child")) {
    return edr_finalizer_foundation_child(argc, argv);
  }
  return edr_finalizer_foundation_self_test();
}
