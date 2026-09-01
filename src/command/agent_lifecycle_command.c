#include "edr/agent_lifecycle_command.h"

#include "cJSON.h"
#include "edr/windows_handoff.h"
#include "edr/windows_native_manifest.h"
#include "edr/windows_spawn.h"
#include "edr/windows_spawn_lock.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD lifecycle_child_creation_flags(DWORD base_flags) {
  BOOL in_job = FALSE;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job) return base_flags;
  memset(&limits, 0, sizeof(limits));
  if (QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &limits,
                                sizeof(limits), NULL) &&
      (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)) {
    return base_flags | CREATE_BREAKAWAY_FROM_JOB;
  }
  return base_flags;
}

typedef struct EdrAgentLifecycleRequest {
  char task_id[129];
  char action[16];
  char endpoint_id[129];
  char attestation_url[1024];
  char attestation_token[257];
  int keep_data;
} EdrAgentLifecycleRequest;

static void lifecycle_clear_token(char *token, size_t capacity) {
  if (!token || !capacity) return;
#ifdef _WIN32
  SecureZeroMemory(token, capacity);
#else
  volatile unsigned char *cursor = (volatile unsigned char *)token;
  while (capacity--) *cursor++ = 0;
#endif
}

static void lifecycle_clear_json_tokens(cJSON *root) {
  cJSON *item;
  if (!root || !cJSON_IsObject(root)) return;
  for (item = root->child; item; item = item->next) {
    if (item->string && strcmp(item->string, "attestation_token") == 0 &&
        cJSON_IsString(item) && item->valuestring) {
      lifecycle_clear_token(item->valuestring, strlen(item->valuestring));
    }
  }
}

static int lifecycle_json_has_duplicate_keys(const cJSON *root) {
  const cJSON *item;
  const cJSON *prior;
  if (!root || !cJSON_IsObject(root)) return 1;
  for (item = root->child; item; item = item->next) {
    if (!item->string) return 1;
    for (prior = root->child; prior != item; prior = prior->next) {
      if (prior->string && strcmp(prior->string, item->string) == 0) return 1;
    }
  }
  return 0;
}

static int copy_json_string(const cJSON *root, const char *name, char *out, size_t cap) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0] ||
      strlen(item->valuestring) >= cap) {
    return 0;
  }
  snprintf(out, cap, "%s", item->valuestring);
  return 1;
}

static int safe_identifier(const char *value) {
  if (!value || !value[0]) return 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') return 0;
  }
  return 1;
}

static int safe_https_url(const char *value) {
  if (!value || strncmp(value, "https://", 8u) != 0) return 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (!isalnum(*p) && !strchr(":/._?&=%-", *p)) return 0;
  }
  return 1;
}

static int lifecycle_bearer_token_valid(const char *value) {
  size_t length;
  if (!value || (length = strlen(value)) < 32u || length > 256u) return 0;
  for (size_t i = 0; i < length; ++i) {
    unsigned char ch = (unsigned char)value[i];
    if (!isalnum(ch) && ch != '_' && ch != '-') return 0;
  }
  return 1;
}

static int lifecycle_payload_contains_nul_escape(const uint8_t *payload, size_t payload_len) {
  size_t i;
  if (!payload) return 0;
  for (i = 0; i + 5u < payload_len; ++i) {
    if (payload[i] == '\\' && (payload[i + 1u] == 'u' || payload[i + 1u] == 'U') &&
        payload[i + 2u] == '0' && payload[i + 3u] == '0' &&
        payload[i + 4u] == '0' && payload[i + 5u] == '0') return 1;
  }
  return 0;
}

static int parse_request(const uint8_t *payload, size_t payload_len,
                         EdrAgentLifecycleRequest *out) {
  char *json = NULL;
  cJSON *root = NULL;
  const char *parse_end = NULL;
  int ok = 0;
  if (!payload || !payload_len || payload_len > 8192u || !out ||
      memchr(payload, '\0', payload_len) != NULL ||
      lifecycle_payload_contains_nul_escape(payload, payload_len)) return 0;
  memset(out, 0, sizeof(*out));
  json = (char *)calloc(payload_len + 1u, 1u);
  if (!json) return 0;
  memcpy(json, payload, payload_len);
  json[payload_len] = '\0';
  root = cJSON_ParseWithLengthOpts(json, payload_len + 1u, &parse_end, 1);
  if (!cJSON_IsObject(root) || parse_end != json + payload_len ||
      lifecycle_json_has_duplicate_keys(root)) goto cleanup;
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *keep_data = cJSON_GetObjectItemCaseSensitive(root, "keep_data");
  ok = cJSON_IsString(schema) && schema->valuestring &&
           strcmp(schema->valuestring, "edr.endpoint.lifecycle.v1") == 0 &&
           copy_json_string(root, "task_id", out->task_id, sizeof(out->task_id)) &&
           copy_json_string(root, "action", out->action, sizeof(out->action)) &&
           safe_identifier(out->task_id) &&
           (!strcmp(out->action, "restart") || !strcmp(out->action, "offboard") ||
            !strcmp(out->action, "uninstall")) && cJSON_IsBool(keep_data);
  if (ok && !strcmp(out->action, "uninstall")) {
    ok = copy_json_string(root, "endpoint_id", out->endpoint_id, sizeof(out->endpoint_id)) &&
         copy_json_string(root, "attestation_url", out->attestation_url,
                          sizeof(out->attestation_url)) &&
         copy_json_string(root, "attestation_token", out->attestation_token,
                          sizeof(out->attestation_token)) &&
         safe_identifier(out->endpoint_id) && safe_https_url(out->attestation_url) &&
         lifecycle_bearer_token_valid(out->attestation_token);
  }
  if (ok) out->keep_data = cJSON_IsTrue(keep_data);
cleanup:
  lifecycle_clear_json_tokens(root);
  cJSON_Delete(root);
  lifecycle_clear_token(json, payload_len + 1u);
  free(json);
  if (!ok) lifecycle_clear_token(out->attestation_token, sizeof(out->attestation_token));
  return ok;
}

static int lifecycle_install_dir(char *directory, size_t cap) {
  char module[MAX_PATH];
  DWORD length = GetModuleFileNameA(NULL, module, (DWORD)sizeof(module));
  if (!length || length >= sizeof(module)) return 0;
  char *slash = strrchr(module, '\\');
  if (!slash) return 0;
  *slash = '\0';
  int written = snprintf(directory, cap, "%s", module);
  return written > 0 && (size_t)written < cap;
}

static int lifecycle_runtime_validate(char identity_sha256[65]) {
  char directory[MAX_PATH];
  wchar_t directory_wide[MAX_PATH];
  if (!lifecycle_install_dir(directory, sizeof(directory)) ||
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, directory, -1,
                          directory_wide, (int)(sizeof(directory_wide) /
                                                sizeof(directory_wide[0]))) <= 0) {
    return 0;
  }
  return edr_windows_native_manifest_validate(directory_wide, identity_sha256);
}

int edr_agent_lifecycle_runtime_ready(void) { return lifecycle_runtime_validate(NULL); }

int edr_agent_lifecycle_runtime_identity(char out_sha256[65]) {
  if (!out_sha256) return 0;
  out_sha256[0] = '\0';
  return lifecycle_runtime_validate(out_sha256);
}

static int lifecycle_paths(const char *command_id, char *helper, size_t helper_cap,
                           char *journal, size_t journal_cap, char *log_path,
                           size_t log_cap) {
  char module[MAX_PATH];
  DWORD length = GetModuleFileNameA(NULL, module, (DWORD)sizeof(module));
  if (!length || length >= sizeof(module)) return 0;
  char *slash = strrchr(module, '\\');
  if (!slash) return 0;
  *slash = '\0';
  if (snprintf(helper, helper_cap, "%s\\FDSecurityInstallerWorker.exe", module) >=
          (int)helper_cap) {
    return 0;
  }
  char program_data[MAX_PATH];
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, (DWORD)sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  char safe_command[181];
  size_t pos = 0u;
  for (const unsigned char *p = (const unsigned char *)command_id;
       *p && pos + 1u < sizeof(safe_command); ++p) {
    safe_command[pos++] = (isalnum(*p) || *p == '-' || *p == '_') ? (char)*p : '_';
  }
  safe_command[pos] = '\0';
  if (!safe_command[0] ||
      snprintf(log_path, log_cap,
               "%s\\FDSecurity\\state\\agent-lifecycle-%s.worker.log",
               program_data, safe_command) >= (int)log_cap ||
      snprintf(journal, journal_cap,
               "%s\\FDSecurity\\state\\agent-lifecycle-%s.journal.json",
               program_data, safe_command) >= (int)journal_cap) {
    return 0;
  }
  return GetFileAttributesA(helper) != INVALID_FILE_ATTRIBUTES && edr_agent_lifecycle_runtime_ready();
}

static int launch_worker(const char *helper, const char *journal, const char *log_path,
                         const char *command_id, EdrAgentLifecycleRequest *request) {
  char install_dir[MAX_PATH];
  SECURITY_ATTRIBUTES security;
  HANDLE secret_read = INVALID_HANDLE_VALUE, secret_write = INVALID_HANDLE_VALUE;
  HANDLE ack_read = INVALID_HANDLE_VALUE, ack_write = INVALID_HANDLE_VALUE;
  HANDLE handles[2];
  PROCESS_INFORMATION process;
  STARTUPINFOA startup;
  wchar_t wide_command[32768];
  wchar_t wide_directory[MAX_PATH];
  EdrWindowsSpawnLock spawn_lock = { 0 };
  char token_ack[256];
  DWORD token_ack_length = 0;
  int ok = 0;
  if (snprintf(install_dir, sizeof(install_dir), "%s", helper) >= (int)sizeof(install_dir)) {
    return 0;
  }
  char *slash = strrchr(install_dir, '\\');
  if (!slash || slash == install_dir) return 0;
  *slash = '\0';
  char command[4096];
  int written = 0;
  if (strcmp(request->action, "uninstall") != 0) {
    written = snprintf(
        command, sizeof(command),
        "\"%s\" --stage lifecycle-%s --service-name \"FDSecurityAgent\" "
        "--install-dir \"%s\" --journal \"%s\" --log \"%s\" --command-id \"%s\" "
        "--task-id \"%s\" --action \"%s\" --delay-ms %u",
        helper, request->action, install_dir, journal, log_path, command_id, request->task_id,
        request->action, strcmp(request->action, "restart") == 0 ? 2000u : 30000u);
  }
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  if (strcmp(request->action, "uninstall") != 0) {
    if (written <= 0 || written >= (int)sizeof(command)) return 0;
    startup.cb = sizeof(STARTUPINFOA);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE,
                        lifecycle_child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS),
                        NULL, NULL, &startup, &process)) return 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 1;
  }
  memset(&security, 0, sizeof(security));
  security.nLength = sizeof(security);
  security.bInheritHandle = FALSE;
  if (!edr_windows_spawn_lock_acquire(&spawn_lock)) goto cleanup;
  if (!CreatePipe(&secret_read, &secret_write, &security, 0) ||
      !CreatePipe(&ack_read, &ack_write, &security, 0)) goto cleanup;
  written = snprintf(command, sizeof(command),
                     "\"%s\" --stage lifecycle-uninstall --service-name \"FDSecurityAgent\" "
                     "--install-dir \"%s\" --journal \"%s\" --log \"%s\" --command-id \"%s\" "
                     "--task-id \"%s\" --action uninstall --delay-ms 30000 "
                     "--attestation-url \"%s\" --endpoint-id \"%s\" "
                     "--secret-read-handle %llu --ack-write-handle %llu --parent-pid %lu",
                     helper, install_dir, journal, log_path, command_id, request->task_id,
                     request->attestation_url, request->endpoint_id,
                     (unsigned long long)(ULONG_PTR)secret_read,
                     (unsigned long long)(ULONG_PTR)ack_write,
                     (unsigned long)GetCurrentProcessId());
  if (written <= 0 || written >= (int)sizeof(command)) goto cleanup;
  handles[0] = secret_read;
  handles[1] = ack_write;
  startup.cb = sizeof(STARTUPINFOA);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, command, -1,
                          wide_command, (int)(sizeof(wide_command) / sizeof(wide_command[0]))) <= 0 ||
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, install_dir, -1,
                          wide_directory, (int)(sizeof(wide_directory) / sizeof(wide_directory[0]))) <= 0 ||
      !edr_windows_spawn_whitelisted(
          wide_command, wide_directory, handles, 2, &process,
          lifecycle_child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS))) {
    goto cleanup;
  }
  edr_windows_spawn_lock_release(&spawn_lock);
  CloseHandle(secret_read); secret_read = INVALID_HANDLE_VALUE;
  CloseHandle(ack_write); ack_write = INVALID_HANDLE_VALUE;
  if (!edr_windows_handoff_write_frame(secret_write, (const BYTE *)request->attestation_token,
                                       (DWORD)strlen(request->attestation_token))) goto cleanup;
  lifecycle_clear_token(request->attestation_token, sizeof(request->attestation_token));
  CloseHandle(secret_write); secret_write = INVALID_HANDLE_VALUE;
  if (!edr_windows_handoff_read_frame(ack_read, (BYTE *)token_ack, sizeof(token_ack),
                                      &token_ack_length) ||
      token_ack_length != sizeof("edr.worker.ready.v1") - 1 ||
      memcmp(token_ack, "edr.worker.ready.v1", sizeof("edr.worker.ready.v1") - 1) != 0) goto cleanup;
  ok = 1;
cleanup:
  edr_windows_spawn_lock_release(&spawn_lock);
  if (request) {
    lifecycle_clear_token(request->attestation_token,
                          sizeof(request->attestation_token));
  }
  SecureZeroMemory(token_ack, sizeof(token_ack));
  if (!ok && process.hProcess) {
    TerminateProcess(process.hProcess, ERROR_CANCELLED);
    WaitForSingleObject(process.hProcess, 5000);
  }
  if (process.hThread) CloseHandle(process.hThread);
  if (process.hProcess) CloseHandle(process.hProcess);
  if (secret_read != INVALID_HANDLE_VALUE) CloseHandle(secret_read);
  if (secret_write != INVALID_HANDLE_VALUE) CloseHandle(secret_write);
  if (ack_read != INVALID_HANDLE_VALUE) CloseHandle(ack_read);
  if (ack_write != INVALID_HANDLE_VALUE) CloseHandle(ack_write);
  return ok;
}

static int read_journal(const char *path, EdrAgentLifecycleRecovery *out) {
  FILE *file = fopen(path, "rb");
  if (!file) return errno == ENOENT ? 0 : -1;
  if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return -1; }
  long length = ftell(file);
  if (length <= 0 || length > 65536L || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return -1;
  }
  char *json = (char *)malloc((size_t)length + 1u);
  if (!json || fread(json, 1u, (size_t)length, file) != (size_t)length) {
    free(json);
    fclose(file);
    return -1;
  }
  fclose(file);
  json[length] = '\0';
  cJSON *root = cJSON_Parse(json);
  free(json);
  const cJSON *succeeded = cJSON_GetObjectItemCaseSensitive(root, "succeeded");
  const cJSON *exit_code = cJSON_GetObjectItemCaseSensitive(root, "exit_code");
  int ok = cJSON_IsObject(root) &&
           copy_json_string(root, "task_id", out->task_id, sizeof(out->task_id)) &&
           copy_json_string(root, "command_id", out->command_id, sizeof(out->command_id)) &&
           copy_json_string(root, "action", out->action, sizeof(out->action)) &&
           copy_json_string(root, "status", out->status, sizeof(out->status)) &&
           copy_json_string(root, "detail", out->detail, sizeof(out->detail)) &&
           cJSON_IsBool(succeeded) && cJSON_IsNumber(exit_code);
  if (ok) {
    out->succeeded = cJSON_IsTrue(succeeded);
    out->exit_code = exit_code->valueint;
  }
  cJSON_Delete(root);
  return ok ? 2 : -1;
}
#endif

#ifndef _WIN32
int edr_agent_lifecycle_runtime_ready(void) { return 0; }
int edr_agent_lifecycle_runtime_identity(char out_sha256[65]) {
  if (out_sha256) out_sha256[0] = '\0';
  return 0;
}
#endif

int edr_agent_lifecycle_execute(const char *command_id, const uint8_t *payload,
                                size_t payload_len, char *detail, size_t detail_cap) {
#ifndef _WIN32
  (void)command_id; (void)payload; (void)payload_len;
  snprintf(detail, detail_cap, "endpoint lifecycle commands are unsupported on non-Windows");
  return EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED;
#else
  EdrAgentLifecycleRequest request;
  if (!command_id || !safe_identifier(command_id) ||
      !parse_request(payload, payload_len, &request)) {
    snprintf(detail, detail_cap, "invalid endpoint lifecycle command payload");
    return 2;
  }
  if (request.keep_data) {
    lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
    snprintf(detail, detail_cap, "keep_data is unsupported; complete uninstall is required");
    return EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED;
  }
  char helper[MAX_PATH], journal[MAX_PATH], log_path[MAX_PATH];
  if (!lifecycle_paths(command_id, helper, sizeof(helper), journal, sizeof(journal),
                       log_path, sizeof(log_path))) {
    lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
    snprintf(detail, detail_cap, "lifecycle worker is missing from the installed runtime");
    return EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED;
  }
  if (!launch_worker(helper, journal, log_path, command_id, &request)) {
    lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
    snprintf(detail, detail_cap, "cannot launch lifecycle worker");
    return 3;
  }
  lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
  if (strcmp(request.action, "restart") != 0) {
    snprintf(detail, detail_cap,
             "%s handoff accepted; local teardown is delayed for command-result delivery",
             request.action);
    return EDR_AGENT_LIFECYCLE_EXIT_HANDOFF;
  }
  snprintf(detail, detail_cap, "restart worker launched; awaiting post-restart recovery");
  return EDR_AGENT_LIFECYCLE_EXIT_LAUNCHED;
#endif
}

int edr_agent_lifecycle_recover(const char *command_id, const uint8_t *payload,
                                size_t payload_len, EdrAgentLifecycleRecovery *out) {
  if (!out) return -1;
  memset(out, 0, sizeof(*out));
#ifndef _WIN32
  (void)command_id; (void)payload; (void)payload_len;
  return 0;
#else
  EdrAgentLifecycleRequest request;
  memset(&request, 0, sizeof(request));
  char helper[MAX_PATH], journal[MAX_PATH], log_path[MAX_PATH];
  if (!command_id || !parse_request(payload, payload_len, &request) ||
      request.keep_data ||
      !lifecycle_paths(command_id, helper, sizeof(helper), journal, sizeof(journal),
                       log_path, sizeof(log_path))) {
    lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
    return -1;
  }
  int rc = read_journal(journal, out);
  if (rc == 2 && (strcmp(out->task_id, request.task_id) ||
                  strcmp(out->command_id, command_id) ||
                  strcmp(out->action, request.action))) {
    memset(out, 0, sizeof(*out));
    lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
    return -1;
  }
  lifecycle_clear_token(request.attestation_token, sizeof(request.attestation_token));
  return rc;
#endif
}
