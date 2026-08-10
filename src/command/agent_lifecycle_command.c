#include "edr/agent_lifecycle_command.h"

#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

typedef struct EdrAgentLifecycleRequest {
  char task_id[129];
  char action[16];
  int keep_data;
} EdrAgentLifecycleRequest;

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

static int parse_request(const uint8_t *payload, size_t payload_len,
                         EdrAgentLifecycleRequest *out) {
  if (!payload || !payload_len || payload_len > 8192u || !out) return 0;
  memset(out, 0, sizeof(*out));
  char *json = (char *)malloc(payload_len + 1u);
  if (!json) return 0;
  memcpy(json, payload, payload_len);
  json[payload_len] = '\0';
  cJSON *root = cJSON_Parse(json);
  free(json);
  if (!cJSON_IsObject(root)) {
    cJSON_Delete(root);
    return 0;
  }
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *keep_data = cJSON_GetObjectItemCaseSensitive(root, "keep_data");
  int ok = cJSON_IsString(schema) && schema->valuestring &&
           strcmp(schema->valuestring, "edr.endpoint.lifecycle.v1") == 0 &&
           copy_json_string(root, "task_id", out->task_id, sizeof(out->task_id)) &&
           copy_json_string(root, "action", out->action, sizeof(out->action)) &&
           safe_identifier(out->task_id) &&
           (!strcmp(out->action, "restart") || !strcmp(out->action, "offboard") ||
            !strcmp(out->action, "uninstall")) && cJSON_IsBool(keep_data);
  if (ok) out->keep_data = cJSON_IsTrue(keep_data);
  cJSON_Delete(root);
  return ok;
}

#ifdef _WIN32
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
          (int)helper_cap ||
      snprintf(log_path, log_cap, "%s\\diagnostics\\lifecycle-worker.log", module) >=
          (int)log_cap) {
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
      snprintf(journal, journal_cap,
               "%s\\FDSecurity\\state\\agent-lifecycle-%s.journal.json",
               program_data, safe_command) >= (int)journal_cap) {
    return 0;
  }
  return GetFileAttributesA(helper) != INVALID_FILE_ATTRIBUTES;
}

static int launch_worker(const char *helper, const char *journal, const char *log_path,
                         const char *command_id, const EdrAgentLifecycleRequest *request) {
  char install_dir[MAX_PATH];
  if (snprintf(install_dir, sizeof(install_dir), "%s", helper) >= (int)sizeof(install_dir)) {
    return 0;
  }
  char *slash = strrchr(install_dir, '\\');
  if (!slash || slash == install_dir) return 0;
  *slash = '\0';
  char command[4096];
  int written = snprintf(
      command, sizeof(command),
      "\"%s\" --stage lifecycle-%s --service-name \"FDSecurityAgent\" "
      "--install-dir \"%s\" "
      "--journal \"%s\" --log \"%s\" --command-id \"%s\" --task-id \"%s\" "
      "--action \"%s\" --delay-ms %u%s",
      helper, request->action, install_dir, journal, log_path, command_id, request->task_id,
      request->action, strcmp(request->action, "restart") == 0 ? 2000u : 30000u,
      request->keep_data ? " --keep-data" : "");
  if (written <= 0 || written >= (int)sizeof(command)) return 0;
  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  if (!CreateProcessA(NULL, command, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &startup, &process)) {
    return 0;
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return 1;
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
  char helper[MAX_PATH], journal[MAX_PATH], log_path[MAX_PATH];
  if (!lifecycle_paths(command_id, helper, sizeof(helper), journal, sizeof(journal),
                       log_path, sizeof(log_path))) {
    snprintf(detail, detail_cap, "lifecycle worker is missing from the installed runtime");
    return EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED;
  }
  if (!launch_worker(helper, journal, log_path, command_id, &request)) {
    snprintf(detail, detail_cap, "cannot launch lifecycle worker");
    return 3;
  }
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
  char helper[MAX_PATH], journal[MAX_PATH], log_path[MAX_PATH];
  if (!command_id || !parse_request(payload, payload_len, &request) ||
      !lifecycle_paths(command_id, helper, sizeof(helper), journal, sizeof(journal),
                       log_path, sizeof(log_path))) {
    return -1;
  }
  int rc = read_journal(journal, out);
  if (rc == 2 && (strcmp(out->task_id, request.task_id) ||
                  strcmp(out->command_id, command_id) ||
                  strcmp(out->action, request.action))) {
    memset(out, 0, sizeof(*out));
    return -1;
  }
  return rc;
#endif
}
