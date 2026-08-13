#include "edr/agent_lifecycle_command.h"

#include "cJSON.h"
#include "edr/sha256.h"

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
#endif

typedef struct EdrAgentLifecycleRequest {
  char task_id[129];
  char action[16];
  char endpoint_id[129];
  char attestation_url[1024];
  char attestation_token[257];
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

static int safe_https_url(const char *value) {
  if (!value || strncmp(value, "https://", 8u) != 0) return 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (!isalnum(*p) && !strchr(":/._?&=%-", *p)) return 0;
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
  if (ok && !strcmp(out->action, "uninstall")) {
    ok = copy_json_string(root, "endpoint_id", out->endpoint_id, sizeof(out->endpoint_id)) &&
         copy_json_string(root, "attestation_url", out->attestation_url,
                          sizeof(out->attestation_url)) &&
         copy_json_string(root, "attestation_token", out->attestation_token,
                          sizeof(out->attestation_token)) &&
         safe_identifier(out->endpoint_id) && safe_https_url(out->attestation_url) &&
         safe_identifier(out->attestation_token);
  }
  if (ok) out->keep_data = cJSON_IsTrue(keep_data);
  cJSON_Delete(root);
  return ok;
}

#ifdef _WIN32
static int lifecycle_file_sha256(const char *path, char out[65]) {
  FILE *file = path ? fopen(path, "rb") : NULL;
  if (!file) return 0;
  EdrSha256Ctx hash;
  edr_sha256_init(&hash);
  unsigned char buffer[16384];
  int ok = 1;
  for (;;) {
    size_t count = fread(buffer, 1u, sizeof(buffer), file);
    if (count) edr_sha256_update(&hash, buffer, count);
    if (count < sizeof(buffer)) { if (ferror(file)) ok = 0; break; }
  }
  if (fclose(file) != 0) ok = 0;
  if (!ok) return 0;
  unsigned char digest[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&hash, digest);
  for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; ++i) snprintf(out + i * 2u, 3u, "%02x", digest[i]);
  out[64] = '\0';
  return 1;
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

static int lifecycle_sha256_text_valid(const char *value) {
  if (!value || strlen(value) != 64u) return 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (!isxdigit(*p)) return 0;
  }
  return 1;
}

static int lifecycle_runtime_name_valid(const char *name) {
  const char *required[] = {"FDSecurityInstallerWorker.exe", "uninstall.exe", "uninstall.ps1"};
  if (!name || !name[0]) return 0;
  for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') return 0;
  }
  for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); ++i) {
    if (_stricmp(name, required[i]) == 0) return 1;
  }
  size_t length = strlen(name);
  return length > 4u && _stricmp(name + length - 4u, ".dll") == 0;
}

static int lifecycle_runtime_validate(char identity_sha256[65]) {
  char directory[MAX_PATH], manifest_path[MAX_PATH];
  if (!lifecycle_install_dir(directory, sizeof(directory)) ||
      snprintf(manifest_path, sizeof(manifest_path), "%s\\native-package-integrity.json", directory) >= (int)sizeof(manifest_path)) return 0;
  FILE *file = fopen(manifest_path, "rb");
  if (!file) return 0;
  if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return 0; }
  long length = ftell(file);
  if (length <= 0 || length > 65536L || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return 0; }
  char *json = (char *)malloc((size_t)length + 1u);
  if (!json || fread(json, 1u, (size_t)length, file) != (size_t)length) { free(json); fclose(file); return 0; }
  fclose(file); json[length] = '\0';
  if (identity_sha256 && edr_sha256_hex((const uint8_t *)json, (size_t)length, identity_sha256) != 0) {
    free(json);
    return 0;
  }
  cJSON *root = cJSON_Parse(json); free(json);
  if (!root) return 0;
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema");
  const cJSON *files = cJSON_GetObjectItemCaseSensitive(root, "files");
  const char *required[] = {"FDSecurityInstallerWorker.exe", "uninstall.exe", "uninstall.ps1"};
  int ok = cJSON_IsObject(root) && cJSON_IsString(schema) && schema->valuestring &&
           strcmp(schema->valuestring, "edr.windows.native-package-integrity.v1") == 0 && cJSON_IsArray(files);
  int file_count = ok ? cJSON_GetArraySize(files) : 0;
  int required_seen[3] = {0, 0, 0};
  if (file_count < 3 || file_count > 64) ok = 0;
  for (const cJSON *item = ok ? files->child : NULL; item && ok; item = item->next) {
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(item, "name");
    const cJSON *sha = cJSON_GetObjectItemCaseSensitive(item, "sha256");
    if (!cJSON_IsObject(item) || !cJSON_IsString(name) ||
        !lifecycle_runtime_name_valid(name->valuestring) || !cJSON_IsString(sha) ||
        !lifecycle_sha256_text_valid(sha->valuestring)) {
      ok = 0;
      break;
    }
    for (const cJSON *previous = files->child; previous && previous != item; previous = previous->next) {
      const cJSON *previous_name = cJSON_GetObjectItemCaseSensitive(previous, "name");
      if (cJSON_IsString(previous_name) && previous_name->valuestring &&
          _stricmp(previous_name->valuestring, name->valuestring) == 0) {
        ok = 0;
        break;
      }
    }
    for (size_t i = 0; ok && i < sizeof(required) / sizeof(required[0]); ++i) {
      if (_stricmp(name->valuestring, required[i]) == 0) required_seen[i] = 1;
    }
    char path[MAX_PATH], actual[65];
    if (!ok || snprintf(path, sizeof(path), "%s\\%s", directory, name->valuestring) >=
                   (int)sizeof(path) ||
        !lifecycle_file_sha256(path, actual) || _stricmp(actual, sha->valuestring) != 0) {
      ok = 0;
    }
  }
  for (size_t i = 0; ok && i < sizeof(required_seen) / sizeof(required_seen[0]); ++i) {
    if (!required_seen[i]) ok = 0;
  }
  cJSON_Delete(root);
  if (!ok && identity_sha256) identity_sha256[0] = '\0';
  return ok;
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
      "--action \"%s\" --delay-ms %u%s%s%s%s%s%s%s%s",
      helper, request->action, install_dir, journal, log_path, command_id, request->task_id,
      request->action, strcmp(request->action, "restart") == 0 ? 2000u : 30000u,
      request->keep_data ? " --keep-data" : "",
      request->attestation_url[0] ? " --attestation-url \"" : "", request->attestation_url,
      request->attestation_url[0] ? "\" --attestation-token \"" : "", request->attestation_token,
      request->attestation_url[0] ? "\" --endpoint-id \"" : "", request->endpoint_id,
      request->attestation_url[0] ? "\"" : "");
  if (written <= 0 || written >= (int)sizeof(command)) return 0;
  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  if (!CreateProcessA(NULL, command, NULL, NULL, FALSE,
                      lifecycle_child_creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS),
                      NULL, NULL, &startup, &process)) {
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
