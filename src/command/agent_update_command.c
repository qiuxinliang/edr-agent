#include "edr/agent_update_command.h"

#include "cJSON.h"
#include "edr/ingest_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "unknown"
#endif
#ifndef EDR_AGENT_UPDATE_SCRIPT_PATH
#define EDR_AGENT_UPDATE_SCRIPT_PATH "scripts/edr_agent_inplace_update.ps1"
#endif

static int fail(char *reason, size_t cap, const char *message) {
  if (reason && cap) snprintf(reason, cap, "%s", message ? message : "agent update failed");
  return 0;
}

static int copy_json_string(const cJSON *root, const char *name, char *out, size_t cap,
                            int required, char *reason, size_t reason_cap) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!item) return required ? fail(reason, reason_cap, "required agent_update field missing") : 1;
  if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0] ||
      strlen(item->valuestring) >= cap) {
    char message[160];
    snprintf(message, sizeof(message), "invalid agent_update string field: %s", name);
    return fail(reason, reason_cap, message);
  }
  snprintf(out, cap, "%s", item->valuestring);
  return 1;
}

static int is_hex(const char *value, size_t length) {
  if (!value || strlen(value) != length) return 0;
  for (const char *p = value; *p; ++p) if (!isxdigit((unsigned char)*p)) return 0;
  return 1;
}

static int parse_component(const char **cursor, uint64_t *value) {
  const char *p = *cursor;
  if (!isdigit((unsigned char)*p)) return 0;
  if (*p == '0' && isdigit((unsigned char)p[1])) return 0;
  uint64_t result = 0;
  while (isdigit((unsigned char)*p)) {
    unsigned digit = (unsigned)(*p - '0');
    if (result > (UINT64_MAX - digit) / 10u) return 0;
    result = result * 10u + digit;
    ++p;
  }
  *cursor = p;
  *value = result;
  return 1;
}

int edr_agent_update_semver_compare(const char *left, const char *right, int *comparison) {
  uint64_t l[3], r[3];
  const char *lp = left, *rp = right;
  if (!left || !right || !comparison) return 0;
  for (int i = 0; i < 3; ++i) {
    if (!parse_component(&lp, &l[i]) || !parse_component(&rp, &r[i])) return 0;
    if (i < 2 && (*lp++ != '.' || *rp++ != '.')) return 0;
  }
  if ((*lp && *lp != '-' && *lp != '+') || (*rp && *rp != '-' && *rp != '+')) return 0;
  for (int i = 0; i < 3; ++i) {
    if (l[i] != r[i]) { *comparison = l[i] < r[i] ? -1 : 1; return 1; }
  }
  /* Update policy compares release precedence. A prerelease is lower than a release. */
  int lpre = *lp == '-', rpre = *rp == '-';
  *comparison = lpre != rpre ? (lpre ? -1 : 1) : 0;
  return 1;
}

int edr_agent_update_journal_is_terminal(const char *status) {
  return status && (!strcmp(status, "succeeded") || !strcmp(status, "failed_rolled_back") ||
                    !strcmp(status, "failed_recovered") || !strcmp(status, "failed"));
}

int edr_agent_update_journal_blocks_replacement(const char *stage) {
  return stage && (!strcmp(stage, "replacement_committed") || !strcmp(stage, "start_new_runtime") ||
                   !strcmp(stage, "completed") || !strcmp(stage, "rollback_started") ||
                   !strcmp(stage, "rollback_completed"));
}

int edr_agent_update_parse_request(const uint8_t *payload, size_t payload_len,
                                   EdrAgentUpdateRequest *out,
                                   char *reason, size_t reason_cap) {
  if (!payload || !payload_len || !out) return fail(reason, reason_cap, "agent_update payload required");
  memset(out, 0, sizeof(*out));
  char *json = (char *)malloc(payload_len + 1u);
  if (!json) return fail(reason, reason_cap, "agent_update allocation failed");
  memcpy(json, payload, payload_len); json[payload_len] = '\0';
  cJSON *root = cJSON_ParseWithLength(json, payload_len);
  free(json);
  if (!cJSON_IsObject(root)) { cJSON_Delete(root); return fail(reason, reason_cap, "agent_update payload must be object"); }
#define COPY(name, member, required) do { if (!copy_json_string(root, name, out->member, sizeof(out->member), required, reason, reason_cap)) goto invalid; } while (0)
  COPY("artifact_url", artifact_url, 1);
  COPY("sha256", sha256, 1);
  COPY("target_version", target_version, 1);
  COPY("architecture", architecture, 1);
  COPY("internal_name", internal_name, 1);
  COPY("publisher_thumbprint", publisher_thumbprint, 1);
  COPY("publisher_subject", publisher_subject, 1);
  COPY("min_current_version", min_current_version, 0);
  COPY("max_current_version", max_current_version, 0);
  COPY("runtime_manifest_url", runtime_manifest_url, 0);
  COPY("runtime_manifest_sha256", runtime_manifest_sha256, 0);
  COPY("deployment_mode", deployment_mode, 0);
  COPY("scheduled_task_name", scheduled_task_name, 0);
  COPY("scheduled_task_path", scheduled_task_path, 0);
  COPY("service_name", service_name, 0);
#undef COPY
  const cJSON *free_bytes = cJSON_GetObjectItemCaseSensitive(root, "min_free_bytes");
  if (free_bytes) {
    if (!cJSON_IsNumber(free_bytes) || free_bytes->valuedouble < 0 ||
        free_bytes->valuedouble > 1099511627776.0 ||
        free_bytes->valuedouble != (double)(uint64_t)free_bytes->valuedouble) {
      fail(reason, reason_cap, "invalid min_free_bytes"); goto invalid;
    }
    out->min_free_bytes = (uint64_t)free_bytes->valuedouble;
  }
  if (!is_hex(out->sha256, 64u) || (out->runtime_manifest_sha256[0] && !is_hex(out->runtime_manifest_sha256, 64u))) {
    fail(reason, reason_cap, "agent_update SHA256 must contain 64 hex characters"); goto invalid;
  }
  int cmp = 0;
  if (!edr_agent_update_semver_compare(out->target_version, out->target_version, &cmp) ||
      (out->min_current_version[0] && !edr_agent_update_semver_compare(out->min_current_version, out->min_current_version, &cmp)) ||
      (out->max_current_version[0] && !edr_agent_update_semver_compare(out->max_current_version, out->max_current_version, &cmp))) {
    fail(reason, reason_cap, "agent_update versions must be semantic versions"); goto invalid;
  }
  if (strcmp(out->architecture, "x64") && strcmp(out->architecture, "arm64")) {
    fail(reason, reason_cap, "architecture must be x64 or arm64"); goto invalid;
  }
  if (!out->deployment_mode[0]) snprintf(out->deployment_mode, sizeof(out->deployment_mode), "auto");
  if (strcmp(out->deployment_mode, "auto") && strcmp(out->deployment_mode, "scheduled_task") && strcmp(out->deployment_mode, "service")) {
    fail(reason, reason_cap, "deployment_mode must be auto, scheduled_task, or service"); goto invalid;
  }
  if (strncmp(out->artifact_url, "https://", 8u) != 0) {
    fail(reason, reason_cap, "artifact_url must use https"); goto invalid;
  }
  if (!!out->runtime_manifest_url[0] != !!out->runtime_manifest_sha256[0] ||
      (out->runtime_manifest_url[0] && strncmp(out->runtime_manifest_url, "https://", 8u) != 0)) {
    fail(reason, reason_cap, "runtime manifest URL and SHA256 must be supplied together over https"); goto invalid;
  }
  cJSON_Delete(root);
  return 1;
invalid:
  cJSON_Delete(root);
  return 0;
}

#ifdef _WIN32
static int quote_ps(const char *input, char *out, size_t cap) {
  size_t used = 0;
  if (cap < 3u) return 0;
  out[used++] = '\'';
  for (const char *p = input ? input : ""; *p; ++p) {
    if (used + (*p == '\'' ? 2u : 1u) + 2u > cap) return 0;
    if (*p == '\'') out[used++] = '\'';
    out[used++] = *p;
  }
  out[used++] = '\''; out[used] = '\0';
  return 1;
}

static int write_launch_script(const char *path, const char *updater, const char *staged,
                               const char *manifest, const EdrAgentUpdateRequest *req,
                               const char *command_id) {
  const char *values[] = { updater, staged, req->sha256, req->target_version, req->architecture,
    req->internal_name, req->publisher_thumbprint, req->publisher_subject, req->min_current_version,
    req->max_current_version, req->deployment_mode, req->scheduled_task_name,
    req->scheduled_task_path, req->service_name, command_id, manifest, req->runtime_manifest_sha256 };
  char quoted[17][4600];
  for (size_t i = 0; i < 17u; ++i) if (!quote_ps(values[i], quoted[i], sizeof(quoted[i]))) return 0;
  FILE *file = fopen(path, "wb");
  if (!file) return 0;
  fprintf(file, "$ErrorActionPreference='Stop'\r\n& %s -StagedBinary %s -ExpectedSha256 %s -TargetVersion %s -ExpectedArchitecture %s -ExpectedInternalName %s -TrustedPublisherThumbprint %s -TrustedPublisherSubject %s -MinCurrentVersion %s -MaxCurrentVersion %s -DeploymentMode %s -ScheduledTaskName %s -ScheduledTaskPath %s -ServiceName %s -CommandId %s -RuntimeManifest %s -RuntimeManifestSha256 %s -MinFreeBytes %llu\r\nexit $LASTEXITCODE\r\n",
          quoted[0], quoted[1], quoted[2], quoted[3], quoted[4], quoted[5], quoted[6], quoted[7], quoted[8], quoted[9], quoted[10], quoted[11], quoted[12], quoted[13], quoted[14], quoted[15], quoted[16], (unsigned long long)req->min_free_bytes);
  return fclose(file) == 0;
}
#endif

static void safe_command_id(const char *command_id, char *out, size_t cap) {
  size_t used = 0;
  for (const unsigned char *p = (const unsigned char *)(command_id ? command_id : ""); *p && used + 1u < cap; ++p) {
    out[used++] = (isalnum(*p) || *p == '.' || *p == '_' || *p == '-') ? (char)*p : '_';
  }
  out[used] = '\0';
}

int edr_agent_update_parse_journal(const char *json, EdrAgentUpdateRecovery *out) {
  if (!json || !out) return -1;
  memset(out, 0, sizeof(*out));
  cJSON *root = cJSON_Parse(json);
  if (!cJSON_IsObject(root)) { cJSON_Delete(root); return -1; }
  const cJSON *status = cJSON_GetObjectItemCaseSensitive(root, "status");
  const cJSON *stage = cJSON_GetObjectItemCaseSensitive(root, "stage");
  const cJSON *error = cJSON_GetObjectItemCaseSensitive(root, "error");
  if (cJSON_IsString(status) && status->valuestring) snprintf(out->status, sizeof(out->status), "%s", status->valuestring);
  if (cJSON_IsString(stage) && stage->valuestring) snprintf(out->stage, sizeof(out->stage), "%s", stage->valuestring);
  if (cJSON_IsString(error) && error->valuestring) snprintf(out->detail, sizeof(out->detail), "%s", error->valuestring);
  cJSON_Delete(root);
  if (!edr_agent_update_journal_is_terminal(out->status)) return 1;
  out->succeeded = strcmp(out->status, "succeeded") == 0;
  out->exit_code = out->succeeded ? 0 : 1;
  if (!out->detail[0]) snprintf(out->detail, sizeof(out->detail), "agent update terminal status=%s stage=%s", out->status, out->stage);
  return 2;
}

int edr_agent_update_recover(const char *command_id, EdrAgentUpdateRecovery *out) {
  if (!out || !command_id || !command_id[0]) return -1;
  memset(out, 0, sizeof(*out));
#ifndef _WIN32
  return 0;
#else
  char safe_id[128], program_data[MAX_PATH], path[MAX_PATH];
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  snprintf(path, sizeof(path), "%s\\FDSecurity\\state\\agent-update-%s.journal.json", program_data, safe_id);
  FILE *file = fopen(path, "rb");
  if (!file) return errno == ENOENT ? 0 : -1;
  if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return -1; }
  long length = ftell(file);
  if (length <= 0 || length > 1024L * 1024L || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return -1; }
  char *json = (char *)malloc((size_t)length + 1u);
  if (!json || fread(json, 1, (size_t)length, file) != (size_t)length) { free(json); fclose(file); return -1; }
  json[length] = '\0'; fclose(file);
  int parse_rc = edr_agent_update_parse_journal(json, out);
  free(json);
  return parse_rc;
#endif
}

int edr_agent_update_execute(const char *command_id, const uint8_t *payload,
                             size_t payload_len, char *detail, size_t detail_cap) {
#ifndef _WIN32
  (void)command_id; (void)payload; (void)payload_len;
  snprintf(detail, detail_cap, "agent_update_v1 unsupported on non-Windows");
  return EDR_AGENT_UPDATE_EXIT_UNSUPPORTED;
#else
  EdrAgentUpdateRequest req;
  char reason[256];
  if (!edr_agent_update_parse_request(payload, payload_len, &req, reason, sizeof(reason))) {
    snprintf(detail, detail_cap, "%s", reason); return 2;
  }
  char temp[MAX_PATH], root[MAX_PATH], staged[MAX_PATH], manifest[MAX_PATH], launcher[MAX_PATH];
  DWORD n = GetTempPathA(sizeof(temp), temp);
  if (!n || n >= sizeof(temp)) { snprintf(detail, detail_cap, "cannot resolve update staging directory"); return 3; }
  snprintf(root, sizeof(root), "%sFDSecurity\\agent-update\\%s", temp, command_id ? command_id : "unknown");
  if (!CreateDirectoryA(root, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { snprintf(detail, detail_cap, "cannot create update staging directory"); return 3; }
  snprintf(staged, sizeof(staged), "%s\\FDSensor.next.exe", root);
  snprintf(manifest, sizeof(manifest), "%s\\runtime-manifest.json", root);
  snprintf(launcher, sizeof(launcher), "%s\\launch-update.ps1", root);
  if (edr_ingest_http_get_url_to_file(req.artifact_url, staged, EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES) != 0) {
    snprintf(detail, detail_cap, "authenticated update artifact download failed"); return 4;
  }
  if (req.runtime_manifest_url[0] && edr_ingest_http_get_url_to_file(req.runtime_manifest_url, manifest, 1024u * 1024u) != 0) {
    DeleteFileA(staged); snprintf(detail, detail_cap, "authenticated runtime manifest download failed"); return 5;
  }
  if (!write_launch_script(launcher, EDR_AGENT_UPDATE_SCRIPT_PATH, staged,
                           req.runtime_manifest_url[0] ? manifest : "", &req, command_id ? command_id : "")) {
    snprintf(detail, detail_cap, "cannot persist external updater launch script"); return 6;
  }
  char params[2 * MAX_PATH + 160];
  snprintf(params, sizeof(params), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"", launcher);
  HINSTANCE launched = ShellExecuteA(NULL, "open", "powershell.exe", params, root, SW_HIDE);
  if ((INT_PTR)launched <= 32) { snprintf(detail, detail_cap, "external updater launch failed code=%lld", (long long)(INT_PTR)launched); return 7; }
  snprintf(detail, detail_cap, "agent update staged and external updater launched command_id=%s target_version=%s", command_id ? command_id : "", req.target_version);
  return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
#endif
}
