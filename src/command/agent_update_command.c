#include "edr/agent_update_command.h"

#include "cJSON.h"
#include "edr/agent_update_event.h"
#include "edr/ingest_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <io.h>
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

static int copy_json_uint64(const cJSON *root, const char *name, uint64_t *out,
                            uint64_t maximum, char *reason, size_t reason_cap) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsNumber(item) || item->valuedouble < 1.0 ||
      item->valuedouble > (double)maximum ||
      item->valuedouble != (double)(uint64_t)item->valuedouble) {
    char message[160];
    snprintf(message, sizeof(message), "invalid agent_update numeric field: %s", name);
    return fail(reason, reason_cap, message);
  }
  *out = (uint64_t)item->valuedouble;
  return 1;
}

static int request_field_known(const char *name) {
  static const char *fields[] = {
    "schema", "task_id", "campaign_id", "operation", "initiated_by", "artifact_id",
    "artifact_url", "hash", "version", "arch", "internal_name",
    "publisher_thumbprint", "publisher_subject", "min_current_version",
    "max_current_version", "runtime_manifest_url", "runtime_manifest_sha256",
    "deployment_mode", "scheduled_task_name", "scheduled_task_path", "service_name",
    "min_free_bytes", "issued_at_unix_ms", "deadline_unix_ms", "health_observe_ms"
  };
  for (size_t i = 0u; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    if (name && strcmp(name, fields[i]) == 0) return 1;
  }
  return 0;
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
  for (const cJSON *field = root->child; field; field = field->next) {
    if (!request_field_known(field->string)) {
      cJSON_Delete(root); return fail(reason, reason_cap, "unknown agent_update payload field");
    }
    for (const cJSON *prior = root->child; prior != field; prior = prior->next) {
      if (prior->string && field->string && strcmp(prior->string, field->string) == 0) {
        cJSON_Delete(root); return fail(reason, reason_cap, "duplicate agent_update payload field");
      }
    }
  }
#define COPY(name, member, required) do { if (!copy_json_string(root, name, out->member, sizeof(out->member), required, reason, reason_cap)) goto invalid; } while (0)
  COPY("schema", schema, 1);
  COPY("task_id", task_id, 1);
  COPY("campaign_id", campaign_id, 0);
  COPY("operation", operation, 1);
  COPY("initiated_by", initiated_by, 1);
  COPY("artifact_id", artifact_id, 1);
  COPY("artifact_url", artifact_url, 1);
  COPY("hash", sha256, 1);
  COPY("version", target_version, 1);
  COPY("arch", architecture, 1);
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
  if (!copy_json_uint64(root, "issued_at_unix_ms", &out->issued_at_unix_ms,
                        9007199254740991ULL, reason, reason_cap) ||
      !copy_json_uint64(root, "deadline_unix_ms", &out->deadline_unix_ms,
                        9007199254740991ULL, reason, reason_cap) ||
      !copy_json_uint64(root, "health_observe_ms", &out->health_observe_ms,
                        86400000ULL, reason, reason_cap)) goto invalid;
  if (strcmp(out->schema, "edr.agent_update.v1") != 0) {
    fail(reason, reason_cap, "agent_update schema must be edr.agent_update.v1"); goto invalid;
  }
  if (strcmp(out->operation, "upgrade") && strcmp(out->operation, "rollback")) {
    fail(reason, reason_cap, "agent_update operation must be upgrade or rollback"); goto invalid;
  }
  if (strcmp(out->initiated_by, "operator") != 0) {
    fail(reason, reason_cap, "agent_update initiated_by must be operator"); goto invalid;
  }
  if (out->deadline_unix_ms <= out->issued_at_unix_ms) {
    fail(reason, reason_cap, "agent_update deadline must be after issued_at_unix_ms"); goto invalid;
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
  if (out->min_current_version[0] && out->max_current_version[0] &&
      (!edr_agent_update_semver_compare(out->min_current_version,
                                        out->max_current_version, &cmp) || cmp > 0)) {
    fail(reason, reason_cap, "min_current_version must not exceed max_current_version"); goto invalid;
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
    req->scheduled_task_path, req->service_name, command_id, manifest, req->runtime_manifest_sha256,
    req->task_id, req->campaign_id, req->operation, req->artifact_id };
  char quoted[21][4600];
  for (size_t i = 0; i < 21u; ++i) if (!quote_ps(values[i], quoted[i], sizeof(quoted[i]))) return 0;
  FILE *file = fopen(path, "wb");
  if (!file) return 0;
  fprintf(file, "$ErrorActionPreference='Stop'\r\n& %s -StagedBinary %s -ExpectedSha256 %s -TargetVersion %s -ExpectedArchitecture %s -ExpectedInternalName %s -TrustedPublisherThumbprint %s -TrustedPublisherSubject %s -MinCurrentVersion %s -MaxCurrentVersion %s -DeploymentMode %s -ScheduledTaskName %s -ScheduledTaskPath %s -ServiceName %s -CommandId %s -RuntimeManifest %s -RuntimeManifestSha256 %s -TaskId %s -CampaignId %s -Operation %s -ArtifactId %s -MinFreeBytes %llu -IssuedAtUnixMs %llu -DeadlineUnixMs %llu -HealthObserveMs %llu\r\nexit $LASTEXITCODE\r\n",
          quoted[0], quoted[1], quoted[2], quoted[3], quoted[4], quoted[5], quoted[6], quoted[7], quoted[8], quoted[9], quoted[10], quoted[11], quoted[12], quoted[13], quoted[14], quoted[15], quoted[16], quoted[17], quoted[18], quoted[19], quoted[20], (unsigned long long)req->min_free_bytes, (unsigned long long)req->issued_at_unix_ms, (unsigned long long)req->deadline_unix_ms, (unsigned long long)req->health_observe_ms);
  return fclose(file) == 0;
}
#endif

#ifdef _WIN32
static void safe_command_id(const char *command_id, char *out, size_t cap) {
  size_t used = 0;
  for (const unsigned char *p = (const unsigned char *)(command_id ? command_id : ""); *p && used + 1u < cap; ++p) {
    out[used++] = (isalnum(*p) || *p == '.' || *p == '_' || *p == '-') ? (char)*p : '_';
  }
  out[used] = '\0';
}
#endif

static int journal_string(const cJSON *root, const char *name, char *out, size_t cap) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsString(item) || !item->valuestring || !item->valuestring[0] ||
      strlen(item->valuestring) >= cap) return 0;
  snprintf(out, cap, "%s", item->valuestring);
  return 1;
}

static int journal_uint64(const cJSON *root, const char *name, uint64_t *out) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsNumber(item) || item->valuedouble < 0.0 ||
      item->valuedouble > 9007199254740991.0 ||
      item->valuedouble != (double)(uint64_t)item->valuedouble) return 0;
  *out = (uint64_t)item->valuedouble;
  return 1;
}

int edr_agent_update_parse_journal(const char *json, EdrAgentUpdateRecovery *out) {
  if (!json || !out) return -1;
  memset(out, 0, sizeof(*out));
  cJSON *root = cJSON_Parse(json);
  if (!cJSON_IsObject(root)) { cJSON_Delete(root); return -1; }
  const cJSON *schema = cJSON_GetObjectItemCaseSensitive(root, "schema_version");
  const cJSON *error = cJSON_GetObjectItemCaseSensitive(root, "error");
  const cJSON *events = cJSON_GetObjectItemCaseSensitive(root, "events");
  if (!cJSON_IsNumber(schema) || schema->valuedouble != 2.0 ||
      !journal_string(root, "task_id", out->task_id, sizeof(out->task_id)) ||
      !journal_string(root, "command_id", out->command_id, sizeof(out->command_id)) ||
      !journal_string(root, "operation", out->operation, sizeof(out->operation)) ||
      !journal_string(root, "artifact_id", out->artifact_id, sizeof(out->artifact_id)) ||
      !journal_string(root, "hash", out->artifact_sha256, sizeof(out->artifact_sha256)) ||
      !journal_string(root, "version", out->target_version, sizeof(out->target_version)) ||
      !journal_string(root, "status", out->status, sizeof(out->status)) ||
      !journal_string(root, "stage", out->stage, sizeof(out->stage)) ||
      !journal_uint64(root, "last_event_seq", &out->last_event_seq) ||
      !is_hex(out->artifact_sha256, 64u) ||
      (strcmp(out->operation, "upgrade") && strcmp(out->operation, "rollback")) ||
      !cJSON_IsArray(events)) {
    cJSON_Delete(root); memset(out, 0, sizeof(*out)); return -1;
  }
  if (out->last_event_seq > 2u && cJSON_GetArraySize(events) == 0) {
    cJSON_Delete(root); memset(out, 0, sizeof(*out)); return -1;
  }
  uint64_t previous_seq = 0u;
  const cJSON *event = NULL;
  cJSON_ArrayForEach(event, events) {
    uint64_t seq = 0u;
    char event_status[32];
    if (!cJSON_IsObject(event) || !journal_uint64(event, "event_seq", &seq) || seq == 0u ||
        seq <= previous_seq || seq > out->last_event_seq ||
        !journal_string(event, "status", event_status, sizeof(event_status))) {
      cJSON_Delete(root); memset(out, 0, sizeof(*out)); return -1;
    }
    previous_seq = seq;
  }
  if (previous_seq != 0u && previous_seq != out->last_event_seq) {
    cJSON_Delete(root); memset(out, 0, sizeof(*out)); return -1;
  }
  if (cJSON_IsString(error) && error->valuestring)
    snprintf(out->detail, sizeof(out->detail), "%s", error->valuestring);
  cJSON_Delete(root);
  if (!edr_agent_update_journal_is_terminal(out->status)) return 1;
  out->succeeded = strcmp(out->status, "succeeded") == 0;
  out->exit_code = out->succeeded ? 0 : 1;
  if (!out->detail[0]) snprintf(out->detail, sizeof(out->detail), "agent update finished");
  return 2;
}

#ifdef _WIN32
static int event_command_dir(const char *command_id, char *out, size_t cap);

static int same_hex(const char *left, const char *right) {
  if (!left || !right || strlen(left) != strlen(right)) return 0;
  while (*left) {
    if (tolower((unsigned char)*left++) != tolower((unsigned char)*right++)) return 0;
  }
  return 1;
}

static int import_journal_events(const cJSON *root, const EdrAgentUpdateRequest *req,
                                 const char *command_id, const char *outbox_dir) {
  EdrAgentUpdateEventContext context;
  memset(&context, 0, sizeof(context));
  snprintf(context.task_id, sizeof(context.task_id), "%s", req->task_id);
  snprintf(context.campaign_id, sizeof(context.campaign_id), "%s", req->campaign_id);
  snprintf(context.command_id, sizeof(context.command_id), "%s", command_id);
  snprintf(context.operation, sizeof(context.operation), "%s", req->operation);
  snprintf(context.artifact_id, sizeof(context.artifact_id), "%s", req->artifact_id);
  snprintf(context.artifact_sha256, sizeof(context.artifact_sha256), "%s", req->sha256);
  snprintf(context.target_version, sizeof(context.target_version), "%s", req->target_version);
  const cJSON *events = cJSON_GetObjectItemCaseSensitive(root, "events");
  const cJSON *event = NULL;
  cJSON_ArrayForEach(event, events) {
    uint64_t seq = 0u;
    char status[32], reported_at[64] = "";
    const cJSON *progress = cJSON_GetObjectItemCaseSensitive(event, "progress");
    const cJSON *detail = cJSON_GetObjectItemCaseSensitive(event, "detail");
    const cJSON *reported = cJSON_GetObjectItemCaseSensitive(event, "reported_at");
    if (!journal_uint64(event, "event_seq", &seq) ||
        !journal_string(event, "status", status, sizeof(status)) ||
        !cJSON_IsNumber(progress) || progress->valuedouble < 0 || progress->valuedouble > 100 ||
        progress->valuedouble != (double)(int)progress->valuedouble || !cJSON_IsObject(detail)) return -1;
    if (cJSON_IsString(reported) && reported->valuestring)
      snprintf(reported_at, sizeof(reported_at), "%s", reported->valuestring);
    char *detail_json = cJSON_PrintUnformatted(detail);
    if (!detail_json) return -1;
    int rc = edr_agent_update_event_persist(outbox_dir, &context, seq, status,
                                             (int)progress->valuedouble, detail_json,
                                             reported_at);
    free(detail_json);
    if (rc != 0) return -1;
  }
  return 0;
}
#endif

int edr_agent_update_recover(const char *command_id, const uint8_t *payload,
                             size_t payload_len, EdrAgentUpdateRecovery *out) {
  if (!out || !command_id || !command_id[0] || !payload || !payload_len) return -1;
  memset(out, 0, sizeof(*out));
#ifndef _WIN32
  return 0;
#else
  EdrAgentUpdateRequest req;
  char reason[256];
  if (!edr_agent_update_parse_request(payload, payload_len, &req, reason, sizeof(reason))) return -1;
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
  cJSON *root = parse_rc >= 1 ? cJSON_Parse(json) : NULL;
  free(json);
  if (!cJSON_IsObject(root) || strcmp(out->task_id, req.task_id) ||
      strcmp(out->command_id, command_id) || strcmp(out->operation, req.operation) ||
      strcmp(out->artifact_id, req.artifact_id) || !same_hex(out->artifact_sha256, req.sha256) ||
      strcmp(out->target_version, req.target_version)) {
    cJSON_Delete(root); memset(out, 0, sizeof(*out)); return -1;
  }
  char outbox_dir[MAX_PATH];
  if (!event_command_dir(command_id, outbox_dir, sizeof(outbox_dir))) return -1;
  if (import_journal_events(root, &req, command_id, outbox_dir) != 0) {
    cJSON_Delete(root); return -1;
  }
  cJSON_Delete(root);
  uint64_t last_acked = 0u;
  if (edr_agent_update_event_flush_ingest(outbox_dir, &last_acked) < 0) return -1;
  out->terminal_event_acked = parse_rc == 2 && last_acked >= out->last_event_seq;
  return out->terminal_event_acked ? 2 : 1;
#endif
}

#ifdef _WIN32
static void event_context_from_request(const EdrAgentUpdateRequest *req,
                                       const char *command_id,
                                       EdrAgentUpdateEventContext *context);

static int event_command_dir(const char *command_id, char *out, size_t cap) {
  char root[512], safe_id[160];
  if (!command_id || !command_id[0]) return 0;
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  if (!safe_id[0]) return 0;
  edr_agent_update_event_default_dir(root, sizeof(root));
#ifdef _WIN32
  int n = snprintf(out, cap, "%s\\%s", root, safe_id);
#else
  int n = snprintf(out, cap, "%s/%s", root, safe_id);
#endif
  return n > 0 && (size_t)n < cap;
}

static int write_failure_journal(const EdrAgentUpdateRequest *req, const char *command_id,
                                 uint64_t event_seq, const char *stage, const char *error) {
  char safe_id[128], program_data[MAX_PATH], state_dir[MAX_PATH], path[MAX_PATH], temporary[MAX_PATH];
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  snprintf(state_dir, sizeof(state_dir), "%s\\FDSecurity\\state", program_data);
  CreateDirectoryA(program_data, NULL);
  char fd_dir[MAX_PATH];
  snprintf(fd_dir, sizeof(fd_dir), "%s\\FDSecurity", program_data);
  CreateDirectoryA(fd_dir, NULL);
  if (!CreateDirectoryA(state_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return -1;
  snprintf(path, sizeof(path), "%s\\agent-update-%s.journal.json", state_dir, safe_id);
  snprintf(temporary, sizeof(temporary), "%s.tmp-%lu", path, (unsigned long)GetCurrentProcessId());
  cJSON *root = cJSON_CreateObject();
  cJSON *events = cJSON_CreateArray();
  cJSON *event = cJSON_CreateObject();
  cJSON *detail = cJSON_CreateObject();
  if (!root || !events || !event || !detail) goto failed;
#define ADD(object, name, value) do { if (!cJSON_AddStringToObject(object, name, value)) goto failed; } while (0)
  if (!cJSON_AddNumberToObject(root, "schema_version", 2)) goto failed;
  ADD(root, "task_id", req->task_id); ADD(root, "command_id", command_id);
  ADD(root, "operation", req->operation); ADD(root, "artifact_id", req->artifact_id);
  ADD(root, "hash", req->sha256); ADD(root, "version", req->target_version);
  ADD(root, "status", "failed"); ADD(root, "stage", stage); ADD(root, "error", error);
  if (!cJSON_AddNumberToObject(root, "last_event_seq", (double)event_seq) ||
      !cJSON_AddNumberToObject(event, "event_seq", (double)event_seq)) goto failed;
  ADD(event, "status", "failed");
  if (!cJSON_AddNumberToObject(event, "progress", 100)) goto failed;
  ADD(detail, "stage", stage); ADD(detail, "error", error);
  if (!cJSON_AddItemToObject(event, "detail", detail)) goto failed;
  detail = NULL;
  if (!cJSON_AddItemToArray(events, event)) goto failed;
  event = NULL;
  if (!cJSON_AddItemToObject(root, "events", events)) goto failed;
  events = NULL;
#undef ADD
  char *body = cJSON_PrintUnformatted(root);
  if (!body) goto failed;
  FILE *file = fopen(temporary, "wb");
  if (!file) { free(body); goto failed; }
  size_t length = strlen(body);
  int ok = fwrite(body, 1u, length, file) == length && fflush(file) == 0 &&
           _commit(_fileno(file)) == 0 && fclose(file) == 0;
  free(body);
  if (!ok || !MoveFileExA(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    remove(temporary); goto failed;
  }
  cJSON_Delete(root);
  return 0;
failed:
  cJSON_Delete(detail); cJSON_Delete(event); cJSON_Delete(events); cJSON_Delete(root);
  return -1;
}

static int update_failure(const EdrAgentUpdateRequest *req, const char *command_id,
                          const char *outbox_dir, uint64_t event_seq,
                          const char *stage, const char *error,
                          int exit_code, char *detail, size_t detail_cap) {
  EdrAgentUpdateEventContext context;
  event_context_from_request(req, command_id, &context);
  char detail_json[1400];
  cJSON *detail_object = cJSON_CreateObject();
  char *printed = NULL;
  if (detail_object && cJSON_AddStringToObject(detail_object, "stage", stage) &&
      cJSON_AddStringToObject(detail_object, "error", error)) printed = cJSON_PrintUnformatted(detail_object);
  if (!printed || edr_agent_update_event_persist(outbox_dir, &context, event_seq,
                                                  "failed", 100, printed, NULL) != 0 ||
      write_failure_journal(req, command_id, event_seq, stage, error) != 0) {
    snprintf(detail, detail_cap, "agent update failure persistence pending");
    free(printed); cJSON_Delete(detail_object); return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  free(printed); cJSON_Delete(detail_object);
  uint64_t acked = 0u;
  (void)edr_agent_update_event_flush_ingest(outbox_dir, &acked);
  if (acked < event_seq) {
    snprintf(detail, detail_cap, "agent update terminal event pending acknowledgement");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  snprintf(detail, detail_cap, "agent update failed; terminal event acknowledged");
  return exit_code;
}

static void event_context_from_request(const EdrAgentUpdateRequest *req,
                                       const char *command_id,
                                       EdrAgentUpdateEventContext *context) {
  memset(context, 0, sizeof(*context));
  snprintf(context->task_id, sizeof(context->task_id), "%s", req->task_id);
  snprintf(context->campaign_id, sizeof(context->campaign_id), "%s", req->campaign_id);
  snprintf(context->command_id, sizeof(context->command_id), "%s", command_id ? command_id : "");
  snprintf(context->operation, sizeof(context->operation), "%s", req->operation);
  snprintf(context->artifact_id, sizeof(context->artifact_id), "%s", req->artifact_id);
  snprintf(context->artifact_sha256, sizeof(context->artifact_sha256), "%s", req->sha256);
  snprintf(context->target_version, sizeof(context->target_version), "%s", req->target_version);
}
#endif

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
  if (!command_id || !command_id[0]) {
    snprintf(detail, detail_cap, "agent_update command_id required"); return 2;
  }
  char outbox_dir[MAX_PATH];
  EdrAgentUpdateEventContext event_context;
  event_context_from_request(&req, command_id, &event_context);
  if (!event_command_dir(command_id, outbox_dir, sizeof(outbox_dir))) {
    snprintf(detail, detail_cap, "agent update event outbox path unavailable");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  const char *first_status = strcmp(req.operation, "rollback") == 0 ? "rolling_back" : "downloading";
  if (edr_agent_update_event_persist(outbox_dir, &event_context, 1u, first_status, 5,
                                     "{\"stage\":\"artifact_download\"}", NULL) != 0) {
    (void)write_failure_journal(&req, command_id, 1u, "event_persist",
                                "cannot persist downloading update event");
    snprintf(detail, detail_cap, "downloading update event persistence pending");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  (void)edr_agent_update_event_flush_ingest(outbox_dir, NULL);
  char temp[MAX_PATH], root[MAX_PATH], staged[MAX_PATH], manifest[MAX_PATH], launcher[MAX_PATH];
  DWORD n = GetTempPathA(sizeof(temp), temp);
  if (!n || n >= sizeof(temp))
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "cannot resolve update staging directory", 3, detail, detail_cap);
  snprintf(root, sizeof(root), "%sFDSecurity\\agent-update\\%s", temp, command_id ? command_id : "unknown");
  if (!CreateDirectoryA(root, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "cannot create update staging directory", 3, detail, detail_cap);
  snprintf(staged, sizeof(staged), "%s\\FDSensor.next.exe", root);
  snprintf(manifest, sizeof(manifest), "%s\\runtime-manifest.json", root);
  snprintf(launcher, sizeof(launcher), "%s\\launch-update.ps1", root);
  if (edr_ingest_http_get_url_to_file(req.artifact_url, staged, EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES) != 0) {
    return update_failure(&req, command_id, outbox_dir, 2u, "artifact_download",
                          "authenticated update artifact download failed", 4, detail, detail_cap);
  }
  if (req.runtime_manifest_url[0] && edr_ingest_http_get_url_to_file(req.runtime_manifest_url, manifest, 1024u * 1024u) != 0) {
    DeleteFileA(staged);
    return update_failure(&req, command_id, outbox_dir, 2u, "runtime_manifest_download",
                          "authenticated runtime manifest download failed", 5, detail, detail_cap);
  }
  const char *second_status = strcmp(req.operation, "rollback") == 0 ? "rolling_back" : "downloaded";
  if (edr_agent_update_event_persist(outbox_dir, &event_context, 2u, second_status, 20,
                                     "{\"stage\":\"artifact_downloaded\"}", NULL) != 0) {
    DeleteFileA(staged); DeleteFileA(manifest);
    (void)write_failure_journal(&req, command_id, 2u, "event_persist",
                                "cannot persist downloaded update event");
    snprintf(detail, detail_cap, "downloaded update event persistence pending");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  (void)edr_agent_update_event_flush_ingest(outbox_dir, NULL);
  if (!write_launch_script(launcher, EDR_AGENT_UPDATE_SCRIPT_PATH, staged,
                           req.runtime_manifest_url[0] ? manifest : "", &req, command_id ? command_id : "")) {
    return update_failure(&req, command_id, outbox_dir, 3u, "launcher_persist",
                          "cannot persist external updater launch script", 6, detail, detail_cap);
  }
  char params[2 * MAX_PATH + 160];
  snprintf(params, sizeof(params), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"", launcher);
  HINSTANCE launched = ShellExecuteA(NULL, "open", "powershell.exe", params, root, SW_HIDE);
  if ((INT_PTR)launched <= 32) {
    char launch_error[128];
    snprintf(launch_error, sizeof(launch_error), "external updater launch failed code=%lld",
             (long long)(INT_PTR)launched);
    return update_failure(&req, command_id, outbox_dir, 3u, "launcher_start",
                          launch_error, 7, detail, detail_cap);
  }
  snprintf(detail, detail_cap, "agent update staged and external updater launched command_id=%s target_version=%s", command_id ? command_id : "", req.target_version);
  return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
#endif
}
