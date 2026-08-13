#include "edr/agent_update_command.h"

#include "cJSON.h"
#include "edr/agent_update_event.h"
#include "edr/command_cancel.h"
#include "edr/ingest_http.h"
#include "edr/sha256.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "edr/windows_resource_ids.h"
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

#ifdef _WIN32
enum embedded_updater_result {
  EMBEDDED_UPDATER_FAILED = -1,
  EMBEDDED_UPDATER_ABSENT = 0,
  EMBEDDED_UPDATER_READY = 1
};

static void runtime_info_error(EdrAgentUpdateRuntimeInfo *info, const char *source,
                               const char *error_code) {
  if (!info) return;
  info->ready = 0;
  snprintf(info->source, sizeof(info->source), "%s", source ? source : "unavailable");
  snprintf(info->version, sizeof(info->version), "%s", EDR_AGENT_VERSION_STRING);
  snprintf(info->error_code, sizeof(info->error_code), "%s",
           error_code ? error_code : "updater_unavailable");
}

static int file_sha256(const char *path, char out65[65]) {
  if (!path || !path[0] || !out65) return 0;
  FILE *file = fopen(path, "rb");
  if (!file) return 0;
  EdrSha256Ctx context;
  edr_sha256_init(&context);
  unsigned char buffer[16384];
  int ok = 1;
  for (;;) {
    size_t count = fread(buffer, 1u, sizeof(buffer), file);
    if (count > 0u) edr_sha256_update(&context, buffer, count);
    if (count < sizeof(buffer)) {
      if (ferror(file)) ok = 0;
      break;
    }
  }
  if (fclose(file) != 0) ok = 0;
  if (!ok) return 0;
  unsigned char digest[EDR_SHA256_DIGEST_LEN];
  edr_sha256_final(&context, digest);
  for (size_t i = 0u; i < EDR_SHA256_DIGEST_LEN; ++i) {
    snprintf(out65 + i * 2u, 3u, "%02x", digest[i]);
  }
  out65[64] = '\0';
  return 1;
}

static int file_time_is_older_than(const FILETIME *value, ULONGLONG age_100ns) {
  if (!value) return 0;
  FILETIME now_file_time;
  GetSystemTimeAsFileTime(&now_file_time);
  ULARGE_INTEGER now, then;
  now.LowPart = now_file_time.dwLowDateTime;
  now.HighPart = now_file_time.dwHighDateTime;
  then.LowPart = value->dwLowDateTime;
  then.HighPart = value->dwHighDateTime;
  return now.QuadPart > then.QuadPart && now.QuadPart - then.QuadPart > age_100ns;
}

static void cleanup_old_materialized_updaters(const char *directory, const char *current_path) {
  if (!directory || !directory[0] || !current_path || !current_path[0]) return;
  char pattern[MAX_PATH];
  int written = snprintf(pattern, sizeof(pattern), "%s\\edr_agent_inplace_update-*", directory);
  if (written <= 0 || (size_t)written >= sizeof(pattern)) return;
  WIN32_FIND_DATAA entry;
  HANDLE search = FindFirstFileA(pattern, &entry);
  if (search == INVALID_HANDLE_VALUE) return;
  const ULONGLONG day = 24ULL * 60ULL * 60ULL * 10000000ULL;
  do {
    if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char candidate[MAX_PATH];
    written = snprintf(candidate, sizeof(candidate), "%s\\%s", directory, entry.cFileName);
    if (written <= 0 || (size_t)written >= sizeof(candidate) ||
        _stricmp(candidate, current_path) == 0) continue;
    const char *temporary = strstr(entry.cFileName, ".tmp-");
    size_t name_len = strlen(entry.cFileName);
    int versioned_script = name_len >= 4u &&
        _stricmp(entry.cFileName + name_len - 4u, ".ps1") == 0;
    ULONGLONG minimum_age = temporary ? day : 7ULL * day;
    if ((temporary || versioned_script) &&
        file_time_is_older_than(&entry.ftLastWriteTime, minimum_age)) {
      (void)DeleteFileA(candidate);
    }
  } while (FindNextFileA(search, &entry));
  FindClose(search);
}

static enum embedded_updater_result materialize_embedded_update_script(
    char *out, size_t out_cap, EdrAgentUpdateRuntimeInfo *info) {
  HMODULE module = GetModuleHandleA(NULL);
  if (!module) {
    runtime_info_error(info, "embedded", "embedded_module_unavailable");
    return EMBEDDED_UPDATER_FAILED;
  }
  SetLastError(ERROR_SUCCESS);
  HRSRC resource = FindResourceA(module, MAKEINTRESOURCEA(IDR_EDR_AGENT_UPDATE_SCRIPT), RT_RCDATA);
  if (!resource) {
    DWORD error = GetLastError();
    if (error == ERROR_RESOURCE_TYPE_NOT_FOUND || error == ERROR_RESOURCE_NAME_NOT_FOUND ||
        error == ERROR_RESOURCE_LANG_NOT_FOUND) {
      return EMBEDDED_UPDATER_ABSENT;
    }
    runtime_info_error(info, "embedded", "embedded_resource_lookup_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  HGLOBAL loaded = resource ? LoadResource(module, resource) : NULL;
  DWORD size = resource ? SizeofResource(module, resource) : 0u;
  const void *bytes = loaded ? LockResource(loaded) : NULL;
  if (!bytes || size == 0u) {
    runtime_info_error(info, "embedded", "embedded_resource_read_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  char embedded_sha256[65];
  if (edr_sha256_hex((const uint8_t *)bytes, (size_t)size, embedded_sha256) != 0) {
    runtime_info_error(info, "embedded", "embedded_resource_hash_failed");
    return EMBEDDED_UPDATER_FAILED;
  }

  char module_path[MAX_PATH], directory[MAX_PATH], version[96];
  DWORD module_path_len = GetModuleFileNameA(NULL, module_path, (DWORD)sizeof(module_path));
  if (module_path_len == 0u || module_path_len >= sizeof(module_path)) {
    runtime_info_error(info, "embedded", "embedded_module_path_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  char *slash = strrchr(module_path, '\\');
  char *forward = strrchr(module_path, '/');
  if (!slash || (forward && forward > slash)) slash = forward;
  if (!slash) {
    runtime_info_error(info, "embedded", "embedded_module_directory_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  *slash = '\0';
  int written = snprintf(directory, sizeof(directory), "%s", module_path);
  if (written <= 0 || (size_t)written >= sizeof(directory)) {
    runtime_info_error(info, "embedded", "embedded_module_directory_failed");
    return EMBEDDED_UPDATER_FAILED;
  }

  size_t version_len = 0u;
  for (const unsigned char *p = (const unsigned char *)EDR_AGENT_VERSION_STRING;
       *p && version_len + 1u < sizeof(version); ++p) {
    version[version_len++] = (isalnum(*p) || *p == '.' || *p == '-' || *p == '_') ? (char)*p : '_';
  }
  if (version_len == 0u) version[version_len++] = '0';
  version[version_len] = '\0';

  char final_path[MAX_PATH], temporary_path[MAX_PATH];
  written = snprintf(final_path, sizeof(final_path), "%s\\edr_agent_inplace_update-%s.ps1", directory, version);
  if (written <= 0 || (size_t)written >= sizeof(final_path)) {
    runtime_info_error(info, "embedded", "embedded_materialized_path_too_long");
    return EMBEDDED_UPDATER_FAILED;
  }
  written = snprintf(temporary_path, sizeof(temporary_path), "%s.tmp-%lu-%lu", final_path,
                     (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId());
  if (written <= 0 || (size_t)written >= sizeof(temporary_path)) {
    runtime_info_error(info, "embedded", "embedded_temporary_path_too_long");
    return EMBEDDED_UPDATER_FAILED;
  }

  char existing_sha256[65];
  if (file_sha256(final_path, existing_sha256) &&
      _stricmp(existing_sha256, embedded_sha256) == 0) {
    written = snprintf(out, out_cap, "%s", final_path);
    if (written <= 0 || (size_t)written >= out_cap) {
      runtime_info_error(info, "embedded", "embedded_output_path_too_long");
      return EMBEDDED_UPDATER_FAILED;
    }
    info->ready = 1;
    info->protocol_version = EDR_AGENT_UPDATE_UPDATER_PROTOCOL_VERSION;
    info->materialized = 1;
    snprintf(info->source, sizeof(info->source), "embedded");
    snprintf(info->version, sizeof(info->version), "%s", EDR_AGENT_VERSION_STRING);
    snprintf(info->sha256, sizeof(info->sha256), "%s", embedded_sha256);
    info->error_code[0] = '\0';
    cleanup_old_materialized_updaters(directory, final_path);
    return EMBEDDED_UPDATER_READY;
  }

  HANDLE file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    runtime_info_error(info, "embedded", "embedded_materialize_open_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  DWORD offset = 0u;
  int ok = 1;
  while (offset < size) {
    DWORD chunk = 0u;
    if (!WriteFile(file, (const unsigned char *)bytes + offset, size - offset, &chunk, NULL) || chunk == 0u) {
      ok = 0;
      break;
    }
    offset += chunk;
  }
  if (ok && !FlushFileBuffers(file)) ok = 0;
  CloseHandle(file);
  if (!ok || !MoveFileExA(temporary_path, final_path,
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileA(temporary_path);
    runtime_info_error(info, "embedded", "embedded_materialize_commit_failed");
    return EMBEDDED_UPDATER_FAILED;
  }
  if (!file_sha256(final_path, existing_sha256) ||
      _stricmp(existing_sha256, embedded_sha256) != 0) {
    (void)DeleteFileA(final_path);
    runtime_info_error(info, "embedded", "embedded_materialized_hash_mismatch");
    return EMBEDDED_UPDATER_FAILED;
  }
  written = snprintf(out, out_cap, "%s", final_path);
  if (written <= 0 || (size_t)written >= out_cap) {
    runtime_info_error(info, "embedded", "embedded_output_path_too_long");
    return EMBEDDED_UPDATER_FAILED;
  }
  info->ready = 1;
  info->protocol_version = EDR_AGENT_UPDATE_UPDATER_PROTOCOL_VERSION;
  info->materialized = 1;
  snprintf(info->source, sizeof(info->source), "embedded");
  snprintf(info->version, sizeof(info->version), "%s", EDR_AGENT_VERSION_STRING);
  snprintf(info->sha256, sizeof(info->sha256), "%s", embedded_sha256);
  info->error_code[0] = '\0';
  cleanup_old_materialized_updaters(directory, final_path);
  return EMBEDDED_UPDATER_READY;
}
#endif

static int fail(char *reason, size_t cap, const char *message) {
  if (reason && cap) snprintf(reason, cap, "%s", message ? message : "agent update failed");
  return 0;
}

int edr_agent_update_get_runtime_info(EdrAgentUpdateRuntimeInfo *info,
                                      char *script_path, size_t script_path_cap) {
  if (!info || !script_path || script_path_cap == 0u) return 0;
  memset(info, 0, sizeof(*info));
  script_path[0] = '\0';
#ifndef _WIN32
  snprintf(info->source, sizeof(info->source), "unsupported");
  snprintf(info->version, sizeof(info->version), "%s", EDR_AGENT_VERSION_STRING);
  snprintf(info->error_code, sizeof(info->error_code), "non_windows");
  return 0;
#else
  enum embedded_updater_result embedded =
      materialize_embedded_update_script(script_path, script_path_cap, info);
  if (embedded == EMBEDDED_UPDATER_READY) return 1;
  if (embedded == EMBEDDED_UPDATER_FAILED) return 0;
  char module[MAX_PATH];
  DWORD length = GetModuleFileNameA(NULL, module, (DWORD)sizeof(module));
  if (length > 0u && length < sizeof(module)) {
    char *slash = strrchr(module, '\\');
    char *forward = strrchr(module, '/');
    if (!slash || (forward && forward > slash)) slash = forward;
    if (slash) {
      slash[1] = '\0';
      int written = snprintf(script_path, script_path_cap, "%sedr_agent_inplace_update.ps1", module);
      if (written > 0 && (size_t)written < script_path_cap) {
        DWORD attrs = GetFileAttributesA(script_path);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
          if (!file_sha256(script_path, info->sha256)) {
            runtime_info_error(info, "installed_sidecar", "installed_sidecar_unreadable");
            script_path[0] = '\0';
            return 0;
          }
          info->ready = 1;
          info->protocol_version = 1;
          snprintf(info->source, sizeof(info->source), "installed_sidecar");
          snprintf(info->version, sizeof(info->version), "legacy");
          return 1;
        }
      }
    }
  }
  int written = snprintf(script_path, script_path_cap, "%s", EDR_AGENT_UPDATE_SCRIPT_PATH);
  if (written > 0 && (size_t)written < script_path_cap) {
    DWORD attrs = GetFileAttributesA(script_path);
    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      if (!file_sha256(script_path, info->sha256)) {
        runtime_info_error(info, "configured_sidecar", "configured_sidecar_unreadable");
        script_path[0] = '\0';
        return 0;
      }
      info->ready = 1;
      info->protocol_version = 1;
      snprintf(info->source, sizeof(info->source), "configured_sidecar");
      snprintf(info->version, sizeof(info->version), "legacy");
      return 1;
    }
  }
  runtime_info_error(info, "unavailable", "embedded_and_sidecar_missing");
  script_path[0] = '\0';
  return 0;
#endif
}

int edr_agent_update_resolve_script_path(char *out, size_t out_cap) {
  EdrAgentUpdateRuntimeInfo info;
  return edr_agent_update_get_runtime_info(&info, out, out_cap);
}

#ifdef _WIN32
static int agent_update_create_directory(const char *path) {
  if (CreateDirectoryA(path, NULL)) return 1;
  if (GetLastError() != ERROR_ALREADY_EXISTS) return 0;
  DWORD attrs = GetFileAttributesA(path);
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0u;
}
#endif

int edr_agent_update_create_directories(const char *path) {
#ifndef _WIN32
  (void)path;
  return 0;
#else
  char copy[MAX_PATH];
  size_t length;
  if (!path || !path[0] || strlen(path) >= sizeof(copy)) return 0;
  snprintf(copy, sizeof(copy), "%s", path);
  length = strlen(copy);
  while (length > 0u && (copy[length - 1u] == '\\' || copy[length - 1u] == '/')) {
    copy[--length] = '\0';
  }
  if (length == 0u) return 0;
  for (size_t i = 1u; i < length; ++i) {
    if (copy[i] != '\\' && copy[i] != '/') continue;
    if (i == 2u && copy[1] == ':') continue;
    char saved = copy[i];
    copy[i] = '\0';
    if (!agent_update_create_directory(copy)) {
      copy[i] = saved;
      return 0;
    }
    copy[i] = saved;
  }
  return agent_update_create_directory(copy);
#endif
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
    "upgrade_class",
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
  COPY("upgrade_class", upgrade_class, 0);
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
  if (!out->upgrade_class[0]) snprintf(out->upgrade_class, sizeof(out->upgrade_class), "%s",
                                       out->runtime_manifest_url[0] ? "runtime_bundle" : "binary_hot");
  if (strcmp(out->upgrade_class, "binary_hot") && strcmp(out->upgrade_class, "runtime_bundle") &&
      strcmp(out->upgrade_class, "installer_required")) {
    fail(reason, reason_cap, "upgrade_class must be binary_hot, runtime_bundle, or installer_required"); goto invalid;
  }
  if (strcmp(out->upgrade_class, "binary_hot") && !out->runtime_manifest_url[0]) {
    fail(reason, reason_cap, "selected upgrade_class requires a task-pinned package"); goto invalid;
  }
  if (!out->deployment_mode[0]) snprintf(out->deployment_mode, sizeof(out->deployment_mode), "auto");
  if (strcmp(out->deployment_mode, "auto") && strcmp(out->deployment_mode, "scheduled_task") && strcmp(out->deployment_mode, "service")) {
    fail(reason, reason_cap, "deployment_mode must be auto, scheduled_task, or service"); goto invalid;
  }
  if (!out->scheduled_task_name[0]) {
    snprintf(out->scheduled_task_name, sizeof(out->scheduled_task_name), "FDSecurityAgent");
  }
  if (!out->scheduled_task_path[0]) {
    snprintf(out->scheduled_task_path, sizeof(out->scheduled_task_path), "\\");
  }
  if (!out->service_name[0]) {
    snprintf(out->service_name, sizeof(out->service_name), "FDSecurityAgent");
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

static int write_update_invocation_script(const char *path, const char *updater, const char *staged,
                                          const char *manifest, const EdrAgentUpdateRequest *req,
                                          const char *command_id, const char *updater_task_name,
                                          const char *staging_directory) {
  const char *values[] = { updater, staged, req->sha256, req->target_version, req->architecture,
    req->internal_name, req->publisher_thumbprint, req->publisher_subject, req->min_current_version,
    req->max_current_version, req->upgrade_class, req->deployment_mode, req->scheduled_task_name,
    req->scheduled_task_path, req->service_name, command_id, manifest, req->runtime_manifest_sha256,
    req->task_id, req->campaign_id, req->operation, req->artifact_id, updater_task_name,
    staging_directory };
  char quoted[24][4600];
  for (size_t i = 0; i < 24u; ++i) if (!quote_ps(values[i], quoted[i], sizeof(quoted[i]))) return 0;
  FILE *file = fopen(path, "wb");
  if (!file) return 0;
  fprintf(file, "$ErrorActionPreference='Stop'\r\n& %s -StagedBinary %s -ExpectedSha256 %s -TargetVersion %s -ExpectedArchitecture %s -ExpectedInternalName %s -TrustedPublisherThumbprint %s -TrustedPublisherSubject %s -MinCurrentVersion %s -MaxCurrentVersion %s -UpgradeClass %s -DeploymentMode %s -ScheduledTaskName %s -ScheduledTaskPath %s -ServiceName %s -CommandId %s -RuntimeManifest %s -RuntimeManifestSha256 %s -TaskId %s -CampaignId %s -Operation %s -ArtifactId %s -UpdaterTaskName %s -StagingDirectory %s -MinFreeBytes %llu -IssuedAtUnixMs %llu -DeadlineUnixMs %llu -HealthObserveMs %llu\r\nexit $LASTEXITCODE\r\n",
          quoted[0], quoted[1], quoted[2], quoted[3], quoted[4], quoted[5], quoted[6], quoted[7], quoted[8], quoted[9], quoted[10], quoted[11], quoted[12], quoted[13], quoted[14], quoted[15], quoted[16], quoted[17], quoted[18], quoted[19], quoted[20], quoted[21], quoted[22], quoted[23], (unsigned long long)req->min_free_bytes, (unsigned long long)req->issued_at_unix_ms, (unsigned long long)req->deadline_unix_ms, (unsigned long long)req->health_observe_ms);
  return fclose(file) == 0;
}

static int write_launch_script(const char *path, const char *invocation,
                               const char *updater_task_name) {
  char invocation_args[2 * MAX_PATH + 160];
  char quoted_args[2 * MAX_PATH + 320];
  char quoted_task[512];
  int written = snprintf(invocation_args, sizeof(invocation_args),
                         "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"",
                         invocation ? invocation : "");
  if (written <= 0 || (size_t)written >= sizeof(invocation_args) ||
      !quote_ps(invocation_args, quoted_args, sizeof(quoted_args)) ||
      !quote_ps(updater_task_name, quoted_task, sizeof(quoted_task))) return 0;
  FILE *file = fopen(path, "wb");
  if (!file) return 0;
  fprintf(file,
          "$ErrorActionPreference='Stop'\r\n"
          "$taskName=%s\r\n"
          "$powershell=Join-Path $env:WINDIR 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'\r\n"
          "$action=New-ScheduledTaskAction -Execute $powershell -Argument %s\r\n"
          "$trigger=New-ScheduledTaskTrigger -AtStartup\r\n"
          "$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\r\n"
          "$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 26)\r\n"
          "Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null\r\n"
          "Start-ScheduledTask -TaskName $taskName\r\n",
          quoted_task, quoted_args);
  return fclose(file) == 0;
}

static int launch_update_bootstrap(const char *launcher, const char *working_dir,
                                   char *reason, size_t reason_cap) {
  char params[2 * MAX_PATH + 160];
  snprintf(params, sizeof(params), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%s\"",
           launcher ? launcher : "");
  SHELLEXECUTEINFOA execute;
  memset(&execute, 0, sizeof(execute));
  execute.cbSize = sizeof(execute);
  execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
  execute.lpVerb = "open";
  execute.lpFile = "powershell.exe";
  execute.lpParameters = params;
  execute.lpDirectory = working_dir;
  execute.nShow = SW_HIDE;
  if (!ShellExecuteExA(&execute) || !execute.hProcess) {
    snprintf(reason, reason_cap, "isolated updater bootstrap launch failed gle=%lu",
             (unsigned long)GetLastError());
    return 0;
  }
  DWORD waited = WaitForSingleObject(execute.hProcess, 30000u);
  DWORD exit_code = STILL_ACTIVE;
  if (waited == WAIT_OBJECT_0) (void)GetExitCodeProcess(execute.hProcess, &exit_code);
  if (waited != WAIT_OBJECT_0 || exit_code != 0u) {
    if (waited == WAIT_TIMEOUT) (void)TerminateProcess(execute.hProcess, 124u);
    snprintf(reason, reason_cap, "isolated updater bootstrap failed wait=%lu exit=%lu",
             (unsigned long)waited, (unsigned long)exit_code);
    CloseHandle(execute.hProcess);
    return 0;
  }
  CloseHandle(execute.hProcess);
  return 1;
}

static void cleanup_prelaunch_update_work(const char *root, const char *staged,
                                          const char *manifest, const char *launcher,
                                          const char *invocation) {
  if (launcher && launcher[0]) (void)DeleteFileA(launcher);
  if (invocation && invocation[0]) (void)DeleteFileA(invocation);
  if (manifest && manifest[0]) (void)DeleteFileA(manifest);
  if (staged && staged[0]) (void)DeleteFileA(staged);
  if (root && root[0]) (void)RemoveDirectoryA(root);
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
  char safe_id[129], program_data[MAX_PATH], path[MAX_PATH];
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  if (!safe_id[0]) return -1;
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  if (snprintf(path, sizeof(path), "%s\\FDSecurity\\state\\agent-update-%s.journal.json",
               program_data, safe_id) >= (int)sizeof(path)) return -1;
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
  char safe_id[129], program_data[MAX_PATH], state_dir[MAX_PATH], path[MAX_PATH], temporary[MAX_PATH];
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  if (!safe_id[0]) return -1;
  DWORD n = GetEnvironmentVariableA("ProgramData", program_data, sizeof(program_data));
  if (!n || n >= sizeof(program_data)) snprintf(program_data, sizeof(program_data), "C:\\ProgramData");
  char fd_dir[MAX_PATH];
  if (snprintf(fd_dir, sizeof(fd_dir), "%s\\FDSecurity", program_data) >= (int)sizeof(fd_dir) ||
      snprintf(state_dir, sizeof(state_dir), "%s\\FDSecurity\\state", program_data) >= (int)sizeof(state_dir))
    return -1;
  CreateDirectoryA(program_data, NULL);
  CreateDirectoryA(fd_dir, NULL);
  if (!CreateDirectoryA(state_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return -1;
  if (snprintf(path, sizeof(path), "%s\\agent-update-%s.journal.json", state_dir, safe_id) >= (int)sizeof(path) ||
      snprintf(temporary, sizeof(temporary), "%s.tmp-%lu", path,
               (unsigned long)GetCurrentProcessId()) >= (int)sizeof(temporary))
    return -1;
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

// Preserve the transport's bounded, credential-free diagnostic instead of
// collapsing every HTTP/TLS/server failure into an authentication message.
// ingest_http never places the request URL or bearer token in last_error.
static void describe_http_download_failure(const char *summary, char *out, size_t out_cap) {
  EdrIngestHttpRuntime runtime;
  if (!out || out_cap == 0u) return;
  memset(&runtime, 0, sizeof(runtime));
  edr_ingest_http_get_runtime(&runtime);
  if (runtime.last_error[0]) {
    snprintf(out, out_cap, "%s: %.159s", summary ? summary : "download failed",
             runtime.last_error);
    return;
  }
  snprintf(out, out_cap, "%s", summary ? summary : "download failed");
}

static void event_context_from_request(const EdrAgentUpdateRequest *req,
                                       const char *command_id,
                                       EdrAgentUpdateEventContext *context);

static int update_cancelled(const EdrAgentUpdateRequest *req, const char *command_id,
                            const char *outbox_dir, uint64_t event_seq,
                            const char *stage, char *detail, size_t detail_cap) {
  if (!edr_command_cancel_requested(command_id)) return 0;
  EdrAgentUpdateEventContext context;
  event_context_from_request(req, command_id, &context);
  cJSON *event_detail = cJSON_CreateObject();
  if (!event_detail || !cJSON_AddStringToObject(event_detail, "stage", stage ? stage : "cancelled") ||
      !cJSON_AddStringToObject(event_detail, "reason", "operator_cancelled_before_replacement")) {
    cJSON_Delete(event_detail);
    snprintf(detail, detail_cap, "agent update cancellation persistence pending");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  char *printed = cJSON_PrintUnformatted(event_detail);
  cJSON_Delete(event_detail);
  if (!printed || edr_agent_update_event_persist(outbox_dir, &context, event_seq,
                                                  "cancelled", 100, printed, NULL) != 0) {
    free(printed);
    snprintf(detail, detail_cap, "agent update cancellation persistence pending");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  free(printed);
  uint64_t acked = 0u;
  (void)edr_agent_update_event_flush_ingest(outbox_dir, &acked);
  if (acked < event_seq) {
    snprintf(detail, detail_cap, "agent update cancellation event pending acknowledgement");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  snprintf(detail, detail_cap, "agent update cancelled before replacement");
  return 130;
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
  char updater[MAX_PATH];
  EdrAgentUpdateRuntimeInfo updater_info;
  if (!edr_agent_update_get_runtime_info(&updater_info, updater, sizeof(updater))) {
    snprintf(detail, detail_cap, "agent_update_v1 runtime unavailable: %s",
             updater_info.error_code[0] ? updater_info.error_code : "updater_unavailable");
    return EDR_AGENT_UPDATE_EXIT_UNSUPPORTED;
  }
  char outbox_dir[MAX_PATH];
  EdrAgentUpdateEventContext event_context;
  event_context_from_request(&req, command_id, &event_context);
  if (!event_command_dir(command_id, outbox_dir, sizeof(outbox_dir))) {
    snprintf(detail, detail_cap, "agent update event outbox path unavailable");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  const char *first_status = strcmp(req.operation, "rollback") == 0 ? "rolling_back" : "downloading";
  int cancel_rc = update_cancelled(&req, command_id, outbox_dir, 1u,
                                   "before_download", detail, detail_cap);
  if (cancel_rc) return cancel_rc;
  if (edr_agent_update_event_persist(outbox_dir, &event_context, 1u, first_status, 5,
                                     "{\"stage\":\"artifact_download\"}", NULL) != 0) {
    (void)write_failure_journal(&req, command_id, 1u, "event_persist",
                                "cannot persist downloading update event");
    snprintf(detail, detail_cap, "downloading update event persistence pending");
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  (void)edr_agent_update_event_flush_ingest(outbox_dir, NULL);
  char temp[MAX_PATH], root[MAX_PATH] = {0}, staged[MAX_PATH] = {0}, manifest[MAX_PATH] = {0};
  char launcher[MAX_PATH] = {0}, invocation[MAX_PATH] = {0}, safe_id[129];
  DWORD n = GetTempPathA(sizeof(temp), temp);
  if (!n || n >= sizeof(temp))
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "cannot resolve update staging directory", 3, detail, detail_cap);
  safe_command_id(command_id, safe_id, sizeof(safe_id));
  if (!safe_id[0])
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "update command id is invalid for staging", 3, detail, detail_cap);
  if (snprintf(root, sizeof(root), "%sFDSecurity\\agent-update\\%s", temp, safe_id) >= (int)sizeof(root))
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "update staging directory path is too long", 3, detail, detail_cap);
  if (!edr_agent_update_create_directories(root))
    return update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                          "cannot create update staging directory", 3, detail, detail_cap);
  if (snprintf(staged, sizeof(staged), "%s\\FDSensor.next.exe", root) >= (int)sizeof(staged) ||
      snprintf(manifest, sizeof(manifest), "%s\\runtime-package.zip", root) >= (int)sizeof(manifest) ||
      snprintf(launcher, sizeof(launcher), "%s\\launch-update.ps1", root) >= (int)sizeof(launcher) ||
      snprintf(invocation, sizeof(invocation), "%s\\invoke-update.ps1", root) >= (int)sizeof(invocation)) {
    int result = update_failure(&req, command_id, outbox_dir, 2u, "staging_directory",
                                "update staging file path is too long", 3, detail, detail_cap);
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return result;
  }
  if (edr_ingest_http_get_url_to_file(req.artifact_url, staged, EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES) != 0) {
    char download_error[256];
    describe_http_download_failure("update artifact download failed", download_error,
                                   sizeof(download_error));
    int result = update_failure(&req, command_id, outbox_dir, 2u, "artifact_download",
                                download_error, 4, detail, detail_cap);
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return result;
  }
  cancel_rc = update_cancelled(&req, command_id, outbox_dir, 2u,
                               "artifact_downloaded", detail, detail_cap);
  if (cancel_rc) {
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return cancel_rc;
  }
  if (req.runtime_manifest_url[0] && edr_ingest_http_get_url_to_file(req.runtime_manifest_url, manifest,
                                                                       EDR_AGENT_UPDATE_MAX_ARTIFACT_BYTES) != 0) {
    char download_error[256];
    describe_http_download_failure("runtime package download failed", download_error,
                                   sizeof(download_error));
    int result = update_failure(&req, command_id, outbox_dir, 2u, "runtime_manifest_download",
                                download_error, 5, detail, detail_cap);
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return result;
  }
  cancel_rc = update_cancelled(&req, command_id, outbox_dir, 2u,
                               "runtime_manifest_downloaded", detail, detail_cap);
  if (cancel_rc) {
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return cancel_rc;
  }
  const char *second_status = strcmp(req.operation, "rollback") == 0 ? "rolling_back" : "downloaded";
  if (edr_agent_update_event_persist(outbox_dir, &event_context, 2u, second_status, 20,
                                     "{\"stage\":\"artifact_downloaded\"}", NULL) != 0) {
    (void)write_failure_journal(&req, command_id, 2u, "event_persist",
                                "cannot persist downloaded update event");
    snprintf(detail, detail_cap, "downloaded update event persistence pending");
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
  }
  (void)edr_agent_update_event_flush_ingest(outbox_dir, NULL);
  char updater_task_name[180];
  snprintf(updater_task_name, sizeof(updater_task_name), "FDSecurityAgentUpdate-%s", safe_id);
  if (!write_update_invocation_script(invocation, updater, staged,
                                      req.runtime_manifest_url[0] ? manifest : "", &req,
                                      command_id ? command_id : "", updater_task_name, root) ||
      !write_launch_script(launcher, invocation, updater_task_name)) {
    int result = update_failure(&req, command_id, outbox_dir, 3u, "launcher_persist",
                                "cannot persist external updater launch script", 6, detail, detail_cap);
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return result;
  }
  cancel_rc = update_cancelled(&req, command_id, outbox_dir, 3u,
                               "before_updater_launch", detail, detail_cap);
  if (cancel_rc) {
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return cancel_rc;
  }
  char launch_error[256];
  if (!launch_update_bootstrap(launcher, root, launch_error, sizeof(launch_error))) {
    int result = update_failure(&req, command_id, outbox_dir, 3u, "launcher_start",
                                launch_error, 7, detail, detail_cap);
    cleanup_prelaunch_update_work(root, staged, manifest, launcher, invocation);
    return result;
  }
  DeleteFileA(launcher);
  snprintf(detail, detail_cap, "agent update staged and isolated updater task launched command_id=%s target_version=%s", command_id ? command_id : "", req.target_version);
  return EDR_AGENT_UPDATE_EXIT_LAUNCHED;
#endif
}
