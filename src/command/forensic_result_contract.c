#include "edr/forensic_result_contract.h"
#include "edr/egress_request_policy.h"
#include "cJSON.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static int command_type_is_forensic(const char *type) {
  static const char *types[] = {
      "collect_forensic", "forensic", "deep_forensic", "forensic_deep",
      "targeted_forensic", "forensic_targeted", "memory_dump", "memdump",
      "yara_scan", "pmfe_scan", "velo_query", NULL};
  if (!type) return 0;
  for (int i = 0; types[i]; i++) {
    if (strcmp(type, types[i]) == 0) return 1;
  }
  return 0;
}

static const char *result_string(const cJSON *object, const char *name) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, name);
  return cJSON_IsString(value) && value->valuestring ? value->valuestring : NULL;
}

/* Only this exact legacy producer shape has an established receipt contract.
 * Other successful objects remain unchanged for the purpose owner to hold. */
static int legacy_bundle_receipt(const char *type, const cJSON *object) {
  static const char *fields[] = {
      "manifest_path", "bundle_path", "sha256", "upload_status", "minio_key", "outbox"};
  if (!strcmp(type, "pmfe_scan") || !strcmp(type, "yara_scan") || !strcmp(type, "velo_query") ||
      !cJSON_IsObject(object)) return 0;
  unsigned seen = 0;
  for (const cJSON *item = object->child; item; item = item->next) {
    unsigned i;
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
      if (item->string && !strcmp(item->string, fields[i])) break;
    }
    if (i == sizeof(fields) / sizeof(fields[0]) || (seen & (1u << i)) ||
        !cJSON_IsString(item) || !item->valuestring || strlen(item->valuestring) > 1200u) return 0;
    seen |= 1u << i;
  }
  if (seen != 63u) return 0;
  const char *sha = result_string(object, "sha256");
  const char *upload = result_string(object, "upload_status");
  const char *key = result_string(object, "minio_key");
  const char *outbox = result_string(object, "outbox");
  if (!*result_string(object, "manifest_path") || !*result_string(object, "bundle_path") ||
      strlen(sha) != 64u || strspn(sha, "0123456789abcdefABCDEF") != 64u ||
      strlen(key) > 1024u || strpbrk(key, "?@\r\n") ||
      (strcmp(upload, "ok") && strcmp(upload, "failed")) ||
      (strcmp(outbox, "none") && strcmp(outbox, "queued") && strcmp(outbox, "failed"))) return 0;
  return strcmp(upload, "ok") || (*key && !strcmp(outbox, "none"));
}

const char *edr_command_normalize_forensic_result(const char *command_type,
                                                  EdrCommandExecutionStatus status,
                                                  int exit_code,
                                                  const char *detail,
                                                  char *out, size_t out_cap) {
  if (!detail) detail = "";
  if (!command_type_is_forensic(command_type) || !out || out_cap == 0u || out_cap > INT_MAX)
    return detail;
  cJSON *parsed = edr_egress_parse_purpose_object(detail, strlen(detail));
  const char *schema = result_string(parsed, "schema");
  if (schema && (!strcmp(schema, "edr.forensic.result.v1") ||
                 !strcmp(schema, "edr.yara_scan.result.v1") ||
                 !strcmp(schema, "pmfe_result_v1") ||
                 !strcmp(schema, "edr.command.status.v1"))) {
    cJSON_Delete(parsed);
    return detail; /* Exact schema is validated by the result purpose owner. */
  }
  cJSON *normalized = NULL;
  if (legacy_bundle_receipt(command_type, parsed)) {
    normalized = cJSON_CreateObject();
    if (normalized &&
        (!cJSON_AddStringToObject(normalized, "schema", "edr.forensic.result.v1") ||
         !cJSON_AddStringToObject(normalized, "status", exit_code == 130 ? "cancelled" :
                                    status == EdrCmdExecOk ? "success" : "failed") ||
         !cJSON_AddStringToObject(normalized, "source", "agent_builtin") ||
         !cJSON_AddStringToObject(normalized, "artifact", "") ||
         !cJSON_AddStringToObject(normalized, "sha256", result_string(parsed, "sha256")) ||
         !cJSON_AddStringToObject(normalized, "object_key", result_string(parsed, "minio_key")) ||
         !cJSON_AddStringToObject(normalized, "upload_status", result_string(parsed, "upload_status")) ||
         !cJSON_AddStringToObject(normalized, "error", exit_code ? "operation_failed" : ""))) {
      cJSON_Delete(normalized); normalized = NULL;
    }
  } else if (!parsed && status != EdrCmdExecOk) {
    /* Pre-execution diagnostics are finite status facts, not a fabricated
     * forensic receipt. Keep the original text locally until projection. */
    const char *start = detail;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (*start != '{' && *start != '[') {
      normalized = cJSON_CreateObject();
      if (normalized &&
          (!cJSON_AddStringToObject(normalized, "schema", "edr.command.status.v1") ||
           !cJSON_AddNumberToObject(normalized, "status", status) ||
           !cJSON_AddNumberToObject(normalized, "exit_code", exit_code) ||
           !cJSON_AddStringToObject(normalized, "diagnostic",
                                      status == EdrCmdExecRejected ? "command_rejected" : "command_failed"))) {
        cJSON_Delete(normalized); normalized = NULL;
      }
    }
  }
  /* Preserve complete local diagnostics, never a truncated apparently valid
   * receipt. A small output buffer leaves the original untouched for holding. */
  int written = normalized && cJSON_AddStringToObject(normalized, "raw_detail", detail) &&
      cJSON_PrintPreallocated(normalized, out, (int)out_cap, 0);
  cJSON_Delete(normalized);
  cJSON_Delete(parsed);
  return written ? out : detail;
}
