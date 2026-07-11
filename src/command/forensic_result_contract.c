#include "edr/forensic_result_contract.h"

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

static void command_json_escape_text(const char *in, char *out, size_t cap) {
  size_t oi = 0;
  if (!out || cap == 0u) return;
  out[0] = '\0';
  if (!in) return;
  for (const unsigned char *p = (const unsigned char *)in; *p && oi + 1u < cap; p++) {
    if (*p == '"' || *p == '\\') {
      if (oi + 2u >= cap) break;
      out[oi++] = '\\'; out[oi++] = (char)*p;
    } else if (*p == '\n' || *p == '\r' || *p == '\t') {
      if (oi + 2u >= cap) break;
      out[oi++] = '\\'; out[oi++] = *p == '\n' ? 'n' : (*p == '\r' ? 'r' : 't');
    } else if (*p >= 0x20u) {
      out[oi++] = (char)*p;
    }
  }
  out[oi] = '\0';
}

const char *edr_command_normalize_forensic_result(const char *command_type,
                                                  EdrCommandExecutionStatus status,
                                                  int exit_code,
                                                  const char *detail,
                                                  char *out, size_t out_cap) {
  if (!command_type_is_forensic(command_type) ||
      (detail && (strstr(detail, "edr.forensic.result.v1") ||
                  strstr(detail, "pmfe_result_v1")))) {
    return detail ? detail : "";
  }
  if (!out || out_cap == 0u) return detail ? detail : "";
  char raw_escaped[4096];
  char error_escaped[1024];
  command_json_escape_text(detail ? detail : "", raw_escaped, sizeof(raw_escaped));
  command_json_escape_text(detail ? detail : "", error_escaped, sizeof(error_escaped));
  const char *result_status = exit_code == 130 ? "cancelled" :
                              status == EdrCmdExecOk ? "success" : "failed";
  snprintf(out, out_cap,
           "{\"schema\":\"edr.forensic.result.v1\",\"status\":\"%s\","
           "\"source\":\"agent_builtin\",\"artifact\":\"\",\"sha256\":\"\","
           "\"object_key\":\"\",\"truncated\":false,"
           "\"upload_status\":\"not_requested\",\"error\":\"%s\","
           "\"raw_detail\":\"%s\"}",
           result_status, status == EdrCmdExecOk ? "" : error_escaped, raw_escaped);
  return out;
}
