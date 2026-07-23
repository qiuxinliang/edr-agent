#include "edr/command_contract.h"

#include "edr/command_registry.h"
#include "cJSON.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  FIELD_STRING = 1u << 0,
  FIELD_NUMBER = 1u << 1,
  FIELD_BOOL = 1u << 2,
  FIELD_ARRAY = 1u << 3,
  FIELD_OBJECT = 1u << 4,
};

typedef struct CommandFieldRule {
  const char *name;
  unsigned types;
  int required;
  double min_value;
  double max_value;
  size_t max_length;
  int max_items;
} CommandFieldRule;

#define RULE(name_value, types_value, required_value, min_value, max_value, max_length, max_items) \
  { name_value, types_value, required_value, min_value, max_value, max_length, max_items }
#define COUNT_OF(values) (sizeof(values) / sizeof((values)[0]))

static const CommandFieldRule k_common_rules[] = {
    RULE("initiated_by", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("reason", FIELD_STRING, 0, 0, 0, 1024, 0),
    RULE("manual", FIELD_BOOL, 0, 0, 0, 0, 0),
};

static const CommandFieldRule k_echo_rules[] = {
    RULE("message", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("data", FIELD_STRING, 0, 0, 0, 4096, 0),
};

static const CommandFieldRule k_telemetry_rules[] = {
    RULE("dict_ver", FIELD_STRING, 0, 0, 0, 128, 0),
    RULE("schema_ver", FIELD_STRING, 0, 0, 0, 128, 0),
    RULE("profile_id", FIELD_STRING, 0, 0, 0, 128, 0),
    RULE("qos_dscp", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("threshold", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("batch_events", FIELD_NUMBER, 0, 1, 1000000, 0, 0),
    RULE("batch_max_events", FIELD_NUMBER, 0, 1, 1000000, 0, 0),
    RULE("flush_interval_s", FIELD_NUMBER, 0, 1, 86400, 0, 0),
    RULE("sampling_pct", FIELD_NUMBER, 0, 0, 100, 0, 0),
    RULE("h2", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("http2_enabled", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("h2_required", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("control_http2_enabled", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("control_http2_require", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("control_http1_fallback", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("zstd", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("control_stream_enabled", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("long_poll_fallback", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("report_events_v2_enabled", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("backpressure_enabled", FIELD_BOOL, 0, 0, 0, 0, 0),
};

static const CommandFieldRule k_pmfe_rules[] = {
    RULE("pid", FIELD_NUMBER, 1, 1, 4294967295.0, 0, 0),
    RULE("region_base", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("region_size", FIELD_NUMBER, 0, 1, 1048576, 0, 0),
    RULE("extract_region", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("run_yara", FIELD_BOOL, 0, 0, 0, 0, 0),
};

static const CommandFieldRule k_memory_rules[] = {
    RULE("pid", FIELD_NUMBER, 1, 1, 4294967295.0, 0, 0),
    RULE("full", FIELD_BOOL | FIELD_NUMBER, 0, 0, 1, 0, 0),
    RULE("timeout_ms", FIELD_NUMBER, 0, 1, 3600000, 0, 0),
};

static const CommandFieldRule k_path_rules[] = {
    RULE("path", FIELD_STRING, 1, 0, 0, 4096, 0),
};

static const CommandFieldRule k_get_file_rules[] = {
    RULE("path", FIELD_STRING, 1, 0, 0, 4096, 0),
    RULE("max_size_bytes", FIELD_NUMBER, 0, 1, 1073741824.0, 0, 0),
    RULE("pe_only", FIELD_BOOL | FIELD_NUMBER, 0, 0, 1, 0, 0),
};

static const CommandFieldRule k_put_file_rules[] = {
    RULE("path", FIELD_STRING, 1, 0, 0, 4096, 0),
    RULE("data_b64", FIELD_STRING, 0, 0, 0, 16u * 1024u * 1024u, 0),
    RULE("offset", FIELD_NUMBER, 0, 0, 1073741824.0, 0, 0),
    RULE("sha256", FIELD_STRING, 0, 0, 0, 64, 0),
};

static const CommandFieldRule k_restore_file_rules[] = {
    RULE("quarantine_id", FIELD_STRING, 0, 0, 0, 256, 0),
    RULE("id", FIELD_STRING, 0, 0, 0, 256, 0),
    RULE("quarantine_path", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("dest", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("restore_path", FIELD_STRING, 0, 0, 0, 4096, 0),
};

static const CommandFieldRule k_forensic_rules[] = {
    RULE("scope", FIELD_STRING | FIELD_NUMBER, 0, 0, 3, 64, 0),
    RULE("collector_id", FIELD_STRING, 0, 0, 0, 128, 0),
    RULE("items", FIELD_ARRAY, 0, 0, 0, 0, 20),
    RULE("paths", FIELD_ARRAY, 0, 0, 0, 0, 64),
    RULE("timeout_ms", FIELD_NUMBER, 0, 1, 3600000, 0, 0),
};

static const CommandFieldRule k_yara_rules[] = {
    RULE("target_path", FIELD_STRING, 1, 0, 0, 4096, 0),
    RULE("target_type", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("rules", FIELD_STRING, 0, 0, 0, 1024u * 1024u, 0),
    RULE("rule_ids", FIELD_ARRAY, 0, 0, 0, 0, 256),
    RULE("recursive", FIELD_BOOL, 0, 0, 0, 0, 0),
    RULE("exclude_paths", FIELD_ARRAY, 0, 0, 0, 0, 64),
    RULE("result_detail", FIELD_STRING, 0, 0, 0, 32, 0),
    RULE("rule_source", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("max_files", FIELD_NUMBER, 0, 1, 100000, 0, 0),
    RULE("max_depth", FIELD_NUMBER, 0, 0, 64, 0, 0),
    RULE("max_file_mb", FIELD_NUMBER, 0, 1, 4096, 0, 0),
    RULE("timeout_ms", FIELD_NUMBER, 0, 1, 3600000, 0, 0),
};

static const CommandFieldRule k_cancel_rules[] = {
    RULE("target_cmd_id", FIELD_STRING, 0, 0, 0, 128, 0),
};

static const CommandFieldRule k_rtq_rules[] = {
    RULE("process_name", FIELD_STRING, 0, 0, 0, 259, 0),
    RULE("process_path", FIELD_STRING, 0, 0, 0, 519, 0),
    RULE("process_cmdline", FIELD_STRING, 0, 0, 0, 4095, 0),
    RULE("process_user", FIELD_STRING, 0, 0, 0, 127, 0),
    RULE("process_pid_min", FIELD_NUMBER, 0, 0, 4294967295.0, 0, 0),
    RULE("process_pid_max", FIELD_NUMBER, 0, 1, 4294967295.0, 0, 0),
    RULE("network_remote_ip", FIELD_STRING, 0, 0, 0, 63, 0),
    RULE("network_remote_port", FIELD_NUMBER, 0, 1, 65535, 0, 0),
    RULE("network_state", FIELD_STRING, 0, 0, 0, 31, 0),
    RULE("network_proto", FIELD_STRING, 0, 0, 0, 15, 0),
    RULE("file_path", FIELD_STRING, 0, 0, 0, 519, 0),
    RULE("file_sha256", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("file_ext", FIELD_STRING, 0, 0, 0, 15, 0),
    RULE("registry_path", FIELD_STRING, 0, 0, 0, 519, 0),
    RULE("registry_value", FIELD_STRING, 0, 0, 0, 259, 0),
    RULE("registry_mode", FIELD_STRING, 0, 0, 0, 15, 0),
    RULE("eventlog_channel", FIELD_STRING, 0, 0, 0, 127, 0),
    RULE("eventlog_query", FIELD_STRING, 0, 0, 0, 511, 0),
    RULE("script_content", FIELD_STRING, 0, 0, 0, 1023, 0),
    RULE("script_engine", FIELD_STRING, 0, 0, 0, 63, 0),
};

static const CommandFieldRule k_cached_query_rules[] = {
    RULE("event_type", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("type", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("limit", FIELD_NUMBER, 0, 1, 1000, 0, 0),
    RULE("time_window_s", FIELD_NUMBER, 0, 1, 604800, 0, 0),
    RULE("pid", FIELD_NUMBER, 0, 1, 4294967295.0, 0, 0),
    RULE("process_name", FIELD_STRING, 0, 0, 0, 512, 0),
    RULE("process_path", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("process_cmdline", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("remote_ip", FIELD_STRING, 0, 0, 0, 128, 0),
    RULE("remote_port", FIELD_NUMBER, 0, 1, 65535, 0, 0),
    RULE("file_path", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("file_sha256", FIELD_STRING, 0, 0, 0, 64, 0),
};

static const CommandFieldRule k_process_tree_rules[] = {
    RULE("pid", FIELD_NUMBER, 1, 1, 4294967295.0, 0, 0),
    RULE("endpoint_id", FIELD_STRING, 0, 0, 0, 128, 0),
};

static const CommandFieldRule k_modules_rules[] = {
    RULE("pid", FIELD_NUMBER, 1, 1, 4294967295.0, 0, 0),
    RULE("max_modules", FIELD_NUMBER, 0, 1, 1000, 0, 0),
};

static const CommandFieldRule k_snapshot_rules[] = {
    RULE("max_processes", FIELD_NUMBER, 0, 1, 5000, 0, 0),
    RULE("max_procs", FIELD_NUMBER, 0, 1, 5000, 0, 0),
};

static const CommandFieldRule k_autoruns_rules[] = {
    RULE("max_rows", FIELD_NUMBER, 0, 1, 5000, 0, 0),
};

static const CommandFieldRule k_velo_rules[] = {
    RULE("scope", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("pid", FIELD_NUMBER, 0, 0, 4294967295.0, 0, 0),
    RULE("limit", FIELD_NUMBER, 0, 1, 100000, 0, 0),
    RULE("backend", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("provider_requested", FIELD_STRING, 0, 0, 0, 64, 0),
    RULE("fallback_reason", FIELD_STRING, 0, 0, 0, 1024, 0),
    RULE("inline_max_bytes", FIELD_NUMBER, 0, 1024, 16777216, 0, 0),
    RULE("download", FIELD_BOOL, 0, 0, 0, 0, 0),
};

static const CommandFieldRule k_eventlog_rules[] = {
    RULE("channel", FIELD_STRING, 0, 0, 0, 256, 0),
    RULE("max_events", FIELD_NUMBER, 0, 1, 10000, 0, 0),
};

static const CommandFieldRule k_registry_rules[] = {
    RULE("key", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("path", FIELD_STRING, 0, 0, 0, 4096, 0),
    RULE("max_values", FIELD_NUMBER, 0, 1, 1000, 0, 0),
    RULE("recursive", FIELD_BOOL | FIELD_NUMBER, 0, 0, 1, 0, 0),
};

static const CommandFieldRule k_shell_open_rules[] = {
    RULE("shell_type", FIELD_STRING, 0, 0, 0, 64, 0),
};

static const CommandFieldRule k_shell_input_rules[] = {
    RULE("session_id", FIELD_STRING, 1, 0, 0, 128, 0),
    RULE("input", FIELD_STRING, 1, 0, 0, 4096, 0),
};

static const CommandFieldRule k_shell_close_rules[] = {
    RULE("session_id", FIELD_STRING, 1, 0, 0, 128, 0),
};

static const CommandFieldRule k_rtr_shell_rules[] = {
    RULE("command", FIELD_STRING, 0, 0, 0, 2048, 0),
    RULE("cmd", FIELD_STRING, 0, 0, 0, 2048, 0),
    RULE("timeout_sec", FIELD_NUMBER, 0, 1, 3600, 0, 0),
    RULE("timeout_s", FIELD_NUMBER, 0, 1, 3600, 0, 0),
};

static const CommandFieldRule k_update_server_rules[] = {
    RULE("server_address", FIELD_STRING, 0, 0, 0, 512, 0),
    RULE("server_addr", FIELD_STRING, 0, 0, 0, 512, 0),
    RULE("address", FIELD_STRING, 0, 0, 0, 512, 0),
};

static int contract_fail(char *reason, size_t cap, const char *message) {
  if (reason && cap > 0u) {
    snprintf(reason, cap, "%s", message ? message : "invalid command payload");
  }
  return 0;
}

static const CommandFieldRule *find_rule(const CommandFieldRule *rules, size_t count,
                                         const char *name) {
  for (size_t i = 0; i < count; i++) {
    if (strcmp(rules[i].name, name) == 0) {
      return &rules[i];
    }
  }
  return NULL;
}

static int json_type_matches(const cJSON *value, unsigned types) {
  return ((types & FIELD_STRING) && cJSON_IsString(value)) ||
         ((types & FIELD_NUMBER) && cJSON_IsNumber(value)) ||
         ((types & FIELD_BOOL) && cJSON_IsBool(value)) ||
         ((types & FIELD_ARRAY) && cJSON_IsArray(value)) ||
         ((types & FIELD_OBJECT) && cJSON_IsObject(value));
}

static int validate_rule_value(const cJSON *value, const CommandFieldRule *rule,
                               char *reason, size_t reason_cap) {
  if (!json_type_matches(value, rule->types)) {
    char message[192];
    snprintf(message, sizeof(message), "invalid type for payload field: %s", rule->name);
    return contract_fail(reason, reason_cap, message);
  }
  if (cJSON_IsString(value)) {
    size_t length = value->valuestring ? strlen(value->valuestring) : 0u;
    if ((rule->required && length == 0u) ||
        (rule->max_length > 0u && length > rule->max_length)) {
      char message[192];
      snprintf(message, sizeof(message), "invalid length for payload field: %s", rule->name);
      return contract_fail(reason, reason_cap, message);
    }
  }
  if (cJSON_IsNumber(value)) {
    double number = value->valuedouble;
    if (!isfinite(number) || number < (double)INT64_MIN || number > (double)INT64_MAX ||
        number != (double)(int64_t)number || number < rule->min_value ||
        (rule->max_value > rule->min_value && number > rule->max_value)) {
      char message[192];
      snprintf(message, sizeof(message), "numeric payload field out of range: %s", rule->name);
      return contract_fail(reason, reason_cap, message);
    }
  }
  if (cJSON_IsArray(value) && rule->max_items > 0 &&
      cJSON_GetArraySize(value) > rule->max_items) {
    char message[192];
    snprintf(message, sizeof(message), "payload array too large: %s", rule->name);
    return contract_fail(reason, reason_cap, message);
  }
  return 1;
}

static void command_rules(EdrCommandKind kind, const CommandFieldRule **rules,
                          size_t *count) {
  *rules = NULL;
  *count = 0u;
  switch (kind) {
    case EDR_COMMAND_KIND_ECHO:
      *rules = k_echo_rules; *count = COUNT_OF(k_echo_rules); break;
    case EDR_COMMAND_KIND_TELEMETRY_PROFILE_UPDATE:
      *rules = k_telemetry_rules; *count = COUNT_OF(k_telemetry_rules); break;
    case EDR_COMMAND_KIND_KILL_PROCESS:
    case EDR_COMMAND_KIND_PMFE_SCAN:
      *rules = k_pmfe_rules; *count = COUNT_OF(k_pmfe_rules); break;
    case EDR_COMMAND_KIND_MEMORY_DUMP:
      *rules = k_memory_rules; *count = COUNT_OF(k_memory_rules); break;
    case EDR_COMMAND_KIND_FILE_STAT:
    case EDR_COMMAND_KIND_REMOVE_FILE:
    case EDR_COMMAND_KIND_QUARANTINE_FILE:
    case EDR_COMMAND_KIND_AVE_FINGERPRINT:
    case EDR_COMMAND_KIND_AVE_INFER:
      *rules = k_path_rules; *count = COUNT_OF(k_path_rules); break;
    case EDR_COMMAND_KIND_GET_FILE:
      *rules = k_get_file_rules; *count = COUNT_OF(k_get_file_rules); break;
    case EDR_COMMAND_KIND_PUT_FILE:
      *rules = k_put_file_rules; *count = COUNT_OF(k_put_file_rules); break;
    case EDR_COMMAND_KIND_RESTORE_FILE:
      *rules = k_restore_file_rules; *count = COUNT_OF(k_restore_file_rules); break;
    case EDR_COMMAND_KIND_COLLECT_FORENSIC:
    case EDR_COMMAND_KIND_FORENSIC:
    case EDR_COMMAND_KIND_DEEP_FORENSIC:
      *rules = k_forensic_rules; *count = COUNT_OF(k_forensic_rules); break;
    case EDR_COMMAND_KIND_TARGETED_FORENSIC:
      *rules = k_forensic_rules; *count = COUNT_OF(k_forensic_rules); break;
    case EDR_COMMAND_KIND_YARA_SCAN:
      *rules = k_yara_rules; *count = COUNT_OF(k_yara_rules); break;
    case EDR_COMMAND_KIND_FORENSIC_CANCEL:
      *rules = k_cancel_rules; *count = COUNT_OF(k_cancel_rules); break;
    case EDR_COMMAND_KIND_RTQ_EXECUTE:
      *rules = k_rtq_rules; *count = COUNT_OF(k_rtq_rules); break;
    case EDR_COMMAND_KIND_RTQ_QUERY:
    case EDR_COMMAND_KIND_LIST_CONNECTIONS:
      *rules = k_cached_query_rules; *count = COUNT_OF(k_cached_query_rules); break;
    case EDR_COMMAND_KIND_PROCESS_TREE:
      *rules = k_process_tree_rules; *count = COUNT_OF(k_process_tree_rules); break;
    case EDR_COMMAND_KIND_LIST_MODULES:
      *rules = k_modules_rules; *count = COUNT_OF(k_modules_rules); break;
    case EDR_COMMAND_KIND_PROCESS_SNAPSHOT:
      *rules = k_snapshot_rules; *count = COUNT_OF(k_snapshot_rules); break;
    case EDR_COMMAND_KIND_LIST_AUTORUNS:
      *rules = k_autoruns_rules; *count = COUNT_OF(k_autoruns_rules); break;
    case EDR_COMMAND_KIND_VELO_QUERY:
      *rules = k_velo_rules; *count = COUNT_OF(k_velo_rules); break;
    case EDR_COMMAND_KIND_EVENTLOG_VIEW:
      *rules = k_eventlog_rules; *count = COUNT_OF(k_eventlog_rules); break;
    case EDR_COMMAND_KIND_REGISTRY_QUERY:
      *rules = k_registry_rules; *count = COUNT_OF(k_registry_rules); break;
    case EDR_COMMAND_KIND_SHELL_OPEN:
      *rules = k_shell_open_rules; *count = COUNT_OF(k_shell_open_rules); break;
    case EDR_COMMAND_KIND_SHELL_INPUT:
      *rules = k_shell_input_rules; *count = COUNT_OF(k_shell_input_rules); break;
    case EDR_COMMAND_KIND_SHELL_CLOSE:
      *rules = k_shell_close_rules; *count = COUNT_OF(k_shell_close_rules); break;
    case EDR_COMMAND_KIND_RTR_SHELL:
      *rules = k_rtr_shell_rules; *count = COUNT_OF(k_rtr_shell_rules); break;
    case EDR_COMMAND_KIND_UPDATE_SERVER_ADDRESS:
      *rules = k_update_server_rules; *count = COUNT_OF(k_update_server_rules); break;
    default:
      break;
  }
}

static int has_nonempty_string(const cJSON *root, const char *name) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, name);
  return cJSON_IsString(value) && value->valuestring && value->valuestring[0];
}

static int validate_semantics(EdrCommandKind kind, const cJSON *root,
                              char *reason, size_t reason_cap) {
  if (kind == EDR_COMMAND_KIND_RTQ_EXECUTE) {
    const cJSON *registry_mode = cJSON_GetObjectItemCaseSensitive(root, "registry_mode");
    if (registry_mode) {
      if (!cJSON_IsString(registry_mode) || !registry_mode->valuestring ||
          (strcmp(registry_mode->valuestring, "exact") != 0 &&
           strcmp(registry_mode->valuestring, "subtree") != 0)) {
        return contract_fail(reason, reason_cap,
                             "registry_mode must be exact or subtree");
      }
      if (!has_nonempty_string(root, "registry_path")) {
        return contract_fail(reason, reason_cap,
                             "registry_mode requires registry_path");
      }
    }
    const cJSON *sha = cJSON_GetObjectItemCaseSensitive(root, "file_sha256");
    if (sha && cJSON_IsString(sha) && sha->valuestring && sha->valuestring[0]) {
      if (strlen(sha->valuestring) != 64u) {
        return contract_fail(reason, reason_cap,
                             "file_sha256 must contain 64 hex characters");
      }
      for (const char *p = sha->valuestring; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
          return contract_fail(reason, reason_cap,
                               "file_sha256 must contain 64 hex characters");
        }
      }
    }
  }
  if (kind == EDR_COMMAND_KIND_PUT_FILE) {
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data_b64");
    if (!cJSON_IsString(data)) {
      return contract_fail(reason, reason_cap, "put_file requires data_b64 string");
    }
  }
  if (kind == EDR_COMMAND_KIND_TARGETED_FORENSIC) {
    const cJSON *items = cJSON_GetObjectItemCaseSensitive(root, "items");
    if (!cJSON_IsArray(items) || cJSON_GetArraySize(items) < 1) {
      return contract_fail(reason, reason_cap, "targeted_forensic requires items");
    }
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, items) {
      if (!cJSON_IsObject(item)) {
        return contract_fail(reason, reason_cap, "targeted forensic item must be an object");
      }
      for (const cJSON *field = item->child; field; field = field->next) {
        if (!field->string ||
            (strcmp(field->string, "type") != 0 && strcmp(field->string, "path") != 0 &&
             strcmp(field->string, "pid") != 0 && strcmp(field->string, "reg_key") != 0)) {
          return contract_fail(reason, reason_cap, "unknown targeted forensic item field");
        }
      }
      const cJSON *type = cJSON_GetObjectItemCaseSensitive(item, "type");
      if (!cJSON_IsString(type) || !type->valuestring || !type->valuestring[0]) {
        return contract_fail(reason, reason_cap, "targeted forensic item requires type");
      }
      if (strcmp(type->valuestring, "file") == 0 &&
          !has_nonempty_string(item, "path")) {
        return contract_fail(reason, reason_cap, "file forensic item requires path");
      }
      if (strcmp(type->valuestring, "registry") == 0 &&
          !has_nonempty_string(item, "reg_key")) {
        return contract_fail(reason, reason_cap, "registry forensic item requires reg_key");
      }
      if ((strcmp(type->valuestring, "process") == 0 ||
           strcmp(type->valuestring, "memory") == 0)) {
        const cJSON *pid = cJSON_GetObjectItemCaseSensitive(item, "pid");
        if (!cJSON_IsNumber(pid) || pid->valuedouble < 1 ||
            pid->valuedouble > 4294967295.0 ||
            pid->valuedouble != (double)(uint64_t)pid->valuedouble) {
          return contract_fail(reason, reason_cap, "process forensic item requires numeric pid");
        }
      }
    }
  }
  if (kind == EDR_COMMAND_KIND_YARA_SCAN) {
    const cJSON *ids = cJSON_GetObjectItemCaseSensitive(root, "rule_ids");
    const cJSON *id = NULL;
    cJSON_ArrayForEach(id, ids) {
      if (!cJSON_IsString(id) || !id->valuestring || !id->valuestring[0] ||
          strlen(id->valuestring) > 128u) {
        return contract_fail(reason, reason_cap, "yara rule_ids must contain non-empty strings");
      }
    }
  }
  if (kind == EDR_COMMAND_KIND_RESTORE_FILE) {
    int by_id = has_nonempty_string(root, "quarantine_id") || has_nonempty_string(root, "id");
    int by_path = has_nonempty_string(root, "quarantine_path") &&
                  (has_nonempty_string(root, "dest") || has_nonempty_string(root, "restore_path"));
    if (!by_id && !by_path) {
      return contract_fail(reason, reason_cap,
                           "restore payload requires quarantine_id or quarantine_path with destination");
    }
  }
  if (kind == EDR_COMMAND_KIND_REGISTRY_QUERY &&
      !has_nonempty_string(root, "key") && !has_nonempty_string(root, "path")) {
    return contract_fail(reason, reason_cap, "registry query requires key or path");
  }
  if (kind == EDR_COMMAND_KIND_RTR_SHELL &&
      !has_nonempty_string(root, "command") && !has_nonempty_string(root, "cmd")) {
    return contract_fail(reason, reason_cap, "rtr_shell requires command");
  }
  if (kind == EDR_COMMAND_KIND_UPDATE_SERVER_ADDRESS &&
      !has_nonempty_string(root, "server_address") &&
      !has_nonempty_string(root, "server_addr") && !has_nonempty_string(root, "address")) {
    return contract_fail(reason, reason_cap, "update_server_address requires server_address");
  }
  if (kind == EDR_COMMAND_KIND_RTQ_EXECUTE) {
    int query_fields = 0;
    for (const cJSON *item = root->child; item; item = item->next) {
      if (item->string && strcmp(item->string, "initiated_by") != 0 &&
          strcmp(item->string, "reason") != 0 && strcmp(item->string, "manual") != 0) {
        query_fields++;
      }
    }
    if (query_fields == 0) {
      return contract_fail(reason, reason_cap, "rtq_execute requires at least one query field");
    }
  }
  return 1;
}

int edr_command_contract_signature_required(const char *command_id, const char *command_type) {
  (void)command_id;
  if (edr_command_registry_is_shell(command_type)) {
    return 1;
  }
  const char *require = getenv("EDR_COMMAND_REQUIRE_SIGNATURE");
  if (require && require[0] == '1') {
    return 1;
  }
  const char *allow_unsigned = getenv("EDR_COMMAND_ALLOW_UNSIGNED");
  if (!allow_unsigned || allow_unsigned[0] != '1') {
    return 1;
  }
  if (edr_command_registry_is_dangerous(command_type)) {
    const char *allow_dangerous = getenv("EDR_COMMAND_ALLOW_UNSIGNED_DANGEROUS");
    return !(allow_dangerous && allow_dangerous[0] == '1');
  }
  return 0;
}

int edr_command_contract_validate(const char *command_type, const uint8_t *payload,
                                  size_t payload_len, char *reason, size_t reason_cap) {
  if (reason && reason_cap > 0u) {
    reason[0] = '\0';
  }
  const EdrCommandDescriptor *descriptor = edr_command_registry_lookup(command_type);
  if (!descriptor) {
    return contract_fail(reason, reason_cap, "unknown command_type");
  }
  size_t max_payload = 16u * 1024u * 1024u;
  const char *limit_env = getenv("EDR_COMMAND_MAX_PAYLOAD_BYTES");
  if (limit_env && limit_env[0]) {
    unsigned long long parsed = strtoull(limit_env, NULL, 10);
    if (parsed >= 4096u && parsed <= 256u * 1024u * 1024u) {
      max_payload = (size_t)parsed;
    }
  }
  if (payload_len > max_payload) {
    return contract_fail(reason, reason_cap, "command payload exceeds configured size limit");
  }
  if (payload_len > 0u && !payload) {
    return contract_fail(reason, reason_cap, "command payload pointer is null");
  }
  if (payload_len == 0u) {
    return descriptor->payload_schema == EDR_COMMAND_PAYLOAD_NONE_OR_OBJECT
               ? 1
               : contract_fail(reason, reason_cap, "command payload is required");
  }

  char *json = (char *)malloc(payload_len + 1u);
  if (!json) {
    return contract_fail(reason, reason_cap, "command payload validation allocation failed");
  }
  memcpy(json, payload, payload_len);
  json[payload_len] = '\0';
  const char *parse_end = NULL;
  cJSON *root = cJSON_ParseWithLengthOpts(json, payload_len + 1u, &parse_end, 1);
  while (parse_end && parse_end < json + payload_len && isspace((unsigned char)*parse_end)) {
    parse_end++;
  }
  if (!cJSON_IsObject(root) || parse_end != json + payload_len) {
    cJSON_Delete(root);
    free(json);
    return contract_fail(reason, reason_cap, "command payload must be a complete JSON object");
  }
  free(json);

  const CommandFieldRule *rules = NULL;
  size_t rule_count = 0u;
  command_rules(descriptor->kind, &rules, &rule_count);

  for (const cJSON *field = root->child; field; field = field->next) {
    if (!field->string) {
      cJSON_Delete(root);
      return contract_fail(reason, reason_cap, "payload field name is missing");
    }
    for (const cJSON *prior = root->child; prior != field; prior = prior->next) {
      if (prior->string && strcmp(prior->string, field->string) == 0) {
        char message[192];
        snprintf(message, sizeof(message), "duplicate payload field: %s", field->string);
        cJSON_Delete(root);
        return contract_fail(reason, reason_cap, message);
      }
    }
    const CommandFieldRule *rule = find_rule(rules, rule_count, field->string);
    if (!rule) {
      rule = find_rule(k_common_rules, COUNT_OF(k_common_rules), field->string);
    }
    if (!rule) {
      char message[192];
      snprintf(message, sizeof(message), "unknown payload field: %s", field->string);
      cJSON_Delete(root);
      return contract_fail(reason, reason_cap, message);
    }
    if (!validate_rule_value(field, rule, reason, reason_cap)) {
      cJSON_Delete(root);
      return 0;
    }
  }

  for (size_t i = 0; i < rule_count; i++) {
    if (rules[i].required && !cJSON_GetObjectItemCaseSensitive(root, rules[i].name)) {
      char message[192];
      snprintf(message, sizeof(message), "required payload field missing: %s", rules[i].name);
      cJSON_Delete(root);
      return contract_fail(reason, reason_cap, message);
    }
  }
  int valid = validate_semantics(descriptor->kind, root, reason, reason_cap);
  cJSON_Delete(root);
  return valid;
}
