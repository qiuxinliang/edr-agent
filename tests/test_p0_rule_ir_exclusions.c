/* Exercise the production parser and immutable-snapshot evaluator. Fixtures
 * contain field observations only; no command or fixture path is executed. */
#include "edr/behavior_record.h"
#include "edr/p0_rule_ir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static char s_path[1024];

static int create_fixture(void) {
#ifdef _WIN32
  char directory[MAX_PATH];
  DWORD size = GetTempPathA(sizeof(directory), directory);
  if (!size || size >= sizeof(directory) ||
      !GetTempFileNameA(directory, "p0x", 0u, s_path)) return 0;
  return _putenv_s("EDR_P0_IR_PATH", s_path) == 0;
#else
  snprintf(s_path, sizeof(s_path), "/tmp/edr-p0-exclusions-XXXXXX");
  int fd = mkstemp(s_path);
  if (fd < 0) return 0;
  close(fd);
  return setenv("EDR_P0_IR_PATH", s_path, 1) == 0;
#endif
}

static int write_bundle(unsigned schema, const char *event, const char *condition) {
  FILE *file = fopen(s_path, "wb");
  if (!file) return 0;
  int wrote = fprintf(file,
      "{\"kind\":\"" EDR_P0_RULE_IR_BUNDLE_KIND "\",\"ir_schema_version\":%u,"
      "\"rules_bundle_version\":\"exclusion-contract\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"test\",\"event_type\":\"%s\",\"condition\":%s}]}",
      schema, event, condition);
  int closed = fclose(file);
  return wrote > 0 && closed == 0;
}

static int load_rule(const char *event, const char *condition) {
  if (!write_bundle(EDR_P0_RULE_IR_SCHEMA_VERSION, event, condition) ||
      !edr_p0_rule_ir_validate_candidate_path(s_path)) return 0;
  edr_p0_rule_ir_reload();
  return edr_p0_rule_ir_is_ready() && edr_p0_rule_ir_rule_count() == 1;
}

static int matches(const EdrBehaviorRecord *record, int expected, const char *label) {
  EdrP0RuleIrEvaluation evaluation;
  if (!edr_p0_rule_ir_evaluate_record(record, NULL, &evaluation)) {
    fprintf(stderr, "unavailable evaluator: %s\n", label);
    return 0;
  }
  int matched = evaluation.match_count == 1u;
  edr_p0_rule_ir_evaluation_free(&evaluation);
  if (matched != expected) {
    fprintf(stderr, "exclusion contract: %s expected=%d actual=%d\n", label, expected, matched);
    return 0;
  }
  return 1;
}

static void record_init(EdrBehaviorRecord *record, EdrEventType type) {
  edr_behavior_record_init(record);
  record->type = type;
  record->net_dport = 1080u;
  snprintf(record->process_name, sizeof(record->process_name), "reader.exe");
  snprintf(record->parent_name, sizeof(record->parent_name), "launcher.exe");
  snprintf(record->cmdline, sizeof(record->cmdline), "reader.exe trigger");
  snprintf(record->exe_path, sizeof(record->exe_path), "C:\\Trusted\\reader.exe");
  snprintf(record->file_path, sizeof(record->file_path), "C:\\protected\\Login Data");
  snprintf(record->network_aux_path, sizeof(record->network_aux_path), "C:\\protected\\Login Data");
}

static int name_exclusions(void) {
  static const struct {
    const char *key;
    const char *values;
    int parent;
  } cases[] = {
    {"process_name_not_in", "[\"browser.exe\"]", 0},
    {"parent_name_not_in", "[\"browser.exe\"]", 1},
    {"process_name_not_regex_any", "[\"(?i)^browser\\\\.exe$\"]", 0},
    {"parent_name_not_regex_any", "[\"(?i)^browser\\\\.exe$\"]", 1},
  };
  static const struct { const char *event; EdrEventType type; } events[] = {
    {"process_create", EDR_EVENT_PROCESS_CREATE},
    {"file_read", EDR_EVENT_FILE_READ},
    {"file_write", EDR_EVENT_FILE_WRITE},
    {"script_powershell", EDR_EVENT_SCRIPT_POWERSHELL},
    {"script_wmi", EDR_EVENT_SCRIPT_WMI},
    {"network_connect", EDR_EVENT_NET_CONNECT},
  };
  for (size_t e = 0u; e < sizeof(events) / sizeof(events[0]); ++e) {
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
      if (events[e].type == EDR_EVENT_NET_CONNECT && cases[i].parent) continue;
      char condition[1024];
      const char *positive = events[e].type == EDR_EVENT_NET_CONNECT
          ? "\"remote_port_in\":[1080]"
          : "\"command_regex_any\":[\"trigger\"]";
      snprintf(condition, sizeof(condition), "{%s,\"%s\":%s}", positive, cases[i].key, cases[i].values);
      if (!load_rule(events[e].event, condition)) return 0;
      EdrBehaviorRecord record;
      record_init(&record, events[e].type);
      if (!matches(&record, 1, "unlisted actor remains detected")) return 0;
      char *field = cases[i].parent ? record.parent_name : record.process_name;
      size_t cap = cases[i].parent ? sizeof(record.parent_name) : sizeof(record.process_name);
      snprintf(field, cap, "BROWSER.EXE");
      if (!matches(&record, 0, "matching actual name is excluded")) return 0;
      if (events[e].type == EDR_EVENT_PROCESS_CREATE &&
          edr_p0_rule_ir_matches("test", record.process_name, record.cmdline,
                                 record.parent_name, 0)) return 0;
      const char *marker = cases[i].parent ? "source.parent_name" : "source.process_name";
      edr_behavior_mark_source_truncated(&record, marker);
      /* FileRead independently requires an intact actor name before P0.
       * Keep that source-quality boundary while testing optional exclusions. */
      if (events[e].type != EDR_EVENT_FILE_READ || cases[i].parent) {
        if (!matches(&record, 1, "truncated exclusion cannot grant an exception")) return 0;
      }
      edr_behavior_resolve_source_truncated(&record, marker);
      field[0] = '\0';
      if (!matches(&record, 1, "absent exclusion field retains positive detection")) return 0;
      snprintf(record.cmdline, sizeof(record.cmdline), "browser.exe trigger");
      snprintf(record.file_path, sizeof(record.file_path), "C:\\browser.exe\\Login Data");
      snprintf(record.exe_path, sizeof(record.exe_path), "C:\\browser.exe\\reader.exe");
      if (!matches(&record, 1, "name exclusions ignore other text fields")) return 0;
    }
  }
  return 1;
}

static int empty_and_path_exclusions(void) {
  EdrBehaviorRecord record;
  static const char *keys[] = {"process_name_not_regex_any", "parent_name_not_regex_any", "file_path_not_regex_any"};
  for (size_t i = 0u; i < sizeof(keys) / sizeof(keys[0]); ++i) {
    char condition[1024];
    snprintf(condition, sizeof(condition),
        "{\"command_regex_any\":[\"trigger\"],\"%s\":[\"^$\"]}", keys[i]);
    if (!load_rule("file_write", condition)) return 0;
    record_init(&record, EDR_EVENT_FILE_WRITE);
    record.process_name[0] = record.parent_name[0] = record.file_path[0] = '\0';
    if (!matches(&record, 1, "empty evidence does not match an exclusion regex")) return 0;
  }
  static const struct { const char *event; EdrEventType type; } events[] = {
    {"file_read", EDR_EVENT_FILE_READ}, {"file_write", EDR_EVENT_FILE_WRITE},
    {"network_connect", EDR_EVENT_NET_CONNECT},
  };
  for (size_t i = 0u; i < sizeof(events) / sizeof(events[0]); ++i) {
    char condition[1024];
    const char *positive = events[i].type == EDR_EVENT_NET_CONNECT
        ? "\"remote_port_in\":[1080]" : "\"process_name_in\":[\"reader.exe\"]";
    snprintf(condition, sizeof(condition),
        "{%s,\"file_path_not_regex_any\":[\"(?i)cache\"]}", positive);
    if (!load_rule(events[i].event, condition)) return 0;
    record_init(&record, events[i].type);
    if (!matches(&record, 1, "unlisted path remains detected")) return 0;
    char *field = events[i].type == EDR_EVENT_NET_CONNECT ? record.network_aux_path : record.file_path;
    size_t cap = events[i].type == EDR_EVENT_NET_CONNECT ? sizeof(record.network_aux_path) : sizeof(record.file_path);
    snprintf(field, cap, "C:\\cache\\Login Data");
    if (!matches(&record, 0, "matching observed path is excluded")) return 0;
    const char *marker = events[i].type == EDR_EVENT_NET_CONNECT
        ? "source.network_aux_path" : "source.file_path";
    edr_behavior_mark_source_truncated(&record, marker);
    if (events[i].type != EDR_EVENT_FILE_READ &&
        !matches(&record, 1, "truncated path cannot exempt a positive actor match")) return 0;
    edr_behavior_resolve_source_truncated(&record, marker);
    if (events[i].type == EDR_EVENT_NET_CONNECT) {
      edr_behavior_mark_source_truncated(&record, "source.file_path");
      if (!matches(&record, 0, "unrelated file truncation does not taint network path evidence")) return 0;
      edr_behavior_resolve_source_truncated(&record, "source.file_path");
    }
    field[0] = '\0';
    if (!matches(&record, 1, "missing path does not grant an exception")) return 0;
    snprintf(record.cmdline, sizeof(record.cmdline), "reader.exe cache trigger");
    snprintf(record.exe_path, sizeof(record.exe_path), "C:\\cache\\reader.exe");
    if (!matches(&record, 1, "path exclusion ignores command and image text")) return 0;
  }
  return 1;
}

static int network_positive_path_quality(void) {
  EdrBehaviorRecord record;
  if (!load_rule("network_connect",
      "{\"remote_port_in\":[1080],\"file_path_regex_any\":[\"Login Data$\"]}")) return 0;
  record_init(&record, EDR_EVENT_NET_CONNECT);
  if (!matches(&record, 1, "intact network auxiliary path satisfies positive predicate")) return 0;
  edr_behavior_mark_source_truncated(&record, "source.network_aux_path");
  if (!matches(&record, 0, "positive network path requires its own intact field")) return 0;
  edr_behavior_resolve_source_truncated(&record, "source.network_aux_path");
  edr_behavior_mark_source_truncated(&record, "source.file_path");
  if (!matches(&record, 1, "positive network path ignores unrelated file quality")) return 0;
  record.network_aux_path[0] = '\0';
  return matches(&record, 0, "missing network auxiliary path cannot satisfy positive predicate");
}

static int unknown_source_quality_exclusions(void) {
  static const struct { const char *event; EdrEventType type; } events[] = {
    {"file_write", EDR_EVENT_FILE_WRITE}, {"network_connect", EDR_EVENT_NET_CONNECT},
    {"script_powershell", EDR_EVENT_SCRIPT_POWERSHELL},
    {"script_wmi", EDR_EVENT_SCRIPT_WMI},
  };
  for (size_t i = 0u; i < sizeof(events) / sizeof(events[0]); ++i) {
    EdrBehaviorRecord record;
    char condition[1024];
    const char *positive = events[i].type == EDR_EVENT_NET_CONNECT
        ? "\"remote_port_in\":[1080]" : "\"command_regex_any\":[\"trigger\"]";
    snprintf(condition, sizeof(condition),
        "{%s,\"process_name_not_in\":[\"browser.exe\"]}", positive);
    if (!load_rule(events[i].event, condition)) return 0;
    record_init(&record, events[i].type);
    snprintf(record.process_name, sizeof(record.process_name), "browser.exe");
    if (!matches(&record, 0, "complete observed actor grants configured exception")) return 0;
    snprintf(record.source_completeness, sizeof(record.source_completeness), "NOT_EVALUABLE");
    if (!matches(&record, 1, "not-evaluable source cannot authorize exclusion")) return 0;
    snprintf(record.source_completeness, sizeof(record.source_completeness), "TRUNCATED");
    /* The authoritative consumer already rejects unprojected truncation.
     * The legacy record consumer must also avoid granting an exception. */
    if (!matches(&record, 0, "authoritative consumer retains positive quality boundary") ||
        !edr_p0_rule_ir_br_matches_index(&record, 0)) return 0;
    record.source_completeness[0] = '\0';
    snprintf(record.source_truncated_fields, sizeof(record.source_truncated_fields),
             "source.source_completeness");
    if (!matches(&record, 0, "authoritative consumer rejects unknown quality marker") ||
        !edr_p0_rule_ir_br_matches_index(&record, 0)) return 0;
  }
  return 1;
}

static int script_exclusions_require_observed_names(void) {
  static const struct { const char *event; EdrEventType type; const char *name; } events[] = {
    {"script_powershell", EDR_EVENT_SCRIPT_POWERSHELL, "powershell.exe"},
    {"script_wmi", EDR_EVENT_SCRIPT_WMI, "wmiprvse.exe"},
  };
  for (size_t i = 0u; i < sizeof(events) / sizeof(events[0]); ++i) {
    char condition[1024];
    EdrBehaviorRecord record;
    snprintf(condition, sizeof(condition),
        "{\"process_name_in\":[\"%s\"],\"process_name_not_in\":[\"%s\"]}",
        events[i].name, events[i].name);
    if (!load_rule(events[i].event, condition)) return 0;
    record_init(&record, events[i].type);
    snprintf(record.process_name, sizeof(record.process_name), "%s", events[i].name);
    if (!matches(&record, 0, "observed script actor grants configured exception")) return 0;
    record.process_name[0] = '\0';
    if (!matches(&record, 1, "script default actor satisfies positive but cannot authorize exclusion")) return 0;
  }
  return 1;
}

static int file_process_paths(void) {
  EdrBehaviorRecord record;
  const char *condition = "{\"file_path_regex_any\":[\"Login Data$\"],"
      "\"process_path_regex_any\":[\"(?i)^C:\\\\\\\\Trusted\\\\\\\\reader\\\\.exe$\"]}";
  static const struct { const char *event; EdrEventType type; } events[] = {
    {"file_read", EDR_EVENT_FILE_READ}, {"file_write", EDR_EVENT_FILE_WRITE},
  };
  for (size_t i = 0u; i < sizeof(events) / sizeof(events[0]); ++i) {
    if (!load_rule(events[i].event, condition)) return 0;
    record_init(&record, events[i].type);
    if (!matches(&record, 1, "file rule consumes actor executable path")) return 0;
    edr_behavior_mark_source_truncated(&record, "source.exe_path");
    if (!matches(&record, 0, "positive executable path requires intact evidence")) return 0;
    edr_behavior_resolve_source_truncated(&record, "source.exe_path");
    snprintf(record.exe_path, sizeof(record.exe_path), "C:\\Untrusted\\reader.exe");
    snprintf(record.cmdline, sizeof(record.cmdline), "C:\\Trusted\\reader.exe trigger");
    if (!matches(&record, 0, "command text cannot substitute actor path")) return 0;
    record.exe_path[0] = '\0';
    if (!matches(&record, 0, "missing actor path cannot satisfy positive path predicate")) return 0;
    if (events[i].type == EDR_EVENT_FILE_READ &&
        !edr_p0_rule_ir_file_read_path_may_match(record.file_path, NULL)) return 0;
    if (!load_rule(events[i].event,
        "{\"process_path_regex_any\":[\"(?i)^C:\\\\\\\\Trusted\\\\\\\\reader\\\\.exe$\"]}")) return 0;
    record_init(&record, events[i].type);
    if (!matches(&record, 1, "actor path alone is an evaluable positive constraint")) return 0;
    record.exe_path[0] = '\0';
    if (!matches(&record, 0, "actor path alone still requires its actual field")) return 0;
  }
  return 1;
}

static int rejected_candidate(unsigned schema, const char *event, const char *condition) {
  EdrP0RuleIrBinding before, after;
  if (!edr_p0_rule_ir_get_binding(&before) || !write_bundle(schema, event, condition) ||
      edr_p0_rule_ir_validate_candidate_path(s_path)) return 0;
  edr_p0_rule_ir_reload();
  return edr_p0_rule_ir_get_binding(&after) &&
         before.snapshot_epoch == after.snapshot_epoch &&
         strcmp(before.artifact_sha256, after.artifact_sha256) == 0;
}

static int candidate_contract(void) {
  static const char *new_keys[] = {
    "process_name_not_in", "parent_name_not_in", "process_name_not_regex_any",
    "parent_name_not_regex_any", "file_path_not_regex_any", "process_path_regex_any",
  };
  for (unsigned schema = 2u; schema <= 3u; ++schema) {
    if (!write_bundle(schema, "file_write", "{\"file_path_regex_any\":[\"Login Data$\"]}") ||
        !edr_p0_rule_ir_validate_candidate_path(s_path)) return 0;
    for (size_t i = 0u; i < sizeof(new_keys) / sizeof(new_keys[0]); ++i) {
      char condition[1024];
      snprintf(condition, sizeof(condition),
          "{\"file_path_regex_any\":[\"Login Data$\"],\"%s\":[\"browser.exe\"]}", new_keys[i]);
      if (!rejected_candidate(schema, "file_write", condition)) return 0;
    }
  }
  static const char *invalid[] = {
    "{\"process_name_not_in\":[\"browser.exe\"]}",
    "{\"file_path_regex_any\":[\"Login Data$\"],\"process_name_not_in\":null}",
    "{\"file_path_regex_any\":[\"Login Data$\"],\"process_name_not_in\":[]}",
    "{\"file_path_regex_any\":[\"Login Data$\"],\"process_name_not_in\":[\"\"]}",
    "{\"file_path_regex_any\":[\"Login Data$\"],\"process_name_not_regex_any\":[\"[\"]}",
    "{\"file_path_regex_any\":[\"Login Data$\"],\"file_path_not_regex_any\":[\"cache\"],\"file_path_not_regex_any\":[\"other\"]}",
  };
  for (size_t i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    if (!rejected_candidate(EDR_P0_RULE_IR_SCHEMA_VERSION, "file_write", invalid[i])) return 0;
  if (!rejected_candidate(EDR_P0_RULE_IR_SCHEMA_VERSION, "network_connect",
      "{\"remote_port_in\":[1080],\"parent_name_not_in\":[\"launcher.exe\"]}")) return 0;
  char long_name[129], condition[1024];
  memset(long_name, 'a', sizeof(long_name) - 1u); long_name[sizeof(long_name) - 1u] = '\0';
  snprintf(condition, sizeof(condition),
      "{\"file_path_regex_any\":[\"Login Data$\"],\"process_name_not_in\":[\"%s\"]}", long_name);
  if (!rejected_candidate(EDR_P0_RULE_IR_SCHEMA_VERSION, "file_write", condition)) return 0;
  for (int regex = 0; regex <= 1; ++regex) {
    char oversized[2048];
    size_t offset = (size_t)snprintf(oversized, sizeof(oversized),
        "{\"file_path_regex_any\":[\"Login Data$\"],\"%s\":[",
        regex ? "process_name_not_regex_any" : "process_name_not_in");
    for (int i = 0; i < (regex ? 41 : 25); ++i)
      offset += (size_t)snprintf(oversized + offset, sizeof(oversized) - offset,
                                "%s\"browser.exe\"", i ? "," : "");
    snprintf(oversized + offset, sizeof(oversized) - offset, "]}");
    if (!rejected_candidate(EDR_P0_RULE_IR_SCHEMA_VERSION, "file_write", oversized)) return 0;
  }
  return 1;
}

int main(void) {
  int okay = create_fixture() && name_exclusions() && empty_and_path_exclusions() &&
             network_positive_path_quality() && unknown_source_quality_exclusions() &&
             script_exclusions_require_observed_names() && file_process_paths() && candidate_contract();
  edr_p0_rule_ir_shutdown();
  if (s_path[0]) remove(s_path);
  if (!okay) fprintf(stderr, "P0 exclusion/actor-path contract failed\n");
  return okay ? 0 : 1;
}
