#include "edr/p0_source_only_contract.h"

#include "cJSON.h"

#include <stdio.h>
#include <string.h>

static const cJSON *p0_json_unique_member(const cJSON *object, const char *name) {
  const cJSON *member;
  const cJSON *found = NULL;
  if (!cJSON_IsObject(object) || !name || !name[0]) return NULL;
  for (member = object->child; member; member = member->next) {
    if (member->string && strcmp(member->string, name) == 0) {
      if (found) return NULL;
      found = member;
    }
  }
  return found;
}

static int p0_json_string_equals(const cJSON *object, const char *name,
                                 const char *expected) {
  const cJSON *member = p0_json_unique_member(object, name);
  return cJSON_IsString(member) && member->valuestring && expected &&
         strcmp(member->valuestring, expected) == 0;
}

static int p0_json_nonempty_string(const cJSON *object, const char *name) {
  const cJSON *member = p0_json_unique_member(object, name);
  return cJSON_IsString(member) && member->valuestring && member->valuestring[0];
}

static int p0_json_hex64(const char *value) {
  size_t i;
  if (!value || strlen(value) != 64u) return 0;
  for (i = 0u; i < 64u; ++i) {
    const char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static int p0_json_member_absent(const cJSON *object, const char *name) {
  return p0_json_unique_member(object, name) == NULL;
}

static int p0_artifact_provenance_is(const char *detection_context,
                                     const char *source, const char *quality) {
  const char *end = NULL;
  const cJSON *evidence;
  const cJSON *artifact;
  cJSON *root;
  int ok = 0;
  if (!detection_context || !detection_context[0] || !source || !quality) return 0;
  root = cJSON_ParseWithLengthOpts(detection_context, strlen(detection_context) + 1u,
                                   &end, 1);
  if (!root || !end || *end != '\0' || !cJSON_IsObject(root)) {
    cJSON_Delete(root);
    return 0;
  }
  evidence = p0_json_unique_member(root, "evidence");
  artifact = p0_json_unique_member(evidence, "artifact");
  ok = cJSON_IsObject(artifact) &&
       p0_json_string_equals(artifact, "source", source) &&
       p0_json_string_equals(artifact, "quality", quality);
  cJSON_Delete(root);
  return ok;
}

int edr_p0_artifact_identity_is_action_authoritative(const char *detection_context) {
  return p0_artifact_provenance_is(detection_context, "process_image_section",
                                   "action_authoritative");
}

static int p0_source_only_forbids_rule_binding(const cJSON *root) {
  return p0_json_member_absent(root, "rule_id") &&
         p0_json_member_absent(root, "rules_bundle_version") &&
         p0_json_member_absent(root, "rules_bundle_sha256") &&
         p0_json_member_absent(root, "alert") &&
         p0_json_member_absent(root, "action");
}

static int p0_ruleset_event_type(EdrEventType type) {
  switch (type) {
  case EDR_EVENT_PROCESS_CREATE:
  case EDR_EVENT_FILE_READ:
  case EDR_EVENT_FILE_WRITE:
  case EDR_EVENT_NET_CONNECT:
  case EDR_EVENT_REG_SET_VALUE:
    return 1;
  default:
    return 0;
  }
}

static int p0_collector_metadata_is_valid(const EdrP0SourceOnlyReason *contract,
                                           const cJSON *root) {
  const cJSON *metadata;
  const cJSON *canonical_path;
  const cJSON *file_key;
  const cJSON *pid;
  const cJSON *start_key;
  const cJSON *event_time;
  const cJSON *rejected_field;
  int path_may_be_null;
  if (!contract) return 0;
  metadata = p0_json_unique_member(root, "collector_metadata");
  if (!cJSON_IsObject(metadata)) return 0;
  canonical_path = p0_json_unique_member(metadata, "canonical_path");
  file_key = p0_json_unique_member(metadata, "file_key");
  pid = p0_json_unique_member(metadata, "pid");
  start_key = p0_json_unique_member(metadata, "process_start_key");
  event_time = p0_json_unique_member(metadata, "event_time_ns");
  rejected_field = p0_json_unique_member(metadata, "rejected_field");
  path_may_be_null = strcmp(contract->reason,
                            EDR_P0_FILE_READ_REASON_CANONICAL_PATH_UNRESOLVED) == 0 ||
                     strcmp(contract->reason,
                            EDR_P0_FILE_READ_REASON_PAYLOAD_UNAVAILABLE) == 0 ||
                     strcmp(contract->reason,
                            EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0;
  if (!(cJSON_IsString(canonical_path) || (path_may_be_null && cJSON_IsNull(canonical_path))) ||
      !(cJSON_IsString(file_key) || cJSON_IsNull(file_key)) ||
      !(cJSON_IsString(pid) || cJSON_IsNumber(pid) || cJSON_IsNull(pid)) ||
      !(cJSON_IsString(start_key) || cJSON_IsNumber(start_key) || cJSON_IsNull(start_key)) ||
      !cJSON_IsString(event_time) || !event_time->valuestring ||
      !cJSON_IsString(rejected_field) || !rejected_field->valuestring ||
      !contract->rejected_field ||
      strcmp(rejected_field->valuestring, contract->rejected_field) != 0) {
    return 0;
  }
  if (strcmp(contract->reason, EDR_P0_FILE_READ_REASON_EVENT_TIME_UNAVAILABLE) == 0) {
    return strcmp(event_time->valuestring, "0") == 0;
  }
  return strcmp(event_time->valuestring, "0") != 0;
}

static int p0_delivery_metadata_is_valid(const cJSON *root) {
  const cJSON *loss_detected = p0_json_unique_member(root, "loss_detected");
  const cJSON *delivery = p0_json_unique_member(root, "source_only_delivery");
  return cJSON_IsTrue(loss_detected) && cJSON_IsObject(delivery) &&
         p0_json_nonempty_string(delivery, "queue_nonce") &&
         p0_json_nonempty_string(delivery, "latch_counter") &&
         p0_json_nonempty_string(delivery, "latch_epoch") &&
         p0_json_nonempty_string(delivery, "commitment_sha256") &&
         p0_json_nonempty_string(delivery, "latch_id");
}

int edr_p0_source_only_validate_record(const EdrBehaviorRecord *record) {
  const char *end = NULL;
  cJSON *root;
  const cJSON *reason;
  const cJSON *stage;
  const EdrP0SourceOnlyReason *contract;
  int ok = 0;
  if (!record || !record->event_id[0] || !record->detection_context[0]) return 0;
  root = cJSON_ParseWithLengthOpts(record->detection_context,
                                   strlen(record->detection_context) + 1u, &end, 1);
  if (!root || !end || *end != '\0' || !cJSON_IsObject(root) ||
      !p0_json_string_equals(root, "p0_disposition", "NOT_EVALUABLE") ||
      !p0_json_string_equals(root, "source_contract_version",
                             EDR_P0_SOURCE_ONLY_CONTRACT_VERSION)) {
    cJSON_Delete(root);
    return 0;
  }
  reason = p0_json_unique_member(root, "reason");
  stage = p0_json_unique_member(root, "stage");
  if (!cJSON_IsString(reason) || !reason->valuestring || !cJSON_IsString(stage) ||
      !stage->valuestring || !(contract = edr_p0_source_only_reason_find(reason->valuestring)) ||
      strcmp(stage->valuestring, edr_p0_source_only_stage_name(contract->stage)) != 0 ||
      (contract->stage == EDR_P0_SOURCE_ONLY_STAGE_DIRECT
           ? !p0_json_member_absent(root, "gate_id")
           : !p0_json_string_equals(root, "gate_id", contract->gate_id))) {
    cJSON_Delete(root);
    return 0;
  }
  switch (contract->stage) {
  case EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION:
    ok = record->type == EDR_EVENT_PROCESS_CREATE && p0_source_only_forbids_rule_binding(root);
    break;
  case EDR_P0_SOURCE_ONLY_STAGE_DIRECT: {
    const cJSON *sha256;
    ok = p0_json_member_absent(root, "gate_id") && p0_json_nonempty_string(root, "rule_id") &&
         p0_json_nonempty_string(root, "rules_bundle_version") &&
         (sha256 = p0_json_unique_member(root, "rules_bundle_sha256")) != NULL &&
         cJSON_IsString(sha256) && p0_json_hex64(sha256->valuestring) &&
         p0_json_member_absent(root, "alert") && p0_json_member_absent(root, "action");
    break;
  }
  case EDR_P0_SOURCE_ONLY_STAGE_RULESET_EVALUATION:
    ok = p0_ruleset_event_type(record->type) && p0_source_only_forbids_rule_binding(root);
    break;
  case EDR_P0_SOURCE_ONLY_STAGE_COLLECTOR_EVIDENCE_GATE:
    ok = record->type == EDR_EVENT_FILE_READ && p0_source_only_forbids_rule_binding(root) &&
         p0_collector_metadata_is_valid(contract, root);
    break;
  case EDR_P0_SOURCE_ONLY_STAGE_SOURCE_ONLY_DELIVERY:
    ok = record->type == EDR_EVENT_CAPABILITY_AUDIT && record->pid == 0u &&
         p0_source_only_forbids_rule_binding(root) && p0_delivery_metadata_is_valid(root);
    break;
  default:
    ok = 0;
    break;
  }
  cJSON_Delete(root);
  return ok;
}

int edr_p0_source_only_build_pre_evaluation_record(const EdrBehaviorRecord *source,
                                                    const char *reason,
                                                    EdrBehaviorRecord *out) {
  const EdrP0SourceOnlyReason *contract;
  const char *evidence;
  size_t evidence_len;
  char preserved[sizeof(out->detection_context)];
  if (!source || !out || !reason || !reason[0] || source->type != EDR_EVENT_PROCESS_CREATE) {
    return 0;
  }
  contract = edr_p0_source_only_reason_find(reason);
  if (!contract || contract->stage != EDR_P0_SOURCE_ONLY_STAGE_PRE_EVALUATION ||
      strcmp(contract->gate_id, EDR_P0_PROCESS_EVIDENCE_GATE) != 0) {
    return 0;
  }
  *out = *source;
  snprintf(out->source_completeness, sizeof(out->source_completeness), "%s",
           "NOT_EVALUABLE");
  evidence = strstr(source->detection_context, "\"evidence\":");
  if (evidence) {
    evidence += strlen("\"evidence\":");
    evidence_len = strlen(evidence);
    if (evidence_len > 0u && evidence[evidence_len - 1u] == '}') evidence_len--;
    if (evidence_len < sizeof(preserved)) {
      const int written = snprintf(
          preserved, sizeof(preserved),
          "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
          "\"source_contract_version\":\"%s\",\"stage\":\"pre_evaluation\","
          "\"gate_id\":\"%s\",\"evidence\":%.*s}",
          reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, contract->gate_id,
          (int)evidence_len, evidence);
      if (written >= 0 && (size_t)written < sizeof(preserved)) {
        snprintf(out->detection_context, sizeof(out->detection_context), "%s", preserved);
        return edr_p0_source_only_validate_record(out);
      }
    }
  }
  if (snprintf(out->detection_context, sizeof(out->detection_context),
               "{\"p0_disposition\":\"NOT_EVALUABLE\",\"reason\":\"%s\","
               "\"source_contract_version\":\"%s\",\"stage\":\"pre_evaluation\","
               "\"gate_id\":\"%s\",\"evidence\":{\"hash\":{\"source\":"
               "\"background_file_hash\",\"quality\":\"unknown\",\"reason\":"
               "\"not_requested\"},\"signature\":{\"status\":\"unknown\","
               "\"source\":\"background_authenticode\",\"quality\":\"unknown\","
               "\"reason\":\"not_requested\"}}}",
               reason, EDR_P0_SOURCE_ONLY_CONTRACT_VERSION, contract->gate_id) < 0) {
    return 0;
  }
  return edr_p0_source_only_validate_record(out);
}
