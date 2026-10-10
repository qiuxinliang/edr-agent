#include "edr/egress_request_policy.h"
#include "edr/agent_update_manifest.h"
#include "cJSON.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t allocation_calls, fail_allocation_at;
static void *fault_malloc(size_t size) {
  return ++allocation_calls == fail_allocation_at ? NULL : malloc(size);
}

static int check(const char *method, const char *path, const char *body) {
  char reason[128];
  return edr_egress_request_validate(method, path, body ? "application/json" : NULL,
      body, body ? strlen(body) : 0u, reason, sizeof(reason));
}
static void test_diagnostic_health_commitments(void) {
  const char *diagnostic = "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.648\",\"policy_version\":\"p\",\"engine_health\":{"
      "\"monitor\":{\"profile\":\"diagnostic\",\"request_id\":\"hm-1791650000000\"},"
      "\"command_delivery\":{\"executor\":{\"started\":true,\"accepting\":true,\"live_workers\":2}},"
      "\"sensor_health\":{\"sensor_interest\":{\"enabled\":true,\"loaded\":true,"
      "\"version\":\"edr-sensor-interest-v1-r289\",\"rules_version\":\"edr-dynamic-rules-v1-r289-8c5791d1\","
      "\"full_admission\":{\"file_read\":true,\"file_write\":true,\"registry_set\":true,\"contract_valid\":true,\"p0_binding_valid\":true},"
      "\"p0_artifact_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"p0_rule_coverage_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
      "\"manifest_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\","
      "\"manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\",\"p0_artifact_rule_count\":183,\"snapshot_epoch\":9}}}}";
  const char *basic = "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.648\",\"policy_version\":\"p\",\"engine_health\":{"
      "\"monitor\":{\"profile\":\"basic\",\"request_id\":\"\"},\"command_delivery\":{\"executor\":{\"accepting\":false}}}}";
  const char *cases[] = {basic, diagnostic};
  for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    cJSON *expected = cJSON_Parse(cases[index]); assert(expected);
    cJSON *raw = cJSON_Duplicate(expected, 1); assert(raw);
    cJSON *health = cJSON_GetObjectItemCaseSensitive(raw, "engine_health");
    cJSON *sensors = cJSON_GetObjectItemCaseSensitive(health, "sensor_health");
    if (!sensors) sensors = cJSON_AddObjectToObject(health, "sensor_health");
    assert(sensors);
    cJSON *filter = cJSON_AddObjectToObject(sensors, "event_filter"); assert(filter);
    cJSON *drop = cJSON_AddObjectToObject(filter, "last_drop"); assert(drop);
    assert(cJSON_AddStringToObject(drop, "path", "synthetic-private-path"));
    assert(cJSON_AddStringToObject(drop, "cmdline", "synthetic-private-command"));
    assert(cJSON_AddStringToObject(drop, "process", "synthetic-private-process"));
    assert(cJSON_AddStringToObject(health, "username", "synthetic-private-user"));
    cJSON *monitor = cJSON_GetObjectItemCaseSensitive(health, "monitor");
    assert(cJSON_AddStringToObject(monitor, "reason", "synthetic-private-reason"));
    cJSON *interest = cJSON_GetObjectItemCaseSensitive(sensors, "sensor_interest");
    if (interest) {
      assert(cJSON_AddStringToObject(interest, "cmdline", "synthetic-private-command"));
      assert(cJSON_AddStringToObject(interest, "path", "synthetic-private-path"));
      assert(cJSON_AddStringToObject(interest, "raw_event", "synthetic-private-event"));
      assert(cJSON_AddNumberToObject(interest, "process_names", 12));
      assert(cJSON_AddNumberToObject(interest, "matched", 99));
      cJSON *admission = cJSON_GetObjectItemCaseSensitive(interest, "full_admission");
      assert(cJSON_AddStringToObject(admission, "username", "synthetic-private-user"));
    }
    char *input = cJSON_PrintUnformatted(raw); assert(input);
    assert(check("POST", "ingest/engine-health", input) != 0);
    char reason[128];
    char *wire = edr_egress_health_project(input, reason, sizeof(reason)); assert(wire);
    assert(!strstr(wire, "synthetic-private") && !strstr(wire, "last_drop"));
    cJSON *projected = cJSON_Parse(wire); assert(projected);
    /* Compare every retained leaf, including an absent SI subtree for basic. */
    assert(cJSON_Compare(projected, expected, 1));
    assert(check("POST", "ingest/engine-health", wire) == 0);
    cJSON *update = cJSON_AddObjectToObject(projected, "engine_health_update"); assert(update);
    assert(cJSON_AddNumberToObject(update, "version", 2));
    assert(cJSON_AddStringToObject(update, "base", "rev"));
    assert(cJSON_AddArrayToObject(update, "removed"));
    char *delta = cJSON_PrintUnformatted(projected); assert(delta);
    assert(check("POST", "ingest/engine-health/delta", delta) == 0);
    free(delta); free(wire); free(input); cJSON_Delete(projected); cJSON_Delete(raw); cJSON_Delete(expected);
  }
  cJSON *unloaded = cJSON_Parse(diagnostic); assert(unloaded);
  cJSON *health = cJSON_GetObjectItemCaseSensitive(unloaded, "engine_health");
  cJSON *interest = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health, "sensor_health"), "sensor_interest");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(interest, "loaded", cJSON_CreateFalse()));
  const char *hashes[] = {"p0_artifact_sha256", "p0_rule_coverage_sha256", "manifest_sha256"};
  for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); ++i)
    assert(cJSON_ReplaceItemInObjectCaseSensitive(interest, hashes[i], cJSON_CreateString("")));
  assert(cJSON_ReplaceItemInObjectCaseSensitive(interest, "snapshot_epoch", cJSON_CreateNumber(0)));
  char *wire = cJSON_PrintUnformatted(unloaded); assert(wire);
  assert(check("POST", "ingest/engine-health", wire) == 0);
  char reason[128];
  char *projected_wire = edr_egress_health_project(wire, reason, sizeof(reason)); assert(projected_wire);
  cJSON *projected = cJSON_Parse(projected_wire); assert(projected && cJSON_Compare(projected, unloaded, 1));
  free(projected_wire); free(wire); cJSON_Delete(projected); cJSON_Delete(unloaded);
  const char *invalid[][3] = {
    {"monitor", "request_id", "\"synthetic private path\""},
    {"executor", "accepting", "\"true\""},
    {"interest", "enabled", "\"true\""}, {"interest", "loaded", "1"},
    {"interest", "version", "\"synthetic private path\""},
    {"interest", "rules_version", "\"synthetic/private/path\""},
    {"interest", "manifest_hash_mode", "\"synthetic private detail\""},
    {"interest", "p0_artifact_sha256", "\"bad-hash\""},
    {"interest", "p0_rule_coverage_sha256", "\"bbbb\""},
    {"interest", "manifest_sha256", "\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\""},
    {"interest", "p0_artifact_rule_count", "-1"},
    {"interest", "p0_artifact_rule_count", "4294967296"},
    {"interest", "snapshot_epoch", "1.5"}, {"interest", "snapshot_epoch", "-1"},
    {"admission", "file_read", "1"}, {"admission", "file_write", "\"true\""},
    {"admission", "registry_set", "null"}, {"admission", "contract_valid", "{}"},
    {"admission", "p0_binding_valid", "[]"}
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    cJSON *raw = cJSON_Parse(diagnostic); assert(raw);
    health = cJSON_GetObjectItemCaseSensitive(raw, "engine_health");
    interest = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health, "sensor_health"), "sensor_interest");
    cJSON *parent = interest;
    if (!strcmp(invalid[i][0], "monitor")) parent = cJSON_GetObjectItemCaseSensitive(health, "monitor");
    else if (!strcmp(invalid[i][0], "executor")) parent = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health, "command_delivery"), "executor");
    else if (!strcmp(invalid[i][0], "admission")) parent = cJSON_GetObjectItemCaseSensitive(interest, "full_admission");
    assert(cJSON_ReplaceItemInObjectCaseSensitive(parent, invalid[i][1], cJSON_Parse(invalid[i][2])));
    wire = cJSON_PrintUnformatted(raw); assert(wire);
    assert(check("POST", "ingest/engine-health", wire) != 0);
    cJSON *update = cJSON_AddObjectToObject(raw, "engine_health_update"); assert(update);
    assert(cJSON_AddNumberToObject(update, "version", 2)); assert(cJSON_AddStringToObject(update, "base", "rev"));
    assert(cJSON_AddArrayToObject(update, "removed"));
    char *delta = cJSON_PrintUnformatted(raw); assert(delta);
    assert(check("POST", "ingest/engine-health/delta", delta) != 0);
    free(delta); free(wire); cJSON_Delete(raw);
  }
  const char *removed = "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.648\",\"policy_version\":\"p\",\"engine_health\":{},"
      "\"engine_health_update\":{\"version\":2,\"base\":\"rev\",\"removed\":[\"/monitor/request_id\",\"/command_delivery/executor/accepting\",\"/sensor_health/sensor_interest\"]}}";
  assert(check("POST", "ingest/engine-health/delta", removed) == 0);
}
static void test_control_ack_transports(void) {
  /* Existing server CommandEnvelope transports, including queued ACK replay. */
  const char *allowed[] = {"https_control", "https_control_stream", "https_long_poll",
    "https_h2_server_stream", "https_http1_stream", "https_h2_long_poll",
    "https_http1_long_poll", "https_transport_v2"};
  const char *denied[] = {"", "https_h2_server_stream_extra", "https_h2_server_stream pmfe",
    "HTTPS_H2_SERVER_STREAM", "http1_stream", "legacy_websocket", "unknown"};
  char body[512];
  for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
    int n = snprintf(body, sizeof(body),
        "{\"endpoint_id\":\"ep\",\"command_id\":\"id\",\"status\":\"received\","
        "\"reason\":\"\",\"transport\":\"%s\",\"last_seq\":1}", allowed[i]);
    assert(n > 0 && (size_t)n < sizeof(body));
    assert(check("POST", "ingest/control/ack", body) == 0);
    cJSON *ack = cJSON_Parse(body); assert(ack);
    assert(cJSON_AddStringToObject(ack, "result", "synthetic-secret"));
    char *extra = cJSON_PrintUnformatted(ack); assert(extra);
    assert(check("POST", "ingest/control/ack", extra) != 0);
    free(extra); cJSON_Delete(ack);
  }
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
    int n = snprintf(body, sizeof(body),
        "{\"endpoint_id\":\"ep\",\"command_id\":\"id\",\"status\":\"received\","
        "\"transport\":\"%s\",\"last_seq\":1}", denied[i]);
    assert(n > 0 && (size_t)n < sizeof(body));
    assert(check("POST", "ingest/control/ack", body) != 0);
  }
}
static void test_health_leaf_delta(void) {
  const char *cases[][2]={
    {"{\"resource\":{\"cpu_percent\":3}}","[\"/resource/current_rss_mb\"]"},
    {"{}","[\"/resource/current_rss_mb\"]"},
    {"{\"resource\":{\"rss_mb\":5}}","[\"/resource/rss_mb\"]"},
    {"{}","[\"/resource\",\"/resource/rss_mb\"]"},
    {"{}","[\"/unknown/username\"]"},
    {"{}","[\"/_health_transport/revision\"]"},
    {"{}","[\"/resource/~2secret\"]"}
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
    char body[1024];snprintf(body,sizeof(body),"{\"endpoint_id\":\"ep\",\"agent_version\":\"1\",\"policy_version\":\"p\",\"engine_health\":%s,\"engine_health_update\":{\"version\":2,\"base\":\"rev\",\"removed\":%s}}",cases[i][0],cases[i][1]);
    assert((check("POST","ingest/engine-health/delta",body)==0)==(i<2));
  }
}
static cJSON *upgrade_entry(cJSON *root) {
  cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
  cJSON *manifest = cJSON_GetObjectItemCaseSensitive(health, "capability_manifest");
  return cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(manifest, "commands"), "agent_update_v1");
}
static void test_upgrade_health_consumers(void) {
  EdrAgentUpdateRuntimeInfo info = {0};
  info.ready = 1; info.protocol_version = 5; info.materialized = 1; info.full_installer_ready = 1;
  snprintf(info.source, sizeof(info.source), "embedded");
  snprintf(info.version, sizeof(info.version), "3.2.622");
  memset(info.sha256, 'a', 64); memset(info.runtime_identity_sha256, 'b', 64);
  snprintf(info.full_installer_reason, sizeof(info.full_installer_reason), "ready");
  snprintf(info.installation_family, sizeof(info.installation_family), "embedded_full_installer");
  snprintf(info.installation_baseline, sizeof(info.installation_baseline), "3.2.622");
  char fragment[2048], body[4096], why[128];
  assert(edr_agent_update_manifest_fragment(&info, fragment, sizeof(fragment)) == 0);
  fragment[strlen(fragment) - 1u] = 0;
  snprintf(body, sizeof(body), "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.622\",\"policy_version\":\"p\","
      "\"engine_health\":{\"capability_manifest\":{\"commands\":{%s}},"
      "\"communication\":{\"enterprise\":{\"protocol\":{\"negotiated_protocol\":\"h2\",\"control_stream_status\":\"connected\"}}},"
      "\"command_delivery\":{\"executor\":{\"started\":true,\"live_workers\":4,\"private_detail\":\"synthetic-secret\"}}}}", fragment);
  char *wire = edr_egress_health_project(body, why, sizeof(why)); assert(wire);
  assert(check("POST", "ingest/engine-health", wire) == 0);
  cJSON *root = cJSON_Parse(wire); assert(root);
  cJSON *entry = upgrade_entry(root); assert(entry);
  const char *fields[] = {"code_supported", "build_supported", "policy_enabled", "runtime_status",
    "updater_source", "updater_version", "updater_sha256", "updater_protocol_version", "updater_materialized",
    "updater_error_code", "runtime_identity_sha256", "full_installer_ready", "full_installer_reason"};
  cJSON *source = cJSON_Parse(body); assert(source);
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
    assert(cJSON_Compare(cJSON_GetObjectItemCaseSensitive(entry, fields[i]),
        cJSON_GetObjectItemCaseSensitive(upgrade_entry(source), fields[i]), 1));
  assert(cJSON_GetArraySize(entry) == 13);
  assert(strstr(wire, "\"negotiated_protocol\":\"h2\"") && strstr(wire, "\"started\":true") &&
      strstr(wire, "\"live_workers\":4"));
  assert(!strstr(wire, "installation_family") && !strstr(wire, "installation_baseline") && !strstr(wire, "synthetic-secret"));
  cJSON_Delete(source);

  /* The final gate rejects injected, mistyped or out-of-range facts. The
   * projector never changes an unknown failure into the success sentinel. */
  const char *invalid[][2] = {{"updater_source", "\"synthetic-secret\""},
    {"updater_version", "\"3.2.622 private\""}, {"updater_sha256", "\"short\""},
    {"runtime_identity_sha256", "\"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg\""},
    {"updater_protocol_version", "-1"}, {"updater_protocol_version", "5.5"},
    {"updater_protocol_version", "2147483648"}, {"updater_protocol_version", "\"5\""},
    {"updater_materialized", "1"}, {"full_installer_ready", "\"true\""},
    {"updater_error_code", "\"synthetic-secret\""}, {"updater_error_code", "null"},
    {"updater_error_code", "false"}, {"updater_error_code", "0"},
    {"updater_error_code", "[\"synthetic-secret\"]"},
    {"updater_error_code", "{\"text\":\"synthetic-secret\"}"},
    {"full_installer_reason", "\"synthetic-secret\""}, {"full_installer_reason", "[\"synthetic-secret\"]"},
    {"full_installer_reason", "{\"text\":\"synthetic-secret\"}"}, {"full_installer_reason", "true"}};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    cJSON *bad = cJSON_Duplicate(root, 1); assert(bad);
    assert(cJSON_ReplaceItemInObjectCaseSensitive(upgrade_entry(bad), invalid[i][0], cJSON_Parse(invalid[i][1])));
    char *raw = cJSON_PrintUnformatted(bad); assert(raw);
    assert(check("POST", "ingest/engine-health", raw) != 0);
    char *projected = edr_egress_health_project(raw, why, sizeof(why)); assert(projected);
    assert(check("POST", "ingest/engine-health", projected) == 0 && !strstr(projected, "synthetic-secret"));
    cJSON *decoded = cJSON_Parse(projected); assert(decoded);
    cJSON *value = cJSON_GetObjectItemCaseSensitive(upgrade_entry(decoded), invalid[i][0]);
    if (!strcmp(invalid[i][0], "updater_error_code") || !strcmp(invalid[i][0], "full_installer_reason"))
      assert(cJSON_IsString(value) && !strcmp(value->valuestring, "detail_available_locally"));
    else assert(value == NULL);
    cJSON_Delete(decoded); free(projected); free(raw); cJSON_Delete(bad);
  }

  /* Failure causes needed by dispatch remain exact, but do not permit free
   * text. A repairable missing uninstaller differs from a partial baseline. */
  const char *causes[] = {"installation_baseline_missing_unins000.exe",
    "installation_baseline_missing_unins000.dat", "installation_identity_conflict"};
  for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
    cJSON *bad = cJSON_Duplicate(root, 1); assert(bad);
    assert(cJSON_ReplaceItemInObjectCaseSensitive(upgrade_entry(bad), "full_installer_ready", cJSON_CreateFalse()));
    assert(cJSON_ReplaceItemInObjectCaseSensitive(upgrade_entry(bad), "full_installer_reason", cJSON_CreateString(causes[i])));
    assert(cJSON_ReplaceItemInObjectCaseSensitive(upgrade_entry(bad), "updater_error_code", cJSON_CreateString("embedded_materialized_hash_mismatch")));
    char *raw = cJSON_PrintUnformatted(bad); assert(raw);
    char *projected = edr_egress_health_project(raw, why, sizeof(why)); assert(projected);
    assert(check("POST", "ingest/engine-health", projected) == 0 && strstr(projected, causes[i]) &&
        strstr(projected, "embedded_materialized_hash_mismatch"));
    free(projected); free(raw); cJSON_Delete(bad);
  }

  cJSON *commands = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
      cJSON_GetObjectItemCaseSensitive(root, "engine_health"), "capability_manifest"), "commands");
  assert(cJSON_AddItemToObject(commands, "rtq_execute", cJSON_Duplicate(entry, 1)));
  char *cross = cJSON_PrintUnformatted(root); assert(cross);
  assert(check("POST", "ingest/engine-health", cross) != 0);
  char *projected = edr_egress_health_project(cross, why, sizeof(why)); assert(projected);
  cJSON *decoded = cJSON_Parse(projected); assert(decoded);
  commands = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
      cJSON_GetObjectItemCaseSensitive(decoded, "engine_health"), "capability_manifest"), "commands");
  assert(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(commands, "rtq_execute")) == 4);
  assert(check("POST", "ingest/engine-health", projected) == 0);
  cJSON_Delete(decoded); free(projected); free(cross); free(wire); cJSON_Delete(root);

  const char *leaves[][2] = {{"\"started\":\"true\"", "\"h2\""},
    {"\"live_workers\":-1", "\"h2\""}, {"\"live_workers\":1.5", "\"h2\""},
    {"\"live_workers\":4294967296", "\"h2\""}, {"\"live_workers\":4", "\"synthetic-secret\""}};
  for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); ++i) {
    snprintf(body, sizeof(body), "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.622\",\"policy_version\":\"p\","
        "\"engine_health\":{\"communication\":{\"enterprise\":{\"protocol\":{\"negotiated_protocol\":%s}}},"
        "\"command_delivery\":{\"executor\":{%s}}}}", leaves[i][1], leaves[i][0]);
    assert(check("POST", "ingest/engine-health", body) != 0);
  }
  const char *delta = "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.622\",\"policy_version\":\"p\","
      "\"engine_health\":{\"capability_manifest\":{\"commands\":{\"agent_update_v1\":{\"updater_error_code\":\"embedded_materialized_hash_mismatch\"}}},"
      "\"command_delivery\":{\"executor\":{\"started\":false,\"live_workers\":0}}},"
      "\"engine_health_update\":{\"version\":2,\"base\":\"rev\",\"removed\":[]}}";
  assert(check("POST", "ingest/engine-health/delta", delta) == 0);
}
int main(void) {
  test_diagnostic_health_commitments();
  test_upgrade_health_consumers();
  test_health_leaf_delta();
  test_control_ack_transports();
  {
    char why[96];
    const char *health = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"monitor\":{\"profile\":\"basic\"},\"p0_offline_queue_capacity\":{\"delivery\":{\"acked\":3,\"sent\":4}}}}";
    char *wire = edr_egress_health_project(health, why, sizeof(why));
    assert(wire && strstr(wire, "\"profile\":\"basic\"") && strstr(wire, "\"acked\":3"));
    assert(check("POST", "ingest/engine-health", wire) == 0); free(wire);
    assert(check("POST", "ingest/engine-health", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"monitor\":{\"profile\":\"synthetic-secret\"}}}") != 0);
  }

  const char *heartbeat = "{\"endpoint_id\":\"synthetic-endpoint\",\"agent_version\":\"test-v1\",\"policy_version\":\"synthetic-p1\"}";
  {
    char why[128];
    assert(edr_egress_request_validate_for_scope("POST","ingest/heartbeat","application/json",
      heartbeat,strlen(heartbeat),"synthetic-tenant","synthetic-endpoint",why,sizeof(why))==0);
    assert(edr_egress_request_validate_for_scope("POST","ingest/heartbeat","application/json",
      heartbeat,strlen(heartbeat),"synthetic-tenant","foreign-endpoint",why,sizeof(why))!=0);
    assert(!strcmp(why,"egress_scope_mismatch"));
    const char *config="{\"tenant_id\":\"foreign-tenant\",\"endpoint_id\":\"synthetic-endpoint\",\"agent_version\":\"v1\",\"policy_version\":\"p1\"}";
    assert(edr_egress_request_validate_for_scope("POST","ingest/config-status","application/json",
      config,strlen(config),"synthetic-tenant","synthetic-endpoint",why,sizeof(why))!=0);
  }
  assert(check("POST", "https://localhost/api/v1/ingest/heartbeat", heartbeat) == 0);
  assert(check("POST", "ingest/heartbeat", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"cmdline\":\"synthetic-secret\"}") != 0);
  assert(check("POST", "ingest/heartbeat", "{\"endpoint_id\":\"ep\",\"endpoint_id\":\"other\",\"agent_version\":\"v1\",\"policy_version\":\"p1\"}") != 0);
  assert(check("POST", "ingest/heartbeat", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\"} trailing") != 0);
  assert(check("POST", "ingest/heartbeat", "{\"endpoint_id\\u0000hidden\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\"}") != 0);
  assert(check("POST", "ingest/heartbeat", "{\"endpoint_id\":\"ep\\u0000hidden\",\"agent_version\":\"v1\",\"policy_version\":\"p1\"}") != 0);
  {
    size_t n = strlen(heartbeat);
    char *hidden = malloc(n + 20u); assert(hidden);
    memcpy(hidden, heartbeat, n); hidden[n] = 0; memcpy(hidden + n + 1u, "synthetic-secret", 16u);
    char why[128];
    assert(edr_egress_request_validate("POST", "ingest/heartbeat", "application/json", hidden,
        n + 17u, why, sizeof(why)) != 0);
    free(hidden);
  }
  const char *input = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"reported_at_unix_ms\":1700000000000,\"config_recovery\":{\"active\":true,\"source\":\"synthetic-secret-path\",\"reason\":\"synthetic-secret-error\"},\"sensor_health\":{\"event_filter\":{\"last_drop\":{\"cmdline\":\"synthetic-secret-command\"}},\"file_read_collection\":{\"metadata_gate\":{\"healthy\":false,\"durable_failures\":2,\"reason\":\"synthetic-secret-user\"}}},\"p0_acceptance\":{\"source_only\":{\"terminal_unhealthy\":true,\"retry_pending\":3,\"reason\":\"process_generation_or_correlation_unavailable\"}},\"p0_offline_queue_capacity\":{\"local_evidence_rows\":4,\"policy_held_rows\":1},\"egress\":{\"policy_version\":\"minimal-egress-v3\",\"task_results_supported\":true,\"result_delivery_renewal_supported\":true,\"denied_requests\":3},\"capability_manifest\":{\"schema\":\"edr.agent.capabilities.v1\",\"commands\":{\"result_delivery_renewal\":{\"code_supported\":true,\"build_supported\":true,\"policy_enabled\":true,\"runtime_status\":\"healthy\"}},\"features\":{\"pmfe\":{\"code_supported\":true,\"runtime_status\":\"healthy\",\"detail\":\"synthetic-secret-detail\"}}},\"raw_event\":{\"username\":\"synthetic-secret-user\"}}}";
  char reason[128];
  assert(check("POST", "ingest/engine-health", input) != 0);
  char *minimal = edr_egress_health_project(input, reason, sizeof(reason));
  size_t minimal_bytes = minimal ? strlen(minimal) : 0u;
  assert(minimal && !strstr(minimal, "synthetic-secret") && !strstr(minimal, "raw_event") && !strstr(minimal, "last_drop"));
  assert(strstr(minimal, "durable_failures") && strstr(minimal, "terminal_unhealthy") && strstr(minimal, "retry_pending"));
  assert(strstr(minimal, "local_evidence_rows") && strstr(minimal, "policy_held_rows") && strstr(minimal, "capability_manifest"));
  assert(strstr(minimal, "process_generation_or_correlation_unavailable"));
  assert(strstr(minimal, "detail_available_locally"));
  assert(strstr(minimal, "\"task_results_supported\":true"));
  assert(strstr(minimal, "\"result_delivery_renewal_supported\":true"));
  assert(strstr(minimal, "\"result_delivery_renewal\":{\"code_supported\":true"));
  assert(check("POST", "ingest/engine-health", minimal) == 0);
  /* Every cJSON allocation boundary either succeeds or fails the complete
   * projection. Never silently return a partial known health block on OOM. */
  {
    cJSON_Hooks hooks = {fault_malloc, free};
    allocation_calls = 0; fail_allocation_at = (size_t)-1; cJSON_InitHooks(&hooks);
    char *probe = edr_egress_health_project(input, reason, sizeof(reason));
    assert(probe); size_t total = allocation_calls; free(probe);
    for (size_t index = 1; index <= total; ++index) {
      allocation_calls = 0; fail_allocation_at = index;
      probe = edr_egress_health_project(input, reason, sizeof(reason));
      assert(!probe && reason[0]);
    }
    cJSON_InitHooks(NULL);
  }
  cJSON *root = cJSON_Parse(minimal), *h = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
  cJSON *recovery = cJSON_GetObjectItemCaseSensitive(h, "config_recovery");
  assert(cJSON_AddStringToObject(recovery, "active", "wrong-type"));
  char *wrong = cJSON_PrintUnformatted(root);
  assert(check("POST", "ingest/engine-health", wrong) != 0);
  free(wrong); cJSON_Delete(root); free(minimal);
  const char *delta = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"reported_at_unix_ms\":1700000000001},\"engine_health_update\":{\"version\":1,\"base\":\"r1\",\"removed\":[\"config_recovery\"]}}";
  assert(check("POST", "ingest/engine-health/delta", delta) == 0);
  assert(check("POST", "ingest/engine-health", delta) != 0);
  assert(check("POST", "ingest/engine-health/delta", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{},\"engine_health_update\":{\"version\":1,\"base\":\"r1\",\"removed\":[\"config_recovery\"]}}") == 0);
  assert(check("POST", "ingest/engine-health/delta", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{},\"engine_health_update\":{\"version\":1,\"base\":\"r1\",\"removed\":[\"raw_event\"]}}") != 0);
  assert(check("POST", "ingest/engine-health/delta", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"config_recovery\":{}},\"engine_health_update\":{\"version\":1,\"base\":\"r1\",\"removed\":[]}}") != 0);
  assert(check("POST", "ingest/engine-health", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{}}") != 0);
  assert(check("POST", "ingest/engine-health", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"resource\":{\"rss_mb\":\"synthetic-secret\"}}}") != 0);
  {
    const char *causes = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"p0_source_only_durability\":{\"reason\":\"source_only_legacy_ack_compatibility_pending\"},\"sensor_health\":{\"file_read_collection\":{\"metadata_gate\":{\"reason\":\"file_read_canonical_path_unresolved\"}}},\"p0_rule\":{\"last_degrade_reason\":\"p0_ir_not_ready\"},\"egress\":{\"capacity_limit_defaulted\":true}}}";
    char *projected = edr_egress_health_project(causes, reason, sizeof(reason));
    assert(projected && strstr(projected, "source_only_legacy_ack_compatibility_pending") &&
        strstr(projected, "file_read_canonical_path_unresolved") && strstr(projected, "p0_ir_not_ready") &&
        strstr(projected, "capacity_limit_defaulted"));
    assert(check("POST", "ingest/engine-health", projected) == 0);
    free(projected);
    assert(check("POST", "ingest/engine-health", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"p0_source_only_durability\":{\"reason\":\"source_only_pending synthetic-secret\"}}}") != 0);
  }
  const char *denied[] = {"ingest/report-command-result", "ingest/upload-file", "endpoints/ep/attack-surface", "ingest/agent-upgrade-event", "unknown", "ingest/report-events?bypass=1"};
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) assert(check("POST", denied[i], heartbeat) != 0);
  assert(check("POST", "ingest/report-events", "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"batch_id\":\"id\",\"payload\":\"AAAA\"}") != 0);
  assert(check("GET", "agent/runtime-policy.toml", NULL) == 0);
  assert(check("GET", "agent/rules.toml?raw_event=secret", NULL) != 0);
  assert(check("GET", "agent/comms-route-profile?endpoint_id=ep&tenant_id=tenant", NULL) == 0);
  assert(check("GET", "ingest/control/stream?endpoint_id=ep&h2=1&zstd=0", NULL) == 0);
  assert(check("GET", "ingest/poll-commands?endpoint_id=ep&limit=8&wait_s=30", NULL) == 0);
  assert(check("GET", "ingest/poll-commands?endpoint_id=ep&limit=80", NULL) != 0);
  assert(check("GET", "ingest/control/stream?endpoint_id=ep&cmdline=secret", NULL) != 0);
  assert(check("GET", "ingest/control/stream?endpoint_id=ep&endpoint_id=other", NULL) != 0);
  assert(check("GET", "agent/forensic-collector/manifest?kind=velociraptor&os=windows&arch=amd64", NULL) == 0);
  assert(check("GET", "agent/download/win_3.2.589", NULL) == 0);
  assert(check("GET", "unknown/download", NULL) != 0);
  assert(check("PUT", "ingest/heartbeat", heartbeat) != 0);
  assert(check("POST", "ingest/control/hello", "{\"type\":\"client_hello\",\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"capabilities\":{\"h2\":true,\"zstd\":false},\"supported_schema\":[\"schema-v1\"]}") == 0);
  assert(check("POST", "ingest/control/ack", "{\"endpoint_id\":\"ep\",\"command_id\":\"id\",\"status\":\"received\",\"reason\":\"\",\"transport\":\"https_control\",\"last_seq\":1}") == 0);
  assert(check("POST", "ingest/control/ack", "{\"endpoint_id\":\"ep\",\"command_id\":\"id\",\"status\":\"received\",\"result\":\"synthetic-secret\"}") != 0);
  assert(check("POST", "agent/lifecycle/uninstall-attest", "{\"schema\":\"edr.endpoint.uninstall.attestation.v1\",\"endpoint_id\":\"ep\",\"task_id\":\"id\",\"service_removed\":true,\"process_stopped\":true,\"install_dir_removed\":true,\"completed_at\":\"2026-10-04T00:00:00.000Z\"}") == 0);
  printf("request policy passed; synthetic health before=%zu after=%zu bytes\n", strlen(input), minimal_bytes);
  return 0;
}
