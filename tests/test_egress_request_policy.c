#include "edr/egress_request_policy.h"
#include "edr/agent_update_manifest.h"
#include "../src/core/evidence_cache_health_json.h"
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
static const char *const parent_exit_metrics[] = {
  "exit_invalid", "exit_duplicate", "exit_conflict", "pending_exits",
  "pending_exits_stored", "pending_exits_applied", "pending_exits_expired",
  "pending_exits_capacity_rejected"
};
static cJSON *parent_exit_health(const char *profile, int zero) {
  cJSON *root = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.669\","
      "\"policy_version\":\"p\",\"engine_health\":{\"monitor\":{},"
      "\"resource\":{\"process_id\":1234,\"cpu_percent\":2},"
      "\"sensor_health\":{\"process_identity\":{\"missing_create\":9}}}}");
  assert(root);
  cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
  assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health, "monitor"), "profile", profile));
  cJSON *identity = cJSON_GetObjectItemCaseSensitive(
      cJSON_GetObjectItemCaseSensitive(health, "sensor_health"), "process_identity");
  for (size_t i = 0; i < sizeof(parent_exit_metrics) / sizeof(parent_exit_metrics[0]); ++i)
    assert(cJSON_AddNumberToObject(identity, parent_exit_metrics[i], zero ? 0 : (double)(i + 1u)));
  return root;
}
static void check_health_routes(cJSON *root, int allowed) {
  char *body = cJSON_PrintUnformatted(root); assert(body);
  assert((check("POST", "ingest/engine-health", body) == 0) == allowed);
  free(body);
  cJSON *update = cJSON_AddObjectToObject(root, "engine_health_update"); assert(update);
  assert(cJSON_AddNumberToObject(update, "version", 2));
  assert(cJSON_AddStringToObject(update, "base", "rev"));
  assert(cJSON_AddArrayToObject(update, "removed"));
  body = cJSON_PrintUnformatted(root); assert(body);
  assert((check("POST", "ingest/engine-health/delta", body) == 0) == allowed);
  free(body); cJSON_DeleteItemFromObjectCaseSensitive(root, "engine_health_update");
}
static void test_evidence_pressure_health_projection(void) {
  const char *profiles[] = {"basic", "diagnostic"};
  for (size_t profile = 0; profile < sizeof(profiles) / sizeof(profiles[0]); ++profile) {
    for (int pressure = 0; pressure <= 1; ++pressure) {
      cJSON *expected = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"test-v1\","
          "\"policy_version\":\"p\",\"engine_health\":{\"monitor\":{},\"evidence_cache\":{}}}");
      assert(expected);
      cJSON *health = cJSON_GetObjectItemCaseSensitive(expected, "engine_health");
      assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health, "monitor"), "profile", profiles[profile]));
      assert(cJSON_AddBoolToObject(cJSON_GetObjectItemCaseSensitive(health, "evidence_cache"), "pressure_active", pressure));
      check_health_routes(expected, 1);

      cJSON *raw = cJSON_Duplicate(expected, 1); assert(raw);
      cJSON *cache = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(raw, "engine_health"), "evidence_cache");
      assert(cJSON_AddStringToObject(cache, "last_error", "synthetic-private-database-error"));
      assert(cJSON_AddStringToObject(cache, "command_line", "synthetic-private-command"));
      assert(cJSON_AddStringToObject(cache, "path", "synthetic-private-path"));
      assert(cJSON_AddStringToObject(cache, "index", "synthetic-private-index"));
      assert(cJSON_AddStringToObject(cache, "dictionary", "synthetic-private-dictionary"));
      assert(cJSON_AddStringToObject(cache, "payload_hash", "synthetic-private-hash"));
      cJSON *event = cJSON_AddObjectToObject(cache, "raw_event"); assert(event);
      assert(cJSON_AddStringToObject(event, "payload", "synthetic-private-event"));
      assert(cJSON_AddNumberToObject(cache, "db_bytes", 8192));
      assert(cJSON_AddBoolToObject(cache, "db_open", 1));
      check_health_routes(raw, 0);
      char *body = cJSON_PrintUnformatted(raw); assert(body);
      char reason[128]; char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
      cJSON *projected = cJSON_Parse(wire); assert(projected);
      /* The top-level cache exposes exactly one boolean, including false. */
      assert(cJSON_Compare(projected, expected, 1));
      cache = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(projected, "engine_health"), "evidence_cache");
      assert(cJSON_GetArraySize(cache) == 1);
      const cJSON *value = cJSON_GetObjectItemCaseSensitive(cache, "pressure_active");
      assert(cJSON_IsBool(value) && cJSON_IsTrue(value) == pressure);
      assert(!strstr(wire, "synthetic-private"));
      check_health_routes(projected, 1);
      free(body); free(wire); cJSON_Delete(projected); cJSON_Delete(raw); cJSON_Delete(expected);
    }
  }
  const char *invalid[] = {"\"true\"", "\"false\"", "\"synthetic-private\"", "0", "1", "-1", "null", "{}", "[]"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    cJSON *raw = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"test-v1\","
        "\"policy_version\":\"p\",\"engine_health\":{\"monitor\":{\"profile\":\"basic\"},"
        "\"evidence_cache\":{\"pressure_active\":false}}}");
    assert(raw);
    cJSON *health = cJSON_GetObjectItemCaseSensitive(raw, "engine_health");
    cJSON *cache = cJSON_GetObjectItemCaseSensitive(health, "evidence_cache");
    assert(cJSON_ReplaceItemInObjectCaseSensitive(cache, "pressure_active", cJSON_Parse(invalid[i])));
    check_health_routes(raw, 0);
    char *body = cJSON_PrintUnformatted(raw); assert(body);
    char reason[128]; char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
    cJSON *projected = cJSON_Parse(wire); assert(projected);
    cJSON_DeleteItemFromObjectCaseSensitive(health, "evidence_cache");
    assert(cJSON_Compare(projected, raw, 1));
    check_health_routes(projected, 1);
    free(body); free(wire); cJSON_Delete(projected); cJSON_Delete(raw);
  }
}
static void test_parent_exit_health_projection(void) {
  /* Both monitor profiles publish these bounded diagnostics. This exercises
   * the real projection/HTTP gate, not the Agent's runtime snapshot builder. */
  const char *profiles[] = {"basic", "diagnostic"};
  for (size_t profile = 0; profile < 2u; ++profile) {
    for (int zero = 0; zero < 2; ++zero) {
      cJSON *expected = parent_exit_health(profiles[profile], zero);
      cJSON *raw = cJSON_Duplicate(expected, 1); assert(raw);
      cJSON *health = cJSON_GetObjectItemCaseSensitive(raw, "engine_health");
      cJSON *identity = cJSON_GetObjectItemCaseSensitive(
          cJSON_GetObjectItemCaseSensitive(health, "sensor_health"), "process_identity");
      assert(cJSON_AddStringToObject(identity, "parent_path", "synthetic-private-parent"));
      assert(cJSON_AddNumberToObject(identity, "unknown_counter", 7));
      assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health, "resource"),
                                    "process_path", "synthetic-private-agent"));
      check_health_routes(raw, 0);
      char *body = cJSON_PrintUnformatted(raw); assert(body);
      char reason[128]; char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
      cJSON *projected = cJSON_Parse(wire); assert(projected);
      assert(cJSON_Compare(projected, expected, 1));
      assert(!strstr(wire, "synthetic-private") && !strstr(wire, "unknown_counter"));
      check_health_routes(projected, 1);
      free(body); free(wire); cJSON_Delete(projected); cJSON_Delete(raw); cJSON_Delete(expected);
    }
  }
  const char *invalid[] = {"\"synthetic-private-counter\"", "true", "null", "{}", "[]",
                           "-1", "1.5", "1e20"};
  const size_t count = sizeof(parent_exit_metrics) / sizeof(parent_exit_metrics[0]);
  for (size_t field = 0; field <= count; ++field) {
    for (size_t value = 0; value < sizeof(invalid) / sizeof(invalid[0]); ++value) {
      cJSON *raw = parent_exit_health("basic", 0);
      cJSON *health = cJSON_GetObjectItemCaseSensitive(raw, "engine_health");
      cJSON *parent = field == count ? cJSON_GetObjectItemCaseSensitive(health, "resource") :
          cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health, "sensor_health"), "process_identity");
      const char *key = field == count ? "process_id" : parent_exit_metrics[field];
      assert(cJSON_ReplaceItemInObjectCaseSensitive(parent, key, cJSON_Parse(invalid[value])));
      check_health_routes(raw, 0);
      char *body = cJSON_PrintUnformatted(raw); assert(body);
      char reason[128]; char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
      cJSON_DeleteItemFromObjectCaseSensitive(parent, key);
      cJSON *projected = cJSON_Parse(wire); assert(projected);
      assert(cJSON_Compare(projected, raw, 1));
      check_health_routes(projected, 1);
      free(body); free(wire); cJSON_Delete(projected); cJSON_Delete(raw);
    }
  }
  cJSON *raw = parent_exit_health("basic", 0);
  cJSON *resource = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(raw, "engine_health"), "resource");
  assert(cJSON_ReplaceItemInObjectCaseSensitive(resource, "process_id", cJSON_CreateNumber(4294967295.0)));
  check_health_routes(raw, 1);
  assert(cJSON_ReplaceItemInObjectCaseSensitive(resource, "process_id", cJSON_CreateNumber(4294967296.0)));
  check_health_routes(raw, 0);
  cJSON_Delete(raw);
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
static void test_parent_context_capability_health_projection(void) {
  const struct { int build, policy; const char *runtime; } states[] = {
    {1, 1, "healthy"}, {1, 1, "unavailable"}, {1, 0, "disabled"}, {0, 1, "unavailable"}
  };
  for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
    char body[2048], why[128];
    snprintf(body, sizeof(body), "{\"endpoint_id\":\"ep\",\"agent_version\":\"3.2.692\","
        "\"policy_version\":\"p\",\"engine_health\":{\"capability_manifest\":{\"commands\":{"
        "\"parent_context_query_v1\":{\"code_supported\":true,\"build_supported\":%s,"
        "\"policy_enabled\":%s,\"runtime_status\":\"%s\",\"rules_count\":7,\"source_event_id\":\"synthetic-private-source\","
        "\"parent\":{\"cmdline\":\"synthetic-private-command\",\"path\":\"synthetic-private-path\"}}}}}}",
        states[i].build ? "true" : "false", states[i].policy ? "true" : "false", states[i].runtime);
    assert(check("POST", "ingest/engine-health", body) != 0);
    char *wire = edr_egress_health_project(body, why, sizeof(why)); assert(wire);
    assert(!strstr(wire, "synthetic-private") && !strstr(wire, "source_event_id"));
    cJSON *decoded = cJSON_Parse(wire); assert(decoded);
    cJSON *commands = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(decoded, "engine_health"), "capability_manifest"), "commands");
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(commands, "parent_context_query_v1");
    assert(cJSON_IsObject(entry) && cJSON_GetArraySize(entry) == 4);
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(entry, "code_supported")));
    assert(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(entry, "build_supported")) &&
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(entry, "build_supported")) == states[i].build);
    assert(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(entry, "policy_enabled")) &&
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(entry, "policy_enabled")) == states[i].policy);
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(entry, "runtime_status")->valuestring, states[i].runtime));
    check_health_routes(decoded, 1);
    assert(cJSON_ReplaceItemInObjectCaseSensitive(entry, "build_supported", cJSON_CreateString("true")));
    check_health_routes(decoded, 0);
    cJSON_Delete(decoded); free(wire);
  }
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
static void test_retention_floor_health_is_numeric_and_bounded(void) {
  const char *raw = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\","
      "\"engine_health\":{\"p0_acceptance\":{\"evidence_cache\":{\"accounting\":{\"local_retention\":{"
      "\"active_ms\":259200001,\"clock_valid\":1,\"clock_failures\":0,\"clock_cause_code\":0,"
      "\"parent_protections\":3,\"floor_held\":4,\"candidate_id\":\"PRIVATE_OWNER\","
      "\"command\":\"PRIVATE_COMMAND\",\"facts\":[\"PRIVATE_FACT\"]}}}}}}";
  char why[128];
  assert(check("POST", "ingest/engine-health", raw) != 0);
  char *projected = edr_egress_health_project(raw, why, sizeof(why));
  assert(projected && !strstr(projected, "PRIVATE_") && !strstr(projected, "candidate_id"));
  assert(check("POST", "ingest/engine-health", projected) == 0);
  cJSON *o = cJSON_Parse(projected); assert(o);
  cJSON *floor = cJSON_GetObjectItemCaseSensitive(o, "engine_health");
  floor = cJSON_GetObjectItemCaseSensitive(floor, "p0_acceptance");
  floor = cJSON_GetObjectItemCaseSensitive(floor, "evidence_cache");
  floor = cJSON_GetObjectItemCaseSensitive(floor, "accounting");
  floor = cJSON_GetObjectItemCaseSensitive(floor, "local_retention");
  const char *fields[] = {"active_ms", "clock_valid", "clock_failures", "clock_cause_code",
                          "parent_protections", "floor_held"};
  const double values[] = {259200001, 1, 0, 0, 3, 4};
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    cJSON *value = cJSON_GetObjectItemCaseSensitive(floor, fields[i]);
    assert(cJSON_IsNumber(value) && value->valuedouble == values[i]);
  }
  assert(cJSON_ReplaceItemInObjectCaseSensitive(floor, "active_ms", cJSON_CreateNumber(-1)));
  char *bad = cJSON_PrintUnformatted(o); assert(bad);
  assert(check("POST", "ingest/engine-health", bad) != 0); free(bad);
  assert(cJSON_ReplaceItemInObjectCaseSensitive(floor, "active_ms", cJSON_CreateString("PRIVATE_CLOCK")));
  bad = cJSON_PrintUnformatted(o); assert(bad);
  assert(check("POST", "ingest/engine-health", bad) != 0); free(bad);
  cJSON_Delete(o); free(projected);
}

static void test_capacity_health_producer_and_projection(void) {
  EdrEvidenceCacheStatus st = {0};
  st.db_open = 1; st.storage_format = 2; st.accounting_generation = 7;
  st.candidate_requests = 100; st.candidate_admitted = 60;
  st.candidate_reused = 10; st.candidate_rejected = 30;
  st.context_facts_written = 31; st.context_refs_written = 62;
  st.wal_bytes = 4096; st.shm_bytes = 32768; st.maintenance_state = 2;
  st.maintenance_pending = 1; st.db_capacity_evicted = 11;
  snprintf(st.path, sizeof(st.path), "PRIVATE_PATH");
  const char *accounting = "{\"scope\":\"current_process\",\"local_retention\":{\"recent_hours\":72,\"selected_hours\":72},\"private_fact\":\"PRIVATE_FACT\"}";
  char cache[EDR_EVIDENCE_HEALTH_JSON_BYTES], exact[EDR_EVIDENCE_HEALTH_JSON_BYTES];
  assert(edr_evidence_cache_health_json(&st, accounting, "{\"PRIVATE_OWNER\":1}", cache, sizeof(cache)) == 0);
  assert(!strstr(cache, "PRIVATE_PATH"));
  size_t needed = strlen(cache) + 1u;
  assert(edr_evidence_cache_health_json(&st, accounting, "{\"PRIVATE_OWNER\":1}", exact, needed) == 0);
  assert(strcmp(cache, exact) == 0);
  assert(edr_evidence_cache_health_json(&st, accounting, "{\"PRIVATE_OWNER\":1}", exact, needed - 1u) != 0);
  assert(exact[0] == '\0');
  assert(edr_evidence_cache_health_json(NULL, accounting, "{}", exact, sizeof(exact)) != 0 && exact[0] == '\0');
  for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
    char body[EDR_EVIDENCE_HEALTH_JSON_BYTES + 1024u], reason[128];
    int n = snprintf(body, sizeof(body), "{\"endpoint_id\":\"ep\",\"agent_version\":\"test\",\"policy_version\":\"p\","
        "\"engine_health\":{\"monitor\":{\"profile\":\"%s\"},\"p0_acceptance\":{\"evidence_cache\":%s}}}",
        diagnostic ? "diagnostic" : "basic", cache);
    assert(n > 0 && (size_t)n < sizeof(body));
    char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
    assert(!strstr(wire, "PRIVATE_") && !strstr(wire, "private_fact"));
    cJSON *root = cJSON_Parse(wire); assert(root);
    cJSON *value = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(root, "engine_health"), "p0_acceptance"), "evidence_cache");
    assert(cJSON_GetObjectItemCaseSensitive(value, "accounting_generation")->valuedouble == 7);
    assert(cJSON_GetObjectItemCaseSensitive(value, "candidate_requests")->valuedouble == 100);
    assert(cJSON_GetObjectItemCaseSensitive(value, "candidate_rejected")->valuedouble == 30);
    assert(cJSON_GetObjectItemCaseSensitive(value, "context_facts_written")->valuedouble == 31);
    assert(cJSON_GetObjectItemCaseSensitive(value, "context_refs_written")->valuedouble == 62);
    assert(!strcmp(cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(value,
        "accounting"), "scope")->valuestring, "current_process"));
    assert(cJSON_GetObjectItemCaseSensitive(value, "wal_bytes")->valuedouble == 4096);
    cJSON *maintenance = cJSON_GetObjectItemCaseSensitive(value, "maintenance");
    assert(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(maintenance, "pending")));
    assert(cJSON_GetObjectItemCaseSensitive(maintenance, "capacity_evicted")->valuedouble == 11);
    check_health_routes(root, 1);
    cJSON_Delete(root); free(wire);
  }
}

static void test_complete_cache_accounting_projection(void) {
  /* Exercise the exact safe-integer boundary before cJSON's decimal printer
   * can round it while building the full/delta fixtures below. */
  const char *unsafe = "{\"endpoint_id\":\"ep\",\"agent_version\":\"test\",\"policy_version\":\"p\","
      "\"engine_health\":{\"p0_acceptance\":{\"evidence_cache\":{\"context_facts_written\":9007199254740992}}}}";
  assert(check("POST", "ingest/engine-health", unsafe) != 0);
  char reason[128];
  char *safe = edr_egress_health_project(unsafe, reason, sizeof(reason));
  assert(!safe || !strstr(safe, "context_facts_written")); free(safe);
  const char *owners[] = {"candidate", "context"};
  const char *causes[] = {"no_database", "capacity_refused", "write_budget_refused",
      "resource_failed", "invalid", "storage_failed", "unclassified_failure"};
  const char *invalid[] = {"-1", "1.5", "100000000000000000", "true", "null", "{}", "[]", "\"PRIVATE_ERROR\""};
  for (unsigned profile = 0; profile < 2; ++profile) {
    cJSON *root = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"test\",\"policy_version\":\"p\","
        "\"engine_health\":{\"monitor\":{},\"p0_acceptance\":{\"evidence_cache\":{\"accounting\":{}}}}}");
    assert(root);
    cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
    cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health, "monitor"), "profile", profile ? "diagnostic" : "basic");
    cJSON *cache = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health, "p0_acceptance"), "evidence_cache");
    cJSON *accounting = cJSON_GetObjectItemCaseSensitive(cache, "accounting");
    /* Older producers remain valid and projection must not invent zeros. */
    char *body = cJSON_PrintUnformatted(root), reason[128]; assert(body);
    char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
    assert(!strstr(wire, "context_facts_written") && !strstr(wire, "scope"));
    free(body); free(wire);
    cJSON_AddStringToObject(accounting, "scope", "current_process");
    cJSON *parents[16]; const char *keys[16]; char names[14][64]; unsigned count = 0;
    parents[count] = cache; keys[count++] = "context_facts_written";
    parents[count] = cache; keys[count++] = "context_refs_written";
    for (unsigned owner = 0; owner < 2; ++owner) {
      char tree[32]; snprintf(tree, sizeof(tree), "%s_failures", owners[owner]);
      cJSON *failures = cJSON_AddObjectToObject(accounting, tree); assert(failures);
      for (unsigned cause = 0; cause < 7; ++cause) {
        snprintf(names[count - 2], sizeof(names[0]), "%s_%s", owners[owner], causes[cause]);
        parents[count] = failures; keys[count] = names[count - 2]; ++count;
      }
    }
    for (unsigned i = 0; i < count; ++i) assert(cJSON_AddNumberToObject(parents[i], keys[i], i % 2 ? 5 : 0));
    check_health_routes(root, 1);
    body = cJSON_PrintUnformatted(root); wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
    cJSON *projected = cJSON_Parse(wire); assert(projected && cJSON_Compare(root, projected, 1));
    free(body); free(wire); cJSON_Delete(projected);
    for (unsigned i = 0; i < count; ++i) {
      for (unsigned j = 0; j < sizeof(invalid)/sizeof(invalid[0]); ++j) {
        assert(cJSON_ReplaceItemInObjectCaseSensitive(parents[i], keys[i], cJSON_Parse(invalid[j])));
        check_health_routes(root, 0);
        body = cJSON_PrintUnformatted(root); wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
        assert(!strstr(wire, keys[i]) && !strstr(wire, "PRIVATE_ERROR"));
        projected = cJSON_Parse(wire); assert(projected); check_health_routes(projected, 1);
        free(body); free(wire); cJSON_Delete(projected);
      }
      assert(cJSON_ReplaceItemInObjectCaseSensitive(parents[i], keys[i], cJSON_CreateNumber(i % 2 ? 5 : 0)));
    }
    const char *bad_scope[] = {"\"PRIVATE_SCOPE\"", "\"\"", "0", "null", "true"};
    for (unsigned j = 0; j < sizeof(bad_scope)/sizeof(bad_scope[0]); ++j) {
      assert(cJSON_ReplaceItemInObjectCaseSensitive(accounting, "scope", cJSON_Parse(bad_scope[j])));
      check_health_routes(root, 0);
      body = cJSON_PrintUnformatted(root); wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
      assert(!strstr(wire, "scope")); free(body); free(wire);
    }
    cJSON_Delete(root);
  }
}

static void test_capacity_instance_health_projection(void) {
  const char *profiles[] = {"basic", "diagnostic"};
  for (unsigned i = 0; i < 2; ++i) {
    cJSON *root = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"test\",\"policy_version\":\"p\","
        "\"engine_health\":{\"monitor\":{},\"resource\":{\"process_id\":42,\"process_start_unix_ms\":1793000000000},"
        "\"p0_acceptance\":{\"evidence_cache\":{\"accounting_generation\":2,\"wal_bytes\":4096,\"shm_bytes\":32768,"
        "\"candidate_reused\":3,\"maintenance\":{\"state\":2,\"pending\":true,\"retention_evicted\":7,\"capacity_evicted\":11}}}}}");
    assert(root);
    cJSON *health = cJSON_GetObjectItemCaseSensitive(root, "engine_health");
    assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health, "monitor"), "profile", profiles[i]));
    check_health_routes(root, 1);
    cJSON *raw = cJSON_Duplicate(root, 1);
    cJSON *cache = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(raw, "engine_health"), "p0_acceptance"), "evidence_cache");
    assert(cJSON_AddStringToObject(cache, "path", "PRIVATE_PATH"));
    assert(cJSON_AddStringToObject(cache, "payload", "PRIVATE_EVIDENCE"));
    check_health_routes(raw, 0);
    char *body = cJSON_PrintUnformatted(raw), reason[128]; assert(body);
    char *wire = edr_egress_health_project(body, reason, sizeof(reason)); assert(wire);
    cJSON *projected = cJSON_Parse(wire);
    assert(projected && cJSON_Compare(root, projected, 1));
    assert(!strstr(wire, "PRIVATE_"));
    cJSON_Delete(projected); free(wire); free(body); cJSON_Delete(raw);
    cJSON *resource = cJSON_GetObjectItemCaseSensitive(health, "resource");
    const char *invalid[] = {"-1", "1.5", "\"PRIVATE_BIRTH\"", "null", "true"};
    for (unsigned j = 0; j < sizeof(invalid)/sizeof(invalid[0]); ++j) {
      assert(cJSON_ReplaceItemInObjectCaseSensitive(resource, "process_start_unix_ms", cJSON_Parse(invalid[j])));
      check_health_routes(root, 0);
    }
    cJSON_Delete(root);
  }
}

static void test_capacity_failure_health_is_numeric_and_bounded(void) {
  const char *causes[] = {"unknown", "db_wal_limit", "wal_busy", "wal_error",
      "physical_guard", "maintenance_deferred", "maintenance_failed", "postwrite_page_limit"};
  const char *profiles[] = {"basic", "diagnostic"};
  const char *invalid[] = {"\"PRIVATE_COMMAND\"", "-1", "1.5", "true", "null", "{}", "[]"};
  for (unsigned profile = 0; profile < 2u; ++profile) {
    cJSON *expected = cJSON_Parse("{\"endpoint_id\":\"ep\",\"agent_version\":\"test\",\"policy_version\":\"p\","
        "\"engine_health\":{\"monitor\":{},\"p0_acceptance\":{\"evidence_cache\":{\"accounting\":{"
        "\"candidate_failures\":{\"candidate_capacity_refused\":8},\"context_failures\":{\"context_capacity_refused\":8},"
        "\"capacity_failures\":{\"candidate\":{},\"context\":{},\"last_cause\":2,\"last_sqlite_rc\":5,\"last_owner\":2}}}}}}");
    assert(expected);
    cJSON *health = cJSON_GetObjectItemCaseSensitive(expected,"engine_health");
    assert(cJSON_AddStringToObject(cJSON_GetObjectItemCaseSensitive(health,"monitor"),"profile",profiles[profile]));
    cJSON *details = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(health,"p0_acceptance"),"evidence_cache"),
        "accounting"),"capacity_failures");
    for (unsigned owner=0;owner<2u;++owner) {
      cJSON *counts=cJSON_GetObjectItemCaseSensitive(details,owner ? "context" : "candidate");
      for (unsigned cause=0;cause<8u;++cause) assert(cJSON_AddNumberToObject(counts,causes[cause],1));
    }
    check_health_routes(expected,1);
    assert(cJSON_AddStringToObject(details,"last_error","PRIVATE_PATH_AND_COMMAND"));
    assert(cJSON_AddObjectToObject(details,"raw_event"));
    check_health_routes(expected,0);
    char *body=cJSON_PrintUnformatted(expected), reason[128]; assert(body);
    char *wire=edr_egress_health_project(body,reason,sizeof(reason)); assert(wire);
    assert(!strstr(wire,"PRIVATE_") && !strstr(wire,"last_error") && !strstr(wire,"raw_event"));
    cJSON_DeleteItemFromObjectCaseSensitive(details,"last_error");
    cJSON_DeleteItemFromObjectCaseSensitive(details,"raw_event");
    cJSON *projected=cJSON_Parse(wire); assert(projected && cJSON_Compare(expected,projected,1));
    check_health_routes(projected,1); cJSON_Delete(projected); free(body); free(wire);
    for (unsigned value=0;value<sizeof(invalid)/sizeof(invalid[0]);++value) {
      cJSON *counts=cJSON_GetObjectItemCaseSensitive(details,"context");
      assert(cJSON_ReplaceItemInObjectCaseSensitive(counts,"wal_busy",cJSON_Parse(invalid[value])));
      check_health_routes(expected,0);
      body=cJSON_PrintUnformatted(expected); assert(body);
      wire=edr_egress_health_project(body,reason,sizeof(reason)); assert(wire);
      projected=cJSON_Parse(wire); assert(projected); check_health_routes(projected,1);
      assert(!strstr(wire,"PRIVATE_"));
      cJSON_Delete(projected); free(body); free(wire);
    }
    cJSON_Delete(expected);
  }
}

static void test_storage_health_is_numeric_and_bounded(void) {
  const char *raw="{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"storage_protection\":{\"directory_hard_limit\":false,\"min_free_bytes\":143479824,\"queue_available_bytes\":200000000,\"command_owner\":{\"accounting_available\":true,\"reserved_bytes\":197190,\"admission_rejected\":2,\"raw_command\":\"PRIVATE_COMMAND\"}},\"queue_local_retention\":{\"retirement_enabled\":true,\"local_retention_policy_version\":2,\"retired_rows\":100,\"unclassified_rows\":4,\"payload\":\"PRIVATE_FACT\"}}}";
  char why[128];
  assert(check("POST","ingest/engine-health",raw)!=0);
  char *projected=edr_egress_health_project(raw,why,sizeof(why)); assert(projected);
  assert(strstr(projected,"reserved_bytes") && strstr(projected,"retired_rows"));
  assert(!strstr(projected,"PRIVATE_") && !strstr(projected,"raw_command"));
  assert(check("POST","ingest/engine-health",projected)==0);
  cJSON *o=cJSON_Parse(projected); assert(o);
  cJSON *q=cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(o,"engine_health"),"queue_local_retention");
  cJSON_AddNumberToObject(q,"maintenance_oversize_holds",1);
  cJSON_AddNumberToObject(q,"terminal_local_retired_rows",3);
  cJSON_AddNumberToObject(q,"terminal_local_retired_bytes",4000);
  cJSON_AddNumberToObject(q,"physical_admission_failures",2);
  cJSON_AddNumberToObject(q,"physical_failure_kind",1);
  char *metrics=cJSON_PrintUnformatted(o); assert(metrics);
  assert(check("POST","ingest/engine-health",metrics)==0);
  free(metrics);
  assert(cJSON_ReplaceItemInObjectCaseSensitive(q,"retired_rows",cJSON_CreateString("PRIVATE_FACT")));
  char *bad=cJSON_PrintUnformatted(o); assert(bad);
  assert(check("POST","ingest/engine-health",bad)!=0);
  free(bad); cJSON_Delete(o); free(projected);
}

int main(void) {
  test_complete_cache_accounting_projection();
  test_capacity_health_producer_and_projection();
  test_capacity_instance_health_projection();
  test_evidence_pressure_health_projection();
  test_storage_health_is_numeric_and_bounded();
  test_capacity_failure_health_is_numeric_and_bounded();
  test_retention_floor_health_is_numeric_and_bounded();
  test_parent_exit_health_projection();
  test_diagnostic_health_commitments();
  test_upgrade_health_consumers();
  test_parent_context_capability_health_projection();
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
