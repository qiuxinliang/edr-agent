#include "edr/egress_request_policy.h"
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
int main(void) {
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
  const char *input = "{\"endpoint_id\":\"ep\",\"agent_version\":\"v1\",\"policy_version\":\"p1\",\"engine_health\":{\"reported_at_unix_ms\":1700000000000,\"config_recovery\":{\"active\":true,\"source\":\"synthetic-secret-path\",\"reason\":\"synthetic-secret-error\"},\"sensor_health\":{\"event_filter\":{\"last_drop\":{\"cmdline\":\"synthetic-secret-command\"}},\"file_read_collection\":{\"metadata_gate\":{\"healthy\":false,\"durable_failures\":2,\"reason\":\"synthetic-secret-user\"}}},\"p0_acceptance\":{\"source_only\":{\"terminal_unhealthy\":true,\"retry_pending\":3,\"reason\":\"process_generation_or_correlation_unavailable\"}},\"p0_offline_queue_capacity\":{\"local_evidence_rows\":4,\"policy_held_rows\":1},\"egress\":{\"policy_version\":\"minimal-egress-v1\",\"denied_requests\":3},\"capability_manifest\":{\"schema\":\"edr.agent.capabilities.v1\",\"features\":{\"pmfe\":{\"code_supported\":true,\"runtime_status\":\"healthy\",\"detail\":\"synthetic-secret-detail\"}}},\"raw_event\":{\"username\":\"synthetic-secret-user\"}}}";
  char reason[128];
  assert(check("POST", "ingest/engine-health", input) != 0);
  char *minimal = edr_egress_health_project(input, reason, sizeof(reason));
  size_t minimal_bytes = minimal ? strlen(minimal) : 0u;
  assert(minimal && !strstr(minimal, "synthetic-secret") && !strstr(minimal, "raw_event") && !strstr(minimal, "last_drop"));
  assert(strstr(minimal, "durable_failures") && strstr(minimal, "terminal_unhealthy") && strstr(minimal, "retry_pending"));
  assert(strstr(minimal, "local_evidence_rows") && strstr(minimal, "policy_held_rows") && strstr(minimal, "capability_manifest"));
  assert(strstr(minimal, "process_generation_or_correlation_unavailable"));
  assert(strstr(minimal, "detail_available_locally"));
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
