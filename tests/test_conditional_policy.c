/* Embed the production config owner to exercise its authenticated cache path;
 * other runtime owners are linked unchanged. No collector/service is started. */
#include "../src/core/agent.c"
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 7);
  edr_ingest_http_configure(argv[1], "synthetic-tenant", "", "", "synthetic-endpoint", "test-v1",
      argv[2], argv[3], argv[4], "pem", "", "", "direct", "", "");
  EdrAgent *agent = edr_agent_create();
  assert(agent);
  agent->cfg.config_signing.signature_required = true;
  snprintf(agent->cfg.config_signing.signing_key_id, sizeof(agent->cfg.config_signing.signing_key_id), "synthetic-key");
  snprintf(agent->cfg.offline.queue_db_path, sizeof(agent->cfg.offline.queue_db_path), "%s", argv[5]);
  char url[1024], reason[192], actual_hash[65];
  snprintf(url, sizeof(url), "%s/agent/runtime-policy.toml", argv[1]);
  EdrAgentConfigHeaders headers;
  for (unsigned step = 0u; step < 10u; ++step) {
    const char *validator = agent->cached_remote_body ? agent->cached_remote_body_hash : NULL;
    int rc = edr_ingest_http_get_url_to_file_conditional(url, argv[6], 1024u * 1024u,
                                                       &headers, 5000, 1, validator);
    if (step == 0u || step == 2u || step == 7u) {
      assert(rc == 0);
      assert(edr_agent_verify_config_headers(&agent->cfg, argv[5], argv[6], &headers, reason, sizeof(reason)) == 0);
      edr_agent_cache_remote_body(agent, argv[6], headers.config_hash);
      assert(agent->cached_remote_body && agent->cached_remote_body_len);
      edr_agent_write_config_sequence_state(argv[5], 2);
    } else {
      assert(rc == 1);
      FILE *f = fopen(argv[6], "rb");
      assert(f && fgetc(f) == EOF); fclose(f);
      assert(edr_agent_restore_cached_remote_body(agent, argv[6]) == 0);
      int verified = edr_agent_verify_policy_response(&agent->cfg, argv[5], argv[6], &headers, 1, reason, sizeof(reason));
      assert((step == 1u || step == 6u) ? verified == 0 : verified != 0);
    }
  }
  /* Optional unsigned 200 compatibility must never authorize a headerless 304. */
  agent->cfg.config_signing.signature_required = false;
  EdrAgentConfigHeaders missing; memset(&missing, 0, sizeof(missing));
  assert(edr_agent_verify_policy_response(&agent->cfg, argv[5], argv[6], &missing, 0, reason, sizeof(reason)) == 0);
  assert(edr_agent_verify_policy_response(&agent->cfg, argv[5], argv[6], &missing, 1, reason, sizeof(reason)) != 0);
  agent->cfg.config_signing.signature_required = true;
  /* In-memory damage must fail the same byte hash check as a downloaded body. */
  agent->cached_remote_body[0] ^= 1;
  assert(edr_agent_restore_cached_remote_body(agent, argv[6]) == 0);
  assert(edr_agent_file_sha256_hex(argv[6], actual_hash) == 0);
  assert(strcmp(actual_hash, agent->cached_remote_body_hash) != 0);
  assert(edr_agent_verify_config_headers(&agent->cfg, argv[5], argv[6], &headers, reason, sizeof(reason)) != 0);
  assert(edr_ingest_http_get_url_to_file_conditional(url, argv[6], 1024u * 1024u,
                                                   &headers, 5000, 1, "bad\r\nheader") < 0);
  /* Production polling drops a bad optional-mode 304 validator, then accepts
   * a fresh signed 200. Repeat for expired metadata without relaxing old 200. */
  agent->cfg.config_signing.signature_required = false;
  snprintf(agent->cfg.platform.rest_base_url, sizeof(agent->cfg.platform.rest_base_url), "%s", argv[1]);
  snprintf(agent->applied_remote_config_hash, sizeof(agent->applied_remote_config_hash), "%s", agent->cached_remote_body_hash);
  snprintf(agent->applied_remote_config_sequence, sizeof(agent->applied_remote_config_sequence), "2");
  agent->applied_remote_config_status_reported = 1;
  uint64_t last_remote_ns = 0u, last_health_for_policy_ns = 0u;
  for (unsigned pull = 0; pull < 4u; ++pull) {
    agent->maintenance_schedule[0].interval_s = 60u;
    agent->maintenance_schedule[0].next_ns = 1u;
    edr_agent_poll_remote_config(agent, &last_remote_ns, &last_health_for_policy_ns);
    assert((pull % 2u) ? agent->cached_remote_body != NULL : agent->cached_remote_body == NULL);
  }
  /* Exercise actual basic/leased diagnostic JSON with an env cadence override. */
  snprintf(agent->cfg.agent.endpoint_id, sizeof(agent->cfg.agent.endpoint_id), "synthetic-endpoint");
  agent->cfg.health_monitor.interval_s = 60u;
  uint64_t last_health_ns = 0u;
  agent->cfg.health_monitor.enabled = false;
  edr_agent_poll_engine_health(agent, &last_health_ns, 1);
  assert(last_health_ns && agent->health_schedule.interval_s == 120u);
  agent->cfg.health_monitor.enabled = true;
  snprintf(agent->cfg.health_monitor.profile, sizeof(agent->cfg.health_monitor.profile), "diagnostic");
  edr_agent_poll_engine_health(agent, &last_health_ns, 1);
  assert(agent->health_schedule.interval_s == 120u);
  free(agent->cached_remote_body); free(agent);
  return 0;
}
