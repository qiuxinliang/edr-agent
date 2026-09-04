#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  long size;
  char *content;
  if (!f || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
    if (f) fclose(f);
    return NULL;
  }
  rewind(f);
  content = (char *)calloc((size_t)size + 1u, 1u);
  if (!content || fread(content, 1u, (size_t)size, f) != (size_t)size) {
    free(content);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return content;
}

static int contains(const char *source, const char *needle) {
  return source && needle && strstr(source, needle) != NULL;
}

static int ordered_before(const char *source, const char *first, const char *second) {
  const char *a = source ? strstr(source, first) : NULL;
  const char *b = source ? strstr(source, second) : NULL;
  return a && b && a < b;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  char agent_path[1024];
  char ingest_path[1024];
  char transport_path[1024];
  char *agent;
  char *ingest;
  char *transport;
  if (!root || !root[0]) root = ".";
  snprintf(agent_path, sizeof(agent_path), "%s/src/core/agent.c", root);
  snprintf(ingest_path, sizeof(ingest_path), "%s/src/transport/ingest_http.c", root);
  snprintf(transport_path, sizeof(transport_path), "%s/src/transport/transport_stub.c", root);
  agent = read_file(agent_path);
  ingest = read_file(ingest_path);
  transport = read_file(transport_path);
  if (!agent || !ingest || !transport) {
    fprintf(stderr, "failed to read remote config sources\n");
    free(agent);
    free(ingest);
    free(transport);
    return 1;
  }
  if (!contains(agent, "edr_agent_report_remote_config_failure(agent, NULL, \"remote_config_download_failed\", now)") ||
      !contains(agent, "edr_agent_report_remote_config_failure(agent, &config_headers, parse_reason, now)") ||
      !contains(agent, "edr_agent_clear_remote_config_failure();") ||
      !contains(agent, "strcmp(agent->applied_remote_config_hash, config_headers.config_hash) == 0") ||
      !contains(agent, "The authenticated content hash is the policy identity") ||
      !contains(agent, "edr_agent_write_config_sequence_state(agent->cfg.offline.queue_db_path, sequence)") ||
      !contains(agent, "edr_agent_poll_rules(agent, &last_rules_ns)") ||
      !contains(agent, "\"%s/agent/rules.toml\"") ||
      !contains(agent, "edr_config_load_preprocessing_rules(tmp, &agent->cfg)") ||
      !contains(agent, "edr_agent_signed_config_identity_matches_headers") ||
      !contains(agent, "edr_agent_parse_config_sequence") ||
      contains(agent, "atoll(config_headers.sequence)") ||
      contains(agent, "atoll(headers->sequence)") ||
      !contains(agent, "signed payload identity mismatch") ||
      !contains(agent, "config_headers.policy_version") ||
      !contains(agent, "edr_ingest_http_set_policy_version(config_headers.policy_version)") ||
      contains(agent, "\"rules_applied\"") ||
      contains(agent, "\"rules_failed\"") ||
      !contains(agent, "15ULL * 60ULL * 1000000000ULL") ||
      !contains(ingest, "X-Rules-Version\", out->policy_version") ||
      !contains(ingest, "static char s_policy_version[128]") ||
      !contains(transport, "edr_ingest_http_set_policy_version(NULL)") ||
      contains(transport, "edr_ingest_http_set_policy_version(cfg->preprocessing.rules_version)") ||
      !contains(ingest, "desired_version && desired_version[0] ? desired_version : \"\"") ||
      !ordered_before(agent, "edr_agent_verify_config_headers(&agent->cfg",
                      "if (config_headers.config_hash[0] &&") ||
      !ordered_before(agent, "if (config_headers.config_hash[0] &&",
                      "EdrError ce = edr_config_load(tmp, &remote);") ||
      !ordered_before(agent, "(void)remove(tmp);\n    return;\n  }\n\n  EdrConfig remote;",
                      "edr_config_load(tmp, &remote)") ||
      !ordered_before(agent, "EdrError ce = edr_config_load(tmp, &remote);",
                      "edr_agent_apply_remote_policy(agent, &remote, tmp)")) {
    fprintf(stderr, "remote config status/retry contract missing\n");
    free(agent);
    free(ingest);
    free(transport);
    return 1;
  }
  free(agent);
  free(ingest);
  free(transport);
  return 0;
}
