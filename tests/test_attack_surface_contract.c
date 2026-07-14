#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  char *buf = (char *)calloc((size_t)n + 1u, 1u);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1u, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  return buf;
}

static int contains(const char *haystack, const char *needle) {
  return haystack && needle && strstr(haystack, needle) != NULL;
}

static char *slice_between(const char *src, const char *begin, const char *end) {
  const char *b = strstr(src, begin);
  if (!b) return NULL;
  const char *e = strstr(b, end);
  if (!e || e <= b) return NULL;
  size_t n = (size_t)(e - b);
  char *out = (char *)calloc(n + 1u, 1u);
  if (!out) return NULL;
  memcpy(out, b, n);
  return out;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";

  char command_path[1024];
  char registry_path[1024];
  char report_path[1024];
  char agent_path[1024];
  snprintf(command_path, sizeof(command_path), "%s/src/command/command_stub.c", root);
  snprintf(registry_path, sizeof(registry_path), "%s/src/command/command_registry.c", root);
  snprintf(report_path, sizeof(report_path), "%s/src/attack_surface/attack_surface_report.c", root);
  snprintf(agent_path, sizeof(agent_path), "%s/src/core/agent.c", root);

  char *command = read_file(command_path);
  char *registry = read_file(registry_path);
  char *report = read_file(report_path);
  char *agent = read_file(agent_path);
  if (!command || !registry || !report || !agent) {
    fprintf(stderr, "failed to read command/registry/report/agent sources\n");
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }

  char *branch = slice_between(
      command,
      "case EDR_COMMAND_KIND_ATTACK_SURFACE:",
      "case EDR_COMMAND_KIND_UNKNOWN:");
  if (!branch) {
    fprintf(stderr, "attack surface command branch not found\n");
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (!contains(registry, "COMMAND(\"GET_ATTACK_SURFACE\"") ||
      !contains(registry, "COMMAND(\"get_attack_surface\"") ||
      !contains(registry, "COMMAND(\"REFRESH_ATTACK_SURFACE\"")) {
    fprintf(stderr, "attack surface aliases missing from command registry\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }

  if (!contains(branch, "edr_attack_surface_execute(id, payload, payload_len,") ||
      !contains(branch, "edr_command_get_config(), detail, sizeof(detail)")) {
    fprintf(stderr, "manual attack surface command must pass its trigger payload to the collector\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (contains(branch, "attack_surface.enabled")) {
    fprintf(stderr, "manual REFRESH_ATTACK_SURFACE must not be gated by attack_surface.enabled\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (contains(branch, "edr_attack_surface_refresh_pending")) {
    fprintf(stderr, "manual REFRESH_ATTACK_SURFACE must not depend on legacy refresh-request polling\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }

  if (!contains(report, "edr_ingest_http_post_json_suffix(suffix, body, NULL, 0u)")) {
    fprintf(stderr, "attack surface upload must use internal ingest HTTP helper\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (!contains(report, "WEXITSTATUS(child_status) != 0") ||
      !contains(report, "listener_collection_failed")) {
    fprintf(stderr, "listener collector failures must not become fresh empty snapshots\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (!contains(report, "cJSON_GetObjectItemCaseSensitive(root, \"reason\")") ||
      !contains(report, "strcmp(reason->valuestring, \"etw_tcpip_wf\") == 0") ||
      !contains(report, "coalesced_inflight") ||
      !contains(report, "listeners_ms=%llu") ||
      !contains(report, "snapshot_ms=%llu") ||
      !contains(report, "upload_ms=%llu")) {
    fprintf(stderr, "attack surface triggers must support ETW light mode, coalescing and phase timings\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (contains(report, "execlp(\"curl\"") || contains(report, "system(\"curl") || contains(report, "popen(\"curl")) {
    fprintf(stderr, "attack surface upload must not shell out to external curl\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (!contains(report, "int have_policy = pthread_create") ||
      !contains(report, "if (have_policy)") ||
      !contains(report, "pthread_join(tpol, NULL)") ||
      !contains(report, "WaitForSingleObject(tp, INFINITE)")) {
    fprintf(stderr, "partial attack-surface thread creation must join every started worker\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }
  if (contains(agent, "edr_attack_surface_execute(") ||
      !contains(agent, "edr_agent_queue_attack_surface(\"agent_start\"") ||
      !contains(agent, "edr_agent_queue_attack_surface(\"config_reload\"") ||
      !contains(agent, "edr_agent_queue_attack_surface(\"remote_config_reload\"")) {
    fprintf(stderr, "agent main/config loops must queue attack-surface collection\n");
    free(branch);
    free(command);
    free(registry);
    free(report);
    free(agent);
    return 1;
  }

  free(branch);
  free(command);
  free(registry);
  free(report);
  free(agent);
  return 0;
}
