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

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  char agent_path[1024];
  char ingest_path[1024];
  char *agent;
  char *ingest;
  if (!root || !root[0]) root = ".";
  snprintf(agent_path, sizeof(agent_path), "%s/src/core/agent.c", root);
  snprintf(ingest_path, sizeof(ingest_path), "%s/src/transport/ingest_http.c", root);
  agent = read_file(agent_path);
  ingest = read_file(ingest_path);
  if (!agent || !ingest) {
    fprintf(stderr, "failed to read remote config sources\n");
    free(agent);
    free(ingest);
    return 1;
  }
  if (!contains(agent, "edr_agent_report_remote_config_failure(agent, NULL, \"remote_config_download_failed\", now)") ||
      !contains(agent, "edr_agent_report_remote_config_failure(agent, &config_headers, parse_reason, now)") ||
      !contains(agent, "edr_agent_clear_remote_config_failure();") ||
      !contains(agent, "15ULL * 60ULL * 1000000000ULL") ||
      !contains(ingest, "desired_version && desired_version[0] ? desired_version : \"\"")) {
    fprintf(stderr, "remote config status/retry contract missing\n");
    free(agent);
    free(ingest);
    return 1;
  }
  free(agent);
  free(ingest);
  return 0;
}
