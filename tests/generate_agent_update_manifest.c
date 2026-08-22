#include "edr/agent_update_command.h"
#include "edr/agent_update_manifest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int edr_ingest_http_post_json_suffix(const char *suffix, const char *body_json,
                                     char *resp_body, size_t resp_body_cap) {
  (void)suffix; (void)body_json; (void)resp_body; (void)resp_body_cap;
  return -1;
}

static int read_file(const char *path, char **out, size_t *len) {
  FILE *f = fopen(path, "rb");
  long n;
  if (!f || fseek(f, 0, SEEK_END) != 0) { if (f) fclose(f); return 0; }
  n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
  *out = (char *)malloc((size_t)n + 1u);
  if (!*out || fread(*out, 1u, (size_t)n, f) != (size_t)n) { free(*out); *out = NULL; fclose(f); return 0; }
  (*out)[n] = '\0'; *len = (size_t)n; fclose(f); return 1;
}

static int write_file(const char *path, const char *data, size_t len) {
  FILE *f = fopen(path, "wb");
  int ok = f && fwrite(data, 1u, len, f) == len;
  if (f) fclose(f);
  return ok;
}

static int build_manifest(char *out, size_t cap) {
  EdrAgentUpdateRuntimeInfo info;
  char script[4096], fragment[4096];
  size_t n;
  memset(&info, 0, sizeof(info));
  if (!edr_agent_update_get_runtime_info(&info, script, sizeof(script))) {
    /* The producer still fills the unsupported/non-Windows capability state. */
  }
  if (edr_agent_update_manifest_fragment(&info, fragment, sizeof(fragment)) != 0) return 0;
  n = strlen(fragment);
  if (n == 0u || fragment[n - 1u] != ',') return 0;
  fragment[n - 1u] = '\0';
  return snprintf(out, cap, "{\"schema\":\"edr.agent.capabilities.v1\",\"capability_manifest\":{\"commands\":{%s}}}\n", fragment) > 0 &&
         strlen(out) < cap;
}

int main(int argc, char **argv) {
  char generated[8192];
  if (!build_manifest(generated, sizeof(generated))) return 2;
  if (argc == 3 && strcmp(argv[1], "--write") == 0) return write_file(argv[2], generated, strlen(generated)) ? 0 : 3;
  if (argc == 3 && strcmp(argv[1], "--check") == 0) {
    char *expected = NULL; size_t len = 0;
    int ok = read_file(argv[2], &expected, &len) && len == strlen(generated) && memcmp(expected, generated, len) == 0;
    free(expected);
    return ok ? 0 : 4;
  }
  if (argc != 1) return 5;
  fputs(generated, stdout);
  return 0;
}
