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
  char report_path[1024];
  snprintf(command_path, sizeof(command_path), "%s/src/command/command_stub.c", root);
  snprintf(report_path, sizeof(report_path), "%s/src/attack_surface/attack_surface_report.c", root);

  char *command = read_file(command_path);
  char *report = read_file(report_path);
  if (!command || !report) {
    fprintf(stderr, "failed to read command/report sources\n");
    free(command);
    free(report);
    return 1;
  }

  char *branch = slice_between(
      command,
      "if (streq(t, \"GET_ATTACK_SURFACE\") || streq(t, \"get_attack_surface\") || streq(t, \"REFRESH_ATTACK_SURFACE\"))",
      "fprintf(stderr, \"[command] unknown type");
  if (!branch) {
    fprintf(stderr, "attack surface command branch not found\n");
    free(command);
    free(report);
    return 1;
  }

  if (!contains(branch, "edr_attack_surface_execute(id, edr_command_get_config(), detail, sizeof(detail))")) {
    fprintf(stderr, "manual attack surface command no longer calls edr_attack_surface_execute directly\n");
    free(branch);
    free(command);
    free(report);
    return 1;
  }
  if (contains(branch, "attack_surface.enabled")) {
    fprintf(stderr, "manual REFRESH_ATTACK_SURFACE must not be gated by attack_surface.enabled\n");
    free(branch);
    free(command);
    free(report);
    return 1;
  }
  if (contains(branch, "edr_attack_surface_refresh_pending")) {
    fprintf(stderr, "manual REFRESH_ATTACK_SURFACE must not depend on legacy refresh-request polling\n");
    free(branch);
    free(command);
    free(report);
    return 1;
  }

  if (!contains(report, "edr_ingest_http_post_json_suffix(suffix, body, NULL, 0u)")) {
    fprintf(stderr, "attack surface upload must use internal ingest HTTP helper\n");
    free(branch);
    free(command);
    free(report);
    return 1;
  }
  if (contains(report, "execlp(\"curl\"") || contains(report, "system(\"curl") || contains(report, "popen(\"curl")) {
    fprintf(stderr, "attack surface upload must not shell out to external curl\n");
    free(branch);
    free(command);
    free(report);
    return 1;
  }

  free(branch);
  free(command);
  free(report);
  return 0;
}
