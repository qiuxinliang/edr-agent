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

static unsigned count_occurrences(const char *haystack, const char *needle) {
  unsigned count = 0;
  size_t needle_len = needle ? strlen(needle) : 0u;
  if (!haystack || needle_len == 0u) {
    return 0u;
  }
  for (const char *p = haystack; (p = strstr(p, needle)) != NULL; p += needle_len) {
    count++;
  }
  return count;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  if (!root || !root[0]) root = ".";

  char path[1024];
  snprintf(path, sizeof(path), "%s/src/transport/ingest_http.c", root);
  char *source = read_file(path);
  if (!source) {
    fprintf(stderr, "failed to read ingest HTTP source\n");
    return 1;
  }

  int ok =
      contains(source, "static int64_t control_stream_lease_ms(void)") &&
      contains(source, "static int control_stream_ready_lease_valid(void)") &&
      contains(source, "s_control_stream_status, sizeof(s_control_stream_status), \"%s\", \"lease_expired\"") &&
      contains(source, "if (control_stream_ready_lease_valid() || s_ws_ready)") &&
      contains(source, "control_stream_ready_lease_valid() ? \"https_control_stream\" : \"https_long_poll\"") &&
      contains(source, "out->control_stream_lease_valid = stream_lease_valid") &&
      contains(source, "out->control_stream_lease_expired_count = s_control_stream_lease_expired") &&
      count_occurrences(source, "note_control_stream_activity();") >= 3u;
  free(source);
  if (!ok) {
    fprintf(stderr, "control stream lease/fallback contract missing\n");
    return 1;
  }
  return 0;
}
