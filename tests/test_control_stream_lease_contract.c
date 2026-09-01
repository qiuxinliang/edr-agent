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

  snprintf(path, sizeof(path), "%s/CMakeLists.txt", root);
  char *cmake = read_file(path);
  snprintf(path, sizeof(path), "%s/resources/FDSensor.manifest", root);
  char *manifest = read_file(path);

  int ok =
      contains(source, "static int64_t control_stream_lease_ms(void)") &&
      contains(source, "static int control_stream_ready_lease_valid(void)") &&
      contains(source, "s_control_stream_status, sizeof(s_control_stream_status), \"%s\", \"lease_expired\"") &&
      contains(source, "if (control_stream_ready_lease_valid())") &&
      !contains(source, "runtime_int_get(&s_ws_ready)") &&
      contains(source, "out->websocket_ready = stream_lease_valid ? 1 : 0") &&
      contains(source, "control_stream_ready_lease_valid() ? \"https_control_stream\" : \"https_long_poll\"") &&
      contains(source, "out->control_stream_lease_valid = stream_lease_valid") &&
      contains(source, "out->control_stream_lease_expired_count = s_control_stream_lease_expired") &&
      contains(source, "CURLOPT_XFERINFOFUNCTION, curl_transfer_progress") &&
      contains(source, "curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &version)") &&
      !contains(source, "#ifdef CURLINFO_HTTP_VERSION") &&
      !contains(source, "#ifdef CURL_HTTP_VERSION_2_0") &&
      contains(source, "(!job->stream_ctx || !job->stream_ctx->failed) && job->h2") &&
      contains(source, "code >= 200 && code < 300 && h2") &&
      contains(source, "code < 300 && !ctx.failed && h2") &&
      !contains(source, "(h2 || !control_http2_required())") &&
      contains(source, "static size_t curl_stream_header_cb") &&
      contains(source, "ctx.require_h2 = 1") &&
      contains(source, "CURLOPT_HEADERFUNCTION, curl_stream_header_cb") &&
      contains(source, "CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS") &&
      !contains(source, "CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE") &&
      contains(cmake, "resources/FDSensor.rc") &&
      contains(cmake, "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/resources/FDSensor.manifest") &&
      contains(manifest, "{4f476546-937d-4f00-9c1b-e235127d47f6}") &&
      contains(manifest, "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}") &&
      contains(source, "json_get_string(line, \"protocol\", protocol") &&
      contains(source, "note_negotiated_protocol_name(protocol, 1)") &&
      contains(source, "server_drain") &&
      contains(source, "control_http2_client_enabled()") &&
      contains(source, "control_http1_fallback_enabled()") &&
      contains(source, "void edr_ingest_http_cancel_inflight(void)") &&
      contains(source, "edr_ingest_http_cancel_inflight();") &&
      count_occurrences(source, "note_control_stream_activity();") >= 3u;
  free(source);
  free(cmake);
  free(manifest);
  if (!ok) {
    fprintf(stderr, "control stream lease/fallback contract missing\n");
    return 1;
  }
  return 0;
}
