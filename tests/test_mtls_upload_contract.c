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
      contains(source, "force_mtls_http1 = !http2_required() && curl_schannel_store_mtls_needs_libcurl_http1(url)") &&
      contains(source, "force_mtls_http1 ? (long)CURL_HTTP_VERSION_1_1 : 0L") &&
      contains(source, "curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L)") &&
      contains(source, "curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L)") &&
      contains(source, "if (!force_mtls_http1)") &&
      contains(source, "Schannel store-backed mTLS upload failed");
  free(source);
  if (!ok) {
    fprintf(stderr, "store-backed mTLS upload isolation contract missing\n");
    return 1;
  }
  return 0;
}
