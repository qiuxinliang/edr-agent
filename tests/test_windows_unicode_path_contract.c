#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  long size;
  char *data;
  if (!file) return NULL;
  if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
      fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  data = (char *)calloc((size_t)size + 1u, 1u);
  if (!data || fread(data, 1u, (size_t)size, file) != (size_t)size) {
    free(data);
    fclose(file);
    return NULL;
  }
  fclose(file);
  return data;
}

static char *read_source(const char *root, const char *relative) {
  char path[1400];
  snprintf(path, sizeof(path), "%s/%s", root, relative);
  return read_file(path);
}

static int expect_contains(const char *text, const char *needle, const char *message) {
  if (text && strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (missing %s)\n", message, needle);
  return 0;
}

static int expect_absent(const char *text, const char *needle, const char *message) {
  if (!text || !strstr(text, needle)) return 1;
  fprintf(stderr, "FAIL: %s (unexpected %s)\n", message, needle);
  return 0;
}

int main(void) {
  const char *root = getenv("EDR_SOURCE_DIR");
  char *header;
  char *identity;
  char *pipeline;
  char *policy;
  int ok = 1;
  if (!root || !root[0]) root = ".";

  header = read_source(root, "include/edr/windows_file_identity.h");
  identity = read_source(root, "src/preprocess/windows_file_identity.c");
  pipeline = read_source(root, "src/preprocess/preprocess_pipeline.c");
  policy = read_source(root, "src/detection/policy_enforcement.c");
  if (!header || !identity || !pipeline || !policy) {
    fprintf(stderr, "FAIL: cannot read Windows Unicode path sources\n");
    free(header);
    free(identity);
    free(pipeline);
    free(policy);
    return 1;
  }

  ok &= expect_contains(header, "EdrWindowsUtf8PathCompareResult",
                        "shared path comparison must have an explicit invalid-UTF-8 result");
  ok &= expect_contains(identity, "MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS",
                        "path boundary must reject malformed UTF-8 before Win32 access");
  ok &= expect_contains(identity, "CreateFileW(",
                        "file identity must open UTF-16 Windows paths");
  ok &= expect_contains(identity, "QueryFullProcessImageNameW(",
                        "process image helper must use the Unicode Win32 API");
  ok &= expect_contains(identity, "CompareStringOrdinal(left, -1, right, -1, TRUE)",
                        "canonical comparison must use ordinal Windows case semantics");
  ok &= expect_absent(identity, "CreateFileA(",
                      "file identity must not fall back to the active code page");
  ok &= expect_absent(identity, "CP_ACP",
                      "path conversion must not use the active code page");
  ok &= expect_absent(identity, "NormalizeString(",
                      "path identity must not collapse distinct UTF-16 normalization forms");
  ok &= expect_absent(identity, "GetFullPathName",
                      "path identity must not reinterpret namespace syntax");
  ok &= expect_absent(identity, "PathCch",
                      "path identity must not rewrite namespace syntax");

  ok &= expect_contains(pipeline, "edr_windows_process_image_path_utf8(",
                        "token enrichment must use the shared Unicode process path helper");
  ok &= expect_contains(pipeline, "edr_windows_utf8_path_compare_ci(",
                        "token cache and live validation must use one Unicode comparison");
  ok &= expect_contains(pipeline, "token_path_invalid_utf8",
                        "malformed token paths must have a fail-closed reason");
  ok &= expect_absent(pipeline, "QueryFullProcessImageNameA(",
                      "token enrichment must not query process images through ANSI");

  ok &= expect_contains(policy, "edr_windows_process_image_path_utf8(",
                        "enforcement must use the shared Unicode process path helper");
  ok &= expect_contains(policy, "edr_windows_utf8_path_compare_ci(",
                        "enforcement must use the shared Unicode comparison");
  ok &= expect_contains(policy, "canonical image path is invalid UTF-8",
                        "enforcement must make invalid expected paths fail closed");
  ok &= expect_absent(policy, "QueryFullProcessImageNameA(",
                      "enforcement must not query process images through ANSI");

  free(header);
  free(identity);
  free(pipeline);
  free(policy);
  if (!ok) return 1;
  puts("windows Unicode path source contract: ok");
  return 0;
}
