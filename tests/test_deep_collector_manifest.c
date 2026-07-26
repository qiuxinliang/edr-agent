#include "edr/ingest_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static int g_failures;
static const char *g_manifest_body;
static const char *g_artifact_body;
static const char *g_fail_download_substr;
static const char *g_rest_base;
static char g_runtime_last_error[160];
static char g_last_manifest_url[512];
static char g_last_artifact_url[512];

static void expect_true(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    g_failures++;
  }
}

static int write_file_bytes(const char *path, const char *data) {
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  if (data && data[0]) {
    size_t n = strlen(data);
    if (fwrite(data, 1, n, f) != n) {
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  return 0;
}

static int make_temp_dir(char *out, size_t cap) {
#ifdef _WIN32
  const char *base = getenv("TEMP");
  if (!base || !base[0]) base = ".";
  if (snprintf(out, cap, "%s\\edr_dc_test_XXXXXX", base) >= (int)cap) return -1;
  if (_mktemp_s(out, cap) != 0) return -1;
  return _mkdir(out);
#else
  const char *base = getenv("TMPDIR");
  if (!base || !base[0]) base = "/tmp";
  if (snprintf(out, cap, "%s/edr_dc_test_XXXXXX", base) >= (int)cap) return -1;
  return mkdtemp(out) ? 0 : -1;
#endif
}

int edr_ingest_http_get_url_to_file(const char *url, const char *file_path, size_t max_bytes) {
  (void)max_bytes;
  g_runtime_last_error[0] = '\0';
  if (g_fail_download_substr && strstr(url, g_fail_download_substr)) {
    snprintf(g_runtime_last_error, sizeof(g_runtime_last_error), "simulated download failure");
    return -1;
  }
  if (strstr(url, "/manifest")) {
    snprintf(g_last_manifest_url, sizeof(g_last_manifest_url), "%s", url);
    return write_file_bytes(file_path, g_manifest_body ? g_manifest_body : "");
  }
  if (strstr(url, "/artifact") || strstr(url, "/download")) {
    snprintf(g_last_artifact_url, sizeof(g_last_artifact_url), "%s", url);
    return write_file_bytes(file_path, g_artifact_body ? g_artifact_body : "");
  }
  return -1;
}

int edr_ingest_http_get_url_to_file_meta(const char *url, const char *file_path,
                                         size_t max_bytes, EdrAgentConfigHeaders *headers) {
  (void)headers;
  return edr_ingest_http_get_url_to_file(url, file_path, max_bytes);
}

void edr_ingest_http_get_runtime(EdrIngestHttpRuntime *out) {
  if (!out) return;
  memset(out, 0, sizeof(*out));
  snprintf(out->last_error, sizeof(out->last_error), "%s", g_runtime_last_error);
}

void edr_ingest_http_get_rest_base(char *out, size_t cap) {
  if (!out || cap == 0) return;
  snprintf(out, cap, "%s", g_rest_base ? g_rest_base : "");
}

#include "../src/forensic/deep_collector.c"

static int read_file_text(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  size_t n = fread(out, 1, cap - 1, f);
  fclose(f);
  out[n] = '\0';
  return 0;
}

static void test_json_url_unescape(void) {
  char out[256];
  int rc = dc_json_str("{\"url\":\"https://plat/api/download?kind=adapter\\u0026os=windows\\u0026arch=amd64\"}",
                       "url", out, sizeof(out));
  expect_true(rc == 0, "json url should parse");
  expect_true(strcmp(out, "https://plat/api/download?kind=adapter&os=windows&arch=amd64") == 0,
              "json url should unescape unicode ampersands");
}

static void test_artifact_failure_keeps_existing_dest(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);
  expect_true(write_file_bytes(dest, "existing-good") == 0, "write existing dest");

  g_manifest_body = "{\"enabled\":true,\"url\":\"https://platform.invalid/artifact bad\",\"sha256\":\"\"}";
  g_artifact_body = "new-bad";
  char detail[256];
  int rc = dc_autofetch_via_manifest("https://platform.invalid/manifest", dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_ERR_DOWNLOAD, "invalid artifact url should fail download");
  expect_true(strstr(detail, "artifact download failed") != NULL, "detail should name artifact stage");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "existing dest should remain readable");
  expect_true(strcmp(got, "existing-good") == 0, "failed artifact download must not delete existing dest");
  char part[512];
  snprintf(part, sizeof(part), "%s.part", dest);
  expect_true(!dc_file_exists(part), "failed artifact download should not leave .part");
  remove(dest);
  rmdir(dir);
}

static void test_success_installs_part_atomically(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);
  g_manifest_body = "{\"enabled\":true,\"url\":\"https://platform.invalid/artifact\",\"sha256\":\"\"}";
  g_artifact_body = "new-good";
  char detail[256];
  int rc = dc_autofetch_via_manifest("https://platform.invalid/manifest", dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "artifact download should install successfully");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "installed dest should be readable");
  expect_true(strcmp(got, "new-good") == 0, "installed dest should contain artifact body");
  char part[512];
  snprintf(part, sizeof(part), "%s.part", dest);
  expect_true(!dc_file_exists(part), "successful install should not leave .part");
  remove(dest);
  rmdir(dir);
}

static void test_artifact_download_fallback_uses_manifest_origin(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);

  g_manifest_body = "{\"enabled\":true,\"url\":\"https://public.invalid/api/v1/agent/forensic-collector/download?kind=adapter\\u0026os=windows\\u0026arch=amd64\",\"sha256\":\"\"}";
  g_artifact_body = "fallback-good";
  g_fail_download_substr = "public.invalid";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1");
#else
  setenv("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1", 1);
#endif

  char detail[256];
  int rc = dc_autofetch_via_manifest(
      "https://reachable.local/api/v1/agent/forensic-collector/manifest?kind=forensic_collector&os=windows&arch=amd64",
      dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "artifact fallback should install successfully");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "fallback dest should be readable");
  expect_true(strcmp(got, "fallback-good") == 0, "fallback should use manifest-origin download URL");
  char part[512];
  snprintf(part, sizeof(part), "%s.part", dest);
  expect_true(!dc_file_exists(part), "fallback install should not leave .part");

#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "");
#else
  unsetenv("EDR_FORENSIC_DOWNLOAD_NO_CURL");
#endif
  g_fail_download_substr = NULL;
  remove(dest);
  rmdir(dir);
}

static void test_ensure_adapter_derives_manifest_from_rest_base(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);
  g_rest_base = "https://reachable.local/api/v1/";
  g_manifest_body = "{\"enabled\":true,\"url\":\"https://reachable.local/artifact\",\"sha256\":\"\"}";
  g_artifact_body = "downloaded-adapter";
  g_last_manifest_url[0] = '\0';
  g_last_artifact_url[0] = '\0';
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_ADAPTER_MANIFEST_URL", "");
  _putenv_s("EDR_FORENSIC_COLLECTOR_AUTOFETCH", "1");
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1");
#else
  unsetenv("EDR_FORENSIC_ADAPTER_MANIFEST_URL");
  setenv("EDR_FORENSIC_COLLECTOR_AUTOFETCH", "1", 1);
  setenv("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1", 1);
#endif

  char detail[256];
  int rc = dc_ensure_adapter_unlocked(dest, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "missing adapter should download via derived manifest");
  expect_true(strstr(g_last_manifest_url, "https://reachable.local/api/v1/agent/forensic-collector/manifest?") != NULL,
              "derived manifest should use rest_base origin");
  expect_true(strstr(g_last_manifest_url, "kind=adapter") != NULL, "derived adapter manifest should use adapter kind");
  expect_true(strstr(g_last_manifest_url, dc_current_os_token()) != NULL, "derived manifest should include OS");
  expect_true(strstr(g_last_manifest_url, dc_current_arch_token()) != NULL, "derived manifest should include arch");
  expect_true(strcmp(g_last_artifact_url, "https://reachable.local/artifact") == 0,
              "derived manifest should download advertised artifact URL");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "derived install dest should be readable");
  expect_true(strcmp(got, "downloaded-adapter") == 0, "derived manifest download installs adapter body");

#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_COLLECTOR_AUTOFETCH", "");
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "");
#else
  unsetenv("EDR_FORENSIC_COLLECTOR_AUTOFETCH");
  unsetenv("EDR_FORENSIC_DOWNLOAD_NO_CURL");
#endif
  g_rest_base = NULL;
  remove(dest);
  rmdir(dir);
}

static void test_stderr_tail_appended(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char errp[600];
  snprintf(errp, sizeof(errp), "%s/fc_stderr.log", dir);
  expect_true(write_file_bytes(errp,
      "[ERROR] While resolving Consumer.Name Symbol Consumer not found\nvelociraptor.exe: error: query\n") == 0,
      "write stderr log");
  char detail[256];
  snprintf(detail, sizeof(detail), "collector exit=3");
  dc_append_stderr_tail(errp, detail, sizeof(detail));
  expect_true(strstr(detail, "collector exit=3") != NULL, "detail keeps base");
  expect_true(strstr(detail, "Symbol Consumer not found") != NULL, "detail gains velo error tail");
  expect_true(strchr(detail, '"') == NULL, "tail must be quote-free for JSON safety");
  remove(errp);
  rmdir(dir);
}

static void test_maybe_refresh_replaces_on_sha_change(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);
  expect_true(write_file_bytes(dest, "old-adapter-body") == 0, "write existing old adapter");

  /* manifest 广告一个新 sha(= new-adapter-body 的 sha),artifact 下载返回新体。 */
  char newsha[65];
  expect_true(edr_sha256_hex((const unsigned char *)"new-adapter-body", 16, newsha) == 0, "hash new body");
  static char mbody[256];
  snprintf(mbody, sizeof(mbody), "{\"enabled\":true,\"url\":\"https://plat.invalid/artifact\",\"sha256\":\"%s\"}", newsha);
  g_manifest_body = mbody;
  g_artifact_body = "new-adapter-body";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "1");
#else
  setenv("EDR_FORENSIC_VERSION_CHECK_SEC", "1", 1);
#endif

  time_t last = 0;
  char detail[256];
  int rc = dc_maybe_refresh(dest, "https://plat.invalid/manifest", NULL, &last, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "refresh with changed sha should succeed");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "dest readable after refresh");
  expect_true(strcmp(got, "new-adapter-body") == 0, "stale adapter replaced with new body");

  /* 第二次:同一 last_check 且间隔未到 → 不再拉取(限流),文件不变。 */
  g_artifact_body = "SHOULD-NOT-BE-USED";
  int rc2 = dc_maybe_refresh(dest, "https://plat.invalid/manifest", NULL, &last, detail, sizeof(detail));
  expect_true(rc2 == EDR_DC_OK, "second refresh within interval is a no-op");
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "dest still readable");
  expect_true(strcmp(got, "new-adapter-body") == 0, "rate-limited: file unchanged on second call");

#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "");
#else
  unsetenv("EDR_FORENSIC_VERSION_CHECK_SEC");
#endif
  remove(dest);
  rmdir(dir);
}

static void test_maybe_refresh_keeps_current_when_sha_matches(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  snprintf(dest, sizeof(dest), "%s/forensic_collector.exe", dir);
  expect_true(write_file_bytes(dest, "current-body") == 0, "write current adapter");
  char cursha[65];
  expect_true(edr_sha256_hex((const unsigned char *)"current-body", 12, cursha) == 0, "hash current");
  static char mbody[256];
  snprintf(mbody, sizeof(mbody), "{\"enabled\":true,\"url\":\"https://plat.invalid/artifact\",\"sha256\":\"%s\"}", cursha);
  g_manifest_body = mbody;
  g_artifact_body = "SHOULD-NOT-DOWNLOAD";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "1");
#else
  setenv("EDR_FORENSIC_VERSION_CHECK_SEC", "1", 1);
#endif
  time_t last = 0;
  char detail[256];
  int rc = dc_maybe_refresh(dest, "https://plat.invalid/manifest", NULL, &last, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "matching sha → no-op OK");
  char got[64];
  read_file_text(dest, got, sizeof(got));
  expect_true(strcmp(got, "current-body") == 0, "matching sha keeps current body (no re-download)");
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "");
#else
  unsetenv("EDR_FORENSIC_VERSION_CHECK_SEC");
#endif
  remove(dest);
  rmdir(dir);
}

#ifndef _WIN32
static int cancel_immediately(void *user) {
  int *calls = (int *)user;
  (*calls)++;
  return 1;
}

static void test_blocking_collector_cancels_process_group(void) {
  char dir[512];
  char script[600];
  char detail[256];
  int cancel_calls = 0;
  EdrCollectorRunSpec spec;
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create cancellation temp dir");
  snprintf(script, sizeof(script), "%s/slow-collector.sh", dir);
  expect_true(write_file_bytes(script, "#!/bin/sh\nsleep 30\n") == 0,
              "write slow collector script");
  expect_true(chmod(script, 0700) == 0, "make slow collector executable");
  memset(&spec, 0, sizeof(spec));
  spec.collector_bin = script;
  spec.scope = "cancel-test";
  spec.output_dir = dir;
  spec.timeout_s = 10;
  spec.cancel_requested = cancel_immediately;
  spec.cancel_user = &cancel_calls;
  expect_true(edr_deep_collector_run_blocking(&spec, detail, sizeof(detail)) ==
                  EDR_DC_ERR_CANCELLED,
              "blocking collector returns cancelled status");
  expect_true(cancel_calls > 0, "blocking collector invokes cancellation callback");
  expect_true(strstr(detail, "cancelled") != NULL, "blocking collector reports cancellation");
  remove(script);
  rmdir(dir);
}
#endif

int main(void) {
  test_json_url_unescape();
  test_artifact_failure_keeps_existing_dest();
  test_success_installs_part_atomically();
  test_artifact_download_fallback_uses_manifest_origin();
  test_ensure_adapter_derives_manifest_from_rest_base();
  test_stderr_tail_appended();
  test_maybe_refresh_replaces_on_sha_change();
  test_maybe_refresh_keeps_current_when_sha_matches();
#ifndef _WIN32
  test_blocking_collector_cancels_process_group();
#endif
  return g_failures == 0 ? 0 : 1;
}
