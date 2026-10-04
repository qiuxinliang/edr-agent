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
static unsigned g_download_calls;

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

static int path_exists(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  fclose(f);
  return 1;
}

static int join_test_path(char *out, size_t cap, const char *base, const char *suffix) {
  size_t base_len;
  size_t suffix_len;
  if (!out || cap == 0u || !base || !suffix) return -1;
  base_len = strlen(base);
  suffix_len = strlen(suffix);
  if (base_len >= cap || suffix_len >= cap - base_len) return -1;
  memcpy(out, base, base_len);
  memcpy(out + base_len, suffix, suffix_len + 1u);
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
  g_download_calls++;
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

int edr_ingest_http_get_url_to_file_meta_bounded(const char *url,
                                                 const char *file_path,
                                                 size_t max_bytes,
                                                 EdrAgentConfigHeaders *headers,
                                                 int timeout_ms,
                                                 int max_attempts) {
  (void)timeout_ms;
  (void)max_attempts;
  return edr_ingest_http_get_url_to_file_meta(url, file_path, max_bytes, headers);
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

static void test_json_str_rejects_oversized_manifest_value(void) {
  char out[8];
  int rc = dc_json_str("{\"url\":\"https://forensic.example.invalid/collector\"}",
                       "url", out, sizeof(out));
  expect_true(rc != 0, "oversized manifest value must be rejected, not prefix-truncated");
  expect_true(out[0] == '\0', "rejected manifest value must not leave a usable prefix");
}

static void test_download_detail_keeps_curl_exit_when_prior_detail_is_full(void) {
  memset(g_dc_download_detail, 'x', sizeof(g_dc_download_detail) - 1u);
  g_dc_download_detail[sizeof(g_dc_download_detail) - 1u] = '\0';
  dc_note_curl_exit(23ul);
  expect_true(strstr(g_dc_download_detail, "previous_download_detail_sha256=") != NULL,
              "full download detail should become an explicit digest");
  expect_true(strstr(g_dc_download_detail, "curl exit=23") != NULL,
              "curl exit must remain visible after detail compaction");
}

static void test_native_http_client_error_detection(void) {
  snprintf(g_dc_download_detail, sizeof(g_dc_download_detail),
           "native http: http get status: HTTP/1.1 404 Not Found");
  expect_true(dc_native_http_client_error(), "HTTP 404 should suppress unauthenticated curl fallback");
  snprintf(g_dc_download_detail, sizeof(g_dc_download_detail),
           "native http: https tcp connect failed");
  expect_true(!dc_native_http_client_error(), "transport failure may still use curl fallback");
}

static void test_artifact_failure_keeps_existing_dest(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }
  expect_true(write_file_bytes(dest, "existing-good") == 0, "write existing dest");

  g_manifest_body = "{\"enabled\":true,\"url\":\"https://platform.invalid/artifact bad\",\"sha256\":\"\"}";
  g_artifact_body = "new-bad";
  g_fail_download_substr = "/download";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1");
#else
  setenv("EDR_FORENSIC_DOWNLOAD_NO_CURL", "1", 1);
#endif
  char detail[256];
  int rc = dc_autofetch_via_manifest("https://platform.invalid/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64", dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_ERR_DOWNLOAD, "invalid artifact url should fail download");
  expect_true(strstr(detail, "artifact download failed") != NULL, "detail should name artifact stage");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "existing dest should remain readable");
  expect_true(strcmp(got, "existing-good") == 0, "failed artifact download must not delete existing dest");
  char part[512];
  if (join_test_path(part, sizeof(part), dest, ".part") != 0) {
    expect_true(0, "build artifact part path without truncation");
    remove(dest);
    rmdir(dir);
    return;
  }
  expect_true(!path_exists(part), "failed artifact download should not leave .part");
  g_fail_download_substr = NULL;
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_DOWNLOAD_NO_CURL", "");
#else
  unsetenv("EDR_FORENSIC_DOWNLOAD_NO_CURL");
#endif
  remove(dest);
  rmdir(dir);
}

static void test_success_installs_part_atomically(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }
  g_manifest_body = "{\"enabled\":true,\"url\":\"https://platform.invalid/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64\",\"sha256\":\"\"}";
  g_artifact_body = "new-good";
  char detail[256];
  int rc = dc_autofetch_via_manifest("https://platform.invalid/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64", dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "artifact download should install successfully");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "installed dest should be readable");
  expect_true(strcmp(got, "new-good") == 0, "installed dest should contain artifact body");
  char part[512];
  if (join_test_path(part, sizeof(part), dest, ".part") != 0) {
    expect_true(0, "build artifact part path without truncation");
    remove(dest);
    rmdir(dir);
    return;
  }
  expect_true(!path_exists(part), "successful install should not leave .part");
  remove(dest);
  rmdir(dir);
}

static void test_unproven_external_download_is_denied_before_io(void) {
  char dir[512], dest[640];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create denial temp dir");
  expect_true(join_test_path(dest, sizeof(dest), dir, "/denied-output") == 0, "denial output path");
  unsigned calls = g_download_calls;
  expect_true(dc_download("https://external.invalid/private-artifact", dest) != 0,
              "unproven external artifact route must be denied");
  expect_true(g_download_calls == calls && !path_exists(dest), "denial must precede native client and file I/O");
  expect_true(strstr(dc_last_download_detail(), "egress") != NULL, "denial has an observable policy cause");
#ifndef _WIN32
  /* Force the subprocess branch and put a harmless marker-writing curl at
   * its PATH. A denied route must return before any subprocess can execute. */
  char fake[640], marker[640];
  expect_true(join_test_path(fake, sizeof(fake), dir, "/curl") == 0, "fake curl path");
  expect_true(join_test_path(marker, sizeof(marker), dir, "/executed") == 0, "execution marker path");
  expect_true(write_file_bytes(fake, "#!/bin/sh\n/usr/bin/touch \"$EDR_EGRESS_EXEC_MARKER\"\n") == 0,
              "write harmless subprocess marker");
  expect_true(chmod(fake, 0700) == 0, "make marker executable");
  const char *existing_path = getenv("PATH");
  char *saved_path = existing_path ? strdup(existing_path) : NULL;
  setenv("PATH", dir, 1); setenv("EDR_EGRESS_EXEC_MARKER", marker, 1);
  setenv("EDR_FORENSIC_DOWNLOAD_NO_INPROC", "1", 1);
  expect_true(dc_download("https://external.invalid/private-artifact", dest) != 0,
              "subprocess download cannot bypass purpose denial");
  expect_true(!path_exists(marker) && !path_exists(dest), "denied route must not execute curl");
  if (saved_path) { setenv("PATH", saved_path, 1); free(saved_path); } else unsetenv("PATH");
  unsetenv("EDR_EGRESS_EXEC_MARKER"); unsetenv("EDR_FORENSIC_DOWNLOAD_NO_INPROC");
  remove(fake);
#endif
  rmdir(dir);
}

static void test_artifact_download_fallback_uses_manifest_origin(void) {
  char dir[512];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create temp dir");
  char dest[512];
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }

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
      "https://reachable.local/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64",
      dest, NULL, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "artifact fallback should install successfully");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "fallback dest should be readable");
  expect_true(strcmp(got, "fallback-good") == 0, "fallback should use manifest-origin download URL");
  char part[512];
  if (join_test_path(part, sizeof(part), dest, ".part") != 0) {
    expect_true(0, "build artifact part path without truncation");
    remove(dest);
    rmdir(dir);
    return;
  }
  expect_true(!path_exists(part), "fallback install should not leave .part");

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
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }
  g_rest_base = "https://reachable.local/api/v1/";
  g_manifest_body = "{\"enabled\":true,\"url\":\"https://reachable.local/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64\",\"sha256\":\"\"}";
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
  expect_true(strcmp(g_last_artifact_url, "https://reachable.local/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64") == 0,
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

static void test_fixed_local_collector_is_never_replaced_by_adapter(void) {
  char dir[512];
  char dest[512];
  char resolved[512];
  char detail[256];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create fixed collector temp dir");
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector_builtin.exe") != 0) {
    expect_true(0, "build fixed collector destination without truncation");
    rmdir(dir);
    return;
  }
  g_rest_base = "https://reachable.local/api/v1/";
  g_manifest_body = "{\"enabled\":true,\"url\":\"https://reachable.local/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64\",\"sha256\":\"\"}";
  g_artifact_body = "downloaded-adapter";
  g_last_manifest_url[0] = '\0';
  g_last_artifact_url[0] = '\0';

  int rc = dc_resolve_verify(dest, dest, 1, resolved, sizeof(resolved), detail, sizeof(detail));
  expect_true(rc == EDR_DC_ERR_DOWNLOAD, "missing fixed collector must fail closed");
  expect_true(!path_exists(dest), "missing fixed collector must not be replaced by adapter download");
  expect_true(g_last_manifest_url[0] == '\0' && g_last_artifact_url[0] == '\0',
              "fixed collector resolution must not access adapter manifest or artifact");
  expect_true(strstr(detail, "fixed local collector missing") != NULL,
              "missing fixed collector should report the recovery boundary failure");

  expect_true(write_file_bytes(dest, "independent-c-baseline") == 0,
              "write independent fixed collector");
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_ADAPTER_SHA256",
            "0000000000000000000000000000000000000000000000000000000000000000");
#else
  setenv("EDR_FORENSIC_ADAPTER_SHA256",
         "0000000000000000000000000000000000000000000000000000000000000000", 1);
#endif
  rc = dc_resolve_verify(dest, dest, 1, resolved, sizeof(resolved), detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK,
              "independent fixed collector must not inherit the adapter SHA-256 pin");
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_ADAPTER_SHA256", "");
#else
  unsetenv("EDR_FORENSIC_ADAPTER_SHA256");
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
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }
  expect_true(write_file_bytes(dest, "old-adapter-body") == 0, "write existing old adapter");

  /* manifest 广告一个新 sha(= new-adapter-body 的 sha),artifact 下载返回新体。 */
  char newsha[65];
  expect_true(edr_sha256_hex((const unsigned char *)"new-adapter-body", 16, newsha) == 0, "hash new body");
  static char mbody[512];
  snprintf(mbody, sizeof(mbody), "{\"enabled\":true,\"url\":\"https://plat.invalid/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64\",\"sha256\":\"%s\"}", newsha);
  g_manifest_body = mbody;
  g_artifact_body = "new-adapter-body";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "1");
#else
  setenv("EDR_FORENSIC_VERSION_CHECK_SEC", "1", 1);
#endif

  time_t last = 0;
  char detail[256];
  int rc = dc_maybe_refresh(dest, "https://plat.invalid/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64", NULL, &last, detail, sizeof(detail));
  expect_true(rc == EDR_DC_OK, "refresh with changed sha should succeed");
  char got[64];
  expect_true(read_file_text(dest, got, sizeof(got)) == 0, "dest readable after refresh");
  expect_true(strcmp(got, "new-adapter-body") == 0, "stale adapter replaced with new body");

  /* 第二次:同一 last_check 且间隔未到 → 不再拉取(限流),文件不变。 */
  g_artifact_body = "SHOULD-NOT-BE-USED";
  int rc2 = dc_maybe_refresh(dest, "https://plat.invalid/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64", NULL, &last, detail, sizeof(detail));
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
  if (join_test_path(dest, sizeof(dest), dir, "/forensic_collector.exe") != 0) {
    expect_true(0, "build artifact destination without truncation");
    rmdir(dir);
    return;
  }
  expect_true(write_file_bytes(dest, "current-body") == 0, "write current adapter");
  char cursha[65];
  expect_true(edr_sha256_hex((const unsigned char *)"current-body", 12, cursha) == 0, "hash current");
  static char mbody[512];
  snprintf(mbody, sizeof(mbody), "{\"enabled\":true,\"url\":\"https://plat.invalid/api/v1/agent/forensic-collector/download?kind=adapter&os=windows&arch=amd64\",\"sha256\":\"%s\"}", cursha);
  g_manifest_body = mbody;
  g_artifact_body = "SHOULD-NOT-DOWNLOAD";
#ifdef _WIN32
  _putenv_s("EDR_FORENSIC_VERSION_CHECK_SEC", "1");
#else
  setenv("EDR_FORENSIC_VERSION_CHECK_SEC", "1", 1);
#endif
  time_t last = 0;
  char detail[256];
  int rc = dc_maybe_refresh(dest, "https://plat.invalid/api/v1/agent/forensic-collector/manifest?kind=adapter&os=windows&arch=amd64", NULL, &last, detail, sizeof(detail));
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

static void test_async_collector_wall_timeout(void) {
  char dir[512], script[600], marker[600], body[1400], detail[256];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create timeout temp dir");
  snprintf(script, sizeof(script), "%s/ignores-timeout.sh", dir);
  snprintf(marker, sizeof(marker), "%s/orphan-write", dir);
  snprintf(body, sizeof(body), "#!/bin/sh\n(sleep 2; echo orphan > '%s') &\nwait\n", marker);
  expect_true(write_file_bytes(script, body) == 0, "write timeout collector");
  expect_true(chmod(script, 0700) == 0, "make timeout collector executable");
  EdrCollectorRunSpec spec = {0};
  spec.collector_bin = script; spec.scope = "triage"; spec.output_dir = dir; spec.timeout_s = 1;
  expect_true(edr_deep_collector_spawn(&spec, detail, sizeof(detail)) == EDR_DC_OK, "spawn timeout collector");
  int rc = 1, ec = 0;
  for (unsigned i = 0; i < 30 && rc > 0; ++i) {
    usleep(100000);
    rc = edr_deep_collector_poll(&ec, detail, sizeof(detail));
  }
  expect_true(rc == EDR_DC_ERR_TIMEOUT, "parent enforces timeout for an uncooperative child");
  expect_true(!edr_deep_collector_is_running(), "timeout clears active slot");
  sleep(2);
  expect_true(!path_exists(marker), "timeout kills descendants before they write more data");
  remove(marker); remove(script); rmdir(dir);
}

#endif


#ifdef _WIN32
static void test_async_collector_wall_timeout_windows(void) {
  char dir[512], marker[600], exe[1024], extra[700], detail[256];
  expect_true(make_temp_dir(dir, sizeof(dir)) == 0, "create Windows timeout directory");
  snprintf(marker, sizeof(marker), "%s\\orphan-write", dir);
  expect_true(GetModuleFileNameA(NULL, exe, sizeof(exe)) > 0, "locate test child executable");
  snprintf(extra, sizeof(extra), "--out-file=\"%s\"", marker);
  EdrCollectorRunSpec spec = {0};
  spec.collector_bin = exe; spec.fixed_local_binary = 1;
  spec.scope = "timeout-test"; spec.output_dir = dir; spec.extra_args = extra; spec.timeout_s = 1;
  expect_true(edr_deep_collector_spawn(&spec, detail, sizeof(detail)) == EDR_DC_OK,
              "spawn Windows timeout collector in a job");
  int rc = 1, ec = 0;
  for (unsigned i = 0; i < 30 && rc > 0; ++i) {
    Sleep(100);
    rc = edr_deep_collector_poll(&ec, detail, sizeof(detail));
  }
  expect_true(rc == EDR_DC_ERR_TIMEOUT, "Windows parent enforces wall-time limit");
  expect_true(!edr_deep_collector_is_running(), "Windows timeout releases active slot");
  Sleep(2500);
  expect_true(!path_exists(marker), "Windows timeout terminates tar-like descendants");
  remove(marker); _rmdir(dir);
}

static int run_timeout_test_child(int argc, char **argv) {
  const char *marker = NULL;
  int collector = 0;
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--late-write=", 13) == 0) {
      Sleep(2500);
      return write_file_bytes(argv[i] + 13, "unexpected orphan write");
    }
    if (strncmp(argv[i], "--out-file=", 11) == 0) marker = argv[i] + 11;
    if (strcmp(argv[i], "--scope=timeout-test") == 0) collector = 1;
  }
  if (!collector) return -1;
  if (!marker) return 5;
  char exe[1024], cmd[1800];
  if (!GetModuleFileNameA(NULL, exe, sizeof(exe))) return 5;
  snprintf(cmd, sizeof(cmd), "\"%s\" --late-write=\"%s\"", exe, marker);
  STARTUPINFOA si = {0}; si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessA(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 5;
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
  Sleep(30000); /* Intentionally ignore --timeout; parent must stop this tree. */
  return 0;
}
#endif

static void test_collector_arguments_cannot_create_independent_egress(void) {
  const char *denied[] = {
    "--upload-url=https://synthetic.invalid/raw", "--frontend=synthetic.invalid",
    "--config=https://synthetic.invalid/client.yaml", "--request=//synthetic-host/share/job.req",
    "--unknown-network-option=1", "--out-file=one --out-file=two",
    "--request=\"unterminated"
  };
  EdrCollectorRunSpec spec = {0};
  spec.collector_bin = "synthetic-absent-local-collector";
  spec.fixed_local_binary = 1;
  spec.scope = "triage";
  spec.output_dir = ".";
  char detail[256];
  unsigned before = g_download_calls;
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
    spec.extra_args = denied[i];
    expect_true(edr_deep_collector_run_blocking(&spec, detail, sizeof(detail)) == EDR_DC_ERR_DISABLED,
                "blocking collector rejects unsupported egress before resolving its binary");
    expect_true(strstr(detail, "collector_arguments_purpose_denied") != NULL,
                "collector reports a bounded local purpose reason");
    expect_true(edr_deep_collector_spawn(&spec, detail, sizeof(detail)) == EDR_DC_ERR_DISABLED,
                "async collector uses the same local argument contract");
  }
  expect_true(g_download_calls == before, "denied collector arguments cannot cause a download");
  EdrDeepCollectorParams params = {0};
  params.scope = "triage";
  params.output_dir = ".";
  params.upload_url = "https://synthetic.invalid/raw";
  expect_true(edr_deep_collector_launch(&params) == EDR_DC_ERR_DISABLED,
              "legacy launch rejects an independent upload URL");
}

#ifndef _WIN32
static void test_local_collector_preserves_quoted_paths(void) {
  char dir[512], script[600], rows[640], extra[1500], detail[256];
  expect_true(make_temp_dir(dir,sizeof(dir))==0,"local quoted-path fixture directory");
  snprintf(script,sizeof(script),"%s/local-collector",dir);
  snprintf(rows,sizeof(rows),"%s/local rows.txt",dir);
  const char *body="#!/bin/sh\nfor value do\n case $value in --out-file=*) out=${value#*=};; esac\ndone\nprintf '%s\\n' \"$@\" > \"$out\"\n";
  expect_true(write_file_bytes(script,body)==0 && chmod(script,0700)==0,"local collector fixture");
  snprintf(extra,sizeof(extra),"--mode=query --request=\"%s/local request.req\" --out-file=\"%s\" --limit=12",dir,rows);
  EdrCollectorRunSpec spec={0}; spec.collector_bin=script; spec.fixed_local_binary=1;
  spec.scope="triage"; spec.output_dir=dir; spec.extra_args=extra; spec.timeout_s=3;
  expect_true(edr_deep_collector_run_blocking(&spec,detail,sizeof(detail))==EDR_DC_OK,
              "local-only queries still execute with quoted local paths");
  FILE *file=fopen(rows,"rb"); char captured[2200]={0};
  expect_true(file!=NULL,"collector writes local output");
  if(file) { (void)fread(captured,1,sizeof(captured)-1,file); fclose(file); }
  expect_true(strstr(captured,"/local request.req\n") && strstr(captured,"/local rows.txt\n"),
              "both quoted paths arrive as complete child arguments");
  remove(rows); remove(script); rmdir(dir);
}
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
  int child_rc = run_timeout_test_child(argc, argv);
  if (child_rc >= 0) return child_rc;
#else
  (void)argc; (void)argv;
#endif
  test_collector_arguments_cannot_create_independent_egress();
  test_json_url_unescape();
  test_json_str_rejects_oversized_manifest_value();
  test_download_detail_keeps_curl_exit_when_prior_detail_is_full();
  test_native_http_client_error_detection();
  test_artifact_failure_keeps_existing_dest();
  test_success_installs_part_atomically();
  test_unproven_external_download_is_denied_before_io();
  test_artifact_download_fallback_uses_manifest_origin();
  test_ensure_adapter_derives_manifest_from_rest_base();
  test_fixed_local_collector_is_never_replaced_by_adapter();
  test_stderr_tail_appended();
  test_maybe_refresh_replaces_on_sha_change();
  test_maybe_refresh_keeps_current_when_sha_matches();
#ifndef _WIN32
  test_local_collector_preserves_quoted_paths();
  test_blocking_collector_cancels_process_group();
  test_async_collector_wall_timeout();
#else
  test_async_collector_wall_timeout_windows();
#endif
  return g_failures == 0 ? 0 : 1;
}
