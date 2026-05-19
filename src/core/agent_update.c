#include "edr/agent_update.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef _MSC_VER
#include <strings.h>
#endif

#ifdef EDR_HAVE_OPENSSL_FL
#include <openssl/sha.h>
#endif

#include "cJSON.h"
#include "edr/config.h"
#include "edr/time_util.h"

#ifndef EDR_HAVE_LIBCURL
int edr_agent_check_update(const EdrConfig *cfg) {
  (void)cfg;
  return 0;
}
#else

#include <curl/curl.h>

static int s_curl_inited = 0;

int edr_agent_exe_path(char *out, size_t cap) {
#ifdef _WIN32
  DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
  return (n > 0 && n < (DWORD)cap) ? 1 : 0;
#elif defined(__APPLE__)
  uint32_t size = (uint32_t)cap;
  if (_NSGetExecutablePath(out, &size) == 0) return 1;
  return 0;
#else
  ssize_t n = readlink("/proc/self/exe", out, cap - 1);
  if (n > 0) { out[n] = 0; return 1; }
  return 0;
#endif
}

int edr_agent_startup_update(const EdrConfig *cfg) {
  (void)cfg;
  char exe_path[1024];
  if (!edr_agent_exe_path(exe_path, sizeof(exe_path))) return 0;

  char staged[1024];
  snprintf(staged, sizeof(staged), "%s.new", exe_path);

  FILE *sf = fopen(staged, "rb");
  if (!sf) return 0;
  fclose(sf);

  fprintf(stderr, "[update] staged .new binary found, replacing %s\n", exe_path);

  char bak[1024];
  snprintf(bak, sizeof(bak), "%s.bak", exe_path);
  (void)remove(bak);
  if (rename(exe_path, bak) != 0) {
    fprintf(stderr, "[update] cannot backup current exe, cleanup staged\n");
    (void)remove(staged);
    return 0;
  }
  if (rename(staged, exe_path) != 0) {
    fprintf(stderr, "[update] cannot replace exe, restoring backup\n");
    rename(bak, exe_path);
    return 0;
  }
  fprintf(stderr, "[update] replaced %s successfully\n", exe_path);
  (void)remove(bak);

#ifdef _WIN32
  {
    char bat[1024];
    snprintf(bat, sizeof(bat), "%s.cleanup.bat", exe_path);
    FILE *f = fopen(bat, "wb");
    if (f) {
      fprintf(f, "@echo off\r\n");
      fprintf(f, "timeout /t 1 /nobreak >nul\r\n");
      fprintf(f, "del \"%s\" >nul 2>&1\r\n", bak);
      fprintf(f, "del \"%%~f0\" >nul 2>&1\r\n");
      fclose(f);
    }
  }
#endif
  return 1;
}

static int update_curl_init(void) {
  if (s_curl_inited) return 0;
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) return -1;
  s_curl_inited = 1;
  return 0;
}

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} update_buf;

static size_t update_write_cb(void *ptr, size_t sz, size_t nmemb, void *userdata) {
  update_buf *b = (update_buf *)userdata;
  size_t total = sz * nmemb;
  if (b->len + total + 1 > b->cap) {
    size_t new_cap = (b->cap > 0) ? b->cap * 2 : 8192;
    while (b->len + total + 1 > new_cap) new_cap *= 2;
    if (new_cap > 256 * 1024 * 1024) return 0;
    char *p = realloc(b->data, new_cap);
    if (!p) return 0;
    b->data = p;
    b->cap = new_cap;
  }
  memcpy(b->data + b->len, ptr, total);
  b->len += total;
  b->data[b->len] = 0;
  return total;
}

static char *update_http_get(const char *url, size_t *out_len) {
  if (update_curl_init() != 0) return NULL;
  CURL *curl = curl_easy_init();
  if (!curl) return NULL;

  update_buf b = {NULL, 0, 0};
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, update_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);

  CURLcode cc = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  if (cc != CURLE_OK || !b.data) {
    free(b.data);
    return NULL;
  }
  if (out_len) *out_len = b.len;
  return b.data;
}

static int update_download_file(const char *url, const char *out_path) {
  if (update_curl_init() != 0) return -1;
  CURL *curl = curl_easy_init();
  if (!curl) return -1;

  FILE *f = fopen(out_path, "wb");
  if (!f) {
    curl_easy_cleanup(curl);
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)f);

  CURLcode cc = curl_easy_perform(curl);
  fclose(f);
  curl_easy_cleanup(curl);

  if (cc != CURLE_OK) {
    (void)remove(out_path);
    return -1;
  }
  return 0;
}

static int sha256_file(const char *path, char out_hex[65]) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;

  unsigned char hash[32];
  unsigned char buf[8192];
  size_t n;

#ifndef EDR_HAVE_OPENSSL_FL
  (void)path;
  (void)out_hex;
  fclose(f);
  return -1;
#else
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    SHA256_Update(&ctx, buf, n);
  }
  SHA256_Final(hash, &ctx);
  fclose(f);

  for (int i = 0; i < 32; i++) {
    snprintf(out_hex + i * 2, 3, "%02x", hash[i]);
  }
  out_hex[64] = 0;
  return 0;
#endif
}

static int compare_versions(const char *current, const char *latest) {
  int cmaj = 0, cmin = 0, cpat = 0;
  int lmaj = 0, lmin = 0, lpat = 0;
  sscanf(current, "%d.%d.%d", &cmaj, &cmin, &cpat);
  sscanf(latest, "%d.%d.%d", &lmaj, &lmin, &lpat);

  if (lmaj != cmaj) return (lmaj > cmaj) ? 1 : -1;
  if (lmin != cmin) return (lmin > cmin) ? 1 : -1;
  if (lpat != cpat) return (lpat > cpat) ? 1 : -1;
  return 0;
}

int edr_agent_check_update(const EdrConfig *cfg) {
  if (!cfg || !cfg->remote.auto_update) return 0;
  if (!cfg->remote.version_url[0] || !cfg->remote.download_url[0]) return 0;

  fprintf(stderr, "[update] checking agent version at %s\n", cfg->remote.version_url);

  size_t body_len = 0;
  char *body = update_http_get(cfg->remote.version_url, &body_len);
  if (!body) {
    fprintf(stderr, "[update] version check failed (network error)\n");
    return 0;
  }

  cJSON *root = cJSON_Parse(body);
  free(body);
  if (!root) {
    fprintf(stderr, "[update] version manifest parse failed\n");
    return 0;
  }

  cJSON *ver = cJSON_GetObjectItem(root, "version");
  cJSON *sha = cJSON_GetObjectItem(root, "sha256");
  if (!cJSON_IsString(ver) || !cJSON_IsString(sha)) {
    fprintf(stderr, "[update] version manifest missing version/sha256\n");
    cJSON_Delete(root);
    return 0;
  }

  const char *latest = ver->valuestring;
  const char *expected_sha = sha->valuestring;
  int cmp = compare_versions(EDR_AGENT_VERSION_STRING, latest);
  cJSON_Delete(root);

  if (cmp >= 0) {
    fprintf(stderr, "[update] up-to-date (%s)\n", EDR_AGENT_VERSION_STRING);
    return 0;
  }

  fprintf(stderr, "[update] new version %s available (current %s), downloading...\n",
          latest, EDR_AGENT_VERSION_STRING);

  char exe_path[1024];
  if (!edr_agent_exe_path(exe_path, sizeof(exe_path))) {
    fprintf(stderr, "[update] cannot resolve exe path\n");
    return 0;
  }

  char staged[1024];
  snprintf(staged, sizeof(staged), "%s.new", exe_path);

  if (update_download_file(cfg->remote.download_url, staged) != 0) {
    fprintf(stderr, "[update] download failed\n");
    (void)remove(staged);
    return 0;
  }

  char actual_sha[65];
  if (sha256_file(staged, actual_sha) != 0) {
    fprintf(stderr, "[update] sha256 check failed (no openssl)\n");
    (void)remove(staged);
    return 0;
  }

#ifdef _MSC_VER
  if (_stricmp(actual_sha, expected_sha) != 0) {
#else
  if (strcasecmp(actual_sha, expected_sha) != 0) {
#endif
    fprintf(stderr, "[update] sha256 mismatch: got %s, expected %s\n", actual_sha, expected_sha);
    (void)remove(staged);
    return 0;
  }

  fprintf(stderr, "[update] sha256 OK, restarting to apply update %s -> %s\n",
          EDR_AGENT_VERSION_STRING, latest);

#if defined(_WIN32)
  {
    char bat[1024];
    snprintf(bat, sizeof(bat), "%s.update.bat", exe_path);
    FILE *f = fopen(bat, "wb");
    if (f) {
      fprintf(f, "@echo off\r\n");
      fprintf(f, "timeout /t 2 /nobreak >nul\r\n");
      fprintf(f, "move /Y \"%s\" \"%s\"\r\n", staged, exe_path);
      fprintf(f, "del \"%%~f0\" >nul 2>&1\r\n");
      fclose(f);
      system(bat);
      exit(0);
    }
  }
#else
  {
    char script[1024];
    snprintf(script, sizeof(script), "%s.update.sh", exe_path);
    FILE *f = fopen(script, "w");
    if (f) {
      fprintf(f, "#!/bin/sh\n");
      fprintf(f, "sleep 2\n");
      fprintf(f, "mv -f '%s' '%s'\n", staged, exe_path);
      fprintf(f, "rm -f '$0'\n");
      fclose(f);
      chmod(script, 0755);
      execl("/bin/sh", "sh", script, NULL);
      _exit(0);
    }
  }
#endif

  return 0;
}
#endif
