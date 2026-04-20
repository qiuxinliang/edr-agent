#include "edr/webshell_forensic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define MKDIR(path) _mkdir(path)
#define SEP '\\'
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define MKDIR(path) mkdir(path, 0755)
#define SEP '/'
#endif

static unsigned long s_alert_seq;

void edr_webshell_make_alert_id(char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  time_t t = time(NULL);
  unsigned long seq = ++s_alert_seq;
  snprintf(out, cap, "ws-%llx-%lx", (unsigned long long)t, seq);
}

int edr_webshell_file_fingerprint(const char *path, char *out_hex, size_t cap) {
  if (!path || !path[0] || !out_hex || cap < 17u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  uint64_t h = 14695981039346656037ULL;
  unsigned char buf[8192];
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (n == 0u) {
      break;
    }
    for (size_t i = 0; i < n; i++) {
      h ^= (uint64_t)buf[i];
      h *= 1099511628211ULL;
    }
  }
  fclose(f);
  snprintf(out_hex, cap, "%016llx", (unsigned long long)h);
  return 0;
}

static void path_join(char *out, size_t cap, const char *a, const char *b) {
  if (!out || cap == 0u) {
    return;
  }
  if (!a || !a[0]) {
    snprintf(out, cap, "%s", b ? b : "");
    return;
  }
  if (!b || !b[0]) {
    snprintf(out, cap, "%s", a);
    return;
  }
  size_t n = strlen(a);
  int has_sep = (n > 0 && (a[n - 1] == '/' || a[n - 1] == '\\'));
  if (has_sep) {
    snprintf(out, cap, "%s%s", a, b);
  } else {
    snprintf(out, cap, "%s%c%s", a, SEP, b);
  }
}

static void normalize_sep(char *s) {
  if (!s) {
    return;
  }
  for (; *s; s++) {
#ifdef _WIN32
    if (*s == '/') {
      *s = '\\';
    }
#else
    if (*s == '\\') {
      *s = '/';
    }
#endif
  }
}

static int ensure_dir(const char *dir) {
  if (!dir || !dir[0]) {
    return 0;
  }
  char tmp[1024];
  snprintf(tmp, sizeof(tmp), "%s", dir);
  normalize_sep(tmp);
  size_t n = strlen(tmp);
  for (size_t i = 1; i < n; i++) {
    if (tmp[i] == '/' || tmp[i] == '\\') {
      char saved = tmp[i];
      tmp[i] = '\0';
      (void)MKDIR(tmp);
      tmp[i] = saved;
    }
  }
  (void)MKDIR(tmp);
  return 1;
}

static const char *basename_c(const char *path) {
  const char *p = path ? path : "";
  for (const char *c = p; *c; c++) {
    if (*c == '/' || *c == '\\') {
      p = c + 1;
    }
  }
  return p;
}

static int copy_file(const char *src, const char *dst) {
  FILE *in = fopen(src, "rb");
  if (!in) {
    return 0;
  }
  FILE *out = fopen(dst, "wb");
  if (!out) {
    fclose(in);
    return 0;
  }
  unsigned char buf[8192];
  int ok = 1;
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), in);
    if (n == 0u) {
      break;
    }
    if (fwrite(buf, 1, n, out) != n) {
      ok = 0;
      break;
    }
  }
  fclose(out);
  fclose(in);
  return ok;
}

int edr_webshell_stage_file(const char *src_path, const char *forensic_root, const char *tenant_id, const char *alert_id,
                            char *out_object_key, size_t out_object_key_cap, char *out_local_path,
                            size_t out_local_path_cap) {
  if (!src_path || !src_path[0] || !forensic_root || !forensic_root[0] || !tenant_id || !tenant_id[0] || !alert_id ||
      !alert_id[0]) {
    return 0;
  }
  time_t t = time(NULL);
  struct tm tmv;
#ifdef _WIN32
  localtime_s(&tmv, &t);
#else
  localtime_r(&t, &tmv);
#endif
  char date[16];
  snprintf(date, sizeof(date), "%04d-%02d-%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
  const char *fn = basename_c(src_path);
  if (!fn[0]) {
    fn = "sample.bin";
  }
  char object_key[512];
  snprintf(object_key, sizeof(object_key), "webshell/%s/%s/%s/%s", tenant_id, date, alert_id, fn);
  char local_path[1024];
  path_join(local_path, sizeof(local_path), forensic_root, object_key);
  normalize_sep(local_path);

  char dir_path[1024];
  snprintf(dir_path, sizeof(dir_path), "%s", local_path);
  char *slash = strrchr(dir_path, '/');
  char *bslash = strrchr(dir_path, '\\');
  char *cut = slash;
  if (!cut || (bslash && bslash > cut)) {
    cut = bslash;
  }
  if (!cut) {
    return 0;
  }
  *cut = '\0';
  if (!ensure_dir(dir_path)) {
    return 0;
  }
  if (!copy_file(src_path, local_path)) {
    return 0;
  }
  if (out_object_key && out_object_key_cap > 0u) {
    snprintf(out_object_key, out_object_key_cap, "%s", object_key);
  }
  if (out_local_path && out_local_path_cap > 0u) {
    snprintf(out_local_path, out_local_path_cap, "%s", local_path);
  }
  return 1;
}
