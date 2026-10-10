#include "edr/command_state.h"
#include "edr/local_evidence_cache.h"
#include "edr/sha256.h"

#include "cJSON.h"

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define EDR_COMMAND_STATE_ESCAPED_DETAIL_CAP (EDR_COMMAND_STATE_DETAIL_CAP * 2u + 2u)
#define EDR_COMMAND_STATE_AUTH_CAP 16384u
#define EDR_COMMAND_STATE_LINE_CAP (EDR_COMMAND_STATE_ESCAPED_DETAIL_CAP + 16384u + EDR_COMMAND_STATE_AUTH_CAP)

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <windows.h>
#include <sddl.h>
#else
#include <dirent.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#endif

typedef struct EdrCommandStateFileInfo {
  long size;
  long mtime;
} EdrCommandStateFileInfo;

static EdrCommandStateQuarantineStats s_quarantine_stats;
static unsigned long s_quarantine_serial;

typedef struct EdrControlAckScanner {
  char dir[1024];
  int pass_started;
  int pass_had_read_error;
  size_t pass_pending_count;
  int64_t pass_earliest_retry_ms;
#ifdef _WIN32
  HANDLE handle;
  WIN32_FIND_DATAA current;
  int current_ready;
#else
  DIR *handle;
#endif
} EdrControlAckScanner;

static EdrControlAckScanner s_ack_scanner;

#ifdef _WIN32
static SRWLOCK s_quarantine_lock = SRWLOCK_INIT;
static SRWLOCK s_ack_scan_lock = SRWLOCK_INIT;
static void quarantine_lock(void) { AcquireSRWLockExclusive(&s_quarantine_lock); }
static void quarantine_unlock(void) { ReleaseSRWLockExclusive(&s_quarantine_lock); }
static void ack_scan_lock(void) { AcquireSRWLockExclusive(&s_ack_scan_lock); }
static void ack_scan_unlock(void) { ReleaseSRWLockExclusive(&s_ack_scan_lock); }
#else
static pthread_mutex_t s_quarantine_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_ack_scan_lock = PTHREAD_MUTEX_INITIALIZER;
static void quarantine_lock(void) { pthread_mutex_lock(&s_quarantine_lock); }
static void quarantine_unlock(void) { pthread_mutex_unlock(&s_quarantine_lock); }
static void ack_scan_lock(void) { pthread_mutex_lock(&s_ack_scan_lock); }
static void ack_scan_unlock(void) { pthread_mutex_unlock(&s_ack_scan_lock); }
#endif

static EdrCommandStateFileInfo s_collect_cache_info;
static int s_collect_cache_pending_zero;
static int64_t s_last_compact_check_ms;
static long s_compact_retained_floor;
static char s_compact_retained_path[1024];

static long state_env_long_clamped(const char *name, long defv, long minv, long maxv);
static void state_ensure_dir(const char *path);
static int state_prepare_dir(const char *path);
static int state_prepare_parent_dir(const char *path);
#ifndef _WIN32
static int state_file_secure_existing_path(const char *path, struct stat *out_st);
#endif

static int64_t state_now_ms(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static int64_t command_running_ttl_ms(const EdrSoarCommandMeta *meta) {
  long def_s = 10L * 60L;
  if (meta && meta->deadline_ms > 0u) {
    long deadline_s = (long)((meta->deadline_ms + 999u) / 1000u);
    if (deadline_s > def_s) {
      def_s = deadline_s;
    }
  }
  long ttl_s = state_env_long_clamped("EDR_COMMAND_RUNNING_DUP_TTL_S", def_s, 30L, 24L * 60L * 60L);
  return (int64_t)ttl_s * 1000LL;
}

#ifdef _WIN32
static void state_ensure_parent_dir(const char *path);

static int state_windows_validate_existing(const char *path, int want_dir) {
  if (!path || !path[0]) {
    return -1;
  }
  DWORD attributes = GetFileAttributesA(path);
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    DWORD error=GetLastError();
    errno=(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND) ? ENOENT : EACCES;
    return -1;
  }
  if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u ||
      ((((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0u) ? 1 : 0) != want_dir)) {
    errno=EACCES;return -1;
  }
  return 0;
}

static int state_windows_secure_existing(const char *path, int want_dir) {
  if (state_windows_validate_existing(path, want_dir) != 0) {
    return -1;
  }
  PSECURITY_DESCRIPTOR descriptor = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
          "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", SDDL_REVISION_1,
          &descriptor, NULL)) {
    return -1;
  }
  BOOL ok = SetFileSecurityA(path,
                             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                             descriptor);
  LocalFree(descriptor);
  return ok ? 0 : -1;
}
#endif

static long state_env_long_clamped(const char *name, long defv, long minv, long maxv) {
  const char *e = getenv(name);
  long v = defv;
  if (e && e[0]) {
    char *end = NULL;
    long parsed = strtol(e, &end, 10);
    if (end != e && parsed > 0) {
      v = parsed;
    }
  }
  if (v < minv) {
    v = minv;
  }
  if (v > maxv) {
    v = maxv;
  }
  return v;
}

static int state_file_info(const char *path, EdrCommandStateFileInfo *out) {
  if (out) {
    memset(out, 0, sizeof(*out));
  }
  if (!path || !path[0] || !out) {
    return -1;
  }
  struct stat st;
#ifdef _WIN32
  if (stat(path, &st) != 0) {
    return -1;
  }
#else
  if (state_file_secure_existing_path(path, &st) != 0 || stat(path, &st) != 0) {
    return -1;
  }
#endif
  out->size = (long)st.st_size;
  out->mtime = (long)st.st_mtime;
  return 0;
}

static int state_file_info_same(EdrCommandStateFileInfo a, EdrCommandStateFileInfo b) {
  return a.size == b.size && a.mtime == b.mtime;
}

#ifndef _WIN32
static int state_owner_allowed(uid_t uid) {
  uid_t euid = geteuid();
  return uid == euid || uid == 0;
}

static int state_dir_secure_existing(const char *path) {
  struct stat st;
  if (!path || !path[0] || lstat(path, &st) != 0) {
    return -1;
  }
  if (!S_ISDIR(st.st_mode) || !state_owner_allowed(st.st_uid)) {
    return -1;
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    return -1;
  }
  return 0;
}

static int state_dir_private_existing(const char *path) {
  struct stat st;
  if (state_dir_secure_existing(path) != 0 || lstat(path, &st) != 0) {
    return -1;
  }
  if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    if (!state_owner_allowed(st.st_uid) || chmod(path, 0700) != 0 ||
        lstat(path, &st) != 0) {
      return -1;
    }
  }
  return (st.st_mode & (S_IRWXG | S_IRWXO)) == 0 ? 0 : -1;
}

static int state_file_secure_fd(int fd, struct stat *out_st) {
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0) {
    return -1;
  }
  if (!S_ISREG(st.st_mode) || !state_owner_allowed(st.st_uid)) {
    return -1;
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    return -1;
  }
  if (out_st) {
    *out_st = st;
  }
  return 0;
}

static int state_file_secure_existing_path(const char *path, struct stat *out_st) {
  struct stat st;
  if (!path || !path[0]) {
    return -1;
  }
  if (lstat(path, &st) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  if (!S_ISREG(st.st_mode) || !state_owner_allowed(st.st_uid)) {
    return -1;
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    return -1;
  }
  if (out_st) {
    *out_st = st;
  }
  return 0;
}

static FILE *state_fdopen_checked(int fd, const char *mode) {
  FILE *f = fdopen(fd, mode);
  if (!f) {
    close(fd);
  }
  return f;
}

static FILE *state_open_read_secure(const char *path, struct stat *out_st) {
  if (!path || !path[0]) {
    return NULL;
  }
  int flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(path, flags);
  if (fd < 0) {
    return NULL;
  }
  if (state_file_secure_fd(fd, out_st) != 0) {
    close(fd);
    return NULL;
  }
  return state_fdopen_checked(fd, "rb");
}

static FILE *state_open_append_secure(const char *path) {
  if (state_prepare_parent_dir(path) != 0 ||
      state_file_secure_existing_path(path, NULL) != 0) {
    return NULL;
  }
  int flags = O_WRONLY | O_CREAT | O_APPEND;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0) {
    return NULL;
  }
  (void)fchmod(fd, 0600);
  if (state_file_secure_fd(fd, NULL) != 0) {
    close(fd);
    return NULL;
  }
  return state_fdopen_checked(fd, "ab");
}

static FILE *state_open_lock_secure(const char *path) {
  if (state_prepare_parent_dir(path) != 0 ||
      state_file_secure_existing_path(path, NULL) != 0) {
    return NULL;
  }
  int flags = O_RDWR | O_CREAT;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0) {
    return NULL;
  }
  (void)fchmod(fd, 0600);
  if (state_file_secure_fd(fd, NULL) != 0) {
    close(fd);
    return NULL;
  }
  return state_fdopen_checked(fd, "a+b");
}

static FILE *state_open_new_secure(const char *path) {
  if (state_prepare_parent_dir(path) != 0) {
    return NULL;
  }
  int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0) {
    return NULL;
  }
  if (state_file_secure_fd(fd, NULL) != 0) {
    close(fd);
    return NULL;
  }
  return state_fdopen_checked(fd, "wb");
}
#else
static FILE *state_open_read_secure(const char *path, struct stat *out_st) {
  if (state_windows_secure_existing(path, 0) != 0) {
    return NULL;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  if (out_st && fstat(_fileno(f), out_st) != 0) {
    fclose(f);
    return NULL;
  }
  return f;
}

static FILE *state_open_append_secure(const char *path) {
  state_ensure_parent_dir(path);
  FILE *f = fopen(path, "ab");
  if (!f || state_windows_secure_existing(path, 0) != 0) {
    if (f) {
      fclose(f);
    }
    return NULL;
  }
  return f;
}

static FILE *state_open_lock_secure(const char *path) {
  state_ensure_parent_dir(path);
  FILE *f = fopen(path, "a+b");
  if (!f || state_windows_secure_existing(path, 0) != 0) {
    if (f) {
      fclose(f);
    }
    return NULL;
  }
  return f;
}

static FILE *state_open_new_secure(const char *path) {
  state_ensure_parent_dir(path);
  if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
    return NULL;
  }
  FILE *f = fopen(path, "wb");
  if (!f || state_windows_secure_existing(path, 0) != 0) {
    if (f) {
      fclose(f);
    }
    (void)DeleteFileA(path);
    return NULL;
  }
  return f;
}
#endif

static void state_boot_id(char *out, size_t cap) {
  static char s_boot_id[64];
  if (!out || cap == 0u) {
    return;
  }
  if (!s_boot_id[0]) {
#ifdef _WIN32
    unsigned long pid = (unsigned long)_getpid();
#else
    unsigned long pid = (unsigned long)getpid();
#endif
    snprintf(s_boot_id, sizeof(s_boot_id), "%lld-%lu",
             (long long)state_now_ms(), pid);
  }
  snprintf(out, cap, "%s", s_boot_id);
}

static int state_replace_file(const char *tmp_path, const char *dst_path) {
  if (!tmp_path || !tmp_path[0] || !dst_path || !dst_path[0]) {
    return -1;
  }
#ifdef _WIN32
  if (MoveFileExA(tmp_path, dst_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return state_windows_secure_existing(dst_path, 0);
  }
  (void)DeleteFileA(tmp_path);
  return -1;
#else
  if (rename(tmp_path, dst_path) == 0) {
    return 0;
  }
  (void)remove(tmp_path);
  return -1;
#endif
}

static void state_default_path(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_STATE_DB");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
  const char *dir = getenv("EDR_COMMAND_STATE_DIR");
  if (dir && dir[0]) {
#ifdef _WIN32
    snprintf(out, cap, "%s\\command_state.jsonl", dir);
#else
    snprintf(out, cap, "%s/command_state.jsonl", dir);
#endif
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\state\\command_state.jsonl");
#elif defined(__APPLE__)
  snprintf(out, cap, "%s", "/Library/Application Support/FDSecurity/state/command_state.jsonl");
#else
  snprintf(out, cap, "%s", "/var/lib/fdsecurity/edr/state/command_state.jsonl");
#endif
}

static FILE *state_lock_acquire(void) {
  char path[1024], lock_path[1100];
  state_default_path(path, sizeof(path));
  if (state_prepare_parent_dir(path) != 0) {
    return NULL;
  }
  snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  FILE *f = state_open_lock_secure(lock_path);
  if (!f) {
    return NULL;
  }
#ifdef _WIN32
  HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov)) {
    fclose(f);
    return NULL;
  }
#else
  if (flock(fileno(f), LOCK_EX) != 0) {
    fclose(f);
    return NULL;
  }
#endif
  return f;
}

static void state_lock_release(FILE *f) {
  if (!f) {
    return;
  }
#ifdef _WIN32
  HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  (void)UnlockFileEx(h, 0, 1, 0, &ov);
#else
  (void)flock(fileno(f), LOCK_UN);
#endif
  fclose(f);
}

static int state_mkdir_one(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
    return state_windows_validate_existing(path, 1);
  }
#else
  if (mkdir(path, 0700) == 0) {
    return 0;
  }
  if (errno == EEXIST && state_dir_secure_existing(path) == 0) {
    return 0;
  }
#endif
  return -1;
}

static int state_parent_dir(const char *path, char *out, size_t cap) {
  char tmp[1024];
  if (!out || cap == 0u) {
    return -1;
  }
  out[0] = '\0';
  if (!path || strlen(path) >= sizeof(tmp)) {
    return -1;
  }
  snprintf(tmp, sizeof(tmp), "%s", path);
  char *last = NULL;
  for (char *p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\') {
      last = p;
    }
  }
  if (!last) {
    snprintf(out, cap, "%s", ".");
    return 0;
  }
  *last = '\0';
  if (!tmp[0]) {
    snprintf(out, cap, "%s", "/");
    return 0;
  }
  snprintf(out, cap, "%s", tmp);
  return 0;
}

#ifdef _WIN32
static void state_ensure_parent_dir(const char *path) {
  char tmp[1024];
  if (state_parent_dir(path, tmp, sizeof(tmp)) != 0 || strcmp(tmp, ".") == 0 || strcmp(tmp, "/") == 0) {
    return;
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char saved = *p;
      *p = '\0';
#ifdef _WIN32
      if (!(strlen(tmp) == 2u && tmp[1] == ':')) {
        (void)state_mkdir_one(tmp);
      }
#else
      (void)state_mkdir_one(tmp);
#endif
      *p = saved;
    }
  }
  (void)state_mkdir_one(tmp);
}
#endif

static void state_ensure_dir(const char *path) {
  char tmp[1024];
  if (!path || !path[0] || strlen(path) >= sizeof(tmp)) {
    return;
  }
  snprintf(tmp, sizeof(tmp), "%s", path);
  size_t len = strlen(tmp);
  while (len > 1u && (tmp[len - 1u] == '/' || tmp[len - 1u] == '\\')) {
    tmp[--len] = '\0';
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char saved = *p;
      *p = '\0';
#ifdef _WIN32
      if (!(strlen(tmp) == 2u && tmp[1] == ':')) {
        (void)state_mkdir_one(tmp);
      }
#else
      (void)state_mkdir_one(tmp);
#endif
      *p = saved;
    }
  }
  (void)state_mkdir_one(tmp);
}

static int state_prepare_parent_dir(const char *path) {
  char dir[1024];
  if (state_parent_dir(path, dir, sizeof(dir)) != 0) {
    return -1;
  }
  if (strcmp(dir, ".") != 0 && strcmp(dir, "/") != 0) {
    state_ensure_dir(dir);
  } else {
    return 0;
  }
#ifdef _WIN32
  return state_windows_secure_existing(dir, 1);
#else
  return state_dir_private_existing(dir);
#endif
}

static int state_prepare_dir(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  state_ensure_dir(path);
#ifdef _WIN32
  return state_windows_secure_existing(path, 1);
#else
  return state_dir_private_existing(path);
#endif
}

static void json_escape_to(char *dst, size_t cap, const char *s) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t o = 0;
  dst[o++] = '"';
  if (!s) {
    s = "";
  }
  for (; *s && o + 2u < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      dst[o++] = '\\';
      dst[o++] = (char)c;
    } else if (c == '\n' || c == '\r' || c == '\t' || c < 0x20u) {
      dst[o++] = ' ';
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

static void parse_json_string_field_line(const char *line, const char *key, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!line || !key) {
    return;
  }
  cJSON *root = cJSON_Parse(line);
  if (!root) {
    return;
  }
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  if (cJSON_IsString(value) && value->valuestring) {
    snprintf(out, cap, "%s", value->valuestring);
  }
  cJSON_Delete(root);
}

static int parse_json_int_field_line(const char *line, const char *key, int defv) {
  if (!line || !key) {
    return defv;
  }
  cJSON *root = cJSON_Parse(line);
  if (!root) {
    return defv;
  }
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  int out = cJSON_IsNumber(value) ? value->valueint : defv;
  cJSON_Delete(root);
  return out;
}

static int64_t parse_json_int64_field_line(const char *line, const char *key, int64_t defv) {
  if (!line || !key) {
    return defv;
  }
  cJSON *root = cJSON_Parse(line);
  if (!root) {
    return defv;
  }
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  int64_t out = cJSON_IsNumber(value) ? (int64_t)value->valuedouble : defv;
  cJSON_Delete(root);
  return out;
}

static char *parse_json_string_field_alloc(const char *line, const char *key) {
  if (!line || !key) {
    return NULL;
  }
  cJSON *root = cJSON_Parse(line);
  if (!root) {
    return NULL;
  }
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
  char *out = NULL;
  if (cJSON_IsString(value) && value->valuestring) {
    size_t n = strlen(value->valuestring);
    out = (char *)malloc(n + 1u);
    if (out) {
      memcpy(out, value->valuestring, n + 1u);
    }
  }
  cJSON_Delete(root);
  return out;
}

static int state_flush_file(FILE *f) {
  if (!f) {
    return -1;
  }
  if (fflush(f) != 0) {
    return -1;
  }
#ifdef _WIN32
  return _commit(_fileno(f));
#else
  return fsync(fileno(f));
#endif
}

static char *hex_encode_alloc(const uint8_t *data, size_t len) {
  static const char h[] = "0123456789abcdef";
  if (len > ((size_t)-1 - 1u) / 2u) {
    return NULL;
  }
  char *out = (char *)malloc(len * 2u + 1u);
  if (!out) {
    return NULL;
  }
  for (size_t i = 0; i < len; i++) {
    unsigned char c = data ? data[i] : 0u;
    out[i * 2u] = h[(c >> 4) & 0x0f];
    out[i * 2u + 1u] = h[c & 0x0f];
  }
  out[len * 2u] = '\0';
  return out;
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int hex_decode_alloc(const char *hex, uint8_t **out, size_t *out_len) {
  if (out) {
    *out = NULL;
  }
  if (out_len) {
    *out_len = 0u;
  }
  if (!hex || !out || !out_len) {
    return -1;
  }
  size_t n = strlen(hex);
  if ((n % 2u) != 0u) {
    return -1;
  }
  size_t len = n / 2u;
  uint8_t *buf = len ? (uint8_t *)malloc(len) : NULL;
  if (len && !buf) {
    return -1;
  }
  for (size_t i = 0; i < len; i++) {
    int hi = hex_value((unsigned char)hex[i * 2u]);
    int lo = hex_value((unsigned char)hex[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return -1;
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out = buf;
  *out_len = len;
  return 0;
}

static int line_matches_key(const char *line, const char *key, const char *value) {
  if (!line || !key || !value || !value[0]) {
    return 0;
  }
  char esc[256];
  char pat[360];
  json_escape_to(esc, sizeof(esc), value);
  snprintf(pat, sizeof(pat), "\"%s\":%s", key, esc);
  return strstr(line, pat) != NULL;
}

static void state_idempotency_key(const EdrSoarCommandMeta *meta, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!meta || !meta->idempotency_key[0]) {
    return;
  }
  const char *raw = meta->idempotency_key;
  const char *sig = strstr(raw, "|sigv1|");
  const char *sig2 = strstr(raw, "|sigv2|");
  if (!sig || (sig2 && sig2 < sig)) {
    sig = sig2;
  }
  size_t n = sig ? (size_t)(sig - raw) : strlen(raw);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, raw, n);
  out[n] = '\0';
}

#include "command_result_contract.inc"

/* Kept inside the existing inbox/result records: no separate grant store. */
static int authorization_json(const EdrCommandResultAuthorization *auth, char *out, size_t cap) {
  EdrCommandResultAuthorization empty = {0};
  if (!auth) auth = &empty;
  cJSON *root = cJSON_CreateObject();
  if (!root) return -1;
  int ok = cJSON_AddStringToObject(root, "command_id", auth->command_id) &&
      cJSON_AddStringToObject(root, "command_type", auth->command_type) &&
      cJSON_AddStringToObject(root, "tenant_id", auth->tenant_id) &&
      cJSON_AddStringToObject(root, "endpoint_id", auth->endpoint_id) &&
      cJSON_AddNumberToObject(root, "expires_unix_ms", (double)auth->expires_unix_ms) &&
      (!auth->content_contract[0] || cJSON_AddItemToObject(root, "content_contract", cJSON_Parse(auth->content_contract))) &&
      cJSON_PrintPreallocated(root, out, (int)cap, 0);
  cJSON_Delete(root);
  return ok ? 0 : -1;
}

static void authorization_from_line(const char *line, EdrCommandResultAuthorization *auth) {
  memset(auth, 0, sizeof(*auth));
  cJSON *root = cJSON_Parse(line);
  const cJSON *a = cJSON_GetObjectItemCaseSensitive(root, "result_authorization");
  const char *names[] = {"command_id", "command_type", "tenant_id", "endpoint_id"};
  char *dest[] = {auth->command_id, auth->command_type, auth->tenant_id, auth->endpoint_id};
  size_t caps[] = {sizeof(auth->command_id), sizeof(auth->command_type),
                   sizeof(auth->tenant_id), sizeof(auth->endpoint_id)};
  int valid = cJSON_IsObject(a);
  for (size_t i = 0; valid && i < 4u; ++i) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(a, names[i]);
    valid = cJSON_IsString(v) && v->valuestring && strlen(v->valuestring) < caps[i];
    if (valid) memcpy(dest[i], v->valuestring, strlen(v->valuestring) + 1u);
  }
  const cJSON *expires = cJSON_GetObjectItemCaseSensitive(a, "expires_unix_ms");
  if (valid && cJSON_IsNumber(expires) && expires->valuedouble > 0 &&
      expires->valuedouble < 9007199254740992.0 &&
      expires->valuedouble == (double)(int64_t)expires->valuedouble) {
    auth->expires_unix_ms = (int64_t)expires->valuedouble;
  } else memset(auth, 0, sizeof(*auth));
  const cJSON *contract = cJSON_GetObjectItemCaseSensitive(a, "content_contract");
  if (auth->expires_unix_ms && cJSON_IsObject(contract) &&
      !cJSON_PrintPreallocated((cJSON *)contract, auth->content_contract, sizeof(auth->content_contract), 0))
    memset(auth, 0, sizeof(*auth));
  cJSON_Delete(root);
}

static void fill_record_from_line(const char *line, EdrCommandStateRecord *out) {
  if (!out) {
    return;
  }
  memset(out, 0, sizeof(*out));
  parse_json_string_field_line(line, "command_id", out->command_id, sizeof(out->command_id));
  parse_json_string_field_line(line, "command_type", out->command_type, sizeof(out->command_type));
  parse_json_string_field_line(line, "idempotency_key", out->idempotency_key, sizeof(out->idempotency_key));
  parse_json_string_field_line(line, "response_status", out->response_status, sizeof(out->response_status));
  parse_json_string_field_line(line, "soar_correlation_id", out->soar_correlation_id, sizeof(out->soar_correlation_id));
  parse_json_string_field_line(line, "playbook_run_id", out->playbook_run_id, sizeof(out->playbook_run_id));
  parse_json_string_field_line(line, "playbook_step_id", out->playbook_step_id, sizeof(out->playbook_step_id));
  parse_json_string_field_line(line, "artifacts", out->artifacts, sizeof(out->artifacts));
  parse_json_string_field_line(line, "detail", out->detail, sizeof(out->detail));
  parse_json_string_field_line(line, "agent_boot_id", out->agent_boot_id, sizeof(out->agent_boot_id));
  parse_json_string_field_line(line, "report_last_error", out->report_last_error,
                               sizeof(out->report_last_error));
  authorization_from_line(line, &out->result_authorization);
  out->execution_status = parse_json_int_field_line(line, "execution_status", 0);
  out->exit_code = parse_json_int_field_line(line, "exit_code", 0);
  out->retry_count = parse_json_int_field_line(line, "retry_count", 0);
  out->final_record = parse_json_int_field_line(line, "final", 0);
  out->report_pending = parse_json_int_field_line(line, "report_pending", 0);
  out->report_policy_held = parse_json_int_field_line(line,"report_policy_held",0);
  parse_json_string_field_line(line,"report_policy_version",out->report_policy_version,sizeof(out->report_policy_version));
  out->report_attempts = (uint32_t)parse_json_int_field_line(line, "report_attempts", 0);
  out->process_id = parse_json_int_field_line(line, "process_id", 0);
  out->updated_unix_ms = parse_json_int64_field_line(line, "updated_unix_ms", 0);
  out->report_last_failure_unix_ms =
      parse_json_int64_field_line(line, "report_last_failure_unix_ms", 0);
  out->report_next_retry_unix_ms =
      parse_json_int64_field_line(line, "report_next_retry_unix_ms", 0);
}

static void command_inbox_default_dir(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_INBOX_DIR");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
  const char *dir = getenv("EDR_COMMAND_STATE_DIR");
  if (dir && dir[0]) {
#ifdef _WIN32
    snprintf(out, cap, "%s\\command_inbox", dir);
#else
    snprintf(out, cap, "%s/command_inbox", dir);
#endif
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\state\\command_inbox");
#elif defined(__APPLE__)
  snprintf(out, cap, "%s", "/Library/Application Support/FDSecurity/state/command_inbox");
#else
  snprintf(out, cap, "%s", "/var/lib/fdsecurity/edr/state/command_inbox");
#endif
}

static void command_inbox_safe_name(const char *command_id, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  size_t o = 0;
  const char *id = command_id && command_id[0] ? command_id : "missing_command_id";
  for (; *id && o + 1u < cap; id++) {
    unsigned char c = (unsigned char)*id;
    if (isalnum(c) || c == '_' || c == '-' || c == '.') {
      out[o++] = (char)c;
    } else {
      out[o++] = '_';
    }
  }
  out[o] = '\0';
}

static int command_inbox_record_path(const char *command_id, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  char dir[1024];
  char safe[128];
  command_inbox_default_dir(dir, sizeof(dir));
  command_inbox_safe_name(command_id, safe, sizeof(safe));
  char sep = '/';
#ifdef _WIN32
  sep = '\\';
#endif
  size_t len = strlen(dir);
  if (len > 0u && (dir[len - 1u] == '/' || dir[len - 1u] == '\\')) {
    snprintf(out, cap, "%s%s.json", dir, safe);
  } else {
    snprintf(out, cap, "%s%c%s.json", dir, sep, safe);
  }
  return out[0] ? 0 : -1;
}

static void control_ack_default_dir(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_ACK_DIR");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
  const char *dir = getenv("EDR_COMMAND_STATE_DIR");
  if (dir && dir[0]) {
#ifdef _WIN32
    snprintf(out, cap, "%s\\command_ack", dir);
#else
    snprintf(out, cap, "%s/command_ack", dir);
#endif
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\state\\command_ack");
#elif defined(__APPLE__)
  snprintf(out, cap, "%s", "/Library/Application Support/FDSecurity/state/command_ack");
#else
  snprintf(out, cap, "%s", "/var/lib/fdsecurity/edr/state/command_ack");
#endif
}

static int control_ack_record_path(const char *command_id, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return -1;
  }
  char dir[1024];
  char safe[128];
  control_ack_default_dir(dir, sizeof(dir));
  command_inbox_safe_name(command_id, safe, sizeof(safe));
  char sep = '/';
#ifdef _WIN32
  sep = '\\';
#endif
  size_t len = strlen(dir);
  if (len > 0u && (dir[len - 1u] == '/' || dir[len - 1u] == '\\')) {
    snprintf(out, cap, "%s%s.json", dir, safe);
  } else {
    snprintf(out, cap, "%s%c%s.json", dir, sep, safe);
  }
  return out[0] ? 0 : -1;
}

int edr_command_state_has_final(const char *command_id,const EdrSoarCommandMeta *meta) {
  char path[1024];state_default_path(path,sizeof(path));
  FILE *lock=state_lock_acquire();if(!lock)return -1;
  errno=0;FILE *f=state_open_read_secure(path,NULL);
  if(!f){int rc=errno==ENOENT ? 0 : -1;state_lock_release(lock);return rc;}
  char idem_key[128];state_idempotency_key(meta,idem_key,sizeof(idem_key));
  char *line=malloc(EDR_COMMAND_STATE_LINE_CAP);int found=line ? 0 : -1;
  while(line && fgets(line,EDR_COMMAND_STATE_LINE_CAP,f)) {
    if(!strchr(line,'\n')){found=-1;break;}
    if(!strstr(line,"\"final\":1"))continue;
    if((command_id && command_id[0] && line_matches_key(line,"command_id",command_id)) ||
        (idem_key[0] && line_matches_key(line,"idempotency_key",idem_key)))found=1;
  }
  if(ferror(f))found=-1;fclose(f);free(line);state_lock_release(lock);return found;
}

static int command_inbox_delete_path(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  return DeleteFileA(path) ? 0 : -1;
#else
  return remove(path);
#endif
}

static void state_quarantine_audit(const char *kind, const char *path, const char *reason, int moved) {
  fprintf(stderr, "[command][quarantine] kind=%s moved=%d path=%s reason=%s\n",
          kind ? kind : "unknown", moved, path ? path : "", reason ? reason : "unknown");
  const char *audit_path = getenv("EDR_CMD_AUDIT_PATH");
  if (!audit_path || !audit_path[0]) {
    return;
  }
  FILE *f = fopen(audit_path, "a");
  if (!f) {
    return;
  }
  fprintf(f, "%lld command_state_quarantine kind=%s moved=%d path=%s reason=%s\n",
          (long long)state_now_ms(), kind ? kind : "unknown", moved,
          path ? path : "", reason ? reason : "unknown");
  fclose(f);
}

static void state_quarantine_note(const char *kind, const char *reason, int moved) {
  quarantine_lock();
  s_quarantine_stats.last_quarantine_unix_ms = state_now_ms();
  snprintf(s_quarantine_stats.last_record_kind, sizeof(s_quarantine_stats.last_record_kind), "%s",
           kind ? kind : "unknown");
  snprintf(s_quarantine_stats.last_reason, sizeof(s_quarantine_stats.last_reason), "%s",
           reason ? reason : "unknown");
  if (!moved) {
    s_quarantine_stats.move_failure_count++;
  } else if (kind && strcmp(kind, "control_ack") == 0) {
    s_quarantine_stats.ack_record_count++;
  } else {
    s_quarantine_stats.inbox_record_count++;
  }
  quarantine_unlock();
}

static int state_move_to_quarantine(const char *dir, const char *path, const char *kind,
                                    const char *reason) {
  if (!dir || !dir[0] || !path || !path[0]) {
    return -1;
  }
  char qdir[1200];
  char base[256];
  char safe[256];
  char dst[1500];
  const char *name = strrchr(path, '/');
  const char *win_name = strrchr(path, '\\');
  if (!name || (win_name && win_name > name)) {
    name = win_name;
  }
  name = name ? name + 1 : path;
  snprintf(base, sizeof(base), "%s", name);
  command_inbox_safe_name(base, safe, sizeof(safe));
#ifdef _WIN32
  snprintf(qdir, sizeof(qdir), "%s\\quarantine", dir);
#else
  snprintf(qdir, sizeof(qdir), "%s/quarantine", dir);
#endif
  if (state_prepare_dir(qdir) != 0) {
    state_quarantine_note(kind, reason, 0);
    state_quarantine_audit(kind, path, reason, 0);
    return -1;
  }
  quarantine_lock();
  unsigned long serial = ++s_quarantine_serial;
  quarantine_unlock();
#ifdef _WIN32
  snprintf(dst, sizeof(dst), "%s\\%s.bad.%lld.%lu.json", qdir, safe,
           (long long)state_now_ms(), serial);
  int moved = MoveFileExA(path, dst, MOVEFILE_WRITE_THROUGH) ? 1 : 0;
#else
  snprintf(dst, sizeof(dst), "%s/%s.bad.%lld.%lu.json", qdir, safe,
           (long long)state_now_ms(), serial);
  int moved = rename(path, dst) == 0 ? 1 : 0;
#endif
  state_quarantine_note(kind, reason, moved);
  state_quarantine_audit(kind, path, reason, moved);
  return moved ? 0 : -1;
}

void edr_command_state_get_quarantine_stats(EdrCommandStateQuarantineStats *out_stats) {
  if (out_stats) {
    quarantine_lock();
    *out_stats = s_quarantine_stats;
    quarantine_unlock();
  }
}

static int control_ack_read_file(const char *path, EdrControlAckRecord *out) {
  if (!path || !out) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  struct stat st;
  FILE *f = state_open_read_secure(path, &st);
  if (!f || st.st_size < 0) {
    if (f) {
      fclose(f);
    }
    return -1;
  }
  long max_bytes = state_env_long_clamped("EDR_COMMAND_ACK_MAX_BYTES", 32L * 1024L,
                                          512L, 1024L * 1024L);
  if (st.st_size > max_bytes) {
    fclose(f);
    return 1;
  }
  size_t n = (size_t)st.st_size;
  char *buf = (char *)malloc(n + 1u);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t got = fread(buf, 1, n, f);
  fclose(f);
  buf[got] = '\0';
  if (got != n) {
    free(buf);
    return 1;
  }
  char record[32];
  parse_json_string_field_line(buf, "record", record, sizeof(record));
  parse_json_string_field_line(buf, "command_id", out->command_id, sizeof(out->command_id));
  parse_json_string_field_line(buf, "transport", out->transport, sizeof(out->transport));
  out->last_seq = parse_json_int64_field_line(buf, "last_seq", 0);
  int64_t attempts = parse_json_int64_field_line(buf, "attempts", 0);
  out->first_failure_unix_ms = parse_json_int64_field_line(buf, "first_failure_unix_ms", 0);
  out->last_failure_unix_ms = parse_json_int64_field_line(buf, "last_failure_unix_ms", 0);
  out->next_retry_unix_ms = parse_json_int64_field_line(buf, "next_retry_unix_ms", 0);
  free(buf);
  if (strcmp(record, "control_ack") != 0 || !out->command_id[0] || !out->transport[0] || attempts < 1 ||
      attempts > 10000000LL || out->next_retry_unix_ms <= 0) {
    return 1;
  }
  out->attempts = (uint32_t)attempts;
  return 0;
}

static int control_ack_name_is_record(const char *name) {
  if (!name || name[0] == '.') {
    return 0;
  }
  size_t n = strlen(name);
  return n > 5u && strcmp(name + n - 5u, ".json") == 0;
}

static void control_ack_scanner_close_locked(void) {
#ifdef _WIN32
  if (s_ack_scanner.handle && s_ack_scanner.handle != INVALID_HANDLE_VALUE) {
    FindClose(s_ack_scanner.handle);
  }
  s_ack_scanner.handle = NULL;
  s_ack_scanner.current_ready = 0;
#else
  if (s_ack_scanner.handle) {
    closedir(s_ack_scanner.handle);
  }
  s_ack_scanner.handle = NULL;
#endif
  s_ack_scanner.pass_started = 0;
}

static int control_ack_scanner_begin_locked(const char *dir) {
  control_ack_scanner_close_locked();
  snprintf(s_ack_scanner.dir, sizeof(s_ack_scanner.dir), "%s", dir ? dir : "");
  s_ack_scanner.pass_pending_count = 0u;
  s_ack_scanner.pass_earliest_retry_ms = 0;
  s_ack_scanner.pass_had_read_error = 0;
  s_ack_scanner.pass_started = 1;
#ifdef _WIN32
  {
    char pattern[1100];
    snprintf(pattern, sizeof(pattern), "%s\\*", s_ack_scanner.dir);
    s_ack_scanner.handle = FindFirstFileA(pattern, &s_ack_scanner.current);
    if (s_ack_scanner.handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      s_ack_scanner.handle = NULL;
      return error == ERROR_FILE_NOT_FOUND ? 0 : -1;
    }
    s_ack_scanner.current_ready = 1;
  }
#else
  s_ack_scanner.handle = opendir(s_ack_scanner.dir);
  if (!s_ack_scanner.handle) {
    return -1;
  }
#endif
  return 1;
}

static int control_ack_scanner_next_locked(char *name, size_t name_cap,
                                           int *out_is_directory) {
  if (!name || name_cap == 0u) {
    return 0;
  }
#ifdef _WIN32
  if (!s_ack_scanner.handle) {
    return 0;
  }
  if (!s_ack_scanner.current_ready) {
    if (!FindNextFileA(s_ack_scanner.handle, &s_ack_scanner.current)) {
      return GetLastError() == ERROR_NO_MORE_FILES ? 0 : -1;
    }
  }
  s_ack_scanner.current_ready = 0;
  snprintf(name, name_cap, "%s", s_ack_scanner.current.cFileName);
  if (out_is_directory) {
    *out_is_directory =
        (s_ack_scanner.current.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  }
#else
  struct dirent *ent;
  if (!s_ack_scanner.handle) {
    return -1;
  }
  errno = 0;
  ent = readdir(s_ack_scanner.handle);
  if (!ent) {
    if (errno != 0) {
      return -1;
    }
    return 0;
  }
  snprintf(name, name_cap, "%s", ent->d_name);
  if (out_is_directory) {
#ifdef DT_DIR
    *out_is_directory = ent->d_type == DT_DIR;
#else
    *out_is_directory = 0;
#endif
  }
#endif
  return 1;
}

int edr_command_state_upsert_pending_ack(const EdrControlAckRecord *record) {
  if (!record || !record->command_id[0]) {
    return -1;
  }
  char dir[1024];
  char path[1200];
  char tmp[1300];
  control_ack_default_dir(dir, sizeof(dir));
  if (control_ack_record_path(record->command_id, path, sizeof(path)) != 0) {
    return -1;
  }
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return -1;
  }
  if (state_prepare_dir(dir) != 0) {
    state_lock_release(lock);
    return -1;
  }
  snprintf(tmp, sizeof(tmp), "%s.tmp.%lld", path, (long long)state_now_ms());
  FILE *f = state_open_new_secure(tmp);
  if (!f) {
    state_lock_release(lock);
    return -1;
  }
  char cid[300], transport[220];
  json_escape_to(cid, sizeof(cid), record->command_id);
  json_escape_to(transport, sizeof(transport), record->transport[0] ? record->transport : "https_control");
  uint32_t attempts = record->attempts ? record->attempts : 1u;
  int64_t now = state_now_ms();
  int64_t first_failure = record->first_failure_unix_ms > 0 ? record->first_failure_unix_ms : now;
  int64_t last_failure = record->last_failure_unix_ms > 0 ? record->last_failure_unix_ms : now;
  int64_t next_retry = record->next_retry_unix_ms > 0 ? record->next_retry_unix_ms : now;
  fprintf(f,
          "{\"record\":\"control_ack\",\"command_id\":%s,\"transport\":%s,"
          "\"last_seq\":%lld,\"attempts\":%u,\"first_failure_unix_ms\":%lld,"
          "\"last_failure_unix_ms\":%lld,\"next_retry_unix_ms\":%lld}\n",
          cid, transport, (long long)record->last_seq, (unsigned)attempts,
          (long long)first_failure, (long long)last_failure, (long long)next_retry);
  int ok = state_flush_file(f) == 0;
  if (fclose(f) != 0) {
    ok = 0;
  }
  if (!ok || state_replace_file(tmp, path) != 0) {
    (void)command_inbox_delete_path(tmp);
    state_lock_release(lock);
    return -1;
  }
  state_lock_release(lock);
  return 0;
}

int edr_command_state_collect_pending_acks(EdrControlAckRecord *out, size_t cap) {
  if (!out || cap == 0u) {
    return 0;
  }
  char dir[1024];
  control_ack_default_dir(dir, sizeof(dir));
  if (state_prepare_dir(dir) != 0) {
    return 0;
  }
  size_t count = 0u;
#ifdef _WIN32
  char pattern[1100];
  snprintf(pattern, sizeof(pattern), "%s\\*.json", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  do {
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        !control_ack_name_is_record(fd.cFileName)) {
      continue;
    }
    char path[1200];
    snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (!control_ack_name_is_record(ent->d_name)) {
      continue;
    }
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
#endif
    EdrControlAckRecord rec;
    int read_rc = control_ack_read_file(path, &rec);
    if (read_rc != 0) {
      if (read_rc > 0) {
        /* A concurrent ACK upsert can atomically replace this path. Re-read
         * under the writer lock before moving it, so a valid replacement is
         * never quarantined based on an earlier malformed snapshot. */
        FILE *lock = state_lock_acquire();
        if (lock) {
          EdrControlAckRecord confirm;
          if (control_ack_read_file(path, &confirm) > 0) {
            (void)state_move_to_quarantine(dir, path, "control_ack", "malformed_control_ack_record");
          }
          state_lock_release(lock);
        }
      }
      continue;
    }
    out[count++] = rec;
    if (count >= cap) {
      break;
    }
#ifdef _WIN32
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  }
  closedir(d);
#endif
  return (int)count;
}

int edr_command_state_collect_due_pending_acks(
    EdrControlAckRecord *out, size_t out_cap, int64_t now_unix_ms,
    size_t scan_budget, EdrControlAckScanStats *out_stats) {
  char dir[1024];
  size_t selected = 0u;
  EdrControlAckScanStats stats;
  memset(&stats, 0, sizeof(stats));
  if (!out || out_cap == 0u || scan_budget == 0u) {
    if (out_stats) {
      *out_stats = stats;
    }
    return 0;
  }
  if (scan_budget > 4096u) {
    scan_budget = 4096u;
  }
  control_ack_default_dir(dir, sizeof(dir));
  ack_scan_lock();
  if (s_ack_scanner.pass_started && strcmp(s_ack_scanner.dir, dir) != 0) {
    control_ack_scanner_close_locked();
  }
  if (state_prepare_dir(dir) != 0) {
    stats.traversal_error = 1;
    goto done;
  }

  if (!s_ack_scanner.pass_started || strcmp(s_ack_scanner.dir, dir) != 0) {
    int begin_rc = control_ack_scanner_begin_locked(dir);
    if (begin_rc <= 0) {
      stats.traversal_complete = begin_rc == 0;
      stats.traversal_error = begin_rc < 0;
      control_ack_scanner_close_locked();
      goto done;
    }
  }
  while (stats.scanned_entry_count < scan_budget && selected < out_cap) {
    char name[512];
    char path[1600];
    int is_directory = 0;
    int next_rc = control_ack_scanner_next_locked(name, sizeof(name), &is_directory);
    if (next_rc <= 0) {
      stats.traversal_complete = next_rc == 0 && !s_ack_scanner.pass_had_read_error;
      stats.traversal_error = next_rc < 0 || s_ack_scanner.pass_had_read_error;
      stats.pending_record_count_observed = s_ack_scanner.pass_pending_count;
      stats.earliest_retry_unix_ms_observed =
          s_ack_scanner.pass_earliest_retry_ms;
      control_ack_scanner_close_locked();
      goto done;
    }
    stats.scanned_entry_count++;
    if (is_directory || !control_ack_name_is_record(name)) {
      continue;
    }
#ifdef _WIN32
    snprintf(path, sizeof(path), "%s\\%s", dir, name);
#else
    snprintf(path, sizeof(path), "%s/%s", dir, name);
#endif
    EdrControlAckRecord rec;
    int read_rc = control_ack_read_file(path, &rec);
    if (read_rc != 0) {
      if (read_rc < 0) {
        s_ack_scanner.pass_had_read_error = 1;
      }
      if (read_rc > 0) {
        /* Match the legacy collector's ownership rule: re-read while holding
         * the writer lock before quarantining a malformed snapshot. */
        FILE *lock = state_lock_acquire();
        if (lock) {
          EdrControlAckRecord confirm;
          int confirm_rc = control_ack_read_file(path, &confirm);
          if (confirm_rc > 0) {
            (void)state_move_to_quarantine(
                dir, path, "control_ack", "malformed_control_ack_record");
          } else if (confirm_rc < 0) {
            s_ack_scanner.pass_had_read_error = 1;
          }
          state_lock_release(lock);
        } else {
          s_ack_scanner.pass_had_read_error = 1;
        }
      }
      continue;
    }
    s_ack_scanner.pass_pending_count++;
    if (s_ack_scanner.pass_earliest_retry_ms == 0 ||
        rec.next_retry_unix_ms < s_ack_scanner.pass_earliest_retry_ms) {
      s_ack_scanner.pass_earliest_retry_ms = rec.next_retry_unix_ms;
    }
    if (rec.next_retry_unix_ms <= now_unix_ms) {
      out[selected++] = rec;
    }
  }
  stats.pending_record_count_observed = s_ack_scanner.pass_pending_count;
  stats.earliest_retry_unix_ms_observed =
      s_ack_scanner.pass_earliest_retry_ms;

done:
  stats.selected_due_count = selected;
  if (out_stats) {
    *out_stats = stats;
  }
  ack_scan_unlock();
  return (int)selected;
}

void edr_command_state_delete_pending_ack(const char *command_id) {
  if (!command_id || !command_id[0]) {
    return;
  }
  char path[1200];
  if (control_ack_record_path(command_id, path, sizeof(path)) != 0) {
    return;
  }
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return;
  }
  (void)command_inbox_delete_path(path);
  state_lock_release(lock);
}

static int command_inbox_read_file(const char *path, EdrCommandInboxRecord *out);

int edr_command_state_store_inbox(const char *command_id, const char *command_type,
                                  const uint8_t *payload, size_t payload_len,
                                  const EdrSoarCommandMeta *meta) {
  if (!command_id || !command_id[0] || (payload_len > 0u && !payload)) {
    return -1;
  }
  char dir[1024];
  char path[1200];
  char tmp[1300];
  command_inbox_default_dir(dir, sizeof(dir));
  if (command_inbox_record_path(command_id, path, sizeof(path)) != 0) {
    return -1;
  }
  char *hex = hex_encode_alloc(payload, payload_len);
  if (!hex) {
    return -1;
  }
  FILE *lock = state_lock_acquire();
  if (!lock) {
    free(hex);
    return -1;
  }
  if (state_prepare_dir(dir) != 0) {
    state_lock_release(lock);
    free(hex);
    return -1;
  }
  /* A repeated delivery is never a grant renewal or a replacement payload.
   * Only the explicit signed renewal owner below may update delivery expiry. */
  EdrCommandInboxRecord previous;
  errno=0;
  int prior=command_inbox_read_file(path,&previous), prior_errno=errno;
  if(prior==0) {
    int same=!strcmp(previous.command_id,command_id) &&
      !strcmp(previous.command_type,command_type ? command_type : "") &&
      previous.payload_len==payload_len && (!payload_len || !memcmp(previous.payload,payload,payload_len));
    edr_command_state_free_inbox_record(&previous);
    state_lock_release(lock);free(hex);return same ? 0 : -1;
  }
  if(prior_errno!=ENOENT) {state_lock_release(lock);free(hex);return -1;}
  snprintf(tmp, sizeof(tmp), "%s.tmp.%lld", path, (long long)state_now_ms());
  FILE *f = state_open_new_secure(tmp);
  if (!f) {
    state_lock_release(lock);
    free(hex);
    return -1;
  }
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = meta ? meta : &empty;
  char cid[300], ctype[180], scid[300], run[240], step[240], idem[1100], by[100];
  json_escape_to(cid, sizeof(cid), command_id);
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(scid, sizeof(scid), sm->soar_correlation_id);
  json_escape_to(run, sizeof(run), sm->playbook_run_id);
  json_escape_to(step, sizeof(step), sm->playbook_step_id);
  json_escape_to(idem, sizeof(idem), sm->idempotency_key);
  json_escape_to(by, sizeof(by), sm->initiated_by);
  char auth[EDR_COMMAND_STATE_AUTH_CAP];
  if (authorization_json(&sm->result_authorization, auth, sizeof(auth)) != 0) {
    fclose(f); (void)command_inbox_delete_path(tmp);
    state_lock_release(lock); free(hex); return -1;
  }
  fprintf(f,
          "{\"record\":\"command_inbox\",\"command_id\":%s,\"command_type\":%s,"
          "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
          "\"idempotency_key\":%s,\"issued_at_unix_ms\":%lld,\"deadline_ms\":%u,"
          "\"initiated_by\":%s,\"received_unix_ms\":%lld,\"result_authorization\":%s,\"payload_hex\":\"",
          cid, ctype, scid, run, step, idem, (long long)sm->issued_at_unix_ms,
          (unsigned)sm->deadline_ms, by, (long long)state_now_ms(), auth);
  fputs(hex, f);
  fputs("\"}\n", f);
  int ok = state_flush_file(f) == 0;
  if (fclose(f) != 0) {
    ok = 0;
  }
  if (!ok || state_replace_file(tmp, path) != 0) {
    (void)command_inbox_delete_path(tmp);
    state_lock_release(lock);
    free(hex);
    return -1;
  }
  state_lock_release(lock);
  free(hex);
  return 0;
}

static int command_inbox_read_file(const char *path, EdrCommandInboxRecord *out) {
  if (!path || !out) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  struct stat st;
  FILE *f = state_open_read_secure(path, &st);
  if (!f || st.st_size < 0) {
    if (f) {
      fclose(f);
    }
    return -1;
  }
  long max_bytes = state_env_long_clamped("EDR_COMMAND_INBOX_MAX_BYTES",
                                          16L * 1024L * 1024L,
                                          1024L, 256L * 1024L * 1024L);
  if (st.st_size > max_bytes) {
    fclose(f);
    return 1;
  }
  size_t n = (size_t)st.st_size;
  char *buf = (char *)malloc(n + 1u);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t got = fread(buf, 1, n, f);
  fclose(f);
  buf[got] = '\0';
  if (got != n) {
    free(buf);
    return 1;
  }
  char record[32];
  parse_json_string_field_line(buf, "record", record, sizeof(record));
  parse_json_string_field_line(buf, "command_id", out->command_id, sizeof(out->command_id));
  parse_json_string_field_line(buf, "command_type", out->command_type, sizeof(out->command_type));
  parse_json_string_field_line(buf, "soar_correlation_id", out->meta.soar_correlation_id,
                               sizeof(out->meta.soar_correlation_id));
  parse_json_string_field_line(buf, "playbook_run_id", out->meta.playbook_run_id,
                               sizeof(out->meta.playbook_run_id));
  parse_json_string_field_line(buf, "playbook_step_id", out->meta.playbook_step_id,
                               sizeof(out->meta.playbook_step_id));
  parse_json_string_field_line(buf, "idempotency_key", out->meta.idempotency_key,
                               sizeof(out->meta.idempotency_key));
  parse_json_string_field_line(buf, "initiated_by", out->meta.initiated_by,
                               sizeof(out->meta.initiated_by));
  authorization_from_line(buf, &out->meta.result_authorization);
  out->meta.issued_at_unix_ms = parse_json_int64_field_line(buf, "issued_at_unix_ms", 0);
  int64_t deadline_ms = parse_json_int64_field_line(buf, "deadline_ms", 0);
  if (deadline_ms > 0 && deadline_ms <= 0xffffffffLL) {
    out->meta.deadline_ms = (uint32_t)deadline_ms;
  }
  out->received_unix_ms = parse_json_int64_field_line(buf, "received_unix_ms", 0);
  char *payload_hex = parse_json_string_field_alloc(buf, "payload_hex");
  free(buf);
  if (strcmp(record, "command_inbox") != 0 || !out->command_id[0] || !out->command_type[0] || !payload_hex) {
    free(payload_hex);
    return 1;
  }
  int rc = hex_decode_alloc(payload_hex, &out->payload, &out->payload_len);
  free(payload_hex);
  if (rc != 0) {
    edr_command_state_free_inbox_record(out);
    return 1;
  }
  return 0;
}

static int scope_string(const cJSON *root,const char *name,char *out,size_t cap) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(root,name);
  if(!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0] || strlen(v->valuestring)>=cap)return 0;
  memcpy(out,v->valuestring,strlen(v->valuestring)+1u);return 1;
}
int edr_command_state_task_scope(const char *command_id,EdrEgressTaskScope *out) {
  if(!command_id || !out)return EDR_EGRESS_REQUEST_DENIED;
  memset(out,0,sizeof(*out));
  char path[1200];
  if(command_inbox_record_path(command_id,path,sizeof(path)))return EDR_EGRESS_LOCAL_STATE_FAILURE;
  FILE *lock=state_lock_acquire();if(!lock)return EDR_EGRESS_LOCAL_STATE_FAILURE;
  EdrCommandInboxRecord inbox;
  errno=0;int rc=command_inbox_read_file(path,&inbox), saved_errno=errno;
  state_lock_release(lock);
  if(rc)return rc<0 && saved_errno==ENOENT ? EDR_EGRESS_REQUEST_DENIED : EDR_EGRESS_LOCAL_STATE_FAILURE;
  const EdrCommandResultAuthorization *a=&inbox.meta.result_authorization;
  /* This protected receipt is created only after signature verification. The
   * updater retains its inbox until the terminal event is durably ACKed. */
  int valid=!strcmp(inbox.command_id,command_id) && !strcmp(inbox.command_type,"agent_update") &&
    !strcmp(a->command_id,command_id) && !strcmp(a->command_type,"agent_update") &&
    a->tenant_id[0] && a->endpoint_id[0] && a->expires_unix_ms>0;
  rc=EDR_EGRESS_REQUEST_DENIED;
  if(valid && a->expires_unix_ms<=state_now_ms())rc=EDR_EGRESS_AUTHORIZATION_EXPIRED;
  else if(valid) {
    cJSON *payload=edr_egress_parse_purpose_object(inbox.payload,inbox.payload_len);
    valid=scope_string(payload,"task_id",out->task_id,sizeof(out->task_id)) &&
      scope_string(payload,"artifact_id",out->artifact_id,sizeof(out->artifact_id)) &&
      scope_string(payload,"hash",out->artifact_sha256,sizeof(out->artifact_sha256)) &&
      scope_string(payload,"version",out->target_version,sizeof(out->target_version)) &&
      scope_string(payload,"operation",out->operation,sizeof(out->operation));
    if(!scope_string(payload,"upgrade_class",out->upgrade_class,sizeof(out->upgrade_class))) {
      const cJSON *manifest=cJSON_GetObjectItemCaseSensitive(payload,"runtime_manifest_url");
      snprintf(out->upgrade_class,sizeof(out->upgrade_class),"%s",cJSON_IsString(manifest)&&manifest->valuestring[0]?"runtime_bundle":"binary_hot");
    }
    /* Older task receipts can still own events without download URLs. New
     * downloads require these exact signed fields at the purpose boundary. */
    (void)scope_string(payload,"artifact_url",out->artifact_url,sizeof(out->artifact_url));
    (void)scope_string(payload,"runtime_manifest_url",out->runtime_manifest_url,sizeof(out->runtime_manifest_url));
    (void)scope_string(payload,"arch",out->architecture,sizeof(out->architecture));
    int64_t issued=inbox.meta.issued_at_unix_ms;
    out->execution_authorized=issued>0 && inbox.meta.deadline_ms>0 &&
      issued<=INT64_MAX-(int64_t)inbox.meta.deadline_ms &&
      issued+(int64_t)inbox.meta.deadline_ms>state_now_ms();
    if(valid) {
      snprintf(out->command_id,sizeof(out->command_id),"%s",command_id);
      snprintf(out->tenant_id,sizeof(out->tenant_id),"%s",a->tenant_id);
      snprintf(out->endpoint_id,sizeof(out->endpoint_id),"%s",a->endpoint_id);rc=0;
    }
    cJSON_Delete(payload);
  }
  edr_command_state_free_inbox_record(&inbox);return rc;
}

static int command_inbox_name_is_record(const char *name) {
  if (!name || name[0] == '.') {
    return 0;
  }
  size_t n = strlen(name);
  return n > 5u && strcmp(name + n - 5u, ".json") == 0;
}

static int64_t command_inbox_deadline_at_ms(const EdrCommandInboxRecord *record) {
  if (!record || record->meta.deadline_ms == 0u) {
    return INT64_MAX;
  }
  int64_t base = record->meta.issued_at_unix_ms > 0
                     ? record->meta.issued_at_unix_ms
                     : record->received_unix_ms;
  if (base <= 0 || base > INT64_MAX - (int64_t)record->meta.deadline_ms) {
    return INT64_MAX;
  }
  return base + (int64_t)record->meta.deadline_ms;
}

static int command_inbox_priority_compare(const void *left, const void *right) {
  const EdrCommandInboxRecord *a = (const EdrCommandInboxRecord *)left;
  const EdrCommandInboxRecord *b = (const EdrCommandInboxRecord *)right;
  int64_t a_deadline = command_inbox_deadline_at_ms(a);
  int64_t b_deadline = command_inbox_deadline_at_ms(b);
  if (a_deadline != b_deadline) {
    return a_deadline < b_deadline ? -1 : 1;
  }
  if (a->received_unix_ms != b->received_unix_ms) {
    return a->received_unix_ms < b->received_unix_ms ? -1 : 1;
  }
  if (a->meta.issued_at_unix_ms != b->meta.issued_at_unix_ms) {
    return a->meta.issued_at_unix_ms < b->meta.issued_at_unix_ms ? -1 : 1;
  }
  return strcmp(a->command_id, b->command_id);
}

static void command_inbox_keep_priority(EdrCommandInboxRecord *out, size_t *count,
                                        size_t cap, EdrCommandInboxRecord *candidate) {
  if (*count < cap) {
    out[(*count)++] = *candidate;
    memset(candidate, 0, sizeof(*candidate));
    return;
  }
  size_t worst = 0u;
  for (size_t i = 1u; i < *count; i++) {
    if (command_inbox_priority_compare(&out[i], &out[worst]) > 0) {
      worst = i;
    }
  }
  if (command_inbox_priority_compare(candidate, &out[worst]) < 0) {
    edr_command_state_free_inbox_record(&out[worst]);
    out[worst] = *candidate;
    memset(candidate, 0, sizeof(*candidate));
    return;
  }
  edr_command_state_free_inbox_record(candidate);
}

size_t edr_command_state_count_inbox(void) {
  char dir[1024];
  command_inbox_default_dir(dir, sizeof(dir));
  if (state_prepare_dir(dir) != 0) {
    return 0u;
  }
  size_t count = 0u;
#ifdef _WIN32
  char pattern[1100];
  snprintf(pattern, sizeof(pattern), "%s\\*.json", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0u;
  }
  do {
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0u &&
        command_inbox_name_is_record(fd.cFileName)) {
      count++;
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return 0u;
  }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (command_inbox_name_is_record(ent->d_name)) {
      count++;
    }
  }
  closedir(d);
#endif
  return count;
}

int edr_command_state_collect_inbox_filtered(EdrCommandInboxRecord *out, size_t cap,
                                             EdrCommandInboxFilter filter, void *user) {
  if (!out || cap == 0u) {
    return 0;
  }
  char dir[1024];
  command_inbox_default_dir(dir, sizeof(dir));
  if (state_prepare_dir(dir) != 0) {
    return 0;
  }
  size_t count = 0;
#ifdef _WIN32
  char pattern[1100];
  snprintf(pattern, sizeof(pattern), "%s\\*.json", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  do {
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        !command_inbox_name_is_record(fd.cFileName)) {
      continue;
    }
    char path[1200];
    snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (!command_inbox_name_is_record(ent->d_name)) {
      continue;
    }
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
#endif
    EdrCommandInboxRecord rec;
    int read_rc = command_inbox_read_file(path, &rec);
    if (read_rc != 0) {
      if (read_rc > 0) {
        /* See ACK collection above: only quarantine the same malformed
         * snapshot while command writers are excluded. */
        FILE *lock = state_lock_acquire();
        if (lock) {
          EdrCommandInboxRecord confirm;
          int confirm_rc = command_inbox_read_file(path, &confirm);
          if (confirm_rc > 0) {
            (void)state_move_to_quarantine(dir, path, "command_inbox", "malformed_command_inbox_record");
          } else if (confirm_rc == 0) {
            edr_command_state_free_inbox_record(&confirm);
          }
          state_lock_release(lock);
        }
      }
      continue;
    }
    if (edr_command_state_has_final(rec.command_id, &rec.meta)==1) {
      edr_command_state_free_inbox_record(&rec);
      (void)command_inbox_delete_path(path);
      continue;
    }
    if (filter && !filter(rec.command_type, user)) {
      edr_command_state_free_inbox_record(&rec);
      continue;
    }
    /* Directory enumeration order is not a scheduler. Keep the most urgent
     * records across the whole inbox, even when pending depth exceeds cap. */
    command_inbox_keep_priority(out, &count, cap, &rec);
#ifdef _WIN32
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  }
  closedir(d);
#endif
  if (count > 1u) {
    qsort(out, count, sizeof(out[0]), command_inbox_priority_compare);
  }
  return (int)count;
}

int edr_command_state_collect_inbox(EdrCommandInboxRecord *out, size_t cap) {
  return edr_command_state_collect_inbox_filtered(out, cap, NULL, NULL);
}

void edr_command_state_delete_inbox(const char *command_id) {
  if (!command_id || !command_id[0]) {
    return;
  }
  char path[1200];
  if (command_inbox_record_path(command_id, path, sizeof(path)) != 0) {
    return;
  }
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return;
  }
  (void)command_inbox_delete_path(path);
  state_lock_release(lock);
}

void edr_command_state_free_inbox_record(EdrCommandInboxRecord *record) {
  if (!record) {
    return;
  }
  free(record->payload);
  memset(record, 0, sizeof(*record));
}

static int append_state_line(const char *line) {
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *f = state_open_append_secure(path);
  if (!f) {
    return -1;
  }
  int ok = fputs(line, f) >= 0 && fputc('\n', f) != EOF && state_flush_file(f) == 0;
  if (fclose(f) != 0) {
    ok = 0;
  }
  return ok ? 0 : -1;
}

static int append_state_line_locked(const char *line) {
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return -1;
  }
  int rc = append_state_line(line);
  state_lock_release(lock);
  return rc;
}

/* The renewal and target record share the existing protected command owner.
 * No content, execution deadline, ACK, owner identity or retry count is changed. */
static int renewal_equal(const cJSON *o,const char *key,const char *value) {
  const cJSON *v=cJSON_GetObjectItemCaseSensitive(o,key);
  return cJSON_IsString(v) && v->valuestring && !strcmp(v->valuestring,value);
}
static int renewal_number(cJSON *o,const char *key,double value) {
  cJSON *n=cJSON_CreateNumber(value);if(!n)return 0;
  if(cJSON_HasObjectItem(o,key))return cJSON_ReplaceItemInObjectCaseSensitive(o,key,n);
  return cJSON_AddItemToObject(o,key,n);
}
static int renewal_text(cJSON *o,const char *key,const char *value) {
  cJSON *n=cJSON_CreateString(value);if(!n)return 0;
  if(cJSON_HasObjectItem(o,key))return cJSON_ReplaceItemInObjectCaseSensitive(o,key,n);
  return cJSON_AddItemToObject(o,key,n);
}
int edr_command_state_renew_delivery(const char *renewal_id,const uint8_t *payload,
    size_t payload_len,const EdrSoarCommandMeta *meta) {
  int rc=EDR_EGRESS_REQUEST_DENIED;int64_t now=state_now_ms();
  if(!renewal_id || !meta || !payload || !payload_len || payload_len>8192u)return rc;
  const EdrCommandResultAuthorization *authority=&meta->result_authorization;
  if(strcmp(authority->command_id,renewal_id) || strcmp(authority->command_type,"result_delivery_renewal") ||
      !authority->tenant_id[0] || !authority->endpoint_id[0] || authority->expires_unix_ms<=now)return rc;
  cJSON *request=cJSON_ParseWithLength((const char *)payload,payload_len);
  const cJSON *id=cJSON_GetObjectItemCaseSensitive(request,"target_command_id");
  const cJSON *type=cJSON_GetObjectItemCaseSensitive(request,"target_command_type");
  const cJSON *kind=cJSON_GetObjectItemCaseSensitive(request,"target_kind");
  const cJSON *hash=cJSON_GetObjectItemCaseSensitive(request,"target_sha256");
  const cJSON *expires=cJSON_GetObjectItemCaseSensitive(request,"expires_unix_ms");
  if(!renewal_equal(request,"schema","edr.result_delivery_renewal.v1") ||
      !renewal_equal(request,"initiated_by","operator") ||
      !renewal_equal(request,"tenant_id",authority->tenant_id) ||
      !renewal_equal(request,"endpoint_id",authority->endpoint_id) ||
      !cJSON_IsString(id) || !id->valuestring[0] || strlen(id->valuestring)>=128u || !strcmp(id->valuestring,renewal_id) ||
      !cJSON_IsString(type) || !type->valuestring[0] || !strcmp(type->valuestring,"result_delivery_renewal") ||
      !cJSON_IsString(kind) || (strcmp(kind->valuestring,"result") && strcmp(kind->valuestring,"upgrade_payload")) ||
      !cJSON_IsString(hash) || strlen(hash->valuestring)!=64u || strspn(hash->valuestring,"0123456789abcdef")!=64u ||
      !cJSON_IsNumber(expires) || expires->valuedouble<=now || expires->valuedouble>now+86400000LL ||
      expires->valuedouble>(double)authority->expires_unix_ms || (double)(int64_t)expires->valuedouble!=expires->valuedouble)goto done;
  int upgrade=!strcmp(kind->valuestring,"upgrade_payload");
  if(upgrade && strcmp(type->valuestring,"agent_update"))goto done;
  FILE *lock=state_lock_acquire();if(!lock){rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto done;}
  cJSON *target=NULL;char path[1200],sha[65];
  if(upgrade) {
    if(command_inbox_record_path(id->valuestring,path,sizeof(path)))goto locked_done;
    EdrCommandInboxRecord inbox;errno=0;int read_rc=command_inbox_read_file(path,&inbox);
    if(read_rc){rc=errno==ENOENT ? EDR_EGRESS_REQUEST_DENIED : EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    int ok=!strcmp(inbox.command_id,id->valuestring) && !strcmp(inbox.command_type,type->valuestring) &&
      edr_sha256_hex(inbox.payload,inbox.payload_len,sha)==0 && !strcmp(sha,hash->valuestring);
    edr_command_state_free_inbox_record(&inbox);if(!ok)goto locked_done;
    FILE *f=state_open_read_secure(path,NULL);if(!f){rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    if(fseek(f,0,SEEK_END)){fclose(f);rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    long len=ftell(f);if(len<=0 || len>33554432 || fseek(f,0,SEEK_SET)){fclose(f);rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    char *raw=malloc((size_t)len+1u);if(!raw){fclose(f);rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    ok=fread(raw,1,(size_t)len,f)==(size_t)len && !ferror(f);fclose(f);raw[len]=0;
    if(ok)target=cJSON_Parse(raw);free(raw);
    if(!target){rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
  } else {
    state_default_path(path,sizeof(path));FILE *f=state_open_read_secure(path,NULL);
    if(!f){rc=errno==ENOENT ? EDR_EGRESS_REQUEST_DENIED : EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    char *line=malloc(EDR_COMMAND_STATE_LINE_CAP);int io_ok=line!=NULL;
    while(line && fgets(line,EDR_COMMAND_STATE_LINE_CAP,f)) {
      if(!strchr(line,'\n')){io_ok=0;break;}
      if(line_matches_key(line,"command_id",id->valuestring)) {
        cJSON *candidate=cJSON_Parse(line);if(!candidate){io_ok=0;break;}
        cJSON_Delete(target);target=candidate;
      }
    }
    if(ferror(f))io_ok=0;fclose(f);free(line);
    if(!io_ok){rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
    const cJSON *final=cJSON_GetObjectItemCaseSensitive(target,"final");
    const cJSON *pending=cJSON_GetObjectItemCaseSensitive(target,"report_pending");
    const cJSON *detail=cJSON_GetObjectItemCaseSensitive(target,"detail");
    if(!cJSON_IsNumber(final) || final->valueint!=1 || !cJSON_IsNumber(pending) || pending->valueint!=1 ||
        !cJSON_IsString(detail) || edr_sha256_hex((const uint8_t *)detail->valuestring,strlen(detail->valuestring),sha) ||
        strcmp(sha,hash->valuestring))goto locked_done;
  }
  cJSON *grant=cJSON_GetObjectItemCaseSensitive(target,"result_authorization");
  const cJSON *old_expiry=cJSON_GetObjectItemCaseSensitive(grant,"expires_unix_ms");
  if(!renewal_equal(target,"command_id",id->valuestring) || !renewal_equal(target,"command_type",type->valuestring) ||
      !renewal_equal(grant,"command_id",id->valuestring) || !renewal_equal(grant,"command_type",type->valuestring) ||
      !renewal_equal(grant,"tenant_id",authority->tenant_id) || !renewal_equal(grant,"endpoint_id",authority->endpoint_id) ||
      !cJSON_IsNumber(old_expiry) || old_expiry->valuedouble<=0 || expires->valuedouble<=old_expiry->valuedouble)goto locked_done;
  /* Expiry is monotonic, so replay cannot alter state or extend authorization. */
  if(!renewal_number(grant,"expires_unix_ms",expires->valuedouble) ||
      !renewal_text(target,"delivery_renewal_id",renewal_id) ||
      (!upgrade && (!renewal_number(target,"report_policy_held",0) ||
                    !renewal_text(target,"report_policy_version","") ||
                    !renewal_number(target,"report_next_retry_unix_ms",0)))) {rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
  char *updated=cJSON_PrintUnformatted(target);if(!updated){rc=EDR_EGRESS_LOCAL_STATE_FAILURE;goto locked_done;}
  if(upgrade) {
    char tmp[1300];snprintf(tmp,sizeof(tmp),"%s.renewal.tmp.%lld",path,(long long)now);
    FILE *f=state_open_new_secure(tmp);int ok=f!=NULL;
    if(f){ok=fputs(updated,f)>=0 && fputc('\n',f)!=EOF && state_flush_file(f)==0;if(fclose(f))ok=0;}
    if(ok)ok=state_replace_file(tmp,path)==0;
    if(!ok)(void)command_inbox_delete_path(tmp);
    rc=ok ? 0 : EDR_EGRESS_LOCAL_STATE_FAILURE;
  } else rc=append_state_line(updated)==0 ? 0 : EDR_EGRESS_LOCAL_STATE_FAILURE;
  free(updated);
  if(rc==0)s_collect_cache_pending_zero=0;
locked_done:
  cJSON_Delete(target);state_lock_release(lock);
done:
  cJSON_Delete(request);return rc;
}

static int count_prior_attempts(const char *command_id, const EdrSoarCommandMeta *meta) {
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return 0;
  }
  FILE *f = state_open_read_secure(path, NULL);
  if (!f) {
    state_lock_release(lock);
    return 0;
  }
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  int retry = 0;
  char line[EDR_COMMAND_STATE_LINE_CAP];
  while (fgets(line, sizeof(line), f)) {
    int match = 0;
    if (idem_key[0]) {
      match = line_matches_key(line, "idempotency_key", idem_key);
    } else if (command_id && command_id[0]) {
      match = line_matches_key(line, "command_id", command_id);
    }
    if (match) {
      retry++;
    }
  }
  fclose(f);
  state_lock_release(lock);
  return retry;
}

int edr_command_state_begin(const char *command_id, const char *command_type,
                            const EdrSoarCommandMeta *meta, int *out_retry_count,
                            EdrCommandStateRecord *out_duplicate) {
  if (out_retry_count) {
    *out_retry_count = 0;
  }
  if (out_duplicate) {
    memset(out_duplicate, 0, sizeof(*out_duplicate));
  }
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return EDR_COMMAND_STATE_BEGIN_ERROR;
  }
  FILE *f = state_open_read_secure(path, NULL);
  int retry = 0;
  int duplicate = 0;
  int running_duplicate = 0;
  EdrCommandStateRecord last_final;
  EdrCommandStateRecord last_running;
  memset(&last_final, 0, sizeof(last_final));
  memset(&last_running, 0, sizeof(last_running));
  int64_t now_ms = state_now_ms();
  int64_t running_ttl_ms = command_running_ttl_ms(meta);
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  if (f) {
    char line[EDR_COMMAND_STATE_LINE_CAP];
    while (fgets(line, sizeof(line), f)) {
      int match = 0;
      if (command_id && command_id[0])
        match = line_matches_key(line, "command_id", command_id);
      if (!match && idem_key[0])
        match = line_matches_key(line, "idempotency_key", idem_key);
      if (!match) {
        continue;
      }
      retry++;
      if (strstr(line, "\"final\":1")) {
        duplicate = 1;
        fill_record_from_line(line, &last_final);
      } else {
        EdrCommandStateRecord running;
        fill_record_from_line(line, &running);
        if (running.updated_unix_ms > 0 && now_ms - running.updated_unix_ms < running_ttl_ms) {
          running_duplicate = 1;
          last_running = running;
        }
      }
    }
    fclose(f);
  }
  if (out_retry_count) {
    *out_retry_count = retry;
  }
  if (duplicate) {
    if (out_duplicate) {
      *out_duplicate = last_final;
    }
    state_lock_release(lock);
    return 1;
  }
  if (running_duplicate) {
    if (out_duplicate) {
      *out_duplicate = last_running;
    }
    state_lock_release(lock);
    return EDR_COMMAND_STATE_BEGIN_DUP_RUNNING;
  }

  char cid[300], ctype[180], idem[300], boot[100], line[1400];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  {
    char boot_raw[64];
    state_boot_id(boot_raw, sizeof(boot_raw));
    json_escape_to(boot, sizeof(boot), boot_raw);
  }
#ifdef _WIN32
  int pid = _getpid();
#else
  int pid = (int)getpid();
#endif
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":0,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":\"queued\",\"execution_status\":0,"
           "\"exit_code\":0,\"retry_count\":%d,\"report_pending\":0,\"updated_unix_ms\":%lld,"
           "\"agent_boot_id\":%s,\"process_id\":%d}",
           cid, ctype, idem, retry, (long long)state_now_ms(), boot, pid);
  int append_rc = append_state_line(line);
  state_lock_release(lock);
  return append_rc == 0 ? EDR_COMMAND_STATE_BEGIN_READY : EDR_COMMAND_STATE_BEGIN_ERROR;
}

int edr_command_state_replay_begin_policy(const char *command_id, const char *command_type,
                                          const EdrSoarCommandMeta *meta,
                                          int allow_replay_after_start,
                                          int *out_retry_count,
                                          EdrCommandStateRecord *out_duplicate) {
  if (out_retry_count) {
    *out_retry_count = 0;
  }
  if (out_duplicate) {
    memset(out_duplicate, 0, sizeof(*out_duplicate));
  }
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return EDR_COMMAND_STATE_BEGIN_ERROR;
  }
  FILE *f = state_open_read_secure(path, NULL);
  int retry = 0;
  int duplicate = 0;
  int running_duplicate = 0;
  int queued_record = 0;
  EdrCommandStateRecord last_final;
  EdrCommandStateRecord last_running;
  EdrCommandStateRecord last_nonfinal;
  memset(&last_final, 0, sizeof(last_final));
  memset(&last_running, 0, sizeof(last_running));
  memset(&last_nonfinal, 0, sizeof(last_nonfinal));
  int64_t now_ms = state_now_ms();
  int64_t running_ttl_ms = command_running_ttl_ms(meta);
  char idem_key[128];
  char current_boot[64];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  state_boot_id(current_boot, sizeof(current_boot));
  if (f) {
    char line[EDR_COMMAND_STATE_LINE_CAP];
    while (fgets(line, sizeof(line), f)) {
      int match = 0;
      if (command_id && command_id[0])
        match = line_matches_key(line, "command_id", command_id);
      if (!match && idem_key[0])
        match = line_matches_key(line, "idempotency_key", idem_key);
      if (!match) {
        continue;
      }
      retry++;
      if (strstr(line, "\"final\":1")) {
        duplicate = 1;
        fill_record_from_line(line, &last_final);
      } else {
        EdrCommandStateRecord running;
        fill_record_from_line(line, &running);
        last_nonfinal = running;
      }
    }
    fclose(f);
  }
  if (out_retry_count) {
    *out_retry_count = retry;
  }
  if (duplicate) {
    if (out_duplicate) {
      *out_duplicate = last_final;
    }
    state_lock_release(lock);
    return EDR_COMMAND_STATE_BEGIN_DUP_FINAL;
  }
  queued_record = strcmp(last_nonfinal.response_status, "queued") == 0;
  if (strcmp(last_nonfinal.response_status, "cancelling") == 0) {
    if (out_duplicate) {
      *out_duplicate = last_nonfinal;
    }
    state_lock_release(lock);
    return EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED;
  }
  if (!allow_replay_after_start && last_nonfinal.command_id[0] && !queued_record) {
    if (out_duplicate) {
      *out_duplicate = last_nonfinal;
    }
    state_lock_release(lock);
    return EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED;
  }
  if (!queued_record && last_nonfinal.command_id[0] &&
      last_nonfinal.updated_unix_ms > 0 &&
      now_ms - last_nonfinal.updated_unix_ms < running_ttl_ms &&
      last_nonfinal.agent_boot_id[0] && strcmp(last_nonfinal.agent_boot_id, current_boot) == 0) {
    running_duplicate = 1;
    last_running = last_nonfinal;
  }
  if (running_duplicate) {
    if (out_duplicate) {
      *out_duplicate = last_running;
    }
    state_lock_release(lock);
    return EDR_COMMAND_STATE_BEGIN_DUP_RUNNING;
  }

  char cid[300], ctype[180], idem[300], boot[100], line[1400];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  json_escape_to(boot, sizeof(boot), current_boot);
#ifdef _WIN32
  int pid = _getpid();
#else
  int pid = (int)getpid();
#endif
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":0,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":\"%s\",\"execution_status\":0,"
           "\"exit_code\":0,\"retry_count\":%d,\"report_pending\":0,\"updated_unix_ms\":%lld,"
           "\"agent_boot_id\":%s,\"process_id\":%d}",
           cid, ctype, idem, queued_record ? "running" : "replaying", retry,
           (long long)state_now_ms(), boot, pid);
  int append_rc = append_state_line(line);
  state_lock_release(lock);
  return append_rc == 0 ? EDR_COMMAND_STATE_BEGIN_READY : EDR_COMMAND_STATE_BEGIN_ERROR;
}

int edr_command_state_replay_begin(const char *command_id, const char *command_type,
                                   const EdrSoarCommandMeta *meta, int *out_retry_count,
                                   EdrCommandStateRecord *out_duplicate) {
  return edr_command_state_replay_begin_policy(command_id, command_type, meta, 1,
                                               out_retry_count, out_duplicate);
}

/* Caller holds the state lock. Compare the complete semantic terminal record;
 * delivery ACK/retry fields belong to the existing result owner and are never
 * reset by a duplicate forensic upload completion. */
static int matching_terminal_locked(const char *command_id, const char *command_type,
    const EdrSoarCommandMeta *meta, const char *response_status, int execution_status,
    int exit_code, const char *detail, const char *artifacts) {
  char path[1024], idem[128];
  state_default_path(path, sizeof(path));
  state_idempotency_key(meta, idem, sizeof(idem));
  FILE *f = state_open_read_secure(path, NULL);
  if (!f) {
    struct stat st;
    return stat(path, &st) != 0 && errno == ENOENT ? 0 : -1;
  }
  char *line = (char *)malloc(EDR_COMMAND_STATE_LINE_CAP);
  EdrCommandStateRecord *prior = (EdrCommandStateRecord *)malloc(sizeof(*prior));
  int result = 0;
  if (!line || !prior) result = -1;
  while (result >= 0 && line && prior && fgets(line, EDR_COMMAND_STATE_LINE_CAP, f)) {
    if (!strchr(line, '\n') && !feof(f)) { result = -1; break; }
    if (!line_matches_key(line, "command_id", command_id)) continue;
    fill_record_from_line(line, prior);
    if (strcmp(prior->command_id, command_id) || !prior->final_record) continue;
    if (strcmp(prior->command_type, command_type ? command_type : "") ||
        strcmp(prior->idempotency_key, idem) ||
        strcmp(prior->response_status, response_status ? response_status : "failed") ||
        prior->execution_status != execution_status || prior->exit_code != exit_code ||
        strcmp(prior->detail, detail ? detail : "") || strcmp(prior->artifacts, artifacts ? artifacts : "") ||
        strcmp(prior->soar_correlation_id, meta ? meta->soar_correlation_id : "") ||
        strcmp(prior->playbook_run_id, meta ? meta->playbook_run_id : "") ||
        strcmp(prior->playbook_step_id, meta ? meta->playbook_step_id : "")) {
      result = -2;
      break;
    }
    result = 1;
  }
  if (ferror(f)) result = -1;
  if (fclose(f) != 0) result = -1;
  free(line); free(prior);
  if (result == 1) {
    /* A prior append can leave a complete readable line even when its flush
     * failed. Reconfirm durability before treating it as an existing commit. */
    FILE *durable = state_open_append_secure(path);
    if (!durable) return -1;
    int flushed = state_flush_file(durable);
    if (fclose(durable) != 0) flushed = -1;
    if (flushed != 0) result = -1;
  }
  return result;
}

static int command_state_finish(const char *command_id, const char *command_type,
                             const EdrSoarCommandMeta *meta, const char *response_status,
                             int execution_status, int exit_code, const char *detail,
                             const char *artifacts, int report_pending, int once) {
  const char *local_detail = detail;
  char projected_detail[EDR_COMMAND_STATE_DETAIL_CAP];
  int content_held=0;
  if (meta && meta->result_authorization.content_contract[0]) {
    content_held=edr_command_result_project_detail(&meta->result_authorization, command_type,
          execution_status, exit_code, detail ? detail : "", projected_detail,
          sizeof(projected_detail)) != 0;
    if(!content_held)detail=projected_detail;
  }
  int retry = count_prior_attempts(command_id, meta);
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  char cid[300], ctype[180], idem[300], st[96], det[EDR_COMMAND_STATE_ESCAPED_DETAIL_CAP], art[2200], scid[300], run[300], step[300], boot[100], line[EDR_COMMAND_STATE_LINE_CAP];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  json_escape_to(st, sizeof(st), response_status ? response_status : "failed");
  json_escape_to(scid, sizeof(scid), meta ? meta->soar_correlation_id : "");
  json_escape_to(run, sizeof(run), meta ? meta->playbook_run_id : "");
  json_escape_to(step, sizeof(step), meta ? meta->playbook_step_id : "");
  {
    char boot_raw[64];
    state_boot_id(boot_raw, sizeof(boot_raw));
    json_escape_to(boot, sizeof(boot), boot_raw);
  }
#ifdef _WIN32
  int pid = _getpid();
#else
  int pid = (int)getpid();
#endif
  json_escape_to(det, sizeof(det), detail ? detail : "");
  json_escape_to(art, sizeof(art), artifacts ? artifacts : "");
  FILE *lock=state_lock_acquire();if(!lock)return -1;
  EdrCommandResultAuthorization final_authority={0};
  if(meta)final_authority=meta->result_authorization;
  if(meta && command_type && !strcmp(command_type,"agent_update")) {
    /* Recovery can finish while another worker renews delivery. Inherit only
     * that same protected inbox grant, never the old snapshot's expiry. */
    char inbox_path[1200];EdrCommandInboxRecord inbox;
    if(command_inbox_record_path(command_id,inbox_path,sizeof(inbox_path))==0 &&
        command_inbox_read_file(inbox_path,&inbox)==0) {
      const EdrCommandResultAuthorization *current=&inbox.meta.result_authorization;
      if(!strcmp(current->command_id,final_authority.command_id) &&
          !strcmp(current->command_type,final_authority.command_type) &&
          !strcmp(current->tenant_id,final_authority.tenant_id) &&
          !strcmp(current->endpoint_id,final_authority.endpoint_id) &&
          current->expires_unix_ms>final_authority.expires_unix_ms)final_authority=*current;
      edr_command_state_free_inbox_record(&inbox);
    }
  }
  char auth[EDR_COMMAND_STATE_AUTH_CAP];
  if (authorization_json(&final_authority, auth, sizeof(auth)) != 0) {state_lock_release(lock);return -1;}
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":%d,"
           "\"report_attempts\":%u,\"report_last_failure_unix_ms\":%lld,"
           "\"report_next_retry_unix_ms\":0,\"report_last_error\":\"%s\",\"report_policy_held\":%d,\"report_policy_version\":\"%s\","
           "\"updated_unix_ms\":%lld,"
           "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
           "\"agent_boot_id\":%s,\"process_id\":%d,\"artifacts\":%s,\"detail\":%s,\"result_authorization\":%s}",
           cid, ctype, idem, st, execution_status, exit_code, retry, report_pending ? 1 : 0,
           0u, 0LL, content_held ? "result_content_contract_denied" : "", content_held,
           content_held ? EDR_EGRESS_POLICY_VERSION : "",
           (long long)state_now_ms(), scid, run, step, boot, pid, art, det, auth);
  int prior=(once || final_authority.content_contract[0]) ? matching_terminal_locked(command_id,command_type,meta,response_status,
      execution_status,exit_code,detail,artifacts) : 0;
  int written=prior==0 ? append_state_line(line) : prior;
  state_lock_release(lock);
  if(written!=0)return written==1 && !once ? 0 : written;
  edr_local_evidence_cache_record_command_result(
      command_id, command_type, response_status ? response_status : "failed",
      execution_status, exit_code, local_detail, artifacts);
  edr_command_state_compact_if_needed();
  return 0;
}

int edr_command_state_finish(const char *command_id, const char *command_type,
    const EdrSoarCommandMeta *meta, const char *response_status, int execution_status,
    int exit_code, const char *detail, const char *artifacts, int report_pending) {
  return command_state_finish(command_id, command_type, meta, response_status,
                              execution_status, exit_code, detail, artifacts, report_pending, 0);
}

int edr_command_state_finish_once(const char *command_id, const char *command_type,
    const EdrSoarCommandMeta *meta, const char *response_status, int execution_status,
    int exit_code, const char *detail, const char *artifacts, int report_pending) {
  if (!command_id || !command_id[0]) return -1;
  return command_state_finish(command_id, command_type, meta, response_status,
                              execution_status, exit_code, detail, artifacts, report_pending, 1);
}

int edr_command_state_request_cancel(const char *command_id,
                                     EdrCommandStateRecord *out_target) {
  if (out_target) {
    memset(out_target, 0, sizeof(*out_target));
  }
  if (!command_id || !command_id[0]) {
    return EDR_COMMAND_STATE_CANCEL_NOT_FOUND;
  }
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  if (!lock) {
    return EDR_COMMAND_STATE_CANCEL_ERROR;
  }
  FILE *f = state_open_read_secure(path, NULL);
  EdrCommandStateRecord latest;
  memset(&latest, 0, sizeof(latest));
  if (f) {
    char line_buf[8192];
    while (fgets(line_buf, sizeof(line_buf), f)) {
      if (line_matches_key(line_buf, "command_id", command_id)) {
        fill_record_from_line(line_buf, &latest);
      }
    }
    fclose(f);
  }
  if (!latest.command_id[0]) {
    state_lock_release(lock);
    return EDR_COMMAND_STATE_CANCEL_NOT_FOUND;
  }
  if (out_target) {
    *out_target = latest;
  }
  if (latest.final_record) {
    state_lock_release(lock);
    return EDR_COMMAND_STATE_CANCEL_ALREADY_FINAL;
  }

  char cid[300], ctype[180], idem[1100], boot[100], line[EDR_COMMAND_STATE_LINE_CAP];
  json_escape_to(cid, sizeof(cid), latest.command_id);
  json_escape_to(ctype, sizeof(ctype), latest.command_type);
  json_escape_to(idem, sizeof(idem), latest.idempotency_key);
  {
    char boot_raw[64];
    state_boot_id(boot_raw, sizeof(boot_raw));
    json_escape_to(boot, sizeof(boot), boot_raw);
  }
#ifdef _WIN32
  int pid = _getpid();
#else
  int pid = (int)getpid();
#endif
  int line_len = snprintf(line, sizeof(line),
                          "{\"record\":\"command_state\",\"final\":0,\"command_id\":%s,\"command_type\":%s,"
                          "\"idempotency_key\":%s,\"response_status\":\"cancelling\",\"execution_status\":0,"
                          "\"exit_code\":0,\"retry_count\":%d,\"report_pending\":0,\"updated_unix_ms\":%lld,"
                          "\"agent_boot_id\":%s,\"process_id\":%d}",
                          cid, ctype, idem, latest.retry_count, (long long)state_now_ms(), boot, pid);
  if (line_len < 0 || (size_t)line_len >= sizeof(line)) {
    state_lock_release(lock);
    return EDR_COMMAND_STATE_CANCEL_ERROR;
  }
  int rc = append_state_line(line);
  state_lock_release(lock);
  return rc == 0 ? EDR_COMMAND_STATE_CANCEL_REQUESTED : EDR_COMMAND_STATE_CANCEL_ERROR;
}

/* Index only identity/offset, then decode the latest record for each owner.
 * Retained ACK tombstones must not occupy a bounded result delivery batch. */
typedef struct CommandPendingOffset {
  char command_id[128];
  long offset;
} CommandPendingOffset;
static int pending_compare_owner(const void *a,const void *b) {
  const CommandPendingOffset *x=a,*y=b;int order=strcmp(x->command_id,y->command_id);
  return order?order:(x->offset<y->offset?-1:x->offset>y->offset);
}
int edr_command_state_collect_pending(EdrCommandStateRecord *out, size_t cap) {
  if (!out || !cap) return 0;
  char path[1024];state_default_path(path,sizeof(path));
  EdrCommandStateFileInfo info;
  if (state_file_info(path,&info)!=0) return 0;
  if (s_collect_cache_pending_zero && state_file_info_same(info,s_collect_cache_info)) return 0;
  FILE *lock=state_lock_acquire();if(!lock)return 0;
  FILE *f=state_open_read_secure(path,NULL);
  if(!f){state_lock_release(lock);return 0;}
  const size_t row_limit=65536u;size_t capacity=512u,count=0,n=0;
  CommandPendingOffset *rows=calloc(capacity,sizeof(*rows));
  EdrCommandStateRecord *rec=calloc(1,sizeof(*rec));
  char *line=malloc(EDR_COMMAND_STATE_LINE_CAP);
  int ok=rows && rec && line,pending_exists=0;const char *failure="allocation_failed";
  while(ok) {
    long offset=ftell(f);if(offset<0){ok=0;failure="read_position_failed";break;}
    if(!fgets(line,EDR_COMMAND_STATE_LINE_CAP,f))break;
    size_t length=strlen(line);
    if(!length || line[length-1]!='\n'){ok=0;failure="incomplete_record";break;}
    cJSON *o=edr_egress_parse_purpose_object(line,length);
    const cJSON *id=cJSON_GetObjectItemCaseSensitive(o,"command_id");
    const cJSON *final=cJSON_GetObjectItemCaseSensitive(o,"final");
    if(!cJSON_IsObject(o) || !cJSON_IsString(id) || !id->valuestring[0] ||
        strlen(id->valuestring)>=sizeof(rows[0].command_id) || !cJSON_IsNumber(final) ||
        (final->valuedouble!=0 && final->valuedouble!=1)) {
      cJSON_Delete(o);ok=0;failure="invalid_record";break;
    }
    if(final->valueint==1) {
      if(count==capacity) {
        size_t next=capacity>row_limit/2u?row_limit:capacity*2u;
        CommandPendingOffset *grown=count<row_limit?realloc(rows,next*sizeof(*rows)):NULL;
        if(!grown){cJSON_Delete(o);ok=0;failure="scratch_capacity_exhausted";break;}
        rows=grown;capacity=next;
      }
      strcpy(rows[count].command_id,id->valuestring);rows[count++].offset=offset;
    }
    cJSON_Delete(o);
  }
  if(ferror(f)){ok=0;failure="read_failed";}
  if(ok) {
    qsort(rows,count,sizeof(*rows),pending_compare_owner);
    int64_t now_ms=state_now_ms();
    for(size_t first=0;first<count && n<cap;) {
      size_t end=first+1;while(end<count && !strcmp(rows[first].command_id,rows[end].command_id))end++;
      if(fseek(f,rows[end-1].offset,SEEK_SET) || !fgets(line,EDR_COMMAND_STATE_LINE_CAP,f)) {
        ok=0;failure="latest_record_read_failed";break;
      }
      fill_record_from_line(line,rec);first=end;
      if(!rec->report_pending)continue;
      pending_exists=1;
      if(rec->report_policy_held && !strcmp(rec->report_policy_version,EDR_EGRESS_POLICY_VERSION))continue;
      if(rec->report_next_retry_unix_ms<=0 || rec->report_next_retry_unix_ms<=now_ms)out[n++]=*rec;
    }
  }
  if(fclose(f)!=0){ok=0;failure="read_close_failed";}
  if(!ok){fprintf(stderr,"[command_state] pending collection incomplete: %s\n",failure);n=0;}
  free(line);free(rec);free(rows);state_lock_release(lock);
  if(ok && !n && !pending_exists){s_collect_cache_info=info;s_collect_cache_pending_zero=1;}
  else s_collect_cache_pending_zero=0;
  return (int)n;
}

static int result_string_equal(const cJSON *result, const char *name, const char *expected) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(result, name);
  return cJSON_IsString(value) && value->valuestring && !strcmp(value->valuestring, expected);
}

int edr_command_state_result_authorized(const char *tenant, const char *endpoint,
                                        const void *body, size_t len) {
  if (!tenant || !tenant[0] || !endpoint || !endpoint[0] || !body || !len) return 0;
  cJSON *root = cJSON_ParseWithLength((const char *)body, len);
  const cJSON *result = cJSON_GetObjectItemCaseSensitive(root, "result");
  const cJSON *id = cJSON_GetObjectItemCaseSensitive(result, "command_id");
  if (!cJSON_IsString(id) || !id->valuestring || !id->valuestring[0]) {
    cJSON_Delete(root); return 0;
  }
  EdrCommandStateRecord *latest = calloc(1u, sizeof(*latest));
  char *line = malloc(EDR_COMMAND_STATE_LINE_CAP);
  if (!latest || !line) { free(latest); free(line); cJSON_Delete(root); return EDR_EGRESS_LOCAL_STATE_FAILURE; }
  char path[1024]; state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  errno=0;
  FILE *f = lock ? state_open_read_secure(path, NULL) : NULL;
  int io_failed=!lock || (!f && errno!=ENOENT);
  int valid = f != NULL;
  while (f && fgets(line, EDR_COMMAND_STATE_LINE_CAP, f)) {
    if (!strchr(line, '\n')) { valid = 0; io_failed=1; break; }
    if (!line_matches_key(line, "command_id", id->valuestring)) continue;
    EdrCommandStateRecord candidate;
    fill_record_from_line(line, &candidate);
    if (!strcmp(candidate.command_id, id->valuestring)) *latest = candidate;
  }
  if (f) { if (ferror(f)) {valid=0;io_failed=1;} fclose(f); }
  state_lock_release(lock);
  const EdrCommandResultAuthorization *a = &latest->result_authorization;
  int64_t now = state_now_ms();
  valid = valid && latest->final_record && latest->report_pending &&
      a->expires_unix_ms > 0 && a->expires_unix_ms <= now + 86700000LL &&
      !strcmp(a->tenant_id, tenant) && !strcmp(a->endpoint_id, endpoint) &&
      result_string_equal(root, "endpoint_id", endpoint) &&
      result_string_equal(result, "endpoint_id", endpoint) &&
      result_string_equal(result, "command_type", latest->command_type) &&
      result_string_equal(result, "detail_utf8", latest->detail) &&
      result_string_equal(result, "soar_correlation_id", latest->soar_correlation_id) &&
      result_string_equal(result, "playbook_run_id", latest->playbook_run_id) &&
      result_string_equal(result, "playbook_step_id", latest->playbook_step_id);
  const cJSON *status = cJSON_GetObjectItemCaseSensitive(result, "status");
  const cJSON *exit_code = cJSON_GetObjectItemCaseSensitive(result, "exit_code");
  valid = valid && cJSON_IsNumber(status) && status->valuedouble == latest->execution_status &&
      cJSON_IsNumber(exit_code) && exit_code->valuedouble == latest->exit_code;
  if (valid && !strcmp(latest->command_type, "shell_stream")) {
    /* Streams inherit the admitted session, never authority from an ID prefix alone. */
    cJSON *stream = cJSON_Parse(latest->detail);
    const cJSON *seq = cJSON_GetObjectItemCaseSensitive(stream, "seq");
    char expected[128] = "";
    if (strlen(a->command_id) < 48u && cJSON_IsNumber(seq) && seq->valuedouble >= 1 &&
        seq->valuedouble < 9007199254740992.0 &&
        seq->valuedouble == (double)(uint64_t)seq->valuedouble) {
      snprintf(expected, sizeof(expected), "%.47s.s%06llu", a->command_id,
               (unsigned long long)seq->valuedouble);
    }
    valid = !strcmp(a->command_type, "shell_open") &&
        result_string_equal(stream, "schema", "edr.shell.stream.v1") &&
        result_string_equal(stream, "session_id", a->command_id) &&
        !strcmp(expected, latest->command_id) &&
        !strcmp(latest->soar_correlation_id, a->command_id);
    cJSON_Delete(stream);
  } else if (valid) {
    valid = !strcmp(a->command_id, latest->command_id) &&
        !strcmp(a->command_type, latest->command_type);
  }
  char projected[EDR_COMMAND_STATE_DETAIL_CAP];
  valid = valid && edr_command_result_project_detail(a, latest->command_type,
      latest->execution_status, latest->exit_code, latest->detail,
      projected, sizeof(projected)) == 0 && !strcmp(projected, latest->detail);
  int decision = io_failed ? EDR_EGRESS_LOCAL_STATE_FAILURE : valid && a->expires_unix_ms <= now ? EDR_EGRESS_AUTHORIZATION_EXPIRED : valid;
  free(latest); free(line); cJSON_Delete(root);
  return decision;
}

static int mark_report_waiting(const EdrCommandStateRecord *record,
                                        const char *error,
                                        int64_t next_retry_unix_ms, int held) {
  if (!record || !record->command_id[0]) {
    return -1;
  }
  char cid[300], ctype[180], idem[1100], st[96], det[EDR_COMMAND_STATE_ESCAPED_DETAIL_CAP], art[2200];
  char scid[300], run[300], step[300], boot[100], report_error[300], line[EDR_COMMAND_STATE_LINE_CAP];
  json_escape_to(cid, sizeof(cid), record->command_id);
  json_escape_to(ctype, sizeof(ctype), record->command_type);
  json_escape_to(idem, sizeof(idem), record->idempotency_key);
  json_escape_to(st, sizeof(st), record->response_status[0] ? record->response_status : "failed");
  json_escape_to(scid, sizeof(scid), record->soar_correlation_id);
  json_escape_to(run, sizeof(run), record->playbook_run_id);
  json_escape_to(step, sizeof(step), record->playbook_step_id);
  json_escape_to(det, sizeof(det), record->detail);
  json_escape_to(art, sizeof(art), record->artifacts);
  json_escape_to(report_error, sizeof(report_error), error ? error : "result delivery failed");
  if (record->agent_boot_id[0]) {
    json_escape_to(boot, sizeof(boot), record->agent_boot_id);
  } else {
    char boot_raw[64];
    state_boot_id(boot_raw, sizeof(boot_raw));
    json_escape_to(boot, sizeof(boot), boot_raw);
  }
#ifdef _WIN32
  int pid = record->process_id ? record->process_id : _getpid();
#else
  int pid = record->process_id ? record->process_id : (int)getpid();
#endif
  int64_t now_ms = state_now_ms();
  uint32_t attempts = held ? record->report_attempts : record->report_attempts < UINT32_MAX
                          ? record->report_attempts + 1u
                          : UINT32_MAX;
  char auth[EDR_COMMAND_STATE_AUTH_CAP];
  if (authorization_json(&record->result_authorization, auth, sizeof(auth)) != 0) return -1;
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":1,"
           "\"report_policy_held\":%d,\"report_policy_version\":\"%s\","
           "\"report_attempts\":%u,\"report_last_failure_unix_ms\":%lld,"
           "\"report_next_retry_unix_ms\":%lld,\"report_last_error\":%s,"
           "\"updated_unix_ms\":%lld,\"soar_correlation_id\":%s,"
           "\"playbook_run_id\":%s,\"playbook_step_id\":%s,\"agent_boot_id\":%s,"
           "\"process_id\":%d,\"artifacts\":%s,\"detail\":%s,\"result_authorization\":%s}",
           cid, ctype, idem, st, record->execution_status, record->exit_code,
           record->retry_count, held, held ? EDR_EGRESS_POLICY_VERSION : "", attempts, (long long)now_ms,
           (long long)next_retry_unix_ms, report_error, (long long)now_ms,
           scid, run, step, boot, pid, art, det, auth);
  /* An in-flight send may report expiry after a signed renewal or ACK.
   * Serialize its retry transition with the current durable owner so stale
   * snapshots cannot undo renewal, reopen an ACK or put it back on hold. */
  FILE *lock=state_lock_acquire();if(!lock)return -1;
  char current_path[1024];state_default_path(current_path,sizeof(current_path));
  FILE *f=state_open_read_secure(current_path,NULL);
  char *current_line=malloc(EDR_COMMAND_STATE_LINE_CAP);
  EdrCommandStateRecord *current=calloc(1,sizeof(*current));
  int ok=f && current_line && current;
  while(ok && fgets(current_line,EDR_COMMAND_STATE_LINE_CAP,f)) {
    if(!strchr(current_line,'\n')){ok=0;break;}
    if(line_matches_key(current_line,"command_id",record->command_id))fill_record_from_line(current_line,current);
  }
  if(f){if(ferror(f))ok=0;fclose(f);}
  ok=ok && current->final_record && !strcmp(current->command_type,record->command_type) &&
      !strcmp(current->detail,record->detail) && current->execution_status==record->execution_status && current->exit_code==record->exit_code;
  int superseded=ok &&
      (!current->report_pending || current->result_authorization.expires_unix_ms>record->result_authorization.expires_unix_ms);
  int wrote=ok && (superseded || append_state_line(line)==0);
  free(current_line);free(current);state_lock_release(lock);
  if(!wrote)return -1;
  s_collect_cache_pending_zero = 0;
  edr_command_state_compact_if_needed();
  return 0;
}

int edr_command_state_mark_report_retry(const EdrCommandStateRecord *record,const char *error,int64_t next) {
  return mark_report_waiting(record,error,next,0);
}
int edr_command_state_mark_report_held(const EdrCommandStateRecord *record,const char *error) {
  return mark_report_waiting(record,error,0,1);
}

int edr_command_state_mark_reported(const EdrCommandStateRecord *record) {
  if (!record || !record->command_id[0]) {
    return -1;
  }
  char cid[300], ctype[180], idem[1100], st[96], det[EDR_COMMAND_STATE_ESCAPED_DETAIL_CAP], art[2200], scid[300], run[300], step[300], boot[100], report_error[300], line[EDR_COMMAND_STATE_LINE_CAP];
  json_escape_to(cid, sizeof(cid), record->command_id);
  json_escape_to(ctype, sizeof(ctype), record->command_type);
  json_escape_to(idem, sizeof(idem), record->idempotency_key);
  json_escape_to(st, sizeof(st), record->response_status[0] ? record->response_status : "ok");
  json_escape_to(scid, sizeof(scid), record->soar_correlation_id);
  json_escape_to(run, sizeof(run), record->playbook_run_id);
  json_escape_to(step, sizeof(step), record->playbook_step_id);
  json_escape_to(det, sizeof(det), record->detail);
  json_escape_to(art, sizeof(art), record->artifacts);
  json_escape_to(report_error, sizeof(report_error), record->report_last_error);
  if (record->agent_boot_id[0]) {
    json_escape_to(boot, sizeof(boot), record->agent_boot_id);
  } else {
    char boot_raw[64];
    state_boot_id(boot_raw, sizeof(boot_raw));
    json_escape_to(boot, sizeof(boot), boot_raw);
  }
#ifdef _WIN32
  int pid = record->process_id ? record->process_id : _getpid();
#else
  int pid = record->process_id ? record->process_id : (int)getpid();
#endif
  char auth[EDR_COMMAND_STATE_AUTH_CAP];
  if (authorization_json(&record->result_authorization, auth, sizeof(auth)) != 0) return -1;
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":0,"
           "\"report_attempts\":%u,\"report_last_failure_unix_ms\":%lld,"
           "\"report_next_retry_unix_ms\":0,\"report_last_error\":%s,"
           "\"updated_unix_ms\":%lld,"
           "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
           "\"agent_boot_id\":%s,\"process_id\":%d,\"artifacts\":%s,\"detail\":%s,\"result_authorization\":%s}",
           cid, ctype, idem, st, record->execution_status, record->exit_code,
           record->retry_count, record->report_attempts,
           (long long)record->report_last_failure_unix_ms,
           record->report_last_error[0] ? report_error : "\"\"",
           (long long)state_now_ms(), scid, run, step, boot, pid, art, det, auth);
  if (append_state_line_locked(line) != 0) {
    return -1;
  }
  s_collect_cache_pending_zero = 0;
  edr_command_state_compact_if_needed();
  return 0;
}

int edr_command_state_mark_report_rejected(const EdrCommandStateRecord *record,
                                           const char *error) {
  if (!record || !record->command_id[0]) {
    return -1;
  }
  EdrCommandStateRecord rejected = *record;
  snprintf(rejected.report_last_error, sizeof(rejected.report_last_error), "%s",
           error && error[0] ? error : "command result rejected by platform");
  rejected.report_last_failure_unix_ms = state_now_ms();
  return edr_command_state_mark_reported(&rejected);
}

/* Compaction may discard superseded delivery history, never the durable
 * execution/result owner. Offsets avoid retaining all result bodies in RAM. */
typedef struct CommandCompactRow {
  char command_id[128], idempotency_key[128];
  long offset;
  size_t length;
  unsigned final_record, retain;
} CommandCompactRow;
static int compact_compare_offset(const void *a,const void *b) {
  const CommandCompactRow *x=a,*y=b;
  return x->offset<y->offset?-1:x->offset>y->offset;
}
static int compact_compare_command(const void *a,const void *b) {
  const CommandCompactRow *x=a,*y=b;int order=strcmp(x->command_id,y->command_id);
  return order?order:compact_compare_offset(a,b);
}
static int compact_compare_idempotency(const void *a,const void *b) {
  const CommandCompactRow *x=a,*y=b;int order=strcmp(x->idempotency_key,y->idempotency_key);
  return order?order:compact_compare_offset(a,b);
}
static void compact_keep_latest(CommandCompactRow *rows,size_t count,int by_idempotency) {
  qsort(rows,count,sizeof(*rows),by_idempotency?compact_compare_idempotency:compact_compare_command);
  for(size_t first=0;first<count;) {
    const char *key=by_idempotency?rows[first].idempotency_key:rows[first].command_id;
    size_t end=first+1,last_final=count;
    while(end<count && !strcmp(key,by_idempotency?rows[end].idempotency_key:rows[end].command_id))end++;
    if(key[0]) {
      rows[end-1].retain=1;
      /* begin/replay checks any final before a later running marker. Keep the
       * latest final separately so compaction cannot reopen execution. */
      for(size_t i=first;i<end;i++)if(rows[i].final_record)last_final=i;
      if(last_final<count)rows[last_final].retain=1;
    }
    first=end;
  }
}

void edr_command_state_compact_if_needed(void) {
  char path[1024];state_default_path(path,sizeof(path));
  long max_bytes=state_env_long_clamped("EDR_COMMAND_STATE_MAX_BYTES",1024L*1024L,65536L,LONG_MAX);
  int64_t now_ms=state_now_ms();
  long interval_ms=state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_INTERVAL_MS",60000L,5000L,3600000L);
  EdrCommandStateFileInfo current_info={0};
  int have_current_info=state_file_info(path,&current_info)==0;
  long emergency_bytes=max_bytes<=LONG_MAX/2L?max_bytes*2L:max_bytes;
  int emergency_compact=have_current_info && current_info.size>emergency_bytes;
  /* Necessary owners can exceed the soft target indefinitely. Revisit that
   * retained floor at the normal interval, or after one max-file-size of new
   * history; a retry append must not trigger a full scan/sort every time. */
  if(emergency_compact && !strcmp(path,s_compact_retained_path) && s_compact_retained_floor>0 &&
      (current_info.size<=s_compact_retained_floor || current_info.size-s_compact_retained_floor<max_bytes))
    emergency_compact=0;
  if(!emergency_compact && s_last_compact_check_ms>0 && now_ms-s_last_compact_check_ms<interval_ms)return;
  s_last_compact_check_ms=now_ms;
  FILE *lock=state_lock_acquire();if(!lock)return;
  FILE *f=state_open_read_secure(path,NULL);
  if(!f){state_lock_release(lock);return;}
  if(fseek(f,0,SEEK_END) || ftell(f)<=max_bytes){fclose(f);state_lock_release(lock);return;}
  rewind(f);
  long target_bytes=state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_TARGET_BYTES",max_bytes/2L,32768L,max_bytes);
  size_t capacity=(size_t)state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_KEEP_LINES",300L,64L,1200L);
  /* Bounded scratch memory; reaching the limit leaves the complete original
   * file intact and observable instead of evicting live or ACKed ownership. */
  const size_t row_limit=65536u;
  CommandCompactRow *rows=calloc(capacity,sizeof(*rows));
  char *buf=malloc(EDR_COMMAND_STATE_LINE_CAP);
  size_t count=0,retained=0,retained_bytes=0;int ok=rows && buf;
  const char *failure="allocation_failed";
  while(ok) {
    long offset=ftell(f);
    if(offset<0){ok=0;failure="read_position_failed";break;}
    if(!fgets(buf,EDR_COMMAND_STATE_LINE_CAP,f))break;
    size_t length=strlen(buf);
    if(!length || buf[length-1]!='\n'){ok=0;failure="incomplete_record";break;}
    cJSON *o=edr_egress_parse_purpose_object(buf,length);
    const cJSON *id=cJSON_GetObjectItemCaseSensitive(o,"command_id");
    const cJSON *idem=cJSON_GetObjectItemCaseSensitive(o,"idempotency_key");
    const cJSON *final=cJSON_GetObjectItemCaseSensitive(o,"final");
    if(!cJSON_IsObject(o)||strcmp(result_text(o,"record"),"command_state") ||
        !cJSON_IsString(id)||!id->valuestring[0]||strlen(id->valuestring)>=128 ||
        !cJSON_IsString(idem)||strlen(idem->valuestring)>=128 || !cJSON_IsNumber(final) ||
        (final->valuedouble!=0 && final->valuedouble!=1)) {
      cJSON_Delete(o);ok=0;failure="invalid_record";break;
    }
    if(count==capacity) {
      size_t next=capacity>row_limit/2u?row_limit:capacity*2u;
      CommandCompactRow *grown=count<row_limit?realloc(rows,next*sizeof(*rows)):NULL;
      if(!grown){cJSON_Delete(o);ok=0;failure="scratch_capacity_exhausted";break;}
      rows=grown;capacity=next;
    }
    CommandCompactRow *row=&rows[count++];memset(row,0,sizeof(*row));
    strcpy(row->command_id,id->valuestring);strcpy(row->idempotency_key,idem->valuestring);
    row->offset=offset;row->length=length;row->final_record=final->valueint==1;
    cJSON_Delete(o);
  }
  if(ferror(f)){ok=0;failure="read_failed";}
  if(ok) {
    compact_keep_latest(rows,count,0);compact_keep_latest(rows,count,1);
    qsort(rows,count,sizeof(*rows),compact_compare_offset);
    for(size_t i=0;i<count;i++)if(rows[i].retain){retained++;retained_bytes+=rows[i].length;}
    if(retained_bytes>(size_t)target_bytes)
      fprintf(stderr,"[command_state] compact retained necessary owners rows=%zu bytes=%zu target=%ld\n",retained,retained_bytes,target_bytes);
  }
  char tmp[1100];tmp[0]=0;
  if(ok && retained<count) {
    snprintf(tmp,sizeof(tmp),"%s.tmp.%lld",path,(long long)state_now_ms());
    FILE *out=state_open_new_secure(tmp);
    if(!out){ok=0;failure="temporary_open_failed";}
    for(size_t i=0;out && ok && i<count;i++)if(rows[i].retain) {
      if(fseek(f,rows[i].offset,SEEK_SET) || fread(buf,1,rows[i].length,f)!=rows[i].length ||
          fwrite(buf,1,rows[i].length,out)!=rows[i].length){ok=0;failure="copy_failed";}
    }
    if(out) {
      if(state_flush_file(out)!=0){ok=0;failure="flush_failed";}
      if(fclose(out)!=0){ok=0;failure="close_failed";}
    }
  }
  if(fclose(f)!=0){ok=0;failure="read_close_failed";}
  if(tmp[0]) {
    if(ok && state_replace_file(tmp,path)!=0){ok=0;failure="replace_failed";}
    if(!ok)(void)command_inbox_delete_path(tmp);
  }
  if(!ok)fprintf(stderr,"[command_state] compact retained original state: %s\n",failure);
  s_compact_retained_floor=ok ? (retained_bytes>(size_t)target_bytes ? (long)retained_bytes : 0) : current_info.size;
  snprintf(s_compact_retained_path,sizeof(s_compact_retained_path),"%s",path);
  free(buf);free(rows);s_collect_cache_pending_zero=0;state_lock_release(lock);
}
