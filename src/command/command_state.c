#include "edr/command_state.h"
#include "edr/local_evidence_cache.h"

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <dirent.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#endif

typedef struct EdrCommandStateFileInfo {
  long size;
  long mtime;
} EdrCommandStateFileInfo;

static EdrCommandStateFileInfo s_collect_cache_info;
static int s_collect_cache_pending_zero;
static int64_t s_last_compact_check_ms;

static long state_env_long_clamped(const char *name, long defv, long minv, long maxv);
static void state_ensure_dir(const char *path);

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

static void state_ensure_parent_dir(const char *path);

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
  if (stat(path, &st) != 0) {
    return -1;
  }
  out->size = (long)st.st_size;
  out->mtime = (long)st.st_mtime;
  return 0;
}

static int state_file_info_same(EdrCommandStateFileInfo a, EdrCommandStateFileInfo b) {
  return a.size == b.size && a.mtime == b.mtime;
}

static int state_replace_file(const char *tmp_path, const char *dst_path) {
  if (!tmp_path || !tmp_path[0] || !dst_path || !dst_path[0]) {
    return -1;
  }
#ifdef _WIN32
  if (MoveFileExA(tmp_path, dst_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return 0;
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

static char *state_strdup_line(const char *s) {
  if (!s) {
    return NULL;
  }
  size_t n = strlen(s) + 1u;
  char *p = (char *)malloc(n);
  if (!p) {
    return NULL;
  }
  memcpy(p, s, n);
  return p;
}

static void state_default_path(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_STATE_DB");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\state\\command_state.jsonl");
#else
  snprintf(out, cap, "%s", "/tmp/edr_command_state.jsonl");
#endif
}

static FILE *state_lock_acquire(void) {
  char path[1024], lock_path[1100];
  state_default_path(path, sizeof(path));
  state_ensure_parent_dir(path);
  snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
  FILE *f = fopen(lock_path, "a+b");
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
    return 0;
  }
#else
  if (mkdir(path, 0755) == 0 || errno == EEXIST) {
    return 0;
  }
#endif
  return -1;
}

static void state_ensure_parent_dir(const char *path) {
  char tmp[1024];
  if (!path || strlen(path) >= sizeof(tmp)) {
    return;
  }
  snprintf(tmp, sizeof(tmp), "%s", path);
  char *last = NULL;
  for (char *p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\') {
      last = p;
    }
  }
  if (!last) {
    return;
  }
  *last = '\0';
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
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *p = strstr(line, pat);
  if (!p) {
    return;
  }
  p += strlen(pat);
  size_t o = 0;
  while (*p && o + 1u < cap) {
    if (*p == '"' && (p == line || p[-1] != '\\')) {
      break;
    }
    if (*p == '\\' && p[1]) {
      p++;
    }
    out[o++] = *p++;
  }
  out[o] = '\0';
}

static int parse_json_int_field_line(const char *line, const char *key, int defv) {
  if (!line || !key) {
    return defv;
  }
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(line, pat);
  if (!p) {
    return defv;
  }
  p += strlen(pat);
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  return (int)strtol(p, NULL, 10);
}

static int64_t parse_json_int64_field_line(const char *line, const char *key, int64_t defv) {
  if (!line || !key) {
    return defv;
  }
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(line, pat);
  if (!p) {
    return defv;
  }
  p += strlen(pat);
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  return strtoll(p, NULL, 10);
}

static char *parse_json_string_field_alloc(const char *line, const char *key) {
  if (!line || !key) {
    return NULL;
  }
  char pat[96];
  snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *p = strstr(line, pat);
  if (!p) {
    return NULL;
  }
  p += strlen(pat);
  char *out = (char *)malloc(strlen(p) + 1u);
  if (!out) {
    return NULL;
  }
  size_t o = 0;
  while (*p) {
    if (*p == '"' && (p == line || p[-1] != '\\')) {
      break;
    }
    if (*p == '\\' && p[1]) {
      p++;
    }
    out[o++] = *p++;
  }
  out[o] = '\0';
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
  out->execution_status = parse_json_int_field_line(line, "execution_status", 0);
  out->exit_code = parse_json_int_field_line(line, "exit_code", 0);
  out->retry_count = parse_json_int_field_line(line, "retry_count", 0);
  out->final_record = parse_json_int_field_line(line, "final", 0);
  out->report_pending = parse_json_int_field_line(line, "report_pending", 0);
  {
    const char *p = strstr(line, "\"updated_unix_ms\"");
    if (p) {
      p = strchr(p, ':');
      if (p) {
        out->updated_unix_ms = strtoll(p + 1, NULL, 10);
      }
    }
  }
}

static void command_inbox_default_dir(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_INBOX_DIR");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\state\\command_inbox");
#else
  snprintf(out, cap, "%s", "/tmp/edr_command_inbox");
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

static int command_state_has_final(const char *command_id, const EdrSoarCommandMeta *meta) {
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  FILE *f = fopen(path, "r");
  if (!f) {
    state_lock_release(lock);
    return 0;
  }
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  int found = 0;
  char line[8192];
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "\"final\":1")) {
      continue;
    }
    int match = 0;
    if (idem_key[0]) {
      match = line_matches_key(line, "idempotency_key", idem_key);
    } else if (command_id && command_id[0]) {
      match = line_matches_key(line, "command_id", command_id);
    }
    if (match) {
      found = 1;
      break;
    }
  }
  fclose(f);
  state_lock_release(lock);
  return found;
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
  state_ensure_dir(dir);
  snprintf(tmp, sizeof(tmp), "%s.tmp.%lld", path, (long long)state_now_ms());
  FILE *f = fopen(tmp, "wb");
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
  fprintf(f,
          "{\"record\":\"command_inbox\",\"command_id\":%s,\"command_type\":%s,"
          "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
          "\"idempotency_key\":%s,\"issued_at_unix_ms\":%lld,\"deadline_ms\":%u,"
          "\"initiated_by\":%s,\"received_unix_ms\":%lld,\"payload_hex\":\"",
          cid, ctype, scid, run, step, idem, (long long)sm->issued_at_unix_ms,
          (unsigned)sm->deadline_ms, by, (long long)state_now_ms());
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
  if (stat(path, &st) != 0 || st.st_size < 0) {
    return -1;
  }
  long max_bytes = state_env_long_clamped("EDR_COMMAND_INBOX_MAX_BYTES",
                                          16L * 1024L * 1024L,
                                          1024L, 256L * 1024L * 1024L);
  if (st.st_size > max_bytes) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
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
  if (got == 0u) {
    free(buf);
    return -1;
  }
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
  out->meta.issued_at_unix_ms = parse_json_int64_field_line(buf, "issued_at_unix_ms", 0);
  int64_t deadline_ms = parse_json_int64_field_line(buf, "deadline_ms", 0);
  if (deadline_ms > 0 && deadline_ms <= 0xffffffffLL) {
    out->meta.deadline_ms = (uint32_t)deadline_ms;
  }
  out->received_unix_ms = parse_json_int64_field_line(buf, "received_unix_ms", 0);
  char *payload_hex = parse_json_string_field_alloc(buf, "payload_hex");
  free(buf);
  if (!out->command_id[0] || !payload_hex) {
    free(payload_hex);
    return -1;
  }
  int rc = hex_decode_alloc(payload_hex, &out->payload, &out->payload_len);
  free(payload_hex);
  if (rc != 0) {
    edr_command_state_free_inbox_record(out);
    return -1;
  }
  return 0;
}

static int command_inbox_name_is_record(const char *name) {
  if (!name || name[0] == '.') {
    return 0;
  }
  size_t n = strlen(name);
  return n > 5u && strcmp(name + n - 5u, ".json") == 0;
}

int edr_command_state_collect_inbox(EdrCommandInboxRecord *out, size_t cap) {
  if (!out || cap == 0u) {
    return 0;
  }
  char dir[1024];
  command_inbox_default_dir(dir, sizeof(dir));
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
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
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
    if (command_inbox_read_file(path, &rec) != 0) {
      continue;
    }
    if (command_state_has_final(rec.command_id, &rec.meta)) {
      edr_command_state_free_inbox_record(&rec);
      (void)command_inbox_delete_path(path);
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

void edr_command_state_delete_inbox(const char *command_id) {
  if (!command_id || !command_id[0]) {
    return;
  }
  char path[1200];
  if (command_inbox_record_path(command_id, path, sizeof(path)) != 0) {
    return;
  }
  FILE *lock = state_lock_acquire();
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

static void append_state_line(const char *line) {
  char path[1024];
  state_default_path(path, sizeof(path));
  state_ensure_parent_dir(path);
  FILE *f = fopen(path, "a");
  if (!f) {
    return;
  }
  fputs(line, f);
  fputc('\n', f);
  fclose(f);
}

static void append_state_line_locked(const char *line) {
  FILE *lock = state_lock_acquire();
  append_state_line(line);
  state_lock_release(lock);
}

static int count_prior_attempts(const char *command_id, const EdrSoarCommandMeta *meta) {
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *lock = state_lock_acquire();
  FILE *f = fopen(path, "r");
  if (!f) {
    state_lock_release(lock);
    return 0;
  }
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  int retry = 0;
  char line[8192];
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
  FILE *f = fopen(path, "r");
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
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
      int match = 0;
      if (idem_key[0]) {
        match = line_matches_key(line, "idempotency_key", idem_key);
      } else if (command_id && command_id[0]) {
        match = line_matches_key(line, "command_id", command_id);
      }
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

  char cid[300], ctype[180], idem[300], line[1200];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":0,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":\"started\",\"execution_status\":0,"
           "\"exit_code\":0,\"retry_count\":%d,\"report_pending\":0,\"updated_unix_ms\":%lld}",
           cid, ctype, idem, retry, (long long)state_now_ms());
  append_state_line(line);
  state_lock_release(lock);
  return 0;
}

void edr_command_state_finish(const char *command_id, const char *command_type,
                              const EdrSoarCommandMeta *meta, const char *response_status,
                              int execution_status, int exit_code, const char *detail,
                              const char *artifacts, int report_pending) {
  int retry = count_prior_attempts(command_id, meta);
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  char cid[300], ctype[180], idem[300], st[96], det[4200], art[2200], scid[300], run[300], step[300], line[12288];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  json_escape_to(st, sizeof(st), response_status ? response_status : "failed");
  json_escape_to(scid, sizeof(scid), meta ? meta->soar_correlation_id : "");
  json_escape_to(run, sizeof(run), meta ? meta->playbook_run_id : "");
  json_escape_to(step, sizeof(step), meta ? meta->playbook_step_id : "");
  json_escape_to(det, sizeof(det), detail ? detail : "");
  json_escape_to(art, sizeof(art), artifacts ? artifacts : "");
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":%d,\"updated_unix_ms\":%lld,"
           "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
           "\"artifacts\":%s,\"detail\":%s}",
           cid, ctype, idem, st, execution_status, exit_code, retry, report_pending ? 1 : 0,
           (long long)state_now_ms(), scid, run, step, art, det);
  append_state_line_locked(line);
  edr_local_evidence_cache_record_command_result(
      command_id, command_type, response_status ? response_status : "failed",
      execution_status, exit_code, detail, artifacts);
  edr_command_state_compact_if_needed();
}

int edr_command_state_collect_pending(EdrCommandStateRecord *out, size_t cap) {
  if (!out || cap == 0u) {
    return 0;
  }
  char path[1024];
  state_default_path(path, sizeof(path));
  EdrCommandStateFileInfo info;
  if (state_file_info(path, &info) != 0) {
    s_collect_cache_pending_zero = 1;
    memset(&s_collect_cache_info, 0, sizeof(s_collect_cache_info));
    return 0;
  }
  if (s_collect_cache_pending_zero && state_file_info_same(info, s_collect_cache_info)) {
    return 0;
  }

  enum { MAX_TRACKED_COMMANDS = 512 };
  EdrCommandStateRecord *latest =
      (EdrCommandStateRecord *)calloc(MAX_TRACKED_COMMANDS, sizeof(EdrCommandStateRecord));
  if (!latest) {
    return 0;
  }
  FILE *lock = state_lock_acquire();
  FILE *f = fopen(path, "r");
  if (!f) {
    state_lock_release(lock);
    free(latest);
    return 0;
  }
  size_t latest_n = 0;
  char line[8192];
  while (fgets(line, sizeof(line), f)) {
    EdrCommandStateRecord rec;
    if (!strstr(line, "\"final\":1")) {
      continue;
    }
    fill_record_from_line(line, &rec);
    if (!rec.command_id[0]) {
      continue;
    }
    size_t idx = latest_n;
    for (size_t i = 0; i < latest_n; i++) {
      if (strcmp(latest[i].command_id, rec.command_id) == 0) {
        idx = i;
        break;
      }
    }
    if (idx == latest_n) {
      if (latest_n >= MAX_TRACKED_COMMANDS) {
        continue;
      }
      latest_n++;
    }
    latest[idx] = rec;
  }
  fclose(f);
  state_lock_release(lock);
  size_t n = 0;
  for (size_t i = 0; i < latest_n && n < cap; i++) {
    if (latest[i].report_pending && latest[i].command_id[0] && latest[i].detail[0]) {
      out[n++] = latest[i];
    }
  }
  free(latest);
  if (n == 0u) {
    s_collect_cache_info = info;
    s_collect_cache_pending_zero = 1;
  } else {
    s_collect_cache_pending_zero = 0;
  }
  return (int)n;
}

void edr_command_state_mark_reported(const EdrCommandStateRecord *record) {
  if (!record || !record->command_id[0]) {
    return;
  }
  char cid[300], ctype[180], idem[300], st[96], det[4200], art[2200], scid[300], run[300], step[300], line[12288];
  json_escape_to(cid, sizeof(cid), record->command_id);
  json_escape_to(ctype, sizeof(ctype), record->command_type);
  json_escape_to(idem, sizeof(idem), record->idempotency_key);
  json_escape_to(st, sizeof(st), record->response_status[0] ? record->response_status : "ok");
  json_escape_to(scid, sizeof(scid), record->soar_correlation_id);
  json_escape_to(run, sizeof(run), record->playbook_run_id);
  json_escape_to(step, sizeof(step), record->playbook_step_id);
  json_escape_to(det, sizeof(det), record->detail);
  json_escape_to(art, sizeof(art), record->artifacts);
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":0,\"updated_unix_ms\":%lld,"
           "\"soar_correlation_id\":%s,\"playbook_run_id\":%s,\"playbook_step_id\":%s,"
           "\"artifacts\":%s,\"detail\":%s}",
           cid, ctype, idem, st, record->execution_status, record->exit_code, record->retry_count,
           (long long)state_now_ms(), scid, run, step, art, det);
  append_state_line_locked(line);
  s_collect_cache_pending_zero = 0;
  edr_command_state_compact_if_needed();
}

void edr_command_state_compact_if_needed(void) {
  char path[1024];
  state_default_path(path, sizeof(path));
  long max_bytes = 1024L * 1024L;
  const char *env = getenv("EDR_COMMAND_STATE_MAX_BYTES");
  if (env && env[0]) {
    long v = strtol(env, NULL, 10);
    if (v >= 65536L) {
      max_bytes = v;
    }
  }
  int64_t now_ms = state_now_ms();
  long interval_ms = state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_INTERVAL_MS",
                                            60000L, 5000L, 3600000L);
  EdrCommandStateFileInfo current_info;
  int have_current_info = state_file_info(path, &current_info) == 0;
  long emergency_bytes = max_bytes > 0 && max_bytes <= (LONG_MAX / 2L) ? max_bytes * 2L : max_bytes;
  int emergency_compact = have_current_info && current_info.size > emergency_bytes;
  if (!emergency_compact && s_last_compact_check_ms > 0 && now_ms - s_last_compact_check_ms < interval_ms) {
    return;
  }
  s_last_compact_check_ms = now_ms;

  FILE *lock = state_lock_acquire();
  FILE *f = fopen(path, "r");
  if (!f) {
    state_lock_release(lock);
    return;
  }
  if (fseek(f, 0, SEEK_END) != 0 || ftell(f) <= max_bytes) {
    fclose(f);
    state_lock_release(lock);
    return;
  }
  rewind(f);
  long keep_lines_long = state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_KEEP_LINES",
                                                300L, 64L, 1200L);
  long target_bytes = state_env_long_clamped("EDR_COMMAND_STATE_COMPACT_TARGET_BYTES",
                                             max_bytes / 2L, 32768L, max_bytes);
  size_t keep_lines = (size_t)keep_lines_long;
  char **lines = (char **)calloc(keep_lines, sizeof(char *));
  size_t *line_lens = (size_t *)calloc(keep_lines, sizeof(size_t));
  if (!lines || !line_lens) {
    free(lines);
    free(line_lens);
    fclose(f);
    state_lock_release(lock);
    return;
  }
  size_t idx = 0;
  size_t retained_bytes = 0u;
  char buf[8192];
  while (fgets(buf, sizeof(buf), f)) {
    size_t slot = idx % keep_lines;
    if (lines[slot]) {
      retained_bytes = retained_bytes >= line_lens[slot] ? retained_bytes - line_lens[slot] : 0u;
      free(lines[slot]);
      lines[slot] = NULL;
      line_lens[slot] = 0u;
    }
    lines[slot] = state_strdup_line(buf);
    if (lines[slot]) {
      line_lens[slot] = strlen(lines[slot]);
      retained_bytes += line_lens[slot];
    }
    idx++;
  }
  fclose(f);
  size_t start = idx > keep_lines ? idx - keep_lines : 0u;
  while (start + 1u < idx && retained_bytes > (size_t)target_bytes) {
    size_t slot = start % keep_lines;
    if (lines[slot]) {
      retained_bytes = retained_bytes >= line_lens[slot] ? retained_bytes - line_lens[slot] : 0u;
    }
    start++;
  }
  char tmp[1100];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *out = fopen(tmp, "w");
  if (out) {
    for (size_t i = start; i < idx; i++) {
      char *line = lines[i % keep_lines];
      if (line) {
        fputs(line, out);
      }
    }
    fclose(out);
    (void)state_replace_file(tmp, path);
  }
  for (size_t i = 0; i < keep_lines; i++) {
    free(lines[i]);
  }
  free(line_lens);
  free(lines);
  s_collect_cache_pending_zero = 0;
  state_lock_release(lock);
}
