#include "edr/command_state.h"
#include "edr/local_evidence_cache.h"

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static int64_t state_now_ms(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static void state_ensure_parent_dir(const char *path);

static void state_default_path(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_STATE_DB");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\EDR Agent\\state\\command_state.jsonl");
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
  EdrCommandStateRecord last_final;
  memset(&last_final, 0, sizeof(last_final));
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
    return 1;
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
  FILE *lock = state_lock_acquire();
  FILE *f = fopen(path, "r");
  if (!f) {
    state_lock_release(lock);
    return 0;
  }
  size_t n = 0;
  char line[8192];
  while (fgets(line, sizeof(line), f) && n < cap) {
    if (!strstr(line, "\"final\":1") || !strstr(line, "\"report_pending\":1")) {
      continue;
    }
    fill_record_from_line(line, &out[n]);
    if (out[n].command_id[0] && out[n].detail[0]) {
      n++;
    }
  }
  fclose(f);
  state_lock_release(lock);
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
  enum { KEEP_LINES = 1200 };
  char **lines = (char **)calloc(KEEP_LINES, sizeof(char *));
  if (!lines) {
    fclose(f);
    state_lock_release(lock);
    return;
  }
  size_t idx = 0;
  char buf[8192];
  while (fgets(buf, sizeof(buf), f)) {
    free(lines[idx % KEEP_LINES]);
    lines[idx % KEEP_LINES] = strdup(buf);
    idx++;
  }
  fclose(f);
  char tmp[1100];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *out = fopen(tmp, "w");
  if (out) {
    size_t start = idx > KEEP_LINES ? idx - KEEP_LINES : 0;
    for (size_t i = start; i < idx; i++) {
      char *line = lines[i % KEEP_LINES];
      if (line) {
        fputs(line, out);
      }
    }
    fclose(out);
    (void)rename(tmp, path);
  }
  for (size_t i = 0; i < KEEP_LINES; i++) {
    free(lines[i]);
  }
  free(lines);
  state_lock_release(lock);
}
