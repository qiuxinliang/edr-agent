#include "edr/command_state.h"

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
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static int64_t state_now_ms(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static void state_default_path(char *out, size_t cap) {
  const char *p = getenv("EDR_COMMAND_STATE_DB");
  if (p && p[0]) {
    snprintf(out, cap, "%s", p);
    return;
  }
#ifdef _WIN32
  p = getenv("ProgramData");
  if (!p || !p[0]) {
    p = getenv("TEMP");
  }
  if (!p || !p[0]) {
    p = ".";
  }
  snprintf(out, cap, "%s\\EDR\\command_state.jsonl", p);
#else
  snprintf(out, cap, "%s", "/tmp/edr_command_state.jsonl");
#endif
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

static int count_prior_attempts(const char *command_id, const EdrSoarCommandMeta *meta) {
  char path[1024];
  state_default_path(path, sizeof(path));
  FILE *f = fopen(path, "r");
  if (!f) {
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
  return 0;
}

void edr_command_state_finish(const char *command_id, const char *command_type,
                              const EdrSoarCommandMeta *meta, const char *response_status,
                              int execution_status, int exit_code, const char *detail,
                              const char *artifacts, int report_pending) {
  int retry = count_prior_attempts(command_id, meta);
  char idem_key[128];
  state_idempotency_key(meta, idem_key, sizeof(idem_key));
  char cid[300], ctype[180], idem[300], st[96], det[4200], art[2200], line[7600];
  json_escape_to(cid, sizeof(cid), command_id ? command_id : "");
  json_escape_to(ctype, sizeof(ctype), command_type ? command_type : "");
  json_escape_to(idem, sizeof(idem), idem_key);
  json_escape_to(st, sizeof(st), response_status ? response_status : "failed");
  json_escape_to(det, sizeof(det), detail ? detail : "");
  json_escape_to(art, sizeof(art), artifacts ? artifacts : "");
  snprintf(line, sizeof(line),
           "{\"record\":\"command_state\",\"final\":1,\"command_id\":%s,\"command_type\":%s,"
           "\"idempotency_key\":%s,\"response_status\":%s,\"execution_status\":%d,"
           "\"exit_code\":%d,\"retry_count\":%d,\"report_pending\":%d,\"updated_unix_ms\":%lld,"
           "\"artifacts\":%s,\"detail\":%s}",
           cid, ctype, idem, st, execution_status, exit_code, retry, report_pending ? 1 : 0,
           (long long)state_now_ms(), art, det);
  append_state_line(line);
}
