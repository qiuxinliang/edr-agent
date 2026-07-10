#include "edr/command_util.h"
#include "edr/command_state.h"
#include "edr/config.h"
#include "edr/ingest_http.h"
#include "edr/transport_v2.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

unsigned long g_cmd_handled;
unsigned long g_cmd_rejected;
unsigned long g_cmd_exec_ok;
unsigned long g_cmd_exec_fail;

static const EdrConfig *s_bound_cfg;

void edr_command_bind_config(const struct EdrConfig *cfg) { s_bound_cfg = cfg; }

const struct EdrConfig *edr_command_get_config(void) { return s_bound_cfg; }

int edr_command_streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

int edr_command_dangerous_enabled(void) {
  const char *e = getenv("EDR_CMD_ENABLED");
  if (e && e[0] == '1') {
    return 1;
  }
  if (e && e[0] == '0') {
    return 0;
  }
  e = getenv("EDR_CMD_DANGEROUS");
  if (e && e[0] == '1') {
    return 1;
  }
  if (e && e[0] == '0') {
    return 0;
  }
  /* fail-safe 默认:未显式开启则禁止高危指令（与原 command_stub.c 语义一致）。 */
  if (s_bound_cfg && s_bound_cfg->command.allow_dangerous) {
    return 1;
  }
  return 0;
}

int edr_command_rtq_readonly_enabled(void) {
  const char *e = getenv("EDR_RTQ_READONLY_ENABLED");
  if (e && e[0] == '1') {
    return 1;
  }
  if (e && e[0] == '0') {
    return 0;
  }
  if (edr_command_dangerous_enabled()) {
    return 1;
  }
  if (s_bound_cfg) {
    return s_bound_cfg->command.allow_rtq_readonly ? 1 : 0;
  }
  return 1;
}

int edr_command_kill_pid_allowed(long pid) {
  const char *list = getenv("EDR_CMD_KILL_ALLOWLIST");
  if (!list || !list[0]) {
    return 1;
  }
  char buf[1024];
  size_t n = strlen(list);
  if (n >= sizeof(buf)) {
    n = sizeof(buf) - 1u;
  }
  memcpy(buf, list, n);
  buf[n] = 0;
  char *p = buf;
  while (p && *p) {
    char *comma = strchr(p, ',');
    if (comma) {
      *comma++ = 0;
    }
    while (*p == ' ' || *p == '\t') {
      p++;
    }
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end != p && v == pid) {
      return 1;
    }
    p = comma;
  }
  return 0;
}

void edr_command_audit_both(const char *cmd_id, const char *msg) {
  fprintf(stderr, "[command][audit] id=%s %s\n", cmd_id ? cmd_id : "", msg);
  const char *ap = getenv("EDR_CMD_AUDIT_PATH");
  if (!ap || !ap[0]) {
    return;
  }
  FILE *f = fopen(ap, "a");
  if (!f) {
    return;
  }
  time_t t = time(NULL);
#ifdef _WIN32
  struct tm tmst;
  localtime_s(&tmst, &t);
#else
  struct tm tmst;
  localtime_r(&t, &tmst);
#endif
  char ts[40];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmst);
  fprintf(f, "%s id=%s %s\n", ts, cmd_id ? cmd_id : "", msg);
  fclose(f);
}

int edr_command_soar_want_report(const EdrSoarCommandMeta *m) {
  const char *a = getenv("EDR_SOAR_REPORT_ALWAYS");
  if (a && a[0] == '1') {
    return 1;
  }
  if (!m) {
    return 0;
  }
  return m->soar_correlation_id[0] || m->playbook_run_id[0];
}

void edr_command_soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm,
                           EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  if (!edr_command_soar_want_report(sm)) {
    return;
  }
  int ok = -1;
  if (edr_ingest_http_configured()) {
    ok = edr_transport_v2_command_result(cmd_id, sm, (int)st, exit_code, detail ? detail : "");
  }
  (void)ok;
}

static const char *command_response_status_label(EdrCommandExecutionStatus st) {
  switch (st) {
    case EdrCmdExecOk:
      return "ok";
    case EdrCmdExecRejected:
      return "denied";
    case EdrCmdExecFailed:
      return "failed";
    case EdrCmdExecUnknownType:
      return "unknown_type";
    default:
      return "unknown";
  }
}

void edr_command_emit_always_typed(const char *cmd_id, const char *command_type,
                                   const EdrSoarCommandMeta *sm,
                                   EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  edr_command_audit_both(cmd_id, detail);
  int report_pending = 0;
  if (edr_ingest_http_configured()) {
    const EdrSoarCommandMeta *report_meta = edr_command_soar_want_report(sm) ? sm : NULL;
    fprintf(stderr, "[cmd_emit_always] HTTP reporting id=%s st=%d\n", cmd_id ? cmd_id : "", (int)st);
    int rc = edr_transport_v2_command_result(cmd_id, report_meta, (int)st, exit_code, detail ? detail : "");
    fprintf(stderr, "[cmd_emit_always] HTTP report rc=%d\n", rc);
    report_pending = (rc != 0);
  } else {
    fprintf(stderr, "[cmd_emit_always] HTTP NOT configured id=%s\n", cmd_id ? cmd_id : "");
  }
  edr_command_state_finish(cmd_id, command_type ? command_type : "", sm, command_response_status_label(st), (int)st, exit_code,
                           detail ? detail : "", "", report_pending);
}

void edr_command_emit_always(const char *cmd_id, const EdrSoarCommandMeta *sm,
                             EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  edr_command_emit_always_typed(cmd_id, "", sm, st, exit_code, detail);
}

int edr_command_parse_pid_json(const uint8_t *p, size_t len, long *out_pid) {
  *out_pid = -1;
  if (!p || len == 0u) {
    return -1;
  }
  char tmp[4096];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char *q = strstr(tmp, "\"pid\"");
  if (!q) {
    q = strstr(tmp, "pid");
  }
  if (!q) {
    return -1;
  }
  char *colon = strchr(q, ':');
  char *start = colon ? colon + 1 : q;
  while (*start && (isspace((unsigned char)*start) || *start == '"' || *start == '\'')) {
    start++;
  }
  *out_pid = strtol(start, NULL, 10);
  if (*out_pid <= 0 || *out_pid > 0x7fffffffL) {
    return -1;
  }
  return 0;
}

int edr_command_parse_path_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  if (!p || len == 0u || !out || outcap < 4u) {
    return -1;
  }
  char tmp[8192];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  char *path_key = strstr(tmp, "\"path\"");
  if (!path_key) {
    return -1;
  }
  char *colon = strchr(path_key, ':');
  if (!colon) {
    return -1;
  }
  char *q = strchr(colon + 1, '"');
  if (!q) {
    return -1;
  }
  q++;
  char *end = strchr(q, '"');
  if (!end) {
    return -1;
  }
  size_t n = (size_t)(end - q);
  if (n == 0u || n >= outcap) {
    return -1;
  }
  memcpy(out, q, n);
  out[n] = 0;
  return 0;
}

int edr_command_parse_server_address_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  if (!p || len == 0u || !out || outcap < 8u) {
    return -1;
  }
  char tmp[2048];
  if (len >= sizeof(tmp)) {
    len = sizeof(tmp) - 1u;
  }
  memcpy(tmp, p, len);
  tmp[len] = 0;
  const char *keys[] = {"\"server_address\"", "\"server_addr\"", "\"address\""};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    char *k = strstr(tmp, keys[i]);
    if (!k) {
      continue;
    }
    char *colon = strchr(k, ':');
    if (!colon) {
      continue;
    }
    char *q = strchr(colon + 1, '"');
    if (!q) {
      continue;
    }
    q++;
    char *end = strchr(q, '"');
    if (!end) {
      continue;
    }
    size_t n = (size_t)(end - q);
    if (n == 0u || n >= outcap) {
      return -1;
    }
    memcpy(out, q, n);
    out[n] = 0;
    return 0;
  }
  return -1;
}
