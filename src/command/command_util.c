#include "edr/command_util.h"
#include "edr/command_cancel.h"
#include "edr/command_state.h"
#include "edr/config.h"
#include "edr/forensic_result_contract.h"
#include "edr/ingest_http.h"
#include "edr/shell_exec.h"
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
#ifdef _MSC_VER
static __declspec(thread) char s_active_command_type[64];
#else
static _Thread_local char s_active_command_type[64];
#endif
static const char *command_response_status_label(EdrCommandExecutionStatus st);

static void command_apply_cancel_override(const char *cmd_id,
                                          EdrCommandExecutionStatus *st,
                                          int *exit_code, const char **detail,
                                          const char **response_status,
                                          char *cancel_detail,
                                          size_t cancel_detail_cap) {
  if (!cmd_id || !st || !exit_code || !detail || !response_status ||
      !cancel_detail || cancel_detail_cap == 0u ||
      !edr_command_cancel_requested(cmd_id) || *exit_code == 130 ||
      (*response_status && strcmp(*response_status, "cancelled") == 0)) {
    return;
  }
  snprintf(cancel_detail, cancel_detail_cap,
           "cancellation requested while action was running; backend returned status=%s exit=%d detail=%.1200s",
           command_response_status_label(*st), *exit_code,
           *detail ? *detail : "");
  *st = EdrCmdExecFailed;
  *exit_code = 130;
  *detail = cancel_detail;
  *response_status = "cancelled";
}

void edr_command_bind_config(const struct EdrConfig *cfg) { s_bound_cfg = cfg; }

void edr_command_set_active_type(const char *command_type) {
  snprintf(s_active_command_type, sizeof(s_active_command_type), "%s", command_type ? command_type : "");
}

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
  char cancel_detail[1536];
  const char *response_status = NULL;
  command_apply_cancel_override(cmd_id, &st, &exit_code, &detail,
                                &response_status, cancel_detail,
                                sizeof(cancel_detail));
  int should_report = edr_command_soar_want_report(sm) ||
                      (cmd_id && strncmp(cmd_id, "cmd_", 4u) == 0);
  if (edr_command_state_finish(cmd_id, s_active_command_type, sm,
                               response_status ? response_status : command_response_status_label(st),
                               (int)st, exit_code, detail ? detail : "", "",
                               should_report && edr_ingest_http_configured()) == 0) {
    edr_command_state_delete_inbox(cmd_id);
  }
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

void edr_command_emit_always_typed_status(const char *cmd_id, const char *command_type,
                                          const EdrSoarCommandMeta *sm,
                                          EdrCommandExecutionStatus st, int exit_code,
                                          const char *detail, const char *response_status) {
  char cancel_detail[1536];
  command_apply_cancel_override(cmd_id, &st, &exit_code, &detail,
                                &response_status, cancel_detail,
                                sizeof(cancel_detail));
  char forensic_detail[8192];
  detail = edr_command_normalize_forensic_result(command_type, st, exit_code, detail,
                                                 forensic_detail, sizeof(forensic_detail));
  edr_command_audit_both(cmd_id, detail);
  if (edr_command_state_finish(cmd_id, command_type ? command_type : "", sm,
                               response_status && response_status[0]
                                   ? response_status
                                   : command_response_status_label(st),
                               (int)st, exit_code,
                               detail ? detail : "", "", edr_ingest_http_configured()) == 0) {
    edr_command_state_delete_inbox(cmd_id);
  }
}

void edr_command_emit_always_typed(const char *cmd_id, const char *command_type,
                                   const EdrSoarCommandMeta *sm,
                                   EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  edr_command_emit_always_typed_status(cmd_id, command_type, sm, st, exit_code,
                                       detail, NULL);
}

void edr_command_emit_always(const char *cmd_id, const EdrSoarCommandMeta *sm,
                             EdrCommandExecutionStatus st, int exit_code, const char *detail) {
  edr_command_emit_always_typed(cmd_id, s_active_command_type, sm, st, exit_code, detail);
}

int edr_command_parse_pid_json(const uint8_t *p, size_t len, long *out_pid) {
  int pid = -1;
  if (!out_pid || !edr_parse_json_int(p, len, "pid", &pid) || pid <= 0) {
    return -1;
  }
  *out_pid = (long)pid;
  return 0;
}

int edr_command_parse_path_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  return edr_parse_json_string(p, len, "path", out, outcap) && out[0] ? 0 : -1;
}

int edr_command_parse_server_address_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  const char *keys[] = {"server_address", "server_addr", "address"};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    if (edr_parse_json_string(p, len, keys[i], out, outcap) && out[0]) {
      return 0;
    }
  }
  return -1;
}
