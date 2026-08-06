/* §8 响应指令执行器 — HTTPS control 分发；高危操作需 EDR_CMD_ENABLED=1；AVE 见 ave_* */

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_NONSTDC_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif
#endif

#include "edr/attack_surface_report.h"
#include "edr/agent_update_command.h"
#include "edr/agent_lifecycle_command.h"
#include "edr/command.h"
#include "edr/command_cancel.h"
#include "edr/command_contract.h"
#include "edr/command_executor.h"
#include "edr/command_registry.h"
#include "edr/command_state.h"
#include "edr/command_util.h"
#include "edr/deep_collector.h"
#include "edr/ave.h"
#include "edr/ave_sdk.h"
#include "edr/config.h"
#include "edr/error.h"
#include "edr/event_batch.h"
#include "edr/forensic_result_contract.h"
#include "edr/ingest_http.h"
#include "edr/local_evidence_cache.h"
#include "edr/pmfe.h"
#include "edr/policy_v2.h"
#include "edr/preprocess.h"
#include "edr/response.h"
#include "edr/resource.h"
#include "edr/transport_v2.h"
#include "edr/self_protect.h"
#include "edr/sha256.h"
#include "edr/shell_exec.h"
#include "edr/shell_session.h"
#include "cJSON.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* MSVC 无 POSIX strcasecmp:映射到 _stricmp(POSIX 编译时此宏不生效)。 */
#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#if defined(EDR_HAVE_OPENSSL_HTTP) || defined(EDR_HAVE_OPENSSL_FL)
#define EDR_HAVE_COMMAND_SIGNATURE_OPENSSL 1
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <winevt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#pragma comment(lib, "wintrust.lib")
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#endif

static unsigned long s_handled;
static unsigned long s_unknown;
static unsigned long s_rejected;
static unsigned long s_exec_ok;
static unsigned long s_exec_fail;
#ifdef _MSC_VER
static __declspec(thread) char s_active_command_type[96];
#else
static _Thread_local char s_active_command_type[96];
#endif

static void command_set_active_type_owned(const char *command_type) {
  snprintf(s_active_command_type, sizeof(s_active_command_type), "%s",
           command_type ? command_type : "");
  edr_command_set_active_type(s_active_command_type);
}
/* PMFE workers must not perform transport I/O. Keep terminal results until
 * the normal command poll loop can persist and emit them. */
#define PMFE_COMPLETION_CAP 32
typedef struct {
  int used;
  char command_id[96];
  uint32_t pid;
  int scan_status;
  char detail[1200];
  EdrPmfeScanResult result;
  EdrPmfeCommandContext context;
} PmfeCompletion;
static PmfeCompletion s_pmfe_completions[PMFE_COMPLETION_CAP];
#ifdef _WIN32
static CRITICAL_SECTION s_pmfe_completion_lock;
static volatile LONG s_pmfe_completion_lock_ready;
static void pmfe_completion_lock_init(void) {
  LONG state = InterlockedCompareExchange(&s_pmfe_completion_lock_ready, 1, 0);
  if (state == 0) {
    InitializeCriticalSection(&s_pmfe_completion_lock);
    InterlockedExchange(&s_pmfe_completion_lock_ready, 2);
  } else {
    while (InterlockedCompareExchange(&s_pmfe_completion_lock_ready, 0, 0) == 1) {
      Sleep(0);
    }
  }
}
static void pmfe_completion_lock(void) {
  pmfe_completion_lock_init();
  EnterCriticalSection(&s_pmfe_completion_lock);
}
static void pmfe_completion_unlock(void) { LeaveCriticalSection(&s_pmfe_completion_lock); }
#else
static pthread_mutex_t s_pmfe_completion_lock = PTHREAD_MUTEX_INITIALIZER;
static void pmfe_completion_lock(void) { pthread_mutex_lock(&s_pmfe_completion_lock); }
static void pmfe_completion_unlock(void) { pthread_mutex_unlock(&s_pmfe_completion_lock); }
#endif

#ifdef _WIN32
static CRITICAL_SECTION s_delivery_health_lock;
static volatile LONG s_delivery_health_lock_ready;
static void delivery_health_lock_init(void) {
  LONG state = InterlockedCompareExchange(&s_delivery_health_lock_ready, 1, 0);
  if (state == 0) {
    InitializeCriticalSection(&s_delivery_health_lock);
    InterlockedExchange(&s_delivery_health_lock_ready, 2);
  } else {
    while (InterlockedCompareExchange(&s_delivery_health_lock_ready, 0, 0) == 1) {
      Sleep(0);
    }
  }
}
static void delivery_health_lock(void) {
  delivery_health_lock_init();
  EnterCriticalSection(&s_delivery_health_lock);
}
static void delivery_health_unlock(void) { LeaveCriticalSection(&s_delivery_health_lock); }
#else
static pthread_mutex_t s_delivery_health_lock = PTHREAD_MUTEX_INITIALIZER;
static void delivery_health_lock(void) { pthread_mutex_lock(&s_delivery_health_lock); }
static void delivery_health_unlock(void) { pthread_mutex_unlock(&s_delivery_health_lock); }
#endif

static int64_t command_now_ms(void);
static uint64_t command_monotonic_ms(void);
static int file_exists_c(const char *path);

static EdrCommandDeliveryHealth s_delivery_health;
static int64_t s_upload_outbox_next_retry_ms;
static uint32_t s_upload_outbox_fail_streak;
static int64_t s_result_outbox_next_flush_ms;
static int64_t s_compact_next_allowed_ms;

static uint32_t command_u32_env_clamped(const char *name, uint32_t defv, uint32_t minv, uint32_t maxv) {
  const char *e = getenv(name);
  uint32_t v = defv;
  if (e && e[0]) {
    unsigned long parsed = strtoul(e, NULL, 10);
    if (parsed > 0ul) {
      v = (uint32_t)parsed;
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

static uint32_t command_elapsed_ms_u32(uint64_t start_ms) {
  uint64_t now = command_monotonic_ms();
  uint64_t elapsed = now > start_ms ? now - start_ms : 0u;
  return elapsed > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (uint32_t)elapsed;
}

static void command_update_max_u32(uint32_t value, uint32_t *max_value) {
  if (max_value && value > *max_value) {
    *max_value = value;
  }
}

static int delivery_health_upload_backoff_active(int64_t now_ms) {
  int active;
  delivery_health_lock();
  active = s_upload_outbox_next_retry_ms > now_ms;
  if (active) {
    s_delivery_health.upload_skipped_backoff++;
  }
  delivery_health_unlock();
  return active;
}

static void delivery_health_upload_attempted(void) {
  delivery_health_lock();
  s_delivery_health.upload_attempted++;
  delivery_health_unlock();
}

static void delivery_health_upload_result(int rc, int64_t now_ms) {
  delivery_health_lock();
  if (rc > 0) {
    s_delivery_health.upload_succeeded++;
    s_upload_outbox_fail_streak = 0u;
    s_upload_outbox_next_retry_ms = 0;
  } else if (rc < 0) {
    s_delivery_health.upload_failed++;
    s_upload_outbox_fail_streak++;
    uint32_t base_s = command_u32_env_clamped("EDR_UPLOAD_OUTBOX_RETRY_BACKOFF_S",
                                               60u, 10u, 3600u);
    uint32_t cap_s = command_u32_env_clamped("EDR_UPLOAD_OUTBOX_MAX_BACKOFF_S",
                                              900u, base_s, 86400u);
    uint32_t mult = s_upload_outbox_fail_streak > 5u ? 5u : s_upload_outbox_fail_streak;
    uint64_t backoff_s = (uint64_t)base_s * (uint64_t)(mult ? mult : 1u);
    if (backoff_s > cap_s) {
      backoff_s = cap_s;
    }
    s_upload_outbox_next_retry_ms = now_ms + (int64_t)backoff_s * 1000LL;
  }
  delivery_health_unlock();
}

static void delivery_health_upload_pending(uint32_t pending_seen) {
  delivery_health_lock();
  s_delivery_health.upload_pending_seen = pending_seen;
  s_delivery_health.upload_fail_streak = s_upload_outbox_fail_streak;
  s_delivery_health.upload_next_retry_unix_ms = s_upload_outbox_next_retry_ms;
  delivery_health_unlock();
}

static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static int dangerous_enabled(void) {
  const char *e = getenv("EDR_CMD_ENABLED");
  if (e && e[0] == '1') {
    return 1;
  }
  e = getenv("EDR_CMD_DANGEROUS");
  if (e && e[0] == '1') {
    return 1;
  }
  if (edr_command_get_config() && edr_command_get_config()->command.allow_dangerous) {
    return 1;
  }
  return 0;
}

static int rtq_readonly_enabled(void) {
  const char *e = getenv("EDR_RTQ_READONLY_ENABLED");
  if (e && e[0] == '1') {
    return 1;
  }
  if (e && e[0] == '0') {
    return 0;
  }
  if (dangerous_enabled()) {
    return 1;
  }
  if (edr_command_get_config()) {
    return edr_command_get_config()->command.allow_rtq_readonly ? 1 : 0;
  }
  return 1;
}

/** 未设置 `EDR_CMD_KILL_ALLOWLIST` 时不限制；设置后仅允许列表内 pid（逗号分隔） */
static int kill_pid_allowed(long pid) {
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

static void audit_both(const char *cmd_id, const char *msg) {
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

static int soar_want_report(const EdrSoarCommandMeta *m) {
  const char *a = getenv("EDR_SOAR_REPORT_ALWAYS");
  if (a && a[0] == '1') {
    return 1;
  }
  if (!m) {
    return 0;
  }
  return m->soar_correlation_id[0] || m->playbook_run_id[0];
}

static int command_should_report(const char *cmd_id, const EdrSoarCommandMeta *m) {
  if (soar_want_report(m)) {
    return 1;
  }
  return cmd_id && strncmp(cmd_id, "cmd_", 4u) == 0;
}

static const char *response_status_label(EdrCommandExecutionStatus st) {
  switch (st) {
    case EdrCmdExecOk:
      return "ok";
    case EdrCmdExecRejected:
      return "denied";
    case EdrCmdExecFailed:
      return "failed";
    case EdrCmdExecUnknownType:
      return "failed";
    default:
      return "failed";
  }
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
    } else if (c == '\n') {
      dst[o++] = '\\';
      dst[o++] = 'n';
    } else if (c == '\r') {
      dst[o++] = '\\';
      dst[o++] = 'r';
    } else if (c == '\t') {
      dst[o++] = '\\';
      dst[o++] = 't';
    } else if (c < 0x20u) {
      if (o + 7u >= cap) {
        break;
      }
      o += (size_t)snprintf(dst + o, cap - o, "\\u%04x", (unsigned)c);
    } else {
      dst[o++] = (char)c;
    }
  }
  if (o + 1u < cap) {
    dst[o++] = '"';
  }
  dst[o < cap ? o : cap - 1u] = '\0';
}

static char *json_escape_alloc_cmd(const char *s) {
  if (!s) {
    s = "";
  }
  size_t len = strlen(s);
  if (len > (((size_t)-1) - 3u) / 6u) {
    return NULL;
  }
  size_t cap = len * 6u + 3u;
  char *out = (char *)malloc(cap);
  if (!out) {
    return NULL;
  }
  size_t o = 0;
  out[o++] = '"';
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      out[o++] = '\\';
      out[o++] = (char)c;
    } else if (c == '\n') {
      out[o++] = '\\';
      out[o++] = 'n';
    } else if (c == '\r') {
      out[o++] = '\\';
      out[o++] = 'r';
    } else if (c == '\t') {
      out[o++] = '\\';
      out[o++] = 't';
    } else if (c < 0x20u) {
      o += (size_t)snprintf(out + o, cap - o, "\\u%04x", (unsigned)c);
    } else {
      out[o++] = (char)c;
    }
  }
  out[o++] = '"';
  out[o] = '\0';
  return out;
}

static void soar_emit_ex(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                         int exit_code, const char *detail, const char *response_status,
                         const char *artifacts) {
  char cancel_detail[1536];
  if (cmd_id && edr_command_cancel_requested(cmd_id) && exit_code != 130 &&
      (!response_status || strcmp(response_status, "cancelled") != 0)) {
    snprintf(cancel_detail, sizeof(cancel_detail),
             "cancellation requested while action was running; backend returned status=%s exit=%d detail=%.1200s",
             response_status_label(st), exit_code, detail ? detail : "");
    st = EdrCmdExecFailed;
    exit_code = 130;
    detail = cancel_detail;
    response_status = "cancelled";
  }
  char forensic_detail[8192];
  detail = edr_command_normalize_forensic_result(s_active_command_type, st, exit_code, detail,
                                                 forensic_detail, sizeof(forensic_detail));
  char taskj[300];
  char statusj[96];
  char *detail_json = NULL;
  const char *persist_detail = NULL;
  char *raw = NULL;
  char *err = NULL;
  const char *rstatus = response_status && response_status[0] ? response_status : response_status_label(st);
  const char *artifact_json = artifacts && artifacts[0] ? artifacts : "[]";
  const char *err_text = st == EdrCmdExecOk ? "" : (detail ? detail : response_status_label(st));
  int retryable = (st == EdrCmdExecFailed && exit_code != 1 && exit_code != 2 && exit_code != 7) ? 1 : 0;
  json_escape_to(taskj, sizeof(taskj), cmd_id ? cmd_id : "");
  json_escape_to(statusj, sizeof(statusj), rstatus);
  raw = json_escape_alloc_cmd(detail ? detail : "");
  err = json_escape_alloc_cmd(err_text);
  if (raw && err) {
    size_t need = strlen(taskj) + strlen(statusj) + strlen(artifact_json) +
                  strlen(err) + strlen(raw) + 256u;
    detail_json = (char *)malloc(need);
    if (detail_json) {
      snprintf(detail_json, need,
               "{\"task_id\":%s,\"status\":%s,\"exit_code\":%d,"
               "\"evidence_refs\":[],\"upload_refs\":[],\"artifacts\":%s,\"error\":%s,"
               "\"retryable\":%s,\"raw_detail\":%s}",
               taskj, statusj, exit_code, artifact_json, err,
               retryable ? "true" : "false", raw);
    }
  }
  if (!detail_json) {
    char fallback[4096];
    char small_raw[1800];
    char small_err[1200];
    json_escape_to(small_raw, sizeof(small_raw), detail ? detail : "");
    json_escape_to(small_err, sizeof(small_err), err_text);
    snprintf(fallback, sizeof(fallback),
             "{\"task_id\":%s,\"status\":%s,\"exit_code\":%d,"
             "\"evidence_refs\":[],\"upload_refs\":[],\"artifacts\":[],\"error\":%s,"
             "\"retryable\":%s,\"raw_detail\":%s}",
             taskj, statusj, exit_code, small_err,
             retryable ? "true" : "false", small_raw);
    persist_detail = fallback;
    int report_pending = command_should_report(cmd_id, sm);
    int state_rc = edr_command_state_finish(cmd_id, s_active_command_type,
                                            sm, rstatus, (int)st, exit_code,
                                            persist_detail, artifacts ? artifacts : "",
                                            report_pending);
    if (state_rc == 0) {
      edr_command_state_delete_inbox(cmd_id);
    } else {
      audit_both(cmd_id, "terminal command state persist failed; durable inbox retained");
    }
    free(raw);
    free(err);
    return;
  }
  persist_detail = detail_json;
  int report_pending = command_should_report(cmd_id, sm);
  int state_rc = edr_command_state_finish(cmd_id, s_active_command_type,
                                          sm, rstatus, (int)st, exit_code,
                                          persist_detail,
                                          artifacts ? artifacts : "",
                                          report_pending);
  /* The inbox is the crash-recovery record. Delete it only after a terminal
   * result is durably recorded; async forensic commands therefore remain
   * replayable while their collector is running. */
  if (state_rc == 0) {
    edr_command_state_delete_inbox(cmd_id);
  } else {
    audit_both(cmd_id, "terminal command state persist failed; durable inbox retained");
  }
  free(raw);
  free(err);
  free(detail_json);
}

static void soar_emit(const char *cmd_id, const EdrSoarCommandMeta *sm, EdrCommandExecutionStatus st,
                      int exit_code, const char *detail) {
  soar_emit_ex(cmd_id, sm, st, exit_code, detail, NULL, NULL);
}

static int parse_json_string_field(const uint8_t *p, size_t len, const char *key,
                                   char *out, size_t outcap) {
  return edr_parse_json_string(p, len, key, out, outcap) ? 0 : -1;
}

static int parse_json_int_field(const uint8_t *p, size_t len, const char *key, long *out) {
  int value = 0;
  if (!out || !edr_parse_json_int(p, len, key, &value)) {
    return -1;
  }
  *out = (long)value;
  return 0;
}

static int parse_json_bool_field(const uint8_t *p, size_t len, const char *key, int *out) {
  return edr_parse_json_bool(p, len, key, out) ? 0 : -1;
}

static int parse_pid_json(const uint8_t *p, size_t len, long *out_pid) {
  int pid = -1;
  if (!out_pid || !edr_parse_json_int(p, len, "pid", &pid) || pid <= 0) {
    return -1;
  }
  *out_pid = (long)pid;
  return 0;
}

static void do_telemetry_profile_update(const char *cmd_id, const uint8_t *pl, size_t len,
                                        const EdrSoarCommandMeta *sm) {
  char dict_ver[64] = "";
  char schema_ver[64] = "";
  char profile_id[64] = "";
  char qos_dscp[32] = "";
  char threshold[32] = "";
  long batch_events = 0;
  long flush_s = 0;
  long sampling_pct = 100;
  int h2 = -1;
  int h2_enabled = -1;
  int h2_required = -1;
  int control_h2_enabled = -1;
  int control_h2_required = -1;
  int control_h1_fallback = -1;
  int zstd = -1;
  int control_stream_enabled = -1;
  int long_poll_fallback = -1;
  int report_events_v2_enabled = -1;
  int backpressure = -1;

  (void)parse_json_string_field(pl, len, "dict_ver", dict_ver, sizeof(dict_ver));
  (void)parse_json_string_field(pl, len, "schema_ver", schema_ver, sizeof(schema_ver));
  (void)parse_json_string_field(pl, len, "profile_id", profile_id, sizeof(profile_id));
  (void)parse_json_string_field(pl, len, "qos_dscp", qos_dscp, sizeof(qos_dscp));
  (void)parse_json_string_field(pl, len, "threshold", threshold, sizeof(threshold));
  if (parse_json_int_field(pl, len, "batch_events", &batch_events) != 0) {
    (void)parse_json_int_field(pl, len, "batch_max_events", &batch_events);
  }
  (void)parse_json_int_field(pl, len, "flush_interval_s", &flush_s);
  (void)parse_json_int_field(pl, len, "sampling_pct", &sampling_pct);
  (void)parse_json_bool_field(pl, len, "h2", &h2);
  h2_enabled = h2;
  (void)parse_json_bool_field(pl, len, "http2_enabled", &h2_enabled);
  (void)parse_json_bool_field(pl, len, "h2_required", &h2_required);
  (void)parse_json_bool_field(pl, len, "control_http2_enabled", &control_h2_enabled);
  (void)parse_json_bool_field(pl, len, "control_http2_require", &control_h2_required);
  (void)parse_json_bool_field(pl, len, "control_http1_fallback", &control_h1_fallback);
  (void)parse_json_bool_field(pl, len, "zstd", &zstd);
  (void)parse_json_bool_field(pl, len, "control_stream_enabled", &control_stream_enabled);
  (void)parse_json_bool_field(pl, len, "long_poll_fallback", &long_poll_fallback);
  (void)parse_json_bool_field(pl, len, "report_events_v2_enabled", &report_events_v2_enabled);
  (void)parse_json_bool_field(pl, len, "backpressure_enabled", &backpressure);

  if (batch_events < 0) {
    batch_events = 0;
  }
  if (batch_events > 50000) {
    batch_events = 50000;
  }
  if (flush_s < 0) {
    flush_s = 0;
  }
  if (flush_s > 300) {
    flush_s = 300;
  }
  if (sampling_pct < 1) {
    sampling_pct = 1;
  }
  if (sampling_pct > 100) {
    sampling_pct = 100;
  }

  edr_event_batch_apply_profile((uint32_t)batch_events, (int)flush_s);
  edr_ingest_http_apply_telemetry_profile(dict_ver, schema_ver, profile_id, h2, zstd,
                                          qos_dscp, (unsigned)sampling_pct, threshold,
                                          backpressure);
  edr_ingest_http_apply_transport_flags(h2_enabled, h2_required, control_stream_enabled,
                                        long_poll_fallback, report_events_v2_enabled);
  if (control_h2_enabled < 0) {
    control_h2_enabled = h2_enabled;
  }
  if (control_h2_required < 0) {
    control_h2_required = h2_required;
  }
  if (control_h1_fallback < 0 && control_h2_required >= 0) {
    control_h1_fallback = control_h2_required ? 0 : 1;
  }
  edr_ingest_http_apply_control_transport_flags(control_h2_enabled, control_h2_required,
                                                control_h1_fallback);

  char detail[512];
  snprintf(detail, sizeof(detail),
           "telemetry profile applied profile=%s dict=%s schema=%s batch=%ld flush=%lds sampling=%ld%% dscp=%s backpressure=%s",
           profile_id[0] ? profile_id : "-",
           dict_ver[0] ? dict_ver : "-",
           schema_ver[0] ? schema_ver : "-",
           batch_events, flush_s, sampling_pct,
           qos_dscp[0] ? qos_dscp : "-",
           backpressure == 1 ? "on" : (backpressure == 0 ? "off" : "inherit"));
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

/** payload UTF-8 JSON：`{"path":"C:\\file.exe"}` 或含 `"path":"..."` */
static int parse_path_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  return parse_json_string_field(p, len, "path", out, outcap);
}

static int parse_server_address_json(const uint8_t *p, size_t len, char *out, size_t outcap) {
  const char *keys[] = {"server_address", "server_addr", "address"};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    if (edr_parse_json_string(p, len, keys[i], out, outcap) && out[0]) {
      return 0;
    }
  }
  return -1;
}

static int ctx_has(const EdrBehaviorRecord *r, const char *needle) {
  return r && needle && needle[0] && strstr(r->detection_context, needle) != NULL;
}

static int env_truthy_cmd(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return 0;
  }
  return strcmp(v, "1") == 0 || streq(v, "true") || streq(v, "TRUE") || streq(v, "yes") || streq(v, "on");
}

static int env_falsy_cmd(const char *name) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return 0;
  }
  return strcmp(v, "0") == 0 || streq(v, "false") || streq(v, "FALSE") || streq(v, "no") || streq(v, "off");
}

static uint32_t env_u32_cmd(const char *name, uint32_t defv, uint32_t minv, uint32_t maxv) {
  const char *v = getenv(name);
  if (!v || !v[0]) {
    return defv;
  }
  char *end = NULL;
  unsigned long n = strtoul(v, &end, 10);
  if (end == v) {
    return defv;
  }
  if (n < minv) {
    n = minv;
  }
  if (n > maxv) {
    n = maxv;
  }
  return (uint32_t)n;
}

static int auto_recommended_rate_allow(uint32_t pid) {
  static int64_t s_global_last_ms;
  static uint32_t s_last_pid;
  static int64_t s_last_pid_ms;
  static int64_t s_hour_start_ms;
  static uint32_t s_hour_count;
  int64_t now = command_now_ms();
  uint32_t global_cd_s = edr_command_get_config() ? edr_command_get_config()->forensic_auto.cooldown_s : 30u;
  uint32_t pid_cd_s = edr_command_get_config() ? edr_command_get_config()->forensic_auto.per_pid_cooldown_s : 300u;
  uint32_t max_per_hour = edr_command_get_config() ? edr_command_get_config()->forensic_auto.max_per_hour : 20u;
  global_cd_s = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_COOLDOWN_S", global_cd_s, 0u, 3600u);
  pid_cd_s = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_PER_PID_COOLDOWN_S", pid_cd_s, 0u, 86400u);
  max_per_hour = env_u32_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_MAX_PER_HOUR", max_per_hour, 0u, 10000u);
  if (s_hour_start_ms == 0 || now - s_hour_start_ms >= 3600000LL) {
    s_hour_start_ms = now;
    s_hour_count = 0;
  }
  if (max_per_hour > 0u && s_hour_count >= max_per_hour) {
    return 0;
  }
  if (global_cd_s > 0u && s_global_last_ms > 0 &&
      now - s_global_last_ms < (int64_t)global_cd_s * 1000LL) {
    return 0;
  }
  if (pid != 0u && pid_cd_s > 0u && s_last_pid == pid && s_last_pid_ms > 0 &&
      now - s_last_pid_ms < (int64_t)pid_cd_s * 1000LL) {
    return 0;
  }
  s_global_last_ms = now;
  s_hour_count++;
  if (pid != 0u) {
    s_last_pid = pid;
    s_last_pid_ms = now;
  }
  return 1;
}

static int auto_pmfe_recommended_enabled(void) {
  if (env_falsy_cmd("EDR_AUTO_RECOMMENDED_PMFE")) {
    return 0;
  }
  if (env_truthy_cmd("EDR_AUTO_RECOMMENDED_PMFE")) {
    return 1;
  }
  return edr_pmfe_is_running();
}

int edr_command_dispatch_recommended_forensics(const EdrBehaviorRecord *r) {
  if (!r || !r->detection_context[0] || !ctx_has(r, "\"recommended_forensics\"")) {
    return 0;
  }
  if ((ctx_has(r, "ransom") || ctx_has(r, "T1486") || ctx_has(r, "T1490")) &&
      !edr_policy_v2_ransomware_enabled("forensic")) {
    return 0;
  }
  if (env_falsy_cmd("EDR_AUTO_RECOMMENDED_FORENSICS")) {
    return 0;
  }
  if (edr_command_get_config() && !edr_command_get_config()->forensic_auto.enabled &&
      !env_truthy_cmd("EDR_AUTO_RECOMMENDED_FORENSICS_FORCE")) {
    return 0;
  }
  if (!edr_command_get_config() && !env_truthy_cmd("EDR_AUTO_RECOMMENDED_FORENSICS")) {
    return 0;
  }
  if (!dangerous_enabled()) {
    return 0;
  }
  if (!auto_recommended_rate_allow(r->pid)) {
    return 0;
  }
  EdrSoarCommandMeta sm;
  memset(&sm, 0, sizeof(sm));
  snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s", "agent_auto_recommended_forensics");
  snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s", r->event_id[0] ? r->event_id : "local_event");
  sm.issued_at_unix_ms = (int64_t)time(NULL) * 1000LL;

  int dispatched = 0;
  if (r->pid != 0u && ctx_has(r, "pmfe_scan") && auto_pmfe_recommended_enabled()) {
    char id[96];
    char payload[96];
    snprintf(id, sizeof(id), "auto-pmfe-%s", r->event_id[0] ? r->event_id : "event");
    snprintf(payload, sizeof(payload), "{\"pid\":%u,\"reason\":\"recommended_forensics\"}", (unsigned)r->pid);
    edr_command_on_internal_envelope(id, "pmfe_scan", (const uint8_t *)payload, strlen(payload), &sm);
    dispatched++;
  }

  if (ctx_has(r, "process_tree") || ctx_has(r, "timeline_window") || ctx_has(r, "targeted_files") ||
      ctx_has(r, "webshell_files") || ctx_has(r, "single_process_minidump")) {
    char id[96];
    char payload[4096];
    char ev[192];
    char pname[256];
    char exe[512];
    char cmd[768];
    char file[512];
    char rip[160];
    char rurl[512];
    json_escape_to(ev, sizeof(ev), r->event_id);
    json_escape_to(pname, sizeof(pname), r->process_name);
    json_escape_to(exe, sizeof(exe), r->exe_path);
    json_escape_to(cmd, sizeof(cmd), r->cmdline);
    json_escape_to(file, sizeof(file), r->file_path);
    json_escape_to(rip, sizeof(rip), r->net_dst);
    json_escape_to(rurl, sizeof(rurl), r->dns_query);
    snprintf(id, sizeof(id), "auto-forensic-%s", r->event_id[0] ? r->event_id : "event");
    snprintf(payload, sizeof(payload),
             "{"
             "\"pid\":%u,\"ppid\":%u,\"event_id\":%s,\"process_name\":%s,"
             "\"exe_path\":%s,\"cmdline\":%s,\"file_path\":%s,"
             "\"remote_ip\":%s,\"remote_url\":%s,"
             "\"recommended_from_detection_context\":true,"
             "\"recommended_forensics\":\"%s%s%s%s%s\""
             "}",
             (unsigned)r->pid, (unsigned)r->ppid, ev, pname,
             exe, cmd, file, rip, rurl,
             ctx_has(r, "process_tree") ? "process_tree," : "",
             ctx_has(r, "timeline_window") ? "timeline_window," : "",
             ctx_has(r, "targeted_files") || ctx_has(r, "webshell_files") ? "targeted_files," : "",
             ctx_has(r, "ioc_lookup") ? "ioc_lookup," : "",
             ctx_has(r, "single_process_minidump") ? "single_process_minidump_if_needed" : "");
    edr_command_on_internal_envelope(id, "forensic", (const uint8_t *)payload, strlen(payload), &sm);
    dispatched++;
  }
  return dispatched;
}

static void do_ave_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  int mf = 0, nf = 0, rd = 0;
  edr_ave_get_scan_counts(&mf, &nf, &rd);
  char detail[256];
  snprintf(detail, sizeof(detail), "model_files=%d non_dir_files=%d ready=%d", mf, nf, rd);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static const char *ave_verdict_tag(EDRVerdict v) {
  switch (v) {
    case VERDICT_CLEAN:
      return "CLEAN";
    case VERDICT_SUSPICIOUS:
      return "SUSPICIOUS";
    case VERDICT_MALWARE:
      return "MALWARE";
    case VERDICT_TRUSTED_CERT:
      return "TRUSTED_CERT";
    case VERDICT_WHITELISTED:
      return "WHITELISTED";
    case VERDICT_IOC_CONFIRMED:
      return "IOC_CONFIRMED";
    case VERDICT_CERT_REVOKED:
      return "CERT_REVOKED";
    case VERDICT_CERT_TAMPERED:
      return "CERT_TAMPERED";
    case VERDICT_TIMEOUT:
      return "TIMEOUT";
    case VERDICT_ERROR:
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

static void do_ave_fingerprint(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  char path[4096];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_fingerprint: payload 需 JSON {\"path\":\"...\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  char hex[32];
  if (edr_ave_file_fingerprint(path, hex, sizeof(hex)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_fingerprint: 读文件或指纹失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 11, "fingerprint failed");
    return;
  }
  char detail[220];
  snprintf(detail, sizeof(detail), "fp=%s", hex);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_ave_infer(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!edr_command_get_config()) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 未绑定配置（内部错误）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 20, "config not bound");
    return;
  }
  char path[4096];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: payload 需 JSON {\"path\":\"...\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 10, "invalid path payload");
    return;
  }
  AVEScanResult res;
  memset(&res, 0, sizeof(res));
  int ar = AVE_ScanFile(path, &res);
  if (ar == AVE_ERR_NOT_INITIALIZED) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: AVE 未初始化（需先 edr_agent_init）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 22, "ave not initialized");
    return;
  }
  if (ar == AVE_ERR_NOT_IMPL) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 推理后端未实现（可设 EDR_AVE_INFER_DRY_RUN=1）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, (int)EDR_ERR_NOT_IMPL, "infer not implemented");
    return;
  }
  if (ar == AVE_ERR_FILE_NOT_FOUND) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 文件不存在");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 23, "file not found");
    return;
  }
  if (ar == AVE_ERR_ACCESS_DENIED) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 无读取权限");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 24, "access denied");
    return;
  }
  if (ar != AVE_OK) {
    s_exec_fail++;
    audit_both(cmd_id, "ave_infer: 扫描失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 21, "scan error");
    return;
  }

  char detail[512];
  snprintf(detail, sizeof(detail),
           "final=%s raw=%s final_conf=%.4f raw_conf=%.4f layer=%.3s sha256=%s dur_ms=%lld",
           ave_verdict_tag(res.final_verdict), ave_verdict_tag(res.raw_ai_verdict),
           (double)res.final_confidence, (double)res.raw_confidence, res.verification_layer, res.sha256,
           (long long)res.scan_duration_ms);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_self_protect_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  char detail[512];
  edr_self_protect_format_status(detail, sizeof(detail));
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, detail);
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_update_server_address(const char *cmd_id, const uint8_t *pl, size_t len,
                                     const EdrSoarCommandMeta *sm) {
  char addr[256];
  if (parse_server_address_json(pl, len, addr, sizeof(addr)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "update_server_address: payload 需 JSON {\"server_address\":\"host:port\"}");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 12, "invalid server address payload");
    return;
  }
  if (strstr(addr, "://") || strchr(addr, '/')) {
    s_exec_fail++;
    audit_both(cmd_id, "update_server_address: 仅支持 host:port");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 13, "server address must be host:port");
    return;
  }
  s_exec_fail++;
  audit_both(cmd_id, "update_server_address: 不再支持 server.address 切换；请通过远程配置更新 platform.rest_base_url");
  soar_emit(cmd_id, sm, EdrCmdExecFailed, 14, "update_server_address unsupported; use platform.rest_base_url");
}

static void do_kill(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject kill: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "kill: payload 无有效 pid（JSON 示例 {\"pid\":1234}）");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  if (!kill_pid_allowed(pid)) {
    s_rejected++;
    audit_both(cmd_id, "kill: pid 不在 EDR_CMD_KILL_ALLOWLIST 中");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 7, "pid not in allowlist");
    return;
  }
#ifdef _WIN32
  if ((DWORD)pid == GetCurrentProcessId()) {
    s_rejected++;
    audit_both(cmd_id, "kill: 拒绝结束本进程");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
      s_exec_fail++;
      audit_both(cmd_id, "kill: OpenProcess 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "OpenProcess failed");
      return;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (ok) {
      s_exec_ok++;
      audit_both(cmd_id, "kill: TerminateProcess 已执行");
      soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "TerminateProcess ok");
    } else {
      s_exec_fail++;
      audit_both(cmd_id, "kill: TerminateProcess 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "TerminateProcess failed");
    }
  }
#else
  if (pid == (long)getpid()) {
    s_rejected++;
    audit_both(cmd_id, "kill: 拒绝结束本进程");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 5, "refuse self");
    return;
  }
  /* SIGTERM 优雅终止 → 宽限期确认 → 仍存活则升级 SIGKILL。
     避免进程 trap/忽略 SIGTERM 后存活、却被报成功(假成功)。 */
  if (kill((pid_t)pid, SIGTERM) != 0) {
    if (errno == ESRCH) {
      s_exec_ok++;
      audit_both(cmd_id, "kill: 进程不存在(视为已终止)");
      soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "process already gone");
    } else {
      s_exec_fail++;
      audit_both(cmd_id, "kill: kill() 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, "kill() failed");
    }
    return;
  }
  int gone = 0;
  for (int i = 0; i < 20; i++) { /* 最多 ~2s 等待优雅退出 */
    struct timespec ts = {0, 100L * 1000L * 1000L};
    nanosleep(&ts, NULL);
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
      gone = 1;
      break;
    }
  }
  if (gone) {
    s_exec_ok++;
    audit_both(cmd_id, "kill: SIGTERM 后进程已退出");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "terminated via SIGTERM");
    return;
  }
  /* 仍存活 → 强制 SIGKILL。 */
  if (kill((pid_t)pid, SIGKILL) != 0 && errno != ESRCH) {
    s_exec_fail++;
    audit_both(cmd_id, "kill: SIGKILL 失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 8, "SIGKILL failed");
    return;
  }
  for (int i = 0; i < 10; i++) { /* 最多 ~1s 确认 SIGKILL 生效 */
    struct timespec ts = {0, 100L * 1000L * 1000L};
    nanosleep(&ts, NULL);
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
      gone = 1;
      break;
    }
  }
  if (gone) {
    s_exec_ok++;
    audit_both(cmd_id, "kill: SIGTERM 无效,已用 SIGKILL 终止");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, "terminated via SIGKILL");
  } else {
    /* SIGKILL 已送达但仍在进程表(僵尸/不可中断 D 态);如实报失败,不谎报成功。 */
    s_exec_fail++;
    audit_both(cmd_id, "kill: SIGKILL 后进程仍存在(僵尸/不可中断)");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 9, "alive after SIGKILL");
  }
#endif
}

static void isolate_stamp_path(char *path, size_t cap) {
  const char *stamp = getenv("EDR_ISOLATE_STAMP_PATH");
  if (stamp && stamp[0]) {
    snprintf(path, cap, "%s", stamp);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(path, cap, "%s\\edr_isolated.state", tmp);
#else
    snprintf(path, cap, "%s", "/tmp/edr_isolated.state");
#endif
  }
}

static void isolate_setenv(const char *k, const char *v) {
#ifdef _WIN32
  (void)_putenv_s(k, v ? v : "");
#else
  (void)setenv(k, v ? v : "", 1);
#endif
}

/* 可执行文件所在目录。 */
static int isolate_self_dir(char *out, size_t cap) {
#ifdef _WIN32
  char buf[1024];
  DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)sizeof(buf));
  if (n == 0 || n >= sizeof(buf)) {
    return -1;
  }
  char *slash = strrchr(buf, '\\');
  if (!slash) {
    return -1;
  }
  *slash = '\0';
  snprintf(out, cap, "%s", buf);
  return 0;
#else
  char buf[1024];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1u);
  if (n <= 0) {
    return -1;
  }
  buf[n] = '\0';
  char *slash = strrchr(buf, '/');
  if (!slash) {
    return -1;
  }
  *slash = '\0';
  snprintf(out, cap, "%s", buf);
  return 0;
#endif
}

/* 解析随包隔离脚本:EDR_ISOLATE_SCRIPT > 可执行同目录 > 同目录 scripts/。 */
static int isolate_resolve_script(char *out, size_t cap) {
  const char *ov = getenv("EDR_ISOLATE_SCRIPT");
  if (ov && ov[0]) {
    snprintf(out, cap, "%s", ov);
    return file_exists_c(out) ? 0 : -1;
  }
  char dir[1024];
  if (isolate_self_dir(dir, sizeof(dir)) != 0) {
    return -1;
  }
#ifdef _WIN32
  const char *name = "windows_isolate_host.ps1";
  snprintf(out, cap, "%s\\%s", dir, name);
  if (file_exists_c(out)) return 0;
  snprintf(out, cap, "%s\\scripts\\%s", dir, name);
  if (file_exists_c(out)) return 0;
#else
  const char *name = "linux_isolate_host.sh";
  snprintf(out, cap, "%s/%s", dir, name);
  if (file_exists_c(out)) return 0;
  snprintf(out, cap, "%s/scripts/%s", dir, name);
  if (file_exists_c(out)) return 0;
#endif
  return -1;
}

/* 隔离前自动放行管理通道:若运维未显式设 EDR_ISOLATE_ALLOW_REMOTE_ADDRS,
   则从后端 rest_base 解析 host→IP 并注入,确保隔离后 agent↔后端 仍可达
   (否则收不到 restore 命令,主机将永久失联)。 */
static void isolate_autofill_allowlist(void) {
  if (getenv("EDR_ISOLATE_ALLOW_REMOTE_ADDRS")) {
    return; /* 尊重运维显式配置 */
  }
  char base[512];
  base[0] = '\0';
  edr_ingest_http_get_rest_base(base, sizeof(base));
  if (!base[0]) {
    return;
  }
  char host[256] = {0};
  char port[16] = {0};
  const char *p = strstr(base, "://");
  p = p ? p + 3 : base;
  size_t i = 0;
  while (*p && *p != ':' && *p != '/' && i < sizeof(host) - 1u) {
    host[i++] = *p++;
  }
  host[i] = '\0';
  if (*p == ':') {
    p++;
    size_t j = 0;
    while (*p && *p != '/' && j < sizeof(port) - 1u) {
      port[j++] = *p++;
    }
    port[j] = '\0';
  }
  if (!host[0]) {
    return;
  }
  if (!port[0]) {
    snprintf(port, sizeof(port), "%s", strncmp(base, "https", 5) == 0 ? "443" : "80");
  }
  char addrs[512];
  addrs[0] = '\0';
#ifndef _WIN32
  struct addrinfo hints, *res = NULL, *it;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, NULL, &hints, &res) == 0) {
    for (it = res; it; it = it->ai_next) {
      char ip[INET6_ADDRSTRLEN] = {0};
      void *sa = NULL;
      if (it->ai_family == AF_INET) {
        sa = &((struct sockaddr_in *)it->ai_addr)->sin_addr;
      } else if (it->ai_family == AF_INET6) {
        sa = &((struct sockaddr_in6 *)it->ai_addr)->sin6_addr;
      }
      if (sa && inet_ntop(it->ai_family, sa, ip, sizeof(ip))) {
        if (addrs[0]) {
          strncat(addrs, ",", sizeof(addrs) - strlen(addrs) - 1u);
        }
        strncat(addrs, ip, sizeof(addrs) - strlen(addrs) - 1u);
      }
    }
    freeaddrinfo(res);
  }
#endif
  if (!addrs[0]) {
    /* 解析失败或 Windows:放行 host 字面量(Windows ps1 会自行将主机名解析成 IP)。 */
    snprintf(addrs, sizeof(addrs), "%s", host);
  }
  isolate_setenv("EDR_ISOLATE_ALLOW_REMOTE_ADDRS", addrs);
  if (!getenv("EDR_ISOLATE_ALLOW_REMOTE_PORTS")) {
    char ports[32];
    if (strcmp(port, "443") == 0) {
      snprintf(ports, sizeof(ports), "443");
    } else {
      snprintf(ports, sizeof(ports), "%s,443", port);
    }
    isolate_setenv("EDR_ISOLATE_ALLOW_REMOTE_PORTS", ports);
  }
}

/* 运行隔离 enforcement。返回 0=成功;-1=失败;-2=无可用 enforcement(无 hook 且无脚本)。
   优先 EDR_ISOLATE_HOOK/EDR_RESTORE_HOOK(运维自定义);否则随包脚本(ps1/sh)。 */
static int isolate_run(int enable, const char *cmd_id) {
  isolate_setenv("EDR_CMD_ID", cmd_id ? cmd_id : "");
  const char *hook;
  if (enable) {
    hook = getenv("EDR_ISOLATE_HOOK");
  } else {
    hook = getenv("EDR_RESTORE_HOOK");
    if (!hook || !hook[0]) {
      hook = getenv("EDR_ISOLATE_RESTORE_HOOK");
    }
  }
  if (hook && hook[0]) {
    return (system(hook) == 0) ? 0 : -1;
  }
  char script[1024];
  if (isolate_resolve_script(script, sizeof(script)) != 0) {
    return -2;
  }
  char cmd[1400];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd),
           "powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\" -Action %s", script,
           enable ? "Enable" : "Remove");
#else
  snprintf(cmd, sizeof(cmd), "/bin/sh \"%s\" %s", script, enable ? "enable" : "remove");
#endif
  return (system(cmd) == 0) ? 0 : -1;
}

/* Status is a second signal from the enforcement backend, not a restatement
 * of the agent stamp. Built-in scripts are required to report an active rule
 * set; custom hooks may provide EDR_ISOLATE_STATUS_HOOK for the same check. */
static int isolate_run_status(char *evidence, size_t evidence_cap) {
  if (evidence && evidence_cap > 0u) {
    evidence[0] = '\0';
  }
  const char *status_hook = getenv("EDR_ISOLATE_STATUS_HOOK");
  if (status_hook && status_hook[0]) {
    return system(status_hook) == 0 ? 0 : -1;
  }
  char script[1024];
  if (isolate_resolve_script(script, sizeof(script)) != 0) {
    return -2;
  }
  char stamp[512];
  isolate_stamp_path(stamp, sizeof(stamp));
  char outpath[700];
  snprintf(outpath, sizeof(outpath), "%s.status", stamp);
  char cmd[1500];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd), "powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\" -Action Status > \"%s\" 2>&1",
           script, outpath);
#else
  snprintf(cmd, sizeof(cmd), "/bin/sh \"%s\" status > \"%s\" 2>&1", script, outpath);
#endif
  int rc = system(cmd) == 0 ? 0 : -1;
  if (evidence && evidence_cap > 1u) {
    FILE *f = fopen(outpath, "rb");
    if (f) {
      size_t n = fread(evidence, 1, evidence_cap - 1u, f);
      evidence[n] = '\0';
      fclose(f);
    }
  }
  (void)remove(outpath);
  return rc;
}

static int isolate_status_reports_active(const char *evidence) {
  if (!evidence || !evidence[0]) {
    return 0;
  }
  return strstr(evidence, "State file:") != NULL || strstr(evidence, "Isolation enabled") != NULL ||
         strstr(evidence, "table inet edr_isolate") != NULL || strstr(evidence, "DefaultInboundAction : Block") != NULL ||
         strstr(evidence, "-P INPUT DROP") != NULL || strstr(evidence, "-P OUTPUT DROP") != NULL;
}

static int isolate_stamp_only_mode(void) {
  const char *mode = getenv("EDR_ISOLATE_MODE");
  return (mode && strcmp(mode, "stamp") == 0) ? 1 : 0;
}

static int do_isolate(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject isolate: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return -1;
  }
  /* 写状态标记(供 isolate_status / 响应查询;非 enforcement 本身)。 */
  char path[512];
  isolate_stamp_path(path, sizeof(path));
  int stamp_written = 0;
  FILE *f = fopen(path, "w");
  if (f) {
    fprintf(f, "isolated=1\ncommand_id=%s\nupdated_unix_ms=%lld\n", cmd_id ? cmd_id : "",
            (long long)command_now_ms());
    stamp_written = fclose(f) == 0 ? 1 : 0;
  }
  if (!stamp_written) {
    s_exec_fail++;
    audit_both(cmd_id, "isolate: cannot persist isolation state stamp");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "cannot persist isolation state");
    return -2;
  }

  if (isolate_stamp_only_mode()) {
    /* 旧行为:仅标记(+可选 hook),用于依赖外部驱动读取标记的部署。 */
    const char *hook = getenv("EDR_ISOLATE_HOOK");
    if (hook && hook[0]) {
      isolate_setenv("EDR_CMD_ID", cmd_id ? cmd_id : "");
      if (system(hook) != 0) {
        (void)remove(path);
        s_exec_fail++;
        audit_both(cmd_id, "isolate(stamp): EDR_ISOLATE_HOOK 返回非零");
        soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "isolate hook non-zero");
        return -3;
      }
    }
    s_exec_ok++;
    audit_both(cmd_id, "isolate: stamp-only 模式(未施加网络 enforcement)");
    char pathj[700], detail[1024];
    json_escape_to(pathj, sizeof(pathj), path);
    snprintf(detail, sizeof(detail),
             "{\"status\":\"isolated\",\"method\":\"stamp\",\"stamp_path\":%s}", pathj);
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
    return 0;
  }

  /* 默认:真实网络隔离。先自动放行管理通道,再施加防火墙隔离。 */
  isolate_autofill_allowlist();
  int rc = isolate_run(1, cmd_id);
  if (rc != 0) {
    (void)remove(path); /* 不谎报:enforcement 未生效则不留隔离标记 */
    s_exec_fail++;
    if (rc == -2) {
      audit_both(cmd_id,
                 "isolate: 未找到 enforcement(设 EDR_ISOLATE_HOOK 或随包 isolate 脚本;或 EDR_ISOLATE_MODE=stamp)");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "no isolation enforcement available");
    } else {
      audit_both(cmd_id, "isolate: 网络 enforcement 失败");
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "isolation enforcement failed");
    }
    return rc == -2 ? -4 : -3;
  }
  int verified = 0;
  const char *verification = "enforcement_status";
  char status_evidence[2048];
  status_evidence[0] = '\0';
  const char *isolate_hook = getenv("EDR_ISOLATE_HOOK");
  if (isolate_hook && isolate_hook[0]) {
    verified = 1; /* Custom hook's zero exit is its enforcement contract. */
    verification = "hook_return_code";
  } else if (isolate_run_status(status_evidence, sizeof(status_evidence)) == 0 &&
             isolate_status_reports_active(status_evidence)) {
    verified = 1;
  }
  if (!verified) {
    (void)remove(path);
    s_exec_fail++;
    audit_both(cmd_id, "isolate: enforcement completed but status verification failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "isolation enforcement status not verified");
    return -5;
  }
  s_exec_ok++;
  audit_both(cmd_id, "isolate: 已施加网络隔离");
  {
    const char *hook = getenv("EDR_ISOLATE_HOOK");
    const char *allow = getenv("EDR_ISOLATE_ALLOW_REMOTE_ADDRS");
    char pathj[700], allowj[600], detail[1500];
    json_escape_to(pathj, sizeof(pathj), path);
    json_escape_to(allowj, sizeof(allowj), allow ? allow : "");
    snprintf(detail, sizeof(detail),
             "{\"status\":\"isolated\",\"method\":\"%s\",\"verification\":\"%s\","
             "\"stamp_path\":%s,\"allow_addrs\":%s}",
             (hook && hook[0]) ? "hook" : "builtin", verification, pathj, allowj);
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
  }
  return 0;
}

static void do_restore_host(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject restore_host: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[512];
  isolate_stamp_path(path, sizeof(path));

  int rc = 0;
  if (isolate_stamp_only_mode()) {
    const char *hook = getenv("EDR_RESTORE_HOOK");
    if (!hook || !hook[0]) {
      hook = getenv("EDR_ISOLATE_RESTORE_HOOK");
    }
    if (hook && hook[0]) {
      isolate_setenv("EDR_CMD_ID", cmd_id ? cmd_id : "");
      rc = (system(hook) == 0) ? 0 : -1;
    }
  } else {
    rc = isolate_run(0, cmd_id);
  }
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "restore_host: enforcement 撤销失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "restore enforcement failed");
    return;
  }
  if (remove(path) != 0 && errno != ENOENT) {
    s_exec_fail++;
    audit_both(cmd_id, "restore_host: stamp remove failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "stamp remove failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  {
    char pathj[700], detail[1024];
    json_escape_to(pathj, sizeof(pathj), path);
    snprintf(detail, sizeof(detail), "{\"status\":\"restored\",\"stamp_path\":%s}", pathj);
    audit_both(cmd_id, "restore_host: ok");
    soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
  }
}

static void do_isolate_status(const char *cmd_id, const EdrSoarCommandMeta *sm) {
  char path[512];
  isolate_stamp_path(path, sizeof(path));
  int exists = 0;
  FILE *f = fopen(path, "r");
  if (f) {
    exists = 1;
    fclose(f);
  }
  int verified = 0;
  const char *verification = "not_isolated";
  char evidence[2048];
  evidence[0] = '\0';
  if (exists && isolate_stamp_only_mode()) {
    verification = "stamp_only";
  } else if (exists) {
    int rc = isolate_run_status(evidence, sizeof(evidence));
    const char *status_hook = getenv("EDR_ISOLATE_STATUS_HOOK");
    if (rc == 0 && ((status_hook && status_hook[0]) || isolate_status_reports_active(evidence))) {
      verified = 1;
      verification = "enforcement_status";
    } else {
      verification = rc == -2 ? "enforcement_unavailable" : "enforcement_not_active";
    }
  }
  char pathj[700], detail[2600];
  json_escape_to(pathj, sizeof(pathj), path);
  snprintf(detail, sizeof(detail),
           "{\"isolated\":%s,\"stamp_present\":%s,\"enforcement_verified\":%s,"
           "\"verification\":\"%s\",\"stamp_path\":%s}",
           (exists && (isolate_stamp_only_mode() || verified)) ? "true" : "false",
           exists ? "true" : "false", verified ? "true" : "false", verification, pathj);
  s_handled++;
  s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

/* 自动勒索处置只允许结束事件归属的进程，并在 OS 层确认进程确实退出，避免把
 * “信号已发送”误报成“加密进程已停止”。手工 kill 仍走 do_kill 的完整命令路径。 */
static int ransom_terminate_pid_checked(uint32_t pid, char *detail, size_t detail_cap) {
  if (detail && detail_cap > 0u) {
    detail[0] = '\0';
  }
  if (pid <= 4u) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "protected pid=%u", (unsigned)pid);
    }
    return -1;
  }
  if (!kill_pid_allowed((long)pid)) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "pid=%u blocked by EDR_CMD_KILL_ALLOWLIST", (unsigned)pid);
    }
    return -2;
  }
#ifdef _WIN32
  if ((DWORD)pid == GetCurrentProcessId()) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "refuse agent pid=%u", (unsigned)pid);
    }
    return -1;
  }
  HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, (DWORD)pid);
  if (!h) {
    if (GetLastError() == ERROR_INVALID_PARAMETER) {
      if (detail && detail_cap > 0u) {
        snprintf(detail, detail_cap, "process pid=%u already gone", (unsigned)pid);
      }
      return 0;
    }
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "OpenProcess failed pid=%u error=%lu", (unsigned)pid,
               (unsigned long)GetLastError());
    }
    return -3;
  }
  if (!TerminateProcess(h, 1)) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "TerminateProcess failed pid=%u error=%lu", (unsigned)pid,
               (unsigned long)GetLastError());
    }
    CloseHandle(h);
    return -3;
  }
  DWORD wait_rc = WaitForSingleObject(h, 1000u);
  CloseHandle(h);
  if (wait_rc != WAIT_OBJECT_0) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "pid=%u still running after TerminateProcess", (unsigned)pid);
    }
    return -4;
  }
  if (detail && detail_cap > 0u) {
    snprintf(detail, detail_cap, "pid=%u terminated", (unsigned)pid);
  }
  return 0;
#else
  if ((pid_t)pid == getpid()) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "refuse agent pid=%u", (unsigned)pid);
    }
    return -1;
  }
  if (kill((pid_t)pid, SIGTERM) != 0) {
    if (errno == ESRCH) {
      if (detail && detail_cap > 0u) {
        snprintf(detail, detail_cap, "process pid=%u already gone", (unsigned)pid);
      }
      return 0;
    }
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "SIGTERM failed pid=%u errno=%d", (unsigned)pid, errno);
    }
    return -3;
  }
  for (int i = 0; i < 5; i++) {
    struct timespec ts = {0, 50L * 1000L * 1000L};
    nanosleep(&ts, NULL);
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
      if (detail && detail_cap > 0u) {
        snprintf(detail, detail_cap, "pid=%u terminated via SIGTERM", (unsigned)pid);
      }
      return 0;
    }
  }
  if (kill((pid_t)pid, SIGKILL) != 0 && errno != ESRCH) {
    if (detail && detail_cap > 0u) {
      snprintf(detail, detail_cap, "SIGKILL failed pid=%u errno=%d", (unsigned)pid, errno);
    }
    return -4;
  }
  for (int i = 0; i < 10; i++) {
    struct timespec ts = {0, 50L * 1000L * 1000L};
    nanosleep(&ts, NULL);
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
      if (detail && detail_cap > 0u) {
        snprintf(detail, detail_cap, "pid=%u terminated via SIGKILL", (unsigned)pid);
      }
      return 0;
    }
  }
  if (detail && detail_cap > 0u) {
    snprintf(detail, detail_cap, "pid=%u remains visible after SIGKILL", (unsigned)pid);
  }
  return -5;
#endif
}

static void ransom_auto_meta(uint32_t pid, EdrSoarCommandMeta *sm) {
  if (!sm) {
    return;
  }
  memset(sm, 0, sizeof(*sm));
  snprintf(sm->soar_correlation_id, sizeof(sm->soar_correlation_id), "ransom-auto-%u", (unsigned)pid);
  snprintf(sm->playbook_run_id, sizeof(sm->playbook_run_id), "ransom-auto");
  snprintf(sm->idempotency_key, sizeof(sm->idempotency_key), "ransom-auto-%u", (unsigned)pid);
  snprintf(sm->initiated_by, sizeof(sm->initiated_by), "automatic");
  sm->issued_at_unix_ms = command_now_ms();
}

void edr_isolate_auto_from_shellcode_alarm(void) {
#if !defined(_WIN32)
  return;
#else
  if (!edr_command_get_config() || !edr_command_get_config()->shellcode_detector.auto_isolate_execute) {
    return;
  }
  if (!dangerous_enabled()) {
    return;
  }
  static volatile LONG s_shellcode_auto_iso_once;
  if (InterlockedCompareExchange(&s_shellcode_auto_iso_once, 1, 0) != 0) {
    return;
  }
  do_isolate("auto-shellcode", NULL);
#endif
}

void edr_isolate_auto_from_ransom_alarm(uint32_t pid) {
  /* 默认关:显式启用后才执行自动终止/隔离，且仍受高危策略保护。 */
  const char *eo = getenv("EDR_RANSOM_AUTO_ISOLATE");
  if ((!eo || eo[0] != '1') && edr_policy_v2_mode_for_category("impact") != EDR_POLICY_MODE_BLOCK) {
    return;
  }
  if (!dangerous_enabled()) {
    return;
  }
  EdrSoarCommandMeta sm;
  ransom_auto_meta(pid, &sm);

  const char *to = getenv("EDR_RANSOM_AUTO_TERMINATE");
  if (to && to[0] == '1' && pid > 0u) {
    static uint32_t s_ransom_auto_terminated_pid;
    if (s_ransom_auto_terminated_pid != pid) {
      EdrSoarCommandMeta terminate_sm = sm;
      snprintf(terminate_sm.idempotency_key, sizeof(terminate_sm.idempotency_key),
               "ransom-auto-%u-terminate", (unsigned)pid);
      char detail[256];
      int rc = ransom_terminate_pid_checked(pid, detail, sizeof(detail));
      s_ransom_auto_terminated_pid = rc == 0 ? pid : 0u;
      char cmd_id[96];
      snprintf(cmd_id, sizeof(cmd_id), "cmd_auto_ransom_%u_terminate", (unsigned)pid);
      if (rc == 0) {
        audit_both(cmd_id, detail);
        soar_emit(cmd_id, &terminate_sm, EdrCmdExecOk, 0, detail);
      } else if (rc == -2 || rc == -1) {
        audit_both(cmd_id, detail);
        soar_emit(cmd_id, &terminate_sm, EdrCmdExecRejected, rc == -2 ? 7 : 5, detail);
      } else {
        audit_both(cmd_id, detail);
        soar_emit(cmd_id, &terminate_sm, EdrCmdExecFailed, -rc, detail);
      }
    }
  }

  static int s_ransom_auto_iso_success;
  static uint32_t s_ransom_auto_iso_attempts;
  static int64_t s_ransom_auto_iso_last_attempt_ms;
  if (s_ransom_auto_iso_success) {
    return;
  }
  uint32_t max_attempts = command_u32_env_clamped("EDR_RANSOM_AUTO_ISOLATE_MAX_ATTEMPTS", 3u, 1u, 10u);
  uint32_t retry_s = command_u32_env_clamped("EDR_RANSOM_AUTO_ISOLATE_RETRY_S", 5u, 1u, 300u);
  int64_t now_ms = command_now_ms();
  if (s_ransom_auto_iso_attempts >= max_attempts ||
      (s_ransom_auto_iso_last_attempt_ms > 0 &&
       now_ms - s_ransom_auto_iso_last_attempt_ms < (int64_t)retry_s * 1000LL)) {
    return;
  }
  s_ransom_auto_iso_attempts++;
  s_ransom_auto_iso_last_attempt_ms = now_ms;
  char cmd_id[96];
  snprintf(cmd_id, sizeof(cmd_id), "cmd_auto_ransom_%u_isolate_%u", (unsigned)pid,
           (unsigned)s_ransom_auto_iso_attempts);
  EdrSoarCommandMeta isolate_sm = sm;
  snprintf(isolate_sm.idempotency_key, sizeof(isolate_sm.idempotency_key),
           "ransom-auto-%u-isolate-%u", (unsigned)pid, (unsigned)s_ransom_auto_iso_attempts);
  if (do_isolate(cmd_id, &isolate_sm) == 0) {
    s_ransom_auto_iso_success = 1;
  }
}

static int forensic_copy_one_file(const char *src, const char *dst) {
#ifdef _WIN32
  return CopyFileA(src, dst, FALSE) ? 0 : -1;
#else
  int fi = open(src, O_RDONLY);
  if (fi < 0) {
    return -1;
  }
  int fo = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fo < 0) {
    close(fi);
    return -1;
  }
  char buf[65536];
  ssize_t nr;
  while ((nr = read(fi, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < nr) {
      ssize_t nw = write(fo, buf + off, (size_t)(nr - off));
      if (nw <= 0) {
        close(fi);
        close(fo);
        return -1;
      }
      off += nw;
    }
  }
  close(fi);
  close(fo);
  return nr < 0 ? -1 : 0;
#endif
}

static int mkdir_one_quiet(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
    return 0;
  }
  return -1;
#else
  if (mkdir(path, 0755) == 0 || errno == EEXIST) {
    return 0;
  }
  return -1;
#endif
}

static int mkdir_p_quiet(char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  char tmp[700];
  snprintf(tmp, sizeof(tmp), "%s", path);
  size_t n = strlen(tmp);
  while (n > 1u && (tmp[n - 1u] == '/' || tmp[n - 1u] == '\\')) {
    tmp[--n] = '\0';
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      char save = *p;
      *p = '\0';
#ifdef _WIN32
      if (!(strlen(tmp) == 2u && tmp[1] == ':')) {
        (void)mkdir_one_quiet(tmp);
      }
#else
      (void)mkdir_one_quiet(tmp);
#endif
      *p = save;
    }
  }
  return mkdir_one_quiet(tmp);
}

static const char *path_basename_c(const char *path) {
  const char *b = path && path[0] ? path : "file";
  for (const char *p = b; *p; p++) {
    if (*p == '/' || *p == '\\') {
      b = p + 1;
    }
  }
  return b && b[0] ? b : "file";
}

static void sanitize_component(char *s) {
  if (!s) {
    return;
  }
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (!isalnum(c) && *s != '-' && *s != '_' && *s != '.') {
      *s = '_';
    }
  }
}

static int file_exists_c(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
#ifdef _WIN32
  DWORD a = GetFileAttributesA(path);
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

static int file_size_mtime(const char *path, unsigned long long *size_out, long long *mtime_out) {
  if (!path || !path[0]) {
    return -1;
  }
#ifdef _WIN32
  WIN32_FILE_ATTRIBUTE_DATA d;
  if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d) || (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    return -1;
  }
  ULARGE_INTEGER sz;
  sz.HighPart = d.nFileSizeHigh;
  sz.LowPart = d.nFileSizeLow;
  if (size_out) {
    *size_out = sz.QuadPart;
  }
  if (mtime_out) {
    ULARGE_INTEGER ft;
    ft.HighPart = d.ftLastWriteTime.dwHighDateTime;
    ft.LowPart = d.ftLastWriteTime.dwLowDateTime;
    *mtime_out = (long long)((ft.QuadPart / 10000000ULL) - 11644473600ULL);
  }
  return 0;
#else
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
    return -1;
  }
  if (size_out) {
    *size_out = (unsigned long long)st.st_size;
  }
  if (mtime_out) {
    *mtime_out = (long long)st.st_mtime;
  }
  return 0;
#endif
}

static int file_sha256_hex(const char *path, char out65[65]) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    if (out65) {
      out65[0] = '\0';
    }
    return -1;
  }
  EdrSha256Ctx ctx;
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t buf[65536];
  edr_sha256_init(&ctx);
  for (;;) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (n > 0u) {
      edr_sha256_update(&ctx, buf, n);
    }
    if (n < sizeof(buf)) {
      if (ferror(f)) {
        fclose(f);
        out65[0] = '\0';
        return -1;
      }
      break;
    }
  }
  fclose(f);
  edr_sha256_final(&ctx, digest);
  static const char *hex = "0123456789abcdef";
  for (size_t i = 0; i < EDR_SHA256_DIGEST_LEN; i++) {
    out65[i * 2u] = hex[(digest[i] >> 4) & 0x0f];
    out65[i * 2u + 1u] = hex[digest[i] & 0x0f];
  }
  out65[64] = '\0';
  return 0;
}

static void quarantine_base_dir(char *out, size_t cap) {
  const char *e = getenv("EDR_QUARANTINE_DIR");
  if (e && e[0]) {
    snprintf(out, cap, "%s", e);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\quarantine");
#else
  snprintf(out, cap, "%s", "/tmp/edr_quarantine");
#endif
}

static int quarantine_path_allowed(const char *base, const char *path) {
  if (!base || !base[0] || !path || !path[0]) {
    return 0;
  }
  size_t n = strlen(base);
  while (n > 0u && (base[n - 1u] == '/' || base[n - 1u] == '\\')) {
    n--;
  }
#ifdef _WIN32
  if (_strnicmp(base, path, n) != 0) {
    return 0;
  }
#else
  if (strncmp(base, path, n) != 0) {
    return 0;
  }
#endif
  return path[n] == '/' || path[n] == '\\';
}

static int move_file_cross_volume(const char *src, const char *dst) {
#ifdef _WIN32
  return MoveFileExA(src, dst, MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
  if (rename(src, dst) == 0) {
    return 0;
  }
  if (errno == EXDEV && forensic_copy_one_file(src, dst) == 0 && remove(src) == 0) {
    return 0;
  }
  return -1;
#endif
}

/* 隔离件加锁:防止被读回 / 再次执行(证据保全)。
   Windows:受限 DACL(仅 Administrators+SYSTEM 全权,其余因无 ACE 隐式拒绝)+ 只读/隐藏/系统属性;
   POSIX:chmod 0400(去执行/写位,仅属主可读,以便特权 agent 后续还原)。 */
static void quarantine_lock(const char *p) {
#ifdef _WIN32
  PSECURITY_DESCRIPTOR sd = NULL;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
          "D:P(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1, &sd, NULL)) {
    (void)SetFileSecurityA(p, DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
  }
  (void)SetFileAttributesA(p, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
#else
  (void)chmod(p, 0400);
#endif
}

/* 还原前解锁:清掉只读/隐藏/系统属性,确保 move/删除可进行。 */
static void quarantine_unlock(const char *p) {
#ifdef _WIN32
  (void)SetFileAttributesA(p, FILE_ATTRIBUTE_NORMAL);
#else
  (void)chmod(p, 0600);
#endif
}

static void do_file_stat(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  unsigned long long sz = 0;
  long long mt = 0;
  char sha[65];
  sha[0] = '\0';
  if (file_size_mtime(path, &sz, &mt) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  (void)file_sha256_hex(path, sha);
  char detail[1800];
  snprintf(detail, sizeof(detail),
           "{\"path\":\"%s\",\"size\":%llu,\"mtime\":%lld,\"sha256\":\"%s\"}",
           path, sz, mt, sha);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_file_stat: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static int parse_int_json_default(const uint8_t *p, size_t len, const char *key, int defv) {
  int value = defv;
  return edr_parse_json_int(p, len, key, &value) ? value : defv;
}

static int ascii_case_equal(const char *a, const char *b) {
  if (!a || !b) {
    return 0;
  }
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static int env_int_default(const char *name, int defv) {
  const char *e = getenv(name);
  if (!e || !e[0]) {
    return defv;
  }
  char *end = NULL;
  long v = strtol(e, &end, 10);
  if (end == e) {
    return defv;
  }
  if (v < 1) {
    return 1;
  }
  if (v > 300) {
    return 300;
  }
  return (int)v;
}

static void rtr_shell_normalize_token(const char *raw, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!raw) {
    return;
  }
  while (*raw && isspace((unsigned char)*raw)) {
    raw++;
  }
  char tmp[256];
  size_t n = 0;
  while (raw[n] && !isspace((unsigned char)raw[n]) && raw[n] != ',' && raw[n] != ';' && n + 1u < sizeof(tmp)) {
    tmp[n] = raw[n];
    n++;
  }
  tmp[n] = '\0';
  while (n > 0u && isspace((unsigned char)tmp[n - 1u])) {
    tmp[--n] = '\0';
  }
  if (n >= 2u && ((tmp[0] == '"' && tmp[n - 1u] == '"') || (tmp[0] == '\'' && tmp[n - 1u] == '\''))) {
    memmove(tmp, tmp + 1u, n - 2u);
    tmp[n - 2u] = '\0';
  }
  const char *base = tmp;
  for (const char *p = tmp; *p; p++) {
    if (*p == '/' || *p == '\\') {
      base = p + 1;
    }
  }
  size_t o = 0;
  for (const char *p = base; *p && o + 1u < cap; p++) {
    out[o++] = (char)tolower((unsigned char)*p);
  }
  out[o] = '\0';
  size_t olen = strlen(out);
  if (olen > 4u && strcmp(out + olen - 4u, ".exe") == 0) {
    out[olen - 4u] = '\0';
  } else if (olen > 4u && strcmp(out + olen - 4u, ".com") == 0) {
    out[olen - 4u] = '\0';
  }
}

static void rtr_shell_first_token(const char *command, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!command) {
    return;
  }
  while (*command && isspace((unsigned char)*command)) {
    command++;
  }
  char raw[256];
  size_t n = 0;
  if (*command == '"' || *command == '\'') {
    char quote = *command++;
    while (*command && *command != quote && n + 1u < sizeof(raw)) {
      raw[n++] = *command++;
    }
  } else {
    while (*command && !isspace((unsigned char)*command) && n + 1u < sizeof(raw)) {
      raw[n++] = *command++;
    }
  }
  raw[n] = '\0';
  rtr_shell_normalize_token(raw, out, cap);
}

static int rtr_shell_has_control_operator(const char *command) {
  if (!command) {
    return 1;
  }
  for (const char *p = command; *p; p++) {
    if (*p == '\n' || *p == '\r' || *p == ';' || *p == '|' || *p == '`' || *p == '<' || *p == '>') {
      return 1;
    }
    if (*p == '&') {
      return 1;
    }
    if (*p == '$' && p[1] == '(') {
      return 1;
    }
  }
  return 0;
}

static void lower_copy(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t i = 0;
  if (!src) {
    src = "";
  }
  for (; src[i] && i + 1u < cap; i++) {
    dst[i] = (char)tolower((unsigned char)src[i]);
  }
  dst[i] = '\0';
}

static int rtr_shell_matches_block_term(const char *lower_cmd, const char *term) {
  if (!lower_cmd || !term || !term[0]) {
    return 0;
  }
  char padded[2300];
  snprintf(padded, sizeof(padded), " %s ", lower_cmd);
  return strstr(padded, term) != NULL || strstr(lower_cmd, term) != NULL;
}

static int rtr_shell_blocked(const char *command, char *reason, size_t reason_cap) {
  char lower[2200];
  lower_copy(lower, sizeof(lower), command);
  static const char *const defaults[] = {
      " rm ", " del ", " erase ", " rmdir ", " rd ", " format ", " fdisk ",
      " shutdown", " reboot", " halt", " poweroff", " logoff", " taskkill",
      " pkill ", " kill ", " reg delete", " reg add", " reg import", " sc delete",
      " net user", " net localgroup", " wevtutil cl", " vssadmin delete", " cipher /w",
      " bcdedit", "-encodedcommand", " encodedcommand", " frombase64string",
      " invoke-expression", " iex ", " downloadstring", " downloadfile", NULL};
  for (int i = 0; defaults[i]; i++) {
    if (rtr_shell_matches_block_term(lower, defaults[i])) {
      snprintf(reason, reason_cap, "blocked term: %s", defaults[i]);
      return 1;
    }
  }
  const char *extra = getenv("EDR_RTR_SHELL_BLOCKLIST");
  if (!extra || !extra[0]) {
    return 0;
  }
  char list[2048];
  snprintf(list, sizeof(list), "%s", extra);
  char *p = list;
  while (p && *p) {
    char *sep = strpbrk(p, ",;");
    if (sep) {
      *sep++ = '\0';
    }
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    char term[256];
    lower_copy(term, sizeof(term), p);
    size_t n = strlen(term);
    while (n > 0u && isspace((unsigned char)term[n - 1u])) {
      term[--n] = '\0';
    }
    if (term[0] && rtr_shell_matches_block_term(lower, term)) {
      snprintf(reason, reason_cap, "blocked by EDR_RTR_SHELL_BLOCKLIST: %s", term);
      return 1;
    }
    p = sep;
  }
  return 0;
}

static int rtr_shell_token_allowed(const char *token, char *matched, size_t matched_cap,
                                   char *reason, size_t reason_cap) {
  if (matched && matched_cap > 0u) {
    matched[0] = '\0';
  }
  if (!token || !token[0]) {
    snprintf(reason, reason_cap, "missing executable token");
    return 0;
  }
  const char *list_src = NULL;
  const char *source = "policy";
  if (edr_command_get_config() && edr_command_get_config()->command.rtr_shell_allowlist[0]) {
    list_src = edr_command_get_config()->command.rtr_shell_allowlist;
  }
  if (!list_src || !list_src[0]) {
    list_src = getenv("EDR_RTR_SHELL_ALLOWLIST");
    source = "EDR_RTR_SHELL_ALLOWLIST";
  }
  if (!list_src || !list_src[0]) {
    list_src = getenv("EDR_SHELL_ALLOWLIST");
    source = "EDR_SHELL_ALLOWLIST";
  }
  if (!list_src || !list_src[0]) {
    snprintf(reason, reason_cap, "rtr_shell allowlist not configured");
    return 0;
  }
  char list_buf[2048];
  snprintf(list_buf, sizeof(list_buf), "%s", list_src);
  char *p = list_buf;
  while (p && *p) {
    char *sep = strpbrk(p, ",;");
    if (sep) {
      *sep++ = '\0';
    }
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    char item[128];
    rtr_shell_normalize_token(p, item, sizeof(item));
    if (item[0] && ascii_case_equal(token, item)) {
      if (matched && matched_cap > 0u) {
        snprintf(matched, matched_cap, "%s", item);
      }
      return 1;
    }
    p = sep;
  }
  snprintf(reason, reason_cap, "command token not in allowlist (%s): %s", source, token);
  return 0;
}

#ifdef _WIN32
static void rtr_shell_output_to_utf8(char *s, size_t cap) {
  if (!s || !s[0] || cap == 0u) {
    return;
  }
  int wlen = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
  if (wlen <= 0) {
    return;
  }
  wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
  if (!wbuf) {
    return;
  }
  if (MultiByteToWideChar(CP_ACP, 0, s, -1, wbuf, wlen) > 0) {
    int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
    if (u8len > 0 && (size_t)u8len < cap) {
      (void)WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, s, u8len, NULL, NULL);
    }
  }
  free(wbuf);
}
#endif

static int rtr_shell_cancel_check(void *user) {
  return edr_command_cancel_requested((const char *)user);
}

static void do_rtr_shell(const char *cmd_id, const uint8_t *pl, size_t len,
                         const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_shell: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled", "denied", NULL);
    return;
  }
  char command[2048];
  if (parse_json_string_field(pl, len, "command", command, sizeof(command)) != 0 &&
      parse_json_string_field(pl, len, "cmd", command, sizeof(command)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: payload 缺少 command");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 2, "missing command", "failed", NULL);
    return;
  }
  if (rtr_shell_has_control_operator(command)) {
    s_rejected++;
    audit_both(cmd_id, "rtr_shell: rejected control operator");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 3, "control operators are not allowed", "denied", NULL);
    return;
  }
  char token[128];
  char allow_item[128];
  char reason[256];
  rtr_shell_first_token(command, token, sizeof(token));
  reason[0] = '\0';
  if (!rtr_shell_token_allowed(token, allow_item, sizeof(allow_item), reason, sizeof(reason))) {
    s_rejected++;
    audit_both(cmd_id, reason[0] ? reason : "rtr_shell: command not allowlisted");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 4,
                 reason[0] ? reason : "command not allowlisted", "denied", NULL);
    return;
  }
  reason[0] = '\0';
  if (rtr_shell_blocked(command, reason, sizeof(reason))) {
    s_rejected++;
    audit_both(cmd_id, reason[0] ? reason : "rtr_shell: blocked command");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 5,
                 reason[0] ? reason : "command blocked", "denied", NULL);
    return;
  }
  int timeout_sec = parse_int_json_default(pl, len, "timeout_sec", 30);
  timeout_sec = parse_int_json_default(pl, len, "timeout_s", timeout_sec);
  int max_timeout = edr_command_get_config() && edr_command_get_config()->command.rtr_shell_max_timeout_sec > 0u
                        ? (int)edr_command_get_config()->command.rtr_shell_max_timeout_sec
                        : env_int_default("EDR_RTR_SHELL_MAX_TIMEOUT_SEC", 60);
  if (timeout_sec <= 0) {
    timeout_sec = 30;
  }
  if (timeout_sec > max_timeout) {
    timeout_sec = max_timeout;
  }
  if (sm && sm->issued_at_unix_ms > 0 && sm->deadline_ms > 0u) {
    int64_t remaining_ms = sm->issued_at_unix_ms + (int64_t)sm->deadline_ms - command_now_ms();
    if (remaining_ms <= 0) {
      s_rejected++;
      audit_both(cmd_id, "rtr_shell: deadline expired before execution");
      soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 124, "deadline expired before execution", "timeout", NULL);
      return;
    }
    int remaining_sec = (int)((remaining_ms + 999) / 1000);
    if (remaining_sec > 0 && timeout_sec > remaining_sec) {
      timeout_sec = remaining_sec;
    }
  }
  char audit_msg[2400];
  snprintf(audit_msg, sizeof(audit_msg), "rtr_shell: start token=%s timeout_sec=%d command=%.2000s",
           token, timeout_sec, command);
  audit_both(cmd_id, audit_msg);

  char out[8192];
  int exit_code = 0;
  int rc = edr_shell_exec_cancellable(command, timeout_sec, out, sizeof(out), &exit_code,
                                      rtr_shell_cancel_check, (void *)cmd_id);
#ifdef _WIN32
  rtr_shell_output_to_utf8(out, sizeof(out));
#endif
  char commandj[4300], tokenj[300], outputj[10000], detail[16000];
  json_escape_to(commandj, sizeof(commandj), command);
  json_escape_to(tokenj, sizeof(tokenj), token);
  json_escape_to(outputj, sizeof(outputj), out);
  snprintf(detail, sizeof(detail),
           "{\"command\":%s,\"allowed_token\":%s,\"timeout_sec\":%d,"
           "\"exit_code\":%d,\"output_truncated\":%s,\"output\":%s}",
           commandj, tokenj, timeout_sec, exit_code,
           strlen(out) + 1u >= sizeof(out) ? "true" : "false", outputj);
  s_handled++;
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: exec failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, exit_code ? exit_code : 6, detail, "failed", NULL);
    return;
  }
  if (exit_code == 124) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: timeout");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 124, detail, "timeout", NULL);
    return;
  }
  if (exit_code == 130 || edr_command_cancel_requested(cmd_id)) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: cancelled");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 130, detail, "cancelled", NULL);
    return;
  }
  if (exit_code != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_shell: command returned non-zero");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, exit_code, detail, "failed", NULL);
    return;
  }
  s_exec_ok++;
  audit_both(cmd_id, "rtr_shell: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void shell_stream_output_cb(const char *sid, uint64_t seq, const char *data, size_t len,
                                   int exit_code, bool closed, void *user) {
  (void)user;
  if (!sid || !sid[0]) {
    return;
  }
  char cmd_id[160];
  snprintf(cmd_id, sizeof(cmd_id), "%s.s%06llu", sid, (unsigned long long)seq);

  char sessionj[300], streamj[40], dataj[EDR_COMMAND_STATE_DETAIL_CAP], detail[EDR_COMMAND_STATE_DETAIL_CAP];
  json_escape_to(sessionj, sizeof(sessionj), sid);
  json_escape_to(streamj, sizeof(streamj), "stdout");
  if (closed && !data) {
    json_escape_to(dataj, sizeof(dataj), "");
  } else if (data && len > 0u) {
    size_t cp = len < EDR_SS_STREAM_CHUNK_BYTES ? len : EDR_SS_STREAM_CHUNK_BYTES;
    char raw[EDR_SS_STREAM_CHUNK_BYTES + 1u];
    memcpy(raw, data, cp);
    raw[cp] = '\0';
    json_escape_to(dataj, sizeof(dataj), raw);
  } else {
    return;
  }
  snprintf(detail, sizeof(detail),
           "{\"schema\":\"edr.shell.stream.v1\",\"session_id\":%s,\"seq\":%llu,"
           "\"stream\":%s,\"data\":%s,\"exit_code\":%d,\"closed\":%s}",
           sessionj, (unsigned long long)seq, streamj, dataj, exit_code,
           closed ? "true" : "false");

  EdrSoarCommandMeta dummy;
  memset(&dummy, 0, sizeof(dummy));
  snprintf(dummy.soar_correlation_id, sizeof(dummy.soar_correlation_id), "%s", sid);
  if (edr_command_state_finish(cmd_id, "shell_stream", &dummy, closed ? "closed" : "ok",
                               (int)EdrCmdExecOk, exit_code, detail, "", 1) == 0) {
    edr_command_state_delete_inbox(cmd_id);
  } else {
    audit_both(cmd_id, "shell_stream state persist failed");
  }
}

static void ensure_shell_session_initialized(void) {
  static int initialized = 0;
  if (!initialized) {
    edr_shell_session_init(EDR_SS_MAX_SESSIONS, 600u, EDR_SS_BUF_KB, shell_stream_output_cb, NULL);
    initialized = 1;
  }
}

static void do_shell_open(const char *cmd_id, const uint8_t *pl, size_t len,
                          const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "shell_open: rejected (allow_dangerous=false)");
    soar_emit_ex(cmd_id, sm, EdrCmdExecRejected, 1,
                 "interactive shell disabled: enable TOML [command] allow_dangerous=true via Agent policy",
                 "denied", NULL);
    return;
  }
  char shell_type[128];
#ifdef _WIN32
  snprintf(shell_type, sizeof(shell_type), "%s", "cmd.exe /Q /K chcp 65001 > nul");
#else
  snprintf(shell_type, sizeof(shell_type), "%s", "/bin/sh");
#endif
  char requested_shell[128];
  requested_shell[0] = '\0';
  if (parse_json_string_field(pl, len, "shell_type", requested_shell,
                              sizeof(requested_shell)) == 0 && requested_shell[0]) {
    snprintf(shell_type, sizeof(shell_type), "%s", requested_shell);
  }
  ensure_shell_session_initialized();
  int rc = edr_shell_session_open(cmd_id, shell_type);
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_open: failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, rc, "shell_open failed", "failed", NULL);
    return;
  }
  s_handled++;
  s_exec_ok++;
  char detail[180];
  snprintf(detail, sizeof(detail), "shell session opened: %s", shell_type);
  audit_both(cmd_id, "shell_open: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void do_shell_input(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  char input[4096];
  session_id[0] = '\0';
  input[0] = '\0';
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  (void)edr_parse_json_string(pl, len, "input", input, sizeof(input));
  if (!session_id[0] || !input[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_input: missing session_id or input");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id or input", "failed", NULL);
    return;
  }
  size_t ilen = strlen(input);
#ifdef _WIN32
  if (ilen + 2u <= sizeof(input)) {
    input[ilen++] = '\r';
    input[ilen++] = '\n';
  }
#else
  if (ilen + 1u <= sizeof(input)) {
    input[ilen++] = '\n';
  }
#endif
  int rc = edr_shell_session_input(session_id, input, ilen);
  if (rc != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_input: write failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, rc,
                 "shell_input write failed: shell session not open or stdin unavailable",
                 "failed", NULL);
    return;
  }
  s_handled++;
  s_exec_ok++;
  char detail[160];
  snprintf(detail, sizeof(detail), "shell_input sent %zu bytes to session %s", ilen, session_id);
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
}

static void do_shell_close(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  char session_id[EDR_SS_ID_LEN];
  session_id[0] = '\0';
  (void)edr_parse_json_string(pl, len, "session_id", session_id, sizeof(session_id));
  if (!session_id[0]) {
    s_exec_fail++;
    audit_both(cmd_id, "shell_close: missing session_id");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 1, "missing session_id", "failed", NULL);
    return;
  }
  edr_shell_session_close(session_id);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "shell_close: ok");
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, "shell session closed", "ok", NULL);
}

static void do_rtr_get_file(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_get_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  unsigned long long sz = 0;
  long long mt = 0;
  if (file_size_mtime(path, &sz, &mt) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  int max_size = parse_int_json_default(pl, len, "max_size_bytes", 100 * 1024 * 1024);
  if (max_size <= 0) {
    max_size = 100 * 1024 * 1024;
  }
  if (sz > (unsigned long long)max_size) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "file size exceeds max_size_bytes");
    return;
  }
  char sha[65];
  sha[0] = '\0';
  if (file_sha256_hex(path, sha) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "sha256 failed");
    return;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "rtr_get_file", path, sha,
                                                        minio_key, sizeof(minio_key));
  char pathj[1400], keyj[1400], artifacts[3600], detail[4096];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(keyj, sizeof(keyj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"rtr_file\",\"path\":%s,\"sha256\":\"%s\",\"size\":%llu,"
           "\"mtime\":%lld,\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, sz, mt, upload_rc == 0 ? "ok" : "failed", keyj);
  snprintf(detail, sizeof(detail),
           "{\"path\":%s,\"sha256\":\"%s\",\"size\":%llu,\"mtime\":%lld,"
           "\"upload_status\":\"%s\",\"minio_key\":%s}",
           pathj, sha, sz, mt, upload_rc == 0 ? "ok" : "failed", keyj);
  s_handled++;
  if (upload_rc == 0) {
    s_exec_ok++;
    audit_both(cmd_id, "rtr_get_file: upload ok");
    soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
  } else {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_get_file: file readable but upload failed");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 6, detail, "partial_success", artifacts);
  }
}

static void do_rtr_rm_file(const char *cmd_id, const uint8_t *pl, size_t len,
                           const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject rtr_rm_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path payload");
    return;
  }
  if (!file_exists_c(path)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "file not found or not regular");
    return;
  }
  if (remove(path) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_rm_file: remove failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "remove failed");
    return;
  }
  char pathj[1400], detail[1600];
  json_escape_to(pathj, sizeof(pathj), path);
  snprintf(detail, sizeof(detail), "{\"removed\":true,\"path\":%s}", pathj);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_rm_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void command_artifact_path(const char *cmd_id, const char *prefix, const char *ext,
                                  char *out, size_t cap) {
  const char *base = getenv("EDR_RESPONSE_ARTIFACT_DIR");
  char root[700];
  if (base && base[0]) {
    snprintf(root, sizeof(root), "%s", base);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(root, sizeof(root), "%s\\edr_response", tmp);
#else
    snprintf(root, sizeof(root), "%s", "/tmp/edr_response");
#endif
  }
  (void)mkdir_p_quiet(root);
  char safe[180];
  snprintf(safe, sizeof(safe), "%s", (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
  sanitize_component(safe);
#ifdef _WIN32
  snprintf(out, cap, "%s\\%s_%s_%lld.%s", root, prefix ? prefix : "artifact", safe,
           (long long)time(NULL), ext ? ext : "json");
#else
  snprintf(out, cap, "%s/%s_%s_%lld.%s", root, prefix ? prefix : "artifact", safe,
           (long long)time(NULL), ext ? ext : "json");
#endif
}

static void fprint_json_escaped(FILE *f, const char *s) {
  if (!f) {
    return;
  }
  if (!s) {
    s = "";
  }
  for (const char *p = s; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc(c, f);
    } else if (c == '\n') {
      fputs("\\n", f);
    } else if (c == '\r') {
      fputs("\\r", f);
    } else if (c == '\t') {
      fputs("\\t", f);
    } else if (c >= 32u) {
      fputc(c, f);
    } else {
      fputc(' ', f);
    }
  }
}

#ifdef _WIN32
#define EDR_EVENTLOG_XML_MAX (256u * 1024u)

static void eventlog_xml_text(const char *xml, const char *tag, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!xml || !tag) {
    return;
  }
  char open[64];
  snprintf(open, sizeof(open), "<%s", tag);
  const char *p = strstr(xml, open);
  if (!p) {
    return;
  }
  p = strchr(p, '>');
  if (!p) {
    return;
  }
  p++;
  char close[72];
  snprintf(close, sizeof(close), "</%s>", tag);
  const char *end = strstr(p, close);
  if (!end || end <= p) {
    return;
  }
  size_t n = (size_t)(end - p);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, p, n);
  out[n] = '\0';
}

static void eventlog_xml_attr(const char *xml, const char *element, const char *attr,
                              char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  char open[96];
  snprintf(open, sizeof(open), "<%s", element ? element : "");
  const char *p = strstr(xml ? xml : "", open);
  if (!p) {
    return;
  }
  const char *close = strchr(p, '>');
  const char *a = strstr(p, attr ? attr : "");
  if (!a || (close && a > close)) {
    return;
  }
  a = strchr(a, '=');
  if (!a || !a[1]) {
    return;
  }
  char quote = a[1] == '\'' || a[1] == '"' ? a[1] : 0;
  const char *start = quote ? a + 2 : a + 1;
  const char *end = quote ? strchr(start, quote) : strpbrk(start, " \t\r\n>");
  if (!end || end <= start) {
    return;
  }
  size_t n = (size_t)(end - start);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, start, n);
  out[n] = '\0';
}

static void eventlog_write_windows_record(FILE *f, const char *xml) {
  char event_id[64], provider[256], record_id[64], level[64], timestamp[128], message[4096];
  eventlog_xml_text(xml, "EventID", event_id, sizeof(event_id));
  eventlog_xml_attr(xml, "Provider", "Name", provider, sizeof(provider));
  eventlog_xml_text(xml, "EventRecordID", record_id, sizeof(record_id));
  eventlog_xml_text(xml, "Level", level, sizeof(level));
  eventlog_xml_attr(xml, "TimeCreated", "SystemTime", timestamp, sizeof(timestamp));
  eventlog_xml_text(xml, "Message", message, sizeof(message));
  fputs("{\"schema\":\"edr.eventlog.v1\",\"event_id\":\"", f);
  fprint_json_escaped(f, event_id);
  fputs("\",\"provider\":\"", f);
  fprint_json_escaped(f, provider);
  fputs("\",\"record_id\":\"", f);
  fprint_json_escaped(f, record_id);
  fputs("\",\"level\":\"", f);
  fprint_json_escaped(f, level);
  fputs("\",\"timestamp\":\"", f);
  fprint_json_escaped(f, timestamp);
  fputs("\",\"message\":\"", f);
  fprint_json_escaped(f, message);
  fputs("\",\"event_xml\":\"", f);
  fprint_json_escaped(f, xml);
  fputs("\"}", f);
}

static int eventlog_query_to_file(const char *channel, int max_events, FILE *f,
                                  const char *cmd_id) {
  wchar_t wchannel[256];
  if (!channel || !channel[0]) {
    channel = "Security";
  }
  MultiByteToWideChar(CP_UTF8, 0, channel, -1, wchannel, 256);
  EVT_HANDLE hq = EvtQuery(NULL, wchannel, L"*", EvtQueryChannelPath);
  if (!hq) {
    return -1;
  }
  EVT_HANDLE events[16];
  DWORD returned = 0;
  int total = 0;
  int first = 1;
  while (total < max_events) {
    if (edr_command_cancel_requested(cmd_id)) {
      EvtClose(hq);
      return -2;
    }
    if (!EvtNext(hq, 16, events, 1000, 0, &returned)) {
      break;
    }
    for (DWORD i = 0; i < returned; i++) {
      if (edr_command_cancel_requested(cmd_id)) {
        for (DWORD j = i; j < returned; j++) {
          EvtClose(events[j]);
        }
        EvtClose(hq);
        return -2;
      }
      if (total >= max_events) {
        EvtClose(events[i]);
        continue;
      }
      DWORD used = 0;
      DWORD props = 0;
      (void)EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &used, &props);
      if (used > 0u && used < EDR_EVENTLOG_XML_MAX) {
        WCHAR *wxml = (WCHAR *)calloc(1, (size_t)used + sizeof(WCHAR));
        if (wxml && EvtRender(NULL, events[i], EvtRenderEventXml, used, wxml, &used, &props)) {
          int need = WideCharToMultiByte(CP_UTF8, 0, wxml, -1, NULL, 0, NULL, NULL);
          if (need > 1) {
            char *utf8 = (char *)malloc((size_t)need);
            if (utf8) {
              WideCharToMultiByte(CP_UTF8, 0, wxml, -1, utf8, need, NULL, NULL);
              if (!first) {
                fputs(",\n", f);
              }
              first = 0;
              eventlog_write_windows_record(f, utf8);
              total++;
              free(utf8);
            }
          }
        }
        free(wxml);
      }
      EvtClose(events[i]);
    }
  }
  EvtClose(hq);
  return total;
}
#else
static int eventlog_query_to_file(const char *channel, int max_events, FILE *f,
                                  const char *cmd_id) {
  if (max_events <= 0) {
    max_events = 100;
  }
  /* 把 Windows 风格 channel 映射到 journalctl 过滤，未识别时回退全量。 */
  const char *filt = "";
  if (channel && channel[0]) {
    if (strcasecmp(channel, "Security") == 0) {
      filt = " SYSLOG_FACILITY=10 SYSLOG_FACILITY=4"; /* authpriv / auth */
    } else if (strcasecmp(channel, "System") == 0) {
      filt = " -k"; /* 内核日志 */
    } else if (strcasecmp(channel, "Application") == 0) {
      filt = " SYSLOG_FACILITY=1 SYSLOG_FACILITY=3"; /* user / daemon */
    }
  }
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "journalctl --output=json -n %d%s 2>/dev/null", max_events, filt);
  size_t output_cap = (size_t)max_events * 8192u + 1u;
  if (output_cap > 8u * 1024u * 1024u) {
    output_cap = 8u * 1024u * 1024u;
  }
  char *output = (char *)calloc(1u, output_cap);
  int exit_code = 0;
  if (!output) {
    return -1;
  }
  if (edr_shell_exec_cancellable(cmd, 30, output, output_cap, &exit_code,
                                 rtr_shell_cancel_check, (void *)cmd_id) != 0) {
    free(output);
    return -1;
  }
  if (exit_code == 130 || edr_command_cancel_requested(cmd_id)) {
    free(output);
    return -2;
  }
  int first = 1;
  int count = 0;
  char *line = output;
  while (*line && count < max_events) {
    char *next = strpbrk(line, "\r\n");
    if (next) {
      *next = '\0';
      char *after = next + 1;
      while (*after == '\r' || *after == '\n') after++;
      next = after;
    }
    if (!line[0]) {
      if (!next) break;
      line = next;
      continue;
    }
    if (!first) {
      fputs(",\n", f);
    }
    first = 0;
    fputs(line, f);
    count++;
    if (!next) break;
    line = next;
  }
  free(output);
  if (exit_code != 0 && count == 0) {
    return -1;
  }
  return count;
}
#endif

static void do_eventlog_view(const char *cmd_id, const uint8_t *pl, size_t len,
                             const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject eventlog_view: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char channel[96];
  if (parse_json_string_field(pl, len, "channel", channel, sizeof(channel)) != 0) {
    snprintf(channel, sizeof(channel), "%s", "Security");
  }
  int max_events = parse_int_json_default(pl, len, "max_events", 100);
  if (max_events <= 0 || max_events > 1000) {
    max_events = 100;
  }
  char path[900];
  command_artifact_path(cmd_id, "eventlog", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "cannot create eventlog artifact");
    return;
  }
  fputs("{\"channel\":\"", f);
  fprint_json_escaped(f, channel);
  fputs("\",\"events\":[\n", f);
  int count = eventlog_query_to_file(channel, max_events, f, cmd_id);
  if (count == -2 || edr_command_cancel_requested(cmd_id)) {
    fclose(f);
    (void)remove(path);
    audit_both(cmd_id, "eventlog_view: cancelled during collection");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 130, "event log collection cancelled",
                 "cancelled", NULL);
    return;
  }
  if (count < 0) {
    fclose(f);
    (void)remove(path);
    s_exec_fail++;
    audit_both(cmd_id, "eventlog_view: query backend unavailable or query failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "eventlog query backend unavailable or query failed");
    return;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "eventlog", path, sha,
                                                        minio_key, sizeof(minio_key));
  char pathj[1200], channelj[256], keyj[1200], artifacts[3200], detail[4096];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(channelj, sizeof(channelj), channel);
  json_escape_to(keyj, sizeof(keyj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"eventlog\",\"path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", keyj);
  /* 内联回流:事件只在产物里,上传失败时不内联会"成功却无数据"。读回产物({channel,events,total},
   * 受 max_events 约束)直接作 detail;上传失败仅降级 ok_upload_failed,不判任务失败。 */
  detail[0] = '\0';
  {
    unsigned long long fsz = 0ull;
    long long fmt_unused = 0;
    if (file_size_mtime(path, &fsz, &fmt_unused) == 0 && fsz > 0ull && fsz < sizeof(detail)) {
      FILE *rf = fopen(path, "rb");
      if (rf) {
        size_t rn = fread(detail, 1, sizeof(detail) - 1, rf);
        fclose(rf);
        detail[rn] = '\0';
        if (rn == 0u || detail[0] != '{') {
          detail[0] = '\0';
        }
      }
    }
  }
  if (!detail[0]) {
    snprintf(detail, sizeof(detail),
             "{\"channel\":%s,\"count\":%d,\"artifact_path\":%s,\"sha256\":\"%s\","
             "\"upload_status\":\"%s\",\"minio_key\":%s}",
             channelj, count, pathj, sha, upload_rc == 0 ? "ok" : "failed", keyj);
  }
  s_handled++;
  s_exec_ok++;
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail,
               upload_rc == 0 ? "ok" : "ok_upload_failed", artifacts);
}

#ifdef _WIN32
static HKEY registry_parse_root(const char *key_path, const char **subkey_out) {
  if (!key_path || !subkey_out) {
    return NULL;
  }
  if (strncmp(key_path, "HKLM\\", 5) == 0 || strncmp(key_path, "HKLM/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_LOCAL_MACHINE;
  }
  if (strncmp(key_path, "HKCU\\", 5) == 0 || strncmp(key_path, "HKCU/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CURRENT_USER;
  }
  if (strncmp(key_path, "HKU\\", 4) == 0 || strncmp(key_path, "HKU/", 4) == 0) {
    *subkey_out = key_path + 4;
    return HKEY_USERS;
  }
  if (strncmp(key_path, "HKCR\\", 5) == 0 || strncmp(key_path, "HKCR/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CLASSES_ROOT;
  }
  if (strncmp(key_path, "HKCC\\", 5) == 0 || strncmp(key_path, "HKCC/", 5) == 0) {
    *subkey_out = key_path + 5;
    return HKEY_CURRENT_CONFIG;
  }
  return NULL;
}

static void registry_format_data(FILE *f, DWORD type, const BYTE *data, DWORD size) {
  if (!f || !data) {
    return;
  }
  if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
    char *tmp = (char *)calloc(1, (size_t)size + 1u);
    if (tmp) {
      memcpy(tmp, data, size);
      fprint_json_escaped(f, tmp);
      free(tmp);
    }
  } else if (type == REG_DWORD && size >= sizeof(DWORD)) {
    DWORD v = 0;
    memcpy(&v, data, sizeof(v));
    fprintf(f, "0x%08lx", (unsigned long)v);
  } else if (type == REG_QWORD && size >= 8u) {
    unsigned long long v = 0;
    memcpy(&v, data, sizeof(v));
    fprintf(f, "0x%016llx", v);
  } else {
    fputs("hex:", f);
    DWORD n = size < 128u ? size : 128u;
    for (DWORD i = 0; i < n; i++) {
      fprintf(f, "%02x", data[i]);
    }
  }
}

static int registry_values_to_file(const char *key_path, int max_values, FILE *f) {
  const char *subkey = NULL;
  HKEY root = registry_parse_root(key_path, &subkey);
  if (!root || !subkey) {
    return -1;
  }
  HKEY hkey;
  if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
    return -1;
  }
  int first = 1;
  int count = 0;
  for (DWORD idx = 0; count < max_values; idx++) {
    char name[512];
    BYTE data[8192];
    DWORD name_size = sizeof(name);
    DWORD data_size = sizeof(data);
    DWORD type = 0;
    LONG lr = RegEnumValueA(hkey, idx, name, &name_size, NULL, &type, data, &data_size);
    if (lr != ERROR_SUCCESS) {
      break;
    }
    if (!first) {
      fputs(",\n", f);
    }
    first = 0;
    fputs("{\"name\":\"", f);
    fprint_json_escaped(f, name);
    fprintf(f, "\",\"type\":%lu,\"data\":\"", (unsigned long)type);
    registry_format_data(f, type, data, data_size);
    fputs("\"}", f);
    count++;
  }
  RegCloseKey(hkey);
  return count;
}
#endif

static void do_registry_query(const char *cmd_id, const uint8_t *pl, size_t len,
                              const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject registry_query: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char key[1024];
  if (parse_json_string_field(pl, len, "key", key, sizeof(key)) != 0 &&
      parse_json_string_field(pl, len, "path", key, sizeof(key)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing registry key");
    return;
  }
  int max_values = parse_int_json_default(pl, len, "max_values", 200);
  if (max_values <= 0 || max_values > 1000) {
    max_values = 200;
  }
#ifndef _WIN32
  char keyj[1400], detail[1800];
  json_escape_to(keyj, sizeof(keyj), key);
  snprintf(detail, sizeof(detail), "{\"key\":%s,\"supported\":false,\"platform\":\"non_windows\"}", keyj);
  s_handled++;
  s_exec_ok++;
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
#else
  char path[900];
  command_artifact_path(cmd_id, "registry", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create registry artifact");
    return;
  }
  fputs("{\"key\":\"", f);
  fprint_json_escaped(f, key);
  fputs("\",\"values\":[\n", f);
  int count = registry_values_to_file(key, max_values, f);
  if (count < 0) {
    count = 0;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "registry", path, sha,
                                                        minio_key, sizeof(minio_key));
  char pathj[1200], keyj[1400], minioj[1200], artifacts[4800], detail[4800];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(keyj, sizeof(keyj), key);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"registry\",\"path\":%s,\"registry_key\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, keyj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  /* 内联回流:注册表值只在产物文件里,上传失败时若不内联,前端会"成功却无数据"。
   * 读回产物({key,values,total},受 max_values 约束体积可控)直接作 detail,
   * 前端 extractRecords 取 values;上传失败仅降级 ok_upload_failed,不再判任务失败。 */
  detail[0] = '\0';
  {
    unsigned long long fsz = 0ull;
    long long fmt_unused = 0;
    if (file_size_mtime(path, &fsz, &fmt_unused) == 0 && fsz > 0ull && fsz < sizeof(detail)) {
      FILE *rf = fopen(path, "rb");
      if (rf) {
        size_t rn = fread(detail, 1, sizeof(detail) - 1, rf);
        fclose(rf);
        detail[rn] = '\0';
        if (rn == 0u || detail[0] != '{') {
          detail[0] = '\0';
        }
      }
    }
  }
  if (!detail[0]) {
    /* 产物过大或读回失败:退化为摘要 detail(仅 count),数据仍在产物中。 */
    snprintf(detail, sizeof(detail),
             "{\"key\":%s,\"count\":%d,\"artifact_path\":%s,\"sha256\":\"%s\","
             "\"upload_status\":\"%s\",\"minio_key\":%s}",
             keyj, count, pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  }
  s_handled++;
  s_exec_ok++;
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail,
               upload_rc == 0 ? "ok" : "ok_upload_failed", artifacts);
#endif
}

static void do_quarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                               const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject quarantine_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char path[1024];
  if (parse_path_json(pl, len, path, sizeof(path)) != 0 || !file_exists_c(path)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid path or file not found");
    return;
  }
  char reason[256];
  if (parse_json_string_field(pl, len, "reason", reason, sizeof(reason)) != 0) {
    snprintf(reason, sizeof(reason), "%s", "manual");
  }
  char base[700];
  quarantine_base_dir(base, sizeof(base));
  if (mkdir_p_quiet(base) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "quarantine directory create failed");
    return;
  }
  char stem[512];
  char safe_cmd[128];
  char safe_base[256];
  const char *cmd_name = (cmd_id && cmd_id[0]) ? cmd_id : "cmd";
  const char *base_name = path_basename_c(path);
  size_t cmd_n = strlen(cmd_name);
  size_t base_n = strlen(base_name);
  if (cmd_n >= sizeof(safe_cmd)) {
    cmd_n = sizeof(safe_cmd) - 1u;
  }
  if (base_n >= sizeof(safe_base)) {
    base_n = sizeof(safe_base) - 1u;
  }
  memcpy(safe_cmd, cmd_name, cmd_n);
  safe_cmd[cmd_n] = '\0';
  memcpy(safe_base, base_name, base_n);
  safe_base[base_n] = '\0';
  snprintf(stem, sizeof(stem), "%lld_%s_%s", (long long)time(NULL),
           safe_cmd, safe_base);
  sanitize_component(stem);
  char qpath[1400], meta[1400];
#ifdef _WIN32
  snprintf(qpath, sizeof(qpath), "%s\\%s.bin", base, stem);
  snprintf(meta, sizeof(meta), "%s\\%s.meta", base, stem);
#else
  snprintf(qpath, sizeof(qpath), "%s/%s.bin", base, stem);
  snprintf(meta, sizeof(meta), "%s/%s.meta", base, stem);
#endif
  unsigned long long sz = 0;
  long long mt = 0;
  char sha[65];
  sha[0] = '\0';
  (void)file_size_mtime(path, &sz, &mt);
  (void)file_sha256_hex(path, sha);
  if (move_file_cross_volume(path, qpath) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "quarantine_file: move failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "quarantine move failed");
    return;
  }
  quarantine_lock(qpath); /* 加锁:去执行/限访问,防读回或再执行 */
  FILE *mf = fopen(meta, "w");
  if (!mf) {
    quarantine_unlock(qpath);
    (void)move_file_cross_volume(qpath, path);
    s_exec_fail++;
    audit_both(cmd_id, "quarantine_file: metadata create failed, rollback complete");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "quarantine metadata create failed");
    return;
  }
  int meta_rc = fprintf(mf, "quarantine_id=%s\noriginal_path=%s\nquarantine_path=%s\nsha256=%s\nsize=%llu\nmtime=%lld\nreason=%s\n",
                        stem, path, qpath, sha, sz, mt, reason);
  if (meta_rc < 0 || fclose(mf) != 0) {
    quarantine_unlock(qpath);
    (void)remove(meta);
    (void)move_file_cross_volume(qpath, path);
    s_exec_fail++;
    audit_both(cmd_id, "quarantine_file: metadata write failed, rollback complete");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "quarantine metadata write failed");
    return;
  }
  char stemj[700], pathj[1400], qpathj[1600], metaj[1600], detail[5600];
  json_escape_to(stemj, sizeof(stemj), stem);
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(qpathj, sizeof(qpathj), qpath);
  json_escape_to(metaj, sizeof(metaj), meta);
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":%s,\"original_path\":%s,\"quarantine_path\":%s,"
           "\"meta_path\":%s,\"sha256\":\"%s\",\"size\":%llu,\"locked\":true}",
           stemj, pathj, qpathj, metaj, sha, sz);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "quarantine_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static int read_meta_value(const char *meta, const char *key, char *out, size_t cap) {
  FILE *f = fopen(meta, "r");
  if (!f) {
    return -1;
  }
  char line[1400];
  size_t kn = strlen(key);
  int ok = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, key, kn) == 0 && line[kn] == '=') {
      char *v = line + kn + 1u;
      v[strcspn(v, "\r\n")] = '\0';
      snprintf(out, cap, "%s", v);
      ok = 0;
      break;
    }
  }
  fclose(f);
  return ok;
}

static void do_unquarantine_file(const char *cmd_id, const uint8_t *pl, size_t len,
                                 const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject unquarantine_file: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char qid[256];
  char base[700], meta[1200];
  quarantine_base_dir(base, sizeof(base));
  char direct_qpath[1400], direct_restore[1400];
  int has_direct_paths = parse_json_string_field(pl, len, "quarantine_path", direct_qpath,
                                                   sizeof(direct_qpath)) == 0 &&
                         (parse_json_string_field(pl, len, "dest", direct_restore,
                                                   sizeof(direct_restore)) == 0 ||
                          parse_json_string_field(pl, len, "restore_path", direct_restore,
                                                   sizeof(direct_restore)) == 0);
  if (has_direct_paths && (!direct_qpath[0] || !direct_restore[0] ||
                           strlen(direct_qpath) >= 1024u ||
                           strlen(direct_restore) >= 1024u)) {
    has_direct_paths = 0;
  }
  if (has_direct_paths) {
    if (!quarantine_path_allowed(base, direct_qpath) || !file_exists_c(direct_qpath)) {
      s_exec_fail++;
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "quarantine_path is outside quarantine directory or missing");
      return;
    }
    snprintf(qid, sizeof(qid), "%s", path_basename_c(direct_qpath));
    char *dot = strrchr(qid, '.');
    if (dot && strcmp(dot, ".bin") == 0) {
      *dot = '\0';
    }
  } else if (parse_json_string_field(pl, len, "quarantine_id", qid, sizeof(qid)) != 0 &&
             parse_json_string_field(pl, len, "id", qid, sizeof(qid)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "missing quarantine_id or quarantine_path/dest");
    return;
  }
  sanitize_component(qid);
#ifdef _WIN32
  snprintf(meta, sizeof(meta), "%s\\%s.meta", base, qid);
#else
  snprintf(meta, sizeof(meta), "%s/%s.meta", base, qid);
#endif
  char qpath[1024], original[1024], restore[1024];
  if (has_direct_paths) {
    snprintf(qpath, sizeof(qpath), "%s", direct_qpath);
    snprintf(restore, sizeof(restore), "%s", direct_restore);
    snprintf(original, sizeof(original), "%s", direct_restore);
  } else {
    if (read_meta_value(meta, "quarantine_path", qpath, sizeof(qpath)) != 0 ||
        read_meta_value(meta, "original_path", original, sizeof(original)) != 0) {
      s_exec_fail++;
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "quarantine metadata not found");
      return;
    }
    if (parse_json_string_field(pl, len, "restore_path", restore, sizeof(restore)) != 0) {
      snprintf(restore, sizeof(restore), "%s", original);
    }
  }
  if (file_exists_c(restore)) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 4, "restore target already exists");
    return;
  }
  quarantine_unlock(qpath); /* 解锁:清属性,确保还原 move/删除可进行 */
  if (move_file_cross_volume(qpath, restore) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "unquarantine_file: restore failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "restore move failed");
    return;
  }
  (void)remove(meta);
  char qidj[700], restorej[1400], originalj[1400], detail[4200];
  json_escape_to(qidj, sizeof(qidj), qid);
  json_escape_to(restorej, sizeof(restorej), restore);
  json_escape_to(originalj, sizeof(originalj), original);
  snprintf(detail, sizeof(detail),
           "{\"quarantine_id\":%s,\"restored_path\":%s,\"original_path\":%s}",
           qidj, restorej, originalj);
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "unquarantine_file: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void forensic_copy_lines(const char *jobdir, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_COPY_PATHS");
  if (!e || e[0] != '1' || !pl || len == 0u) {
    return;
  }
  char work[8192];
  if (len >= sizeof(work)) {
    len = sizeof(work) - 1u;
  }
  memcpy(work, pl, len);
  work[len] = 0;
  char *p = work;
  int idx = 0;
  for (;;) {
    char *line = p;
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    while (*line == ' ' || *line == '\r') {
      line++;
    }
    if (line[0] && line[0] != '#') {
      char dst[900];
#ifdef _WIN32
      snprintf(dst, sizeof(dst), "%s\\copied_%02d", jobdir, idx++);
#else
      snprintf(dst, sizeof(dst), "%s/copied_%02d", jobdir, idx++);
#endif
      (void)forensic_copy_one_file(line, dst);
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
}

static void upload_outbox_dir(char *out, size_t cap) {
  const char *e = getenv("EDR_UPLOAD_OUTBOX_DIR");
  if (!e || !e[0]) {
    e = getenv("EDR_COMMAND_OUTBOX_DIR");
  }
  if (e && e[0]) {
    snprintf(out, cap, "%s", e);
    return;
  }
#ifdef _WIN32
  snprintf(out, cap, "%s", "C:\\Program Files\\FDSecurity\\upload_outbox");
#else
  snprintf(out, cap, "%s", "/tmp/edr_upload_outbox");
#endif
}

static void write_upload_outbox(const char *cmd_id, const char *bundle, const char *sha,
                                const char *manifest) {
  char dir[700];
  upload_outbox_dir(dir, sizeof(dir));
  if (mkdir_p_quiet(dir) != 0) {
    return;
  }
  char safe[180];
  snprintf(safe, sizeof(safe), "%s", (cmd_id && cmd_id[0]) ? cmd_id : "cmd");
  sanitize_component(safe);
  char path[900];
#ifdef _WIN32
  snprintf(path, sizeof(path), "%s\\upload_%s_%lld.pending", dir, safe, (long long)time(NULL));
#else
  snprintf(path, sizeof(path), "%s/upload_%s_%lld.pending", dir, safe, (long long)time(NULL));
#endif
  FILE *f = fopen(path, "w");
  if (!f) {
    return;
  }
  fprintf(f, "command_id=%s\nbundle_path=%s\nsha256=%s\nmanifest_path=%s\ncreated_unix_ms=%lld\n",
          cmd_id ? cmd_id : "", bundle ? bundle : "", sha ? sha : "", manifest ? manifest : "",
          (long long)command_now_ms());
  fclose(f);
}

static void upload_meta_value(char *value) {
  if (!value) return;
  for (; *value; value++) {
    if (*value == '\r' || *value == '\n') *value = ' ';
  }
}

int edr_command_queue_forensic_upload(const char *command_id, const char *command_type,
                                      const EdrSoarCommandMeta *soar_meta,
                                      const char *artifact_path, const char *sha256,
                                      const char *source, int partial) {
  if (!command_id || !command_id[0] || !artifact_path || !artifact_path[0] ||
      !file_exists_c(artifact_path)) {
    return -1;
  }
  char dir[700];
  upload_outbox_dir(dir, sizeof(dir));
  if (mkdir_p_quiet(dir) != 0) return -1;
  char safe[180];
  snprintf(safe, sizeof(safe), "%s", command_id);
  sanitize_component(safe);
  int64_t now_ms = command_now_ms();
  char path[900], tmp[920];
#ifdef _WIN32
  snprintf(path, sizeof(path), "%s\\upload_%s_%lld.pending", dir, safe, (long long)now_ms);
#else
  snprintf(path, sizeof(path), "%s/upload_%s_%lld.pending", dir, safe, (long long)now_ms);
#endif
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  FILE *f = fopen(tmp, "w");
  if (!f) return -1;
  char type[80], src[80], idem[520], soar[140], run[108], step[108];
  snprintf(type, sizeof(type), "%s", command_type ? command_type : "collect_forensic");
  snprintf(src, sizeof(src), "%s", source ? source : "builtin");
  snprintf(idem, sizeof(idem), "%s", soar_meta ? soar_meta->idempotency_key : "");
  snprintf(soar, sizeof(soar), "%s", soar_meta ? soar_meta->soar_correlation_id : "");
  snprintf(run, sizeof(run), "%s", soar_meta ? soar_meta->playbook_run_id : "");
  snprintf(step, sizeof(step), "%s", soar_meta ? soar_meta->playbook_step_id : "");
  upload_meta_value(type); upload_meta_value(src); upload_meta_value(idem);
  upload_meta_value(soar); upload_meta_value(run); upload_meta_value(step);
  fprintf(f,
          "kind=forensic_terminal\ncommand_id=%s\ncommand_type=%s\nbundle_path=%s\n"
          "sha256=%s\nsource=%s\npartial=%d\nidempotency_key=%s\n"
          "soar_correlation_id=%s\nplaybook_run_id=%s\nplaybook_step_id=%s\n"
          "created_unix_ms=%lld\n",
          command_id, type, artifact_path, sha256 ? sha256 : "", src, partial ? 1 : 0,
          idem, soar, run, step, (long long)now_ms);
  if (fclose(f) != 0 || rename(tmp, path) != 0) {
    (void)remove(tmp);
    return -1;
  }
  edr_command_executor_wake();
  return 0;
}

static int read_kv_file_value(const char *path, const char *key, char *out, size_t cap) {
  return read_meta_value(path, key, out, cap);
}

static int flush_upload_outbox_one(const char *pending_path) {
  char cmd_id[128], bundle[1024], sha[65], kind[48];
  kind[0] = '\0';
  (void)read_kv_file_value(pending_path, "kind", kind, sizeof(kind));
  if (read_kv_file_value(pending_path, "command_id", cmd_id, sizeof(cmd_id)) != 0 ||
      read_kv_file_value(pending_path, "bundle_path", bundle, sizeof(bundle)) != 0 ||
      read_kv_file_value(pending_path, "sha256", sha, sizeof(sha)) != 0) {
    return 0;
  }
  if (!file_exists_c(bundle)) {
    if (strcmp(kind, "forensic_terminal") == 0) {
      char command_type[80], source[80], partial_raw[16];
      EdrSoarCommandMeta sm;
      memset(&sm, 0, sizeof(sm));
      command_type[0] = source[0] = partial_raw[0] = '\0';
      (void)read_kv_file_value(pending_path, "command_type", command_type, sizeof(command_type));
      (void)read_kv_file_value(pending_path, "source", source, sizeof(source));
      (void)read_kv_file_value(pending_path, "partial", partial_raw, sizeof(partial_raw));
      (void)read_kv_file_value(pending_path, "idempotency_key", sm.idempotency_key, sizeof(sm.idempotency_key));
      (void)read_kv_file_value(pending_path, "soar_correlation_id", sm.soar_correlation_id, sizeof(sm.soar_correlation_id));
      (void)read_kv_file_value(pending_path, "playbook_run_id", sm.playbook_run_id, sizeof(sm.playbook_run_id));
      (void)read_kv_file_value(pending_path, "playbook_step_id", sm.playbook_step_id, sizeof(sm.playbook_step_id));
      edr_response_forensic_complete_queued_upload(cmd_id, command_type, &sm, bundle, sha, "",
                                                   source, atoi(partial_raw), 0,
                                                   "artifact missing before upload retry");
      char failed[1100];
      snprintf(failed, sizeof(failed), "%s.failed", pending_path);
      (void)rename(pending_path, failed);
      return 1;
    }
    return 0;
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  if (edr_transport_v2_upload_file(cmd_id[0] ? cmd_id : "upload_outbox", bundle, sha, minio_key, sizeof(minio_key)) == 0) {
    if (strcmp(kind, "forensic_terminal") == 0) {
      char command_type[80], source[80], partial_raw[16];
      EdrSoarCommandMeta sm;
      memset(&sm, 0, sizeof(sm));
      command_type[0] = source[0] = partial_raw[0] = '\0';
      (void)read_kv_file_value(pending_path, "command_type", command_type, sizeof(command_type));
      (void)read_kv_file_value(pending_path, "source", source, sizeof(source));
      (void)read_kv_file_value(pending_path, "partial", partial_raw, sizeof(partial_raw));
      (void)read_kv_file_value(pending_path, "idempotency_key", sm.idempotency_key, sizeof(sm.idempotency_key));
      (void)read_kv_file_value(pending_path, "soar_correlation_id", sm.soar_correlation_id, sizeof(sm.soar_correlation_id));
      (void)read_kv_file_value(pending_path, "playbook_run_id", sm.playbook_run_id, sizeof(sm.playbook_run_id));
      (void)read_kv_file_value(pending_path, "playbook_step_id", sm.playbook_step_id, sizeof(sm.playbook_step_id));
      edr_response_forensic_complete_queued_upload(cmd_id, command_type, &sm, bundle, sha, minio_key,
                                                   source, atoi(partial_raw), 1, "");
    }
    char done[1100];
    snprintf(done, sizeof(done), "%s.done", pending_path);
    (void)rename(pending_path, done);
    return 1;
  }
  return -1;
}

static void flush_upload_outbox(void) {
  char dir[700];
  upload_outbox_dir(dir, sizeof(dir));
  int64_t now_ms = command_now_ms();
  if (delivery_health_upload_backoff_active(now_ms)) {
    return;
  }
  uint32_t max_per_poll = command_u32_env_clamped("EDR_UPLOAD_OUTBOX_MAX_PER_POLL", 1u, 1u, 64u);
  uint32_t attempted_this_poll = 0u;
  uint32_t seen_this_poll = 0u;
#ifdef _WIN32
  char pattern[900];
  snprintf(pattern, sizeof(pattern), "%s\\*.pending", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      char path[1000];
      snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
      seen_this_poll++;
      if (attempted_this_poll >= max_per_poll) {
        continue;
      }
      attempted_this_poll++;
      delivery_health_upload_attempted();
      int rc = flush_upload_outbox_one(path);
      delivery_health_upload_result(rc, now_ms);
      if (rc < 0) {
        break;
      }
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  DIR *d = opendir(dir);
  if (!d) {
    return;
  }
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    const char *name = ent->d_name;
    size_t n = strlen(name);
    if (n > 8u && strcmp(name + n - 8u, ".pending") == 0) {
      char path[1000];
      snprintf(path, sizeof(path), "%s/%s", dir, name);
      seen_this_poll++;
      if (attempted_this_poll >= max_per_poll) {
        continue;
      }
      attempted_this_poll++;
      delivery_health_upload_attempted();
      int rc = flush_upload_outbox_one(path);
      delivery_health_upload_result(rc, now_ms);
      if (rc < 0) {
        break;
      }
    }
  }
  closedir(d);
#endif
  delivery_health_upload_pending(seen_this_poll);
}

/* 取证 velo 仅人工下发 gate:命令需带 initiated_by="operator"(或 payload {"initiated_by":"operator"}/{"manual":true})。
 * env EDR_FORENSIC_OPERATOR_ONLY="0" 可关闭(默认开)。返回 1=放行,0=拒绝。 */
static int forensic_operator_gate(const EdrSoarCommandMeta *sm, const uint8_t *pl, size_t len) {
  const char *e = getenv("EDR_FORENSIC_OPERATOR_ONLY");
  if (e && e[0] == '0') {
    return 1; /* 显式关闭 gate */
  }
  if (sm && sm->initiated_by[0]) {
    if (strcasecmp(sm->initiated_by, "operator") == 0 || strcasecmp(sm->initiated_by, "manual") == 0) {
      return 1;
    }
  }
  /* payload 兜底:结构化解析 {"initiated_by":"operator"/"manual"}(后端对人工命令注入此字段)。
   * 不再用松散 strstr 子串匹配,避免被其它字段值伪造绕过。 */
  char ib[32];
  ib[0] = '\0';
  if (parse_json_string_field(pl, len, "initiated_by", ib, sizeof(ib)) == 0 &&
      (strcasecmp(ib, "operator") == 0 || strcasecmp(ib, "manual") == 0)) {
    return 1;
  }
  return 0;
}

static void do_forensic(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject forensic: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  char base[512];
  const char *o = getenv("EDR_FORENSIC_OUT");
  if (o && o[0]) {
    snprintf(base, sizeof(base), "%s", o);
  } else {
#ifdef _WIN32
    const char *tmp = getenv("TEMP");
    if (!tmp || !tmp[0]) {
      tmp = getenv("TMP");
    }
    if (!tmp || !tmp[0]) {
      tmp = ".";
    }
    snprintf(base, sizeof(base), "%s\\edr_forensic", tmp);
#else
    snprintf(base, sizeof(base), "%s", "/tmp/edr_forensic");
#endif
  }
  const char *job = (cmd_id && cmd_id[0]) ? cmd_id : "job";
  char dir[700];
#ifdef _WIN32
  snprintf(dir, sizeof(dir), "%s\\%s", base, job);
  {
    char cmdline[900];
    snprintf(cmdline, sizeof(cmdline), "cmd /c mkdir \"%s\" 2>nul", dir);
    (void)system(cmdline);
  }
#else
  snprintf(dir, sizeof(dir), "%s/%s", base, job);
  {
    char cmdline[800];
    snprintf(cmdline, sizeof(cmdline), "mkdir -p \"%s\" 2>/dev/null", dir);
    (void)system(cmdline);
  }
#endif
  char manifest[800];
#ifdef _WIN32
  snprintf(manifest, sizeof(manifest), "%s\\manifest.txt", dir);
#else
  snprintf(manifest, sizeof(manifest), "%s/manifest.txt", dir);
#endif
  FILE *f = fopen(manifest, "w");
  if (!f) {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: 写 manifest 失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "manifest write failed");
    return;
  }
  fprintf(f, "command_id=%s\npayload_len=%zu\n", cmd_id ? cmd_id : "", len);
  {
    char shahex[65];
    if (pl && len > 0u) {
      (void)edr_sha256_hex(pl, len, shahex);
      fprintf(f, "payload_sha256=%s\n", shahex);
    } else {
      fprintf(f, "payload_sha256=\n");
    }
  }
#ifdef _WIN32
  fprintf(f, "platform=windows\n");
  {
    char hn[256];
    DWORD hnl = sizeof(hn);
    if (GetComputerNameA(hn, &hnl)) {
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#else
  fprintf(f, "platform=posix\n");
  {
    char hn[256];
    if (gethostname(hn, sizeof(hn)) == 0) {
      hn[sizeof(hn) - 1] = '\0';
      fprintf(f, "hostname=%s\n", hn);
    }
  }
#endif
  if (edr_command_get_config()) {
    fprintf(f, "endpoint_id=%s\ntenant_id=%s\n", edr_command_get_config()->agent.endpoint_id[0] ? edr_command_get_config()->agent.endpoint_id : "",
            edr_command_get_config()->agent.tenant_id[0] ? edr_command_get_config()->agent.tenant_id : "");
  }
  fclose(f);
  forensic_copy_lines(dir, pl, len);
  char bundle[800];
#ifdef _WIN32
  snprintf(bundle, sizeof(bundle), "%s\\bundle.tgz", dir);
  {
    char tarcmd[1800];
    snprintf(tarcmd, sizeof(tarcmd), "cmd /c tar czf \"%s\" -C \"%s\" . 2>nul", bundle, dir);
    (void)system(tarcmd);
  }
#else
  snprintf(bundle, sizeof(bundle), "%s/bundle.tgz", dir);
  {
    char tarcmd[1700];
    snprintf(tarcmd, sizeof(tarcmd), "tar czf \"%s\" -C \"%s\" . 2>/dev/null", bundle, dir);
    (void)system(tarcmd);
  }
#endif
  if (!file_exists_c(bundle)) {
    s_exec_fail++;
    audit_both(cmd_id, "forensic: bundle.tgz 生成失败");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "forensic bundle create failed");
    return;
  }
  char bundle_sha[65];
  bundle_sha[0] = '\0';
  (void)file_sha256_hex(bundle, bundle_sha);
  char upload_key[1024];
  upload_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "forensic", bundle, bundle_sha,
                                                        upload_key, sizeof(upload_key));
  if (upload_rc != 0) {
    write_upload_outbox(cmd_id, bundle, bundle_sha, manifest);
  }
  char manifest_json[900];
#ifdef _WIN32
  snprintf(manifest_json, sizeof(manifest_json), "%s\\artifact_manifest.json", dir);
#else
  snprintf(manifest_json, sizeof(manifest_json), "%s/artifact_manifest.json", dir);
#endif
  {
    FILE *af = fopen(manifest_json, "w");
    if (af) {
      char mj[1200], bj[1200], kj[1200];
      json_escape_to(mj, sizeof(mj), manifest);
      json_escape_to(bj, sizeof(bj), bundle);
      json_escape_to(kj, sizeof(kj), upload_key);
      fprintf(af,
              "{\"command_id\":\"%s\",\"manifest_path\":%s,\"bundle_path\":%s,"
              "\"bundle_sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}\n",
              cmd_id ? cmd_id : "", mj, bj, bundle_sha, upload_rc == 0 ? "ok" : "failed", kj);
      fclose(af);
    }
  }
  s_handled++;
  audit_both(cmd_id, upload_rc == 0
                         ? "forensic: manifest + bundle.tgz + artifact upload ok"
                         : "forensic: manifest + bundle.tgz ok; artifact upload failed, queued outbox");
  {
    char manifestj[1200], bundlej[1200], keyj[1200], artifacts[4200], detail[4800];
    json_escape_to(manifestj, sizeof(manifestj), manifest);
    json_escape_to(bundlej, sizeof(bundlej), bundle);
    json_escape_to(keyj, sizeof(keyj), upload_key);
    snprintf(artifacts, sizeof(artifacts),
             "[{\"type\":\"forensic_bundle\",\"path\":%s,\"manifest_path\":%s,\"sha256\":\"%s\","
             "\"upload_status\":\"%s\",\"minio_key\":%s}]",
             bundlej, manifestj, bundle_sha, upload_rc == 0 ? "ok" : "failed", keyj);
    snprintf(detail, sizeof(detail),
             "{\"manifest_path\":%s,\"bundle_path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\","
             "\"minio_key\":%s,\"outbox\":\"%s\"}",
             manifestj, bundlej, bundle_sha, upload_rc == 0 ? "ok" : "failed", keyj,
             upload_rc == 0 ? "none" : "queued");
    if (upload_rc == 0) {
      s_exec_ok++;
      soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, "ok", artifacts);
    } else {
      s_exec_fail++;
      soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 4, detail, "partial_success", artifacts);
    }
  }
}

static void do_rtq_query(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  char payload[4096];
  if (pl && len > 0u) {
    if (len >= sizeof(payload)) {
      len = sizeof(payload) - 1u;
    }
    memcpy(payload, pl, len);
    payload[len] = '\0';
  } else {
    snprintf(payload, sizeof(payload), "{\"limit\":50,\"time_window_s\":600}");
  }
  char detail[12000];
  if (edr_local_evidence_cache_query_json(payload, detail, sizeof(detail)) != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtq_query: failed");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "rtq query failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtq_query: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_rtr_process_tree(const char *cmd_id, const uint8_t *pl, size_t len,
                                const EdrSoarCommandMeta *sm) {
  long pid = -1;
  if (parse_pid_json(pl, len, &pid) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  if (pid <= 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_process_tree: pid required");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "pid is required");
    return;
  }
  char endpoint_id[64];
  if (parse_json_string_field(pl, len, "endpoint_id", endpoint_id, sizeof(endpoint_id)) != 0) {
    endpoint_id[0] = '\0';
  }
  char detail[12000];
  int r = edr_local_evidence_cache_process_tree_json((uint32_t)pid, endpoint_id, detail, sizeof(detail));
  if (r != 0) {
    s_exec_fail++;
    audit_both(cmd_id, "rtr_process_tree: no cached process");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "process not found in local evidence cache");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_process_tree: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

static void do_rtr_list_connections(const char *cmd_id, const uint8_t *pl, size_t len,
                                    const EdrSoarCommandMeta *sm) {
  char payload[4096];
  if (pl && len > 0u) {
    if (len >= sizeof(payload)) {
      len = sizeof(payload) - 1u;
    }
    memcpy(payload, pl, len);
    payload[len] = '\0';
  } else {
    snprintf(payload, sizeof(payload), "{\"event_type\":\"network\",\"limit\":50,\"time_window_s\":600}");
  }
  char requested_type[64] = "";
  int has_event_type = edr_parse_json_string((const uint8_t *)payload, strlen(payload),
                                             "event_type", requested_type,
                                             sizeof(requested_type));
  if (!has_event_type) {
    has_event_type = edr_parse_json_string((const uint8_t *)payload, strlen(payload),
                                           "type", requested_type,
                                           sizeof(requested_type));
  }
  if (!has_event_type) {
    char wrapped[4096];
    const char *body = payload;
    while (*body && isspace((unsigned char)*body)) {
      body++;
    }
    if (*body == '{') {
      body++;
      snprintf(wrapped, sizeof(wrapped), "{\"event_type\":\"network\",%s", body);
    } else {
      snprintf(wrapped, sizeof(wrapped), "{\"event_type\":\"network\",\"limit\":50,\"time_window_s\":600}");
    }
    snprintf(payload, sizeof(payload), "%s", wrapped);
  }
  char detail[12000];
  if (edr_local_evidence_cache_query_json(payload, detail, sizeof(detail)) != 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "connection query failed");
    return;
  }
  s_handled++;
  s_exec_ok++;
  audit_both(cmd_id, "rtr_list_connections: ok");
  soar_emit(cmd_id, sm, EdrCmdExecOk, 0, detail);
}

/* 主机显微镜：枚举指定进程已加载的模块（Win: Toolhelp 模块快照；Linux: /proc/pid/maps 可执行映射）。
 * 镜像 do_registry_query：落 JSON 产物 + SHA-256 + 上传 + soar_emit_ex 带 artifacts。只读巡检，沿用 dangerous 门控。 */
#ifdef _WIN32
/* 真 Authenticode 验签：先验内嵌签名，再查系统目录（catalog，多数 OS DLL 无内嵌签名）。
 * 返回 1=已签名且受信任，0=确定未签名/不受信任，-1=无法判定（默认保守，前端按"未知"处理，绝不误报未签名）。
 * 兼容 SHA256（Win8+ CryptCATAdminAcquireContext2）与 SHA1 旧 catalog。禁用网络吊销检查以加速。 */
static int win_file_signed(const char *path) {
  if (!path || !path[0]) {
    return -1;
  }
  wchar_t wpath[1024];
  if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024) == 0) {
    return -1;
  }
  /* 1) 内嵌签名 */
  WINTRUST_FILE_INFO fi;
  memset(&fi, 0, sizeof(fi));
  fi.cbStruct = sizeof(fi);
  fi.pcwszFilePath = wpath;
  GUID gv = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA wd;
  memset(&wd, 0, sizeof(wd));
  wd.cbStruct = sizeof(wd);
  wd.dwUIChoice = WTD_UI_NONE;
  wd.fdwRevocationChecks = WTD_REVOKE_NONE;
  wd.dwUnionChoice = WTD_CHOICE_FILE;
  wd.pFile = &fi;
  wd.dwStateAction = WTD_STATEACTION_VERIFY;
  wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  LONG st = WinVerifyTrust(NULL, &gv, &wd);
  wd.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(NULL, &gv, &wd);
  if (st == 0) {
    return 1; /* ERROR_SUCCESS：内嵌签名受信任 */
  }
  int embedded_nosig = ((unsigned long)st == 0x800B0100UL); /* TRUST_E_NOSIGNATURE */
  /* 2) 系统 catalog 验签 */
  HANDLE hf = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hf == INVALID_HANDLE_VALUE) {
    return -1;
  }
  HCATADMIN hca = NULL;
  BYTE *hash = NULL;
  DWORD hlen = 0;
  int hashed = 0;
  if (CryptCATAdminAcquireContext2(&hca, NULL, L"SHA256", NULL, 0)) {
    CryptCATAdminCalcHashFromFileHandle2(hca, hf, &hlen, NULL, 0);
    if (hlen > 0 && (hash = (BYTE *)malloc(hlen)) != NULL &&
        CryptCATAdminCalcHashFromFileHandle2(hca, hf, &hlen, hash, 0)) {
      hashed = 1;
    }
  }
  if (!hashed) {
    if (hca) { CryptCATAdminReleaseContext(hca, 0); hca = NULL; }
    free(hash); hash = NULL; hlen = 0;
    if (CryptCATAdminAcquireContext(&hca, NULL, 0)) {
      CryptCATAdminCalcHashFromFileHandle(hf, &hlen, NULL, 0);
      if (hlen > 0 && (hash = (BYTE *)malloc(hlen)) != NULL &&
          CryptCATAdminCalcHashFromFileHandle(hf, &hlen, hash, 0)) {
        hashed = 1;
      }
    }
  }
  int result = -1;
  if (hashed && hca) {
    HCATINFO hci = CryptCATAdminEnumCatalogFromHash(hca, hash, hlen, 0, NULL);
    if (hci) {
      result = 1; /* 命中系统 catalog → OS 受信任 */
      CryptCATAdminReleaseCatalogContext(hca, hci, 0);
    } else {
      result = embedded_nosig ? 0 : -1; /* 仅在内嵌确为无签名且不在 catalog 时判未签名 */
    }
  }
  free(hash);
  if (hca) {
    CryptCATAdminReleaseContext(hca, 0);
  }
  CloseHandle(hf);
  return result;
}
#endif

static void do_list_modules(const char *cmd_id, const uint8_t *pl, size_t len,
                            const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject list_modules: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  long pid = -1;
  if (parse_pid_json(pl, len, &pid) != 0 || pid <= 0) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid pid payload");
    return;
  }
  int max_modules = parse_int_json_default(pl, len, "max_modules", 200);
  if (max_modules <= 0 || max_modules > 1000) {
    max_modules = 200;
  }
  char path[900];
  command_artifact_path(cmd_id, "modules", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create modules artifact");
    return;
  }
  fprintf(f, "{\"pid\":%ld,\"modules\":[\n", pid);
  int count = 0;
  int cancelled = 0;
  /* 同步累积前若干条模块的内联 JSON，随结果回流（主机显微镜内联表格直接展示，无需下载产物）。 */
  char inline_mods[9000];
  size_t io = 0;
  int inline_count = 0;
  inline_mods[0] = '\0';
  /* 把一条已构造好的模块对象 obj 写入文件，并在容量允许时追加到内联缓冲。 */
#define EDR_MOD_EMIT(obj)                                                              \
  do {                                                                                 \
    if (count) fputs(",\n", f);                                                        \
    fputs((obj), f);                                                                   \
    size_t _ol = strlen(obj);                                                          \
    if (io + _ol + 2u < sizeof(inline_mods)) {                                         \
      if (inline_count) { inline_mods[io++] = ','; }                                   \
      memcpy(inline_mods + io, (obj), _ol);                                            \
      io += _ol;                                                                       \
      inline_mods[io] = '\0';                                                          \
      inline_count++;                                                                  \
    }                                                                                  \
    count++;                                                                           \
  } while (0)
#ifdef _WIN32
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pid);
  if (snap != INVALID_HANDLE_VALUE) {
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
      do {
        if (edr_command_cancel_requested(cmd_id)) {
          cancelled = 1;
          break;
        }
        if (count >= max_modules) {
          break;
        }
        char nmj[600], pthj2[1100], obj[1960];
        json_escape_to(nmj, sizeof(nmj), me.szModule);
        json_escape_to(pthj2, sizeof(pthj2), me.szExePath);
        int sg = win_file_signed(me.szExePath); /* 1=signed 0=unsigned -1=unknown */
        char sgf[24];
        if (sg == 1) snprintf(sgf, sizeof(sgf), ",\"signed\":true");
        else if (sg == 0) snprintf(sgf, sizeof(sgf), ",\"signed\":false");
        else sgf[0] = '\0';
        snprintf(obj, sizeof(obj), "{\"name\":%s,\"path\":%s,\"base\":\"0x%llx\",\"size\":%lu%s}",
                 nmj, pthj2, (unsigned long long)(size_t)me.modBaseAddr, (unsigned long)me.modBaseSize, sgf);
        EDR_MOD_EMIT(obj);
      } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
  }
#else
  char maps[64];
  snprintf(maps, sizeof(maps), "/proc/%ld/maps", pid);
  FILE *mp = fopen(maps, "r");
  if (mp) {
    char line[4096];
    char prevpath[512];
    prevpath[0] = '\0';
    while (fgets(line, sizeof(line), mp) && count < max_modules) {
      if (edr_command_cancel_requested(cmd_id)) {
        cancelled = 1;
        break;
      }
      unsigned long long a0 = 0, a1 = 0;
      char perms[8] = {0};
      char pathbuf[512] = {0};
      /* maps 行格式：addr_start-addr_end perms offset dev inode pathname */
      if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &a0, &a1, perms, pathbuf) >= 3) {
        char *pp = pathbuf;
        while (*pp == ' ' || *pp == '\t') {
          pp++;
        }
        if (pp[0] != '/') {
          continue; /* 仅文件映射的模块 */
        }
        if (!strchr(perms, 'x')) {
          continue; /* 仅可执行映射 */
        }
        if (strcmp(pp, prevpath) == 0) {
          continue; /* 相邻段去重（同一映像多段连续出现） */
        }
        snprintf(prevpath, sizeof(prevpath), "%s", pp);
        char pthj2[1100], prmj[64], obj[1300];
        json_escape_to(pthj2, sizeof(pthj2), pp);
        json_escape_to(prmj, sizeof(prmj), perms);
        snprintf(obj, sizeof(obj), "{\"path\":%s,\"base\":\"0x%llx\",\"perms\":%s}", pthj2, a0, prmj);
        EDR_MOD_EMIT(obj);
      }
    }
    fclose(mp);
  }
#endif
#undef EDR_MOD_EMIT
  if (cancelled || edr_command_cancel_requested(cmd_id)) {
    fclose(f);
    (void)remove(path);
    s_exec_fail++;
    audit_both(cmd_id, "list_modules: cancelled during enumeration");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 130, "module enumeration cancelled",
                 "cancelled", NULL);
    return;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "modules", path, sha,
                                               minio_key, sizeof(minio_key));
  char pathj[1200], minioj[1200], artifacts[3200], detail[11000];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"modules\",\"path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  /* detail 内联前 inline_count 条模块（剩余在产物文件中），主机显微镜据此渲染表格。 */
  snprintf(detail, sizeof(detail),
           "{\"pid\":%ld,\"count\":%d,\"inline_count\":%d,\"modules\":[%s],"
           "\"artifact_path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}",
           pid, count, inline_count, inline_mods, pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  s_handled++;
  s_exec_ok++;
  /* 数据已内联回流，采集即成功；上传失败只降级为 upload_status=failed（详情/产物已标注），不再判任务失败。 */
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, upload_rc == 0 ? "ok" : "ok_upload_failed", artifacts);
}

/* 主机显微镜主干：全机进程快照（Win Toolhelp / Linux /proc），输出扁平 {pid,ppid,name} 列表。
 * 只读巡检，沿用 dangerous 门控；镜像 do_list_modules 的产物+内联+上传结构。前端据此构进程树。
 * 为尽量内联完整列表，Tier 1 省略 image（≈ name），命令行/用户经 rtr_process_tree 下钻。 */
static void do_host_process_tree(const char *cmd_id, const uint8_t *pl, size_t len,
                                 const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject host_process_tree: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int max_procs = parse_int_json_default(pl, len, "max_procs", 2000);
  if (max_procs <= 0 || max_procs > 5000) {
    max_procs = 2000;
  }
  char path[900];
  command_artifact_path(cmd_id, "proctree", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create proctree artifact");
    return;
  }
  fputs("{\"processes\":[\n", f);
  int count = 0;
  int cancelled = 0;
  char inline_procs[28000];
  size_t io = 0;
  int inline_count = 0;
  inline_procs[0] = '\0';
#define EDR_PROC_EMIT(obj)                                                             \
  do {                                                                                 \
    if (count) fputs(",\n", f);                                                        \
    fputs((obj), f);                                                                   \
    size_t _ol = strlen(obj);                                                          \
    if (io + _ol + 2u < sizeof(inline_procs)) {                                        \
      if (inline_count) { inline_procs[io++] = ','; }                                  \
      memcpy(inline_procs + io, (obj), _ol);                                           \
      io += _ol;                                                                       \
      inline_procs[io] = '\0';                                                         \
      inline_count++;                                                                  \
    }                                                                                  \
    count++;                                                                           \
  } while (0)
#ifdef _WIN32
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe;
    pe.dwSize = (DWORD)sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
      do {
        if (edr_command_cancel_requested(cmd_id)) {
          cancelled = 1;
          break;
        }
        if (count >= max_procs) {
          break;
        }
        char name[520];
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, (int)sizeof(name), NULL, NULL);
        char nmj[600], obj[800];
        json_escape_to(nmj, sizeof(nmj), name);
        snprintf(obj, sizeof(obj), "{\"pid\":%lu,\"ppid\":%lu,\"name\":%s}",
                 (unsigned long)pe.th32ProcessID, (unsigned long)pe.th32ParentProcessID, nmj);
        EDR_PROC_EMIT(obj);
      } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
  }
#else
  DIR *pd = opendir("/proc");
  if (pd) {
    struct dirent *ent;
    while ((ent = readdir(pd)) != NULL && count < max_procs) {
      if (edr_command_cancel_requested(cmd_id)) {
        cancelled = 1;
        break;
      }
      const char *nm = ent->d_name;
      int isnum = nm[0] != '\0';
      for (const char *q = nm; *q; q++) {
        if (*q < '0' || *q > '9') { isnum = 0; break; }
      }
      if (!isnum) {
        continue;
      }
      long pid = strtol(nm, NULL, 10);
      long ppid = 0;
      char comm[256];
      comm[0] = '\0';
      char statp[80];
      snprintf(statp, sizeof(statp), "/proc/%s/stat", nm);
      FILE *sf = fopen(statp, "r");
      if (sf) {
        char line[4096];
        if (fgets(line, sizeof(line), sf)) {
          char *lp = strchr(line, '(');
          char *rp = lp ? strrchr(line, ')') : NULL;
          if (lp && rp && rp > lp) {
            size_t cl = (size_t)(rp - lp - 1);
            if (cl >= sizeof(comm)) {
              cl = sizeof(comm) - 1;
            }
            memcpy(comm, lp + 1, cl);
            comm[cl] = '\0';
            char stc;
            long pp = 0;
            if (sscanf(rp + 1, " %c %ld", &stc, &pp) >= 2) {
              ppid = pp;
            }
          }
        }
        fclose(sf);
      }
      char nmj[600], obj[800];
      json_escape_to(nmj, sizeof(nmj), comm[0] ? comm : nm);
      snprintf(obj, sizeof(obj), "{\"pid\":%ld,\"ppid\":%ld,\"name\":%s}", pid, ppid, nmj);
      EDR_PROC_EMIT(obj);
    }
    closedir(pd);
  }
#endif
#undef EDR_PROC_EMIT
  if (cancelled || edr_command_cancel_requested(cmd_id)) {
    fclose(f);
    (void)remove(path);
    s_exec_fail++;
    audit_both(cmd_id, "host_process_tree: cancelled during enumeration");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 130, "process snapshot cancelled",
                 "cancelled", NULL);
    return;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "proctree", path, sha,
                                               minio_key, sizeof(minio_key));
  char pathj[1200], minioj[1200], artifacts[3200], detail[30000];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"process_tree\",\"path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  snprintf(detail, sizeof(detail),
           "{\"count\":%d,\"inline_count\":%d,\"processes\":[%s],"
           "\"artifact_path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}",
           count, inline_count, inline_procs, pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  s_handled++;
  s_exec_ok++;
  /* 数据已内联回流，采集即成功；上传失败只降级为 upload_status=failed，不再判任务失败。 */
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, upload_rc == 0 ? "ok" : "ok_upload_failed", artifacts);
}

typedef struct EdrVeloValidatedOutput {
  char *raw;
  cJSON *root;
  int partial;
  int rows_manifest;
  char provider_status[32];
  char provider_error[512];
} EdrVeloValidatedOutput;

static void velo_validated_output_free(EdrVeloValidatedOutput *out) {
  if (!out) return;
  cJSON_Delete(out->root);
  free(out->raw);
  memset(out, 0, sizeof(*out));
}

static int velo_load_validated_output(const char *path, unsigned long long file_size,
                                      EdrVeloValidatedOutput *out, char *error,
                                      size_t error_cap) {
  const unsigned long long max_contract_bytes = 64ull * 1024ull * 1024ull;
  if (!out || !path || !path[0]) return 0;
  memset(out, 0, sizeof(*out));
  if (file_size == 0ull || file_size > max_contract_bytes) {
    if (error && error_cap) {
      snprintf(error, error_cap, "query output size is outside the validated 1..64MiB contract");
    }
    return 0;
  }
  out->raw = (char *)malloc((size_t)file_size + 1u);
  if (!out->raw) {
    if (error && error_cap) snprintf(error, error_cap, "out of memory validating query output");
    return 0;
  }
  FILE *f = fopen(path, "rb");
  size_t read_bytes = f ? fread(out->raw, 1, (size_t)file_size, f) : 0u;
  if (f) fclose(f);
  out->raw[read_bytes] = '\0';
  if (read_bytes != (size_t)file_size) {
    if (error && error_cap) snprintf(error, error_cap, "query output could not be read completely");
    velo_validated_output_free(out);
    return 0;
  }
  out->root = cJSON_Parse(out->raw);
  if (!out->root || !cJSON_IsObject(out->root)) {
    if (error && error_cap) snprintf(error, error_cap, "query output is not a JSON object");
    velo_validated_output_free(out);
    return 0;
  }
  cJSON *schema = cJSON_GetObjectItemCaseSensitive(out->root, "schema");
  if (cJSON_IsString(schema) && schema->valuestring &&
      strcmp(schema->valuestring, "edr.velo_rows.manifest.v1") == 0) {
    cJSON *chunks = cJSON_GetObjectItemCaseSensitive(out->root, "chunks");
    if (!cJSON_IsArray(chunks)) {
      if (error && error_cap) snprintf(error, error_cap, "velo rows manifest is missing the required chunks array");
      velo_validated_output_free(out);
      return 0;
    }
    out->rows_manifest = 1;
  } else {
    cJSON *rows = cJSON_GetObjectItemCaseSensitive(out->root, "rows");
    if (!cJSON_IsArray(rows)) {
      if (error && error_cap) snprintf(error, error_cap, "query output is missing the required rows array");
      velo_validated_output_free(out);
      return 0;
    }
  }
  cJSON *provider_error = cJSON_GetObjectItemCaseSensitive(out->root, "error");
  if (provider_error && !cJSON_IsNull(provider_error) && !cJSON_IsString(provider_error)) {
    if (error && error_cap) snprintf(error, error_cap, "query output error must be a string");
    velo_validated_output_free(out);
    return 0;
  }
  if (cJSON_IsString(provider_error) && provider_error->valuestring && provider_error->valuestring[0]) {
    snprintf(out->provider_error, sizeof(out->provider_error), "%s", provider_error->valuestring);
  }
  cJSON *status = cJSON_GetObjectItemCaseSensitive(out->root, "status");
  if (status && !cJSON_IsString(status)) {
    if (error && error_cap) snprintf(error, error_cap, "query output status must be a string");
    velo_validated_output_free(out);
    return 0;
  }
  if (cJSON_IsString(status) && status->valuestring) {
    snprintf(out->provider_status, sizeof(out->provider_status), "%s", status->valuestring);
    if (strcasecmp(status->valuestring, "failed") == 0 ||
        strcasecmp(status->valuestring, "error") == 0 ||
        strcasecmp(status->valuestring, "rejected") == 0 ||
        strcasecmp(status->valuestring, "cancelled") == 0 ||
        strcasecmp(status->valuestring, "canceled") == 0) {
      if (error && error_cap) {
        snprintf(error, error_cap, "collector reported status %.80s%s%.400s", status->valuestring,
                 out->provider_error[0] ? ": " : "", out->provider_error);
      }
      velo_validated_output_free(out);
      return 0;
    }
    if (strcasecmp(status->valuestring, "partial") == 0 ||
        strcasecmp(status->valuestring, "partial_success") == 0 ||
        strcasecmp(status->valuestring, "degraded") == 0) {
      out->partial = 1;
    } else if (status->valuestring[0] && strcasecmp(status->valuestring, "ok") != 0 &&
               strcasecmp(status->valuestring, "success") != 0 &&
               strcasecmp(status->valuestring, "completed") != 0) {
      if (error && error_cap) snprintf(error, error_cap, "collector returned unsupported status %.80s", status->valuestring);
      velo_validated_output_free(out);
      return 0;
    }
  }
  if (out->provider_error[0] && !out->partial) {
    if (error && error_cap) snprintf(error, error_cap, "collector returned an error: %.400s", out->provider_error);
    velo_validated_output_free(out);
    return 0;
  }
  return 1;
}

static void path_dirname_to(const char *path, char *out, size_t cap) {
  if (!out || cap == 0u) return;
  snprintf(out, cap, "%s", ".");
  if (!path || !path[0]) return;
  size_t n = strlen(path);
  if (n >= cap) n = cap - 1u;
  memcpy(out, path, n);
  out[n] = '\0';
  char *last = NULL;
  for (char *p = out; *p; p++) {
    if (*p == '/' || *p == '\\') last = p;
  }
  if (!last) {
    snprintf(out, cap, "%s", ".");
  } else if (last == out) {
    last[1] = '\0';
  } else {
    *last = '\0';
  }
}

static int relative_chunk_path_safe(const char *rel) {
  if (!rel || !rel[0]) return 0;
  if (rel[0] == '/' || rel[0] == '\\' || strchr(rel, ':')) return 0;
  const char *p = rel;
  while (*p) {
    while (*p == '/' || *p == '\\') p++;
    const char *start = p;
    while (*p && *p != '/' && *p != '\\') p++;
    size_t len = (size_t)(p - start);
    if (len == 2u && start[0] == '.' && start[1] == '.') return 0;
  }
  return 1;
}

static int join_relative_path(const char *dir, const char *rel, char *out, size_t cap) {
  if (!out || cap == 0u || !relative_chunk_path_safe(rel)) return -1;
  int n = snprintf(out, cap, "%s/%s", (dir && dir[0]) ? dir : ".", rel);
  return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

static int velo_write_manifest_file(const char *path, cJSON *root, char *error, size_t error_cap) {
  char *body = cJSON_PrintUnformatted(root);
  if (!body) {
    if (error && error_cap) snprintf(error, error_cap, "manifest serialization failed");
    return -1;
  }
  FILE *f = fopen(path, "wb");
  if (!f) {
    if (error && error_cap) snprintf(error, error_cap, "manifest rewrite failed");
    cJSON_free(body);
    return -1;
  }
  size_t len = strlen(body);
  size_t n = fwrite(body, 1, len, f);
  int close_rc = fclose(f);
  cJSON_free(body);
  if (n != len || close_rc != 0) {
    if (error && error_cap) snprintf(error, error_cap, "manifest rewrite incomplete");
    return -1;
  }
  return 0;
}

static int velo_upload_manifest_chunks(const char *cmd_id, const char *manifest_path, cJSON *root,
                                       char *error, size_t error_cap) {
  cJSON *chunks = cJSON_GetObjectItemCaseSensitive(root, "chunks");
  if (!cJSON_IsArray(chunks)) {
    if (error && error_cap) snprintf(error, error_cap, "manifest chunks missing");
    return -1;
  }
  char dir[900];
  path_dirname_to(manifest_path, dir, sizeof(dir));
  cJSON *chunk = NULL;
  cJSON_ArrayForEach(chunk, chunks) {
    if (!cJSON_IsObject(chunk)) continue;
    cJSON *storage = cJSON_GetObjectItemCaseSensitive(chunk, "storage_key");
    cJSON *object_key = cJSON_GetObjectItemCaseSensitive(chunk, "object_key");
    cJSON *minio_key = cJSON_GetObjectItemCaseSensitive(chunk, "minio_key");
    if ((cJSON_IsString(storage) && storage->valuestring && storage->valuestring[0]) ||
        (cJSON_IsString(object_key) && object_key->valuestring && object_key->valuestring[0]) ||
        (cJSON_IsString(minio_key) && minio_key->valuestring && minio_key->valuestring[0])) {
      continue;
    }
    cJSON *path = cJSON_GetObjectItemCaseSensitive(chunk, "path");
    if (!cJSON_IsString(path) || !path->valuestring || !path->valuestring[0]) {
      if (error && error_cap) snprintf(error, error_cap, "manifest chunk path missing");
      return -1;
    }
    char chunk_path[1200];
    if (join_relative_path(dir, path->valuestring, chunk_path, sizeof(chunk_path)) != 0 || !file_exists_c(chunk_path)) {
      if (error && error_cap) snprintf(error, error_cap, "manifest chunk not found: %.200s", path->valuestring);
      return -1;
    }
    char sha[65];
    sha[0] = '\0';
    if (file_sha256_hex(chunk_path, sha) != 0 || !sha[0]) {
      if (error && error_cap) snprintf(error, error_cap, "manifest chunk hash failed: %.200s", path->valuestring);
      return -1;
    }
    char key[1024];
    key[0] = '\0';
    if (edr_transport_v2_upload_file(cmd_id ? cmd_id : "velo_rows", chunk_path, sha, key, sizeof(key)) != 0 || !key[0]) {
      if (error && error_cap) snprintf(error, error_cap, "manifest chunk upload failed: %.200s", path->valuestring);
      return -1;
    }
    cJSON_DeleteItemFromObjectCaseSensitive(chunk, "sha256");
    cJSON_AddStringToObject(chunk, "sha256", sha);
    cJSON_DeleteItemFromObjectCaseSensitive(chunk, "storage_key");
    cJSON_AddStringToObject(chunk, "storage_key", key);
    cJSON_DeleteItemFromObjectCaseSensitive(chunk, "object_key");
    cJSON_AddStringToObject(chunk, "object_key", key);
    cJSON_DeleteItemFromObjectCaseSensitive(chunk, "minio_key");
    cJSON_AddStringToObject(chunk, "minio_key", key);
    (void)remove(chunk_path);
  }
  return velo_write_manifest_file(manifest_path, root, error, error_cap);
}

/* 主机显微镜·Velociraptor 富数据（V1：进程）。调外部采集器 query 模式跑 VQL → JSONL 行 →
 * 适配器写 out-file 为 {source,artifact,rows:[...],total}；本命令读回并内联回流（前端 extractRecords 取 rows）。
 * 只读、沿用 dangerous 门控；不自动回退（前端有"数据源"手动开关）。 */
static void do_velo_query(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject velo_query: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  uint64_t total_started_ms = command_monotonic_ms();
  long pid = -1;
  (void)parse_pid_json(pl, len, &pid); /* 可选 */
  /* 大结果走产物下载通道，limit 上限提到 5000（与适配器一致）；默认 1000 以含较全集。 */
  int limit = parse_int_json_default(pl, len, "limit", 1000);
  if (limit <= 0 || limit > 5000) {
    limit = 1000;
  }
  char scope[64];
  if (parse_json_string_field(pl, len, "scope", scope, sizeof(scope)) != 0 || !scope[0]) {
    snprintf(scope, sizeof(scope), "%s", "inspect_process");
  }
  /* 闸：仅放行 inspect_* 前缀 + 字符集/长度护栏（[a-z0-9_]，≤48）。具体 scope 由适配器注册表精确校验。
   * scope 串不进 VQL（仅查表 + 拼 action），无注入面。 */
  {
    size_t sl = strlen(scope);
    int ok = (strncmp(scope, "inspect_", 8) == 0) && sl > 8u && sl <= 48u;
    for (size_t i = 0; ok && i < sl; i++) {
      char ch = scope[i];
      if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) {
        ok = 0;
      }
    }
    if (!ok) {
      s_exec_fail++;
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 2, "invalid velo scope (allow: inspect_<name>)");
      return;
    }
  }
  char reqpath[900], rowspath[900];
  command_artifact_path(cmd_id, "veloreq", "json", reqpath, sizeof(reqpath));
  command_artifact_path(cmd_id, "velorows", "json", rowspath, sizeof(rowspath));
  {
    FILE *rf = fopen(reqpath, "w");
    if (!rf) {
      s_exec_fail++;
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create velo request file");
      return;
    }
    fprintf(rf, "{\"scope\":\"%s\",\"pid\":%ld,\"limit\":%d}", scope, pid, limit);
    fclose(rf);
  }
  char extra[2048];
  snprintf(extra, sizeof(extra), "--mode=query --request=%s --out-file=%s --limit=%d", reqpath, rowspath, limit);
  EdrCollectorRunSpec spec;
  memset(&spec, 0, sizeof(spec));
  spec.scope = scope;
  spec.output_dir = ".";
  spec.extra_args = extra;
  spec.timeout_s = 60u;
  spec.cpu_limit_percent = 40u;
  spec.needs_velociraptor = 1; /* velo_query 走 velo 适配器,运行前确保 velo 就绪 */
  spec.cancel_requested = rtr_shell_cancel_check;
  spec.cancel_user = (void *)cmd_id;
  char dc_detail[512];
  dc_detail[0] = '\0';
  uint64_t collector_started_ms = command_monotonic_ms();
  int rc = edr_deep_collector_run_blocking(&spec, dc_detail, sizeof(dc_detail));
  uint64_t collector_finished_ms = command_monotonic_ms();
  (void)remove(reqpath);
  if (rc == 5) {
    s_exec_fail++;
    audit_both(cmd_id, "velo_query: velociraptor 采集器未部署");
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 5, "velociraptor 采集器未部署（设 EDR_FORENSIC_COLLECTOR_BIN 或随包 velociraptor）");
    return;
  }
  if (rc != 0 && rc != 2) {
    s_exec_fail++;
    char fail[640];
    snprintf(fail, sizeof(fail), "velo_query failed rc=%d: %.560s", rc, dc_detail);
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 6, fail);
    return;
  }
  /* 读回适配器产出的 {source,artifact,rows:[...],total}。
   * 大产物上传对象存储 → 前端经 /rtr/velo/:task/rows 取回全量；小产物直接内联回流（前端 extractRecords 取 rows）。
   * 镜像 do_list_modules 的 sha+上传+artifacts+内联 结构（截断不再判失败，改走下载通道）。 */
  unsigned long long fsz = 0ull;
  long long fmt_unused = 0;
  if (file_size_mtime(rowspath, &fsz, &fmt_unused) != 0 || fsz == 0ull) {
    (void)remove(rowspath);
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 7, "velo_query: empty or missing query output");
    return;
  }
  EdrVeloValidatedOutput validated;
  char validation_error[640];
  validation_error[0] = '\0';
  if (!velo_load_validated_output(rowspath, fsz, &validated, validation_error, sizeof(validation_error))) {
    (void)remove(rowspath);
    s_exec_fail++;
    char fail[760];
    snprintf(fail, sizeof(fail), "velo_query: invalid collector result: %.640s",
             validation_error[0] ? validation_error : "unknown contract violation");
    audit_both(cmd_id, fail);
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 7, fail);
    return;
  }
  int provider_partial = validated.partial;
  int rows_manifest = validated.rows_manifest;
  char provider_status[sizeof(validated.provider_status)];
  char provider_error[sizeof(validated.provider_error)];
  snprintf(provider_status, sizeof(provider_status), "%s", validated.provider_status);
  snprintf(provider_error, sizeof(provider_error), "%s", validated.provider_error);
  if (rows_manifest) {
    if (velo_upload_manifest_chunks(cmd_id, rowspath, validated.root, validation_error, sizeof(validation_error)) != 0) {
      velo_validated_output_free(&validated);
      (void)remove(rowspath);
      s_exec_fail++;
      char fail[760];
      snprintf(fail, sizeof(fail), "velo_query: upload manifest chunks failed: %.640s",
               validation_error[0] ? validation_error : "unknown error");
      audit_both(cmd_id, fail);
      soar_emit(cmd_id, sm, EdrCmdExecFailed, 8, fail);
      return;
    }
    free(validated.raw);
    validated.raw = NULL;
  }
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(rowspath, sha);
  int manifest_total = -1;
  char manifest_artifact[256];
  manifest_artifact[0] = '\0';
  if (rows_manifest && validated.root) {
    cJSON *total_item = cJSON_GetObjectItemCaseSensitive(validated.root, "total");
    if (cJSON_IsNumber(total_item)) manifest_total = total_item->valueint;
    cJSON *artifact_item = cJSON_GetObjectItemCaseSensitive(validated.root, "artifact");
    if (cJSON_IsString(artifact_item) && artifact_item->valuestring) {
      snprintf(manifest_artifact, sizeof(manifest_artifact), "%s", artifact_item->valuestring);
    }
  }
  char minio_key[1024];
  minio_key[0] = '\0';
  uint64_t upload_started_ms = command_monotonic_ms();
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "velo_rows", rowspath, sha,
                                               minio_key, sizeof(minio_key));
  uint64_t upload_finished_ms = command_monotonic_ms();
  char pathj[1200], minioj[1200], artifacts[3200];
  json_escape_to(pathj, sizeof(pathj), rowspath);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"velo_rows\",\"path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  /* raw_detail is JSON-escaped again inside the command-result envelope. Keep
   * inline rows below the durable command-state cap; larger results use the
   * already-uploaded velo_rows artifact instead of becoming invalid JSON. */
  const unsigned long long state_safe_inline_cap =
      EDR_COMMAND_STATE_DETAIL_CAP > 8192u
          ? (unsigned long long)(EDR_COMMAND_STATE_DETAIL_CAP - 8192u) / 2ull
          : 1024ull;
  unsigned long long inline_cap = state_safe_inline_cap;
  {
    const char *cs = getenv("EDR_VELO_INLINE_CAP");
    if (cs && cs[0]) {
      long long v = atoll(cs);
      if (v > 0) {
        inline_cap = (unsigned long long)v;
      }
    }
    if (inline_cap > state_safe_inline_cap) {
      inline_cap = state_safe_inline_cap;
    }
  }
  if (!rows_manifest && fsz <= inline_cap) {
    /* 小产物：已验证的文件内容直接内联回流。 */
    char *detail = validated.raw;
    cJSON *root = validated.root;
    validated.raw = NULL;
    validated.root = NULL;
    (void)remove(rowspath);
    if (root && detail) {
      char combined_error[760];
      combined_error[0] = '\0';
      if (provider_error[0]) {
        snprintf(combined_error, sizeof(combined_error), "%s", provider_error);
      } else if (provider_partial) {
        snprintf(combined_error, sizeof(combined_error), "%s", "collector returned a partial result");
      }
      if (upload_rc != 0) {
        size_t used = strlen(combined_error);
        snprintf(combined_error + used, sizeof(combined_error) - used, "%sartifact upload failed; inline rows retained",
                 used ? "; " : "");
      }
      if (provider_status[0]) {
        cJSON_DeleteItemFromObjectCaseSensitive(root, "provider_status");
        cJSON_AddStringToObject(root, "provider_status", provider_status);
      }
      cJSON_DeleteItemFromObjectCaseSensitive(root, "schema");
      cJSON_AddStringToObject(root, "schema", "edr.forensic.result.v1");
      cJSON_DeleteItemFromObjectCaseSensitive(root, "status");
      cJSON_AddStringToObject(root, "status", (provider_partial || upload_rc != 0) ? "partial_success" : "success");
      if (!cJSON_GetObjectItemCaseSensitive(root, "source"))
        cJSON_AddStringToObject(root, "source", "velociraptor");
      if (!cJSON_GetObjectItemCaseSensitive(root, "artifact"))
        cJSON_AddStringToObject(root, "artifact", rowspath);
      cJSON_DeleteItemFromObjectCaseSensitive(root, "sha256");
      cJSON_AddStringToObject(root, "sha256", sha);
      cJSON_DeleteItemFromObjectCaseSensitive(root, "object_key");
      cJSON_AddStringToObject(root, "object_key", minio_key);
      cJSON_DeleteItemFromObjectCaseSensitive(root, "truncated");
      cJSON_AddBoolToObject(root, "truncated", 0);
      cJSON_DeleteItemFromObjectCaseSensitive(root, "upload_status");
      cJSON_AddStringToObject(root, "upload_status", upload_rc == 0 ? "ok" : "failed");
      cJSON_DeleteItemFromObjectCaseSensitive(root, "error");
      cJSON_AddStringToObject(root, "error", combined_error);
      cJSON_DeleteItemFromObjectCaseSensitive(root, "cpu_limit_percent");
      cJSON_AddNumberToObject(root, "cpu_limit_percent", spec.cpu_limit_percent);
      cJSON *timings = cJSON_CreateObject();
      if (timings) {
        cJSON_AddNumberToObject(timings, "prepare_ms",
                                (double)(collector_started_ms - total_started_ms));
        cJSON_AddNumberToObject(timings, "collector_ms",
                                (double)(collector_finished_ms - collector_started_ms));
        cJSON_AddNumberToObject(timings, "process_ms",
                                (double)(upload_started_ms - collector_finished_ms));
        cJSON_AddNumberToObject(timings, "upload_ms",
                                (double)(upload_finished_ms - upload_started_ms));
        cJSON_AddNumberToObject(timings, "total_ms",
                                (double)(command_monotonic_ms() - total_started_ms));
        cJSON_DeleteItemFromObjectCaseSensitive(root, "timings_ms");
        cJSON_AddItemToObject(root, "timings_ms", timings);
      }
      char *contract_detail = cJSON_PrintUnformatted(root);
      cJSON_Delete(root);
      s_handled++;
      s_exec_ok++;
      audit_both(cmd_id, provider_partial ? "velo_query: partial (inline)" : "velo_query: ok (inline)");
      soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, contract_detail ? contract_detail : detail,
                   provider_partial ? "ok_partial" : (upload_rc == 0 ? "ok" : "ok_upload_failed"), artifacts);
      if (contract_detail) cJSON_free(contract_detail);
      free(detail);
      return;
    }
  }
  velo_validated_output_free(&validated);
  (void)remove(rowspath);
  /* 大产物（或内联缓冲分配失败）：空内联 + 下载标记，前端经下载通道取全量。 */
  {
    int can_dl = (upload_rc == 0 && minio_key[0]) ? 1 : 0;
    const char *large_status = can_dl ? (provider_partial ? "partial_success" : "success") : "failed";
    const char *large_error = can_dl
                                  ? (provider_error[0] ? provider_error
                                                       : (provider_partial ? "collector returned a partial result" : ""))
                                  : "large result upload failed; no retrievable rows";
    cJSON *result = cJSON_CreateObject();
    cJSON *timings = result ? cJSON_CreateObject() : NULL;
    cJSON *rows = result ? cJSON_CreateArray() : NULL;
    if (!result || !timings || !rows) {
      cJSON_Delete(rows);
      cJSON_Delete(timings);
      cJSON_Delete(result);
      rows = NULL;
      timings = NULL;
      result = NULL;
    } else {
      cJSON_AddStringToObject(result, "schema", "edr.forensic.result.v1");
      cJSON_AddStringToObject(result, "status", large_status);
      cJSON_AddStringToObject(result, "source", "velociraptor");
      cJSON_AddStringToObject(result, "artifact",
                             manifest_artifact[0] ? manifest_artifact : rowspath);
      cJSON_AddStringToObject(result, "sha256", sha);
      cJSON_AddStringToObject(result, "object_key", minio_key);
      cJSON_AddBoolToObject(result, "truncated", 1);
      cJSON_AddStringToObject(result, "upload_status", upload_rc == 0 ? "ok" : "failed");
      cJSON_AddStringToObject(result, "error", large_error);
      cJSON_AddNumberToObject(result, "cpu_limit_percent", spec.cpu_limit_percent);
      cJSON_AddBoolToObject(result, "download", can_dl);
      cJSON_AddNumberToObject(result, "total", manifest_total);
      cJSON_AddItemToObject(result, "rows", rows);
      rows = NULL;
      cJSON_AddNumberToObject(timings, "prepare_ms",
                              (double)(collector_started_ms - total_started_ms));
      cJSON_AddNumberToObject(timings, "collector_ms",
                              (double)(collector_finished_ms - collector_started_ms));
      cJSON_AddNumberToObject(timings, "process_ms",
                              (double)(upload_started_ms - collector_finished_ms));
      cJSON_AddNumberToObject(timings, "upload_ms",
                              (double)(upload_finished_ms - upload_started_ms));
      cJSON_AddNumberToObject(timings, "total_ms",
                              (double)(command_monotonic_ms() - total_started_ms));
      cJSON_AddItemToObject(result, "timings_ms", timings);
      timings = NULL;
    }
    char *detail = result ? cJSON_PrintUnformatted(result) : NULL;
    cJSON_Delete(rows);
    cJSON_Delete(timings);
    cJSON_Delete(result);
    s_handled++;
    if (can_dl) {
      s_exec_ok++;
    } else {
      s_exec_fail++;
    }
    audit_both(cmd_id, can_dl ? (provider_partial ? "velo_query: partial (download)" : "velo_query: ok (download)")
                              : "velo_query: large result, upload failed");
    soar_emit_ex(cmd_id, sm, can_dl ? EdrCmdExecOk : EdrCmdExecFailed, can_dl ? 0 : 9,
                 detail ? detail : "{\"schema\":\"edr.forensic.result.v1\",\"status\":\"failed\",\"source\":\"velociraptor\",\"error\":\"result serialization failed\"}",
                 can_dl && provider_partial ? "ok_partial" : (upload_rc == 0 ? "ok" : "upload_failed"), artifacts);
    if (detail) cJSON_free(detail);
  }
}

/* 主机显微镜·持久化全景（类 Autoruns）：枚举常见自启动位置 → 扁平 {type,name,command,location} 行。
 * Win：Run/RunOnce 注册表 + 计划任务 + 启动项；Linux：cron + systemd + rc.local + autostart。
 * 只读巡检，沿用 dangerous 门控；镜像 do_list_modules 的产物+内联+上传结构。 */
static void do_list_autoruns(const char *cmd_id, const uint8_t *pl, size_t len,
                             const EdrSoarCommandMeta *sm) {
  if (!dangerous_enabled()) {
    s_rejected++;
    audit_both(cmd_id, "reject list_autoruns: 设置 EDR_CMD_ENABLED=1 或 TOML [command] allow_dangerous=true");
    soar_emit(cmd_id, sm, EdrCmdExecRejected, 1, "policy disabled");
    return;
  }
  int max_rows = parse_int_json_default(pl, len, "max_rows", 500);
  if (max_rows <= 0 || max_rows > 2000) {
    max_rows = 500;
  }
  char path[900];
  command_artifact_path(cmd_id, "autoruns", "json", path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f) {
    s_exec_fail++;
    soar_emit(cmd_id, sm, EdrCmdExecFailed, 3, "cannot create autoruns artifact");
    return;
  }
  fputs("{\"autoruns\":[\n", f);
  int count = 0;
  int cancelled = 0;
  char inl[24000];
  size_t io = 0;
  int inl_n = 0;
  inl[0] = '\0';
#define EDR_AR_EMIT(obj)                                                               \
  do {                                                                                 \
    if (count) fputs(",\n", f);                                                        \
    fputs((obj), f);                                                                   \
    size_t _ol = strlen(obj);                                                          \
    if (io + _ol + 2u < sizeof(inl)) {                                                 \
      if (inl_n) { inl[io++] = ','; }                                                  \
      memcpy(inl + io, (obj), _ol);                                                    \
      io += _ol;                                                                       \
      inl[io] = '\0';                                                                  \
      inl_n++;                                                                         \
    }                                                                                  \
    count++;                                                                           \
  } while (0)
#ifdef _WIN32
  {
    static const struct { HKEY root; const char *sub; const char *label; } RUN_KEYS[] = {
      { HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\...\\Run" },
      { HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM\\...\\RunOnce" },
      { HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\...\\Run" },
      { HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\...\\RunOnce" },
      { HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Wow6432\\Run" },
    };
    for (size_t ki = 0; ki < sizeof(RUN_KEYS) / sizeof(RUN_KEYS[0]) && count < max_rows; ki++) {
      if (edr_command_cancel_requested(cmd_id)) { cancelled = 1; break; }
      HKEY hk;
      if (RegOpenKeyExA(RUN_KEYS[ki].root, RUN_KEYS[ki].sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        continue;
      }
      for (DWORD idx = 0; count < max_rows; idx++) {
        if (edr_command_cancel_requested(cmd_id)) { cancelled = 1; break; }
        char name[512];
        BYTE data[4096];
        DWORD ns = sizeof(name), ds = sizeof(data), type = 0;
        LONG lr = RegEnumValueA(hk, idx, name, &ns, NULL, &type, data, &ds);
        if (lr != ERROR_SUCCESS) {
          break;
        }
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
          continue;
        }
        char cmd[4096];
        DWORD cl = ds < (DWORD)(sizeof(cmd) - 1) ? ds : (DWORD)(sizeof(cmd) - 1);
        memcpy(cmd, data, cl);
        cmd[cl] = '\0'; /* REG_SZ data 末尾含 NUL；此处再兜底终止 */
        char nmj[700], cmj[4200], locj[200], obj[5400];
        json_escape_to(nmj, sizeof(nmj), name);
        json_escape_to(cmj, sizeof(cmj), cmd);
        json_escape_to(locj, sizeof(locj), RUN_KEYS[ki].label);
        snprintf(obj, sizeof(obj), "{\"type\":\"run_key\",\"name\":%s,\"command\":%s,\"location\":%s}", nmj, cmj, locj);
        EDR_AR_EMIT(obj);
      }
      RegCloseKey(hk);
      if (cancelled) break;
    }
    /* 计划任务 + 启动项：通过可取消执行器采样，避免 popen/fgets 无输出时卡住。 */
    static const struct { const char *cmd; const char *type; const char *loc; } WIN_CMDS[] = {
      { "schtasks /query /fo csv /nh 2>nul", "scheduled_task", "schtasks" },
      { "wmic startup get Caption,Command /format:csv 2>nul", "startup_item", "wmic_startup" },
    };
    for (size_t ci = 0; !cancelled && ci < sizeof(WIN_CMDS) / sizeof(WIN_CMDS[0]) && count < max_rows; ci++) {
      char *output = (char *)calloc(1u, 65536u);
      int exit_code = 0;
      if (!output) { continue; }
      if (edr_shell_exec_cancellable(WIN_CMDS[ci].cmd, 15, output, 65536u, &exit_code,
                                     rtr_shell_cancel_check, (void *)cmd_id) != 0) {
        free(output);
        continue;
      }
      if (exit_code == 130 || edr_command_cancel_requested(cmd_id)) {
        cancelled = 1;
        free(output);
        break;
      }
      char *line = output;
      while (*line && count < max_rows) {
        char *next = strpbrk(line, "\r\n");
        if (next) {
          *next = '\0';
          char *after = next + 1;
          while (*after == '\r' || *after == '\n') after++;
          next = after;
        }
        if (!line[0]) { line = next ? next : line + strlen(line); continue; }
        char lj[2200], tj[64], loj[64], obj[2500];
        json_escape_to(lj, sizeof(lj), line);
        json_escape_to(tj, sizeof(tj), WIN_CMDS[ci].type);
        json_escape_to(loj, sizeof(loj), WIN_CMDS[ci].loc);
        snprintf(obj, sizeof(obj), "{\"type\":%s,\"name\":%s,\"command\":%s,\"location\":%s}", tj, lj, lj, loj);
        EDR_AR_EMIT(obj);
        if (!next) break;
        line = next;
      }
      free(output);
    }
  }
#else
  {
    static const struct { const char *cmd; const char *type; const char *loc; } NIX_CMDS[] = {
      { "crontab -l 2>/dev/null", "cron", "user_crontab" },
      { "ls -1 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null", "cron_system", "/etc/cron.*" },
      { "systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | head -300", "systemd", "systemd_enabled" },
      { "cat /etc/rc.local 2>/dev/null", "rc_local", "/etc/rc.local" },
      { "ls -1 ~/.config/autostart /etc/xdg/autostart 2>/dev/null", "autostart", "autostart" },
    };
    for (size_t ci = 0; !cancelled && ci < sizeof(NIX_CMDS) / sizeof(NIX_CMDS[0]) && count < max_rows; ci++) {
      char *output = (char *)calloc(1u, 65536u);
      int exit_code = 0;
      if (!output) { continue; }
      if (edr_shell_exec_cancellable(NIX_CMDS[ci].cmd, 15, output, 65536u, &exit_code,
                                     rtr_shell_cancel_check, (void *)cmd_id) != 0) {
        free(output);
        continue;
      }
      if (exit_code == 130 || edr_command_cancel_requested(cmd_id)) {
        cancelled = 1;
        free(output);
        break;
      }
      char *line = output;
      while (*line && count < max_rows) {
        char *next = strpbrk(line, "\r\n");
        if (next) {
          *next = '\0';
          char *after = next + 1;
          while (*after == '\r' || *after == '\n') after++;
          next = after;
        }
        if (!line[0] || line[0] == '#') { line = next ? next : line + strlen(line); continue; }
        char lj[2200], tj[64], loj[64], obj[2500];
        json_escape_to(lj, sizeof(lj), line);
        json_escape_to(tj, sizeof(tj), NIX_CMDS[ci].type);
        json_escape_to(loj, sizeof(loj), NIX_CMDS[ci].loc);
        snprintf(obj, sizeof(obj), "{\"type\":%s,\"name\":%s,\"command\":%s,\"location\":%s}", tj, lj, lj, loj);
        EDR_AR_EMIT(obj);
        if (!next) break;
        line = next;
      }
      free(output);
    }
  }
#endif
#undef EDR_AR_EMIT
  if (cancelled || edr_command_cancel_requested(cmd_id)) {
    fclose(f);
    (void)remove(path);
    s_exec_fail++;
    audit_both(cmd_id, "list_autoruns: cancelled during enumeration");
    soar_emit_ex(cmd_id, sm, EdrCmdExecFailed, 130, "autoruns collection cancelled",
                 "cancelled", NULL);
    return;
  }
  fprintf(f, "\n],\"total\":%d}\n", count);
  fclose(f);
  char sha[65];
  sha[0] = '\0';
  (void)file_sha256_hex(path, sha);
  char minio_key[1024];
  minio_key[0] = '\0';
  int upload_rc = edr_transport_v2_upload_file(cmd_id ? cmd_id : "autoruns", path, sha,
                                               minio_key, sizeof(minio_key));
  char pathj[1200], minioj[1200], artifacts[3200], detail[26000];
  json_escape_to(pathj, sizeof(pathj), path);
  json_escape_to(minioj, sizeof(minioj), minio_key);
  snprintf(artifacts, sizeof(artifacts),
           "[{\"type\":\"autoruns\",\"path\":%s,\"sha256\":\"%s\","
           "\"upload_status\":\"%s\",\"minio_key\":%s}]",
           pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  snprintf(detail, sizeof(detail),
           "{\"count\":%d,\"inline_count\":%d,\"autoruns\":[%s],"
           "\"artifact_path\":%s,\"sha256\":\"%s\",\"upload_status\":\"%s\",\"minio_key\":%s}",
           count, inl_n, inl, pathj, sha, upload_rc == 0 ? "ok" : "failed", minioj);
  s_handled++;
  s_exec_ok++;
  /* 数据已内联回流，采集即成功；上传失败只降级为 upload_status=failed，不再判任务失败。 */
  soar_emit_ex(cmd_id, sm, EdrCmdExecOk, 0, detail, upload_rc == 0 ? "ok" : "ok_upload_failed", artifacts);
}

static void do_pmfe_scan(const char *cmd_id, const uint8_t *pl, size_t len, const EdrSoarCommandMeta *sm) {
  edr_response_pmfe_scan(cmd_id, pl, len, sm);
}

static void hex_from_bytes(const uint8_t *in, size_t len, char *out, size_t cap) {
  static const char *hx = "0123456789abcdef";
  if (!out || cap == 0u) {
    return;
  }
  size_t o = 0;
  for (size_t i = 0; i < len && o + 2u < cap; i++) {
    out[o++] = hx[in[i] >> 4];
    out[o++] = hx[in[i] & 15u];
  }
  out[o] = 0;
}

static void hmac_sha256_hex(const char *key, const uint8_t *data, size_t len, char out65[65]) {
  uint8_t key_block[64];
  uint8_t digest[EDR_SHA256_DIGEST_LEN];
  uint8_t ipad[64];
  uint8_t opad[64];
  memset(key_block, 0, sizeof(key_block));
  if (!key) {
    key = "";
  }
  size_t key_len = strlen(key);
  if (key_len > sizeof(key_block)) {
    EdrSha256Ctx kh;
    edr_sha256_init(&kh);
    edr_sha256_update(&kh, (const uint8_t *)key, key_len);
    edr_sha256_final(&kh, key_block);
  } else if (key_len > 0u) {
    memcpy(key_block, key, key_len);
  }
  for (size_t i = 0; i < sizeof(key_block); i++) {
    ipad[i] = key_block[i] ^ 0x36u;
    opad[i] = key_block[i] ^ 0x5cu;
  }
  EdrSha256Ctx inner;
  edr_sha256_init(&inner);
  edr_sha256_update(&inner, ipad, sizeof(ipad));
  edr_sha256_update(&inner, data, len);
  edr_sha256_final(&inner, digest);

  EdrSha256Ctx outer;
  edr_sha256_init(&outer);
  edr_sha256_update(&outer, opad, sizeof(opad));
  edr_sha256_update(&outer, digest, sizeof(digest));
  edr_sha256_final(&outer, digest);
  hex_from_bytes(digest, sizeof(digest), out65, 65u);
}

static int command_signature_extract_sigv1(const char *idempotency_key, char sig65[65]) {
  if (!idempotency_key || !sig65) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  if (!mark) {
    return 0;
  }
  const char *keyid = mark + strlen("|sigv1|");
  const char *bar = strchr(keyid, '|');
  if (!bar || strlen(bar + 1) != 64u) {
    return 0;
  }
  for (size_t i = 0; i < 64u; i++) {
    char c = bar[1 + i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return 0;
    }
    sig65[i] = (char)tolower((unsigned char)c);
  }
  sig65[64] = 0;
  return 1;
}

static int b64url_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
  if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
  if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

static int b64url_decode_raw(const char *s, uint8_t *out, size_t out_cap, size_t *out_len) {
  if (!s || !out || !out_len) {
    return -1;
  }
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t o = 0;
  for (; *s; s++) {
    if (*s == '=') {
      break;
    }
    int v = b64url_value((unsigned char)*s);
    if (v < 0) {
      return -1;
    }
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= out_cap) {
        return -1;
      }
      out[o++] = (uint8_t)((acc >> bits) & 0xffu);
    }
  }
  *out_len = o;
  return 0;
}

static int command_signature_extract_sigv2(const char *idempotency_key, char *alg, size_t alg_cap,
                                           uint8_t *sig, size_t sig_cap, size_t *sig_len) {
  if (!idempotency_key || !alg || alg_cap == 0u || !sig || !sig_len) {
    return 0;
  }
  const char *mark = strstr(idempotency_key, "|sigv2|");
  if (!mark) {
    return 0;
  }
  const char *algp = mark + strlen("|sigv2|");
  const char *bar1 = strchr(algp, '|');
  if (!bar1 || bar1 == algp) {
    return 0;
  }
  size_t alg_len = (size_t)(bar1 - algp);
  if (alg_len >= alg_cap) {
    alg_len = alg_cap - 1u;
  }
  memcpy(alg, algp, alg_len);
  alg[alg_len] = '\0';
  const char *keyid = bar1 + 1;
  const char *bar2 = strchr(keyid, '|');
  if (!bar2 || bar2 == keyid || !bar2[1]) {
    return 0;
  }
  if (b64url_decode_raw(bar2 + 1, sig, sig_cap, sig_len) != 0) {
    return 0;
  }
  return *sig_len > 0u;
}

static void normalize_pem_newlines(char *s) {
  if (!s) {
    return;
  }
  char *r = s;
  char *w = s;
  while (*r) {
    if (r[0] == '\\' && r[1] == 'n') {
      *w++ = '\n';
      r += 2;
    } else {
      *w++ = *r++;
    }
  }
  *w = '\0';
}

static int read_text_file_small(const char *path, char *out, size_t cap) {
  if (!path || !path[0] || !out || cap < 2u) {
    return -1;
  }
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  size_t n = fread(out, 1, cap - 1u, f);
  fclose(f);
  out[n] = '\0';
  return n > 0u ? 0 : -1;
}

static int read_command_public_key_path(const char *path, char *out, size_t cap) {
  if (!path || !path[0]) {
    return -1;
  }
  if (read_text_file_small(path, out, cap) == 0) {
    return 0;
  }
#ifdef _WIN32
  {
    const char *legacy = "\\EDR Agent\\";
    const char *p = strstr(path, legacy);
    if (p) {
      char alt[1024];
      size_t prefix_len = (size_t)(p - path);
      int n = snprintf(alt, sizeof(alt), "%.*s\\FDSecurity\\%s",
                       (int)prefix_len, path, p + strlen(legacy));
      if (n > 0 && (size_t)n < sizeof(alt) &&
          read_text_file_small(alt, out, cap) == 0) {
        return 0;
      }
    }
  }
#endif
  return -1;
}

static int command_public_key_pem(char *out, size_t cap) {
  if (!out || cap < 2u) {
    return 0;
  }
  out[0] = '\0';
  const char *inline_pem = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY");
  if (!inline_pem || !inline_pem[0]) {
    inline_pem = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY");
  }
  if (inline_pem && inline_pem[0]) {
    snprintf(out, cap, "%s", inline_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  const char *path = getenv("EDR_COMMAND_SIGNING_PUBLIC_KEY_PATH");
  if (!path || !path[0]) {
    path = getenv("EDR_COMMAND_VERIFY_PUBLIC_KEY_PATH");
  }
  if (path && path[0] && read_command_public_key_path(path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  if (edr_command_get_config() && edr_command_get_config()->command.signing_public_key_pem[0]) {
    snprintf(out, cap, "%s", edr_command_get_config()->command.signing_public_key_pem);
    normalize_pem_newlines(out);
    return out[0] != '\0';
  }
  if (edr_command_get_config() && edr_command_get_config()->command.signing_public_key_path[0] &&
      read_command_public_key_path(edr_command_get_config()->command.signing_public_key_path, out, cap) == 0) {
    normalize_pem_newlines(out);
    return 1;
  }
  return 0;
}

static int command_verify_ed25519_pem(const char *public_key_pem, const uint8_t *msg, size_t msg_len,
                                      const uint8_t *sig, size_t sig_len) {
#ifdef EDR_HAVE_COMMAND_SIGNATURE_OPENSSL
  if (!public_key_pem || !public_key_pem[0] || !msg || !sig || sig_len == 0u) {
    return 0;
  }
  BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
  if (!bio) {
    return 0;
  }
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    return 0;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = 0;
  if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) {
    ok = 1;
  }
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
  EVP_PKEY_free(pkey);
  return ok;
#else
  (void)public_key_pem;
  (void)msg;
  (void)msg_len;
  (void)sig;
  (void)sig_len;
  return -1;
#endif
}

static void command_signature_idempotency_value(const char *idempotency_key, char *out, size_t cap) {
  if (!out || cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (!idempotency_key || !idempotency_key[0]) {
    return;
  }
  const char *mark = strstr(idempotency_key, "|sigv1|");
  const char *mark2 = strstr(idempotency_key, "|sigv2|");
  if (!mark || (mark2 && mark2 < mark)) {
    mark = mark2;
  }
  size_t n = mark ? (size_t)(mark - idempotency_key) : strlen(idempotency_key);
  if (n >= cap) {
    n = cap - 1u;
  }
  memcpy(out, idempotency_key, n);
  out[n] = '\0';
}

static int command_signature_verify(const char *cmd_id, const char *cmd_type, const uint8_t *payload,
                                    size_t payload_len, const EdrSoarCommandMeta *sm,
                                    int internal_trusted, char *reason, size_t reason_cap) {
  int required = internal_trusted ? 0 :
      edr_command_contract_signature_required(cmd_id, cmd_type);
  if (required && (!sm || sm->issued_at_unix_ms <= 0 || sm->deadline_ms == 0u)) {
    snprintf(reason, reason_cap, "signed external command requires issued_at_unix_ms and deadline_ms");
    return 0;
  }
  if (required) {
    int64_t now_ms = command_now_ms();
    uint32_t max_future_skew_ms = command_u32_env_clamped(
        "EDR_COMMAND_MAX_FUTURE_SKEW_MS", 300000u, 1000u, 3600000u);
    if (sm->issued_at_unix_ms > now_ms + (int64_t)max_future_skew_ms) {
      snprintf(reason, reason_cap, "command issued_at_unix_ms is too far in the future");
      return 0;
    }
  }

  char idem[512];
  command_signature_idempotency_value(sm ? sm->idempotency_key : NULL, idem, sizeof(idem));
  if (required && !idem[0]) {
    snprintf(reason, reason_cap, "missing idempotency key");
    return 0;
  }
  char payload_hash[65];
  (void)edr_sha256_hex(payload ? payload : (const uint8_t *)"", payload_len, payload_hash);
  char canonical[1024];
  snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%lld\n%u\n%s",
           cmd_id ? cmd_id : "", cmd_type ? cmd_type : "",
           idem,
           (long long)(sm ? sm->issued_at_unix_ms : 0), (unsigned)(sm ? sm->deadline_ms : 0),
           payload_hash);

  char alg[32];
  uint8_t sig2[96];
  size_t sig2_len = 0u;
  if (command_signature_extract_sigv2(sm ? sm->idempotency_key : NULL, alg, sizeof(alg),
                                      sig2, sizeof(sig2), &sig2_len)) {
    if (strcmp(alg, "ed25519") != 0) {
      snprintf(reason, reason_cap, "unsupported command signature algorithm: %s", alg);
      return 0;
    }
    if (sig2_len != 64u) {
      snprintf(reason, reason_cap, "invalid command sigv2 signature length");
      return 0;
    }
    char public_key_pem[4096];
    if (!command_public_key_pem(public_key_pem, sizeof(public_key_pem))) {
      snprintf(reason, reason_cap, "command sigv2 public key missing");
      return 0;
    }
    int ok = command_verify_ed25519_pem(public_key_pem, (const uint8_t *)canonical,
                                        strlen(canonical), sig2, sig2_len);
    if (ok == -1) {
      snprintf(reason, reason_cap, "command sigv2 requires OpenSSL verification support");
      return 0;
    }
    if (!ok) {
      snprintf(reason, reason_cap, "invalid command sigv2 signature");
      return 0;
    }
    return 1;
  }

  char configured_public_key[4096];
  int has_public_key = command_public_key_pem(configured_public_key, sizeof(configured_public_key));
  const char *accept_legacy = getenv("EDR_COMMAND_ACCEPT_LEGACY_HMAC");
  if (required && has_public_key && !(accept_legacy && accept_legacy[0] == '1')) {
    snprintf(reason, reason_cap, "missing command sigv2 signature");
    return 0;
  }

  const char *key = getenv("EDR_COMMAND_SIGNING_KEY");
  if ((!key || !key[0]) && !required) {
    return 1;
  }
  if (!key || !key[0]) {
    snprintf(reason, reason_cap, "command signature required but no sigv2 public key or EDR_COMMAND_SIGNING_KEY configured");
    return 0;
  }

  char got[65];
  if (!command_signature_extract_sigv1(sm ? sm->idempotency_key : NULL, got)) {
    if (required) {
      snprintf(reason, reason_cap, "missing command signature");
      return 0;
    }
    return 1;
  }
  char want[65];
  hmac_sha256_hex(key, (const uint8_t *)canonical, strlen(canonical), want);
  if (strcmp(got, want) != 0) {
    snprintf(reason, reason_cap, "invalid command signature");
    return 0;
  }
  return 1;
}

static int64_t command_now_ms(void) {
  return (int64_t)time(NULL) * 1000LL;
}

static uint64_t command_monotonic_ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0u;
  }
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

static int command_deadline_expired(const EdrSoarCommandMeta *sm, char *reason, size_t cap) {
  if (!sm || sm->issued_at_unix_ms <= 0 || sm->deadline_ms == 0u) {
    return 0;
  }
  int64_t deadline = sm->issued_at_unix_ms + (int64_t)sm->deadline_ms;
  int64_t now = command_now_ms();
  if (now <= deadline) {
    return 0;
  }
  snprintf(reason, cap, "command expired issued_at=%lld deadline_ms=%u now=%lld",
           (long long)sm->issued_at_unix_ms, (unsigned)sm->deadline_ms, (long long)now);
  return 1;
}

static int command_lane_filter(const char *command_type, void *user) {
  int lane = user ? *(const int *)user : -1;
  return lane < 0 || (int)edr_command_registry_execution_lane(command_type) == lane;
}

int edr_command_replay_persisted_inbox_once_for_lane(int lane) {
  EdrCommandInboxRecord inbox[16];
  memset(inbox, 0, sizeof(inbox));
  int n = edr_command_state_collect_inbox_filtered(
      inbox, sizeof(inbox) / sizeof(inbox[0]), command_lane_filter, &lane);
  int work_done = 0;
  int saw_error = 0;
  for (int i = 0; i < n; i++) {
    if (!edr_command_cancel_begin(inbox[i].command_id)) {
      continue;
    }
    command_set_active_type_owned(inbox[i].command_type);
    char sig_reason[160];
    sig_reason[0] = '\0';
    int internal_trusted = strncmp(inbox[i].command_id, "auto-", 5u) == 0 &&
                           strcmp(inbox[i].meta.initiated_by, "agent_auto") == 0;
    if (!command_signature_verify(inbox[i].command_id, inbox[i].command_type,
                                  inbox[i].payload, inbox[i].payload_len,
                                  &inbox[i].meta, internal_trusted,
                                  sig_reason, sizeof(sig_reason))) {
      audit_both(inbox[i].command_id, sig_reason[0] ? sig_reason : "persisted command signature rejected");
      soar_emit(inbox[i].command_id, &inbox[i].meta, EdrCmdExecRejected, 15,
                sig_reason[0] ? sig_reason : "persisted command signature rejected");
      edr_command_cancel_end(inbox[i].command_id);
      work_done = 1;
      break;
    }
    if (strcmp(inbox[i].command_type, "agent_update") == 0) {
      EdrAgentUpdateRecovery recovery;
      int recovery_rc = edr_agent_update_recover(inbox[i].command_id, inbox[i].payload,
                                                   inbox[i].payload_len, &recovery);
      if (recovery_rc == 2) {
        /* Stage and task lifecycle data is delivered only through the durable
         * upgrade-event outbox. The command result is an ACK-gated transport
         * terminal and deliberately carries no task-event detail. */
        soar_emit_ex(inbox[i].command_id, &inbox[i].meta,
                     recovery.succeeded ? EdrCmdExecOk : EdrCmdExecFailed,
                     recovery.exit_code, "agent update terminal event acknowledged",
                     recovery.succeeded ? "ok" : "failed", NULL);
        edr_command_cancel_end(inbox[i].command_id);
        work_done = 1;
        break;
      }
      if (recovery_rc < 0) {
        audit_both(inbox[i].command_id, "agent update journal recovery read failed; inbox retained");
        edr_command_cancel_end(inbox[i].command_id);
        saw_error = 1;
        continue;
      }
      if (recovery_rc == 1) {
        edr_command_cancel_end(inbox[i].command_id);
        continue;
      }
      /* No journal yet: this may be the first execution of the queued command.
       * Continue through durable begin; final-only replay policy will block an
       * already-started command rather than launch replacement twice. */
    }
    if (strcmp(inbox[i].command_type, "agent_restart_service") == 0) {
      EdrAgentLifecycleRecovery recovery;
      int recovery_rc = edr_agent_lifecycle_recover(
          inbox[i].command_id, inbox[i].payload, inbox[i].payload_len, &recovery);
      if (recovery_rc == 2) {
        soar_emit_ex(inbox[i].command_id, &inbox[i].meta,
                     recovery.succeeded ? EdrCmdExecOk : EdrCmdExecFailed,
                     recovery.exit_code,
                     recovery.detail[0] ? recovery.detail : "Agent service restart completed",
                     recovery.succeeded ? "ok" : "failed", NULL);
        edr_command_cancel_end(inbox[i].command_id);
        work_done = 1;
        break;
      }
      if (recovery_rc < 0) {
        audit_both(inbox[i].command_id,
                   "Agent lifecycle journal recovery failed; inbox retained");
        edr_command_cancel_end(inbox[i].command_id);
        saw_error = 1;
        continue;
      }
      if (recovery_rc == 1) {
        edr_command_cancel_end(inbox[i].command_id);
        continue;
      }
    }
    char reason[180];
    reason[0] = '\0';
    if (command_deadline_expired(&inbox[i].meta, reason, sizeof(reason))) {
      audit_both(inbox[i].command_id, reason);
      soar_emit_ex(inbox[i].command_id, &inbox[i].meta, EdrCmdExecFailed, 16,
                   reason, "timeout", NULL);
      edr_command_cancel_end(inbox[i].command_id);
      work_done = 1;
      break;
    }
    int retry_count = 0;
    EdrCommandStateRecord dup;
    int allow_replay = edr_command_registry_replay_policy(inbox[i].command_type) ==
                       EDR_COMMAND_REPLAY_IDEMPOTENT;
    int begin_rc = edr_command_state_replay_begin_policy(
        inbox[i].command_id, inbox[i].command_type, &inbox[i].meta, allow_replay,
        &retry_count, &dup);
    if (begin_rc == EDR_COMMAND_STATE_BEGIN_DUP_FINAL) {
      audit_both(inbox[i].command_id, "persisted command replay suppressed by final idempotency state");
      edr_command_state_delete_inbox(inbox[i].command_id);
      edr_command_cancel_end(inbox[i].command_id);
      work_done = 1;
      break;
    }
    if (begin_rc == EDR_COMMAND_STATE_BEGIN_DUP_RUNNING) {
      if (edr_command_cancel_requested(inbox[i].command_id)) {
        edr_command_emit_always_typed_status(
            inbox[i].command_id, inbox[i].command_type, &inbox[i].meta,
            EdrCmdExecFailed, 130, "command cancelled before action started", "cancelled");
        edr_command_cancel_end(inbox[i].command_id);
        work_done = 1;
        break;
      }
      char detail[320];
      snprintf(detail, sizeof(detail), "persisted command replay deferred; command already running id=%s type=%s retry=%d",
               dup.command_id[0] ? dup.command_id : inbox[i].command_id,
               dup.command_type[0] ? dup.command_type : inbox[i].command_type,
               retry_count);
      audit_both(inbox[i].command_id, detail);
      edr_command_cancel_end(inbox[i].command_id);
      continue;
    }
    if (begin_rc == EDR_COMMAND_STATE_BEGIN_REPLAY_BLOCKED) {
      if (strcmp(inbox[i].command_type, "agent_update") == 0) {
        audit_both(inbox[i].command_id,
                   "agent update already launched; awaiting terminal updater journal");
        edr_command_cancel_end(inbox[i].command_id);
        continue;
      }
      if (strcmp(inbox[i].command_type, "agent_restart_service") == 0) {
        audit_both(inbox[i].command_id,
                   "Agent restart already launched; awaiting terminal worker journal");
        edr_command_cancel_end(inbox[i].command_id);
        continue;
      }
      int was_cancelling = strcmp(dup.response_status, "cancelling") == 0;
      audit_both(inbox[i].command_id, was_cancelling
                                            ? "persisted cancelled command suppressed on replay"
                                            : "persisted command replay blocked by command replay policy");
      soar_emit_ex(inbox[i].command_id, &inbox[i].meta, EdrCmdExecFailed,
                   was_cancelling ? 130 : 17,
                   was_cancelling ? "command cancellation recovered after restart"
                                  : "command was interrupted and is not safe to replay",
                   was_cancelling ? "cancelled" : "failed", NULL);
      edr_command_cancel_end(inbox[i].command_id);
      work_done = 1;
      break;
    }
    if (begin_rc != EDR_COMMAND_STATE_BEGIN_READY) {
      audit_both(inbox[i].command_id, "persisted command replay begin failed");
      edr_command_cancel_end(inbox[i].command_id);
      saw_error = 1;
      continue;
    }
    audit_both(inbox[i].command_id, "replaying persisted command inbox");
    if (edr_command_cancel_requested(inbox[i].command_id)) {
      edr_command_emit_always_typed_status(
          inbox[i].command_id, inbox[i].command_type, &inbox[i].meta,
          EdrCmdExecFailed, 130, "command cancelled before action started", "cancelled");
      edr_command_cancel_end(inbox[i].command_id);
      work_done = 1;
      break;
    }
    edr_command_execute_persisted_envelope(inbox[i].command_id, inbox[i].command_type,
                                           inbox[i].payload, inbox[i].payload_len,
                                           &inbox[i].meta);
    edr_command_cancel_end(inbox[i].command_id);
    work_done = 1;
    break;
  }
  for (int i = 0; i < n; i++) {
    edr_command_state_free_inbox_record(&inbox[i]);
  }
  if (work_done) {
    return 1;
  }
  return saw_error ? -1 : 0;
}

int edr_command_replay_persisted_inbox_once(void) {
  for (int lane = 0; lane < EDR_COMMAND_LANE_COUNT; lane++) {
    int rc = edr_command_replay_persisted_inbox_once_for_lane(lane);
    if (rc != 0) {
      return rc;
    }
  }
  return 0;
}

static uint32_t command_result_retry_delay_ms(const EdrCommandStateRecord *record) {
  uint64_t delay = command_u32_env_clamped("EDR_COMMAND_RESULT_RETRY_BASE_MS", 5000u, 1000u, 60000u);
  uint64_t cap = command_u32_env_clamped("EDR_COMMAND_RESULT_RETRY_MAX_MS", 300000u, 5000u, 3600000u);
  uint32_t attempts = record && record->report_attempts ? record->report_attempts : 1u;
  for (uint32_t i = 1u; i < attempts && delay < cap; i++) {
    delay *= 2u;
    if (delay > cap) {
      delay = cap;
    }
  }
  /* Deterministic bounded jitter avoids endpoints retrying the same result in
   * lockstep while preserving a reproducible delay for a persisted record. */
  uint32_t hash = 2166136261u;
  if (record) {
    for (const unsigned char *p = (const unsigned char *)record->command_id; p && *p; p++) {
      hash = (hash ^ *p) * 16777619u;
    }
  }
  uint64_t jitter = delay / 10u;
  if (jitter > 0u) {
    delay += hash % (jitter + 1u);
  }
  return (uint32_t)(delay > cap ? cap : delay);
}

static void record_command_result_delivery_failure(const EdrCommandStateRecord *record, int rc) {
  char error[192];
  int retryable = 1;
  error[0] = '\0';
  edr_ingest_http_get_last_command_result_delivery_error(error, sizeof(error), &retryable);
  if (!error[0]) {
    snprintf(error, sizeof(error), "%s", "command result delivery failed");
  }
  if (rc == EDR_INGEST_COMMAND_RESULT_REJECTED || !retryable) {
    if (edr_command_state_mark_report_rejected(record, error) != 0) {
      audit_both(record->command_id,
                 "command result rejection received but terminal state persistence failed; pending result retained");
    } else {
      audit_both(record->command_id,
                 "command result permanently rejected; retained in local dead-letter state");
    }
    return;
  }
  uint32_t alert_attempts = command_u32_env_clamped("EDR_COMMAND_RESULT_RETRY_ALERT_ATTEMPTS", 12u, 1u, 1000u);
  if (record->report_attempts == alert_attempts) {
    audit_both(record->command_id, "command result retry threshold reached; durable retry remains active");
  }
  int64_t next_retry = command_now_ms() + (int64_t)command_result_retry_delay_ms(record);
  if (edr_command_state_mark_report_retry(record, error, next_retry) != 0) {
    audit_both(record->command_id, "command result delivery failed and retry state could not be persisted");
  }
}

static void flush_command_result_outbox(void) {
  EdrCommandStateRecord pending[16];
  int n = edr_command_state_collect_pending(pending, sizeof(pending) / sizeof(pending[0]));
  if (n <= 0) {
    return;
  }
  for (int i = 0; i < n; i++) {
    EdrSoarCommandMeta sm;
    memset(&sm, 0, sizeof(sm));
    snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s", pending[i].soar_correlation_id);
    snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s", pending[i].playbook_run_id);
    snprintf(sm.playbook_step_id, sizeof(sm.playbook_step_id), "%s", pending[i].playbook_step_id);
    if (!command_should_report(pending[i].command_id, &sm)) {
      continue;
    }
    int rc = -1;
    if (edr_ingest_http_configured()) {
      rc = edr_transport_v2_command_result_typed(pending[i].command_id, pending[i].command_type, &sm,
                                                 pending[i].execution_status, pending[i].exit_code,
                                                 pending[i].detail);
    }
    if (rc == 0) {
      if (edr_command_state_mark_reported(&pending[i]) != 0) {
        audit_both(pending[i].command_id,
                   "command result accepted but reported-state persistence failed; idempotent delivery remains pending");
      }
    } else {
      record_command_result_delivery_failure(&pending[i], rc);
    }
  }
}

void edr_command_on_pmfe_scan_complete(const char *command_id, uint32_t pid, int scan_status,
                                       const char *detail,
                                       const EdrPmfeScanResult *result,
                                       const struct EdrPmfeCommandContext *context) {
  if (!command_id || !command_id[0]) {
    return;
  }
  pmfe_completion_lock();
  for (size_t i = 0; i < PMFE_COMPLETION_CAP; i++) {
    if (s_pmfe_completions[i].used) {
      continue;
    }
    PmfeCompletion *slot = &s_pmfe_completions[i];
    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    snprintf(slot->command_id, sizeof(slot->command_id), "%s", command_id);
    slot->pid = pid;
    slot->scan_status = scan_status;
    snprintf(slot->detail, sizeof(slot->detail), "%s", detail ? detail : "pmfe scan completed without detail");
    if (result) {
      slot->result = *result;
    }
    if (context) {
      slot->context = *context;
    }
    pmfe_completion_unlock();
    return;
  }
  pmfe_completion_unlock();
  edr_command_audit_both(command_id, "pmfe completion queue full; terminal result remains in command inbox");
}

static cJSON *pmfe_region_json(const char *command_id, EdrPmfeRegionResult *r,
                              cJSON *artifacts, int *upload_failed) {
  cJSON *item = cJSON_CreateObject();
  if (!item || !r) return item;
  char base[32];
  char allocation_base[32];
  snprintf(base, sizeof(base), "0x%llx", (unsigned long long)r->base);
  snprintf(allocation_base, sizeof(allocation_base), "0x%llx",
           (unsigned long long)r->allocation_base);
  cJSON_AddStringToObject(item, "base", base);
  cJSON_AddStringToObject(item, "allocation_base", allocation_base);
  cJSON_AddNumberToObject(item, "size_bytes", (double)r->size_bytes);
  cJSON_AddNumberToObject(item, "bytes_sampled", (double)r->bytes_sampled);
  cJSON_AddStringToObject(item, "protection", r->protection_name);
  cJSON_AddStringToObject(item, "allocation_protection",
                          r->allocation_protection_name);
  cJSON_AddStringToObject(item, "kind", r->kind);
  if (r->mapped_path[0]) {
    cJSON_AddStringToObject(item, "mapped_path", r->mapped_path);
  }
  cJSON_AddNumberToObject(item, "score", r->score);
  cJSON_AddNumberToObject(item, "entropy", r->entropy);
  cJSON_AddStringToObject(item, "reason", r->reason);
  cJSON_AddStringToObject(item, "sha256", r->sha256);
  cJSON_AddBoolToObject(item, "read_ok", r->read_ok ? 1 : 0);
  if (r->pe_arch[0]) {
    cJSON *pe = cJSON_AddObjectToObject(item, "pe");
    cJSON_AddStringToObject(pe, "arch", r->pe_arch);
    cJSON_AddNumberToObject(pe, "sections", r->pe_sections);
    cJSON_AddNumberToObject(pe, "timestamp", r->pe_timestamp);
    cJSON_AddNumberToObject(pe, "entrypoint_rva", r->pe_entrypoint_rva);
    if (r->entrypoint_preview_hex[0]) {
      cJSON_AddStringToObject(pe, "entrypoint_preview_hex",
                              r->entrypoint_preview_hex);
    }
  }
  cJSON *thread_starts = cJSON_AddArrayToObject(item, "thread_starts");
  for (uint8_t i = 0; i < r->thread_start_count &&
                          i < EDR_PMFE_MAX_THREAD_STARTS; i++) {
    cJSON *thread_start = cJSON_CreateObject();
    char start_address[32];
    snprintf(start_address, sizeof(start_address), "0x%llx",
             (unsigned long long)r->thread_starts[i].start_address);
    cJSON_AddNumberToObject(thread_start, "tid", r->thread_starts[i].tid);
    cJSON_AddStringToObject(thread_start, "start_address", start_address);
    cJSON_AddItemToArray(thread_starts, thread_start);
  }
  cJSON *yara = cJSON_AddArrayToObject(item, "yara_hits");
  for (uint8_t i = 0; i < r->yara_hit_count && i < EDR_PMFE_MAX_YARA_HITS; i++) {
    cJSON_AddItemToArray(yara, cJSON_CreateString(r->yara_hits[i]));
  }
  if (r->artifact_path[0]) {
    char object_key[1024];
    object_key[0] = '\0';
    int upload_rc = edr_transport_v2_upload_file(command_id, r->artifact_path,
                                                   r->sha256, object_key,
                                                   sizeof(object_key));
    if (upload_rc != 0 && upload_failed) *upload_failed = 1;
    cJSON *evidence = cJSON_AddObjectToObject(item, "evidence");
    cJSON_AddStringToObject(evidence, "local_path", r->artifact_path);
    cJSON_AddStringToObject(evidence, "object_key", object_key);
    cJSON_AddStringToObject(evidence, "sha256", r->sha256);
    cJSON_AddStringToObject(evidence, "upload_status", upload_rc == 0 ? "ok" : "failed");
    if (artifacts) {
      cJSON *artifact = cJSON_CreateObject();
      cJSON_AddStringToObject(artifact, "type", "pmfe_region");
      cJSON_AddStringToObject(artifact, "path", r->artifact_path);
      cJSON_AddStringToObject(artifact, "sha256", r->sha256);
      cJSON_AddStringToObject(artifact, "object_key", object_key);
      cJSON_AddStringToObject(artifact, "upload_status", upload_rc == 0 ? "ok" : "failed");
      cJSON_AddItemToArray(artifacts, artifact);
    }
    if (upload_rc == 0) {
      (void)remove(r->artifact_path);
      r->artifact_path[0] = '\0';
    }
  }
  if (r->reconstruction_status[0]) {
    cJSON *reconstruction = cJSON_AddObjectToObject(item, "reconstruction");
    cJSON_AddStringToObject(reconstruction, "status", r->reconstruction_status);
    cJSON_AddStringToObject(reconstruction, "sha256", r->reconstructed_sha256);
    if (r->reconstructed_path[0]) {
      char object_key[1024];
      object_key[0] = '\0';
      int upload_rc = edr_transport_v2_upload_file(
          command_id, r->reconstructed_path, r->reconstructed_sha256,
          object_key, sizeof(object_key));
      if (upload_rc != 0 && upload_failed) *upload_failed = 1;
      cJSON_AddStringToObject(reconstruction, "local_path", r->reconstructed_path);
      cJSON_AddStringToObject(reconstruction, "object_key", object_key);
      cJSON_AddStringToObject(reconstruction, "upload_status",
                              upload_rc == 0 ? "ok" : "failed");
      if (artifacts) {
        cJSON *artifact = cJSON_CreateObject();
        cJSON_AddStringToObject(artifact, "type", "pmfe_reconstructed_pe");
        cJSON_AddStringToObject(artifact, "path", r->reconstructed_path);
        cJSON_AddStringToObject(artifact, "sha256", r->reconstructed_sha256);
        cJSON_AddStringToObject(artifact, "object_key", object_key);
        cJSON_AddStringToObject(artifact, "upload_status",
                                upload_rc == 0 ? "ok" : "failed");
        cJSON_AddItemToArray(artifacts, artifact);
      }
      if (upload_rc == 0) {
        (void)remove(r->reconstructed_path);
        r->reconstructed_path[0] = '\0';
      }
    }
  }
  return item;
}

static void pmfe_mark_upload_partial(PmfeCompletion *completion, cJSON *root) {
  if (!completion || !root) return;
  snprintf(completion->result.status, sizeof(completion->result.status), "%s", "partial");
  cJSON_DeleteItemFromObjectCaseSensitive(root, "status");
  cJSON_AddStringToObject(root, "status", "partial");
  if (!cJSON_GetObjectItemCaseSensitive(root, "artifact_upload_failed")) {
    cJSON_AddBoolToObject(root, "artifact_upload_failed", 1);
    cJSON *warnings = cJSON_GetObjectItemCaseSensitive(root, "warnings");
    if (!cJSON_IsArray(warnings)) warnings = cJSON_AddArrayToObject(root, "warnings");
    cJSON_AddItemToArray(warnings, cJSON_CreateString("one or more PMFE evidence artifacts failed to upload"));
  }
}

static char *pmfe_completion_result_json(PmfeCompletion *completion) {
  if (!completion) return NULL;
  EdrPmfeScanResult *r = &completion->result;
  cJSON *root = cJSON_CreateObject();
  if (!root) return NULL;
  cJSON_AddStringToObject(root, "schema", EDR_PMFE_RESULT_SCHEMA);
  cJSON_AddStringToObject(root, "status", r->status[0] ? r->status :
                         (completion->scan_status == 0 ? "completed_clean" : "failed"));
  cJSON_AddStringToObject(root, "verdict", r->verdict[0] ? r->verdict : "inconclusive");
  cJSON_AddStringToObject(root, "task_id", completion->command_id);
  cJSON *target = cJSON_AddObjectToObject(root, "target");
  cJSON_AddNumberToObject(target, "pid", completion->pid);
  cJSON_AddStringToObject(target, "path", r->image_path);
  cJSON *scan = cJSON_AddObjectToObject(root, "scan");
  cJSON_AddNumberToObject(scan, "started_unix_ms", (double)r->started_unix_ms);
  cJSON_AddNumberToObject(scan, "finished_unix_ms", (double)r->finished_unix_ms);
  cJSON_AddNumberToObject(scan, "duration_ms", (double)r->duration_ms);
  cJSON_AddNumberToObject(scan, "regions_total", r->regions_total);
  cJSON_AddNumberToObject(scan, "regions_read", r->regions_read);
  cJSON_AddNumberToObject(scan, "read_failures", r->read_failures);
  cJSON_AddNumberToObject(scan, "threads_total", r->threads_total);
  cJSON_AddNumberToObject(scan, "thread_start_matches", r->thread_start_matches);
  cJSON_AddNumberToObject(scan, "thread_query_failures", r->thread_query_failures);
  cJSON_AddNumberToObject(scan, "bytes_sampled", (double)r->bytes_sampled);
  cJSON_AddBoolToObject(scan, "truncated", r->truncated ? 1 : 0);
  cJSON *signals = cJSON_AddObjectToObject(root, "signals");
  cJSON_AddNumberToObject(signals, "stomp_suspicious", r->stomp_suspicious);
  cJSON_AddNumberToObject(signals, "mz_hits", r->mz_hits);
  cJSON_AddNumberToObject(signals, "dns_hits", r->dns_hits);
  cJSON_AddNumberToObject(signals, "dns_best", r->dns_best);
  cJSON_AddStringToObject(signals, "dns_sample", r->dns_sample);
  cJSON_AddStringToObject(signals, "dns_owner", r->dns_owner);
  cJSON_AddNumberToObject(signals, "ave_max_score", r->ave_max_score);
  cJSON_AddNumberToObject(signals, "entropy_max", r->entropy_max);
  cJSON_AddNumberToObject(signals, "regions_scanned", r->regions_total);
  cJSON_AddNumberToObject(signals, "private_exec", r->private_exec);
  cJSON_AddNumberToObject(signals, "memfd_exec", r->memfd_exec);
  cJSON_AddNumberToObject(signals, "deleted_exec", r->deleted_exec);
  cJSON_AddStringToObject(signals, "module_consistency", r->module_consistency);
  cJSON *correlation = cJSON_AddObjectToObject(root, "correlation");
  cJSON *cross_process_write = cJSON_AddObjectToObject(
      correlation, "cross_process_write");
  cJSON_AddStringToObject(cross_process_write, "status",
                          r->cross_process_write_status[0]
                              ? r->cross_process_write_status
                              : "not_observed");
  cJSON_AddStringToObject(
      cross_process_write, "explanation",
      "No source-to-target memory write telemetry was available for this scan");
  cJSON *injection = cJSON_AddObjectToObject(correlation, "injection_signal");
  cJSON_AddBoolToObject(injection, "observed", r->injection_observed ? 1 : 0);
  if (r->injection_observed) {
    char event_time_ns[32];
    snprintf(event_time_ns, sizeof(event_time_ns), "%lld",
             (long long)r->injection_event_time_ns);
    cJSON_AddStringToObject(injection, "event_time_ns", event_time_ns);
    cJSON_AddNumberToObject(injection, "age_ms", (double)r->injection_age_ms);
    cJSON_AddStringToObject(injection, "technique", r->injection_technique);
    cJSON_AddStringToObject(injection, "source", r->injection_source);
    cJSON_AddStringToObject(
        injection, "scope",
        "process_level_correlation_not_region_writer_attribution");
  }
  cJSON *artifacts = cJSON_AddArrayToObject(root, "artifacts");
  cJSON *regions = cJSON_AddArrayToObject(root, "regions");
  int upload_failed = 0;
  for (uint8_t i = 0; i < r->region_count && i < EDR_PMFE_MAX_REGIONS; i++) {
    cJSON_AddItemToArray(regions, pmfe_region_json(completion->command_id, &r->regions[i], artifacts,
                                                   &upload_failed));
  }
  if (upload_failed) pmfe_mark_upload_partial(completion, root);
  if (r->warning[0]) {
    cJSON *warnings = cJSON_AddArrayToObject(root, "warnings");
    cJSON_AddItemToArray(warnings, cJSON_CreateString(r->warning));
  }
  cJSON_AddStringToObject(root, "raw_detail", completion->detail);

  char result_path[1024];
  command_artifact_path(completion->command_id, "pmfe_result", "json",
                        result_path, sizeof(result_path));
  char *file_json = cJSON_PrintUnformatted(root);
  if (file_json) {
    FILE *fp = fopen(result_path, "wb");
    if (fp && fwrite(file_json, 1, strlen(file_json), fp) == strlen(file_json)) {
      fclose(fp);
      char sha[65];
      char object_key[1024];
      sha[0] = '\0';
      object_key[0] = '\0';
      int hash_rc = file_sha256_hex(result_path, sha);
      int upload_rc = hash_rc == 0
                          ? edr_transport_v2_upload_file(completion->command_id, result_path, sha,
                                                         object_key, sizeof(object_key))
                          : -1;
      if (upload_rc != 0) upload_failed = 1;
      cJSON *evidence = cJSON_AddObjectToObject(root, "evidence");
      cJSON_AddStringToObject(evidence, "object_key", object_key);
      cJSON_AddStringToObject(evidence, "sha256", sha);
      cJSON_AddStringToObject(evidence, "content_type", "application/json");
      cJSON_AddStringToObject(evidence, "upload_status", upload_rc == 0 ? "ok" : "failed");
      cJSON *artifact = cJSON_CreateObject();
      cJSON_AddStringToObject(artifact, "type", "pmfe_result");
      cJSON_AddStringToObject(artifact, "path", result_path);
      cJSON_AddStringToObject(artifact, "sha256", sha);
      cJSON_AddStringToObject(artifact, "object_key", object_key);
      cJSON_AddStringToObject(artifact, "upload_status", upload_rc == 0 ? "ok" : "failed");
      cJSON_AddItemToArray(artifacts, artifact);
      if (upload_rc == 0) (void)remove(result_path);
    } else if (fp) {
      fclose(fp);
      upload_failed = 1;
    } else {
      upload_failed = 1;
    }
    cJSON_free(file_json);
  } else {
    upload_failed = 1;
  }
  if (upload_failed) pmfe_mark_upload_partial(completion, root);
  char *out = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  return out;
}

static void drain_pmfe_completions(void) {
  for (;;) {
    PmfeCompletion completion;
    int found = 0;
    pmfe_completion_lock();
    for (size_t i = 0; i < PMFE_COMPLETION_CAP; i++) {
      if (!s_pmfe_completions[i].used) {
        continue;
      }
      completion = s_pmfe_completions[i];
      memset(&s_pmfe_completions[i], 0, sizeof(s_pmfe_completions[i]));
      found = 1;
      break;
    }
    pmfe_completion_unlock();
    if (!found) {
      return;
    }
    EdrSoarCommandMeta sm;
    memset(&sm, 0, sizeof(sm));
    snprintf(sm.soar_correlation_id, sizeof(sm.soar_correlation_id), "%s",
             completion.context.soar_correlation_id);
    snprintf(sm.playbook_run_id, sizeof(sm.playbook_run_id), "%s",
             completion.context.playbook_run_id);
    snprintf(sm.playbook_step_id, sizeof(sm.playbook_step_id), "%s",
             completion.context.playbook_step_id);
    char *result = pmfe_completion_result_json(&completion);
    if (!result) {
      result = (char *)malloc(1600u);
      if (result) {
        snprintf(result, 1600u, "pmfe_scan %s pid=%u detail=%s",
                 completion.scan_status == 0 ? "completed" : "failed",
                 completion.pid, completion.detail);
      }
    }
    if (completion.scan_status == 0) {
      s_exec_ok++;
      edr_command_emit_always_typed_status(
          completion.command_id, "pmfe_scan", &sm, EdrCmdExecOk, 0,
          result ? result : completion.detail,
          strcmp(completion.result.status, "partial") == 0 ? "partial_success" : "ok");
    } else {
      s_exec_fail++;
      edr_command_emit_always_typed(completion.command_id, "pmfe_scan", &sm,
                                    EdrCmdExecFailed, 8,
                                    result ? result : completion.detail);
    }
    cJSON_free(result);
  }
}

static void command_delivery_run_once(void) {
  static int64_t last_poll_ms;
  drain_pmfe_completions();
  int64_t now = command_now_ms();
  int pressure = edr_resource_preprocess_throttle_active() ? 1 : 0;
  uint32_t poll_ms = command_u32_env_clamped("EDR_COMMAND_DELIVERY_POLL_MS", 5000u, 1000u, 600000u);
  if (edr_shell_session_active_count() > 0u && poll_ms > 200u) {
    poll_ms = 200u;
  }
  if (last_poll_ms > 0 && now - last_poll_ms < (int64_t)poll_ms) {
    return;
  }
  last_poll_ms = now;
  uint64_t total_start = command_monotonic_ms();
  delivery_health_lock();
  s_delivery_health.poll_count++;
  s_delivery_health.last_poll_unix_ms = now;
  delivery_health_unlock();
  edr_ingest_http_retry_pending_control_acks();
  uint64_t step_start = command_monotonic_ms();
  flush_upload_outbox();
  uint32_t upload_ms = command_elapsed_ms_u32(step_start);
  delivery_health_lock();
  s_delivery_health.last_upload_ms = upload_ms;
  command_update_max_u32(upload_ms, &s_delivery_health.max_upload_ms);
  delivery_health_unlock();
  edr_command_executor_wake();
  uint32_t result_ms = 0u;
  if (s_result_outbox_next_flush_ms <= 0 || now >= s_result_outbox_next_flush_ms) {
    step_start = command_monotonic_ms();
    flush_command_result_outbox();
    result_ms = command_elapsed_ms_u32(step_start);
    if (pressure) {
      uint32_t next_ms = command_u32_env_clamped("EDR_COMMAND_RESULT_PRESSURE_INTERVAL_MS",
                                                 5000u, 1000u, 60000u);
      if (result_ms >=
          command_u32_env_clamped("EDR_COMMAND_DELIVERY_SLOW_MS", 750u, 100u, 60000u)) {
        next_ms = command_u32_env_clamped("EDR_COMMAND_RESULT_SLOW_BACKOFF_MS",
                                          300000u, next_ms, 1800000u);
      }
      s_result_outbox_next_flush_ms = now + (int64_t)next_ms;
    } else {
      s_result_outbox_next_flush_ms = 0;
    }
  }
  delivery_health_lock();
  s_delivery_health.last_result_ms = result_ms;
  command_update_max_u32(result_ms, &s_delivery_health.max_result_ms);
  delivery_health_unlock();
  uint32_t compact_ms = 0u;
  if (!pressure && (s_compact_next_allowed_ms <= 0 || now >= s_compact_next_allowed_ms)) {
    step_start = command_monotonic_ms();
    edr_command_state_compact_if_needed();
    compact_ms = command_elapsed_ms_u32(step_start);
    if (compact_ms >=
        command_u32_env_clamped("EDR_COMMAND_DELIVERY_SLOW_MS", 750u, 100u, 60000u)) {
      uint32_t next_ms = command_u32_env_clamped("EDR_COMMAND_COMPACT_SLOW_BACKOFF_MS",
                                                600000u, 60000u, 3600000u);
      s_compact_next_allowed_ms = now + (int64_t)next_ms;
    }
  }
  uint32_t total_ms = command_elapsed_ms_u32(total_start);
  delivery_health_lock();
  s_delivery_health.last_compact_ms = compact_ms;
  command_update_max_u32(compact_ms, &s_delivery_health.max_compact_ms);
  s_delivery_health.last_total_ms = total_ms;
  command_update_max_u32(total_ms, &s_delivery_health.max_total_ms);
  delivery_health_unlock();
}

enum {
  COMMAND_DELIVERY_STOPPED = 0,
  COMMAND_DELIVERY_RUNNING = 1,
  COMMAND_DELIVERY_STOPPING = 2
};

#ifdef _WIN32
static HANDLE s_delivery_thread;
static SRWLOCK s_delivery_thread_mu = SRWLOCK_INIT;
static LONG s_delivery_thread_state;
static volatile LONG s_delivery_thread_stop;
static volatile LONG s_delivery_thread_exited;

static DWORD WINAPI command_delivery_thread_main(LPVOID unused) {
  (void)unused;
  while (InterlockedCompareExchange(&s_delivery_thread_stop, 0, 0) == 0) {
    command_delivery_run_once();
    Sleep(1000u);
  }
  InterlockedExchange(&s_delivery_thread_exited, 1);
  return 0;
}

static void command_delivery_thread_start(void) {
  AcquireSRWLockExclusive(&s_delivery_thread_mu);
  if (s_delivery_thread_state != COMMAND_DELIVERY_STOPPED) {
    ReleaseSRWLockExclusive(&s_delivery_thread_mu);
    return;
  }
  InterlockedExchange(&s_delivery_thread_stop, 0);
  InterlockedExchange(&s_delivery_thread_exited, 0);
  HANDLE thread = CreateThread(NULL, 0u, command_delivery_thread_main, NULL, 0u, NULL);
  if (thread) {
    s_delivery_thread = thread;
    s_delivery_thread_state = COMMAND_DELIVERY_RUNNING;
  }
  ReleaseSRWLockExclusive(&s_delivery_thread_mu);
}
#else
static pthread_t s_delivery_thread;
static pthread_mutex_t s_delivery_thread_mu = PTHREAD_MUTEX_INITIALIZER;
static int s_delivery_thread_state;
static int s_delivery_thread_stop;
static int s_delivery_thread_exited;

static void *command_delivery_thread_main(void *unused) {
  (void)unused;
  for (;;) {
    pthread_mutex_lock(&s_delivery_thread_mu);
    int stop = s_delivery_thread_stop;
    pthread_mutex_unlock(&s_delivery_thread_mu);
    if (stop) break;
    command_delivery_run_once();
    usleep(1000000u);
  }
  pthread_mutex_lock(&s_delivery_thread_mu);
  s_delivery_thread_exited = 1;
  pthread_mutex_unlock(&s_delivery_thread_mu);
  return NULL;
}

static void command_delivery_thread_start(void) {
  pthread_mutex_lock(&s_delivery_thread_mu);
  if (s_delivery_thread_state != COMMAND_DELIVERY_STOPPED) {
    pthread_mutex_unlock(&s_delivery_thread_mu);
    return;
  }
  s_delivery_thread_stop = 0;
  s_delivery_thread_exited = 0;
  if (pthread_create(&s_delivery_thread, NULL, command_delivery_thread_main, NULL) == 0) {
    s_delivery_thread_state = COMMAND_DELIVERY_RUNNING;
  }
  pthread_mutex_unlock(&s_delivery_thread_mu);
}
#endif

void edr_command_poll_reliable_delivery(void) {
  command_delivery_thread_start();
}

int edr_command_delivery_shutdown_timeout(uint32_t timeout_ms) {
  edr_ingest_http_cancel_inflight();
#ifdef _WIN32
  AcquireSRWLockExclusive(&s_delivery_thread_mu);
  if (s_delivery_thread_state == COMMAND_DELIVERY_STOPPED) {
    ReleaseSRWLockExclusive(&s_delivery_thread_mu);
    return 1;
  }
  if (s_delivery_thread_state == COMMAND_DELIVERY_RUNNING) {
    s_delivery_thread_state = COMMAND_DELIVERY_STOPPING;
  }
  InterlockedExchange(&s_delivery_thread_stop, 1);
  HANDLE thread = s_delivery_thread;
  ReleaseSRWLockExclusive(&s_delivery_thread_mu);
  DWORD wait_rc = thread ? WaitForSingleObject(thread, (DWORD)timeout_ms) : WAIT_OBJECT_0;
  AcquireSRWLockExclusive(&s_delivery_thread_mu);
  if (wait_rc == WAIT_OBJECT_0) {
    if (thread) CloseHandle(thread);
    s_delivery_thread = NULL;
    s_delivery_thread_state = COMMAND_DELIVERY_STOPPED;
  }
  ReleaseSRWLockExclusive(&s_delivery_thread_mu);
  if (wait_rc != WAIT_OBJECT_0) {
    audit_both("command_delivery", "delivery thread did not stop after transport cancellation");
    return 0;
  }
  return 1;
#else
  pthread_mutex_lock(&s_delivery_thread_mu);
  if (s_delivery_thread_state == COMMAND_DELIVERY_STOPPED) {
    pthread_mutex_unlock(&s_delivery_thread_mu);
    return 1;
  }
  if (s_delivery_thread_state == COMMAND_DELIVERY_RUNNING) {
    s_delivery_thread_state = COMMAND_DELIVERY_STOPPING;
  }
  s_delivery_thread_stop = 1;
  pthread_t thread = s_delivery_thread;
  pthread_mutex_unlock(&s_delivery_thread_mu);

  uint32_t waited_ms = 0u;
  for (;;) {
    pthread_mutex_lock(&s_delivery_thread_mu);
    int exited = s_delivery_thread_exited;
    pthread_mutex_unlock(&s_delivery_thread_mu);
    if (exited) break;
    if (waited_ms >= timeout_ms) {
      audit_both("command_delivery", "delivery thread did not stop after transport cancellation");
      return 0;
    }
    uint32_t step_ms = timeout_ms - waited_ms;
    if (step_ms > 10u) step_ms = 10u;
    usleep((useconds_t)step_ms * 1000u);
    waited_ms += step_ms;
  }
  int join_rc = pthread_join(thread, NULL);
  pthread_mutex_lock(&s_delivery_thread_mu);
  s_delivery_thread_state = join_rc == 0 ? COMMAND_DELIVERY_STOPPED : COMMAND_DELIVERY_RUNNING;
  pthread_mutex_unlock(&s_delivery_thread_mu);
  if (join_rc != 0) {
    audit_both("command_delivery", "delivery thread join failed after transport cancellation");
    return 0;
  }
  return 1;
#endif
}

void edr_command_delivery_shutdown(void) {
  (void)edr_command_delivery_shutdown_timeout(10000u);
}

void edr_command_get_delivery_health(EdrCommandDeliveryHealth *out_health) {
  if (!out_health) {
    return;
  }
  delivery_health_lock();
  *out_health = s_delivery_health;
  out_health->upload_fail_streak = s_upload_outbox_fail_streak;
  out_health->upload_next_retry_unix_ms = s_upload_outbox_next_retry_ms;
  delivery_health_unlock();
  EdrCommandStateQuarantineStats quarantine;
  memset(&quarantine, 0, sizeof(quarantine));
  edr_command_state_get_quarantine_stats(&quarantine);
  out_health->inbox_quarantined = quarantine.inbox_record_count;
  out_health->ack_quarantined = quarantine.ack_record_count;
  out_health->quarantine_move_failed = quarantine.move_failure_count;
  out_health->last_quarantine_unix_ms = quarantine.last_quarantine_unix_ms;
  snprintf(out_health->last_quarantine_kind, sizeof(out_health->last_quarantine_kind), "%s",
           quarantine.last_record_kind);
  snprintf(out_health->last_quarantine_reason, sizeof(out_health->last_quarantine_reason), "%s",
           quarantine.last_reason);
}

static int command_receive_envelope_impl(const char *command_id, const char *command_type,
                                         const uint8_t *payload, size_t payload_len,
                                         const EdrSoarCommandMeta *soar_meta,
                                         int internal_trusted) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const char *t = command_type ? command_type : "";
  const char *id = command_id ? command_id : "";
  command_set_active_type_owned(t);

  char sig_reason[160];
  sig_reason[0] = 0;
  if (!command_signature_verify(id, t, payload, payload_len, sm, internal_trusted,
                                sig_reason, sizeof(sig_reason))) {
    s_rejected++;
    audit_both(id, sig_reason[0] ? sig_reason : "command signature rejected");
    soar_emit(id, sm, EdrCmdExecRejected, 15, sig_reason[0] ? sig_reason : "command signature rejected");
    return 0;
  }

  EdrSoarCommandMeta normalized_meta = *sm;
  if (normalized_meta.issued_at_unix_ms <= 0) {
    normalized_meta.issued_at_unix_ms = command_now_ms();
  }
  if (normalized_meta.deadline_ms == 0u) {
    normalized_meta.deadline_ms = edr_command_registry_default_timeout_s(t) * 1000u;
  }
  sm = &normalized_meta;

  char deadline_reason[180];
  deadline_reason[0] = '\0';
  if (command_deadline_expired(sm, deadline_reason, sizeof(deadline_reason))) {
    s_rejected++;
    audit_both(id, deadline_reason);
    soar_emit_ex(id, sm, EdrCmdExecFailed, 16, deadline_reason, "timeout", NULL);
    return 0;
  }

  char contract_reason[192];
  contract_reason[0] = '\0';
  if (!edr_command_contract_validate(t, payload, payload_len,
                                     contract_reason, sizeof(contract_reason))) {
    const EdrCommandDescriptor *descriptor = edr_command_registry_lookup(t);
    s_rejected++;
    audit_both(id, contract_reason[0] ? contract_reason : "command payload contract rejected");
    soar_emit(id, sm, descriptor ? EdrCmdExecRejected : EdrCmdExecUnknownType,
              descriptor ? 19 : 1,
              contract_reason[0] ? contract_reason : "command payload contract rejected");
    return 0;
  }

  if (!edr_command_executor_admit(t)) {
    audit_both(id, "command durable queue full; receipt deferred");
    return -1;
  }

  int inbox_store_rc = edr_command_state_store_inbox(id, t, payload, payload_len, sm);
  edr_command_executor_release_admission();
  if (inbox_store_rc != 0) {
    s_exec_fail++;
    audit_both(id, "command inbox persist failed; command not acked");
    soar_emit_ex(id, sm, EdrCmdExecFailed, 18,
                 "command inbox persist failed before received ack", "failed", NULL);
    return -1;
  }

  int retry_count = 0;
  EdrCommandStateRecord dup;
  int dup_rc = edr_command_state_begin(id, t, sm, &retry_count, &dup);
  (void)retry_count;
  if (dup_rc == EDR_COMMAND_STATE_BEGIN_DUP_FINAL) {
    edr_command_state_delete_inbox(id);
    char detail[2600];
    if (streq(t, "shell_open")) {
      snprintf(detail, sizeof(detail),
               "duplicate shell_open suppressed; live shell session was not reopened (previous_status=%s previous_exit=%d)",
               dup.response_status[0] ? dup.response_status : "unknown", dup.exit_code);
      audit_both(id, "duplicate shell_open suppressed by local idempotency state");
      soar_emit_ex(id, sm, EdrCmdExecFailed, 17, detail, "failed", NULL);
      return 0;
    }
    snprintf(detail, sizeof(detail), "duplicate command suppressed previous_status=%s previous_exit=%d previous_detail=%s",
             dup.response_status[0] ? dup.response_status : "unknown", dup.exit_code,
             dup.detail[0] ? dup.detail : "");
    audit_both(id, "duplicate command suppressed by local idempotency state");
    soar_emit_ex(id, sm, (EdrCommandExecutionStatus)(dup.execution_status ? dup.execution_status : EdrCmdExecOk),
                 dup.exit_code, detail, dup.response_status[0] ? dup.response_status : "ok", NULL);
    return 0;
  }
  if (dup_rc == EDR_COMMAND_STATE_BEGIN_DUP_RUNNING) {
    char detail[320];
    snprintf(detail, sizeof(detail), "duplicate command already running; command_id=%s type=%s retry=%d",
             dup.command_id[0] ? dup.command_id : id, dup.command_type[0] ? dup.command_type : t,
             retry_count);
    audit_both(id, detail);
    return 0;
  }
  if (dup_rc != EDR_COMMAND_STATE_BEGIN_READY) {
    s_exec_fail++;
    audit_both(id, "command queued-state persist failed; command not acked");
    return -1;
  }
  return 1;
}

int edr_command_receive_envelope(const char *command_id, const char *command_type,
                                 const uint8_t *payload, size_t payload_len,
                                 const EdrSoarCommandMeta *soar_meta) {
  return command_receive_envelope_impl(command_id, command_type, payload, payload_len,
                                       soar_meta, 0);
}

void edr_command_execute_received_envelope(const char *command_id, const char *command_type,
                                           const uint8_t *payload, size_t payload_len,
                                           const EdrSoarCommandMeta *soar_meta) {
  EdrSoarCommandMeta empty;
  memset(&empty, 0, sizeof(empty));
  const EdrSoarCommandMeta *sm = soar_meta ? soar_meta : &empty;
  const EdrCommandDescriptor *descriptor = edr_command_registry_lookup(command_type);
  const char *t = descriptor ? descriptor->canonical_type : "";
  const char *id = command_id ? command_id : "";
  command_set_active_type_owned(t);

  if (!descriptor) {
    fprintf(stderr, "[command] unknown type id=%s type=%s\n", id,
            command_type ? command_type : "");
    s_unknown++;
    soar_emit(id, sm, EdrCmdExecUnknownType, 1, "unknown command_type");
    return;
  }

  switch (descriptor->kind) {
    case EDR_COMMAND_KIND_NOOP:
      fprintf(stderr, "[command] ok id=%s type=%s\n", id, t);
      s_handled++;
      soar_emit(id, sm, EdrCmdExecOk, 0, t);
      return;
    case EDR_COMMAND_KIND_ECHO:
      fprintf(stderr, "[command] echo id=%s len=%zu\n", id, payload_len);
      if (payload && payload_len > 0u && payload_len < 4096u) {
        fwrite(payload, 1, payload_len, stderr);
        fputc('\n', stderr);
      }
      s_handled++;
      soar_emit(id, sm, EdrCmdExecOk, 0, "echo");
      return;
    case EDR_COMMAND_KIND_TELEMETRY_PROFILE_UPDATE:
      do_telemetry_profile_update(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_ISOLATE_HOST:
      do_isolate(id, sm);
      return;
    case EDR_COMMAND_KIND_RESTORE_HOST:
      do_restore_host(id, sm);
      return;
    case EDR_COMMAND_KIND_ISOLATE_STATUS:
      do_isolate_status(id, sm);
      return;
    case EDR_COMMAND_KIND_KILL_PROCESS:
      do_kill(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_COLLECT_FORENSIC:
      edr_response_collect_forensic(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_FORENSIC:
      do_forensic(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_MEMORY_DUMP:
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        edr_command_audit_both(id, "reject memory_dump: operator-only(人工下发) gate");
        edr_command_emit_always(id, sm, EdrCmdExecRejected, 8,
                                "forensic requires operator-initiated dispatch");
        return;
      }
      edr_response_memory_dump(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_TARGETED_FORENSIC:
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        edr_command_audit_both(id, "reject targeted_forensic: operator-only(人工下发) gate");
        edr_command_emit_always(id, sm, EdrCmdExecRejected, 8,
                                "forensic requires operator-initiated dispatch");
        return;
      }
      edr_response_targeted_forensic(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_YARA_SCAN:
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        edr_command_audit_both(id, "reject yara_scan: operator-only(人工下发) gate");
        edr_command_emit_always(id, sm, EdrCmdExecRejected, 8,
                                "forensic requires operator-initiated dispatch");
        return;
      }
      edr_response_yara_scan(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_FORENSIC_CANCEL: {
      char target[96];
      target[0] = '\0';
      (void)parse_json_string_field(payload, payload_len, "target_cmd_id", target, sizeof(target));
      EdrCommandStateRecord target_state;
      memset(&target_state, 0, sizeof(target_state));
      int state_rc = target[0]
                         ? edr_command_state_request_cancel(target, &target_state)
                         : EDR_COMMAND_STATE_CANCEL_NOT_FOUND;
      int active_hit = target[0] ? edr_command_cancel_request(target) : 0;
      int forensic_hit = edr_response_forensic_async_cancel(target[0] ? target : NULL);

      if (state_rc == EDR_COMMAND_STATE_CANCEL_REQUESTED &&
          strcmp(target_state.response_status, "queued") == 0 && !active_hit && !forensic_hit) {
        EdrSoarCommandMeta target_meta;
        memset(&target_meta, 0, sizeof(target_meta));
        snprintf(target_meta.idempotency_key, sizeof(target_meta.idempotency_key), "%s",
                 target_state.idempotency_key);
        snprintf(target_meta.soar_correlation_id, sizeof(target_meta.soar_correlation_id), "%s",
                 target_state.soar_correlation_id);
        snprintf(target_meta.playbook_run_id, sizeof(target_meta.playbook_run_id), "%s",
                 target_state.playbook_run_id);
        snprintf(target_meta.playbook_step_id, sizeof(target_meta.playbook_step_id), "%s",
                 target_state.playbook_step_id);
        edr_command_emit_always_typed_status(
            target, target_state.command_type, &target_meta, EdrCmdExecFailed, 130,
            "command cancelled before execution", "cancelled");
      }
      char detail[384];
      snprintf(detail, sizeof(detail),
               "cancel target=%s state=%d active=%d forensic=%d mode=%d",
               target[0] ? target : "current_forensic", state_rc, active_hit, forensic_hit,
               target_state.command_type[0]
                   ? (int)edr_command_registry_cancel_mode(target_state.command_type)
                   : (int)EDR_COMMAND_CANCEL_HARD);
      if (state_rc == EDR_COMMAND_STATE_CANCEL_ERROR) {
        edr_cmd_inc_exec_fail();
        edr_command_emit_always(id, sm, EdrCmdExecFailed, 5,
                                "cancel request could not be durably recorded");
      } else if (state_rc == EDR_COMMAND_STATE_CANCEL_REQUESTED || active_hit || forensic_hit) {
        edr_cmd_inc_handled();
        edr_cmd_inc_exec_ok();
        edr_command_emit_always(id, sm, EdrCmdExecOk, 0, detail);
      } else {
        edr_cmd_inc_exec_fail();
        edr_command_emit_always(id, sm, EdrCmdExecFailed, 4,
                                target[0] ? "cancel target not found or already final"
                                          : "no active forensic task to cancel");
      }
      return;
    }
    case EDR_COMMAND_KIND_DEEP_FORENSIC:
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        edr_command_audit_both(id, "reject deep_forensic: operator-only(人工下发) gate");
        edr_command_emit_always(id, sm, EdrCmdExecRejected, 8,
                                "forensic requires operator-initiated dispatch");
        return;
      }
      edr_response_deep_forensic(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_PUT_FILE:
      edr_response_put_file(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_RTQ_EXECUTE:
      edr_response_rtq_execute(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_RTQ_QUERY:
      do_rtq_query(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_PROCESS_TREE:
      do_rtr_process_tree(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_LIST_CONNECTIONS:
      do_rtr_list_connections(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_LIST_MODULES:
      do_list_modules(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_PROCESS_SNAPSHOT:
      do_host_process_tree(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_LIST_AUTORUNS:
      do_list_autoruns(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_VELO_QUERY:
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        edr_command_audit_both(id, "reject velo_query: operator-only(人工下发) gate");
        edr_command_emit_always(id, sm, EdrCmdExecRejected, 8,
                                "velo_query requires operator-initiated dispatch");
        return;
      }
      do_velo_query(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_FILE_STAT:
      do_file_stat(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_GET_FILE:
      do_rtr_get_file(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_REMOVE_FILE:
      do_rtr_rm_file(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_EVENTLOG_VIEW:
      do_eventlog_view(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_REGISTRY_QUERY:
      do_registry_query(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_QUARANTINE_FILE:
      do_quarantine_file(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_RESTORE_FILE:
      do_unquarantine_file(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_PMFE_SCAN:
      do_pmfe_scan(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_SHELL_OPEN:
      do_shell_open(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_SHELL_INPUT:
      do_shell_input(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_SHELL_CLOSE:
      do_shell_close(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_RTR_SHELL:
      do_rtr_shell(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_AVE_STATUS:
      do_ave_status(id, sm);
      return;
    case EDR_COMMAND_KIND_AVE_FINGERPRINT:
      do_ave_fingerprint(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_AVE_INFER:
      do_ave_infer(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_SELF_PROTECT_STATUS:
      do_self_protect_status(id, sm);
      return;
    case EDR_COMMAND_KIND_UPDATE_SERVER_ADDRESS:
      do_update_server_address(id, payload, payload_len, sm);
      return;
    case EDR_COMMAND_KIND_AGENT_UPDATE: {
      char detail[1024];
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        s_rejected++;
        soar_emit_ex(id, sm, EdrCmdExecRejected, 8,
                     "agent_update requires operator-initiated dispatch", "denied", NULL);
        return;
      }
      int update_rc = edr_agent_update_execute(id, payload, payload_len, detail, sizeof(detail));
      if (update_rc == EDR_AGENT_UPDATE_EXIT_LAUNCHED) {
        s_handled++;
        audit_both(id, detail);
        /* Deliberately nonterminal: the durable inbox is retained. The restarted
         * Agent consumes the updater journal and only then persists/emits the
         * succeeded, failed, or rolled-back terminal result. */
        return;
      }
      s_exec_fail++;
      soar_emit_ex(id, sm,
                   update_rc == EDR_AGENT_UPDATE_EXIT_UNSUPPORTED ? EdrCmdExecRejected : EdrCmdExecFailed,
                   update_rc, detail, update_rc == EDR_AGENT_UPDATE_EXIT_UNSUPPORTED ? "unsupported" : "failed", NULL);
      return;
    }
    case EDR_COMMAND_KIND_AGENT_RESTART_SERVICE:
    case EDR_COMMAND_KIND_AGENT_OFFBOARD:
    case EDR_COMMAND_KIND_AGENT_UNINSTALL: {
      char detail[1024];
      if (!forensic_operator_gate(sm, payload, payload_len)) {
        s_rejected++;
        soar_emit_ex(id, sm, EdrCmdExecRejected, 8,
                     "endpoint lifecycle command requires operator-initiated dispatch",
                     "denied", NULL);
        return;
      }
      int lifecycle_rc = edr_agent_lifecycle_execute(id, payload, payload_len,
                                                       detail, sizeof(detail));
      if (lifecycle_rc == EDR_AGENT_LIFECYCLE_EXIT_LAUNCHED) {
        s_handled++;
        audit_both(id, detail);
        return;
      }
      if (lifecycle_rc == EDR_AGENT_LIFECYCLE_EXIT_HANDOFF) {
        s_handled++;
        s_exec_ok++;
        audit_both(id, detail);
        soar_emit_ex(id, sm, EdrCmdExecOk, 0, detail, "ok", NULL);
        return;
      }
      s_exec_fail++;
      soar_emit_ex(id, sm,
                   lifecycle_rc == EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED
                       ? EdrCmdExecRejected : EdrCmdExecFailed,
                   lifecycle_rc, detail,
                   lifecycle_rc == EDR_AGENT_LIFECYCLE_EXIT_UNSUPPORTED
                       ? "unsupported" : "failed",
                   NULL);
      return;
    }
    case EDR_COMMAND_KIND_ATTACK_SURFACE: {
      char detail[384];
      int r = edr_attack_surface_execute(id, payload, payload_len,
                                         edr_command_get_config(), detail, sizeof(detail));
      if (r != 0) {
        s_exec_fail++;
        audit_both(id, "GET_ATTACK_SURFACE: failed");
        soar_emit(id, sm, EdrCmdExecFailed, r, detail[0] ? detail : "attack_surface_failed");
      } else {
        s_handled++;
        s_exec_ok++;
        audit_both(id, "GET_ATTACK_SURFACE: ok");
        soar_emit(id, sm, EdrCmdExecOk, 0, detail[0] ? detail : "attack_surface_ok");
      }
      return;
    }
    case EDR_COMMAND_KIND_UNKNOWN:
    default:
      fprintf(stderr, "[command] registry dispatch missing id=%s type=%s\n", id, t);
      s_unknown++;
      soar_emit(id, sm, EdrCmdExecUnknownType, 1, "command registry dispatch missing");
      return;
  }
}

void edr_command_execute_persisted_envelope(const char *command_id, const char *command_type,
                                            const uint8_t *payload, size_t payload_len,
                                            const EdrSoarCommandMeta *soar_meta) {
  edr_command_execute_received_envelope(command_id, command_type, payload, payload_len, soar_meta);
}

void edr_command_on_envelope(const char *command_id, const char *command_type, const uint8_t *payload,
                             size_t payload_len, const EdrSoarCommandMeta *soar_meta) {
  int receive_rc = edr_command_receive_envelope(command_id, command_type, payload, payload_len, soar_meta);
  if (receive_rc <= 0) {
    return;
  }
  edr_command_executor_wake();
}

void edr_command_on_internal_envelope(const char *command_id, const char *command_type,
                                      const uint8_t *payload, size_t payload_len,
                                      const EdrSoarCommandMeta *soar_meta) {
  if (!command_id || strncmp(command_id, "auto-", 5u) != 0) {
    audit_both(command_id, "trusted internal command rejected: command_id must use auto- prefix");
    return;
  }
  EdrSoarCommandMeta internal_meta;
  memset(&internal_meta, 0, sizeof(internal_meta));
  if (soar_meta) {
    internal_meta = *soar_meta;
  }
  snprintf(internal_meta.initiated_by, sizeof(internal_meta.initiated_by), "%s", "agent_auto");
  int receive_rc = command_receive_envelope_impl(command_id, command_type, payload, payload_len,
                                                  &internal_meta, 1);
  if (receive_rc > 0) {
    edr_command_executor_wake();
  }
}

unsigned long edr_command_handled_count(void) { return s_handled; }

unsigned long edr_command_unknown_count(void) { return s_unknown; }

unsigned long edr_command_rejected_count(void) { return s_rejected; }

unsigned long edr_command_exec_ok_count(void) { return s_exec_ok; }

unsigned long edr_command_exec_fail_count(void) { return s_exec_fail; }
