/**
 * MPMC 队列 + 单消费线程 + PID 状态；入队与停机标记使用短临界区同步。
 * 行为分数由本地启发式计算，关停先排空已接收事件。
 */

#include "ave_behavior_pipeline.h"

#include "edr/ave_behavior_features.h"
#include "edr/ave_behavior_gates.h"
#include "edr/ingest_http.h"
#include "edr/pid_history.h"
#include "edr/resource.h"

#include "ave_lf_mpmc.h"
#include "edr/config.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#ifdef _WIN32
typedef volatile LONG64 EdrBpMetric64;
static void bp_metric_store(EdrBpMetric64 *p, uint64_t v) { (void)InterlockedExchange64(p, (LONG64)v); }
static uint64_t bp_metric_inc(EdrBpMetric64 *p) { return (uint64_t)InterlockedIncrement64(p); }
static uint64_t bp_metric_load(EdrBpMetric64 *p) { return (uint64_t)InterlockedCompareExchange64(p, 0, 0); }
#else
typedef volatile uint64_t EdrBpMetric64;
static void bp_metric_store(EdrBpMetric64 *p, uint64_t v) { __atomic_store_n(p, v, __ATOMIC_RELAXED); }
static uint64_t bp_metric_inc(EdrBpMetric64 *p) { return __atomic_add_fetch(p, 1u, __ATOMIC_RELAXED); }
static uint64_t bp_metric_load(EdrBpMetric64 *p) { return __atomic_load_n(p, __ATOMIC_RELAXED); }
#endif

static EdrBpMetric64 s_bp_feed_total;
static EdrBpMetric64 s_bp_queue_enqueued;
static EdrBpMetric64 s_bp_queue_full_fallback;
static EdrBpMetric64 s_bp_queue_full_dropped;
static EdrBpMetric64 s_bp_feed_sync_bypass;
static EdrBpMetric64 s_bp_worker_dequeued;
static EdrBpMetric64 s_bp_pressure_feed_dropped;

/* `pid:<id>` is already the pipeline's explicit no-name sentinel.  Preserve
 * that state when a path basename cannot be represented rather than emitting
 * a partial name as if it were complete. */
static void bp_copy_path_basename_or_pid(char *out, size_t out_cap, const char *path,
                                         size_t path_cap, uint32_t pid) {
  char fallback[16];
  size_t base = 0u;
  size_t length = 0u;
  if (!out || out_cap == 0u) {
    return;
  }
  out[0] = '\0';
  if (path && path_cap > 0u) {
    while (length < path_cap && path[length]) {
      if (path[length] == '/' || path[length] == '\\') {
        base = length + 1u;
      }
      length++;
    }
    if (length < path_cap && length > base && length - base < out_cap) {
      memcpy(out, path + base, length - base);
      out[length - base] = '\0';
      return;
    }
  }
  {
    int written = snprintf(fallback, sizeof(fallback), "pid:%u", (unsigned)pid);
    if (written > 0 && (size_t)written < out_cap) {
      memcpy(out, fallback, (size_t)written + 1u);
    }
  }
}

static void bp_reset_metrics(void) {
  bp_metric_store(&s_bp_feed_total, 0u);
  bp_metric_store(&s_bp_queue_enqueued, 0u);
  bp_metric_store(&s_bp_queue_full_fallback, 0u);
  bp_metric_store(&s_bp_queue_full_dropped, 0u);
  bp_metric_store(&s_bp_feed_sync_bypass, 0u);
  bp_metric_store(&s_bp_worker_dequeued, 0u);
  bp_metric_store(&s_bp_pressure_feed_dropped, 0u);
}

static int bp_str_has_ci(const char *hay, const char *needle);

static void json_escape_copy(const char *src, char *dst, size_t cap) {
  if (!dst || cap == 0u) {
    return;
  }
  size_t j = 0u;
  if (!src) {
    dst[0] = '\0';
    return;
  }
  for (size_t i = 0u; src[i] && j + 1u < cap; i++) {
    unsigned char c = (unsigned char)src[i];
    if ((c == '"' || c == '\\') && j + 2u < cap) {
      dst[j++] = '\\';
      dst[j++] = (char)c;
    } else if (c == '\n' && j + 2u < cap) {
      dst[j++] = '\\';
      dst[j++] = 'n';
    } else if (c == '\r' && j + 2u < cap) {
      dst[j++] = '\\';
      dst[j++] = 'r';
    } else if (c == '\t' && j + 2u < cap) {
      dst[j++] = '\\';
      dst[j++] = 't';
    } else if (c >= 0x20u) {
      dst[j++] = (char)c;
    }
  }
  dst[j] = '\0';
}


static void ave_fill_related_iocs_json(AVEBehaviorAlert *al, const char *remote_ip, const char *remote_domain,
                                       const char *file_sha256, uint8_t ioc_ip_hit, uint8_t ioc_domain_hit,
                                       uint8_t ioc_sha256_hit) {
  if (!al) {
    return;
  }
  al->related_iocs_json[0] = '\0';
  char ip[64], domain[300], sha[80];
  json_escape_copy(remote_ip, ip, sizeof(ip));
  json_escape_copy(remote_domain, domain, sizeof(domain));
  json_escape_copy(file_sha256, sha, sizeof(sha));
  int first = 1;
  size_t off = 0u;
  int n = snprintf(al->related_iocs_json, sizeof(al->related_iocs_json), "[");
  if (n < 0) {
    al->related_iocs_json[0] = '\0';
    return;
  }
  off = (size_t)n;
#define APPEND_IOC(kind, value)                                                                  \
  do {                                                                                            \
    if ((value)[0] && off + 64u < sizeof(al->related_iocs_json)) {                                 \
      n = snprintf(al->related_iocs_json + off, sizeof(al->related_iocs_json) - off,               \
                   "%s{\"type\":\"%s\",\"value\":\"%s\",\"source\":\"endpoint_ioc\"}", \
                   first ? "" : ",", (kind), (value));                                            \
      if (n > 0) {                                                                                 \
        off += (size_t)n;                                                                          \
        first = 0;                                                                                 \
      }                                                                                            \
    }                                                                                              \
  } while (0)
  if (ioc_ip_hit) APPEND_IOC("ip", ip);
  if (ioc_domain_hit) APPEND_IOC("domain", domain);
  if (ioc_sha256_hit) APPEND_IOC("sha256", sha);
#undef APPEND_IOC
  if (first) {
    al->related_iocs_json[0] = '\0';
    return;
  }
  if (off + 2u < sizeof(al->related_iocs_json)) {
    snprintf(al->related_iocs_json + off, sizeof(al->related_iocs_json) - off, "]");
  } else {
    al->related_iocs_json[0] = '\0';
  }
}

static void ave_fill_detection_context(AVEBehaviorAlert *al, AVEEventType event_type, uint32_t parent_pid,
                                       const char *cmdline, const char *target_path, const char *file_sha256, const char *remote_ip,
                                       const char *remote_domain, uint16_t remote_port, float shellcode_score,
                                       float webshell_score, float pmfe_confidence, float pmfe_dns_tunnel,
                                       uint8_t pmfe_pe_found, uint8_t ioc_ip_hit, uint8_t ioc_domain_hit,
                                       uint8_t ioc_sha256_hit, float script_content_score, float tls_anomaly_score,
                                       float ransom_counter_score, uint8_t script_block_present,
                                       uint8_t amsi_content_present, uint8_t ja3_anomaly, uint8_t sni_anomaly,
                                       uint8_t cert_anomaly, uint8_t suspicious_extension_burst,
                                       uint8_t shadow_copy_delete) {
  if (!al) {
    return;
  }
  const char *engine = "ave";
  const char *rule_id = "behavior_anomaly";
  const char *forensics = "[\"process_tree\",\"timeline_window\",\"targeted_files\",\"pmfe_scan\"]";
  if (event_type == AVE_EVT_PMFE_RESULT) {
    engine = "pmfe";
    rule_id = "pmfe_signal";
  } else if (event_type == AVE_EVT_SHELLCODE_SIGNAL) {
    engine = "shellcode";
    rule_id = "shellcode_signal";
    forensics = "[\"process_tree\",\"timeline_window\",\"pmfe_scan\",\"single_process_minidump_if_needed\"]";
  } else if (event_type == AVE_EVT_WEBSHELL_SIGNAL) {
    engine = "webshell";
    rule_id = "webshell_signal";
    forensics = "[\"timeline_window\",\"targeted_files\",\"process_tree\"]";
  }

  char proc_name[256], proc_path[512], cmdline_esc[1024], target_path_esc[512], file_sha_esc[80], remote_ip_esc[64], remote_domain_esc[300];
  char policy_ver[64], policy_esc[96];
  json_escape_copy(al->process_name, proc_name, sizeof(proc_name));
  json_escape_copy(al->process_path, proc_path, sizeof(proc_path));
  json_escape_copy(cmdline, cmdline_esc, sizeof(cmdline_esc));
  json_escape_copy(target_path, target_path_esc, sizeof(target_path_esc));
  json_escape_copy(file_sha256, file_sha_esc, sizeof(file_sha_esc));
  json_escape_copy(remote_ip, remote_ip_esc, sizeof(remote_ip_esc));
  json_escape_copy(remote_domain, remote_domain_esc, sizeof(remote_domain_esc));
  edr_ingest_http_copy_policy_version(policy_ver, sizeof(policy_ver));
  json_escape_copy(policy_ver, policy_esc, sizeof(policy_esc));

  char network[512] = "";
  if (remote_ip_esc[0] || remote_domain_esc[0] || remote_port != 0u) {
    snprintf(network, sizeof(network),
             ",\"network\":{\"remote_ip\":\"%s\",\"remote_url\":\"%s\",\"dst_port\":%u}",
             remote_ip_esc, remote_domain_esc, (unsigned)remote_port);
  }
  char file[720] = "";
  if (target_path_esc[0] || file_sha_esc[0]) {
    snprintf(file, sizeof(file),
             ",\"file\":{\"path\":\"%s\",\"sha256\":\"%s\",\"signed\":false,"
             "\"signature_status\":\"unknown\"}",
             target_path_esc, file_sha_esc);
  }
  char policy[180] = "";
  if (policy_esc[0]) {
    snprintf(policy, sizeof(policy), ",\"policy_version\":\"%s\"", policy_esc);
  }

  snprintf(al->user_subject_json, sizeof(al->user_subject_json),
           "{\"subject_type\":\"detection_context\",\"detection_context\":{\"engine\":\"%s\","
           "\"rule_id\":\"%s\",\"confidence\":%.3f,\"process\":{\"pid\":%u,\"name\":\"%s\","
           "\"path\":\"%s\",\"parent_pid\":%u,\"cmdline\":\"%s\"}%s%s%s,"
           "\"engine_signals\":{\"shellcode_score\":%.3f,\"webshell_score\":%.3f,"
           "\"pmfe_confidence\":%.3f,\"pmfe_dns_tunnel\":%.3f,\"pmfe_pe_found\":%s,"
           "\"script_content_score\":%.3f,\"tls_anomaly_score\":%.3f,\"ransom_counter_score\":%.3f,"
           "\"script_block_present\":%s,\"amsi_content_present\":%s,\"ja3_anomaly\":%s,"
           "\"sni_anomaly\":%s,\"cert_anomaly\":%s,\"suspicious_extension_burst\":%s,"
           "\"shadow_copy_delete\":%s,\"ioc_ip_hit\":%s,\"ioc_domain_hit\":%s,\"ioc_sha256_hit\":%s},"
           "\"suppression\":{\"applied\":false,\"policy_version\":\"%s\"},"
           "\"recommended_forensics\":%s}}",
           engine, rule_id, (double)al->anomaly_score, (unsigned)al->pid, proc_name, proc_path,
           (unsigned)parent_pid, cmdline_esc, file, network, policy, (double)shellcode_score, (double)webshell_score,
           (double)pmfe_confidence, (double)pmfe_dns_tunnel, pmfe_pe_found ? "true" : "false",
           (double)script_content_score, (double)tls_anomaly_score, (double)ransom_counter_score,
           script_block_present ? "true" : "false", amsi_content_present ? "true" : "false",
           ja3_anomaly ? "true" : "false", sni_anomaly ? "true" : "false", cert_anomaly ? "true" : "false",
           suspicious_extension_burst ? "true" : "false", shadow_copy_delete ? "true" : "false",
           ioc_ip_hit ? "true" : "false", ioc_domain_hit ? "true" : "false", ioc_sha256_hit ? "true" : "false",
           policy_esc, forensics);
}

static int bp_str_eq_ci(const char *a, const char *b) {
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

static int bp_path_has_ransom_ext(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  const char *exts[] = {".locked", ".lockbit", ".encrypted", ".crypt", ".crypted", ".conti", ".ryuk",
                        ".blackcat", ".akira", ".8base", ".mallox", ".medusa", NULL};
  const char *base = path;
  const char *dot = NULL;
  for (const char *p = path; *p; ++p) {
    if (*p == '\\' || *p == '/') {
      base = p + 1;
      dot = NULL;
    } else if (*p == '.') {
      dot = p;
    }
  }
  if (!dot || dot == base || dot[1] == '\0') {
    return 0;
  }
  for (const char **p = exts; *p; ++p) {
    if (bp_str_eq_ci(dot, *p)) {
      return 1;
    }
  }
  return 0;
}

static float bp_ransom_counter_score(const EdrPidHistory *sl, const AVEBehaviorEvent *e) {
  float s = e ? e->ransom_counter_score : 0.f;
  if (!sl || !e) {
    return s;
  }
  if (e->event_type == AVE_EVT_FILE_WRITE) {
    if (sl->file_write_count >= 200u) s += 0.40f;
    else if (sl->file_write_count >= 80u) s += 0.25f;
    else if (sl->file_write_count >= 30u) s += 0.12f;
    if (bp_path_has_ransom_ext(e->target_path)) s += 0.18f;
  }
  if ((e->behavior_flags & AVE_BEH_SHADOW_COPY_DELETE) || e->shadow_copy_delete) {
    s += 0.25f;
  }
  if (s > 1.f) s = 1.f;
  return s;
}

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#define AVE_BP_RING_CAP_DEFAULT 1024u
#define AVE_BP_RING_CAP_MAX 4096u
#define AVE_BP_RING_CAP_MIN 64u
#define AVE_BP_PID_SLOTS 512u
#define AVE_BP_ALERT_THRESH EDR_AVE_BEH_SCORE_HIGH
#define AVE_BP_ALERT_COOLDOWN_NS (10LL * 1000000000LL)
#define AVE_BP_TS_BUF 128u
#define AVE_BP_IP_SLOTS 8u

static EdrPidHistory *s_hist;
static uint32_t s_hist_capacity;

static AVECallbacks s_callbacks;
static int s_callbacks_set;

static AveMpmcQueue *s_q;
static uint32_t s_q_capacity;

#ifdef _WIN32
static SRWLOCK s_mu = SRWLOCK_INIT;
static HANDLE s_thread;
static SRWLOCK s_feed_mu = SRWLOCK_INIT;
static void lock_feed(void) { AcquireSRWLockExclusive(&s_feed_mu); }
static void unlock_feed(void) { ReleaseSRWLockExclusive(&s_feed_mu); }
#else
static pthread_mutex_t s_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_thread;
static pthread_mutex_t s_feed_mu = PTHREAD_MUTEX_INITIALIZER;
static void lock_feed(void) { pthread_mutex_lock(&s_feed_mu); }
static void unlock_feed(void) { pthread_mutex_unlock(&s_feed_mu); }
#endif

static atomic_int s_worker_stop;
static atomic_int s_monitor_started;
static atomic_int s_worker_exited = 1;

static int bp_hist_ensure(void) {
  if (s_hist) {
    return 0;
  }
  s_hist = (EdrPidHistory *)calloc((size_t)AVE_BP_PID_SLOTS, sizeof(*s_hist));
  if (!s_hist) {
    s_hist_capacity = 0u;
    return -1;
  }
  s_hist_capacity = AVE_BP_PID_SLOTS;
  return 0;
}

static void bp_hist_free(void) {
  free(s_hist);
  s_hist = NULL;
  s_hist_capacity = 0u;
}

static uint32_t bp_queue_capacity_from_env(void) {
  const char *e = getenv("EDR_AVE_BP_QUEUE_CAP");
  uint32_t cap = AVE_BP_RING_CAP_DEFAULT;
  if (e && e[0]) {
    char *end = NULL;
    unsigned long v = strtoul(e, &end, 10);
    if (end && *end == '\0' && v >= AVE_BP_RING_CAP_MIN && v <= AVE_BP_RING_CAP_MAX) {
      cap = (uint32_t)v;
    }
  }
  if (cap < AVE_BP_RING_CAP_MIN) {
    cap = AVE_BP_RING_CAP_MIN;
  }
  if (cap > AVE_BP_RING_CAP_MAX) {
    cap = AVE_BP_RING_CAP_MAX;
  }
  uint32_t pow2 = AVE_BP_RING_CAP_MIN;
  while (pow2 < cap && pow2 < AVE_BP_RING_CAP_MAX) {
    pow2 <<= 1u;
  }
  return pow2;
}

static void lock_bp(void) {
#ifdef _WIN32
  AcquireSRWLockExclusive(&s_mu);
#else
  (void)pthread_mutex_lock(&s_mu);
#endif
}

static void unlock_bp(void) {
#ifdef _WIN32
  ReleaseSRWLockExclusive(&s_mu);
#else
  (void)pthread_mutex_unlock(&s_mu);
#endif
}

static int64_t wall_ns(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  const uint64_t epoch_100ns = 116444736000000000ULL;
  if (u.QuadPart < epoch_100ns) {
    return 0;
  }
  return (int64_t)((u.QuadPart - epoch_100ns) * 100ULL);
#else
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) {
    return 0;
  }
  return (int64_t)tv.tv_sec * 1000000000LL + (int64_t)tv.tv_usec * 1000LL;
#endif
}

void edr_ave_bp_configure_resource_limits(const struct EdrConfig *cfg) {
  /* The public hook remains so remote policy reloads stay ABI compatible.
   * Model-inference budgets were retired with endpoint ONNX execution. */
  (void)cfg;
}

static int bp_pressure_active(void) {
  return edr_resource_preprocess_throttle_active() ? 1 : 0;
}

static int bp_event_high_value_under_pressure(const AVEBehaviorEvent *event) {
  if (!event) {
    return 0;
  }
  if (event->severity_hint >= 128u || event->behavior_flags != 0u) {
    return 1;
  }
  if (event->event_type == AVE_EVT_PROCESS_INJECT ||
      event->event_type == AVE_EVT_MEM_ALLOC_EXEC ||
      event->event_type == AVE_EVT_LSASS_ACCESS ||
      event->event_type == AVE_EVT_SHELLCODE_SIGNAL ||
      event->event_type == AVE_EVT_WEBSHELL_SIGNAL ||
      event->event_type == AVE_EVT_PMFE_RESULT) {
    return 1;
  }
  if (event->script_content_score >= 0.50f || event->tls_anomaly_score >= 0.60f ||
      event->ransom_counter_score >= 0.45f || event->pmfe_confidence >= 0.50f ||
      event->shellcode_score >= 0.50f || event->webshell_score >= 0.50f) {
    return 1;
  }
  return event->script_block_present || event->amsi_content_present ||
         event->ja3_anomaly || event->sni_anomaly || event->cert_anomaly ||
         event->suspicious_extension_burst || event->shadow_copy_delete ||
         event->ioc_ip_hit || event->ioc_domain_hit || event->ioc_sha256_hit;
}

static int popcount_u32(uint32_t x) {
  int n = 0;
  while (x) {
    n++;
    x &= x - 1u;
  }
  return n;
}

static uint32_t bp_hash_str(const char *s) {
  uint32_t h = 5381u;
  while (s && *s) {
    h = ((h << 5) + h) + (unsigned char)*s++;
  }
  return h;
}

static int bp_str_has_ci(const char *hay, const char *needle) {
  if (!hay || !needle) {
    return 0;
  }
  while (*hay) {
    const char *a = hay;
    const char *b = needle;
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
      a++;
      b++;
    }
    if (!*b) {
      return 1;
    }
    hay++;
  }
  return 0;
}

static void bp_ts_push(EdrPidHistory *sl, int64_t now) {
  const int64_t win5 = 300000000000LL;
  while (sl->ts_buf_n > 0u && sl->ts_buf[0] < now - win5) {
    memmove(sl->ts_buf, sl->ts_buf + 1, (sl->ts_buf_n - 1u) * sizeof(int64_t));
    sl->ts_buf_n--;
  }
  if (sl->ts_buf_n < AVE_BP_TS_BUF) {
    sl->ts_buf[sl->ts_buf_n++] = now;
  } else {
    memmove(sl->ts_buf, sl->ts_buf + 1, (AVE_BP_TS_BUF - 1u) * sizeof(int64_t));
    sl->ts_buf[AVE_BP_TS_BUF - 1u] = now;
  }
}

static uint32_t bp_ts_count_since(const EdrPidHistory *sl, int64_t now, int64_t window_ns) {
  uint32_t c = 0u;
  for (uint32_t i = 0u; i < sl->ts_buf_n; i++) {
    if (sl->ts_buf[i] >= now - window_ns) {
      c++;
    }
  }
  return c;
}

static void bp_ip_add(EdrPidHistory *sl, const char *ip) {
  if (!ip || !ip[0]) {
    return;
  }
  uint32_t h = bp_hash_str(ip);
  for (uint32_t i = 0u; i < sl->ip_count; i++) {
    if (sl->ip_hashes[i] == h) {
      return;
    }
  }
  if (sl->ip_count < AVE_BP_IP_SLOTS) {
    sl->ip_hashes[sl->ip_count++] = h;
  }
}

static float bp_clamp01f(float x) {
  if (x <= 0.f) {
    return 0.f;
  }
  if (x >= 1.f) {
    return 1.f;
  }
  return x;
}

static void ph_append_feat(EdrPidHistory *ph, const float *f64) {
  size_t cap = (size_t)EDR_PID_HISTORY_MAX_SEQ;
  if (ph->feat_len < cap) {
    memcpy(ph->feat_chrono[ph->feat_len], f64, EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    ph->feat_len++;
  } else {
    memmove(ph->feat_chrono[0], ph->feat_chrono[1], (cap - 1u) * EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    memcpy(ph->feat_chrono[cap - 1u], f64, EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    ph->feat_len = (uint32_t)cap;
  }
}

static void fill_pid_snapshot(const EdrPidHistory *sl, const AVEBehaviorEvent *e, uint32_t ec_prev, int64_t prev_ns_for_gap,
                              int64_t now_ns, uint32_t burst_1s, uint32_t n1, uint32_t n5,
                              EdrAveBehaviorPidSnapshot *out) {
  memset(out, 0, sizeof(*out));
  out->total_events_incl_current = ec_prev + 1u;
  out->file_write_count = sl->file_write_count;
  out->net_connect_count = sl->net_connect_count;
  out->reg_write_count = sl->reg_write_count;
  out->dll_load_count = sl->dll_load_count;
  out->has_injected_memory = sl->sticky_injected ? 1.f : 0.f;
  out->has_accessed_lsass = sl->sticky_lsass ? 1.f : 0.f;
  out->has_loaded_suspicious_dll = sl->sticky_susp_dll ? 1.f : 0.f;
  out->has_ioc_connection = sl->sticky_ioc_conn ? 1.f : 0.f;
  {
    float pd = (float)sl->parent_chain_depth;
    if (pd > 10.f) {
      pd = 10.f;
    }
    out->parent_chain_depth_norm = pd / 10.f;
  }
  out->is_system_account = 0.f;
  if (sl->create_time_ns > 0u) {
    int64_t ct = (int64_t)sl->create_time_ns;
    if (now_ns > ct) {
      double sec = (double)(now_ns - ct) / 1e9;
      out->time_since_birth_norm = bp_clamp01f((float)(sec / 3600.0));
    }
  } else if (sl->first_seen_ns > 0 && now_ns > sl->first_seen_ns) {
    double sec = (double)(now_ns - sl->first_seen_ns) / 1e9;
    out->time_since_birth_norm = bp_clamp01f((float)(sec / 3600.0));
  }
  out->unique_ip_count = (uint32_t)sl->ip_count;
  out->is_high_value_host = sl->pmfe_high_value ? 1.f : 0.f;
  out->prev_event_ns = prev_ns_for_gap;
  out->now_ns = now_ns;
  out->burst_1s_count = burst_1s;
  out->events_last_1min = n1;
  out->events_last_5min = n5;
  out->is_first_event_of_proc = (ec_prev == 0u) ? 1 : 0;
  out->events_after_net_connect = sl->events_after_net_connect;
}

static void build_behavior_features(const AVEBehaviorEvent *e, const EdrAveBehaviorFeatExtra *ex,
                                    const EdrAveBehaviorPidSnapshot *snap, float *feat, size_t n) {
  edr_ave_behavior_encode_m3b(e, ex, snap, feat, n);
}

static int pid_gc_slot_if_expired(uint32_t idx, int64_t now_ns) {
  if (!s_hist || idx >= s_hist_capacity) {
    return 0;
  }
  EdrPidHistory *h = &s_hist[idx];
  if (!h->valid || h->is_active) {
    return 0;
  }
  if (h->exit_ts_ns <= 0) {
    return 0;
  }
  if ((now_ns - h->exit_ts_ns) < 300LL * 1000000000LL) {
    return 0;
  }
  memset(h, 0, sizeof(*h));
  return 1;
}

/** 全表：同 pid 的**唯一**规范槽 — 优先最近 `last_event_ns`（否则 `first_seen_ns`），再比 `event_count`，再比槽下标（确定性）。 */
static int pid_best_existing(uint32_t pid) {
  if (pid == 0u) {
    return -1;
  }
  int bi = -1;
  int64_t best_key = INT64_MIN;
  uint32_t best_ec = 0u;
  if (!s_hist || s_hist_capacity == 0u) {
    return -1;
  }
  for (uint32_t i = 0u; i < s_hist_capacity; i++) {
    if (!s_hist[i].valid || s_hist[i].pid != pid) {
      continue;
    }
    int64_t rk = s_hist[i].last_event_ns > 0 ? s_hist[i].last_event_ns : s_hist[i].first_seen_ns;
    uint32_t ec = s_hist[i].event_count;
    if (bi < 0 || rk > best_key || (rk == best_key && ec > best_ec) ||
        (rk == best_key && ec == best_ec && i < (uint32_t)bi)) {
      best_key = rk;
      best_ec = ec;
      bi = (int)i;
    }
  }
  return bi;
}

/** 清除除 keep 外所有同 pid 槽（严格一对一）。 */
static void pid_drop_duplicate_slots_except(uint32_t pid, int keep) {
  if (pid == 0u || keep < 0) {
    return;
  }
  if (!s_hist || s_hist_capacity == 0u) {
    return;
  }
  for (uint32_t k = 0u; k < s_hist_capacity; k++) {
    if ((int)k == keep) {
      continue;
    }
    if (s_hist[k].valid && s_hist[k].pid == pid) {
      memset(&s_hist[k], 0, sizeof(s_hist[k]));
    }
  }
}

/**
 * 线性探测上的首个空位（供新 pid 插入）；若表中已有该 pid，返回**规范槽**并去重。
 * 探测全程不因首个空槽提前返回，避免与链上后段已占槽语义冲突。
 */
static int pid_find_slot(uint32_t pid) {
  if (pid == 0u || !s_hist || s_hist_capacity == 0u) {
    return -1;
  }
  int64_t now_ns = wall_ns();
  uint32_t start = pid % s_hist_capacity;
  int first_empty = -1;
  for (uint32_t j = 0u; j < s_hist_capacity; j++) {
    uint32_t idx = (start + j) % s_hist_capacity;
    if (!s_hist[idx].valid) {
      if (first_empty < 0) {
        first_empty = (int)idx;
      }
      continue;
    }
    if (pid_gc_slot_if_expired(idx, now_ns)) {
      if (first_empty < 0) {
        first_empty = (int)idx;
      }
      continue;
    }
    /* 槽被其它 pid 占用，沿探测链继续 */
  }
  int best = pid_best_existing(pid);
  if (best >= 0) {
    pid_drop_duplicate_slots_except(pid, best);
    return best;
  }
  return first_empty;
}

static void pid_evict_lru(void) {
  int64_t oldest = INT64_MAX;
  int bi = -1;
  if (!s_hist || s_hist_capacity == 0u) {
    return;
  }
  for (uint32_t i = 0; i < s_hist_capacity; i++) {
    if (!s_hist[i].valid) {
      continue;
    }
    if (!s_hist[i].is_active) {
      continue;
    }
    if (s_hist[i].last_event_ns < oldest) {
      oldest = s_hist[i].last_event_ns;
      bi = (int)i;
    }
  }
  if (bi >= 0) {
    memset(&s_hist[bi], 0, sizeof(s_hist[bi]));
  }
}

/** 《11》§3.2：同 PID 新进程实例（Kernel-Process 创建）→ 重置生命周期字段，保留 pid/valid。 */
static void ph_reset_lifecycle_for_pid_reuse(EdrPidHistory *sl, const AVEBehaviorEvent *e, int64_t now_ns) {
  uint32_t pid_keep = sl->pid;
  uint64_t cts = (e->timestamp_ns > 0) ? (uint64_t)e->timestamp_ns : (uint64_t)now_ns;
  memset(sl, 0, sizeof(*sl));
  sl->pid = pid_keep;
  sl->valid = 1;
  sl->is_active = 1u;
  sl->create_time_ns = cts;
  sl->first_seen_ns = now_ns;
  sl->ppid = e->ppid;
  if (e->ppid != 0u) {
    int pxi = pid_find_slot(e->ppid);
    if (pxi >= 0 && s_hist[pxi].valid && s_hist[pxi].pid == e->ppid) {
      uint32_t pd = s_hist[pxi].parent_chain_depth;
      sl->parent_chain_depth = (pd < 100000u) ? pd + 1u : pd;
    } else {
      sl->parent_chain_depth = 1u;
    }
  }
  if (e->process_path[0]) {
    snprintf(sl->process_path, sizeof(sl->process_path), "%s", e->process_path);
  }
  if (e->process_name[0]) {
    snprintf(sl->process_name, sizeof(sl->process_name), "%s", e->process_name);
  } else if (e->process_path[0]) {
    bp_copy_path_basename_or_pid(sl->process_name, sizeof(sl->process_name), e->process_path,
                                 sizeof(e->process_path), e->pid);
  } else {
    snprintf(sl->process_name, sizeof(sl->process_name), "pid:%u", e->pid);
  }
}

static void process_one_event(const AVEBehaviorEvent *e) {
  int64_t now = e->timestamp_ns > 0 ? e->timestamp_ns : wall_ns();

  lock_bp();
  int si = pid_find_slot(e->pid);
  if (si < 0) {
    pid_evict_lru();
    si = pid_find_slot(e->pid);
    if (si < 0) {
      unlock_bp();
      return;
    }
  }
  EdrPidHistory *sl = &s_hist[si];
  if (sl->valid && e->event_type == AVE_EVT_PROCESS_CREATE && sl->pid == e->pid) {
    ph_reset_lifecycle_for_pid_reuse(sl, e, now);
  }
  if (!sl->valid) {
    memset(sl, 0, sizeof(*sl));
    sl->pid = e->pid;
    sl->valid = 1;
    sl->first_seen_ns = now;
    sl->is_active = 1u;
    sl->create_time_ns = (e->timestamp_ns > 0) ? (uint64_t)e->timestamp_ns : (uint64_t)now;
    if (e->ppid != 0u) {
      int pxi = pid_find_slot(e->ppid);
      if (pxi >= 0 && s_hist[pxi].valid && s_hist[pxi].pid == e->ppid) {
        uint32_t pd = s_hist[pxi].parent_chain_depth;
        sl->parent_chain_depth = (pd < 100000u) ? pd + 1u : pd;
      } else {
        sl->parent_chain_depth = 1u;
      }
    }
    if (e->process_path[0]) {
      snprintf(sl->process_path, sizeof(sl->process_path), "%s", e->process_path);
    }
    if (e->process_name[0]) {
      snprintf(sl->process_name, sizeof(sl->process_name), "%s", e->process_name);
    } else if (e->process_path[0]) {
      bp_copy_path_basename_or_pid(sl->process_name, sizeof(sl->process_name), e->process_path,
                                   sizeof(e->process_path), e->pid);
    } else {
      snprintf(sl->process_name, sizeof(sl->process_name), "pid:%u", e->pid);
    }
  }
  if (e->process_name[0] && strncmp(e->process_name, "pid:", 4) != 0) {
    snprintf(sl->process_name, sizeof(sl->process_name), "%s", e->process_name);
  }
  if (e->process_path[0]) {
    snprintf(sl->process_path, sizeof(sl->process_path), "%s", e->process_path);
  }
  sl->ppid = e->ppid;
  sl->events_since_last_inference++;

  uint32_t ec_prev = sl->event_count;
  int64_t prev_gap_ns = sl->prev_event_ns;

  if (e->event_type == AVE_EVT_NET_CONNECT) {
    sl->last_net_connect_ns = now;
    sl->events_after_net_connect = 0u;
  } else if (sl->last_net_connect_ns != 0) {
    sl->events_after_net_connect++;
  }

  switch (e->event_type) {
  case AVE_EVT_FILE_WRITE:
    sl->file_write_count++;
    break;
  case AVE_EVT_NET_CONNECT:
    sl->net_connect_count++;
    break;
  case AVE_EVT_REG_WRITE:
    sl->reg_write_count++;
    break;
  case AVE_EVT_DLL_LOAD:
    sl->dll_load_count++;
    break;
  default:
    break;
  }

  {
    uint32_t f = e->behavior_flags;
    if (f & (AVE_BEH_ALLOC_EXEC_REMOTE | AVE_BEH_MODULE_STOMP | AVE_BEH_HOLLOW_PROCESS | AVE_BEH_REFLECTIVE_LOAD)) {
      sl->sticky_injected = 1u;
    }
    if (f & (AVE_BEH_INJECT_LSASS | AVE_BEH_LSASS_DUMP)) {
      sl->sticky_lsass = 1u;
    }
    if (e->event_type == AVE_EVT_LSASS_ACCESS) {
      sl->sticky_lsass = 1u;
    }
    if (e->event_type == AVE_EVT_DLL_LOAD && e->target_path[0] &&
        !bp_str_has_ci(e->target_path, "system32") && !bp_str_has_ci(e->target_path, "syswow64")) {
      sl->sticky_susp_dll = 1u;
    }
    if (e->ioc_ip_hit && (e->event_type == AVE_EVT_NET_CONNECT || e->event_type == AVE_EVT_NET_DNS)) {
      sl->sticky_ioc_conn = 1u;
    }
  }
  if (e->pmfe_confidence > 0.75f) {
    sl->pmfe_high_value = 1u;
  }
  {
    float sig_bump = 0.f;
    if (e->script_content_score > 0.65f || e->script_block_present || e->amsi_content_present) {
      sig_bump += 0.06f;
    }
    if (e->tls_anomaly_score > 0.60f || e->ja3_anomaly || e->sni_anomaly || e->cert_anomaly) {
      sig_bump += 0.06f;
    }
    if (bp_ransom_counter_score(sl, e) > 0.55f) {
      sig_bump += 0.10f;
    }
    if (sig_bump > 0.f) {
      sl->anomaly = fminf(1.0f, sl->anomaly + sig_bump);
    }
  }

  if ((e->event_type == AVE_EVT_NET_CONNECT || e->event_type == AVE_EVT_NET_DNS) && e->target_ip[0]) {
    bp_ip_add(sl, e->target_ip);
  }

  bp_ts_push(sl, now);
  uint32_t burst_1s = bp_ts_count_since(sl, now, 1000000000LL);
  uint32_t n1 = bp_ts_count_since(sl, now, 60000000000LL);
  uint32_t n5 = bp_ts_count_since(sl, now, 300000000000LL);

  EdrAveBehaviorPidSnapshot snap;
  fill_pid_snapshot(sl, e, ec_prev, prev_gap_ns, now, burst_1s, n1, n5, &snap);

  EdrAveBehaviorFeatExtra ex;
  memset(&ex, 0, sizeof(ex));
  ex.static_max_conf = fmaxf(sl->ave_static_max_conf, e->ave_confidence);
  ex.static_verdict_norm = (float)sl->ave_verdict / 9.f;
  ex.cert_revoked_ancestor = sl->sticky_cert_revoked_ancestor ? 1.f : 0.f;
  if (e->ppid != 0u) {
    int pxi = pid_find_slot(e->ppid);
    if (pxi >= 0 && s_hist[pxi].valid && s_hist[pxi].pid == e->ppid) {
      ex.parent_static_max_conf = s_hist[pxi].ave_static_max_conf;
    }
  }
  {
    float ssum = 0.f;
    int scnt = 0;
    for (uint32_t k = 0; k < s_hist_capacity; k++) {
      if (!s_hist[k].valid) {
        continue;
      }
      if (s_hist[k].pid == e->pid) {
        continue;
      }
      if (e->ppid != 0u && s_hist[k].ppid == e->ppid) {
        ssum += s_hist[k].anomaly;
        scnt++;
      }
    }
    ex.sibling_anomaly_mean = (scnt > 0) ? (ssum / (float)scnt) : 0.f;
  }

  sl->flags |= e->behavior_flags;
  sl->event_count++;
  sl->last_event_ns = now;
  sl->prev_event_ns = now;

  float vec64[EDR_PID_HISTORY_FEAT_DIM];
  build_behavior_features(e, &ex, &snap, vec64, (size_t)EDR_PID_HISTORY_FEAT_DIM);
  ph_append_feat(sl, vec64);

  float last_tactic_probs[14];
  memset(last_tactic_probs, 0, sizeof(last_tactic_probs));
  {
    float sev = (float)e->severity_hint / 255.0f;
    float bump = sev * 0.12f + (float)popcount_u32(e->behavior_flags) * 0.04f;
    if (e->event_type == AVE_EVT_LSASS_ACCESS || e->event_type == AVE_EVT_MEM_ALLOC_EXEC) {
      bump += 0.08f;
    }
    sl->anomaly = fminf(1.0f, sl->anomaly + bump);
  }

  int fire = 0;
  if (s_callbacks_set && s_callbacks.on_behavior_alert && sl->anomaly >= AVE_BP_ALERT_THRESH &&
      (sl->last_alert_ns == 0 || now - sl->last_alert_ns >= AVE_BP_ALERT_COOLDOWN_NS)) {
    fire = 1;
    sl->last_alert_ns = now;
  }

  float an_copy = sl->anomaly;
  uint32_t fl_copy = sl->flags;
  uint32_t pid_copy = e->pid;
  uint32_t ppid_copy = e->ppid;
  AVEEventType evt_copy = e->event_type;
  AVEBehaviorCallback cb = s_callbacks.on_behavior_alert;
  void *ud = s_callbacks.user_data;
  float tactic_copy[14];
  memcpy(tactic_copy, last_tactic_probs, sizeof(tactic_copy));
  char sl_proc_name[256];
  memcpy(sl_proc_name, sl->process_name, sizeof(sl_proc_name));
  char ev_tgt_path[sizeof(e->target_path)];
  memcpy(ev_tgt_path, e->target_path, sizeof(ev_tgt_path));
  char ev_proc_path[512];
  snprintf(ev_proc_path, sizeof(ev_proc_path), "%s", e->process_path);
  char ev_cmdline[1024];
  snprintf(ev_cmdline, sizeof(ev_cmdline), "%s", e->cmdline);
  char ev_file_sha[80];
  snprintf(ev_file_sha, sizeof(ev_file_sha), "%s", e->file_sha256_hex);
  char ev_tgt_ip[64];
  snprintf(ev_tgt_ip, sizeof(ev_tgt_ip), "%s", e->target_ip);
  char ev_tgt_domain[300];
  snprintf(ev_tgt_domain, sizeof(ev_tgt_domain), "%s", e->target_domain);
  uint16_t ev_tgt_port = e->target_port;
  float ev_shellcode_score = e->shellcode_score;
  float ev_webshell_score = e->webshell_score;
  float ev_pmfe_confidence = e->pmfe_confidence;
  float ev_pmfe_dns_tunnel = e->pmfe_dns_tunnel;
  float ev_script_content_score = e->script_content_score;
  float ev_tls_anomaly_score = e->tls_anomaly_score;
  float ev_ransom_counter_score = bp_ransom_counter_score(sl, e);
  uint8_t ev_pmfe_pe_found = e->pmfe_pe_found;
  uint8_t ev_script_block_present = e->script_block_present;
  uint8_t ev_amsi_content_present = e->amsi_content_present;
  uint8_t ev_ja3_anomaly = e->ja3_anomaly;
  uint8_t ev_sni_anomaly = e->sni_anomaly;
  uint8_t ev_cert_anomaly = (uint8_t)(e->cert_anomaly || e->cert_revoked_ancestor);
  uint8_t ev_suspicious_extension_burst =
      (uint8_t)(e->suspicious_extension_burst || (e->event_type == AVE_EVT_FILE_WRITE && bp_path_has_ransom_ext(e->target_path)));
  uint8_t ev_shadow_copy_delete = (uint8_t)(e->shadow_copy_delete || ((e->behavior_flags & AVE_BEH_SHADOW_COPY_DELETE) != 0u));
  uint8_t ev_ioc_ip_hit = e->ioc_ip_hit;
  uint8_t ev_ioc_domain_hit = e->ioc_domain_hit;
  uint8_t ev_ioc_sha256_hit = e->ioc_sha256_hit;
  unlock_bp();

  if (fire && cb) {
    AVEBehaviorAlert al;
    memset(&al, 0, sizeof(al));
    al.pid = pid_copy;
    al.ppid = ppid_copy;
    snprintf(al.cmdline, sizeof(al.cmdline), "%s", ev_cmdline);
    al.anomaly_score = an_copy;
    memcpy(al.tactic_probs, tactic_copy, sizeof(al.tactic_probs));
    al.triggered_tactics[0] = '\0';
    al.skip_ai_analysis = true;
    al.needs_l2_review = true;
    al.behavior_flags = (AVEBehaviorFlags)fl_copy;
    al.timestamp_ns = now;
    if (sl_proc_name[0] && strncmp(sl_proc_name, "pid:", 4) != 0) {
      snprintf(al.process_name, sizeof(al.process_name), "%s", sl_proc_name);
    } else if (ev_tgt_path[0]) {
      bp_copy_path_basename_or_pid(al.process_name, sizeof(al.process_name), ev_tgt_path,
                                   sizeof(ev_tgt_path), pid_copy);
    } else {
      snprintf(al.process_name, sizeof(al.process_name), "pid:%u", (unsigned)pid_copy);
    }
    if (ev_proc_path[0]) {
      snprintf(al.process_path, sizeof(al.process_path), "%s", ev_proc_path);
    } else if (ev_tgt_path[0] && evt_copy == AVE_EVT_PROCESS_CREATE) {
      memcpy(al.process_path, ev_tgt_path, sizeof(al.process_path));
    }
    /* 可选：与平台 alerts.user_subject_json 对齐的 JSON 真源（调试用/专线注入；生产建议由策略填 AVEBehaviorAlert） */
    {
      const char *ujs = getenv("EDR_BEHAVIOR_USER_SUBJECT_JSON");
      if (ujs && ujs[0] == '{') {
        size_t n = strlen(ujs);
        if (n < sizeof(al.user_subject_json)) {
          memcpy(al.user_subject_json, ujs, n + 1u);
        }
      }
    }
    if (!al.user_subject_json[0]) {
      ave_fill_detection_context(&al, evt_copy, ppid_copy, ev_cmdline, ev_tgt_path, ev_file_sha, ev_tgt_ip, ev_tgt_domain,
                                 ev_tgt_port, ev_shellcode_score, ev_webshell_score, ev_pmfe_confidence,
                                 ev_pmfe_dns_tunnel, ev_pmfe_pe_found, ev_ioc_ip_hit, ev_ioc_domain_hit,
                                 ev_ioc_sha256_hit, ev_script_content_score, ev_tls_anomaly_score,
                                 ev_ransom_counter_score, ev_script_block_present, ev_amsi_content_present,
                                 ev_ja3_anomaly, ev_sni_anomaly, ev_cert_anomaly, ev_suspicious_extension_burst,
                                 ev_shadow_copy_delete);
    }
    if (!al.related_iocs_json[0]) {
      ave_fill_related_iocs_json(&al, ev_tgt_ip, ev_tgt_domain, ev_file_sha, ev_ioc_ip_hit, ev_ioc_domain_hit,
                                 ev_ioc_sha256_hit);
    }
    cb(&al, ud);
  }
}

#ifdef _WIN32
static DWORD WINAPI worker_main(LPVOID arg) {
  (void)arg;
  for (;;) {
    AVEBehaviorEvent ev;
    int drained = 0;
    if (s_q) {
      while (ave_mpmc_try_pop(s_q, &ev) == 0) {
        (void)bp_metric_inc(&s_bp_worker_dequeued);
        process_one_event(&ev);
        drained = 1;
      }
    }
    if (atomic_load(&s_worker_stop) && (!s_q || ave_mpmc_approx_depth(s_q) == 0u)) break;
    if (!drained) {
      Sleep(20);
    }
  }
  atomic_store(&s_worker_exited, 1);
  return 0;
}
#else
static void *worker_main(void *arg) {
  (void)arg;
  for (;;) {
    AVEBehaviorEvent ev;
    int drained = 0;
    if (s_q) {
      while (ave_mpmc_try_pop(s_q, &ev) == 0) {
        (void)bp_metric_inc(&s_bp_worker_dequeued);
        process_one_event(&ev);
        drained = 1;
      }
    }
    if (atomic_load(&s_worker_stop) && (!s_q || ave_mpmc_approx_depth(s_q) == 0u)) break;
    if (!drained) {
      usleep(20000);
    }
  }
  atomic_store(&s_worker_exited, 1);
  return NULL;
}
#endif

void edr_ave_bp_init(void) {
  if (s_q) {
    ave_mpmc_destroy(s_q);
    s_q = NULL;
  }
  s_q_capacity = 0u;
#ifdef _WIN32
  s_thread = NULL;
#endif
  s_worker_stop = 0;
  s_monitor_started = 0;
  atomic_store(&s_worker_exited, 1);
  bp_hist_free();
  memset(&s_callbacks, 0, sizeof(s_callbacks));
  s_callbacks_set = 0;
  bp_reset_metrics();
}

int edr_ave_bp_drain_stop(uint32_t timeout_ms) {
  /* Serialize the last admitted producer with the stop marker. The worker
   * drains everything already admitted before observing the terminal state. */
  lock_feed();
  atomic_store(&s_worker_stop, 1);
  unlock_feed();
  if (!atomic_load(&s_monitor_started)) return AVE_OK;
#ifdef _WIN32
  if (s_thread) {
    if (WaitForSingleObject(s_thread, timeout_ms) != WAIT_OBJECT_0) return AVE_ERR_TIMEOUT;
    CloseHandle(s_thread);
    s_thread = NULL;
  }
#else
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  uint64_t deadline = (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u + timeout_ms;
  while (!atomic_load(&s_worker_exited)) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    if ((uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u >= deadline)
      return AVE_ERR_TIMEOUT;
    struct timespec delay = {0, 1000000L};
    nanosleep(&delay, NULL);
  }
  if (pthread_join(s_thread, NULL) != 0) return AVE_ERR_INTERNAL;
#endif
  atomic_store(&s_monitor_started, 0);
  return AVE_OK;
}

int edr_ave_bp_shutdown(void) {
  if (edr_ave_bp_drain_stop(30000u) != AVE_OK) return 0;
  if (s_q) {
    ave_mpmc_destroy(s_q);
    s_q = NULL;
  }
  edr_ave_bp_init();
  return 1;
}

void edr_ave_bp_set_callbacks(const AVECallbacks *callbacks) {
  if (!callbacks) {
    return;
  }
  lock_bp();
  s_callbacks = *callbacks;
  s_callbacks_set = s_callbacks.on_behavior_alert ? 1 : 0;
  unlock_bp();
}

int edr_ave_bp_start_monitor(const struct EdrConfig *cfg) {
  if (atomic_load(&s_worker_stop)) return AVE_ERR_INTERNAL;
  if (!cfg) {
    return AVE_ERR_INVALID_PARAM;
  }
  edr_ave_bp_configure_resource_limits(cfg);
  if (!cfg->ave.behavior_monitor_enabled) {
    return AVE_OK;
  }
  if (!s_callbacks_set || !s_callbacks.on_behavior_alert) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (bp_hist_ensure() != 0) {
    fprintf(stderr, "[ave/bp] pid history allocation failed\n");
    return AVE_ERR_INTERNAL;
  }
  if (!s_q) {
    const uint32_t cap = bp_queue_capacity_from_env();
    if (ave_mpmc_init(&s_q, cap) != 0) {
      s_q = NULL;
      s_q_capacity = 0u;
      fprintf(stderr, "[ave/bp] MPMC init failed\n");
      return AVE_ERR_INTERNAL;
    }
    s_q_capacity = cap;
  }
  if (s_monitor_started) {
    return AVE_OK;
  }
  s_worker_stop = 0;
  atomic_store(&s_worker_exited, 0);
#ifdef _WIN32
  s_thread = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
  if (!s_thread) {
    return AVE_ERR_INTERNAL;
  }
#else
  if (pthread_create(&s_thread, NULL, worker_main, NULL) != 0) {
    return AVE_ERR_INTERNAL;
  }
#endif
  s_monitor_started = 1;
  return AVE_OK;
}

int edr_ave_bp_feed(const AVEBehaviorEvent *event) {
  if (!event) {
    return AVE_ERR_INVALID_PARAM;
  }
  (void)bp_metric_inc(&s_bp_feed_total);
  lock_feed();
  if (atomic_load(&s_worker_stop)) {
    (void)bp_metric_inc(&s_bp_feed_sync_bypass);
    unlock_feed();
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (s_monitor_started && bp_pressure_active() && !bp_event_high_value_under_pressure(event)) {
    (void)bp_metric_inc(&s_bp_pressure_feed_dropped);
    unlock_feed();
    return AVE_OK; /* Existing resource-pressure policy, not queue admission. */
  }
  if (!s_monitor_started) {
    (void)bp_metric_inc(&s_bp_feed_sync_bypass);
    unlock_feed();
    return AVE_ERR_NOT_INITIALIZED;
  }
  if (s_q) {
    if (ave_mpmc_try_push(s_q, event) != 0) {
      (void)bp_metric_inc(&s_bp_queue_full_dropped);
      unlock_feed();
      return AVE_ERR_QUEUE_FULL;
    } else {
      (void)bp_metric_inc(&s_bp_queue_enqueued);
    }
  } else {
    (void)bp_metric_inc(&s_bp_feed_sync_bypass);
    unlock_feed();
    return AVE_ERR_NOT_INITIALIZED;
  }
  unlock_feed();
  return AVE_OK;
}

int edr_ave_bp_get_flags(uint32_t pid, AVEBehaviorFlags *flags_out) {
  if (!flags_out) {
    return AVE_ERR_INVALID_PARAM;
  }
  *flags_out = 0;
  lock_bp();
  int si = pid_find_slot(pid);
  if (si >= 0 && s_hist[si].valid && s_hist[si].pid == pid) {
    *flags_out = s_hist[si].flags;
  }
  unlock_bp();
  return AVE_OK;
}

int edr_ave_bp_get_score(uint32_t pid, float *score_out) {
  if (!score_out) {
    return AVE_ERR_INVALID_PARAM;
  }
  *score_out = 0.f;
  lock_bp();
  int si = pid_find_slot(pid);
  if (si >= 0 && s_hist[si].valid && s_hist[si].pid == pid) {
    *score_out = s_hist[si].anomaly;
  }
  unlock_bp();
  return AVE_OK;
}

void edr_ave_bp_notify_exit(uint32_t pid) {
  lock_bp();
  int si = pid_find_slot(pid);
  if (si >= 0 && s_hist[si].valid && s_hist[si].pid == pid) {
    s_hist[si].is_active = 0u;
    s_hist[si].exit_ts_ns = wall_ns();
  }
  unlock_bp();
}

void edr_ave_bp_merge_static_scan(uint32_t pid, float max_confidence, int verdict_edr_enum) {
  if (pid == 0u) {
    return;
  }
  if (!s_hist || s_hist_capacity == 0u) {
    return;
  }
  lock_bp();
  int si = pid_find_slot(pid);
  if (si < 0) {
    pid_evict_lru();
    si = pid_find_slot(pid);
  }
  if (si < 0) {
    unlock_bp();
    return;
  }
  EdrPidHistory *sl = &s_hist[si];
  if (!sl->valid) {
    memset(sl, 0, sizeof(*sl));
    sl->pid = pid;
    sl->valid = 1;
    sl->is_active = 1u;
  }
  if (max_confidence > sl->ave_static_max_conf) {
    sl->ave_static_max_conf = max_confidence;
  }
  if (verdict_edr_enum >= 0 && verdict_edr_enum <= 9) {
    sl->ave_verdict = (uint8_t)verdict_edr_enum;
  }
  if (verdict_edr_enum == (int)VERDICT_CERT_REVOKED) {
    sl->sticky_cert_revoked_ancestor = 1u;
  }
  unlock_bp();
}

uint32_t edr_ave_bp_queue_depth(void) {
  if (!s_q) {
    return 0u;
  }
  size_t d = ave_mpmc_approx_depth(s_q);
  return d > 0xffffffffu ? 0xffffffffu : (uint32_t)d;
}

uint32_t edr_ave_bp_queue_capacity(void) { return s_q_capacity; }

void edr_ave_bp_fill_metrics(AVEStatus *status_out) {
  if (!status_out) {
    return;
  }
  uint32_t hist_used = 0u;
  lock_bp();
  if (s_hist && s_hist_capacity > 0u) {
    for (uint32_t i = 0; i < s_hist_capacity; i++) {
      if (s_hist[i].valid) {
        hist_used++;
      }
    }
  }
  unlock_bp();
  status_out->behavior_feed_total = bp_metric_load(&s_bp_feed_total);
  status_out->behavior_queue_enqueued = bp_metric_load(&s_bp_queue_enqueued);
  status_out->behavior_queue_full_sync_fallback = bp_metric_load(&s_bp_queue_full_fallback);
  status_out->behavior_queue_full_dropped = bp_metric_load(&s_bp_queue_full_dropped);
  status_out->behavior_feed_sync_bypass = bp_metric_load(&s_bp_feed_sync_bypass);
  status_out->behavior_worker_dequeued = bp_metric_load(&s_bp_worker_dequeued);
  status_out->behavior_infer_ok = 0u;
  status_out->behavior_infer_fail = 0u;
  status_out->behavior_infer_budget_dropped = 0u;
  status_out->behavior_pressure_feed_dropped = bp_metric_load(&s_bp_pressure_feed_dropped);
  status_out->behavior_pressure_infer_dropped = 0u;
  status_out->behavior_infer_budget_per_min = 0u;
  status_out->behavior_infer_effective_budget_per_min = 0u;
  status_out->behavior_infer_latency_last_ms = 0u;
  status_out->behavior_infer_latency_p95_ms = 0u;
  status_out->behavior_pressure_active = bp_pressure_active() ? 1u : 0u;
  status_out->behavior_queue_capacity = edr_ave_bp_queue_capacity();
  status_out->behavior_pid_history_used = hist_used;
  status_out->behavior_pid_history_capacity = s_hist_capacity;
  status_out->behavior_pid_history_static_bytes =
      s_hist ? (uint64_t)s_hist_capacity * (uint64_t)sizeof(*s_hist) : 0u;
}

int edr_ave_bp_monitor_running(void) { return s_monitor_started ? 1 : 0; }
