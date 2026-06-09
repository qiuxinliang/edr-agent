/**
 * P2：MPMC 无锁入队 + 单消费线程 + PID 状态；behavior.onnx 就绪时以模型分替代启发式 bump。
 */

#include "ave_behavior_pipeline.h"

#include "edr/behavior_alert_emit.h"
#include "edr/ave_behavior_features.h"
#include "edr/ave_behavior_gates.h"
#include "edr/ingest_http.h"
#include "edr/pid_history.h"
#include "edr/resource.h"

#include "ave_lf_mpmc.h"
#include "ave_onnx_infer.h"

#include "edr/config.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/** 《11》§6.1 最大展平元素数；热路径 ORT 输入缓冲（T04） */
#define AVE_BP_ORT_NELEM_MAX (EDR_PID_HISTORY_MAX_SEQ * EDR_PID_HISTORY_FEAT_DIM)

static float s_bp_ort_scratch[AVE_BP_ORT_NELEM_MAX];

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

static EdrBpMetric64 s_bp_beh_infer_ok;
static EdrBpMetric64 s_bp_beh_infer_fail;
static EdrBpMetric64 s_bp_feed_total;
static EdrBpMetric64 s_bp_queue_enqueued;
static EdrBpMetric64 s_bp_queue_full_fallback;
static EdrBpMetric64 s_bp_queue_full_dropped;
static EdrBpMetric64 s_bp_feed_sync_bypass;
static EdrBpMetric64 s_bp_worker_dequeued;
static EdrBpMetric64 s_bp_infer_budget_dropped;
static EdrBpMetric64 s_bp_pressure_feed_dropped;
static EdrBpMetric64 s_bp_pressure_infer_dropped;
static uint32_t s_bp_behavior_infer_per_min;
static uint32_t s_bp_low_priority_keep_percent_under_pressure;
static int64_t s_bp_infer_budget_window_ns;
static uint32_t s_bp_infer_budget_count;
static uint32_t s_bp_infer_latency_ms[64];
static uint32_t s_bp_infer_latency_pos;
static uint32_t s_bp_infer_latency_count;
static uint32_t s_bp_infer_latency_last_ms;

static void bp_reset_metrics(void) {
  bp_metric_store(&s_bp_beh_infer_ok, 0u);
  bp_metric_store(&s_bp_beh_infer_fail, 0u);
  bp_metric_store(&s_bp_feed_total, 0u);
  bp_metric_store(&s_bp_queue_enqueued, 0u);
  bp_metric_store(&s_bp_queue_full_fallback, 0u);
  bp_metric_store(&s_bp_queue_full_dropped, 0u);
  bp_metric_store(&s_bp_feed_sync_bypass, 0u);
  bp_metric_store(&s_bp_worker_dequeued, 0u);
  bp_metric_store(&s_bp_infer_budget_dropped, 0u);
  bp_metric_store(&s_bp_pressure_feed_dropped, 0u);
  bp_metric_store(&s_bp_pressure_infer_dropped, 0u);
  s_bp_infer_budget_window_ns = 0;
  s_bp_infer_budget_count = 0u;
  s_bp_infer_latency_pos = 0u;
  s_bp_infer_latency_count = 0u;
  s_bp_infer_latency_last_ms = 0u;
  memset(s_bp_infer_latency_ms, 0, sizeof(s_bp_infer_latency_ms));
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

static void ave_fill_detection_context(AVEBehaviorAlert *al, AVEEventType event_type, uint32_t parent_pid,
                                       const char *target_path, const char *file_sha256, const char *remote_ip,
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

  char proc_name[256], proc_path[512], target_path_esc[512], file_sha_esc[80], remote_ip_esc[64], remote_domain_esc[300];
  char policy_ver[64], policy_esc[96];
  json_escape_copy(al->process_name, proc_name, sizeof(proc_name));
  json_escape_copy(al->process_path, proc_path, sizeof(proc_path));
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
           "\"path\":\"%s\",\"parent_pid\":%u}%s%s%s,"
           "\"engine_signals\":{\"shellcode_score\":%.3f,\"webshell_score\":%.3f,"
           "\"pmfe_confidence\":%.3f,\"pmfe_dns_tunnel\":%.3f,\"pmfe_pe_found\":%s,"
           "\"script_content_score\":%.3f,\"tls_anomaly_score\":%.3f,\"ransom_counter_score\":%.3f,"
           "\"script_block_present\":%s,\"amsi_content_present\":%s,\"ja3_anomaly\":%s,"
           "\"sni_anomaly\":%s,\"cert_anomaly\":%s,\"suspicious_extension_burst\":%s,"
           "\"shadow_copy_delete\":%s,\"ioc_ip_hit\":%s,\"ioc_domain_hit\":%s,\"ioc_sha256_hit\":%s},"
           "\"suppression\":{\"applied\":false,\"policy_version\":\"%s\"},"
           "\"recommended_forensics\":%s}}",
           engine, rule_id, (double)al->anomaly_score, (unsigned)al->pid, proc_name, proc_path,
           (unsigned)parent_pid, file, network, policy, (double)shellcode_score, (double)webshell_score,
           (double)pmfe_confidence, (double)pmfe_dns_tunnel, pmfe_pe_found ? "true" : "false",
           (double)script_content_score, (double)tls_anomaly_score, (double)ransom_counter_score,
           script_block_present ? "true" : "false", amsi_content_present ? "true" : "false",
           ja3_anomaly ? "true" : "false", sni_anomaly ? "true" : "false", cert_anomaly ? "true" : "false",
           suspicious_extension_burst ? "true" : "false", shadow_copy_delete ? "true" : "false",
           ioc_ip_hit ? "true" : "false", ioc_domain_hit ? "true" : "false", ioc_sha256_hit ? "true" : "false",
           policy_esc, forensics);
}

static int bp_path_has_ransom_ext(const char *path) {
  if (!path || !path[0]) {
    return 0;
  }
  const char *exts[] = {".locked", ".lockbit", ".encrypted", ".crypt", ".crypted", ".conti", ".ryuk",
                        ".blackcat", ".akira", ".8base", ".mallox", ".medusa", NULL};
  for (const char **p = exts; *p; ++p) {
    if (bp_str_has_ci(path, *p)) {
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
    if (bp_path_has_ransom_ext(e->target_path)) s += 0.35f;
  }
  if ((e->behavior_flags & AVE_BEH_SHADOW_COPY_DELETE) || e->shadow_copy_delete) {
    s += 0.35f;
  }
  if (s > 1.f) s = 1.f;
  return s;
}

/**
 * 若设置了 **EDR_AVE_BEH_INFER_MIN_EVENTS**，则仅使用该 legacy 阈值（与旧版「每 N 事件推理」一致），
 * **不**再套用《11》§7.1 的立即触发与 16/8 步长。
 * @return 非 0 表示已设置且写入 *out_min*
 */
static int env_infer_min_events_explicit(uint32_t *out_min) {
  const char *e = getenv("EDR_AVE_BEH_INFER_MIN_EVENTS");
  if (!e || !e[0]) {
    return 0;
  }
  char *end = NULL;
  unsigned long v = strtoul(e, &end, 10);
  if (end == e || v < 1ul) {
    *out_min = 1u;
    return 1;
  }
  if (v > 10000ul) {
    *out_min = 10000u;
    return 1;
  }
  *out_min = (uint32_t)v;
  return 1;
}

/** 《11》§7.1：P0 立即触发 ORT（与 `events_since_last_inference` 无关，阈值取 1） */
static int bp_infer_immediate(const AVEBehaviorEvent *e) {
  if (!e) {
    return 0;
  }
  if (e->event_type == AVE_EVT_PROCESS_INJECT || e->event_type == AVE_EVT_MEM_ALLOC_EXEC ||
      e->event_type == AVE_EVT_LSASS_ACCESS) {
    return 1;
  }
  if (e->event_type == AVE_EVT_SHELLCODE_SIGNAL || e->event_type == AVE_EVT_PMFE_RESULT ||
      e->event_type == AVE_EVT_WEBSHELL_SIGNAL) {
    return 1;
  }
  if (e->ioc_ip_hit || e->ioc_domain_hit) {
    return 1;
  }
  const uint32_t nx = (uint32_t)(AVE_BEH_INJECT_LSASS | AVE_BEH_ALLOC_EXEC_REMOTE | AVE_BEH_MODULE_STOMP |
                                 AVE_BEH_HOLLOW_PROCESS | AVE_BEH_REFLECTIVE_LOAD | AVE_BEH_LSASS_DUMP |
                                 AVE_BEH_NTDS_ACCESS | AVE_BEH_SAM_DUMP | AVE_BEH_DNS_TUNNEL);
  if (e->behavior_flags & nx) {
    return 1;
  }
  return 0;
}

static int env_dynamic_threshold_enabled(void) {
  const char *e = getenv("EDR_AVE_BEH_DYNAMIC_THRESHOLD");
  if (e && (e[0] == '0' || e[0] == 'n' || e[0] == 'N')) {
    return 0;
  }
  return 1;  // 默认启用
}

static uint32_t bp_infer_events_threshold_design7(const AVEBehaviorEvent *e, const EdrPidHistory *sl) {
  if (bp_infer_immediate(e)) {
    return 1u;
  }
  uint32_t step = EDR_AVE_BEH_INFER_STEP_DEFAULT;
  if (sl->consecutive_medium_scores >= EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT) {
    step = EDR_AVE_BEH_INFER_STEP_TIGHT;
  }

  // 动态调整：根据当前异常分数调整阈值（性能优化）
  if (env_dynamic_threshold_enabled()) {
    if (sl->anomaly < 0.1f) {
      return step * 2;  // 低风险，降低推理频率
    } else if (sl->anomaly > 0.7f) {
      // 高风险，提高推理频率
      return (step > 1) ? (step / 2) : step;
    }
  }

  return step;
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
static CRITICAL_SECTION s_mu;
static HANDLE s_thread;
#else
static pthread_mutex_t s_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_thread;
#endif

static volatile int s_worker_stop;
static volatile int s_monitor_started;

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
  EnterCriticalSection(&s_mu);
#else
  (void)pthread_mutex_lock(&s_mu);
#endif
}

static void unlock_bp(void) {
#ifdef _WIN32
  LeaveCriticalSection(&s_mu);
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
  uint32_t v = cfg ? cfg->resource_limit.behavior_infer_per_min : 30u;
  uint32_t keep = cfg ? cfg->resource_limit.low_priority_keep_percent_under_pressure : 5u;
  if (keep > 100u) {
    keep = 100u;
  }
  lock_bp();
  s_bp_behavior_infer_per_min = v;
  s_bp_low_priority_keep_percent_under_pressure = keep;
  unlock_bp();
}

static int bp_pressure_active(void) {
  return edr_resource_preprocess_throttle_active() ? 1 : 0;
}

static uint32_t bp_effective_behavior_infer_limit(void) {
  uint32_t limit = s_bp_behavior_infer_per_min;
  if (limit == 0u || !bp_pressure_active()) {
    return limit;
  }
  uint32_t keep = s_bp_low_priority_keep_percent_under_pressure;
  if (keep == 0u) {
    return 0u;
  }
  uint64_t scaled = ((uint64_t)limit * (uint64_t)keep + 99ULL) / 100ULL;
  if (scaled == 0u) {
    scaled = 1u;
  }
  return scaled > 0xffffffffULL ? 0xffffffffu : (uint32_t)scaled;
}

static int bp_behavior_infer_budget_allow(int64_t now_ns) {
  uint32_t configured = s_bp_behavior_infer_per_min;
  uint32_t limit = bp_effective_behavior_infer_limit();
  if (limit == 0u) {
    (void)bp_metric_inc(&s_bp_infer_budget_dropped);
    if (configured > 0u && bp_pressure_active()) {
      (void)bp_metric_inc(&s_bp_pressure_infer_dropped);
    }
    return 0;
  }
  if (s_bp_infer_budget_window_ns == 0 || now_ns < s_bp_infer_budget_window_ns ||
      now_ns - s_bp_infer_budget_window_ns >= 60000000000LL) {
    s_bp_infer_budget_window_ns = now_ns;
    s_bp_infer_budget_count = 0u;
  }
  if (s_bp_infer_budget_count >= limit) {
    (void)bp_metric_inc(&s_bp_infer_budget_dropped);
    if (limit < configured && bp_pressure_active()) {
      (void)bp_metric_inc(&s_bp_pressure_infer_dropped);
    }
    return 0;
  }
  s_bp_infer_budget_count++;
  return 1;
}

static void bp_record_infer_latency_ms(uint32_t ms) {
  s_bp_infer_latency_last_ms = ms;
  s_bp_infer_latency_ms[s_bp_infer_latency_pos++ % 64u] = ms;
  if (s_bp_infer_latency_count < 64u) {
    s_bp_infer_latency_count++;
  }
}

static uint32_t bp_latency_p95_ms(void) {
  uint32_t n = s_bp_infer_latency_count;
  if (n == 0u) {
    return 0u;
  }
  uint32_t tmp[64];
  for (uint32_t i = 0; i < n; i++) {
    tmp[i] = s_bp_infer_latency_ms[i];
  }
  for (uint32_t i = 1; i < n; i++) {
    uint32_t v = tmp[i];
    uint32_t j = i;
    while (j > 0u && tmp[j - 1u] > v) {
      tmp[j] = tmp[j - 1u];
      j--;
    }
    tmp[j] = v;
  }
  uint32_t idx = (uint32_t)(((uint64_t)n * 95u + 99u) / 100u);
  if (idx == 0u) {
    idx = 1u;
  }
  if (idx > n) {
    idx = n;
  }
  return tmp[idx - 1u];
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

static float score_to_unit(float s) {
  if (s >= 0.f && s <= 1.f) {
    return s;
  }
  return 1.f / (1.f + expf(-s));
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
  if (edr_onnx_behavior_ready()) {
    size_t m = edr_onnx_behavior_input_seq_len();
    if (m > 0u && m < cap) {
      cap = m;
    }
  }
  if (ph->feat_len < cap) {
    memcpy(ph->feat_chrono[ph->feat_len], f64, EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    ph->feat_len++;
  } else {
    memmove(ph->feat_chrono[0], ph->feat_chrono[1], (cap - 1u) * EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    memcpy(ph->feat_chrono[cap - 1u], f64, EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    ph->feat_len = (uint32_t)cap;
  }
}

static void ph_build_ort_input(const EdrPidHistory *ph, float *out, size_t nelem) {
  memset(out, 0, nelem * sizeof(float));
  size_t seq = edr_onnx_behavior_input_seq_len();
  if (seq > (size_t)EDR_PID_HISTORY_MAX_SEQ) {
    seq = (size_t)EDR_PID_HISTORY_MAX_SEQ;
  }
  if (nelem == (size_t)EDR_PID_HISTORY_FEAT_DIM) {
    if (ph->feat_len == 0u) {
      memset(out, 0, EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
      return;
    }
    memcpy(out, ph->feat_chrono[ph->feat_len - 1u], EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    return;
  }
  if (seq > 0u && nelem == seq * (size_t)EDR_PID_HISTORY_FEAT_DIM) {
    size_t pad = (ph->feat_len < seq) ? (seq - ph->feat_len) : 0u;
    /* 《11》§5.6 PAD：每步 64 维全 0（含维 57 is_real_event=0），与 encode_e_group 中真实步 feat[57]=1 对偶。 */
    for (size_t i = 0; i < pad; i++) {
      memset(out + i * (size_t)EDR_PID_HISTORY_FEAT_DIM, 0, (size_t)EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    }
    for (size_t i = 0; i < ph->feat_len && i < seq; i++) {
      memcpy(out + (pad + i) * (size_t)EDR_PID_HISTORY_FEAT_DIM, ph->feat_chrono[i],
             (size_t)EDR_PID_HISTORY_FEAT_DIM * sizeof(float));
    }
    return;
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

/** 与设计 §6.3 MITRE 战术维度顺序一致（14）。 */
static const char *k_tactic_label[14] = {
    "Initial Access",      "Execution",           "Persistence",          "Privilege Escalation",
    "Defense Evasion",     "Credential Access",   "Discovery",          "Lateral Movement",
    "Collection",          "Exfiltration",        "Command and Control", "Impact",
    "Resource Development", "Reconnaissance",
};

static void fill_triggered_tactics(const float tactic_probs[14], char *buf, size_t cap) {
  if (!buf || cap == 0u) {
    return;
  }
  buf[0] = '\0';
  size_t pos = 0u;
  for (int i = 0; i < 14; i++) {
    if (tactic_probs[i] <= 0.50f) {
      continue;
    }
    int w = snprintf(buf + pos, cap > pos ? cap - pos : 0, "%s%s", pos > 0u ? ", " : "", k_tactic_label[i]);
    if (w < 0 || (size_t)w >= cap - pos) {
      break;
    }
    pos += (size_t)w;
  }
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
  if (e->target_path[0]) {
    snprintf(sl->process_path, sizeof(sl->process_path), "%s", e->target_path);
    const char *base = e->target_path;
    for (const char *p = e->target_path; *p; p++) {
      if (*p == '/' || *p == '\\') {
        base = p + 1;
      }
    }
    snprintf(sl->process_name, sizeof(sl->process_name), "%s", base);
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
    if (e->target_path[0]) {
      snprintf(sl->process_path, sizeof(sl->process_path), "%s", e->target_path);
      const char *base = e->target_path;
      for (const char *p = e->target_path; *p; p++) {
        if (*p == '/' || *p == '\\') {
          base = p + 1;
        }
      }
      snprintf(sl->process_name, sizeof(sl->process_name), "%s", base);
    } else {
      snprintf(sl->process_name, sizeof(sl->process_name), "pid:%u", e->pid);
    }
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
  if (edr_onnx_behavior_ready()) {
    size_t need = edr_onnx_behavior_input_nelem();
    uint32_t min_ev;
    if (env_infer_min_events_explicit(&min_ev)) {
      /* legacy：显式 EDR_AVE_BEH_INFER_MIN_EVENTS */
    } else {
      /* 《11》§7.1：立即触发 或 步长 16/8（由连续中等分计数收紧） */
      min_ev = bp_infer_events_threshold_design7(e, sl);
    }
    /* 序列张量：避免仅 PAD 步即推理；legacy 下仍可将环境变量调到 ≥4 */
    if (need > (size_t)EDR_PID_HISTORY_FEAT_DIM && min_ev < 4u) {
      min_ev = 4u;
    }
    if (need > 0u && need <= 1024u * 1024u && sl->events_since_last_inference >= min_ev) {
      if (!bp_behavior_infer_budget_allow(now)) {
        sl->events_since_last_inference = 0u;
        goto behavior_infer_done;
      }
      float *ort_in = NULL;
      int use_stack = (need <= (size_t)AVE_BP_ORT_NELEM_MAX) ? 1 : 0;
      if (use_stack) {
        ort_in = s_bp_ort_scratch;
      } else {
        ort_in = (float *)malloc(need * sizeof(float));
      }
      if (ort_in) {
        ph_build_ort_input(sl, ort_in, need);
        float raw = 0.f;
        int64_t infer_t0 = wall_ns();
        if (edr_onnx_behavior_infer(ort_in, need, &raw, last_tactic_probs) == EDR_OK) {
          int64_t infer_t1 = wall_ns();
          uint32_t ms = (infer_t1 > infer_t0) ? (uint32_t)((infer_t1 - infer_t0) / 1000000LL) : 0u;
          bp_record_infer_latency_ms(ms);
          float u = score_to_unit(raw);
          sl->anomaly = fminf(1.f, 0.35f * sl->anomaly + 0.65f * u);
          sl->last_anomaly_score = u;
          sl->last_inference_ts = (uint64_t)now;
          sl->events_since_last_inference = 0u;
          if (u >= EDR_AVE_BEH_SCORE_MEDIUM_LOW && u < EDR_AVE_BEH_SCORE_HIGH &&
              sl->consecutive_medium_scores < 255u) {
            sl->consecutive_medium_scores++;
          } else {
            sl->consecutive_medium_scores = 0u;
          }
          (void)bp_metric_inc(&s_bp_beh_infer_ok);
        } else {
          int64_t infer_t1 = wall_ns();
          uint32_t ms = (infer_t1 > infer_t0) ? (uint32_t)((infer_t1 - infer_t0) / 1000000LL) : 0u;
          bp_record_infer_latency_ms(ms);
          uint64_t nf = bp_metric_inc(&s_bp_beh_infer_fail);
          if ((nf & 63u) == 0u) {
            fprintf(stderr, "[ave/bp] behavior onnx infer failures (count=%llu)\n",
                    (unsigned long long)nf);
          }
        }
        if (!use_stack) {
          free(ort_in);
        }
      }
    }
behavior_infer_done:
    ;
  } else {
    float sev = (float)e->severity_hint / 255.0f;
    float bump = sev * 0.12f + (float)popcount_u32(e->behavior_flags) * 0.04f;
    if (e->event_type == AVE_EVT_LSASS_ACCESS || e->event_type == AVE_EVT_MEM_ALLOC_EXEC) {
      bump += 0.08f;
    }
    sl->anomaly = fminf(1.0f, sl->anomaly + bump);
  }

  int fire = 0;
  int onnx_ready = edr_onnx_behavior_ready();
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
  char ev_tgt_path[1024];
  snprintf(ev_tgt_path, sizeof(ev_tgt_path), "%s", e->target_path);
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
    al.anomaly_score = an_copy;
    memcpy(al.tactic_probs, tactic_copy, sizeof(al.tactic_probs));
    if (!onnx_ready) {
      al.triggered_tactics[0] = '\0';
      al.skip_ai_analysis = true;
      al.needs_l2_review = true;
    } else {
      fill_triggered_tactics(tactic_copy, al.triggered_tactics, sizeof(al.triggered_tactics));
      al.needs_l2_review = true;
      al.skip_ai_analysis = false;
    }
    al.behavior_flags = (AVEBehaviorFlags)fl_copy;
    al.timestamp_ns = now;
    if (sl_proc_name[0] && strncmp(sl_proc_name, "pid:", 4) != 0) {
      snprintf(al.process_name, sizeof(al.process_name), "%s", sl_proc_name);
    } else if (ev_tgt_path[0]) {
      const char *bn = ev_tgt_path;
      for (const char *c = ev_tgt_path; *c; c++) {
        if (*c == '\\' || *c == '/') bn = c + 1;
      }
      snprintf(al.process_name, sizeof(al.process_name), "%s", bn);
    } else {
      snprintf(al.process_name, sizeof(al.process_name), "pid:%u", (unsigned)pid_copy);
    }
    if (ev_tgt_path[0]) {
      snprintf(al.process_path, sizeof(al.process_path), "%s", ev_tgt_path);
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
      ave_fill_detection_context(&al, evt_copy, ppid_copy, ev_tgt_path, ev_file_sha, ev_tgt_ip, ev_tgt_domain,
                                 ev_tgt_port, ev_shellcode_score, ev_webshell_score, ev_pmfe_confidence,
                                 ev_pmfe_dns_tunnel, ev_pmfe_pe_found, ev_ioc_ip_hit, ev_ioc_domain_hit,
                                 ev_ioc_sha256_hit, ev_script_content_score, ev_tls_anomaly_score,
                                 ev_ransom_counter_score, ev_script_block_present, ev_amsi_content_present,
                                 ev_ja3_anomaly, ev_sni_anomaly, ev_cert_anomaly, ev_suspicious_extension_burst,
                                 ev_shadow_copy_delete);
    }
    edr_behavior_alert_emit_to_batch(&al);
    cb(&al, ud);
  }
}

#ifdef _WIN32
static DWORD WINAPI worker_main(LPVOID arg) {
  (void)arg;
  while (!s_worker_stop) {
    AVEBehaviorEvent ev;
    int drained = 0;
    if (s_q) {
      while (ave_mpmc_try_pop(s_q, &ev) == 0) {
        (void)bp_metric_inc(&s_bp_worker_dequeued);
        process_one_event(&ev);
        drained = 1;
      }
    }
    if (!drained) {
      Sleep(20);
    }
  }
  return 0;
}
#else
static void *worker_main(void *arg) {
  (void)arg;
  while (!s_worker_stop) {
    AVEBehaviorEvent ev;
    int drained = 0;
    if (s_q) {
      while (ave_mpmc_try_pop(s_q, &ev) == 0) {
        (void)bp_metric_inc(&s_bp_worker_dequeued);
        process_one_event(&ev);
        drained = 1;
      }
    }
    if (!drained) {
      usleep(20000);
    }
  }
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
  InitializeCriticalSection(&s_mu);
  s_thread = NULL;
#endif
  s_worker_stop = 0;
  s_monitor_started = 0;
  bp_hist_free();
  memset(&s_callbacks, 0, sizeof(s_callbacks));
  s_callbacks_set = 0;
  s_bp_behavior_infer_per_min = 30u;
  s_bp_low_priority_keep_percent_under_pressure = 5u;
  bp_reset_metrics();
}

void edr_ave_bp_shutdown(void) {
  s_worker_stop = 1;
#ifdef _WIN32
  if (s_thread) {
    WaitForSingleObject(s_thread, INFINITE);
    CloseHandle(s_thread);
    s_thread = NULL;
  }
  DeleteCriticalSection(&s_mu);
#else
  if (s_monitor_started) {
    (void)pthread_join(s_thread, NULL);
  }
#endif
  s_monitor_started = 0;
  if (s_q) {
    ave_mpmc_destroy(s_q);
    s_q = NULL;
  }
  edr_ave_bp_init();
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

void edr_ave_bp_feed(const AVEBehaviorEvent *event) {
  if (!event) {
    return;
  }
  (void)bp_metric_inc(&s_bp_feed_total);
  if (s_monitor_started && bp_pressure_active() && !bp_event_high_value_under_pressure(event)) {
    (void)bp_metric_inc(&s_bp_pressure_feed_dropped);
    return;
  }
  if (!s_monitor_started) {
    (void)bp_metric_inc(&s_bp_feed_sync_bypass);
    return;
  }
  if (s_q) {
    if (ave_mpmc_try_push(s_q, event) != 0) {
      (void)bp_metric_inc(&s_bp_queue_full_dropped);
      return;
    } else {
      (void)bp_metric_inc(&s_bp_queue_enqueued);
    }
  } else {
    (void)bp_metric_inc(&s_bp_feed_sync_bypass);
    return;
  }
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
  status_out->behavior_infer_ok = bp_metric_load(&s_bp_beh_infer_ok);
  status_out->behavior_infer_fail = bp_metric_load(&s_bp_beh_infer_fail);
  status_out->behavior_infer_budget_dropped = bp_metric_load(&s_bp_infer_budget_dropped);
  status_out->behavior_pressure_feed_dropped = bp_metric_load(&s_bp_pressure_feed_dropped);
  status_out->behavior_pressure_infer_dropped = bp_metric_load(&s_bp_pressure_infer_dropped);
  status_out->behavior_infer_budget_per_min = s_bp_behavior_infer_per_min;
  status_out->behavior_infer_effective_budget_per_min = bp_effective_behavior_infer_limit();
  status_out->behavior_infer_latency_last_ms = s_bp_infer_latency_last_ms;
  status_out->behavior_infer_latency_p95_ms = bp_latency_p95_ms();
  status_out->behavior_pressure_active = bp_pressure_active() ? 1u : 0u;
  status_out->behavior_queue_capacity = edr_ave_bp_queue_capacity();
  status_out->behavior_pid_history_used = hist_used;
  status_out->behavior_pid_history_capacity = s_hist_capacity;
  status_out->behavior_pid_history_static_bytes =
      s_hist ? (uint64_t)s_hist_capacity * (uint64_t)sizeof(*s_hist) : 0u;
}

int edr_ave_bp_monitor_running(void) { return s_monitor_started ? 1 : 0; }
