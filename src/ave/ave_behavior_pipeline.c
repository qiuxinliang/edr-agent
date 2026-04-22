/**
 * P2：MPMC 无锁入队 + 单消费线程 + PID 状态；behavior.onnx 就绪时以模型分替代启发式 bump。
 */

#include "ave_behavior_pipeline.h"

#include "edr/behavior_alert_emit.h"
#include "edr/ave_behavior_features.h"
#include "edr/ave_behavior_gates.h"
#include "edr/pid_history.h"

#include "ave_lf_mpmc.h"
#include "ave_onnx_infer.h"

#include "edr/config.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** 《11》§6.1 最大展平元素数；热路径 ORT 输入缓冲（T04） */
#define AVE_BP_ORT_NELEM_MAX (EDR_PID_HISTORY_MAX_SEQ * EDR_PID_HISTORY_FEAT_DIM)

static float s_bp_ort_scratch[AVE_BP_ORT_NELEM_MAX];
static _Atomic uint64_t s_bp_beh_infer_ok = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_beh_infer_fail = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_feed_total = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_queue_enqueued = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_queue_full_fallback = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_feed_sync_bypass = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t s_bp_worker_dequeued = ATOMIC_VAR_INIT(0);

static void bp_reset_metrics(void) {
  atomic_store_explicit(&s_bp_beh_infer_ok, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_beh_infer_fail, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_feed_total, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_queue_enqueued, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_queue_full_fallback, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_feed_sync_bypass, 0u, memory_order_relaxed);
  atomic_store_explicit(&s_bp_worker_dequeued, 0u, memory_order_relaxed);
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

static uint32_t bp_infer_events_threshold_design7(const AVEBehaviorEvent *e, const EdrPidHistory *sl) {
  if (bp_infer_immediate(e)) {
    return 1u;
  }
  uint32_t step = EDR_AVE_BEH_INFER_STEP_DEFAULT;
  if (sl->consecutive_medium_scores >= EDR_AVE_BEH_MEDIUM_RUN_LEN_FOR_STEP_TIGHT) {
    step = EDR_AVE_BEH_INFER_STEP_TIGHT;
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

#define AVE_BP_RING_CAP 4096u
#define AVE_BP_PID_SLOTS 512u
#define AVE_BP_ALERT_THRESH EDR_AVE_BEH_SCORE_HIGH
#define AVE_BP_ALERT_COOLDOWN_NS (10LL * 1000000000LL)
#define AVE_BP_TS_BUF 128u
#define AVE_BP_IP_SLOTS 8u

static EdrPidHistory s_hist[AVE_BP_PID_SLOTS];

static AVECallbacks s_callbacks;
static int s_callbacks_set;

static AveMpmcQueue *s_q;

#ifdef _WIN32
static CRITICAL_SECTION s_mu;
static HANDLE s_thread;
#else
static pthread_mutex_t s_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_thread;
#endif

static volatile int s_worker_stop;
static volatile int s_monitor_started;

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
  for (uint32_t i = 0u; i < AVE_BP_PID_SLOTS; i++) {
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
  for (uint32_t k = 0u; k < AVE_BP_PID_SLOTS; k++) {
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
  if (pid == 0u) {
    return -1;
  }
  int64_t now_ns = wall_ns();
  uint32_t start = pid % AVE_BP_PID_SLOTS;
  int first_empty = -1;
  for (uint32_t j = 0u; j < AVE_BP_PID_SLOTS; j++) {
    uint32_t idx = (start + j) % AVE_BP_PID_SLOTS;
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
  for (uint32_t i = 0; i < AVE_BP_PID_SLOTS; i++) {
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
    for (uint32_t k = 0; k < AVE_BP_PID_SLOTS; k++) {
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
        if (edr_onnx_behavior_infer(ort_in, need, &raw, last_tactic_probs) == EDR_OK) {
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
          (void)atomic_fetch_add_explicit(&s_bp_beh_infer_ok, 1u, memory_order_relaxed);
        } else {
          uint64_t nf = atomic_fetch_add_explicit(&s_bp_beh_infer_fail, 1u, memory_order_relaxed) + 1u;
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
  } else {
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
  AVEBehaviorFlags fl_copy = sl->flags;
  uint32_t pid_copy = e->pid;
  AVEBehaviorCallback cb = s_callbacks.on_behavior_alert;
  void *ud = s_callbacks.user_data;
  float tactic_copy[14];
  memcpy(tactic_copy, last_tactic_probs, sizeof(tactic_copy));
  unlock_bp();

  if (fire && cb) {
    AVEBehaviorAlert al;
    memset(&al, 0, sizeof(al));
    al.pid = pid_copy;
    al.anomaly_score = an_copy;
    memcpy(al.tactic_probs, tactic_copy, sizeof(al.tactic_probs));
    fill_triggered_tactics(tactic_copy, al.triggered_tactics, sizeof(al.triggered_tactics));
    al.behavior_flags = fl_copy;
    al.timestamp_ns = now;
    snprintf(al.process_name, sizeof(al.process_name), "pid:%u", (unsigned)pid_copy);
    if (e->target_path[0]) {
      snprintf(al.process_path, sizeof(al.process_path), "%s", e->target_path);
    }
    al.needs_l2_review = true;
    al.skip_ai_analysis = false;
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
        (void)atomic_fetch_add_explicit(&s_bp_worker_dequeued, 1u, memory_order_relaxed);
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
        (void)atomic_fetch_add_explicit(&s_bp_worker_dequeued, 1u, memory_order_relaxed);
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
  if (ave_mpmc_init(&s_q, AVE_BP_RING_CAP) != 0) {
    s_q = NULL;
    fprintf(stderr, "[ave/bp] MPMC 初始化失败\n");
  }
#ifdef _WIN32
  InitializeCriticalSection(&s_mu);
  s_thread = NULL;
#endif
  s_worker_stop = 0;
  s_monitor_started = 0;
  memset(s_hist, 0, sizeof(s_hist));
  memset(&s_callbacks, 0, sizeof(s_callbacks));
  s_callbacks_set = 0;
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
  if (!cfg->ave.behavior_monitor_enabled) {
    return AVE_OK;
  }
  if (!s_callbacks_set || !s_callbacks.on_behavior_alert) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (!s_q) {
    return AVE_ERR_INTERNAL;
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
  (void)atomic_fetch_add_explicit(&s_bp_feed_total, 1u, memory_order_relaxed);
  if (!s_monitor_started) {
    (void)atomic_fetch_add_explicit(&s_bp_feed_sync_bypass, 1u, memory_order_relaxed);
    process_one_event(event);
    return;
  }
  if (s_q) {
    if (ave_mpmc_try_push(s_q, event) != 0) {
      (void)atomic_fetch_add_explicit(&s_bp_queue_full_fallback, 1u, memory_order_relaxed);
      process_one_event(event);
    } else {
      (void)atomic_fetch_add_explicit(&s_bp_queue_enqueued, 1u, memory_order_relaxed);
    }
  } else {
    (void)atomic_fetch_add_explicit(&s_bp_feed_sync_bypass, 1u, memory_order_relaxed);
    process_one_event(event);
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

uint32_t edr_ave_bp_queue_capacity(void) { return AVE_BP_RING_CAP; }

void edr_ave_bp_fill_metrics(AVEStatus *status_out) {
  if (!status_out) {
    return;
  }
  status_out->behavior_feed_total = atomic_load_explicit(&s_bp_feed_total, memory_order_relaxed);
  status_out->behavior_queue_enqueued = atomic_load_explicit(&s_bp_queue_enqueued, memory_order_relaxed);
  status_out->behavior_queue_full_sync_fallback =
      atomic_load_explicit(&s_bp_queue_full_fallback, memory_order_relaxed);
  status_out->behavior_feed_sync_bypass = atomic_load_explicit(&s_bp_feed_sync_bypass, memory_order_relaxed);
  status_out->behavior_worker_dequeued = atomic_load_explicit(&s_bp_worker_dequeued, memory_order_relaxed);
  status_out->behavior_infer_ok = atomic_load_explicit(&s_bp_beh_infer_ok, memory_order_relaxed);
  status_out->behavior_infer_fail = atomic_load_explicit(&s_bp_beh_infer_fail, memory_order_relaxed);
  status_out->behavior_queue_capacity = edr_ave_bp_queue_capacity();
}

int edr_ave_bp_monitor_running(void) { return s_monitor_started ? 1 : 0; }
