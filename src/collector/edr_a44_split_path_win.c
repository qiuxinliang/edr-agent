/**
 * A4.4 二期：有界 SPSC+信号量+CS，支持多线程解码池。见 ADR。
 * `edr_collector_decode_from_a44_item` 在 collector_win.c。
 */
#if !defined(_WIN32)
void edr_a44_split_path_win_c_only_non_win(void) {}
#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "edr/edr_a44_split_path_win.h"
#include "edr/event_bus.h"
#include "edr/error.h"

#include <process.h>
#include <windows.h>

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void edr_collector_decode_from_a44_item(const EdrA44QueueItem *it);

#ifndef EDR_A44_QUEUE_CAP
#define EDR_A44_QUEUE_CAP 512u
#endif

#ifndef EDR_A44_DECODE_THREADS
#define EDR_A44_DECODE_THREADS 1
#endif

#define EDR_A44_MAX_THREADS 4

static int edr_a44_yes(const char *e) {
  if (!e || !e[0]) {
    return 0;
  }
  if (e[0] == '1' && e[1] == 0) {
    return 1;
  }
  {
    int a = (e[0] | 32);
    return a == (int)'y' || a == (int)'t';
  }
}

static int edr_get_env_int(const char *name, int default_val, int min_val, int max_val) {
  const char *e = getenv(name);
  if (!e || !e[0]) {
    return default_val;
  }
  int v = atoi(e);
  if (v < min_val) {
    v = min_val;
  }
  if (v > max_val) {
    v = max_val;
  }
  return v;
}

int edr_a44_split_path_enabled(void) { return edr_a44_yes(getenv("EDR_A44_SPLIT_PATH")); }

int edr_a44_item_pack(PEVENT_RECORD r, uint64_t ts_ns, EdrEventType ty, const char *tag, EdrA44QueueItem *out,
                      int *reason_sync) {
  if (!r || !out) {
    return -1;
  }
  if (reason_sync) {
    *reason_sync = 0;
  }
  if (r->ExtendedDataCount != 0) {
    if (reason_sync) {
      *reason_sync = 1;
    }
    return 1;
  }
  if (r->UserDataLength > (USHORT)EDR_A44_MAX_USERDATA) {
    if (reason_sync) {
      *reason_sync = 2;
    }
    return 1;
  }
  memset(out, 0, sizeof(*out));
  out->ts_ns = ts_ns;
  out->ty = ty;
  if (tag) {
    snprintf(out->tag, sizeof(out->tag), "%s", tag);
  }
  memcpy(&out->evh, &r->EventHeader, sizeof(out->evh));
  out->udlen = r->UserDataLength;
  out->edcount = 0;
  out->buffer_context = r->BufferContext;
  if (r->UserData && r->UserDataLength > 0) {
    memcpy(out->ud, r->UserData, (size_t)r->UserDataLength);
  }
  return 0;
}

void edr_a44_item_to_event_record(const EdrA44QueueItem *it, EVENT_RECORD *er) {
  if (!it || !er) {
    return;
  }
  memset(er, 0, sizeof(*er));
  memcpy(&er->EventHeader, &it->evh, sizeof(er->EventHeader));
  er->UserDataLength = it->udlen;
  er->ExtendedDataCount = 0;
  er->BufferContext = it->buffer_context;
  er->UserData = (PVOID)it->ud;
  er->ExtendedData = NULL;
}

static CRITICAL_SECTION s_a44_lock;
static EdrA44QueueItem *s_a44_buf;
static uint32_t s_a44_buf_cap;
static uint32_t s_a44_head;
static uint32_t s_a44_tail;
static HANDLE *s_a44_threads;
static HANDLE s_a44_hFree;
static HANDLE s_a44_hData;
static volatile LONG s_a44_life;
static volatile LONG64 s_a44_drop;
static volatile LONG64 s_a44_backoff_sync;
static volatile LONG64 s_a44_extended_data_drop;
static volatile LONG64 s_a44_userdata_overflow_drop;
static volatile LONG64 s_a44_total_processed;
static volatile LONG64 s_a44_total_pushed;
static int s_a44_num_threads;
static uint32_t s_a44_current_depth;
static volatile LONG64 s_a44_q_depth_sum;
static volatile LONG64 s_a44_q_depth_samples;
static volatile LONG64 s_a44_thread_processed[EDR_A44_MAX_THREADS];
static int s_a44_thread_indices[EDR_A44_MAX_THREADS];
static volatile int64_t s_a44_start_time_ns;
static volatile uint64_t s_a44_total_alloc_bytes;
static volatile uint64_t s_a44_total_free_bytes;
static volatile uint32_t s_a44_active_alloc_count;
static volatile uint32_t s_a44_peak_alloc_count;
static volatile LONG s_a44_circuit_open;
static volatile int64_t s_a44_circuit_open_time_ns;
static volatile uint64_t s_a44_circuit_drop_threshold;
static volatile uint64_t s_a44_circuit_recovery_timeout_ms;
static volatile uint32_t s_a44_rate_limit_qps;
static volatile uint32_t s_a44_rate_limit_current_count;
static volatile uint32_t s_a44_rate_limit_window_start_sec;
static volatile int s_a44_perf_measurement_enabled;
static volatile uint64_t s_a44_perf_callback_total_ns;
static volatile uint64_t s_a44_perf_callback_count;
static volatile uint64_t s_a44_perf_callback_max_ns;
static volatile uint64_t s_a44_perf_callback_min_ns;
static volatile uint64_t s_a44_perf_tdh_total_ns;
static volatile uint64_t s_a44_perf_tdh_count;
static volatile uint64_t s_a44_perf_tdh_max_ns;
static volatile uint64_t s_a44_perf_bus_push_total_ns;
static volatile uint64_t s_a44_perf_bus_push_count;
static volatile uint64_t s_a44_perf_bus_push_max_ns;
static CRITICAL_SECTION s_a44_aggr_lock;
static EdrEventSlot *s_a44_aggr_buf;
static uint32_t s_a44_aggr_cap;
static uint32_t s_a44_aggr_count;
static volatile uint64_t s_a44_aggr_total_count;
static volatile uint64_t s_a44_aggr_flush_count;
static volatile int64_t s_a44_aggr_last_flush_ns;
static CRITICAL_SECTION s_a44_mempool_lock;
static void **s_a44_mempool_blocks;
static uint32_t s_a44_mempool_item_size;
static uint32_t s_a44_mempool_capacity;
static uint32_t s_a44_mempool_total_blocks;
static uint32_t s_a44_mempool_used_blocks;
static uint32_t s_a44_mempool_peak_used_blocks;
static volatile uint64_t s_a44_mempool_total_alloc_bytes;
static volatile uint64_t s_a44_mempool_total_free_bytes;
static volatile uint32_t s_a44_mempool_alloc_count;
static volatile uint32_t s_a44_mempool_free_count;
static volatile uint32_t s_a44_mempool_alloc_fail_count;
static volatile LONG s_a44_lockfree_head;
static volatile LONG s_a44_lockfree_tail;
static void *s_a44_lockfree_buf;
static uint32_t s_a44_lockfree_cap;
static volatile uint32_t s_a44_lockfree_item_size;
static volatile uint64_t s_a44_lockfree_try_push_count;
static volatile uint64_t s_a44_lockfree_push_success_count;
static volatile uint64_t s_a44_lockfree_pop_count;
static volatile uint64_t s_a44_lockfree_pop_success_count;
static volatile uint64_t s_a44_lockfree_empty_count;
static volatile int s_a44_cache_friendly_mode;
static uint8_t s_a44_cacheline_padding[64];
static volatile EdrA44AdaptiveMode s_adaptive_mode;
static volatile int s_adaptive_enabled;
static double s_throughput_history[900];
static uint32_t s_throughput_history_head;
static uint32_t s_throughput_history_count;
static volatile double s_scale_up_threshold;
static volatile double s_scale_down_threshold;
static volatile int s_scale_up_cooldown_ms;
static volatile int s_scale_down_cooldown_ms;
static volatile int s_last_scale_action;
static volatile int64_t s_last_scale_time_ns;
static volatile double s_trend_slope;
static volatile double s_prediction_accuracy;

static EdrA44DynamicConfig s_dynamic_config = {
    .enabled = 0,
    .min_threads = 1,
    .max_threads = EDR_A44_MAX_THREADS,
    .high_water_mark = 80,
    .low_water_mark = 20,
    .cooldown_ms = 5000
};
static volatile LONG64 s_last_adjust_time = 0;
static CRITICAL_SECTION s_thread_reconfig_lock;

static void edr_a44_init_dynamic_config(void) {
  if (edr_a44_yes(getenv("EDR_A44_DYNAMIC_THREADS"))) {
    s_dynamic_config.enabled = 1;
    s_dynamic_config.min_threads = edr_get_env_int("EDR_A44_DYNAMIC_MIN", 1, 1, EDR_A44_MAX_THREADS);
    s_dynamic_config.max_threads = edr_get_env_int("EDR_A44_DYNAMIC_MAX", EDR_A44_MAX_THREADS, 1, EDR_A44_MAX_THREADS);
    s_dynamic_config.high_water_mark = edr_get_env_int("EDR_A44_DYNAMIC_HIGH", 80, 50, 95);
    s_dynamic_config.low_water_mark = edr_get_env_int("EDR_A44_DYNAMIC_LOW", 20, 5, 50);
    s_dynamic_config.cooldown_ms = edr_get_env_int("EDR_A44_DYNAMIC_COOLDOWN", 5000, 1000, 30000);
    InitializeCriticalSection(&s_thread_reconfig_lock);
    fprintf(stderr, "[collector_win] A4.4 dynamic threads enabled: min=%d max=%d high=%d%% low=%d%% cooldown=%dms\n",
            s_dynamic_config.min_threads, s_dynamic_config.max_threads,
            s_dynamic_config.high_water_mark, s_dynamic_config.low_water_mark,
            s_dynamic_config.cooldown_ms);
  }
}

static void edr_a44_decode_one_popped(EdrA44QueueItem *it) {
  edr_collector_decode_from_a44_item(it);
}

#ifndef EDR_A44_BATCH_SIZE
#define EDR_A44_BATCH_SIZE 8
#endif

static unsigned __stdcall edr_a44_decode_trampoline(void *arg) {
  int thread_idx = arg ? *(int *)arg : 0;
  EdrA44QueueItem batch_items[EDR_A44_BATCH_SIZE];
  while (InterlockedCompareExchange(&s_a44_life, 1, 1) == 1) {
    DWORD w = WaitForSingleObject(s_a44_hData, 80);
    if (w == WAIT_OBJECT_0) {
      uint32_t batch_count = 0;
      EnterCriticalSection(&s_a44_lock);
      while (batch_count < EDR_A44_BATCH_SIZE) {
        uint32_t head = s_a44_head;
        if (head == s_a44_tail) {
          break;
        }
        batch_items[batch_count] = s_a44_buf[head % s_a44_buf_cap];
        s_a44_head = (s_a44_head + 1u) % s_a44_buf_cap;
        batch_count++;
      }
      LeaveCriticalSection(&s_a44_lock);
      for (uint32_t i = 0; i < batch_count; i++) {
        (void)ReleaseSemaphore(s_a44_hFree, 1, NULL);
        edr_a44_decode_one_popped(&batch_items[i]);
        (void)InterlockedIncrement64(&s_a44_total_processed);
        if (thread_idx >= 0 && thread_idx < EDR_A44_MAX_THREADS) {
          (void)InterlockedIncrement64(&s_a44_thread_processed[thread_idx]);
        }
      }
      if (batch_count == 0) {
        if (InterlockedCompareExchange(&s_a44_life, 1, 1) == 0) {
          break;
        }
      }
    } else {
      if (InterlockedCompareExchange(&s_a44_life, 1, 1) == 0) {
        break;
      }
    }
  }

  for (;;) {
    DWORD w = WaitForSingleObject(s_a44_hData, 0);
    if (w != WAIT_OBJECT_0) {
      break;
    }
    uint32_t batch_count = 0;
    EnterCriticalSection(&s_a44_lock);
    while (batch_count < EDR_A44_BATCH_SIZE) {
      uint32_t head = s_a44_head;
      if (head == s_a44_tail) {
        break;
      }
      batch_items[batch_count] = s_a44_buf[head % s_a44_buf_cap];
      s_a44_head = (s_a44_head + 1u) % s_a44_buf_cap;
      batch_count++;
    }
    LeaveCriticalSection(&s_a44_lock);
    for (uint32_t i = 0; i < batch_count; i++) {
      (void)ReleaseSemaphore(s_a44_hFree, 1, NULL);
      edr_a44_decode_one_popped(&batch_items[i]);
      (void)InterlockedIncrement64(&s_a44_total_processed);
      if (thread_idx >= 0 && thread_idx < EDR_A44_MAX_THREADS) {
        (void)InterlockedIncrement64(&s_a44_thread_processed[thread_idx]);
      }
    }
    if (batch_count == 0) {
      break;
    }
  }
  return 0u;
}

EdrError edr_a44_split_path_start(EdrEventBus *bus) {
  (void)bus;
  if (!edr_a44_split_path_enabled()) {
    return EDR_OK;
  }
  if (s_a44_threads) {
    return EDR_OK;
  }

  edr_a44_init_dynamic_config();
  int thread_count = s_dynamic_config.enabled ? s_dynamic_config.min_threads :
                     edr_get_env_int("EDR_A44_DECODE_THREADS", EDR_A44_DECODE_THREADS, 1, EDR_A44_MAX_THREADS);
  s_a44_num_threads = thread_count;
  s_a44_buf_cap = (uint32_t)edr_get_env_int("EDR_A44_QUEUE_CAP", EDR_A44_QUEUE_CAP, 128, 2048);

  s_a44_buf = (EdrA44QueueItem *)calloc(s_a44_buf_cap, sizeof(EdrA44QueueItem));
  if (!s_a44_buf) {
    return EDR_ERR_INTERNAL;
  }

  InitializeCriticalSection(&s_a44_lock);
  s_a44_head = 0u;
  s_a44_tail = 0u;
  s_a44_life = 1;
  s_a44_drop = 0;
  s_a44_backoff_sync = 0;
  s_a44_extended_data_drop = 0;
  s_a44_userdata_overflow_drop = 0;
  s_a44_total_processed = 0;
  s_a44_total_pushed = 0;
  s_a44_current_depth = 0;
  s_a44_q_depth_sum = 0;
  s_a44_q_depth_samples = 0;
  s_a44_start_time_ns = 0;
  s_a44_total_alloc_bytes = 0;
  s_a44_total_free_bytes = 0;
  s_a44_active_alloc_count = 0;
  s_a44_peak_alloc_count = 0;
  s_a44_circuit_open = 0;
  s_a44_circuit_open_time_ns = 0;
  s_a44_circuit_drop_threshold = 100;
  s_a44_circuit_recovery_timeout_ms = 5000;
  s_a44_rate_limit_qps = 0;
  s_a44_rate_limit_current_count = 0;
  s_a44_rate_limit_window_start_sec = 0;
  memset((void *)s_a44_thread_processed, 0, sizeof(s_a44_thread_processed));

  s_a44_hFree = CreateSemaphoreW(NULL, (LONG)s_a44_buf_cap, (LONG)s_a44_buf_cap, NULL);
  s_a44_hData = CreateSemaphoreW(NULL, 0, (LONG)s_a44_buf_cap, NULL);
  if (!s_a44_hFree || !s_a44_hData) {
    DeleteCriticalSection(&s_a44_lock);
    free(s_a44_buf);
    s_a44_buf = NULL;
    return EDR_ERR_INTERNAL;
  }

  s_a44_threads = (HANDLE *)calloc(s_a44_num_threads, sizeof(HANDLE));
  if (!s_a44_threads) {
    CloseHandle(s_a44_hFree);
    CloseHandle(s_a44_hData);
    DeleteCriticalSection(&s_a44_lock);
    free(s_a44_buf);
    s_a44_buf = NULL;
    return EDR_ERR_INTERNAL;
  }

  for (int i = 0; i < s_a44_num_threads; i++) {
    s_a44_thread_indices[i] = i;
  }

  if (edr_get_env_int("EDR_A44_LOCKFREE_ENABLED", 0, 0, 1)) {
      uint32_t lockfree_cap = (uint32_t)edr_get_env_int("EDR_A44_LOCKFREE_CAP", s_a44_buf_cap / 2, 64, 8192);
      if (edr_a44_lockfree_queue_init(lockfree_cap) == 0) {
          fprintf(stderr, "[a44] lockfree queue enabled, cap=%u\n", lockfree_cap);
      }
  }

  for (int i = 0; i < s_a44_num_threads; i++) {
    s_a44_threads[i] = (HANDLE)_beginthreadex(NULL, 0, edr_a44_decode_trampoline, &s_a44_thread_indices[i], 0, NULL);
    if (!s_a44_threads[i]) {
      for (int j = 0; j < i; j++) {
        CloseHandle(s_a44_threads[j]);
      }
      free(s_a44_threads);
      s_a44_threads = NULL;
      CloseHandle(s_a44_hFree);
      CloseHandle(s_a44_hData);
      DeleteCriticalSection(&s_a44_lock);
      free(s_a44_buf);
      s_a44_buf = NULL;
      return EDR_ERR_INTERNAL;
    }
  }

  fprintf(stderr, "[collector_win] A4.4 split: %d decode threads started (cap=%u)\n",
          s_a44_num_threads, (unsigned)s_a44_buf_cap);
  {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    s_a44_start_time_ns = (int64_t)(u.QuadPart * 100);
  }
  return EDR_OK;
}

int edr_a44_try_push(const EdrA44QueueItem *it) {
  if (!it) {
    return 0;
  }
  if (!s_a44_threads || s_a44_life == 0) {
    return 0;
  }
  if (WaitForSingleObject(s_a44_hFree, 0) != WAIT_OBJECT_0) {
    (void)InterlockedAdd64(&s_a44_drop, 1);
    return 0;
  }
  EnterCriticalSection(&s_a44_lock);
  uint32_t tail = s_a44_tail;
  s_a44_buf[tail % s_a44_buf_cap] = *it;
  s_a44_tail = (s_a44_tail + 1u) % s_a44_buf_cap;
  uint32_t head = s_a44_head;
  uint32_t new_depth = (s_a44_tail >= head) ? (s_a44_tail - head) : (s_a44_buf_cap - head + s_a44_tail);
  LeaveCriticalSection(&s_a44_lock);
  (void)InterlockedExchange64((volatile LONG64 *)&s_a44_current_depth, new_depth);
  (void)InterlockedAdd64(&s_a44_q_depth_sum, new_depth);
  (void)InterlockedIncrement64(&s_a44_q_depth_samples);
  (void)InterlockedAdd64(&s_a44_total_pushed, 1);
  (void)ReleaseSemaphore(s_a44_hData, 1, NULL);
  return 1;
}

uint64_t edr_a44_dropped_total(void) { return (uint64_t)s_a44_drop; }

int edr_a44_get_stats(EdrA44Stats *out_stats) {
  if (!out_stats) {
    return -1;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->dropped_total = (uint64_t)s_a44_drop;
  out_stats->backoff_sync_total = (uint64_t)s_a44_backoff_sync;
  out_stats->queue_capacity = s_a44_buf_cap;
  out_stats->current_depth = (uint32_t)s_a44_current_depth;
  out_stats->active_threads = (uint32_t)(s_a44_threads ? s_a44_num_threads : 0);
  out_stats->total_processed = (uint64_t)s_a44_total_processed;
  out_stats->total_pushed = (uint64_t)s_a44_total_pushed;
  out_stats->batch_size = EDR_A44_BATCH_SIZE;
  if (s_a44_q_depth_samples > 0) {
    out_stats->queue_depth_avg = (double)s_a44_q_depth_sum / (double)s_a44_q_depth_samples;
  } else {
    out_stats->queue_depth_avg = 0.0;
  }
  out_stats->queue_depth_max = s_a44_buf_cap;
  if (out_stats->queue_capacity > 0) {
    out_stats->queue_utilization_pct = (double)out_stats->current_depth * 100.0 / (double)out_stats->queue_capacity;
  }
  for (int i = 0; i < EDR_A44_MAX_THREADS; i++) {
    out_stats->thread_processed[i] = (uint64_t)s_a44_thread_processed[i];
  }
  if (out_stats->active_threads > 1) {
    double mean = (double)out_stats->total_processed / (double)out_stats->active_threads;
    double variance_sum = 0.0;
    for (int i = 0; i < (int)out_stats->active_threads; i++) {
      double diff = (double)out_stats->thread_processed[i] - mean;
      variance_sum += diff * diff;
    }
    double variance = variance_sum / (double)out_stats->active_threads;
    out_stats->load_balance_stddev = sqrt(variance);
  } else {
    out_stats->load_balance_stddev = 0.0;
  }
  if (s_a44_start_time_ns > 0) {
    FILETIME ft_now;
    GetSystemTimePreciseAsFileTime(&ft_now);
    ULARGE_INTEGER u_now;
    u_now.LowPart = ft_now.dwLowDateTime;
    u_now.HighPart = ft_now.dwHighDateTime;
    int64_t now_ns = (int64_t)(u_now.QuadPart * 100);
    int64_t elapsed_ns = now_ns - s_a44_start_time_ns;
    if (elapsed_ns > 0) {
      out_stats->throughput_rps = (double)out_stats->total_processed * 1000000000.0 / (double)elapsed_ns;
    }
    out_stats->start_time_ns = (uint64_t)s_a44_start_time_ns;
    out_stats->last_update_ns = (uint64_t)now_ns;
  }
  out_stats->total_alloc_bytes = (uint64_t)s_a44_total_alloc_bytes;
  out_stats->total_free_bytes = (uint64_t)s_a44_total_free_bytes;
  out_stats->active_alloc_count = (uint32_t)s_a44_active_alloc_count;
  out_stats->peak_alloc_count = (uint32_t)s_a44_peak_alloc_count;
  return 0;
}

void edr_a44_get_drop_reason_stats(uint64_t *out_extended_data_drop, uint64_t *out_userdata_overflow_drop) {
  if (out_extended_data_drop) {
    *out_extended_data_drop = (uint64_t)s_a44_extended_data_drop;
  }
  if (out_userdata_overflow_drop) {
    *out_userdata_overflow_drop = (uint64_t)s_a44_userdata_overflow_drop;
  }
}

int edr_a44_circuit_breaker_set_threshold(uint64_t drop_threshold, uint64_t recovery_timeout_ms) {
  (void)InterlockedExchange64((volatile LONG64 *)&s_a44_circuit_drop_threshold, (int64_t)drop_threshold);
  (void)InterlockedExchange64((volatile LONG64 *)&s_a44_circuit_recovery_timeout_ms, (int64_t)recovery_timeout_ms);
  return 0;
}

int edr_a44_rate_limit_set(uint32_t max_qps) {
  (void)InterlockedExchange((volatile LONG *)&s_a44_rate_limit_qps, (LONG)max_qps);
  return 0;
}

static void edr_a44_check_circuit_breaker(void) {
  uint64_t drop_count = (uint64_t)s_a44_drop;
  uint64_t threshold = (uint64_t)s_a44_circuit_drop_threshold;
  if (drop_count >= threshold && s_a44_circuit_open == 0) {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    (void)InterlockedExchange((volatile LONG *)&s_a44_circuit_open, 1);
    (void)InterlockedExchange64((volatile LONG64 *)&s_a44_circuit_open_time_ns, (int64_t)(u.QuadPart * 100));
    fprintf(stderr, "[collector_win] A4.4 circuit breaker OPEN (drop=%lu threshold=%lu)\n",
            (unsigned long)drop_count, (unsigned long)threshold);
  } else if (s_a44_circuit_open == 1) {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    int64_t now_ns = (int64_t)(u.QuadPart * 100);
    int64_t open_time_ns = (int64_t)s_a44_circuit_open_time_ns;
    uint64_t timeout_ms = (uint64_t)s_a44_circuit_recovery_timeout_ms;
    if ((now_ns - open_time_ns) / 1000000 >= (int64_t)timeout_ms) {
      (void)InterlockedExchange((volatile LONG *)&s_a44_circuit_open, 0);
      fprintf(stderr, "[collector_win] A4.4 circuit breaker CLOSED (recovered)\n");
    }
  }
}

int edr_a44_try_acquire_rate_limit(void) {
  uint32_t max_qps = (uint32_t)s_a44_rate_limit_qps;
  if (max_qps == 0) {
    return 1;
  }
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  SYSTEMTIME st;
  FileTimeToSystemTime(&ft, &st);
  uint32_t current_window = (uint32_t)st.wSecond;
  (void)InterlockedCompareExchange((volatile LONG *)&s_a44_rate_limit_window_start_sec, current_window, s_a44_rate_limit_window_start_sec);
  if (current_window != s_a44_rate_limit_window_start_sec) {
    (void)InterlockedExchange((volatile LONG *)&s_a44_rate_limit_current_count, 0);
    (void)InterlockedExchange((volatile LONG *)&s_a44_rate_limit_window_start_sec, current_window);
  }
  uint32_t current_count = (uint32_t)InterlockedIncrement((volatile LONG *)&s_a44_rate_limit_current_count);
  if (current_count > max_qps) {
    return 0;
  }
  return 1;
}

int edr_a44_enable_perf_measurement(int enable) {
    (void)InterlockedExchange((volatile LONG *)&s_a44_perf_measurement_enabled, enable ? 1 : 0);
    if (enable) {
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_callback_total_ns, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_callback_count, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_callback_max_ns, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_callback_min_ns, UINT64_MAX);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_tdh_total_ns, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_tdh_count, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_tdh_max_ns, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_bus_push_total_ns, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_bus_push_count, 0);
        (void)InterlockedExchange64((volatile LONG64 *)&s_a44_perf_bus_push_max_ns, 0);
    }
    return 0;
}

int edr_a44_get_perf_profile(EdrA44PerfProfile *out_profile) {
    if (!out_profile) {
        return -1;
    }
    memset(out_profile, 0, sizeof(*out_profile));
    out_profile->total_callback_ns = (uint64_t)s_a44_perf_callback_total_ns;
    out_profile->callback_count = (uint64_t)s_a44_perf_callback_count;
    out_profile->max_callback_ns = (uint64_t)s_a44_perf_callback_max_ns;
    out_profile->min_callback_ns = (uint64_t)s_a44_perf_callback_min_ns;
    if (out_profile->callback_count > 0) {
        out_profile->avg_callback_ns = out_profile->total_callback_ns / out_profile->callback_count;
    }
    out_profile->total_tdh_ns = (uint64_t)s_a44_perf_tdh_total_ns;
    out_profile->tdh_count = (uint64_t)s_a44_perf_tdh_count;
    out_profile->max_tdh_ns = (uint64_t)s_a44_perf_tdh_max_ns;
    if (out_profile->tdh_count > 0) {
        out_profile->avg_tdh_ns = out_profile->total_tdh_ns / out_profile->tdh_count;
    }
    out_profile->total_bus_push_ns = (uint64_t)s_a44_perf_bus_push_total_ns;
    out_profile->bus_push_count = (uint64_t)s_a44_perf_bus_push_count;
    out_profile->avg_bus_push_ns = out_profile->bus_push_count > 0 ? out_profile->total_bus_push_ns / out_profile->bus_push_count : 0;
    out_profile->max_bus_push_ns = (uint64_t)s_a44_perf_bus_push_max_ns;
    return 0;
}

static void edr_a44_record_callback_time(uint64_t elapsed_ns) {
    if (!s_a44_perf_measurement_enabled) {
        return;
    }
    (void)InterlockedAdd64((volatile LONG64 *)&s_a44_perf_callback_total_ns, elapsed_ns);
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_perf_callback_count);
    uint64_t old_max = (uint64_t)s_a44_perf_callback_max_ns;
    while (elapsed_ns > old_max && old_max != UINT64_MAX) {
        (void)InterlockedCompareExchange64((volatile LONG64 *)&s_a44_perf_callback_max_ns, elapsed_ns, old_max);
        old_max = (uint64_t)s_a44_perf_callback_max_ns;
    }
    uint64_t old_min = (uint64_t)s_a44_perf_callback_min_ns;
    while (elapsed_ns < old_min && old_min != 0) {
        (void)InterlockedCompareExchange64((volatile LONG64 *)&s_a44_perf_callback_min_ns, elapsed_ns, old_min);
        old_min = (uint64_t)s_a44_perf_callback_min_ns;
    }
}

static void edr_a44_record_tdh_time(uint64_t elapsed_ns) {
    if (!s_a44_perf_measurement_enabled) {
        return;
    }
    (void)InterlockedAdd64((volatile LONG64 *)&s_a44_perf_tdh_total_ns, elapsed_ns);
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_perf_tdh_count);
    uint64_t old_max = (uint64_t)s_a44_perf_tdh_max_ns;
    while (elapsed_ns > old_max) {
        (void)InterlockedCompareExchange64((volatile LONG64 *)&s_a44_perf_tdh_max_ns, elapsed_ns, old_max);
        old_max = (uint64_t)s_a44_perf_tdh_max_ns;
    }
}

static void edr_a44_record_bus_push_time(uint64_t elapsed_ns) {
    if (!s_a44_perf_measurement_enabled) {
        return;
    }
    (void)InterlockedAdd64((volatile LONG64 *)&s_a44_perf_bus_push_total_ns, elapsed_ns);
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_perf_bus_push_count);
    uint64_t old_max = (uint64_t)s_a44_perf_bus_push_max_ns;
    while (elapsed_ns > old_max) {
        (void)InterlockedCompareExchange64((volatile LONG64 *)&s_a44_perf_bus_push_max_ns, elapsed_ns, old_max);
        old_max = (uint64_t)s_a44_perf_bus_push_max_ns;
    }
}

int edr_a44_aggr_init(uint32_t max_pending) {
    if (s_a44_aggr_buf) {
        return 0;
    }
    InitializeCriticalSection(&s_a44_aggr_lock);
    s_a44_aggr_cap = max_pending > 0 ? max_pending : 256;
    s_a44_aggr_buf = (EdrEventSlot *)calloc(s_a44_aggr_cap, sizeof(EdrEventSlot));
    if (!s_a44_aggr_buf) {
        DeleteCriticalSection(&s_a44_aggr_lock);
        return -1;
    }
    s_a44_aggr_count = 0;
    s_a44_aggr_total_count = 0;
    s_a44_aggr_flush_count = 0;
    s_a44_aggr_last_flush_ns = 0;
    return 0;
}

int edr_a44_aggr_add(const EdrEventSlot *slot) {
    if (!slot || !s_a44_aggr_buf) {
        return -1;
    }
    EnterCriticalSection(&s_a44_aggr_lock);
    if (s_a44_aggr_count >= s_a44_aggr_cap) {
        LeaveCriticalSection(&s_a44_aggr_lock);
        return -1;
    }
    s_a44_aggr_buf[s_a44_aggr_count++] = *slot;
    (void)InterlockedIncrement64(&s_a44_aggr_total_count);
    LeaveCriticalSection(&s_a44_aggr_lock);
    return 0;
}

int edr_a44_aggr_flush(void) {
    if (!s_a44_aggr_buf || s_a44_aggr_count == 0) {
        return 0;
    }
    EnterCriticalSection(&s_a44_aggr_lock);
    uint32_t count = s_a44_aggr_count;
    s_a44_aggr_count = 0;
    LeaveCriticalSection(&s_a44_aggr_lock);
    (void)InterlockedIncrement64(&s_a44_aggr_flush_count);
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    (void)InterlockedExchange64(&s_a44_aggr_last_flush_ns, (int64_t)(u.QuadPart * 100));
    (void)count;
    return 0;
}

int edr_a44_aggr_get_stats(EdrA44AggStats *out_stats) {
    if (!out_stats) {
        return -1;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    EnterCriticalSection(&s_a44_aggr_lock);
    out_stats->pending_count = s_a44_aggr_count;
    out_stats->max_pending = s_a44_aggr_cap;
    LeaveCriticalSection(&s_a44_aggr_lock);
    out_stats->aggregated_count = (uint64_t)s_a44_aggr_total_count;
    out_stats->flush_count = (uint64_t)s_a44_aggr_flush_count;
    out_stats->last_flush_ns = (uint64_t)s_a44_aggr_last_flush_ns;
    return 0;
}

int edr_a44_memory_pool_init(uint32_t item_size, uint32_t capacity) {
    if (s_a44_mempool_blocks) {
        return 0;
    }
    if (item_size == 0 || capacity == 0) {
        return -1;
    }
    InitializeCriticalSection(&s_a44_mempool_lock);
    s_a44_mempool_item_size = item_size;
    s_a44_mempool_capacity = capacity;
    s_a44_mempool_total_blocks = 0;
    s_a44_mempool_used_blocks = 0;
    s_a44_mempool_peak_used_blocks = 0;
    s_a44_mempool_total_alloc_bytes = 0;
    s_a44_mempool_total_free_bytes = 0;
    s_a44_mempool_alloc_count = 0;
    s_a44_mempool_free_count = 0;
    s_a44_mempool_alloc_fail_count = 0;
    s_a44_mempool_blocks = (void **)calloc(capacity, sizeof(void *));
    if (!s_a44_mempool_blocks) {
        DeleteCriticalSection(&s_a44_mempool_lock);
        return -1;
    }
    return 0;
}

int edr_a44_memory_pool_set_prealloc(uint32_t prealloc_count) {
    if (!s_a44_mempool_blocks || prealloc_count == 0) {
        return -1;
    }
    EnterCriticalSection(&s_a44_mempool_lock);
    uint32_t allocated = 0;
    for (uint32_t i = 0; i < prealloc_count && s_a44_mempool_total_blocks < s_a44_mempool_capacity; i++) {
        void *block = malloc(s_a44_mempool_item_size);
        if (block) {
            s_a44_mempool_blocks[s_a44_mempool_total_blocks++] = block;
            allocated++;
        } else {
            break;
        }
    }
    LeaveCriticalSection(&s_a44_mempool_lock);
    if (allocated > 0) {
        (void)InterlockedAdd((volatile LONG *)&s_a44_mempool_alloc_count, allocated);
        (void)InterlockedAdd((volatile LONG *)&s_a44_mempool_used_blocks, allocated);
        (void)InterlockedExchange((volatile LONG *)&s_a44_mempool_peak_used_blocks, allocated);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_alloc_bytes, (uint64_t)allocated * (uint64_t)s_a44_mempool_item_size);
    }
    return (int)allocated;
}

void *edr_a44_memory_pool_alloc(void) {
    if (!s_a44_mempool_blocks) {
        return NULL;
    }
    EnterCriticalSection(&s_a44_mempool_lock);
    if (s_a44_mempool_total_blocks > 0) {
        void *block = s_a44_mempool_blocks[--s_a44_mempool_total_blocks];
        s_a44_mempool_blocks[s_a44_mempool_total_blocks] = NULL;
        s_a44_mempool_used_blocks++;
        uint32_t peak = s_a44_mempool_peak_used_blocks;
        if (s_a44_mempool_used_blocks > peak) {
            s_a44_mempool_peak_used_blocks = s_a44_mempool_used_blocks;
        }
        LeaveCriticalSection(&s_a44_mempool_lock);
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_alloc_count);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_alloc_bytes, s_a44_mempool_item_size);
        return block;
    }
    LeaveCriticalSection(&s_a44_mempool_lock);
    void *block = malloc(s_a44_mempool_item_size);
    if (block) {
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_alloc_count);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_alloc_bytes, s_a44_mempool_item_size);
    } else {
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_alloc_fail_count);
    }
    return block;
}

void edr_a44_memory_pool_free(void *ptr) {
    if (!ptr || !s_a44_mempool_blocks) {
        if (ptr) {
            free(ptr);
        }
        return;
    }
    EnterCriticalSection(&s_a44_mempool_lock);
    if (s_a44_mempool_total_blocks < s_a44_mempool_capacity) {
        s_a44_mempool_blocks[s_a44_mempool_total_blocks++] = ptr;
        s_a44_mempool_used_blocks--;
        LeaveCriticalSection(&s_a44_mempool_lock);
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_free_count);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_free_bytes, s_a44_mempool_item_size);
    } else {
        LeaveCriticalSection(&s_a44_mempool_lock);
        free(ptr);
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_free_count);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_free_bytes, s_a44_mempool_item_size);
    }
}

int edr_a44_memory_pool_get_stats(EdrA44MemoryPoolStats *out_stats) {
    if (!out_stats) {
        return -1;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    EnterCriticalSection(&s_a44_mempool_lock);
    out_stats->pool_item_size = s_a44_mempool_item_size;
    out_stats->pool_capacity = s_a44_mempool_capacity;
    out_stats->total_blocks = s_a44_mempool_total_blocks;
    out_stats->used_blocks = s_a44_mempool_used_blocks;
    out_stats->peak_used_blocks = s_a44_mempool_peak_used_blocks;
    LeaveCriticalSection(&s_a44_mempool_lock);
    out_stats->total_alloc_bytes = (uint64_t)s_a44_mempool_alloc_count * (uint64_t)s_a44_mempool_item_size;
    out_stats->total_free_bytes = (uint64_t)s_a44_mempool_free_count * (uint64_t)s_a44_mempool_item_size;
    out_stats->alloc_count = s_a44_mempool_alloc_count;
    out_stats->free_count = s_a44_mempool_free_count;
    out_stats->alloc_fail_count = s_a44_mempool_alloc_fail_count;
    uint32_t total_allocs = s_a44_mempool_alloc_count;
    if (total_allocs > 0) {
        out_stats->hit_rate_pct = (double)(total_allocs - s_a44_mempool_alloc_fail_count) * 100.0 / (double)total_allocs;
    }
    return 0;
}

int edr_a44_memory_pool_trim(uint32_t target_free_count) {
    if (!s_a44_mempool_blocks) {
        return 0;
    }
    EnterCriticalSection(&s_a44_mempool_lock);
    uint32_t trimmed = 0;
    while (s_a44_mempool_total_blocks > target_free_count && s_a44_mempool_total_blocks > 0) {
        void *block = s_a44_mempool_blocks[--s_a44_mempool_total_blocks];
        s_a44_mempool_blocks[s_a44_mempool_total_blocks] = NULL;
        LeaveCriticalSection(&s_a44_mempool_lock);
        free(block);
        trimmed++;
        (void)InterlockedIncrement((volatile LONG *)&s_a44_mempool_free_count);
        (void)InterlockedAdd64((volatile LONG64 *)&s_a44_mempool_total_free_bytes, s_a44_mempool_item_size);
        EnterCriticalSection(&s_a44_mempool_lock);
    }
    LeaveCriticalSection(&s_a44_mempool_lock);
    return (int)trimmed;
}

void edr_a44_memory_pool_shutdown(void) {
    if (!s_a44_mempool_blocks) {
        return;
    }
    EnterCriticalSection(&s_a44_mempool_lock);
    for (uint32_t i = 0; i < s_a44_mempool_total_blocks; i++) {
        free(s_a44_mempool_blocks[i]);
    }
    free(s_a44_mempool_blocks);
    s_a44_mempool_blocks = NULL;
    s_a44_mempool_total_blocks = 0;
    s_a44_mempool_used_blocks = 0;
    LeaveCriticalSection(&s_a44_mempool_lock);
    DeleteCriticalSection(&s_a44_mempool_lock);
}

int edr_a44_lockfree_queue_init(uint32_t capacity) {
    if (s_a44_lockfree_buf) {
        return 0;
    }
    s_a44_lockfree_cap = capacity;
    s_a44_lockfree_item_size = sizeof(EdrA44QueueItem);
    size_t total_size = (size_t)capacity * (size_t)s_a44_lockfree_item_size;
    s_a44_lockfree_buf = calloc(1, total_size);
    if (!s_a44_lockfree_buf) {
        return -1;
    }
    s_a44_lockfree_head = 0;
    s_a44_lockfree_tail = 0;
    s_a44_lockfree_try_push_count = 0;
    s_a44_lockfree_push_success_count = 0;
    s_a44_lockfree_pop_count = 0;
    s_a44_lockfree_pop_success_count = 0;
    s_a44_lockfree_empty_count = 0;
    s_a44_cache_friendly_mode = edr_a44_yes(getenv("EDR_A44_CACHE_FRIENDLY")) ? 1 : 0;
    if (s_a44_cache_friendly_mode) {
        memset(s_a44_cacheline_padding, 0, sizeof(s_a44_cacheline_padding));
    }
    return 0;
}

int edr_a44_lockfree_queue_try_push(const void *item, uint32_t item_size) {
    if (!item || !s_a44_lockfree_buf) {
        return -1;
    }
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_lockfree_try_push_count);
    LONG head = s_a44_lockfree_head;
    LONG tail = s_a44_lockfree_tail;
    LONG next_tail = (tail + 1) % s_a44_lockfree_cap;
    if (next_tail == head) {
        (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_lockfree_empty_count);
        return 0;
    }
    uint8_t *slot = (uint8_t *)s_a44_lockfree_buf + (size_t)tail * (size_t)item_size;
    memcpy(slot, item, item_size);
    _InterlockedExchange(&s_a44_lockfree_tail, next_tail);
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_lockfree_push_success_count);
    return 1;
}

int edr_a44_lockfree_queue_try_pop(void *out_item, uint32_t *out_item_size) {
    if (!out_item || !s_a44_lockfree_buf) {
        return -1;
    }
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_lockfree_pop_count);
    LONG head = s_a44_lockfree_head;
    LONG tail = s_a44_lockfree_tail;
    if (head == tail) {
        return 0;
    }
    uint8_t *slot = (uint8_t *)s_a44_lockfree_buf + (size_t)head * (size_t)s_a44_lockfree_item_size;
    memcpy(out_item, slot, s_a44_lockfree_item_size);
    LONG next_head = (head + 1) % s_a44_lockfree_cap;
    _InterlockedExchange(&s_a44_lockfree_head, next_head);
    if (out_item_size) {
        *out_item_size = s_a44_lockfree_item_size;
    }
    (void)InterlockedIncrement64((volatile LONG64 *)&s_a44_lockfree_pop_success_count);
    return 1;
}

int edr_a44_lockfree_queue_get_stats(EdrA44ConcurrencyStats *out_stats) {
    if (!out_stats) {
        return -1;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->lockfree_try_push_count = s_a44_lockfree_try_push_count;
    out_stats->lockfree_push_success_count = s_a44_lockfree_push_success_count;
    out_stats->lockfree_pop_count = s_a44_lockfree_pop_count;
    out_stats->lockfree_pop_success_count = s_a44_lockfree_pop_success_count;
    out_stats->lockfree_empty_count = s_a44_lockfree_empty_count;
    out_stats->padding_bytes = s_a44_cache_friendly_mode ? (uint32_t)sizeof(s_a44_cacheline_padding) : 0;
    return 0;
}

void edr_a44_lockfree_queue_shutdown(void) {
    if (s_a44_lockfree_buf) {
        free(s_a44_lockfree_buf);
        s_a44_lockfree_buf = NULL;
        s_a44_lockfree_cap = 0;
    }
}

int edr_a44_enable_cache_friendly_mode(int enable) {
    s_a44_cache_friendly_mode = enable ? 1 : 0;
    return 0;
}

int edr_a44_get_concurrency_stats(EdrA44ConcurrencyStats *out_stats) {
    return edr_a44_lockfree_queue_get_stats(out_stats);
}

int edr_a44_adaptive_init(EdrA44AdaptiveMode mode) {
    s_adaptive_mode = mode;
    s_adaptive_enabled = (mode != EDR_A44_ADAPTIVE_MODE_FIXED) ? 1 : 0;
    s_throughput_history_head = 0;
    s_throughput_history_count = 0;
    s_scale_up_threshold = 80.0;
    s_scale_down_threshold = 20.0;
    s_scale_up_cooldown_ms = 10000;
    s_scale_down_cooldown_ms = 30000;
    s_last_scale_action = 0;
    s_last_scale_time_ns = 0;
    s_trend_slope = 0.0;
    s_prediction_accuracy = 0.0;
    memset(s_throughput_history, 0, sizeof(s_throughput_history));
    const char *env_thresholds = getenv("EDR_A44_ADAPTIVE_THRESHOLDS");
    if (env_thresholds && strlen(env_thresholds) > 0) {
        double up_th = 80.0, down_th = 20.0;
        if (sscanf(env_thresholds, "%lf,%lf", &up_th, &down_th) == 2) {
            s_scale_up_threshold = up_th;
            s_scale_down_threshold = down_th;
        }
    }
    fprintf(stderr, "[collector_win] A4.4 adaptive mode: %d enabled=%d up=%.1f%% down=%.1f%%\n",
            mode, s_adaptive_enabled, s_scale_up_threshold, s_scale_down_threshold);
    return 0;
}

int edr_a44_adaptive_get_config(EdrA44AdaptiveConfig *out_config) {
    if (!out_config) {
        return -1;
    }
    memset(out_config, 0, sizeof(*out_config));
    out_config->mode = s_adaptive_mode;
    out_config->enabled = s_adaptive_enabled;
    out_config->trend_window_size = 900;
    out_config->scale_up_threshold = s_scale_up_threshold;
    out_config->scale_down_threshold = s_scale_down_threshold;
    out_config->scale_up_cooldown_ms = s_scale_up_cooldown_ms;
    out_config->scale_down_cooldown_ms = s_scale_down_cooldown_ms;
    out_config->prediction_accuracy = s_prediction_accuracy;
    out_config->last_scale_action = s_last_scale_action;
    out_config->last_scale_time_ns = (uint64_t)s_last_scale_time_ns;
    return 0;
}

int edr_a44_adaptive_set_thresholds(double scale_up, double scale_down) {
    s_scale_up_threshold = scale_up;
    s_scale_down_threshold = scale_down;
    return 0;
}

int edr_a44_adaptive_update_throughput(double throughput) {
    if (!s_adaptive_enabled) {
        return 0;
    }
    s_throughput_history[s_throughput_history_head] = throughput;
    s_throughput_history_head = (s_throughput_history_head + 1) % 900;
    if (s_throughput_history_count < 900) {
        s_throughput_history_count++;
    }
    if (s_adaptive_mode == EDR_A44_ADAPTIVE_MODE_PREDICTIVE && s_throughput_history_count >= 60) {
        double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_xx = 0.0;
        int n = (s_throughput_history_count < 60) ? s_throughput_history_count : 60;
        for (int i = 0; i < n; i++) {
            double x = (double)i;
            uint32_t idx = (s_throughput_history_head + 900 - n + i) % 900;
            double y = s_throughput_history[idx];
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_xx += x * x;
        }
        double denom = n * sum_xx - sum_x * sum_x;
        if (denom != 0.0) {
            s_trend_slope = (n * sum_xy - sum_x * sum_y) / denom;
        }
        double predicted = 0.0;
        for (int i = 0; i < n; i++) {
            uint32_t idx = (s_throughput_history_head + 900 - n + i) % 900;
            predicted += s_throughput_history[idx];
        }
        s_prediction_accuracy = predicted / (double)n;
    }
    return 0;
}

int edr_a44_adaptive_get_recommendation(EdrA44ScalingRecommendation *out_rec) {
    if (!out_rec || !s_adaptive_enabled) {
        return -1;
    }
    memset(out_rec, 0, sizeof(*out_rec));
    int n1 = (s_throughput_history_count < 60) ? s_throughput_history_count : 60;
    int n5 = (s_throughput_history_count < 300) ? s_throughput_history_count : 300;
    int n15 = s_throughput_history_count;
    double sum1 = 0.0, sum5 = 0.0, sum15 = 0.0;
    for (int i = 0; i < n1; i++) {
        uint32_t idx = (s_throughput_history_head + 900 - n1 + i) % 900;
        sum1 += s_throughput_history[idx];
    }
    for (int i = 0; i < n5; i++) {
        uint32_t idx = (s_throughput_history_head + 900 - n5 + i) % 900;
        sum5 += s_throughput_history[idx];
    }
    for (int i = 0; i < n15; i++) {
        uint32_t idx = (s_throughput_history_head + 900 - n15 + i) % 900;
        sum15 += s_throughput_history[idx];
    }
    out_rec->current_throughput = (n1 > 0) ? (sum1 / (double)n1) : 0.0;
    out_rec->avg_throughput_last_1m = (n1 > 0) ? (sum1 / (double)n1) : 0.0;
    out_rec->avg_throughput_last_5m = (n5 > 0) ? (sum5 / (double)n5) : 0.0;
    out_rec->avg_throughput_last_15m = (n15 > 0) ? (sum15 / (double)n15) : 0.0;
    out_rec->trend_slope = s_trend_slope;
    out_rec->predicted_throughput_1m = out_rec->avg_throughput_last_1m + s_trend_slope * 60.0;
    if (out_rec->predicted_throughput_1m < 0) {
        out_rec->predicted_throughput_1m = 0;
    }
    EdrA44Stats stats;
    if (edr_a44_get_stats(&stats) == 0) {
        out_rec->recommended_threads = (int)stats.active_threads;
        if (out_rec->predicted_throughput_1m > s_scale_up_threshold && stats.queue_utilization_pct > 50.0) {
            out_rec->recommended_threads = (int)stats.active_threads + 1;
            if (out_rec->recommended_threads > EDR_A44_MAX_THREADS) {
                out_rec->recommended_threads = EDR_A44_MAX_THREADS;
            }
            out_rec->scaling_score = out_rec->predicted_throughput_1m / 100.0;
        } else if (out_rec->predicted_throughput_1m < s_scale_down_threshold && stats.queue_utilization_pct < 30.0) {
            out_rec->recommended_threads = (int)stats.active_threads - 1;
            if (out_rec->recommended_threads < s_dynamic_config.min_threads) {
                out_rec->recommended_threads = s_dynamic_config.min_threads;
            }
            out_rec->scaling_score = 1.0 - (out_rec->predicted_throughput_1m / 100.0);
        } else {
            out_rec->scaling_score = 0.5;
        }
    }
    out_rec->confidence_level = (s_throughput_history_count >= 300) ? 3 : (s_throughput_history_count >= 60) ? 2 : 1;
    return 0;
}

int edr_a44_adaptive_execute_scale(int target_threads) {
    if (!s_adaptive_enabled) {
        return -1;
    }
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    int64_t now_ns = (int64_t)(u.QuadPart * 100);
    int cooldown_ms = (target_threads > (int)s_dynamic_config.min_threads) ? s_scale_up_cooldown_ms : s_scale_down_cooldown_ms;
    if ((now_ns - s_last_scale_time_ns) / 1000000 < cooldown_ms) {
        return -2;
    }
    int current_threads = s_a44_num_threads;
    if (target_threads == current_threads) {
        return 0;
    }
    int result = edr_a44_set_thread_count(target_threads);
    if (result == 0) {
        s_last_scale_time_ns = now_ns;
        s_last_scale_action = target_threads > current_threads ? 1 : -1;
        fprintf(stderr, "[collector_win] A4.4 adaptive scale: %d -> %d\n", current_threads, target_threads);
    }
    return result;
}

int edr_a44_set_thread_count(int target_count) {
    if (!s_a44_threads || !s_dynamic_config.enabled) {
        return -1;
    }
    if (target_count < s_dynamic_config.min_threads || target_count > s_dynamic_config.max_threads) {
        return -1;
    }
    EnterCriticalSection(&s_thread_reconfig_lock);
    int current_count = s_a44_num_threads;
    if (target_count == current_count) {
        LeaveCriticalSection(&s_thread_reconfig_lock);
        return 0;
    }
    if (target_count > current_count) {
        HANDLE *new_threads = (HANDLE *)calloc(target_count, sizeof(HANDLE));
        if (!new_threads) {
            LeaveCriticalSection(&s_thread_reconfig_lock);
            return -1;
        }
        for (int i = 0; i < current_count; i++) {
            new_threads[i] = s_a44_threads[i];
        }
        int started = current_count;
        for (int i = current_count; i < target_count; i++) {
            new_threads[i] = (HANDLE)_beginthreadex(NULL, 0, edr_a44_decode_trampoline, NULL, 0, NULL);
            if (new_threads[i]) {
                started++;
            } else {
                break;
            }
        }
        free(s_a44_threads);
        s_a44_threads = new_threads;
        s_a44_num_threads = started;
        fprintf(stderr, "[collector_win] A4.4 threads increased: %d -> %d\n", current_count, s_a44_num_threads);
    } else {
        for (int i = target_count; i < current_count; i++) {
            (void)ReleaseSemaphore(s_a44_hData, 1, NULL);
        }
        for (int i = target_count; i < current_count; i++) {
            (void)WaitForSingleObject(s_a44_threads[i], 5000);
            CloseHandle(s_a44_threads[i]);
        }
        HANDLE *new_threads = (HANDLE *)calloc(target_count, sizeof(HANDLE));
        if (new_threads) {
            for (int i = 0; i < target_count; i++) {
                new_threads[i] = s_a44_threads[i];
            }
            free(s_a44_threads);
            s_a44_threads = new_threads;
            s_a44_num_threads = target_count;
            fprintf(stderr, "[collector_win] A4.4 threads decreased: %d -> %d\n", current_count, s_a44_num_threads);
        }
    }
    LeaveCriticalSection(&s_thread_reconfig_lock);
    return 0;
}

int edr_a44_get_dynamic_config(EdrA44DynamicConfig *out_config) {
    if (!out_config) {
        return -1;
    }
    memcpy(out_config, &s_dynamic_config, sizeof(s_dynamic_config));
    return 0;
}

int edr_a44_adjust_threads_dynamically(void) {
    if (!s_dynamic_config.enabled || !s_a44_threads) {
        return 0;
    }
    uint64_t now = GetTickCount64();
    uint64_t last = (uint64_t)InterlockedCompareExchange64(&s_last_adjust_time, 0, 0);
    if (now - last < (uint64_t)s_dynamic_config.cooldown_ms) {
        return 0;
    }
    EdrA44Stats stats;
    if (edr_a44_get_stats(&stats) != 0) {
        return 0;
    }
    int current_threads = (int)stats.active_threads;
    int target_threads = current_threads;
    int capacity_percent = (int)(stats.current_depth * 100 / stats.queue_capacity);
    if (capacity_percent >= s_dynamic_config.high_water_mark && current_threads < s_dynamic_config.max_threads) {
        target_threads = current_threads + 1;
    } else if (capacity_percent <= s_dynamic_config.low_water_mark && current_threads > s_dynamic_config.min_threads) {
        target_threads = current_threads - 1;
    }
    if (target_threads != current_threads) {
        (void)InterlockedExchange64(&s_last_adjust_time, (LONG64)now);
        return edr_a44_set_thread_count(target_threads);
    }
    return 0;
}

int edr_a44_get_health_report(EdrA44HealthReport *out_report) {
    if (!out_report) {
        return -1;
    }
    memset(out_report, 0, sizeof(*out_report));
    EdrA44Stats stats;
    if (edr_a44_get_stats(&stats) != 0) {
        out_report->status = EDR_A44_HEALTH_ERROR;
        return -1;
    }
    out_report->active_threads = (int)stats.active_threads;
    out_report->queue_capacity = stats.queue_capacity;
    out_report->current_depth = stats.current_depth;
    out_report->queue_utilization_pct = stats.queue_utilization_pct;
    out_report->dropped_total = stats.dropped_total;
    out_report->total_processed = stats.total_processed;
    out_report->throughput_rps = stats.throughput_rps;
    out_report->is_dropping = stats.dropped_total > 0 ? 1 : 0;
    out_report->is_backing_off = stats.backoff_sync_total > 0 ? 1 : 0;
    EdrA44DynamicConfig dyn_cfg;
    edr_a44_get_dynamic_config(&dyn_cfg);
    out_report->dynamic_adjustment_enabled = dyn_cfg.enabled;
    out_report->circuit_breaker_open = s_a44_circuit_open;
    out_report->circuit_breaker_open_time_ns = (uint64_t)s_a44_circuit_open_time_ns;
    out_report->rate_limit_qps = (uint32_t)s_a44_rate_limit_qps;
    out_report->current_qps = (uint32_t)s_a44_rate_limit_current_count;
    if (s_a44_circuit_open) {
        out_report->status = EDR_A44_HEALTH_CRITICAL;
    } else if (stats.queue_utilization_pct >= 95.0 || stats.dropped_total > 1000) {
        out_report->status = EDR_A44_HEALTH_CRITICAL;
    } else if (stats.queue_utilization_pct >= 80.0 || stats.dropped_total > 100) {
        out_report->status = EDR_A44_HEALTH_ERROR;
    } else if (stats.queue_utilization_pct >= 60.0 || stats.dropped_total > 10) {
        out_report->status = EDR_A44_HEALTH_WARNING;
    } else {
        out_report->status = EDR_A44_HEALTH_OK;
    }
    return 0;
}

/* LONG/LONG64 for Win32 Interlocked* (MSVC C4057); pipeline flags below same. */
static volatile LONG s_e2e_tracking_enabled;
static volatile LONG64 s_e2e_total_events;
static volatile LONG64 s_e2e_dropped_events;
static volatile LONG64 s_e2e_latency_min_ns;
static volatile LONG64 s_e2e_latency_max_ns;
static volatile LONG64 s_e2e_latency_sum_ns;
static volatile LONG64 s_e2e_latency_count;
static volatile uint64_t s_e2e_latency_samples[1000];
static volatile LONG s_e2e_latency_sample_head;
static volatile LONG s_e2e_latency_sample_count;
static volatile LONG s_pipeline_prefetch_enabled;
static volatile LONG s_pipeline_parallel_enabled;
static volatile LONG s_pipeline_batch_timeout_ms;
static volatile LONG s_pipeline_max_batch_size;

int edr_a44_e2e_enable_tracking(int enable) {
    (void)InterlockedExchange(&s_e2e_tracking_enabled, (LONG)enable);
    return 0;
}

int edr_a44_e2e_record_event(uint64_t timestamp_ns) {
    if (!s_e2e_tracking_enabled) {
        return 0;
    }
    (void)InterlockedIncrement64(&s_e2e_total_events);
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    uint64_t now_ns = (uint64_t)(u.QuadPart * 100);
    if (timestamp_ns > 0 && now_ns > timestamp_ns) {
        uint64_t latency = now_ns - timestamp_ns;
        uint64_t old_min = (uint64_t)s_e2e_latency_min_ns;
        while (latency < old_min && old_min != 0) {
            (void)InterlockedCompareExchange64(&s_e2e_latency_min_ns, (LONG64)latency, (LONG64)old_min);
            old_min = (uint64_t)s_e2e_latency_min_ns;
        }
        uint64_t old_max = (uint64_t)s_e2e_latency_max_ns;
        while (latency > old_max) {
            (void)InterlockedCompareExchange64(&s_e2e_latency_max_ns, (LONG64)latency, (LONG64)old_max);
            old_max = (uint64_t)s_e2e_latency_max_ns;
        }
        (void)InterlockedAdd64(&s_e2e_latency_sum_ns, (LONG64)latency);
        (void)InterlockedIncrement64(&s_e2e_latency_count);
        uint32_t idx = (uint32_t)InterlockedIncrement(&s_e2e_latency_sample_head) % 1000;
        s_e2e_latency_samples[idx] = latency;
        (void)InterlockedIncrement(&s_e2e_latency_sample_count);
    }
    return 0;
}

int edr_a44_e2e_get_stats(EdrA44EndToEndStats *out_stats) {
    if (!out_stats) {
        return -1;
    }
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->total_events = (uint64_t)s_e2e_total_events;
    out_stats->dropped_events = (uint64_t)s_e2e_dropped_events;
    out_stats->latency_min_ns = (uint64_t)s_e2e_latency_min_ns;
    out_stats->latency_max_ns = (uint64_t)s_e2e_latency_max_ns;
    if (s_e2e_latency_count > 0) {
        out_stats->latency_avg_ns = (uint64_t)((double)s_e2e_latency_sum_ns / (double)s_e2e_latency_count);
    }
    uint32_t sample_count = (uint32_t)s_e2e_latency_sample_count;
    if (sample_count > 0) {
        uint64_t sorted[1000];
        uint32_t copy_count = sample_count < 1000 ? sample_count : 1000;
        for (uint32_t i = 0; i < copy_count; i++) {
            sorted[i] = s_e2e_latency_samples[i];
        }
        for (uint32_t i = 1; i < copy_count; i++) {
            for (uint32_t j = 0; j < copy_count - i; j++) {
                if (sorted[j] > sorted[j + 1]) {
                    uint64_t tmp = sorted[j];
                    sorted[j] = sorted[j + 1];
                    sorted[j + 1] = tmp;
                }
            }
        }
        uint32_t p50_idx = (copy_count * 50) / 100;
        uint32_t p95_idx = (copy_count * 95) / 100;
        uint32_t p99_idx = (copy_count * 99) / 100;
        if (p50_idx < copy_count) out_stats->latency_p50_ns = sorted[p50_idx];
        if (p95_idx < copy_count) out_stats->latency_p95_ns = sorted[p95_idx];
        if (p99_idx < copy_count) out_stats->latency_p99_ns = sorted[p99_idx];
    }
    EdrA44Stats a44_stats;
    if (edr_a44_get_stats(&a44_stats) == 0) {
        out_stats->throughput_avg_rps = a44_stats.throughput_rps;
        out_stats->queue_util_avg_pct = a44_stats.queue_utilization_pct;
        out_stats->queue_depth_max = a44_stats.queue_capacity;
    }
    return 0;
}

int edr_a44_e2e_reset_stats(void) {
    (void)InterlockedExchange64(&s_e2e_total_events, 0);
    (void)InterlockedExchange64(&s_e2e_dropped_events, 0);
    (void)InterlockedExchange64(&s_e2e_latency_min_ns, 0);
    (void)InterlockedExchange64(&s_e2e_latency_max_ns, 0);
    (void)InterlockedExchange64(&s_e2e_latency_sum_ns, 0);
    (void)InterlockedExchange64(&s_e2e_latency_count, 0);
    (void)InterlockedExchange(&s_e2e_latency_sample_head, 0);
    (void)InterlockedExchange(&s_e2e_latency_sample_count, 0);
    return 0;
}

int edr_a44_pipeline_get_config(EdrA44PipelineConfig *out_config) {
    if (!out_config) {
        return -1;
    }
    out_config->prefetch_enabled = s_pipeline_prefetch_enabled;
    out_config->pipeline_parallel_enabled = s_pipeline_parallel_enabled;
    out_config->batch_timeout_ms = s_pipeline_batch_timeout_ms;
    out_config->max_batch_size = s_pipeline_max_batch_size;
    return 0;
}

int edr_a44_pipeline_set_config(const EdrA44PipelineConfig *config) {
    if (!config) {
        return -1;
    }
    (void)InterlockedExchange(&s_pipeline_prefetch_enabled, config->prefetch_enabled);
    (void)InterlockedExchange(&s_pipeline_parallel_enabled, config->pipeline_parallel_enabled);
    (void)InterlockedExchange(&s_pipeline_batch_timeout_ms, config->batch_timeout_ms);
    (void)InterlockedExchange(&s_pipeline_max_batch_size, config->max_batch_size);
    return 0;
}

int edr_a44_pipeline_prefetch_start(int lookahead_count) {
    (void)InterlockedExchange(&s_pipeline_prefetch_enabled, 1);
    return 0;
}

void edr_a44_pipeline_prefetch_stop(void) {
    (void)InterlockedExchange(&s_pipeline_prefetch_enabled, 0);
}

int edr_a44_pipeline_span_begin(EdrA44PipelineSpan *span) {
    if (!span) {
        return -1;
    }
    memset(span, 0, sizeof(*span));
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    span->callback_enter_ns = (uint64_t)(u.QuadPart * 100);
    return 0;
}

int edr_a44_pipeline_span_end(EdrA44PipelineSpan *span) {
    if (!span) {
        return -1;
    }
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    uint64_t now_ns = (uint64_t)(u.QuadPart * 100);
    (void)now_ns;
    return 0;
}

int edr_a44_pipeline_span_record(const EdrA44PipelineSpan *span) {
    if (!span) {
        return -1;
    }
    (void)span;
    return 0;
}

void edr_a44_split_path_stop(void) {
  if (!s_a44_threads) {
    return;
  }
  (void)InterlockedExchange(&s_a44_life, 0);
  for (int i = 0; i < s_a44_num_threads; i++) {
    (void)ReleaseSemaphore(s_a44_hData, 1, NULL);
  }
  for (int i = 0; i < s_a44_num_threads; i++) {
    (void)WaitForSingleObject(s_a44_threads[i], 25000);
    CloseHandle(s_a44_threads[i]);
  }
  free(s_a44_threads);
  s_a44_threads = NULL;
  if (s_a44_hFree) {
    CloseHandle(s_a44_hFree);
    s_a44_hFree = NULL;
  }
  if (s_a44_hData) {
    CloseHandle(s_a44_hData);
    s_a44_hData = NULL;
  }
  DeleteCriticalSection(&s_a44_lock);
  if (s_dynamic_config.enabled) {
    DeleteCriticalSection(&s_thread_reconfig_lock);
  }
  free(s_a44_buf);
  s_a44_buf = NULL;
  fprintf(stderr, "[collector_win] A4.4 split: decode joined (a44_drop=%" PRId64 " a44_backoff=%" PRId64 ")\n",
          (int64_t)s_a44_drop, (int64_t)s_a44_backoff_sync);
}

#endif