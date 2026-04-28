/**
 * A4.4 第二期（仅 Windows、默认关）：`EDR_A44_SPLIT_PATH=1` 时 ETW 收/解 有界分径，见
 * Cauld `ADR_A4.4_ETW_Receive_Path_Decouple.md` v0.3+。
 */
#ifndef EDR_EDR_A44_SPLIT_PATH_WIN_H
#define EDR_EDR_A44_SPLIT_PATH_WIN_H

#if defined(_WIN32)
#include <windows.h>
#include "edr/error.h"
#include "edr/event_bus.h"
#include "edr/types.h"

#include <evntcons.h>
#include <stdint.h>

#ifndef EDR_A44_MAX_USERDATA
#define EDR_A44_MAX_USERDATA 32768u
#endif

/** A44统计结构体 */
typedef struct {
    uint64_t dropped_total;
    uint64_t backoff_sync_total;
    double queue_depth_avg;
    uint32_t queue_depth_max;
    uint64_t thread_busy_time[4];
    uint64_t thread_processed[4];
    uint32_t active_threads;
    uint64_t total_processed;
    uint64_t total_pushed;
    uint32_t queue_capacity;
    uint32_t current_depth;
    double load_balance_stddev;
    double throughput_rps;
    uint64_t start_time_ns;
    uint64_t last_update_ns;
    uint32_t batch_size;
    double queue_utilization_pct;
    uint64_t total_alloc_bytes;
    uint64_t total_free_bytes;
    uint32_t active_alloc_count;
    uint32_t peak_alloc_count;
} EdrA44Stats;

/** 动态线程调整配置 */
typedef struct {
    int enabled;
    int min_threads;
    int max_threads;
    int high_water_mark;
    int low_water_mark;
    int cooldown_ms;
} EdrA44DynamicConfig;

typedef enum {
    EDR_A44_HEALTH_OK = 0,
    EDR_A44_HEALTH_WARNING = 1,
    EDR_A44_HEALTH_ERROR = 2,
    EDR_A44_HEALTH_CRITICAL = 3
} EdrA44HealthStatus;

typedef struct {
    EdrA44HealthStatus status;
    int active_threads;
    uint32_t queue_capacity;
    uint32_t current_depth;
    double queue_utilization_pct;
    uint64_t dropped_total;
    uint64_t total_processed;
    double throughput_rps;
    int is_dropping;
    int is_backing_off;
    int dynamic_adjustment_enabled;
    int circuit_breaker_open;
    uint64_t circuit_breaker_open_time_ns;
    uint32_t rate_limit_qps;
    uint32_t current_qps;
} EdrA44HealthReport;

/** 有界入队一帧。解线程栈上 `EVENT_RECORD::UserData` 指向本副本 `ud`。 */
typedef struct {
  uint64_t ts_ns;
  EdrEventType ty;
  char tag[16];
  EVENT_HEADER evh;
  uint16_t udlen;
  uint16_t edcount;
  uint8_t resv[4];
  /** 与 `EVENT_RECORD::BufferContext` 一致（新 SDK 为 `ETW_BUFFER_CONTEXT`，非 uint64） */
  ETW_BUFFER_CONTEXT buffer_context;
  uint8_t ud[EDR_A44_MAX_USERDATA];
} EdrA44QueueItem;

int edr_a44_split_path_enabled(void);
EdrError edr_a44_split_path_start(EdrEventBus *bus);
void edr_a44_split_path_stop(void);

/**
 * 填 `out`。reason_sync：0=可入队 1=ExtendedData 非 0 须同步 2=UserData 超长须同步
 * 成功返回 0；否则不填可入队字段。
 */
int edr_a44_item_pack(PEVENT_RECORD r, uint64_t ts_ns, EdrEventType ty, const char *tag, EdrA44QueueItem *out,
                      int *reason_sync);

int edr_a44_try_push(const EdrA44QueueItem *it);
uint64_t edr_a44_dropped_total(void);
void edr_a44_item_to_event_record(const EdrA44QueueItem *it, EVENT_RECORD *er);

int edr_a44_get_stats(EdrA44Stats *out_stats);
void edr_a44_get_drop_reason_stats(uint64_t *out_extended_data_drop, uint64_t *out_userdata_overflow_drop);

int edr_a44_set_thread_count(int target_count);
int edr_a44_get_dynamic_config(EdrA44DynamicConfig *out_config);
int edr_a44_adjust_threads_dynamically(void);
int edr_a44_get_health_report(EdrA44HealthReport *out_report);

int edr_a44_circuit_breaker_set_threshold(uint64_t drop_threshold, uint64_t recovery_timeout_ms);
int edr_a44_rate_limit_set(uint32_t max_qps);
int edr_a44_try_acquire_rate_limit(void);

typedef struct {
    uint64_t total_callback_ns;
    uint64_t callback_count;
    uint64_t avg_callback_ns;
    uint64_t max_callback_ns;
    uint64_t min_callback_ns;
    uint64_t total_tdh_ns;
    uint64_t tdh_count;
    uint64_t avg_tdh_ns;
    uint64_t max_tdh_ns;
    uint64_t total_bus_push_ns;
    uint64_t bus_push_count;
    uint64_t avg_bus_push_ns;
    uint64_t max_bus_push_ns;
} EdrA44PerfProfile;

int edr_a44_get_perf_profile(EdrA44PerfProfile *out_profile);
int edr_a44_enable_perf_measurement(int enable);

typedef struct {
    uint64_t aggregated_count;
    uint64_t flush_count;
    uint32_t pending_count;
    uint32_t max_pending;
    uint64_t last_flush_ns;
} EdrA44AggStats;

int edr_aggr_init(uint32_t max_pending);
int edr_a44_aggr_add(const EdrEventSlot *slot);
int edr_a44_aggr_flush(void);
int edr_a44_aggr_get_stats(EdrA44AggStats *out_stats);

typedef struct {
    uint32_t pool_item_size;
    uint32_t pool_capacity;
    uint32_t total_blocks;
    uint32_t used_blocks;
    uint32_t peak_used_blocks;
    uint64_t total_alloc_bytes;
    uint64_t total_free_bytes;
    uint32_t alloc_count;
    uint32_t free_count;
    uint32_t alloc_fail_count;
    double hit_rate_pct;
} EdrA44MemoryPoolStats;

int edr_a44_memory_pool_init(uint32_t item_size, uint32_t capacity);
int edr_a44_memory_pool_set_prealloc(uint32_t prealloc_count);
void *edr_a44_memory_pool_alloc(void);
void edr_a44_memory_pool_free(void *ptr);
int edr_a44_memory_pool_get_stats(EdrA44MemoryPoolStats *out_stats);
int edr_a44_memory_pool_trim(uint32_t target_free_count);
void edr_a44_memory_pool_shutdown(void);

typedef struct {
    uint64_t lockfree_try_push_count;
    uint64_t lockfree_push_success_count;
    uint64_t lockfree_pop_count;
    uint64_t lockfree_pop_success_count;
    uint64_t lockfree_empty_count;
    uint64_t cacheline_false_sharing_hits;
    uint32_t padding_bytes;
} EdrA44ConcurrencyStats;

int edr_a44_lockfree_queue_init(uint32_t capacity);
int edr_a44_lockfree_queue_try_push(const void *item, uint32_t item_size);
int edr_a44_lockfree_queue_try_pop(void *out_item, uint32_t *out_item_size);
int edr_a44_lockfree_queue_get_stats(EdrA44ConcurrencyStats *out_stats);
void edr_a44_lockfree_queue_shutdown(void);

int edr_a44_enable_cache_friendly_mode(int enable);
int edr_a44_get_concurrency_stats(EdrA44ConcurrencyStats *out_stats);

typedef enum {
    EDR_A44_ADAPTIVE_MODE_FIXED = 0,
    EDR_A44_ADAPTIVE_MODE_REACTIVE = 1,
    EDR_A44_ADAPTIVE_MODE_PREDICTIVE = 2
} EdrA44AdaptiveMode;

typedef struct {
    EdrA44AdaptiveMode mode;
    int enabled;
    int trend_window_size;
    double scale_up_threshold;
    double scale_down_threshold;
    int scale_up_cooldown_ms;
    int scale_down_cooldown_ms;
    double prediction_accuracy;
    int last_scale_action;
    uint64_t last_scale_time_ns;
} EdrA44AdaptiveConfig;

typedef struct {
    double current_throughput;
    double avg_throughput_last_1m;
    double avg_throughput_last_5m;
    double avg_throughput_last_15m;
    double trend_slope;
    double predicted_throughput_1m;
    double scaling_score;
    int recommended_threads;
    int confidence_level;
} EdrA44ScalingRecommendation;

int edr_a44_adaptive_init(EdrA44AdaptiveMode mode);
int edr_a44_adaptive_get_config(EdrA44AdaptiveConfig *out_config);
int edr_a44_adaptive_set_thresholds(double scale_up, double scale_down);
int edr_a44_adaptive_get_recommendation(EdrA44ScalingRecommendation *out_rec);
int edr_a44_adaptive_execute_scale(int target_threads);
int edr_a44_adaptive_update_throughput(double throughput);

typedef struct {
    uint64_t total_events;
    uint64_t dropped_events;
    uint64_t queue_depth_max;
    uint64_t latency_min_ns;
    uint64_t latency_max_ns;
    uint64_t latency_avg_ns;
    uint64_t latency_p50_ns;
    uint64_t latency_p95_ns;
    uint64_t latency_p99_ns;
    double throughput_avg_rps;
    double queue_util_avg_pct;
} EdrA44EndToEndStats;

int edr_a44_e2e_enable_tracking(int enable);
int edr_a44_e2e_record_event(uint64_t timestamp_ns);
int edr_a44_e2e_get_stats(EdrA44EndToEndStats *out_stats);
int edr_a44_e2e_reset_stats(void);

typedef struct {
    int prefetch_enabled;
    int pipeline_parallel_enabled;
    int batch_timeout_ms;
    int max_batch_size;
} EdrA44PipelineConfig;

int edr_a44_pipeline_get_config(EdrA44PipelineConfig *out_config);
int edr_a44_pipeline_set_config(const EdrA44PipelineConfig *config);
int edr_a44_pipeline_prefetch_start(int lookahead_count);
void edr_a44_pipeline_prefetch_stop(void);

typedef struct {
    uint64_t callback_enter_ns;
    uint64_t tdh_start_ns;
    uint64_t tdh_end_ns;
    uint64_t bus_push_start_ns;
    uint64_t bus_push_end_ns;
    uint32_t event_size_bytes;
} EdrA44PipelineSpan;

int edr_a44_pipeline_span_begin(EdrA44PipelineSpan *span);
int edr_a44_pipeline_span_end(EdrA44PipelineSpan *span);
int edr_a44_pipeline_span_record(const EdrA44PipelineSpan *span);

#endif /* _WIN32 */
#endif /* EDR_EDR_A44_SPLIT_PATH_WIN_H */
