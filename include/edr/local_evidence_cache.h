/**
 * 端侧轻量证据缓存。
 *
 * 目标：维护 hot ring、P0/P1 候选、取证产物、命令结果和聚合指标分区。
 * 普通 ETW 只进入内存 hot ring 与滑动 drop counters，不写 SQLite，不读取文件内容。
 */
#ifndef EDR_LOCAL_EVIDENCE_CACHE_H
#define EDR_LOCAL_EVIDENCE_CACHE_H

#include "edr/behavior_record.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int db_open;
  uint64_t records_written;
  uint64_t records_dropped;
  uint64_t records_skipped;
  uint64_t hot_ring_ingested;
  uint64_t p0_candidates_written;
  uint64_t artifacts_written;
  /* Physical normalized post-context writes. `artifacts_written` remains the
   * count of candidate-visible materialized artifacts changed. */
  uint64_t context_facts_written;
  uint64_t context_refs_written;
  uint64_t command_results_written;
  /* Candidate accounting has non-overlapping denominators:
   * requests = reused + admission_attempts;
   * admission_attempts = admitted + rejected.
   * `admitted` advances only after the containing SQLite transaction commits. */
  uint64_t candidate_requests;
  /* Current-process, short-window local evidence reuse only. It is neither
   * alert suppression nor a persistent/cross-restart cache-hit metric. */
  uint64_t candidate_reused;
  uint64_t candidate_admission_attempts;
  uint64_t candidate_admitted;
  uint64_t candidate_rejected;
  uint64_t candidate_transaction_failures;
  /* A fixed in-memory field received a longer source value. The retained
   * prefix is explicitly counted so evidence degradation is observable. */
  uint64_t bounded_string_truncations;
  /* A bounded pre/post context manifest was rejected before any artifact row
   * committed (invalid UTF-8, allocation failure, or insufficient buffer). */
  uint64_t manifest_rejections;
  uint64_t candidate_deduped;
  /* Rejection reasons count comparable dedupe-slot checks, not candidate
   * requests. A single rejected check may increment more than one reason so
   * compound guard failures remain observable without per-event logging. */
  uint64_t candidate_dedup_generation_conflict_rejects;
  uint64_t candidate_dedup_source_shape_rejects;
  uint64_t candidate_dedup_semantic_mismatch_rejects;
  uint64_t candidate_dedup_skew_rejects;
  uint64_t write_budget_dropped;
  uint64_t write_budget_candidate_dropped;
  uint64_t write_budget_context_dropped;
  /* Critical action/ancestry context is capacity-bound rather than governed by
   * a fixed per-minute counter: used/limit/dropped stay zero. Database size,
   * retention, bounded context windows, generation/tenant scope, and transaction
   * failures remain authoritative. The aggregate used/limit fields describe
   * ordinary context. */
  uint64_t write_budget_critical_context_dropped;
  uint64_t write_budget_ordinary_context_dropped;
  uint32_t write_budget_used;
  uint32_t write_budget_limit;
  uint32_t write_budget_base_limit;
  uint32_t write_budget_critical_context_used;
  uint32_t write_budget_critical_context_limit;
  uint32_t write_budget_ordinary_context_used;
  uint32_t write_budget_ordinary_context_limit;
  uint64_t db_budget_dropped;
  uint64_t pressure_dropped;
  uint64_t ordinary_coalesced;
  uint64_t file_coalesced;
  uint64_t registry_coalesced;
  uint64_t network_coalesced;
  uint64_t summaries_emitted;
  uint64_t metric_file_drops;
  uint64_t metric_registry_drops;
  uint64_t metric_network_drops;
  uint64_t metric_other_drops;
  uint64_t maintenance_runs;
  uint64_t identity_observations_total;
  uint64_t identity_none;
  uint64_t process_cache_hits;
  uint64_t process_cache_misses;
  uint64_t identity_cache_hits;
  uint64_t identity_cache_misses;
  uint64_t identity_upgrades;
  uint64_t identity_stale_rejects;
  uint64_t process_cache_evictions;
  uint64_t ring_evictions;
  uint64_t hot_ring_evictions;
  uint64_t context_window_evictions;
  uint64_t metric_slot_evictions;
  uint64_t candidate_dedup_evictions;
  uint64_t aggregate_slot_evictions;
  uint64_t db_retention_evicted;
  uint64_t db_capacity_evicted;
  uint64_t identity_target_4688;
  uint64_t identity_creator_fallback;
  uint64_t identity_cache;
  uint64_t identity_token_sid;
  uint64_t identity_enrich_attempts;
  uint64_t identity_generation_unknown_rejects;
  uint64_t identity_generation_mismatch_rejects;
  uint64_t generation_resets;
  uint64_t late_generation_rejects;
  uint64_t generation_unknown_update_rejects;
  uint64_t generation_mismatch_update_rejects;
  uint32_t process_slots_used;
  uint32_t process_slots_capacity;
  uint32_t ring_events;
  uint32_t ring_capacity;
  uint32_t hot_ring_events;
  uint32_t hot_ring_capacity;
  uint32_t metrics_minutes;
  uint32_t metrics_capacity;
  uint32_t aggregate_slots_used;
  uint32_t aggregate_slots_capacity;
  uint32_t context_windows_used;
  uint32_t context_windows_capacity;
  uint32_t candidate_dedup_slots_used;
  uint32_t candidate_dedup_capacity;
  uint32_t process_slots_utilization_bps;
  uint32_t ring_utilization_bps;
  uint32_t hot_ring_utilization_bps;
  uint32_t metrics_utilization_bps;
  uint32_t aggregate_utilization_bps;
  uint32_t context_windows_utilization_bps;
  uint32_t candidate_dedup_utilization_bps;
  uint32_t db_utilization_bps;
  uint32_t pressure_active;
  /* Completed module-mutex samples for this process. Wait/hold percentiles
   * are conservative upper bounds from a fixed 64-bucket log2(ns)
   * histogram; every percentile is 0 when there are no completed samples. */
  uint64_t mutex_lock_samples;
  uint64_t mutex_wait_total_ns;
  uint64_t mutex_wait_max_ns;
  uint64_t mutex_wait_p95_ns;
  uint64_t mutex_wait_p99_ns;
  uint64_t mutex_hold_total_ns;
  uint64_t mutex_hold_max_ns;
  uint64_t mutex_hold_p95_ns;
  uint64_t mutex_hold_p99_ns;
  uint64_t static_bytes;
  uint32_t max_db_mb;
  uint32_t retention_hours;
  uint64_t db_bytes;
  uint64_t wal_bytes;
  uint64_t p0_candidate_rows;
  int64_t oldest_process_last_seen_ns;
  int64_t oldest_ring_event_time_ns;
  int64_t oldest_hot_ring_event_time_ns;
  int64_t oldest_candidate_dedup_ns;
  int64_t oldest_p0_candidate_event_time_ns;
  char path[512];
  char last_engine[32];
  int64_t last_event_time_ns;
  char last_error[160];
} EdrEvidenceCacheStatus;

/* SQLite readers must use this view for artifact delivery. It preserves the
 * historical artifacts projection while materializing normalized post-context
 * facts with their candidate attribution. */
#define EDR_LOCAL_EVIDENCE_MATERIALIZED_ARTIFACTS_VIEW "materialized_artifacts"

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours);
void edr_local_evidence_cache_close(void);

/** 用已缓存的进程元数据补全 pid/ppid/name/path/cmdline/parent。 */
void edr_local_evidence_cache_enrich_behavior(EdrBehaviorRecord *r);

/** Observe process metadata before rule/P0 evaluation. Never persists evidence. */
void edr_local_evidence_cache_observe_process(const EdrBehaviorRecord *r);

/** 记录一条行为元数据；函数内部会维护内存环与 SQLite。 */
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r);

/** 是否属于可落库/可上传的告警候选。普通 ETW 只进入 hot ring 与滑动指标。 */
int edr_local_evidence_cache_is_candidate(const EdrBehaviorRecord *r);

/** 命令结果分区镜像，供本地可靠投递和运维诊断使用。 */
void edr_local_evidence_cache_record_command_result(
    const char *command_id, const char *command_type, const char *status,
    int execution_status, int exit_code, const char *detail, const char *artifacts);

/** 周期性 TTL 清理、大小水位清理和 WAL checkpoint。 */
void edr_local_evidence_cache_poll_maintenance(void);

/**
 * Flush 已关闭窗口（早于当前分钟）且计数达到阈值（EDR_SUMMARY_MIN_COUNT，默认 5）的
 * 普通事件聚合槽，为每个槽构造一条 EDR_EVENT_BEHAVIOR_SUMMARY 记录并通过 emit 回调上报，
 * 用一条摘要替代被 coalesce 丢弃的重复明细。emit 由调用方提供（编码 + 入批次）。
 */
void edr_local_evidence_cache_flush_summaries(int64_t now_ns,
                                              void (*emit)(const EdrBehaviorRecord *));

void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out);

#ifdef EDR_LOCAL_EVIDENCE_CACHE_TESTING
/* Test-only wall clock for historical replay and retention checks. Survives
 * cache close/open; pass zero to restore the real clock after the scenario. */
void edr_local_evidence_cache_test_set_now_unix_ns(int64_t now_ns);
/* Aborts the next candidate-cache transaction commits from SQLite's commit
 * hook. This is test-only evidence that counters and dedupe state move only
 * after the durable boundary succeeds. */
void edr_local_evidence_cache_test_fail_next_commits(unsigned count);
/* Test-only mutex timing controls. They never exist in production builds. */
void edr_local_evidence_cache_test_reset_mutex_timing(void);
void edr_local_evidence_cache_test_record_mutex_timing(uint64_t wait_ns,
                                                        uint64_t hold_ns);
void edr_local_evidence_cache_test_hold_mutex(uint32_t hold_ms);
#endif

/** 追加 engine_health JSON 片段，形如 `"evidence_cache":{...}`。 */
void edr_local_evidence_cache_status_json(char *out, size_t cap);

/**
 * RTQ/RTR 轻量查询：payload_json 支持 event_type/type、pid、endpoint_id、
 * process_name_contains、cmdline_contains、file_path/file_path_contains、
 * file_sha256、file_ext、remote_ip、registry_key_contains、limit、time_window_s。
 * 优先返回内存 ring，SQLite 可用时补历史。file_sha256 只查缓存，不触发文件系统扫描。
 */
int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap);

/**
 * RTQ file hash cache lookup. Returns a JSON array of file rows from local
 * evidence cache; it never scans the filesystem. file_path_contains/file_ext are
 * optional narrowing filters. returned/scanned may be NULL.
 */
int edr_local_evidence_cache_query_file_hash_json(const char *file_sha256,
                                                  const char *file_path_contains,
                                                  const char *file_ext,
                                                  uint32_t limit,
                                                  char *out, size_t cap,
                                                  uint32_t *returned,
                                                  uint32_t *scanned,
                                                  int *truncated);

/** 用进程缓存返回 pid 的父进程和直接子进程，供 RTR 进程树查看。 */
int edr_local_evidence_cache_process_tree_json(uint32_t pid, const char *endpoint_id,
                                               char *out, size_t cap);

#endif
