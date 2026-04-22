/**
 * 《11》behavior.onnx 64 维特征编码 — M3a（8–43 占位）/ M3b（§5.1–5.5 管线用完整 B/C/D）。
 */
#ifndef EDR_AVE_BEHAVIOR_FEATURES_H
#define EDR_AVE_BEHAVIOR_FEATURES_H

#include "edr/ave_sdk.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 与 `ave_behavior_pipeline` 中 static/父子/兄弟互馈一致，供 E 组 44–45、51–52 */
typedef struct EdrAveBehaviorFeatExtra {
  float static_max_conf;
  float static_verdict_norm;
  float parent_static_max_conf;
  float sibling_anomaly_mean;
  /** 《11》§5.5 维 56：0/1，来自 PidHistory 粘性位（`merge_static_scan`）；与 **`AVEBehaviorEvent.cert_revoked_ancestor`** 在编码中 OR */
  float cert_revoked_ancestor;
} EdrAveBehaviorFeatExtra;

/**
 * M3b：由行为管线按 PID 聚合得到（对应《11》PidHistory 子集 + 时序窗）。
 * `now_ns` 为当前事件时间戳（墙钟或单调均可，与 `prev_event_ns` 同基即可）。
 */
typedef struct EdrAveBehaviorPidSnapshot {
  uint32_t total_events_incl_current;
  uint32_t file_write_count;
  uint32_t net_connect_count;
  uint32_t reg_write_count;
  uint32_t dll_load_count;
  float has_injected_memory;
  float has_accessed_lsass;
  float has_loaded_suspicious_dll;
  float has_ioc_connection;
  float parent_chain_depth_norm;
  float is_system_account;
  float time_since_birth_norm;
  uint32_t unique_ip_count;
  float is_high_value_host;
  int64_t prev_event_ns;
  int64_t now_ns;
  uint32_t burst_1s_count;
  uint32_t events_last_1min;
  uint32_t events_last_5min;
  int is_first_event_of_proc;
  uint32_t events_after_net_connect;
} EdrAveBehaviorPidSnapshot;

/**
 * M3a：`feat` 长度 `n` 通常为 64。§5.2–5.4（8–43）为 **0**；§5.5 E 组同 M3b。
 */
void edr_ave_behavior_encode_m3a(const AVEBehaviorEvent *e, uint32_t event_count_before,
                                   const EdrAveBehaviorFeatExtra *ex, float *feat, size_t n);

/**
 * M3b：§5.1–5.4 + §5.5 E 组；`snap` 由管线填充（可与 `e` 同一事件）。
 */
void edr_ave_behavior_encode_m3b(const AVEBehaviorEvent *e, const EdrAveBehaviorFeatExtra *ex,
                                   const EdrAveBehaviorPidSnapshot *snap, float *feat, size_t n);

#ifdef __cplusplus
}
#endif

#endif
