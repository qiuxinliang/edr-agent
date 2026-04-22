/**
 * 《11》§3 PidHistory：进程行为状态 + **128×64** 特征序列（用于 behavior.onnx）。
 * 与 `AVEBehaviorEvent` 环形缓冲等价物：此处存 **已编码** 的 64 维向量序列（时间正序，最旧→最新）。
 */
#ifndef EDR_PID_HISTORY_H
#define EDR_PID_HISTORY_H

#include "edr/ave_sdk.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 与 §6.1 / ONNX 默认一致；若模型 seq 更小，运行期截断 */
#define EDR_PID_HISTORY_MAX_SEQ 128
#define EDR_PID_HISTORY_FEAT_DIM 64

/**
 * 单进程 PidHistory（设计 §3.1 的核心字段 + 端侧实现约束）。
 *
 * **与设计 §3.1 对照（T07）**
 * - **已实现于本结构**：pid/ppid、`create_time_ns`、`process_name`/`process_path`、`is_active`、
 *   B 组计数与粘性标志、`feat_chrono`/`feat_len`、推理控制字段、`sticky_cert_revoked_ancestor`。
 * - **由 `AVEBehaviorEvent` 携带、不进槽**：路径/网络/DNS 细粒度、MOTW、IOC 位、E 组标量分数等。
 * - **P2 T9 跨引擎写回**：Shellcode / Webshell / PMFE 经预处理 **`edr_ave_cross_engine_feed_from_record` → `AVE_FeedEvent`**
 *   写入 **当前步** 的 E 组维 **46–47、53–54**（见 `encode_e_group`）；**PMFE 线程**仍只写 **`pmfe_snapshot`**
 *   与 **`edr_pid_history_pmfe_ingest_scan_detail`**，不直接调 AVE（见 **`pmfe.h`** 头注释）。
 * - **设计有、尚未进槽**：证书细项、`pmfe_last_scan_ts`、原始 `event_buf[128]` 环形缓冲（端侧以 **编码向量** 代替）等 — 见《11》§3.1 全文。
 */
typedef struct EdrPidHistory {
  uint32_t pid;
  uint32_t ppid;
  uint64_t create_time_ns;
  char process_name[256];
  char process_path[512];
  uint8_t is_active;
  uint8_t _pad_hdr[3];

  AVEBehaviorFlags flags;
  uint32_t event_count;
  int64_t last_event_ns;
  float anomaly;
  int64_t last_alert_ns;
  float ave_static_max_conf;
  uint8_t ave_verdict;
  uint8_t _pad_av[3];

  uint32_t file_write_count;
  uint32_t net_connect_count;
  uint32_t reg_write_count;
  uint32_t dll_load_count;
  uint32_t parent_chain_depth;
  uint8_t sticky_injected;
  uint8_t sticky_lsass;
  uint8_t sticky_susp_dll;
  uint8_t sticky_ioc_conn;
  /** §5.5 维 56：静态扫描判决为 VERDICT_CERT_REVOKED 时置 1 且保持（当前作「吊销」代理；真正祖先链由后续证书子系统补） */
  uint8_t sticky_cert_revoked_ancestor;
  uint8_t pmfe_high_value;
  uint8_t is_system_account;
  uint8_t _pad_st[1];
  int64_t first_seen_ns;
  uint32_t ip_hashes[8];
  uint8_t ip_count;
  int64_t prev_event_ns;
  int64_t last_net_connect_ns;
  uint32_t events_after_net_connect;
  uint32_t ts_buf_n;
  int64_t ts_buf[128];

  /** §3：最近编码特征（oldest=0 … newest=feat_len-1），feat_len≤EDR_PID_HISTORY_MAX_SEQ */
  uint32_t feat_len;
  float feat_chrono[EDR_PID_HISTORY_MAX_SEQ][EDR_PID_HISTORY_FEAT_DIM];

  /** §3 推理控制 */
  uint32_t events_since_last_inference;
  float last_anomaly_score;
  uint8_t consecutive_medium_scores;
  uint8_t _pad_inf[3];
  uint64_t last_inference_ts;
  /** `edr_ave_bp_notify_exit` 时刻；`is_active=0` 且超过 300s 可由 `pid_find_slot` GC（《11》§3.2） */
  int64_t exit_ts_ns;

  int valid;
} EdrPidHistory;

#ifdef __cplusplus
}
#endif

#endif
