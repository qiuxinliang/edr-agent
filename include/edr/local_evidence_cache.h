/**
 * 端侧轻量证据缓存。
 *
 * 目标：维护最近进程/文件/网络/注册表元数据的内存索引，并可选落 SQLite
 * local_evidence_cache.db，供实时查询、告警取证和进程树补全使用。默认只缓存元数据，
 * 不读取文件内容。
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
  uint64_t maintenance_runs;
  uint32_t process_slots_used;
  uint32_t ring_events;
  uint32_t max_db_mb;
  uint32_t retention_hours;
  char path[512];
  char last_engine[32];
  int64_t last_event_time_ns;
  char last_error[160];
} EdrEvidenceCacheStatus;

int edr_local_evidence_cache_open(const char *path, uint32_t max_db_mb,
                                  uint32_t retention_hours);
void edr_local_evidence_cache_close(void);

/** 用已缓存的进程元数据补全 pid/ppid/name/path/cmdline/parent。 */
void edr_local_evidence_cache_enrich_behavior(EdrBehaviorRecord *r);

/** 记录一条行为元数据；函数内部会维护内存环与 SQLite。 */
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r);

/** 周期性 TTL 清理、大小水位清理和 WAL checkpoint。 */
void edr_local_evidence_cache_poll_maintenance(void);

void edr_local_evidence_cache_get_status(EdrEvidenceCacheStatus *out);

/** 追加 engine_health JSON 片段，形如 `"evidence_cache":{...}`。 */
void edr_local_evidence_cache_status_json(char *out, size_t cap);

/**
 * RTQ/RTR 轻量查询：payload_json 支持 event_type/type、pid、endpoint_id、
 * process_name_contains、cmdline_contains、file_path_contains、remote_ip、
 * registry_key_contains、limit、time_window_s。优先返回内存 ring，SQLite 可用时补历史。
 */
int edr_local_evidence_cache_query_json(const char *payload_json, char *out, size_t cap);

/** 用进程缓存返回 pid 的父进程和直接子进程，供 RTR 进程树查看。 */
int edr_local_evidence_cache_process_tree_json(uint32_t pid, const char *endpoint_id,
                                               char *out, size_t cap);

#endif
