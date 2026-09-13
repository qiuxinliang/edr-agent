/**
 * 进程树缓存 — 线程安全 LRU 哈希表（PID→父链），供 P0 富化和告警发送快照。
 * 4096 条目，~1.5MB 常驻。跨线程调用必须使用复制型 API，禁止持有内部条目指针。
 */
#ifndef EDR_PROCESS_TREE_CACHE_H
#define EDR_PROCESS_TREE_CACHE_H

#include <stddef.h>
#include <stdint.h>

#define EDR_PTC_STR_SHORT 64u
#define EDR_PTC_STR_LONG  256u
#define EDR_PTC_STR_PATH  512u
#define EDR_PTC_EXIT_GRACE_NS (30ULL * 1000000000ULL)

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  /* A parent may be selected only when these are captured from the same
   * lifecycle generation.  For exact generations `start_time_ns` is the
   * canonical Unix birth derived from creation_filetime_100ns; observation
   * time is tracked separately in last_seen_ns. */
  uint64_t process_start_key;
  uint64_t creation_filetime_100ns;
  uint64_t start_time_ns;
  uint64_t last_seen_ns;
  uint64_t exit_time_ns;
  char process_name[EDR_PTC_STR_SHORT];
  char cmdline[EDR_PTC_STR_LONG];
  char exe_path[EDR_PTC_STR_PATH];
  char parent_name[EDR_PTC_STR_SHORT];
} ProcessTreeEntry;

void edr_pt_cache_init(void);
void edr_pt_cache_shutdown(void);

/**
 * 插入/更新进程条目（进程创建时调用）。
 * 返回 0 成功，-1 满（淘汰最老条目继续插入）。
 */
int edr_pt_cache_put(uint32_t pid, uint32_t ppid,
                     const char *process_name, const char *cmdline,
                     const char *exe_path, const char *parent_name,
                     uint64_t start_time_ns);

/* Insert or update one exact process generation.  `observation_time_ns` says
 * when this metadata was observed and only advances last_seen_ns.  The
 * generation interval birth is canonicalized internally from
 * creation_filetime_100ns and is immutable on later observations, as is a
 * known exit.  Both generation values must be non-zero. */
int edr_pt_cache_put_generation(uint32_t pid, uint32_t ppid,
                                const char *process_name, const char *cmdline,
                                const char *exe_path, const char *parent_name,
                                uint64_t observation_time_ns,
                                uint64_t process_start_key,
                                uint64_t creation_filetime_100ns);

/** 根据 PID 查找内部条目；仅可在缓存实现内部持锁调用。 */
const ProcessTreeEntry *edr_pt_cache_get(uint32_t pid);

/** 线程安全复制快照；命中返回 0，未命中/未初始化返回 -1。 */
int edr_pt_cache_snapshot(uint32_t pid, ProcessTreeEntry *out);

/**
 * 按源事件时间复制快照。命中返回 0；未命中返回 -1；事件不属于当前 PID
 * generation 或已超出退出宽限时返回 -2。
 */
int edr_pt_cache_snapshot_at(uint32_t pid, uint64_t event_time_ns, ProcessTreeEntry *out);

/** 标记进程退出，保留短暂迟到告警宽限。返回 0 成功，-1 未找到。 */
int edr_pt_cache_mark_exit(uint32_t pid, uint64_t exit_time_ns);

/* Mark only the matching ProcessStartKey generation exited.  PID-only exit
 * notifications are intentionally not an authority to close a newer reuse. */
int edr_pt_cache_mark_exit_generation(uint32_t pid, uint64_t process_start_key,
                                      uint64_t exit_time_ns);

/** 移除条目。返回 0 成功，-1 未找到。 */
int edr_pt_cache_remove(uint32_t pid);

/** 获取自 PID 向上的进程链深度。返回跳数（含自身）。 */
uint32_t edr_pt_cache_chain_depth(uint32_t pid);

/** 填充 BehaviorRecord 的祖父/父进程字段（P0 富化）。 */
void edr_pt_cache_fill_record(uint32_t pid,
                              char *grandparent_name, size_t gn_cap,
                              char *grandparent_path, size_t gp_cap,
                              uint32_t *out_grandparent_pid,
                              char *parent_cmdline,    size_t pc_cap,
                              uint32_t *out_chain_depth);

/* Event-time variant used by P0 enrichment.  It traverses the same historical
 * generation interval for every parent hop, so a delayed child cannot borrow
 * a later PID reuse's parent chain. */
void edr_pt_cache_fill_record_at(uint32_t pid, uint64_t event_time_ns,
                                 char *grandparent_name, size_t gn_cap,
                                 char *grandparent_path, size_t gp_cap,
                                 uint32_t *out_grandparent_pid,
                                 char *parent_cmdline, size_t pc_cap,
                                 uint32_t *out_chain_depth);

typedef struct {
  uint64_t puts;
  uint64_t updates;
  uint64_t put_time_rejects;
  uint64_t snapshot_hits;
  uint64_t snapshot_misses;
  uint64_t snapshot_time_rejects;
  uint64_t exits_marked;
  uint64_t evictions;
  uint32_t entries;
} EdrProcessTreeCacheMetrics;

void edr_pt_cache_get_metrics(EdrProcessTreeCacheMetrics *out);

#define EDR_KEY_PROC_MAX 12

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  char name[EDR_PTC_STR_SHORT];
  int valid;
} EdrKeyProcSlot;

/**
 * 进程树缓存预热：Agent 启动时通过 CreateToolhelp32Snapshot 全量枚举当前运行进程，
 * 预填充 g_pt_table，减少冷启动阶段 PPID=0 事件。
 * 返回预热条目数；失败返回 -1。
 * 仅 Windows 有效；非 Windows 返回 0。
 */
int edr_pt_cache_warmup(void);

/**
 * 返回关键系统进程的 PID 信息填充到 `out`（长度 EDR_KEY_PROC_MAX）。
 * 包括：System, smss.exe, csrss.exe, wininit.exe, services.exe, lsass.exe,
 *       winlogon.exe, svchost.exe, explorer.exe 等。
 * 每次调用 edr_pt_cache_warmup 后自动刷新。
 */
void edr_pt_cache_get_key_procs(EdrKeyProcSlot *out, int max);

/**
 * 根据名称查找关键系统进程 PID；返回 0 成功（pid 有效），-1 未找到。
 */
int edr_pt_cache_find_key_proc(const char *name, uint32_t *out_pid);

/**
 * PPID 推断回退：通过进程树缓存中的时间信息推断 PPID（预案未实现）。
 * 返回 0 成功，-1 未实现或推断失败。
 */
int edr_pt_cache_infer_parent(uint32_t pid, uint64_t event_time_ns,
                              uint32_t *out_ppid, char *out_parent_name,
                              size_t name_cap);

#endif
