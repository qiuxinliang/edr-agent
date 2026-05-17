/**
 * 进程树缓存 — 预处理线程内 LRU 哈希表（PID→父链），供 P0 事件上下文富化。
 * 4096 条目，~1.5MB 常驻，仅在预处理线程访问（无需锁）。
 */
#ifndef EDR_PROCESS_TREE_CACHE_H
#define EDR_PROCESS_TREE_CACHE_H

#include <stddef.h>
#include <stdint.h>

#define EDR_PTC_STR_SHORT 64u
#define EDR_PTC_STR_LONG  256u
#define EDR_PTC_STR_PATH  512u

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint64_t start_time_ns;
  uint64_t last_seen_ns;
  uint64_t terminate_time_ns;
  char process_name[EDR_PTC_STR_SHORT];
  char cmdline[EDR_PTC_STR_LONG];
  char exe_path[EDR_PTC_STR_PATH];
  char parent_name[EDR_PTC_STR_SHORT];
  uint32_t generation;
  int terminated;
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

/** 根据 PID 查找条目；未命中返回 NULL。仅预处理线程调用。 */
const ProcessTreeEntry *edr_pt_cache_get(uint32_t pid);

/** 移除条目（进程退出时调用）。返回 0 成功，-1 未找到。 */
int edr_pt_cache_remove(uint32_t pid);

/** 获取自 PID 向上的进程链深度。返回跳数（含自身）。 */
uint32_t edr_pt_cache_chain_depth(uint32_t pid);

/** 填充 BehaviorRecord 的祖父/父进程字段（P0 富化）。 */
void edr_pt_cache_fill_record(uint32_t pid,
                              char *grandparent_name, size_t gn_cap,
                              char *grandparent_path, size_t gp_cap,
                              char *parent_cmdline,    size_t pc_cap,
                              uint32_t *out_chain_depth);

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
 * 智能推断父进程：当直接获取PPID失败时，基于时间窗口和启发式算法推断父进程
 * @param pid: 目标进程PID
 * @param event_time_ns: 事件时间戳（纳秒）
 * @param out_ppid: 输出推断的父进程PID
 * @param out_parent_name: 输出父进程名称
 * @param name_len: 名称缓冲区长度
 * @return: 0 成功，-1 失败
 */
int edr_pt_cache_infer_parent(uint32_t pid, uint64_t event_time_ns,
                              uint32_t *out_ppid, char *out_parent_name, size_t name_len);

/**
 * 获取历史进程记录（即使已终止也能查询）
 * @param pid: 目标进程PID
 * @param timestamp: 查询时间戳（用于处理PID复用）
 * @param out: 输出进程信息
 * @return: 0 成功，-1 未找到
 */
int edr_pt_cache_get_historical(uint32_t pid, uint64_t timestamp, ProcessTreeEntry *out);

/**
 * 标记进程终止（保留历史记录）
 * @param pid: 进程PID
 * @param terminate_time_ns: 终止时间戳
 * @return: 0 成功，-1 未找到
 */
int edr_pt_cache_mark_terminated(uint32_t pid, uint64_t terminate_time_ns);

/**
 * 获取PID世代计数器（用于检测PID复用）
 */
uint32_t edr_pt_cache_get_generation(void);

/**
 * 增加PID世代计数器
 */
void edr_pt_cache_increment_generation(void);

/**
 * 设置历史记录保留时间（秒）
 */
void edr_pt_cache_set_history_ttl(uint32_t ttl_seconds);

/**
 * 清理过期历史记录
 */
void edr_pt_cache_cleanup_history(void);

#endif
