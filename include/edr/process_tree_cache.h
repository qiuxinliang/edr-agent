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

#endif
