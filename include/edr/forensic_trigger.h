/**
 * 取证触发器 — 预处理管线内异步触发取证收集。
 * 纯内存判断 O(1)，速率限制，通过事件总写入队触发队列。
 */
#ifndef EDR_FORENSIC_TRIGGER_H
#define EDR_FORENSIC_TRIGGER_H

#include "edr/behavior_record.h"
#include "edr/types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EDR_FT_QUEUE_CAPACITY 32u
#define EDR_FT_MAX_MITRE_TRIGGERS 16u

typedef enum {
  EDR_FT_SCOPE_QUICK = 1,
  EDR_FT_SCOPE_FULL  = 2,
} EdrForensicTriggerScope;

typedef struct {
  char reason[128];
  uint64_t source_event_id[2];
  uint32_t target_pid;
  char target_path[512];
  EdrForensicTriggerScope scope;
  uint64_t created_ns;
  char mitre_tag[16];
} EdrForensicTrigger;

typedef struct {
  bool enabled;
  uint32_t cooldown_s;
  uint32_t max_per_hour;
  uint32_t max_concurrent;
  uint32_t per_mitre_cooldown_s;
  char trigger_mitre[EDR_FT_MAX_MITRE_TRIGGERS][16];
  uint32_t mitre_trigger_count;
  bool trigger_on_p0;
  bool collect_process_tree;
  bool collect_network_state;
  bool collect_autoruns;
} EdrForensicAutoConfig;

void edr_forensic_trigger_init(const EdrForensicAutoConfig *cfg);
void edr_forensic_trigger_shutdown(void);

/**
 * 评估是否触发取证。
 * 在预处理线程中调用（无锁），仅入队不执行。
 * slot->priority==0 且 trigger_on_p0 为 true 或 mitre tag 命中时触发。
 */
void edr_forensic_trigger_evaluate(const EdrEventSlot *slot,
                                   const EdrBehaviorRecord *rec);

/**
 * 出队取证触发任务。返回 true 表示弹出成功。
 * 在主线程中调用，每次最多弹出一个任务。
 */
bool edr_forensic_trigger_try_pop(EdrForensicTrigger *out);

/**
 * 返回当前积压数（仅主线程调用，用于日志/监控）。
 */
uint32_t edr_forensic_trigger_backlog(void);

#endif
