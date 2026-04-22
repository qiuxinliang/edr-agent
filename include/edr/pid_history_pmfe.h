/**
 * 按 PID 缓存最近一次 PMFE 扫描摘要（设计中的 PidHistory.pmfe 侧写回），供预处理阶段并入 EdrBehaviorRecord。
 * `EDR_PMFE_PID_HISTORY=0` 关闭写入与合并。
 */
#ifndef EDR_PID_HISTORY_PMFE_H
#define EDR_PID_HISTORY_PMFE_H

#include "behavior_record.h"

#include <stdint.h>

void edr_pid_history_pmfe_init(void);
void edr_pid_history_pmfe_shutdown(void);

/** 扫描线程：解析 `pmfe_scan_*` 产出的 detail 行并更新表 */
void edr_pid_history_pmfe_ingest_scan_detail(uint32_t pid, const char *detail);

/** 预处理：将当前 `br->pid` 对应的摘要写入 `br->pmfe_snapshot`（JSON，可为空） */
void edr_pid_history_pmfe_fill_record(EdrBehaviorRecord *br);

#endif
