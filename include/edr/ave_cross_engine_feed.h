/**
 * P2 T9：跨引擎写回 — 将 Shellcode / Webshell / PMFE 摘要标量送入 **`AVE_FeedEvent` → `EdrPidHistory`**（《11》§5.5 E 组 46–47、53–54）。
 *
 * - **入口**：预处理线程在 **`edr_behavior_from_slot`** 之后调用 **`edr_ave_cross_engine_feed_from_record`**（见 `preprocess_pipeline.c`）。
 * - **采集 / PMFE 线程**：仍只负责 **`edr_event_bus_try_push`** 与 **`edr_pid_history_pmfe_ingest_scan_detail`**；不直接触碰 AVE（边界见 **`pmfe.h`** 头注释）。
 * - **关闭**：`EDR_AVE_CROSS_ENGINE_FEED=0` 跳过写回（默认开启：未设置即写）。
 */
#ifndef EDR_AVE_CROSS_ENGINE_FEED_H
#define EDR_AVE_CROSS_ENGINE_FEED_H

#include "edr/behavior_record.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 在 `t1`/`t2`/`t3` 中查找首个 `score=` 浮点（无则 0）。 */
float edr_ave_cross_engine_parse_first_score(const char *t1, const char *t2, const char *t3);

/** 解析 `pmfe_snapshot` JSON 中的 `"ave":` 浮点（无则 0）。 */
float edr_ave_cross_engine_pmfe_snapshot_ave(const char *json);

/** 解析 `pmfe_snapshot` 中 `"mz":` / `"stomp":` / `"elf":` 是否暗示 PE/可疑内存（供 feat[54]）。 */
int edr_ave_cross_engine_pmfe_snapshot_pe_hint(const char *json);

/**
 * 将单条行为记录中的跨引擎标量写入行为管线（内部 **`AVE_FeedEvent`**）。
 * 仅处理 **`EDR_EVENT_PROTOCOL_SHELLCODE` / `EDR_EVENT_WEBSHELL_DETECTED` / `EDR_EVENT_PMFE_SCAN_RESULT`**。
 */
void edr_ave_cross_engine_feed_from_record(const EdrBehaviorRecord *br);

#ifdef __cplusplus
}
#endif

#endif
