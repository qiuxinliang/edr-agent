/**
 * 事件总线（§1.2、§2.3）
 * A4.1：定长 **MPMC** 无互斥环表（每槽 `turn` 世代 + 单调 `head`/`tail` 位标；与 LMAX / rigtorp
 * 类 `turn(·)*2` 可发布语义同构）。**多**路 `edr_event_bus_try_push`（ETW/WinDivert/PMFE/…）与
 * 预处理线程的 `try_pop* **并发安全**；不为严格 SPSC 专用。
 */
#ifndef EDR_EVENT_BUS_H
#define EDR_EVENT_BUS_H

#include "types.h"

#include <stdint.h>

typedef struct EdrEventBus EdrEventBus;

EdrEventBus *edr_event_bus_create(uint32_t slot_count);
void edr_event_bus_destroy(EdrEventBus *bus);

/**
 * 非阻塞推送。满则返回 false，调用方应累计 dropped（§2.3 背压）。
 */
bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot);

/**
 * 弹出一条待处理事件；无事件返回 false。
 */
bool edr_event_bus_try_pop(EdrEventBus *bus, EdrEventSlot *out_slot);

/**
 * 批量弹出最多 max_count 条事件，返回实际弹出数量；0 表示当前无事件。
 * 用于减少高频加锁开销（处理顺序与单条 pop 一致）。
 */
uint32_t edr_event_bus_try_pop_many(EdrEventBus *bus, EdrEventSlot *out_slots, uint32_t max_count);

uint32_t edr_event_bus_capacity(const EdrEventBus *bus);
uint32_t edr_event_bus_used_approx(EdrEventBus *bus);
uint64_t edr_event_bus_dropped_total(EdrEventBus *bus);

/** 成功入队总次数（与 dropped 对读可估算背压下推送尝试分布） */
uint64_t edr_event_bus_pushed_total(EdrEventBus *bus);

/** 占用槽位 ≥ 容量 80% 时的累计命中次数（§2.3 背压观测） */
uint64_t edr_event_bus_high_water_hits(EdrEventBus *bus);

#endif
