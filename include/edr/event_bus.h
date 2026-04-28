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

typedef enum {
    EDR_BUS_TYPE_NORMAL = 0,
    EDR_BUS_TYPE_HIGH_PRIORITY = 1,
    EDR_BUS_TYPE_LOW_PRIORITY = 2,
} EdrBusType;

int edr_dual_bus_enabled(void);

EdrEventBus *edr_event_bus_create_dual(uint32_t high_priority_slot_count, uint32_t low_priority_slot_count);

int edr_event_bus_try_push_dual(EdrBusType bus_type, const EdrEventSlot *slot);

bool edr_event_bus_try_pop_high_priority(EdrEventBus *bus, EdrEventSlot *out_slot);

bool edr_event_bus_try_pop_low_priority(EdrEventBus *bus, EdrEventSlot *out_slot);

uint32_t edr_event_bus_used_approx_high_priority(EdrEventBus *bus);

uint32_t edr_event_bus_used_approx_low_priority(EdrEventBus *bus);

uint64_t edr_event_bus_dropped_total_high_priority(EdrEventBus *bus);

uint64_t edr_event_bus_dropped_total_low_priority(EdrEventBus *bus);

#endif
