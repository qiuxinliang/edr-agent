/**
 * 事件总线（§1.2、§2.3）
 * 设计目标：无锁环形缓冲区；当前骨架为互斥保护环形队列，便于先联调模块边界。
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

uint32_t edr_event_bus_capacity(const EdrEventBus *bus);
uint32_t edr_event_bus_used_approx(EdrEventBus *bus);
uint64_t edr_event_bus_dropped_total(EdrEventBus *bus);

/** 占用槽位 ≥ 容量 80% 时的累计命中次数（§2.3 背压观测） */
uint64_t edr_event_bus_high_water_hits(EdrEventBus *bus);

#endif
