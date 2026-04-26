#include "edr/event_bus.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/**
 * A4.1：无互斥的定长 MPMC 环表（多路 try_push、多路 try_pop 安全）。
 * 实现要点与 LMAX / rigtorp::MPMCQueue 类似：每槽 `turn` 世代与单调 `head`（入队位标）/ `tail`（出队位标）配合；
 * 本进程 **唯一** 消费者为预处理线程时仍满足该模型（MPMC 为 MPSC 的超集）。
 * 见 `include/edr/event_bus.h` 无锁设计说明。
 */

typedef struct {
  _Alignas(64) _Atomic uint64_t turn;
  EdrEventSlot data;
} EdrEventBusCell;

struct EdrEventBus {
  EdrEventBusCell *cells;
  uint32_t cap;
  _Alignas(64) _Atomic uint64_t head;
  _Alignas(64) _Atomic uint64_t tail;
  _Atomic uint64_t dropped;
  _Atomic uint64_t pushed;
  _Atomic uint64_t high_water_hits;
};

static inline uint64_t bus_lap(uint64_t pos, uint32_t cap) { return pos / (uint64_t)cap; }

static inline uint32_t bus_idx(uint64_t pos, uint32_t cap) { return (uint32_t)(pos % (uint64_t)cap); }

EdrEventBus *edr_event_bus_create(uint32_t slot_count) {
  if (slot_count < 2u) {
    return NULL;
  }
  EdrEventBus *bus = (EdrEventBus *)calloc(1, sizeof(EdrEventBus));
  if (!bus) {
    return NULL;
  }
  bus->cells = (EdrEventBusCell *)calloc(slot_count, sizeof(EdrEventBusCell));
  if (!bus->cells) {
    free(bus);
    return NULL;
  }
  bus->cap = slot_count;
  for (uint32_t i = 0; i < slot_count; i++) {
    atomic_init(&bus->cells[i].turn, 0u);
  }
  atomic_init(&bus->head, 0u);
  atomic_init(&bus->tail, 0u);
  atomic_init(&bus->dropped, 0u);
  atomic_init(&bus->pushed, 0u);
  atomic_init(&bus->high_water_hits, 0u);
  return bus;
}

void edr_event_bus_destroy(EdrEventBus *bus) {
  if (!bus) {
    return;
  }
  free(bus->cells);
  free(bus);
}

bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot) {
  if (!bus || !slot) {
    return false;
  }
  const uint32_t cap = bus->cap;
  uint64_t pos = atomic_load_explicit(&bus->head, memory_order_acquire);
  for (;;) {
    EdrEventBusCell *cell = &bus->cells[bus_idx(pos, cap)];
    const uint64_t lap = bus_lap(pos, cap);
    const uint64_t want = lap * 2u;
    if (atomic_load_explicit(&cell->turn, memory_order_acquire) == want) {
      if (atomic_compare_exchange_strong_explicit(&bus->head, &pos, pos + 1u, memory_order_acq_rel,
                                                  memory_order_acquire)) {
        memcpy(&cell->data, slot, sizeof(EdrEventSlot));
        atomic_store_explicit(&cell->turn, lap * 2u + 1u, memory_order_release);
        (void)atomic_fetch_add_explicit(&bus->pushed, 1u, memory_order_relaxed);
        {
          const uint64_t t = atomic_load_explicit(&bus->tail, memory_order_relaxed);
          const uint64_t h = pos + 1u;
          if (h > t) {
            const uint64_t used = h - t;
            if (used * 100u >= (uint64_t)cap * 80u) {
              (void)atomic_fetch_add_explicit(&bus->high_water_hits, 1u, memory_order_relaxed);
            }
          }
        }
        return true;
      }
    } else {
      const uint64_t prev = pos;
      pos = atomic_load_explicit(&bus->head, memory_order_acquire);
      if (pos == prev) {
        (void)atomic_fetch_add_explicit(&bus->dropped, 1u, memory_order_relaxed);
        return false;
      }
    }
  }
}

bool edr_event_bus_try_pop(EdrEventBus *bus, EdrEventSlot *out_slot) {
  if (!bus || !out_slot) {
    return false;
  }
  const uint32_t cap = bus->cap;
  uint64_t pos = atomic_load_explicit(&bus->tail, memory_order_acquire);
  for (;;) {
    EdrEventBusCell *cell = &bus->cells[bus_idx(pos, cap)];
    const uint64_t lap = bus_lap(pos, cap);
    const uint64_t need = lap * 2u + 1u;
    if (atomic_load_explicit(&cell->turn, memory_order_acquire) == need) {
      if (atomic_compare_exchange_strong_explicit(&bus->tail, &pos, pos + 1u, memory_order_acq_rel,
                                                  memory_order_acquire)) {
        memcpy(out_slot, &cell->data, sizeof(EdrEventSlot));
        atomic_store_explicit(&cell->turn, lap * 2u + 2u, memory_order_release);
        return true;
      }
    } else {
      const uint64_t prev = pos;
      pos = atomic_load_explicit(&bus->tail, memory_order_acquire);
      if (pos == prev) {
        return false;
      }
    }
  }
}

uint32_t edr_event_bus_try_pop_many(EdrEventBus *bus, EdrEventSlot *out_slots, uint32_t max_count) {
  if (!bus || !out_slots || max_count == 0u) {
    return 0u;
  }
  uint32_t n = 0u;
  while (n < max_count) {
    if (!edr_event_bus_try_pop(bus, &out_slots[n])) {
      break;
    }
    n++;
  }
  return n;
}

uint32_t edr_event_bus_capacity(const EdrEventBus *bus) { return bus ? bus->cap : 0u; }

uint32_t edr_event_bus_used_approx(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  const uint64_t h = atomic_load_explicit(&bus->head, memory_order_relaxed);
  const uint64_t t = atomic_load_explicit(&bus->tail, memory_order_relaxed);
  if (h <= t) {
    return 0u;
  }
  const uint64_t u = h - t;
  return (uint32_t)(u > (uint64_t)bus->cap ? (uint64_t)bus->cap : u);
}

uint64_t edr_event_bus_dropped_total(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  return atomic_load_explicit(&bus->dropped, memory_order_relaxed);
}

uint64_t edr_event_bus_pushed_total(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  return atomic_load_explicit(&bus->pushed, memory_order_relaxed);
}

uint64_t edr_event_bus_high_water_hits(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  return atomic_load_explicit(&bus->high_water_hits, memory_order_relaxed);
}
