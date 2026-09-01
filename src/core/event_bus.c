#include "edr/event_bus.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <stdatomic.h>
#include <time.h>
#endif

/**
 * A4.1：无互斥的定长 MPMC 环表（多路 try_push、多路 try_pop 安全）。
 * 实现要点与 LMAX / rigtorp::MPMCQueue 类似：每槽 `turn` 世代与单调 `head`（入队位标）/ `tail`（出队位标）配合；
 * 本进程 **唯一** 消费者为预处理线程时仍满足该模型（MPMC 为 MPSC 的超集）。
 * 见 `include/edr/event_bus.h` 无锁设计说明。
 */

/* Keep the reservation small but nonzero: one critical record must always be
 * able to displace ordinary flood pressure, including the cap=1 seam used by
 * the fail-safe FileRead tests.  Critical producers may use all physical
 * slots; only ordinary producers are constrained by this logical limit. */
static uint32_t edr_event_bus_p0_reserve_for_capacity(uint32_t cap) {
  uint32_t reserve;
  if (cap == 0u) {
    return 0u;
  }
  reserve = cap / 16u;
  if (reserve == 0u) {
    reserve = 1u;
  }
  if (reserve > 64u) {
    reserve = 64u;
  }
  return reserve > cap ? cap : reserve;
}

#ifdef _WIN32

typedef struct {
  EdrEventSlot data;
} EdrEventBusCell;

struct EdrEventBus {
  EdrEventBusCell *cells;
  uint32_t cap;
  uint32_t head;
  uint32_t tail;
  uint32_t count;
  uint32_t normal_count;
  uint32_t p0_reserved;
  uint64_t dropped;
  uint64_t ordinary_reserve_rejected;
  uint64_t p0_reserve_rejected;
  uint64_t pushed;
  uint64_t high_water_hits;
  CRITICAL_SECTION mu;
  CONDITION_VARIABLE nonempty;
  int mu_inited;
};

EdrEventBus *edr_event_bus_create(uint32_t slot_count) {
  if (slot_count == 0u) {
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
  bus->p0_reserved = edr_event_bus_p0_reserve_for_capacity(slot_count);
  InitializeCriticalSection(&bus->mu);
  InitializeConditionVariable(&bus->nonempty);
  bus->mu_inited = 1;
  return bus;
}

void edr_event_bus_destroy(EdrEventBus *bus) {
  if (!bus) {
    return;
  }
  if (bus->mu_inited) {
    DeleteCriticalSection(&bus->mu);
  }
  free(bus->cells);
  free(bus);
}

bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot) {
  if (!bus || !slot || !bus->mu_inited) {
    return false;
  }
  EnterCriticalSection(&bus->mu);
  if (!slot->p0_critical &&
      bus->normal_count >= bus->cap - bus->p0_reserved) {
    bus->dropped++;
    bus->ordinary_reserve_rejected++;
    LeaveCriticalSection(&bus->mu);
    return false;
  }
  if (bus->count >= bus->cap) {
    bus->dropped++;
    if (slot->p0_critical) {
      bus->p0_reserve_rejected++;
    } else {
      bus->ordinary_reserve_rejected++;
    }
    LeaveCriticalSection(&bus->mu);
    return false;
  }
  int was_empty = bus->count == 0u;
  memcpy(&bus->cells[bus->tail].data, slot, sizeof(EdrEventSlot));
  bus->tail = (bus->tail + 1u) % bus->cap;
  bus->count++;
  if (!slot->p0_critical) {
    bus->normal_count++;
  }
  bus->pushed++;
  if ((uint64_t)bus->count * 100u >= (uint64_t)bus->cap * 80u) {
    bus->high_water_hits++;
  }
  if (was_empty) {
    WakeConditionVariable(&bus->nonempty);
  }
  LeaveCriticalSection(&bus->mu);
  return true;
}

bool edr_event_bus_try_pop(EdrEventBus *bus, EdrEventSlot *out_slot) {
  if (!bus || !out_slot || !bus->mu_inited) {
    return false;
  }
  EnterCriticalSection(&bus->mu);
  if (bus->count == 0u) {
    LeaveCriticalSection(&bus->mu);
    return false;
  }
  memcpy(out_slot, &bus->cells[bus->head].data, sizeof(EdrEventSlot));
  bus->head = (bus->head + 1u) % bus->cap;
  bus->count--;
  if (!out_slot->p0_critical && bus->normal_count > 0u) {
    bus->normal_count--;
  }
  LeaveCriticalSection(&bus->mu);
  return true;
}

bool edr_event_bus_wait(EdrEventBus *bus, uint32_t timeout_ms) {
  if (!bus || !bus->mu_inited) {
    return false;
  }
  EnterCriticalSection(&bus->mu);
  if (bus->count == 0u) {
    DWORD wait_ms = timeout_ms == 0u ? 1u : (DWORD)timeout_ms;
    (void)SleepConditionVariableCS(&bus->nonempty, &bus->mu, wait_ms);
  }
  bool ready = bus->count > 0u;
  LeaveCriticalSection(&bus->mu);
  return ready;
}

void edr_event_bus_wake(EdrEventBus *bus) {
  if (bus && bus->mu_inited) {
    WakeAllConditionVariable(&bus->nonempty);
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

uint32_t edr_event_bus_p0_reserved_slots(const EdrEventBus *bus) {
  return bus ? bus->p0_reserved : 0u;
}

uint64_t edr_event_bus_ordinary_reserve_rejected_total(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint64_t n = bus->ordinary_reserve_rejected;
  LeaveCriticalSection(&bus->mu);
  return n;
}

uint64_t edr_event_bus_p0_reserve_rejected_total(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint64_t n = bus->p0_reserve_rejected;
  LeaveCriticalSection(&bus->mu);
  return n;
}

uint64_t edr_event_bus_static_bytes(const EdrEventBus *bus) {
  return bus ? (uint64_t)sizeof(*bus) + (uint64_t)bus->cap * (uint64_t)sizeof(EdrEventBusCell) : 0u;
}

uint32_t edr_event_bus_used_approx(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint32_t n = bus->count;
  LeaveCriticalSection(&bus->mu);
  return n;
}

uint64_t edr_event_bus_dropped_total(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint64_t n = bus->dropped;
  LeaveCriticalSection(&bus->mu);
  return n;
}

uint64_t edr_event_bus_pushed_total(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint64_t n = bus->pushed;
  LeaveCriticalSection(&bus->mu);
  return n;
}

uint64_t edr_event_bus_high_water_hits(EdrEventBus *bus) {
  if (!bus || !bus->mu_inited) {
    return 0u;
  }
  EnterCriticalSection(&bus->mu);
  uint64_t n = bus->high_water_hits;
  LeaveCriticalSection(&bus->mu);
  return n;
}

#else

typedef struct {
  _Alignas(64) _Atomic uint64_t turn;
  EdrEventSlot data;
} EdrEventBusCell;

struct EdrEventBus {
  EdrEventBusCell *cells;
  uint32_t cap;
  uint32_t p0_reserved;
  _Alignas(64) _Atomic uint64_t head;
  _Alignas(64) _Atomic uint64_t tail;
  _Alignas(64) _Atomic uint32_t normal_count;
  _Atomic uint64_t dropped;
  _Atomic uint64_t ordinary_reserve_rejected;
  _Atomic uint64_t p0_reserve_rejected;
  _Atomic uint64_t pushed;
  _Atomic uint64_t high_water_hits;
};

static inline uint64_t bus_lap(uint64_t pos, uint32_t cap) { return pos / (uint64_t)cap; }

static inline uint32_t bus_idx(uint64_t pos, uint32_t cap) { return (uint32_t)(pos % (uint64_t)cap); }

EdrEventBus *edr_event_bus_create(uint32_t slot_count) {
  if (slot_count == 0u) {
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
  bus->p0_reserved = edr_event_bus_p0_reserve_for_capacity(slot_count);
  for (uint32_t i = 0; i < slot_count; i++) {
    atomic_init(&bus->cells[i].turn, 0u);
  }
  atomic_init(&bus->head, 0u);
  atomic_init(&bus->tail, 0u);
  atomic_init(&bus->normal_count, 0u);
  atomic_init(&bus->dropped, 0u);
  atomic_init(&bus->ordinary_reserve_rejected, 0u);
  atomic_init(&bus->p0_reserve_rejected, 0u);
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
  int normal_reserved = 0;
  if (!slot->p0_critical) {
    const uint32_t normal_limit = cap - bus->p0_reserved;
    uint32_t normal_count = atomic_load_explicit(&bus->normal_count, memory_order_acquire);
    for (;;) {
      if (normal_count >= normal_limit) {
        (void)atomic_fetch_add_explicit(&bus->dropped, 1u, memory_order_relaxed);
        (void)atomic_fetch_add_explicit(&bus->ordinary_reserve_rejected, 1u,
                                        memory_order_relaxed);
        return false;
      }
      if (atomic_compare_exchange_weak_explicit(&bus->normal_count, &normal_count,
                                                normal_count + 1u, memory_order_acq_rel,
                                                memory_order_acquire)) {
        normal_reserved = 1;
        break;
      }
    }
  }
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
        if (normal_reserved) {
          (void)atomic_fetch_sub_explicit(&bus->normal_count, 1u, memory_order_acq_rel);
        }
        (void)atomic_fetch_add_explicit(&bus->dropped, 1u, memory_order_relaxed);
        if (slot->p0_critical) {
          (void)atomic_fetch_add_explicit(&bus->p0_reserve_rejected, 1u,
                                          memory_order_relaxed);
        } else {
          (void)atomic_fetch_add_explicit(&bus->ordinary_reserve_rejected, 1u,
                                          memory_order_relaxed);
        }
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
        if (!out_slot->p0_critical) {
          (void)atomic_fetch_sub_explicit(&bus->normal_count, 1u, memory_order_acq_rel);
        }
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

bool edr_event_bus_wait(EdrEventBus *bus, uint32_t timeout_ms) {
  (void)bus;
  if (timeout_ms == 0u) {
    timeout_ms = 1u;
  }
  {
    struct timespec ts;
    ts.tv_sec = (time_t)(timeout_ms / 1000u);
    ts.tv_nsec = (long)(timeout_ms % 1000u) * 1000000L;
    (void)nanosleep(&ts, NULL);
  }
  return bus && edr_event_bus_used_approx(bus) > 0u;
}

void edr_event_bus_wake(EdrEventBus *bus) { (void)bus; }

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

uint32_t edr_event_bus_p0_reserved_slots(const EdrEventBus *bus) {
  return bus ? bus->p0_reserved : 0u;
}

uint64_t edr_event_bus_ordinary_reserve_rejected_total(EdrEventBus *bus) {
  return bus ? atomic_load_explicit(&bus->ordinary_reserve_rejected, memory_order_relaxed) : 0u;
}

uint64_t edr_event_bus_p0_reserve_rejected_total(EdrEventBus *bus) {
  return bus ? atomic_load_explicit(&bus->p0_reserve_rejected, memory_order_relaxed) : 0u;
}

uint64_t edr_event_bus_static_bytes(const EdrEventBus *bus) {
  return bus ? (uint64_t)sizeof(*bus) + (uint64_t)bus->cap * (uint64_t)sizeof(EdrEventBusCell) : 0u;
}

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

#endif

static int edr_is_high_value_event(const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  if (slot->priority == 0) {
    return 1;
  }
  if (slot->attack_surface_hint != 0) {
    return 1;
  }
  switch (slot->type) {
    case EDR_EVENT_PROCESS_INJECT:
    case EDR_EVENT_THREAD_CREATE_REMOTE:
    case EDR_EVENT_PROTOCOL_SHELLCODE:
    case EDR_EVENT_WEBSHELL_DETECTED:
    case EDR_EVENT_FIREWALL_RULE_CHANGE:
      return 1;
    default:
      return 0;
  }
}

static volatile int s_dual_bus_enabled;
static EdrEventBus *s_high_priority_bus;
static EdrEventBus *s_low_priority_bus;

static int edr_dual_bus_yes(const char *e) {
  if (!e || !e[0]) {
    return 0;
  }
  if (e[0] == '1' && e[1] == 0) {
    return 1;
  }
  {
    int a = (e[0] | 32);
    return a == (int)'y' || a == (int)'t';
  }
}

int edr_dual_bus_enabled(void) {
  if (!s_dual_bus_enabled) {
    s_dual_bus_enabled = edr_dual_bus_yes(getenv("EDR_DUAL_BUS_ENABLED")) ? 1 : -1;
  }
  return s_dual_bus_enabled > 0 ? 1 : 0;
}

EdrEventBus *edr_event_bus_create_dual(uint32_t high_priority_slot_count, uint32_t low_priority_slot_count) {
  if (high_priority_slot_count < 2u || low_priority_slot_count < 2u) {
    return NULL;
  }
  s_high_priority_bus = edr_event_bus_create(high_priority_slot_count);
  if (!s_high_priority_bus) {
    return NULL;
  }
  s_low_priority_bus = edr_event_bus_create(low_priority_slot_count);
  if (!s_low_priority_bus) {
    edr_event_bus_destroy(s_high_priority_bus);
    s_high_priority_bus = NULL;
    return NULL;
  }
  return s_high_priority_bus;
}

int edr_event_bus_try_push_dual(EdrBusType bus_type, const EdrEventSlot *slot) {
  if (!slot) {
    return 0;
  }
  EdrEventBus *target_bus = NULL;
  if (bus_type == EDR_BUS_TYPE_HIGH_PRIORITY) {
    target_bus = s_high_priority_bus;
  } else if (bus_type == EDR_BUS_TYPE_LOW_PRIORITY) {
    target_bus = s_low_priority_bus;
  } else {
    if (edr_is_high_value_event(slot)) {
      target_bus = s_high_priority_bus;
    } else {
      target_bus = s_low_priority_bus;
    }
  }
  if (!target_bus) {
    return 0;
  }
  return edr_event_bus_try_push(target_bus, slot) ? 1 : 0;
}

bool edr_event_bus_try_pop_high_priority(EdrEventBus *bus, EdrEventSlot *out_slot) {
  (void)bus;
  if (!s_high_priority_bus) {
    return false;
  }
  return edr_event_bus_try_pop(s_high_priority_bus, out_slot);
}

bool edr_event_bus_try_pop_low_priority(EdrEventBus *bus, EdrEventSlot *out_slot) {
  (void)bus;
  if (!s_low_priority_bus) {
    return false;
  }
  return edr_event_bus_try_pop(s_low_priority_bus, out_slot);
}

uint32_t edr_event_bus_used_approx_high_priority(EdrEventBus *bus) {
  (void)bus;
  if (!s_high_priority_bus) {
    return 0u;
  }
  return edr_event_bus_used_approx(s_high_priority_bus);
}

uint32_t edr_event_bus_used_approx_low_priority(EdrEventBus *bus) {
  (void)bus;
  if (!s_low_priority_bus) {
    return 0u;
  }
  return edr_event_bus_used_approx(s_low_priority_bus);
}

uint64_t edr_event_bus_dropped_total_high_priority(EdrEventBus *bus) {
  (void)bus;
  if (!s_high_priority_bus) {
    return 0u;
  }
  return edr_event_bus_dropped_total(s_high_priority_bus);
}

uint64_t edr_event_bus_dropped_total_low_priority(EdrEventBus *bus) {
  (void)bus;
  if (!s_low_priority_bus) {
    return 0u;
  }
  return edr_event_bus_dropped_total(s_low_priority_bus);
}
