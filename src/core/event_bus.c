#include "edr/event_bus.h"

#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

struct EdrEventBus {
  EdrEventSlot *slots;
  uint32_t cap;
  uint32_t head;
  uint32_t tail;
  uint64_t dropped;
  uint64_t high_water_hits;
#ifdef _WIN32
  CRITICAL_SECTION lock;
#else
  pthread_mutex_t lock;
#endif
};

static void lock_init(EdrEventBus *bus) {
#ifdef _WIN32
  InitializeCriticalSection(&bus->lock);
#else
  pthread_mutex_init(&bus->lock, NULL);
#endif
}

static void lock_fini(EdrEventBus *bus) {
#ifdef _WIN32
  DeleteCriticalSection(&bus->lock);
#else
  pthread_mutex_destroy(&bus->lock);
#endif
}

static void lock(EdrEventBus *bus) {
#ifdef _WIN32
  EnterCriticalSection(&bus->lock);
#else
  pthread_mutex_lock(&bus->lock);
#endif
}

static void unlock(EdrEventBus *bus) {
#ifdef _WIN32
  LeaveCriticalSection(&bus->lock);
#else
  pthread_mutex_unlock(&bus->lock);
#endif
}

EdrEventBus *edr_event_bus_create(uint32_t slot_count) {
  if (slot_count < 2u) {
    return NULL;
  }
  EdrEventBus *bus = (EdrEventBus *)calloc(1, sizeof(EdrEventBus));
  if (!bus) {
    return NULL;
  }
  bus->slots = (EdrEventSlot *)calloc(slot_count, sizeof(EdrEventSlot));
  if (!bus->slots) {
    free(bus);
    return NULL;
  }
  bus->cap = slot_count;
  bus->head = 0;
  bus->tail = 0;
  bus->dropped = 0;
  bus->high_water_hits = 0;
  lock_init(bus);
  return bus;
}

void edr_event_bus_destroy(EdrEventBus *bus) {
  if (!bus) {
    return;
  }
  lock_fini(bus);
  free(bus->slots);
  free(bus);
}

bool edr_event_bus_try_push(EdrEventBus *bus, const EdrEventSlot *slot) {
  if (!bus || !slot) {
    return false;
  }
  lock(bus);
  uint32_t next = (bus->tail + 1u) % bus->cap;
  if (next == bus->head) {
    bus->dropped++;
    unlock(bus);
    return false;
  }
  bus->slots[bus->tail] = *slot;
  bus->tail = next;
  {
    uint32_t used = (bus->tail + bus->cap - bus->head) % bus->cap;
    if (used * 100u >= bus->cap * 80u) {
      bus->high_water_hits++;
    }
  }
  unlock(bus);
  return true;
}

bool edr_event_bus_try_pop(EdrEventBus *bus, EdrEventSlot *out_slot) {
  if (!bus || !out_slot) {
    return false;
  }
  lock(bus);
  if (bus->head == bus->tail) {
    unlock(bus);
    return false;
  }
  *out_slot = bus->slots[bus->head];
  bus->head = (bus->head + 1u) % bus->cap;
  unlock(bus);
  return true;
}

uint32_t edr_event_bus_try_pop_many(EdrEventBus *bus, EdrEventSlot *out_slots, uint32_t max_count) {
  if (!bus || !out_slots || max_count == 0u) {
    return 0u;
  }
  lock(bus);
  uint32_t n = 0u;
  while (n < max_count && bus->head != bus->tail) {
    out_slots[n++] = bus->slots[bus->head];
    bus->head = (bus->head + 1u) % bus->cap;
  }
  unlock(bus);
  return n;
}

uint32_t edr_event_bus_capacity(const EdrEventBus *bus) {
  return bus ? bus->cap : 0u;
}

uint32_t edr_event_bus_used_approx(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  lock(bus);
  uint32_t h = bus->head;
  uint32_t t = bus->tail;
  unlock(bus);
  return (t + bus->cap - h) % bus->cap;
}

uint64_t edr_event_bus_dropped_total(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  lock(bus);
  uint64_t d = bus->dropped;
  unlock(bus);
  return d;
}

uint64_t edr_event_bus_high_water_hits(EdrEventBus *bus) {
  if (!bus) {
    return 0u;
  }
  lock(bus);
  uint64_t h = bus->high_water_hits;
  unlock(bus);
  return h;
}
